#!/usr/bin/env python3
"""
geo_enrich.py — finds client IPs from modsec_events that aren't yet
geolocated, looks them up locally via MaxMind GeoLite2 (no network calls),
and upserts the results into ip_geo_cache on Supabase.

Intended to run on a schedule (cron every 1-2 minutes).
"""

import os
from datetime import datetime, timezone
import ipaddress
import sys
import requests
from dotenv import load_dotenv
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

# ---- load env ----
ENV_CANDIDATES = [
    os.getenv("LOG_SHIPPER_ENV"),
    "/etc/log-shipper/apache.env",
    "/etc/log-shipper/nginx.env",
]
ENV_PATH = next((p for p in ENV_CANDIDATES if p and os.path.exists(p)), "/etc/log-shipper/apache.env")
load_dotenv(ENV_PATH)

# ---- config ----
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
MMDB_PATH = "/opt/log-shipper/GeoLite2-City.mmdb"  # adjust if you used geoipupdate's default path

# Validate that we successfully loaded the credentials
if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    sys.stderr.write(f"[{datetime.now(timezone.utc).isoformat()}] ERROR: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY in {ENV_PATH}\n")
    sys.exit(1)

# ---- Supabase REST helpers ----
def supabase_get(table, params=None):
    if params is None:
        params = {}
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{table}"
    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if not response.ok:
            sys.stderr.write(f"[supabase_get:{table}] HTTP {response.status_code} — {response.text}\n")
            return []
        data = response.json()
        return data if isinstance(data, list) else []
    except Exception as e:
        sys.stderr.write(f"[supabase_get:{table}] request error — {e}\n")
        return []

def supabase_upsert(table, rows):
    if not rows:
        return True
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{table}"
    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=minimal",
    }
    try:
        response = requests.post(url, headers=headers, json=rows, timeout=15)
        if not response.ok:
            sys.stderr.write(f"[supabase_upsert:{table}] HTTP {response.status_code} — {response.text}\n")
            return False
        return True
    except Exception as e:
        sys.stderr.write(f"[supabase_upsert:{table}] request error — {e}\n")
        return False

# ---- Helper to check if IP is private or reserved ----
def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return False

# ---- 1. get all client IPs seen in modsec_events ----
events = supabase_get('modsec_events', {
    'select': 'client_ip',
    'client_ip': 'not.is.null',
    'limit': '5000',
})

seen_ips = {}
for e in events:
    ip = e.get('client_ip')
    if ip:
        seen_ips[ip] = True
seen_ips = list(seen_ips.keys())

if not seen_ips:
    sys.stdout.write(f"[{datetime.now(timezone.utc).isoformat()}] no client IPs found in modsec_events yet\n")
    sys.exit(0)

# ---- 2. get IPs already cached ----
cached = supabase_get('ip_geo_cache', {
    'select': 'ip',
    'limit': '5000',
})
cached_ips = {row['ip']: True for row in cached if 'ip' in row}

# ---- 3. diff: only look up new IPs ----
new_ips = [ip for ip in seen_ips if ip not in cached_ips]

if not new_ips:
    sys.stdout.write(f"[{datetime.now(timezone.utc).isoformat()}] no new IPs to geolocate ({len(seen_ips)} total seen)\n")
    sys.exit(0)

sys.stdout.write(f"[{datetime.now(timezone.utc).isoformat()}] geolocating {len(new_ips)} new IP(s)...\n")

# ---- 4. look up each new IP locally via MaxMind ----
def empty_geo_row(ip, status):
    return {
        'ip': ip,
        'country': None,
        'country_code': None,
        'region': None,
        'city': None,
        'lat': None,
        'lon': None,
        'lookup_status': status,
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }

rows = []
try:
    with Reader(MMDB_PATH) as reader:
        for ip in new_ips:
            # Skip private/reserved ranges — mark as 'private' so we don't re-check them every run
            if not is_public_ip(ip):
                rows.append(empty_geo_row(ip, 'private'))
                continue

            try:
                record = reader.city(ip)
                row = empty_geo_row(ip, 'ok')
                row['country'] = record.country.name
                row['country_code'] = record.country.iso_code
                row['region'] = record.subdivisions.most_specific.name # <--- FIXED HERE
                row['city'] = record.city.name
                row['lat'] = record.location.latitude
                row['lon'] = record.location.longitude
                rows.append(row)
            except AddressNotFoundError:
                rows.append(empty_geo_row(ip, 'fail'))
            except Exception as e:
                sys.stderr.write(f"  lookup error for {ip}: {e}\n")
                rows.append(empty_geo_row(ip, 'fail'))
except Exception as e:
    sys.stderr.write(f"Failed to open MaxMind database at {MMDB_PATH}: {e}\n")
    sys.exit(1)

# ---- 5. upsert results to Supabase ----
if supabase_upsert('ip_geo_cache', rows):
    sys.stdout.write(f"[{datetime.now(timezone.utc).isoformat()}] upserted {len(rows)} geo record(s)\n")
else:
    sys.stderr.write(f"[{datetime.now(timezone.utc).isoformat()}] upsert failed — see errors above\n")
    sys.exit(1)
