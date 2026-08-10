# WAF Centralized Monitoring & Management System
### Deployment and Configuration Guide

| | |
|---|---|
| **System** | Nginx / Apache + ModSecurity (OWASP CRS) |
| **Backend** | Supabase (PostgreSQL + REST API) |
| **Log Pipeline** | Python (log-shipper, geo-enrichment) |
| **Dashboard** | Python web application |
| **Document Status** | Setup Complete — Reference Documentation |

---

## 1. Overview

This document describes the deployment of a centralized security monitoring and management system for a ModSecurity-protected web server environment. The system consists of two phases:

- **Phase 1 — Monitoring Pipeline:** ModSecurity, access, and error logs are parsed in near real-time and shipped to a central Supabase database, enriched with IP geolocation data, and surfaced through a web dashboard.
- **Phase 2 — Administrative Actions:** The dashboard is extended with privileged, audited operations — updating the OWASP Core Rule Set (CRS), disabling individual rules, and adding custom blocking rules — executed through a restricted set of server-side scripts.

### 1.1 Architecture Summary

```text
 [ModSecurity / Access / Error Logs]
              │
              ▼
     [log-shipper (Python)]  ── near real-time, inotify-based
              │
              ▼
        [Supabase (Postgres)]  ◄── [geo_enrich.py]  (scheduled, every 2 minutes)
              │
              ▼
        [Web Dashboard]  ──► [Privileged Scripts]  ──► [Live ModSecurity Config]
                                     (audited via admin_actions)
```

---

## 2. Prerequisites

- A running web server (Nginx and/or Apache) with ModSecurity and the OWASP CRS installed.
- A Supabase project (URL, `anon` key, and `service_role` key).
- Python 3 with `venv` module.
- Root/sudo access on the host server.
- The `WAF/Dashboard` repository cloned or copied to your server. 

Navigate to your local copy of the repository to begin:
```bash
cd /path/to/WAF/Dashboard
```

---

## PHASE 1 — Monitoring Pipeline

### 3. Supabase Schema — Core Logging Tables

Execute the following in the Supabase SQL Editor to provision the core logging tables.

```sql
drop table if exists modsec_events cascade;
drop table if exists access_logs cascade;
drop table if exists error_logs cascade;

create table modsec_events (
  id bigint generated always as identity primary key,
  server text not null,
  event_time timestamptz,
  client_ip text,
  request_line text,
  method text,
  uri text,
  http_status text,
  blocked boolean default false,
  rules jsonb default '[]'::jsonb,
  raw_id text,
  user_agent text,
  client_type text default 'unknown',       -- human | bot | ai_agent | verified_bot | spoofed_bot | headless_browser | script_bot | unknown
  bot_score integer,                         -- 1-99, lower = more bot-like
  verified_bot boolean,
  classification_reasons jsonb default '[]'::jsonb,
  created_at timestamptz default now()
);

create table access_logs (
  id bigint generated always as identity primary key,
  server text not null,
  ip text,
  log_time text,
  request text,
  http_status text,
  size text,
  created_at timestamptz default now()
);

create table error_logs (
  id bigint generated always as identity primary key,
  server text not null,
  message text,
  created_at timestamptz default now()
);

create unique index modsec_events_raw_id_idx on modsec_events (raw_id) where raw_id is not null;
create index modsec_events_event_time_idx on modsec_events (event_time desc);
create index access_logs_created_at_idx on access_logs (created_at desc);
create index error_logs_created_at_idx on error_logs (created_at desc);

alter table modsec_events enable row level security;
alter table access_logs enable row level security;
alter table error_logs enable row level security;

create policy "public read modsec_events" on modsec_events for select using (true);
create policy "public read access_logs" on access_logs for select using (true);
create policy "public read error_logs" on error_logs for select using (true);
-- No INSERT policies are defined for the anon role.
-- Writes are permitted only via the service_role key, used exclusively by the log-shipper.
```

> **Security note:** Row Level Security (RLS) restricts the public/`anon` key to read-only access. All write operations require the `service_role` key, which must never be exposed to client-side or dashboard-facing code.

---

### 4. Log Shipper — Installation

Install the Python venv module, create a virtual environment, and install dependencies to avoid breaking system packages:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip

sudo mkdir -p /opt/log-shipper /var/lib/log-shipper
sudo python3 -m venv /opt/log-shipper/venv

# Install dependencies inside the virtual environment
sudo /opt/log-shipper/venv/bin/pip install requests watchdog geoip2
```

Deploy the shipper script from the repository:

```bash
# Assuming you are in the WAF/Dashboard directory
sudo cp deployment_scripts/shipper.py /opt/log-shipper/shipper.py
sudo chmod +x /opt/log-shipper/shipper.py
```

---

### 5. Log Shipper — Environment Configuration

Each monitored web server instance requires its own environment file, specifying its Supabase credentials and server label.

**Nginx** — `/etc/log-shipper/nginx.env`

```bash
sudo mkdir -p /etc/log-shipper
sudo tee /etc/log-shipper/nginx.env > /dev/null << 'EOF'
SUPABASE_URL=https://[Project ID].supabase.co
SUPABASE_SERVICE_KEY=PASTE_YOUR_SERVICE_ROLE_KEY_HERE
SERVER_LABEL=nginx
EOF
```

**Apache** — `/etc/log-shipper/apache.env`

```bash
sudo tee /etc/log-shipper/apache.env > /dev/null << 'EOF'
SUPABASE_URL=https://[Project ID].supabase.co
SUPABASE_SERVICE_KEY=PASTE_YOUR_SERVICE_ROLE_KEY_HERE
SERVER_LABEL=apache
EOF
```

Restrict access to these files, as they contain the privileged `service_role` credential:

```bash
sudo chown root:root /etc/log-shipper/*.env
sudo chmod 600 /etc/log-shipper/*.env
```

---

### 6. Log Shipper — Systemd Service

Create a templated systemd unit at `/etc/systemd/system/log-shipper@.service`:

```ini
[Unit]
Description=Log shipper for %i -> Supabase
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/log-shipper/%i.env
ExecStart=/opt/log-shipper/venv/bin/python3 /opt/log-shipper/shipper.py
Restart=always
RestartSec=3
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

> **Note:** The `ExecStart` line uses the Python executable inside the virtual environment we created in step 4.

Enable and start an instance per monitored server:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now log-shipper@nginx.service
# Only run the following if you also use Apache
# sudo systemctl enable --now log-shipper@apache.service
```

**Verification:**

```bash
sudo systemctl status log-shipper@nginx.service
sudo journalctl -u log-shipper@nginx.service -f
```

At this stage, ModSecurity, access, and error log entries should be actively populating the corresponding tables in Supabase.

---

### 7. Geolocation — Supabase Schema

Execute the following in the Supabase SQL Editor:

```sql
create table ip_geo_cache (
  ip text primary key,
  country text,
  country_code text,
  region text,
  city text,
  lat double precision,
  lon double precision,
  lookup_status text default 'ok',   -- 'ok', 'fail', 'private'
  updated_at timestamptz default now()
);

alter table ip_geo_cache enable row level security;

-- Dashboard (anon key) may read
create policy "public read ip_geo_cache" on ip_geo_cache for select using (true);
-- Writes are permitted only via service_role (the enrichment script)
```

Verify that Row Level Security is enabled:
```sql
select tablename, rowsecurity from pg_tables where tablename = 'ip_geo_cache';
```

---

### 8. Geolocation — Enrichment Script

Deploy the enrichment script from the repository:

```bash
# Assuming you are in the WAF/Dashboard directory
sudo cp deployment_scripts/geo_enrich.py /opt/log-shipper/geo_enrich.py
sudo chmod +x /opt/log-shipper/geo_enrich.py
```

Download the GeoLite2 City database (`.mmdb`) and place it under `/opt` (or wherever `MMDB_PATH` is configured in `geo_enrich.py`):

```bash
# Ensure your database is downloaded and extracted, e.g., to /opt/log-shipper/GeoLite2-City.mmdb
```

Schedule the enrichment job via cron (runs every two minutes):

```bash
sudo crontab -e
```

Add the following line (make sure to use the virtual environment's python!):

```text
*/2 * * * * /opt/log-shipper/venv/bin/python3 /opt/log-shipper/geo_enrich.py >> /var/log/geo_enrich.log 2>&1
```

Initialize the log file and verify execution:

```bash
sudo touch /var/log/geo_enrich.log
sudo tail -f /var/log/geo_enrich.log
```

Within a few minutes, records should begin appearing in the `ip_geo_cache` table.

> **✅ Phase 1 Complete** — the monitoring pipeline (log ingestion, geolocation enrichment, and dashboard visualization) is fully operational.

---

## PHASE 2 — Administrative Actions

### 9. Audit Log — Supabase Schema

All privileged administrative actions performed through the dashboard are recorded for accountability and traceability.

```sql
create table admin_actions (
  id bigint generated always as identity primary key,
  action_type text not null,       -- 'crs_update' | 'rule_remove' | 'rule_add'
  target text,                     -- rule id, keyword, or CRS version
  success boolean not null,
  output text,
  performed_by text,
  performed_at timestamptz default now()
);

alter table admin_actions enable row level security;
create policy "public read admin_actions" on admin_actions for select using (true);
-- Writes are permitted only via service_role, consistent with all other tables
```

---

### 10. Privileged Scripts — Deployment

Create the dedicated scripts directory and deploy each administrative script:

```bash
sudo mkdir -p /opt/waf-admin/scripts/
sudo mkdir -p /var/log/waf-admin/

# Copy from the repository
sudo cp admin_scripts/*.sh /opt/waf-admin/scripts/
sudo cp manage_rules.py /opt/waf-admin/scripts/

sudo chown root:root /opt/waf-admin/scripts/*
sudo chmod 700 /opt/waf-admin/scripts/*
```

> **Required:** Each script writes to its own dedicated log file under `/var/log/waf-admin/` for auditability of individual invocations, independent of the centralized `admin_actions` table. Ensure `/var/log/waf-admin/` is created and writable by root.

---

### 11. Privilege Escalation — Sudo Configuration

Grant the application's runtime user narrow, script-specific `sudo` access — limited strictly to the five administrative scripts, with no broader privileges granted.

```bash
sudo visudo -f /etc/sudoers.d/waf-admin
```

Add the following entry, replacing `<username>` with the actual system user under which the dashboard application (`app.py`) runs:

```
<username> ALL=(ALL) NOPASSWD: /opt/waf-admin/scripts/add-custom-rule.sh, \
  /opt/waf-admin/scripts/crs-status.sh, \
  /opt/waf-admin/scripts/remove-rule.sh, \
  /opt/waf-admin/scripts/restore-rule.sh, \
  /opt/waf-admin/scripts/update-crs.sh, \
  /opt/waf-admin/scripts/manage_rules.py
```

> ⚠️ **Security consideration:** This grant should reference exact script paths only — never a wildcard or directory-level grant — to ensure the privileged surface remains limited to the approved, individually-audited operations.

---

### 12. Custom Rules — Include Directive

Register the custom rules directory with ModSecurity so newly added rules are loaded on reload:

```bash
sudo mkdir -p /usr/local/modsecurity-crs/rules/custom/
sudo touch /usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf
echo "Include /usr/local/modsecurity-crs/rules/custom/*.conf" | sudo tee -a /etc/nginx/modsec/main.conf
sudo nginx -t && sudo systemctl reload nginx
```

If you prefer to align with CRS rule order, place `REQUEST-948-LOCAL-RULES.conf` appropriately:
```bash
sudo touch /usr/local/modsecurity-crs/rules/REQUEST-948-LOCAL-RULES.conf
```

---

### 13. Dashboard — Deployment

Finally, set up the web dashboard itself.

```bash
# Still inside the WAF/Dashboard directory
python3 -m venv myenv

# Activate the virtual environment
source myenv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the dashboard application
python3 app.py
```

At this point, verify that all three administrative API endpoints (CRS update, rule removal, custom rule addition) respond correctly, and confirm the live site continues serving traffic normally.

---

## 14. Post-Deployment Verification Checklist

| # | Check | Expected Result |
|---|---|---|
| 1 | `sudo systemctl status log-shipper@nginx.service` | `active (running)` |
| 2 | Supabase → `modsec_events` table | New rows appear as traffic occurs |
| 3 | Supabase → `ip_geo_cache` table | Rows populated for client IPs |
| 4 | `sudo tail -f /var/log/geo_enrich.log` | Successful enrichment entries every 2 minutes |
| 5 | `sudo /opt/waf-admin/scripts/crs-status.sh` | Returns current/latest CRS version |
| 6 | `sudo nginx -t` | `syntax is ok` / `test is successful` |
| 7 | Dashboard: CRS update action | Version updates, audit row created in `admin_actions` |
| 8 | Dashboard: rule removal action | Rule excluded, audit row created in `admin_actions` |
| 9 | Dashboard: custom rule addition | Rule blocks matching traffic (HTTP 403), audit row created |

---

## 15. File & Path Reference

| Component | Path |
|---|---|
| Log shipper | `/opt/log-shipper/shipper.py` |
| Geo enrichment script | `/opt/log-shipper/geo_enrich.py` |
| Shipper virtual env | `/opt/log-shipper/venv/` |
| Shipper environment files | `/etc/log-shipper/*.env` |
| Shipper systemd unit | `/etc/systemd/system/log-shipper@.service` |
| Shipper state (offsets) | `/var/lib/log-shipper/` |
| Admin scripts | `/opt/waf-admin/scripts/` |
| Admin script logs | `/var/log/waf-admin/` |
| Sudoers grant | `/etc/sudoers.d/waf-admin` |
| CRS installation | `/usr/local/modsecurity-crs/` |
| Custom / local rules | `/usr/local/modsecurity-crs/rules/REQUEST-948-LOCAL-RULES.conf` |
| ModSecurity main config | `/etc/nginx/modsec/main.conf` |
| Dashboard code | `/path/to/WAF/Dashboard/` |

---

*End of document.*
