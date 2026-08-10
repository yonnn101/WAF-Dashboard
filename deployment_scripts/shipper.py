#!/usr/bin/env python3
"""
shipper.py — tails ModSecurity/access/error logs and ships parsed,
classified rows to Supabase in near real-time.

Config via environment variables (set in the systemd unit's EnvironmentFile):
    SUPABASE_URL, SUPABASE_SERVICE_KEY, SERVER_LABEL (nginx|apache)

Requires: pip install requests watchdog --break-system-packages
"""

import os
import re
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
SERVER_LABEL = os.environ.get("SERVER_LABEL", "unknown")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    print("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY env vars", file=sys.stderr)
    sys.exit(1)

IS_NGINX = SERVER_LABEL == "nginx"

PATHS = {
    "modsec": "/var/log/modsec_audit.log" if IS_NGINX else "/var/log/apache2/modsec_audit.log",
    "access": "/var/log/nginx/access.log" if IS_NGINX else "/var/log/apache2/access.log",
    "error":  "/var/log/nginx/error.log" if IS_NGINX else "/var/log/apache2/error.log",
}

STATE_DIR = Path("/var/lib/log-shipper")
STATE_DIR.mkdir(parents=True, exist_ok=True)

SUPABASE_HEADERS = {
    "apikey": SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "resolution=ignore-duplicates,return=minimal",
}


# ---------------------------------------------------------------------------
# offset tracking (so restarts never re-ship old data)
# ---------------------------------------------------------------------------

def load_offset(key: str) -> int:
    f = STATE_DIR / f"{key}.offset"
    if f.is_file():
        try:
            return int(f.read_text().strip())
        except ValueError:
            return 0
    return 0


def save_offset(key: str, offset: int) -> None:
    (STATE_DIR / f"{key}.offset").write_text(str(offset))


def read_new_bytes(path: str, key: str) -> str:
    p = Path(path)
    if not p.is_file() or not os.access(path, os.R_OK):
        return ""
    size = p.stat().st_size
    offset = load_offset(key)

    if offset > size:  # log rotation / truncation
        offset = 0
    if offset == size:
        return ""

    with open(path, "r", errors="replace") as fh:
        fh.seek(offset)
        data = fh.read()

    save_offset(key, size)
    return data


# ---------------------------------------------------------------------------
# Supabase REST helper
# ---------------------------------------------------------------------------

def supabase_insert(table: str, rows: list) -> bool:
    if not rows:
        return True
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{table}"
    try:
        resp = requests.post(url, headers=SUPABASE_HEADERS, data=json.dumps(rows), timeout=10)
    except requests.RequestException as e:
        print(f"[supabase_insert:{table}] request failed: {e}", file=sys.stderr)
        return False

    if 200 <= resp.status_code < 300:
        return True

    print(f"[supabase_insert:{table}] HTTP {resp.status_code} — {resp.text}", file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# advanced request classifier (WAF-style)
# ---------------------------------------------------------------------------

VERIFIABLE_BOTS = {
    "googlebot": ["googlebot.com", "google.com"],
    "bingbot": ["search.msn.com"],
    "duckduckbot": ["duckduckgo.com"],
    "baiduspider": ["baidu.com", "baidu.jp"],
    "yandexbot": ["yandex.com", "yandex.ru", "yandex.net"],
    "applebot": ["applebot.apple.com"],
    "facebookexternalhit": ["fbsv.net", "facebook.com"],
}

AI_AGENT_PATTERNS = [
    "gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-web",
    "anthropic-ai", "perplexitybot", "cohere-ai", "ccbot", "google-extended",
    "bytespider", "youbot", "diffbot", "meta-externalagent", "meta-externalfetcher",
    "applebot-extended", "duckassistbot", "amazonbot", "timpibot", "omgili",
]

HEADLESS_PATTERNS = [
    "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
    "slimerjs", "htmlunit", "electron",
]

SCRIPT_PATTERNS = [
    "curl", "wget", "python-requests", "go-http-client", "libwww-perl",
    "scrapy", "postmanruntime", "httpclient", "axios", "node-fetch",
    "okhttp", "java/", "php/", "ruby",
]

_dns_cache = {}  # ip -> bool, avoids repeat lookups within one process run


def extract_header(section_b: str, name: str):
    m = re.search(rf"^{re.escape(name)}:\s*(.+)$", section_b, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None


def has_header(section_b: str, name: str) -> bool:
    return re.search(rf"^{re.escape(name)}:", section_b, re.MULTILINE | re.IGNORECASE) is not None


def fcrdns_verify(ip: str, expected_suffixes: list) -> bool:
    cache_key = (ip, tuple(expected_suffixes))
    if cache_key in _dns_cache:
        return _dns_cache[cache_key]

    result = False
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host_lower = host.lower()
        if any(host_lower.endswith(suffix) for suffix in expected_suffixes):
            forward_ips = socket.gethostbyname_ex(host)[2]
            result = ip in forward_ips
    except (socket.herror, socket.gaierror, OSError):
        result = False

    _dns_cache[cache_key] = result
    return result


def classify_request(ip: str, ua: str, section_b: str):
    reasons = []
    ua_lower = (ua or "").lower()

    # header fingerprint score (1-99, lower = more bot-like)
    score = 50
    if section_b:
        if has_header(section_b, "accept-language"):
            score += 15
        else:
            score -= 10
            reasons.append("missing Accept-Language")
        if has_header(section_b, "accept-encoding"):
            score += 10
        else:
            score -= 5
            reasons.append("missing Accept-Encoding")
        if has_header(section_b, "sec-fetch-site"):
            score += 10
        if has_header(section_b, "sec-fetch-mode"):
            score += 10
        if has_header(section_b, "sec-fetch-dest"):
            score += 5
        if has_header(section_b, "sec-fetch-user"):
            score += 5
        if has_header(section_b, "upgrade-insecure-requests"):
            score += 5

    if not ua:
        score -= 30
        reasons.append("no User-Agent header")

    looks_like_browser = bool(ua_lower) and "mozilla" in ua_lower and (
        "chrome" in ua_lower or "safari" in ua_lower or
        "firefox" in ua_lower or "edg" in ua_lower or "opr" in ua_lower
    )

    def clamp(v):
        return max(1, min(99, v))

    # 1. AI crawlers/agents
    for p in AI_AGENT_PATTERNS:
        if p in ua_lower:
            reasons.append(f"UA matches known AI agent pattern '{p}'")
            return {"client_type": "ai_agent", "bot_score": clamp(score), "verified_bot": None, "reasons": reasons}

    # 2. Headless / automation frameworks
    for p in HEADLESS_PATTERNS:
        if p in ua_lower:
            reasons.append(f"UA matches automation framework '{p}'")
            return {"client_type": "headless_browser", "bot_score": clamp(score - 20), "verified_bot": False, "reasons": reasons}

    # 3. Claims to be a known good crawler — verify via FCrDNS
    for name, suffixes in VERIFIABLE_BOTS.items():
        if name in ua_lower:
            if ip and fcrdns_verify(ip, suffixes):
                reasons.append(f"UA claims '{name}', FCrDNS verified against {ip}")
                return {"client_type": "verified_bot", "bot_score": 90, "verified_bot": True, "reasons": reasons}
            else:
                reasons.append(f"UA claims '{name}' but FCrDNS verification FAILED for {ip} — likely spoofed")
                return {"client_type": "spoofed_bot", "bot_score": 5, "verified_bot": False, "reasons": reasons}

    # 4. Generic script / HTTP client libraries
    for p in SCRIPT_PATTERNS:
        if p in ua_lower:
            reasons.append(f"UA matches script/library pattern '{p}'")
            return {"client_type": "script_bot", "bot_score": clamp(score - 15), "verified_bot": None, "reasons": reasons}

    # 5. Claims browser, but header fingerprint doesn't back it up
    if looks_like_browser and score < 30:
        reasons.append("UA claims browser but header fingerprint is bot-like (possible spoofed UA)")
        return {"client_type": "headless_browser", "bot_score": max(1, score), "verified_bot": False, "reasons": reasons}

    # 6. Genuine-looking browser
    if looks_like_browser and score >= 50:
        reasons.append("UA and header fingerprint consistent with a real browser")
        return {"client_type": "human", "bot_score": min(99, score), "verified_bot": None, "reasons": reasons}

    reasons.append("no strong signal either way")
    return {"client_type": "unknown", "bot_score": clamp(score), "verified_bot": None, "reasons": reasons}


# ---------------------------------------------------------------------------
# timestamp parsing (tolerant of Apache mod_security2's doubled-dash offset bug)
# ---------------------------------------------------------------------------

def iso_time(modsec_ts: str):
    ts = modsec_ts.strip()
    # Apache's mod_security2 sometimes writes negative UTC offsets doubled,
    # e.g. "--0400" instead of "-0400"
    ts = re.sub(r"--(\d{4})$", r"-\1", ts)

    for fmt in ("%d/%b/%Y:%H:%M:%S %z",):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.isoformat()
        except ValueError:
            pass

    # fallback: date/time without a parseable offset, assume UTC
    m = re.match(r"^(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})", modsec_ts)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    return None


# ---------------------------------------------------------------------------
# ModSecurity audit log parsing
# ---------------------------------------------------------------------------

BOUNDARY_SPLIT_RE = re.compile(r"(?=^-+[0-9a-zA-Z]{6,}-+A-+\s*$)", re.MULTILINE)
SECTION_SPLIT_RE = re.compile(r"^-+[0-9a-zA-Z]{6,}-+([A-Z])-+\s*$", re.MULTILINE)


def parse_modsec_chunk(raw: str):
    raw = raw.strip()
    if not raw:
        return None

    parts = SECTION_SPLIT_RE.split(raw)
    sections = {}
    for i in range(1, len(parts), 2):
        letter = parts[i]
        body = parts[i + 1].strip() if i + 1 < len(parts) else ""
        sections[letter] = body
    if not sections:
        return None

    entry = {
        "event_time": None, "client_ip": None, "request_line": None,
        "method": None, "uri": None, "http_status": None, "blocked": False,
        "rules": [], "raw_id": None, "user_agent": None,
    }

    if "A" in sections:
        m = re.match(r"^\[([^\]]+)\]\s+(\S+)\s+(\S+)", sections["A"])
        if m:
            entry["event_time"] = iso_time(m.group(1))
            entry["raw_id"] = m.group(2)
            entry["client_ip"] = m.group(3)

    section_b = sections.get("B")
    if section_b:
        firstline = section_b.split("\n", 1)[0].strip()
        entry["request_line"] = firstline
        m = re.match(r"^(\S+)\s+(\S+)", firstline)
        if m:
            entry["method"] = m.group(1)
            entry["uri"] = m.group(2)
        entry["user_agent"] = extract_header(section_b, "user-agent")

    if "F" in sections:
        m = re.match(r"^\S+\s+(\d{3})", sections["F"])
        if m:
            entry["http_status"] = m.group(1)

    if "H" in sections:
        for m in re.finditer(
            r'\[id "(\d+)"\].*?\[msg "([^"]*)"\](?:.*?\[severity "([^"]*)"\])?',
            sections["H"], re.DOTALL,
        ):
            entry["rules"].append({"id": m.group(1), "msg": m.group(2), "severity": (m.group(3) or "").upper()})
        if "Action: Intercepted" in sections["H"]:
            entry["blocked"] = True

    if entry["http_status"] == "403":
        entry["blocked"] = True

    classification = classify_request(entry["client_ip"], entry["user_agent"], section_b or "")
    entry["client_type"] = classification["client_type"]
    entry["bot_score"] = classification["bot_score"]
    entry["verified_bot"] = classification["verified_bot"]
    entry["classification_reasons"] = classification["reasons"]

    return entry


def parse_access_line(line: str):
    m = re.match(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)', line)
    if m:
        return {"ip": m.group(1), "log_time": m.group(2), "request": m.group(3),
                "http_status": m.group(4), "size": m.group(5)}
    return None


# ---------------------------------------------------------------------------
# per-cycle processing
# ---------------------------------------------------------------------------

def process_modsec():
    new = read_new_bytes(PATHS["modsec"], f"modsec_{SERVER_LABEL}")
    if not new:
        return

    chunks = BOUNDARY_SPLIT_RE.split(new)
    rows = []
    for chunk in chunks:
        e = parse_modsec_chunk(chunk)
        if not e:
            continue
        rows.append({
            "server": SERVER_LABEL,
            "event_time": e["event_time"],
            "client_ip": e["client_ip"],
            "request_line": e["request_line"],
            "method": e["method"],
            "uri": e["uri"],
            "http_status": e["http_status"],
            "blocked": e["blocked"],
            "rules": e["rules"],
            "raw_id": e["raw_id"],
            "user_agent": e["user_agent"],
            "client_type": e["client_type"],
            "bot_score": e["bot_score"],
            "verified_bot": e["verified_bot"],
            "classification_reasons": e["classification_reasons"],
        })

    if rows:
        supabase_insert("modsec_events", rows)
        print(f"[{datetime.now().isoformat()}] shipped {len(rows)} modsec_events ({SERVER_LABEL})")


def process_access():
    new = read_new_bytes(PATHS["access"], f"access_{SERVER_LABEL}")
    if not new:
        return

    rows = []
    for line in filter(None, new.split("\n")):
        p = parse_access_line(line)
        if p:
            rows.append({"server": SERVER_LABEL, **p})

    if rows:
        supabase_insert("access_logs", rows)
        print(f"[{datetime.now().isoformat()}] shipped {len(rows)} access_logs ({SERVER_LABEL})")


def process_error():
    new = read_new_bytes(PATHS["error"], f"error_{SERVER_LABEL}")
    if not new:
        return

    rows = [{"server": SERVER_LABEL, "message": line.strip()}
            for line in filter(None, new.split("\n")) if line.strip()]

    if rows:
        supabase_insert("error_logs", rows)
        print(f"[{datetime.now().isoformat()}] shipped {len(rows)} error_logs ({SERVER_LABEL})")


PROCESSORS = {"modsec": process_modsec, "access": process_access, "error": process_error}


# ---------------------------------------------------------------------------
# main loop — watchdog (inotify-backed) file watcher
# ---------------------------------------------------------------------------

class LogChangeHandler(FileSystemEventHandler):
    def __init__(self, watched_paths: dict):
        # watched_paths: {absolute_path: type_key}
        self.watched_paths = watched_paths

    def on_modified(self, event):
        if event.is_directory:
            return
        type_key = self.watched_paths.get(event.src_path)
        if type_key:
            PROCESSORS[type_key]()


def main():
    print(f"log-shipper starting for server={SERVER_LABEL}")

    # initial catch-up pass
    for proc in PROCESSORS.values():
        proc()

    watched_dirs = set()
    watched_paths = {}
    for type_key, path in PATHS.items():
        p = Path(path)
        if p.is_file():
            watched_dirs.add(str(p.parent))
            watched_paths[str(p.resolve())] = type_key
        else:
            print(f"WARNING: {path} does not exist yet, will not be watched until it does", file=sys.stderr)

    handler = LogChangeHandler(watched_paths)
    observer = Observer()
    for d in watched_dirs:
        observer.schedule(handler, d, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
