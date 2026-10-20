# WAF Centralized Monitoring & Management System
## Production Deployment & Operational Guide

| Attribute | Specification |
|:---|:---|
| **Supported Engines** | **Apache 2.4** (`mod_security2`) & **Nginx** (`libmodsecurity3`) |
| **Ruleset Engine** | **OWASP ModSecurity Core Rule Set (CRS v3.3+)** |
| **Data Backend** | **Supabase** (PostgreSQL 15+ & PostgREST API) |
| **Log Shipper** | Python 3 + `watchdog` daemon (inotify event pipeline) |
| **Enrichment Pipeline** | Python 3 + MaxMind GeoLite2 City (`geo_enrich.py` cron) |
| **SOC Dashboard** | Python 3 Flask / Gunicorn Security Operations Center Console |
| **Document Version** | 2.1 — Verified Production Deployment Reference |

---

## 1. System Architecture Overview

The system captures, ships, enriches, and manages Layer 7 HTTP security telemetry across one or more web servers:

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      WEB SERVER (Apache 2.4 / Nginx)                   │
 │                                                                        │
 │   Incoming HTTP Request                                                │
 │            │                                                           │
 │            ▼                                                           │
 │   [ModSecurity Engine] ──(OWASP CRS v3.3+)──► Blocks attack (HTTP 403) │
 │            │                                                           │
 │            ▼                                                           │
 │   [modsec_audit.log] + [access.log] + [error.log]                      │
 └────────────┬───────────────────────────────────────────────────────────┘
              │ inotify tailing
              ▼
 ┌──────────────────────────────────────┐
 │   log-shipper@<server>.service       │
 │   (/opt/log-shipper/shipper.py)      │
 └────────────┬─────────────────────────┘
              │ HTTPS REST (service_role key)
              ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      SUPABASE CLOUD / POSTGRESQL                       │
 │                                                                        │
 │   • modsec_events   (Attack logs, triggered rules, client classification)│
 │   • access_logs     (HTTP traffic stream)                              │
 │   • error_logs      (Server error stream)                              │
 │   • ip_geo_cache    (Enriched country, city, coordinates)              │
 │   • admin_actions   (Audit trail for rule modifications)               │
 └────────────▲───────────────────────────────────────▲───────────────────┘
              │ Reads & Caches                        │ Read-only (anon key)
              │ (every 2 min cron)                    │ & Audited Actions
 ┌────────────┴─────────────┐            ┌────────────┴───────────────────┐
 │ geo_enrich.py            │            │ WAF Security Operations Center │
 │ (MaxMind GeoLite2 MMDB)  │            │ (Flask Console on Port 8082)   │
 └──────────────────────────┘            └────────────┬───────────────────┘
                                                      │ Privileged sudo execution
                                                      ▼
                                         ┌────────────────────────────────┐
                                         │ /opt/waf-admin/scripts/        │
                                         │ • add-custom-rule.sh           │
                                         │ • remove-rule.sh / restore...  │
                                         │ • update-crs.sh / crs-status.sh│
                                         └────────────────────────────────┘
```

---

## 2. Server Prerequisites & User-Supplied Inputs

### 2.1 System Packages
Ensure the following packages and tools are installed on your Linux server (Ubuntu 22.04 / 24.04 LTS recommended):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip curl git jq \
  libmaxminddb0 libmaxminddb-dev mmdb-bin
```

### 2.2 The 3 Inputs You Must Supply Yourself
Before beginning, make sure you have the following project-specific variables ready:

1. **Supabase Project Credentials** (from your Supabase Dashboard → *Project Settings* → *API*):
   - **`SUPABASE_URL`**: `https://[YOUR_PROJECT_ID].supabase.co`
   - **`SUPABASE_SERVICE_KEY`** (`service_role` secret key): Required by the backend log shipper in `/etc/log-shipper/apache.env` to write logs securely bypassing RLS.
   - **`SUPABASE_ANON_KEY`** (`anon` public key): Required by the dashboard in `config.py` for read-only user queries.

2. **MaxMind GeoLite2 City Database (`GeoLite2-City.mmdb`)**:
   - Required by the geolocation enrichment cron job.
   - Create a free account at [MaxMind](https://www.maxmind.com/), download the `GeoLite2-City.mmdb` file, and place it at `/opt/log-shipper/GeoLite2-City.mmdb`.

3. **Dashboard Web Console Password**:
   - A secure password of your choice configured in `config.py` (`APP_PASSWORD = "YourStrongPasswordHere!"`).

---

## PHASE 1: Supabase Database Schema

Open the **SQL Editor** in your Supabase dashboard and run the complete database migration script:

```sql
-- 1. Core ModSecurity Events Table
drop table if exists modsec_events cascade;
create table modsec_events (
  id bigint generated always as identity primary key,
  server text not null,                     -- 'apache' or 'nginx'
  event_time timestamptz not null default now(),
  client_ip text not null,
  request_line text,
  method text,
  uri text,
  http_status text,
  blocked boolean default false,
  rules jsonb default '[]'::jsonb,
  raw_id text,
  user_agent text,
  client_type text default 'unknown',       -- human | bot | ai_agent | verified_bot | script_bot
  bot_score integer,                         -- 1-99, lower = more bot-like
  verified_bot boolean default false,
  classification_reasons jsonb default '[]'::jsonb,
  created_at timestamptz default now()
);

-- Indexes for high-speed dashboard telemetry
create unique index if not exists modsec_events_raw_id_idx on modsec_events (raw_id) where raw_id is not null;
create index if not exists modsec_events_event_time_idx on modsec_events (event_time desc);
create index if not exists modsec_events_client_ip_idx on modsec_events (client_ip);
create index if not exists modsec_events_server_idx on modsec_events (server);

-- 2. Access Logs Table
drop table if exists access_logs cascade;
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
create index if not exists access_logs_created_at_idx on access_logs (created_at desc);

-- 3. Error Logs Table
drop table if exists error_logs cascade;
create table error_logs (
  id bigint generated always as identity primary key,
  server text not null,
  message text,
  created_at timestamptz default now()
);
create index if not exists error_logs_created_at_idx on error_logs (created_at desc);

-- 4. IP Geolocation Cache Table
drop table if exists ip_geo_cache cascade;
create table ip_geo_cache (
  ip text primary key,
  country text,
  country_code text,
  region text,
  city text,
  lat double precision,
  lon double precision,
  lookup_status text default 'ok',          -- 'ok', 'fail', 'private'
  updated_at timestamptz default now()
);

-- 5. Administrative Audit Log Table
drop table if exists admin_actions cascade;
create table admin_actions (
  id bigint generated always as identity primary key,
  action_type text not null,                -- 'crs_update' | 'rule_remove' | 'rule_add' | 'rule_restore'
  target text,                              -- rule id, keyword, or CRS version
  success boolean not null,
  output text,
  performed_by text default 'soc-admin',
  performed_at timestamptz default now()
);
create index if not exists admin_actions_performed_at_idx on admin_actions (performed_at desc);

-- 6. Row Level Security (RLS) Policies
alter table modsec_events enable row level security;
alter table access_logs enable row level security;
alter table error_logs enable row level security;
alter table ip_geo_cache enable row level security;
alter table admin_actions enable row level security;

-- Read-only access for the web dashboard (via Anon Key)
create policy "public read modsec_events" on modsec_events for select using (true);
create policy "public read access_logs" on access_logs for select using (true);
create policy "public read error_logs" on error_logs for select using (true);
create policy "public read ip_geo_cache" on ip_geo_cache for select using (true);
create policy "public read admin_actions" on admin_actions for select using (true);

-- Writes are restricted strictly to service_role (log-shipper & admin scripts)
```

---

## PHASE 2: Web Server & ModSecurity Configuration

### Option A: Apache 2.4 Configuration (Recommended for Apache Environments)

1. **Install Apache ModSecurity & CRS:**
   ```bash
   sudo apt install -y apache2 libapache2-mod-security2
   sudo a2enmod security2 headers unique_id
   ```

2. **Configure ModSecurity (`/etc/modsecurity/modsecurity.conf`):**
   ```bash
   sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
   ```
   Edit `/etc/modsecurity/modsecurity.conf` and ensure the following directives are active:
   ```apache
   SecRuleEngine On
   SecRequestBodyAccess On
   SecResponseBodyAccess Off

   # Audit Log Configuration
   SecAuditEngine RelevantOnly
   SecAuditLogRelevantStatus "^(?:5|4(?!04))"
   SecAuditLogParts ABIJDEFHZ
   SecAuditLogType Serial
   SecAuditLog /var/log/apache2/modsec_audit.log
   ```

3. **Initialize the Audit Log with Proper Permissions:**
   ```bash
   sudo touch /var/log/apache2/modsec_audit.log
   sudo chown www-data:adm /var/log/apache2/modsec_audit.log
   sudo chmod 640 /var/log/apache2/modsec_audit.log
   ```

4. **Install & Track OWASP CRS as a Git Repository:**
   > ⚠️ **CRITICAL REQUIREMENT:** The management scripts (`crs-status.sh`, `update-crs.sh`) require `/usr/local/modsecurity-crs/` to be a valid Git repository to check tags and perform automated upstream updates.
   ```bash
   sudo rm -rf /usr/local/modsecurity-crs
   sudo git clone https://github.com/coreruleset/coreruleset.git /usr/local/modsecurity-crs
   cd /usr/local/modsecurity-crs
   sudo git checkout v3.3.8
   sudo cp crs-setup.conf.example crs-setup.conf
   ```

5. **Set Up Custom Rules & Rule Exclusions Directory:**
   ```bash
   sudo mkdir -p /usr/local/modsecurity-crs/rules/custom
   sudo touch /usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf
   sudo touch /usr/local/modsecurity-crs/rules/custom/custom-rules.conf
   sudo chown -R root:root /usr/local/modsecurity-crs/rules/custom
   sudo chmod -R 755 /usr/local/modsecurity-crs/rules/custom
   ```

6. **Wire Up ModSecurity in Apache (`/etc/apache2/mods-enabled/security2.conf`):**
   ```apache
   <IfModule security2_module>
       SecDataDir /var/cache/modsecurity
       IncludeOptional /etc/modsecurity/*.conf
       IncludeOptional /usr/local/modsecurity-crs/crs-setup.conf
       IncludeOptional /usr/local/modsecurity-crs/rules/*.conf
       IncludeOptional /usr/local/modsecurity-crs/rules/custom/*.conf
   </IfModule>
   ```

7. **Test Configuration and Reload Apache:**
   ```bash
   sudo apache2ctl configtest
   # Output must be: Syntax OK
   sudo systemctl reload apache2
   ```

---

### Option B: Nginx Configuration

1. **Install Nginx ModSecurity v3 Connector:**
   ```bash
   sudo apt install -y nginx libmodsecurity3
   ```

2. **Configure ModSecurity Include in `/etc/nginx/modsec/main.conf`:**
   ```nginx
   Include /etc/nginx/modsec/modsecurity.conf
   Include /usr/local/modsecurity-crs/crs-setup.conf
   Include /usr/local/modsecurity-crs/rules/*.conf
   Include /usr/local/modsecurity-crs/rules/custom/*.conf
   ```

3. **Verify and Reload Nginx:**
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

---

## PHASE 3: Log Shipper & Ingestion Pipeline

The log shipper continuously monitors `/var/log/apache2/modsec_audit.log` (or Nginx audit log), parses events into structured JSON, and ships them via HTTPS to Supabase.

1. **Create Virtual Environment & Install Dependencies:**
   ```bash
   sudo mkdir -p /opt/log-shipper /var/lib/log-shipper /etc/log-shipper
   sudo python3 -m venv /opt/log-shipper/venv

   # Note: python-dotenv is required for environment parsing
   sudo /opt/log-shipper/venv/bin/pip install --upgrade pip
   sudo /opt/log-shipper/venv/bin/pip install requests watchdog geoip2 python-dotenv
   ```

2. **Deploy Shipper Script:**
   ```bash
   # From the repository root:
   sudo cp deployment_scripts/shipper.py /opt/log-shipper/shipper.py
   sudo chmod 755 /opt/log-shipper/shipper.py
   ```

3. **Create Environment File (`/etc/log-shipper/apache.env`):**
   ```bash
   sudo tee /etc/log-shipper/apache.env > /dev/null << 'EOF'
   SUPABASE_URL=https://[YOUR_PROJECT_ID].supabase.co
   SUPABASE_SERVICE_KEY=[YOUR_SUPABASE_SERVICE_ROLE_KEY]
   SERVER_LABEL=apache
   EOF

   # Secure the credentials:
   sudo chown root:root /etc/log-shipper/*.env
   sudo chmod 600 /etc/log-shipper/*.env
   ```
   *(For Nginx environments, create `/etc/log-shipper/nginx.env` with `SERVER_LABEL=nginx`)*

4. **Install Systemd Shipper Service (`/etc/systemd/system/log-shipper@.service`):**
   ```ini
   [Unit]
   Description=WAF Log Shipper for %i -> Supabase
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

5. **Start and Enable Service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now log-shipper@apache.service

   # Check status:
   sudo systemctl status log-shipper@apache.service
   ```

---

## PHASE 4: Geolocation Enrichment Pipeline

1. **Deploy Enrichment Script:**
   ```bash
   sudo cp deployment_scripts/geo_enrich.py /opt/log-shipper/geo_enrich.py
   sudo chmod 755 /opt/log-shipper/geo_enrich.py
   ```

2. **Install MaxMind GeoLite2 City Database:**
   Place `GeoLite2-City.mmdb` into `/opt/log-shipper/`:
   ```bash
   # Verify the file is present and readable:
   ls -la /opt/log-shipper/GeoLite2-City.mmdb
   ```

3. **Configure Cron Job:**
   Open root cron:
   ```bash
   sudo crontab -e
   ```
   Add the 2-minute recurring enrichment job:
   ```cron
   */2 * * * * /opt/log-shipper/venv/bin/python3 /opt/log-shipper/geo_enrich.py >> /var/log/geo_enrich.log 2>&1
   ```

4. **Initialize Log & Test Run:**
   ```bash
   sudo touch /var/log/geo_enrich.log
   sudo /opt/log-shipper/venv/bin/python3 /opt/log-shipper/geo_enrich.py
   cat /var/log/geo_enrich.log
   ```

---

## PHASE 5: Privileged Administrative Management Scripts

These scripts allow the SOC console to query CRS status, add custom rules, and disable/restore rules safely without granting arbitrary root privileges to the web app.

1. **Deploy Scripts to `/opt/waf-admin/scripts/`:**
   ```bash
   sudo mkdir -p /opt/waf-admin/scripts /var/log/waf-admin
   sudo cp admin_scripts/*.sh /opt/waf-admin/scripts/
   sudo cp manage_rules.py /opt/waf-admin/scripts/

   sudo chown -R root:root /opt/waf-admin/scripts
   sudo chmod 700 /opt/waf-admin/scripts/*
   sudo chmod 755 /var/log/waf-admin
   ```

2. **Configure Sudoers Privileges (`/etc/sudoers.d/waf-admin`):**
   ```bash
   sudo visudo -f /etc/sudoers.d/waf-admin
   ```
   Add the following (replace `ubuntu` with your application execution user):
   ```sudoers
   ubuntu ALL=(ALL) NOPASSWD: /opt/waf-admin/scripts/add-custom-rule.sh, \
     /opt/waf-admin/scripts/crs-status.sh, \
     /opt/waf-admin/scripts/remove-rule.sh, \
     /opt/waf-admin/scripts/restore-rule.sh, \
     /opt/waf-admin/scripts/update-crs.sh, \
     /opt/waf-admin/scripts/manage_rules.py
   ```

3. **Verify Script Execution:**
   ```bash
   # Test CRS status check (must return valid JSON):
   sudo /opt/waf-admin/scripts/crs-status.sh
   # Expected: {"installed": true, "version": "v3.3.8", ...}
   ```

---

## PHASE 6: Web Dashboard Deployment

1. **Configure Environment in Repository (`config.py` / `.env`):**
   ```bash
   cd /home/ubuntu/WAF-Dashboard
   ```
   Ensure [config.py](file:///home/ubuntu/WAF-Dashboard/config.py) contains:
   ```python
   SUPABASE_URL = "https://[YOUR_PROJECT_ID].supabase.co"
   SUPABASE_ANON_KEY = "[YOUR_SUPABASE_ANON_PUBLIC_KEY]"
   APP_PASSWORD = "[YOUR_STRONG_DASHBOARD_PASSWORD]"
   AUTH_ENABLED = True
   ```

2. **Run as a Managed Systemd Service (`/etc/systemd/system/waf-dashboard.service`):**
   ```ini
   [Unit]
   Description=WAF Security Operations Center Console
   After=network.target

   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/home/ubuntu/WAF-Dashboard
   ExecStart=/home/ubuntu/WAF-Dashboard/myenv/bin/python3 app.py
   Restart=always
   RestartSec=3
   Environment=PYTHONUNBUFFERED=1

   [Install]
   WantedBy=multi-user.target
   ```

3. **Start and Enable Service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now waf-dashboard.service
   sudo systemctl status waf-dashboard.service
   ```

4. **Access the Console:**
   - URL: `http://<SERVER_IP>:8082/`
   - Default Password: `[YOUR_STRONG_DASHBOARD_PASSWORD]`

---

## PHASE 7: End-to-End Attack Verification Suite

To verify that the entire pipeline (ModSecurity -> Local Audit Log -> Log Shipper -> Supabase -> SOC Dashboard) is functioning:

1. **Deploy a Local Test Site:**
   Ensure `/var/www/html/index.html` exists and is served by Apache.

2. **Execute Common Attack Vectors:**
   ```bash
   # 1. SQL Injection (Rule 942100)
   curl -s -i "http://127.0.0.1/index.html?id=1'+OR+'1'='1" | head -n 5

   # 2. Remote Command Execution (Rule 932100)
   curl -s -i "http://127.0.0.1/index.html?exec=/bin/cat+/etc/passwd" | head -n 5

   # 3. Cross-Site Scripting (Rule 941100)
   curl -s -i "http://127.0.0.1/index.html?q=<script>alert(1)</script>" | head -n 5

   # 4. Path Traversal (Rule 930100)
   curl -s -i "http://127.0.0.1/index.html?file=../../../../etc/shadow" | head -n 5
   ```
   **Expected Response:** `HTTP/1.1 403 Forbidden` for all attacks.

3. **Verify Dashboard Telemetry:**
   - Check the **Recent Events** log stream on `http://127.0.0.1:8082/`.
   - The requests will appear with `⛔ 403 BLOCKED`, HTTP status `403`, client IP `127.0.0.1`, and rule tags `#942100`, `#932100`, etc.

---

## 8. Stage-by-Stage Verification Checklist

Use this checklist as you progress through each deployment phase to confirm your setup:

| Stage / Milestone | Verification Command | Expected Output |
|:---|:---|:---|
| **1. Apache & ModSec Config** | `sudo apache2ctl configtest` | `Syntax OK` |
| **2. Audit Log File** | `ls -la /var/log/apache2/modsec_audit.log` | Ownership `www-data:adm` and permissions `640` |
| **3. CRS Git Repository** | `cd /usr/local/modsecurity-crs && git status` | `On branch master` (or detached at tag `v3.3.8`) |
| **4. Log Shipper Service** | `sudo systemctl status log-shipper@apache.service` | `Active: active (running)` |
| **5. Geo-Enrichment Cron** | `sudo tail -n 20 /var/log/geo_enrich.log` | `Processed X IP(s)` or `No un-enriched IPs` |
| **6. CRS Admin Scripts** | `sudo /opt/waf-admin/scripts/crs-status.sh` | Valid JSON with `"installed": true, "version": "v3.3.8"` |
| **7. Sudoers Configuration** | `sudo -u ubuntu sudo -n /opt/waf-admin/scripts/crs-status.sh` | Returns JSON without prompting for a password |
| **8. Dashboard Service** | `sudo systemctl status waf-dashboard.service` | `Active: active (running)` on port 8082 |
| **9. Attack Mitigation** | `curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1/?exec=/bin/sh"` | **`403`** (Forbidden) |
| **10. SOC Live Stream** | Open `http://<SERVER_IP>:8082/` in your browser | Event appears in the real-time event timeline |

---

## 9. Troubleshooting & Common Pitfalls Reference

| Symptom / Error | Root Cause | Solution |
|:---|:---|:---|
| `ERROR: ... is not a git repository` | `/usr/local/modsecurity-crs/` was extracted from an archive without `.git` | Clone via `git clone https://github.com/coreruleset/coreruleset.git /usr/local/modsecurity-crs` and checkout tag. |
| `ModuleNotFoundError: No module named 'dotenv'` | `python-dotenv` missing in shipper venv | Run `/opt/log-shipper/venv/bin/pip install python-dotenv`. |
| ModSecurity does not block attacks | Engine running in `DetectionOnly` | Change `SecRuleEngine DetectionOnly` to `SecRuleEngine On` in `/etc/modsecurity/modsecurity.conf` and reload Apache. |
| Log shipper service fails to start | Missing environment file or permissions | Ensure `/etc/log-shipper/apache.env` exists with mode `600` and contains valid `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`. |
| Audit log stays 0 bytes | Apache lacks write access to audit log | Run `sudo chown www-data:adm /var/log/apache2/modsec_audit.log && sudo chmod 640 /var/log/apache2/modsec_audit.log`. |
| Sudo error when managing rules | Sudoers path mismatch | Check `/etc/sudoers.d/waf-admin` matches exact user and paths. Validate with `sudo visudo -c`. |
