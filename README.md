# 🛡️ WAF Security Console & Dashboard

A real-time, production-grade **Web Application Firewall (WAF) Security Console** built with Python Flask, Supabase, and ModSecurity/CRS. Provides threat intelligence, traffic classification, interactive geolocation maps, actionable insights with 1-click server mitigation code generation, and ModSecurity rule exclusion management.

---

## 🌟 Key Features

- **📊 Real-Time Security Dashboard**:
  - Live metric updates (Total Requests, Blocked, Passed, Block Rate).
  - Dynamic **Threat Index** composite score (0–100) with 24-hour sparkline trends.
  - Auto-refresh every 10 seconds with pause/resume controls.

- **🤖 Traffic & Bot Classification**:
  - Distinguishes traffic between **Humans**, **Verified Bots**, **AI Crawlers**, and **Malicious Bots**.
  - Analyzes behavioral patterns, User-Agent anomalies, and request velocity.

- **💡 Actionable Insights & 1-Click Mitigation**:
  - Automatic detection of Brute Force, Privilege Escalation, SQLi/XSS, and Bot Campaigns.
  - Generates instant firewall rule snippets for **Nginx**, **Apache**, **ModSecurity**, and **iptables**.

- **🗺️ Interactive Geolocation Intelligence Map**:
  - Live spatial mapping powered by Leaflet.js.
  - Features **Markers**, **Heatmap**, and **Attack Lines** showing origin-to-target attack vectors.

- **⚙️ ModSecurity / CRS Rule Management**:
  - Manage rules directly from the web console.
  - Enable/disable rules, view status, and add custom CRS exclusions seamlessly.

- **📥 Data Export & Audit Log**:
  - Download attack log datasets in CSV format.
  - Track rule modifications and admin action logs.

---

## 🏗️ Architecture & Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Backend Framework** | Python 3, Flask, Gunicorn |
| **Database & API** | Supabase (PostgreSQL), `supabase-py` client |
| **Log Ingestion & Shipper** | Python watchdog daemon, GeoIP2 (`MaxMind GeoLite2`) |
| **WAF Engine** | ModSecurity v3 / OWASP Core Rule Set (CRS) |
| **Frontend UI** | HTML5, Vanilla CSS, JS (ES6+) |
| **Visualization** | Chart.js (Trends/Breakdowns), Leaflet.js (Map & Heatmap) |

---

## 🚀 Quick Start & Local Setup

### Prerequisites
- Python 3.8+
- Supabase account & project database credentials
- ModSecurity / OWASP CRS installed on server (optional for dashboard mode)

### 1. Clone the Repository
```bash
git clone https://github.com/yonnn101/WAF-Dashboard.git
cd WAF-Dashboard
```

### 2. Create Virtual Environment & Install Dependencies
```bash
python3 -m venv myenv
source myenv/bin/activate  # On Windows: myenv\Scripts\activate
pip install -r requirements.txt
```

### 3. Environment Configuration
Create a `.env` file or export environment variables:
```env
SUPABASE_URL=https://your-supabase-project.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key
APP_PASSWORD=your_secure_admin_password
AUTH_ENABLED=true
```

### 4. Run the Application
```bash
python app.py
```
Access the dashboard at `http://localhost:5000`.

---

## 📜 Directory Structure

```text
├── admin_scripts/            # ModSecurity & CRS management shell scripts
│   ├── add-custom-rule.sh
│   ├── crs-status.sh
│   ├── remove-rule.sh
│   ├── restore-rule.sh
│   └── update-crs.sh
├── deployment_scripts/       # Log shipping & GeoIP enrichment daemons
│   ├── geo_enrich.py
│   └── shipper.py
├── static/                   # Static assets
│   ├── css/
│   │   └── style.css         # Modern, responsive UI theme
│   └── js/
│       ├── app.js            # Main dashboard controller & filters
│       └── charts.js         # Chart.js & Leaflet map initializers
├── templates/                # Jinja2 HTML templates
│   ├── index.html            # Dashboard main view
│   └── login.html            # Authentication view
├── app.py                    # Main Flask application & API routes
├── auth.py                   # Authentication decorator & session helpers
├── bot_detector.py           # User-Agent & behavioral bot detection
├── config.py                 # Application configuration & env loader
├── data.py                   # Database query handlers & filters
├── insights_engine.py        # Threat aggregation & insight generation
├── manage_rules.py           # CRS rule management interface
├── threat_index.py           # Threat Index calculation algorithms
├── supabase_client.py        # Supabase DB connection client
├── requirements.txt          # Python dependencies
├── USER_GUIDE.md             # Detailed user manual
└── WAF-Deployment-Guide.md   # Server deployment & ModSecurity setup guide
```

---

## 📚 Documentation

For detailed deployment guides and user instructions, refer to:
- 📖 [User Guide](USER_GUIDE.md) — Complete walkthrough of dashboard features and threat workflows.
- 🛠️ [WAF Deployment Guide](WAF-Deployment-Guide.md) — Step-by-step production deployment guide for Nginx, ModSecurity, and Log Shipper.

---

## 🔒 Security & Best Practices

- Always set a strong `APP_PASSWORD` and use HTTPS in production.
- Keep Supabase service keys secure and do not check `.env` into version control.
- Refer to [.gitignore](.gitignore) for excluded files and build artifacts.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
