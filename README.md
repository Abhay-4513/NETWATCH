# 🛡️ NetWatch

**Network Monitoring & Website Filtering System**

A Python-based DNS-level network monitor that intercepts DNS queries from every device on your Wi-Fi, filters blocked domains, logs all activity, and displays everything on a real-time web dashboard.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0+-black?logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightblue?logo=sqlite)

---

## 📸 Dashboard Preview

> Real-time dashboard at `http://localhost:5000` showing device activity, DNS logs, and blocked domain management.

---

## ✨ Features

- 🔍 **DNS-level filtering** — blocks domains before the browser makes any connection
- 📊 **Real-time dashboard** — charts, live feed, per-device activity
- 🏷️ **Auto categorization** — search, media, adult, gambling, malware, social, and more
- 💻 **Device tracking** — identifies devices by IP and MAC address with vendor info
- 🚨 **Alerts** — Telegram bot and email (Gmail) notifications on blocked access
- 🎭 **Simulate mode** — test the dashboard without root access
- 📥 **CSV export** — download full access logs
- 🔁 **Toggle domains** — pause/resume blocked domains without deleting them

---

## 📁 Project Structure

```
netwatch/
├── app.py                    # Flask web app + all REST API routes
├── requirements.txt          # Python dependencies
├── .env.example              # Config template
│
├── templates/
│   └── dashboard.html        # Admin dashboard (single-page app)
│
└── utils/
    ├── __init__.py
    ├── database.py           # DatabaseManager — schema, queries, block checking
    ├── dns_server.py         # DNS server via dnslib (port 53)
    ├── dns_monitor.py        # DNS capture, simulation, live Scapy sniffing
    ├── alert_manager.py      # Email + Telegram alert dispatcher
    ├── device_tracker.py     # ARP-based network device scanner
    └── domain_categorizer.py # Classifies domains by category
```

---

## 🚀 Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/netwatch.git
cd netwatch
```

### 2. Create a virtual environment

```bash
# Create
python -m venv venv

# Activate — Windows
venv\Scripts\activate

# Activate — Mac / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install flask dnslib requests python-dotenv
```

> **Note:** `scapy` is optional — only needed for passive network sniffing mode.
> ```bash
> pip install scapy
> ```

### 4. Configure alerts (optional)

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Telegram
TELEGRAM_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id

# Email (Gmail)
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
EMAIL_TO=admin@example.com
```

> You can also configure alerts later through the dashboard Settings page.

### 5. Run the app

> ⚠️ **The DNS server requires Administrator / root privileges** to bind to port 53.

**Windows** — open terminal as Administrator:
```bash
python app.py
```

**Mac / Linux:**
```bash
sudo python app.py
```

Open your browser at **http://localhost:5000**

---

## 🎭 Running Without Admin Rights (Demo Mode)

If you can't run as Administrator, comment out the DNS server lines in `app.py` and start the traffic simulator instead:

```python
# In app.py — comment out:
# from utils.dns_server import start_dns_server
# start_dns_server(db, dns_monitor)

# Add this instead:
import threading
t = threading.Thread(target=dns_monitor.start_simulation, daemon=True)
t.start()
```

Then run normally:
```bash
python app.py
```

The dashboard, charts, and all API endpoints work identically — you just won't see real device traffic.

---

## 🌐 Network Setup

To monitor **all devices** on your network, point your router's DNS to the machine running NetWatch:

1. Log into your router admin panel (usually `http://192.168.1.1`)
2. Find **DNS settings** under DHCP / LAN configuration
3. Set **Primary DNS** to the IP address of the NetWatch machine
4. NetWatch must be running with port 53 active

To monitor only **your own device**, change your PC's DNS settings to `127.0.0.1`.

---

## 📊 Dashboard Pages

| Page | Description |
|------|-------------|
| **Overview** | Stat cards (requests, blocked, block rate, active devices), hourly timeline chart, top domains |
| **Access Logs** | Full log table — filter by status, device IP, or time window |
| **Devices** | All devices with MAC, vendor, request count, and last seen time |
| **Blocked Domains** | Add, remove, or toggle domains on the blocklist |
| **Top Domains** | Most accessed domains ranked by request count |
| **Categories** | Traffic breakdown by category for the last 24 hours |
| **Live Feed** | Real-time stream of incoming DNS requests |
| **Settings** | Configure Telegram, email, alert threshold, DNS interface |

---

## 🔌 REST API

Base URL: `http://localhost:5000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Today's totals: requests, blocked, block rate, active devices |
| `GET` | `/api/logs` | Access logs — params: `limit`, `status`, `device_ip`, `hours` |
| `GET` | `/api/devices` | All known devices with aggregate stats |
| `GET` | `/api/devices/<mac>` | Single device + last 50 DNS requests |
| `PUT` | `/api/devices/<mac>` | Update device name or notes |
| `GET` | `/api/top-domains` | Top domains by request count — params: `hours`, `limit` |
| `GET` | `/api/timeline` | Hourly allowed/blocked counts for charts |
| `GET` | `/api/categories` | Traffic by category for last 24h |
| `GET` | `/api/blocked-domains` | Full blocklist with category, reason, active status |
| `POST` | `/api/blocked-domains` | Add domain — body: `{domain, category, reason}` |
| `DELETE` | `/api/blocked-domains/<id>` | Soft-delete (sets active=0) |
| `POST` | `/api/blocked-domains/<id>/toggle` | Toggle domain active/inactive |
| `GET` | `/api/export/csv` | Download logs as CSV — param: `hours` |
| `GET` | `/api/settings` | Current settings (passwords masked) |
| `PUT` | `/api/settings` | Update any setting key-value pair |
| `POST` | `/api/simulate` | Inject a fake DNS event for testing |
| `GET` | `/api/recent-events` | Latest 20 events since a given ID (live feed polling) |

**Example — simulate a DNS event:**
```bash
curl -X POST http://localhost:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com", "device_ip": "192.168.1.100"}'
```

**Example — block a domain:**
```bash
curl -X POST http://localhost:5000/api/blocked-domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "category": "custom", "reason": "Test block"}'
```

---

## 🗄️ Database Schema

NetWatch uses a single SQLite file `netwatch.db` (auto-created on first run).

<details>
<summary><strong>access_logs</strong> — one row per DNS request</summary>

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `device_ip` | TEXT | Source device IP |
| `device_mac` | TEXT | Source device MAC |
| `domain` | TEXT | Queried domain name |
| `category` | TEXT | Auto-assigned category |
| `status` | TEXT | `ALLOWED` or `BLOCKED` |
| `timestamp` | TIMESTAMP | UTC datetime |
| `response_time_ms` | INTEGER | DNS response time |

</details>

<details>
<summary><strong>devices</strong> — one row per unique MAC address</summary>

| Column | Type | Description |
|--------|------|-------------|
| `mac_address` | TEXT UNIQUE | Hardware address |
| `ip_address` | TEXT | Most recent IP |
| `hostname` | TEXT | Resolved hostname |
| `device_name` | TEXT | Admin-assigned label |
| `device_type` | TEXT | laptop / mobile / smart-tv / gaming |
| `vendor` | TEXT | Manufacturer from MAC OUI |
| `first_seen` | TIMESTAMP | First observed |
| `last_seen` | TIMESTAMP | Most recent activity |

</details>

<details>
<summary><strong>blocked_domains</strong> — the blocklist</summary>

| Column | Type | Description |
|--------|------|-------------|
| `domain` | TEXT UNIQUE | Domain to block |
| `category` | TEXT | adult / gambling / malware / social / custom |
| `reason` | TEXT | Human-readable reason |
| `active` | INTEGER | `1` = enforced, `0` = paused |
| `added_at` | TIMESTAMP | When domain was added |

</details>

---

## 🔔 Alert Configuration

### Telegram

1. Message **@BotFather** on Telegram → `/newbot`
2. Copy the bot token
3. Send any message to your new bot
4. Visit `https://api.telegram.org/bot<TOKEN>/getUpdates` — copy the `chat.id`
5. Enter both values in the NetWatch **Settings** page

### Email (Gmail)

1. Enable 2-Factor Auth on your Google account
2. Go to **myaccount.google.com → Security → App Passwords**
3. Generate a password for "Mail" — copy the 16-character code
4. Enter your Gmail address, App Password, and recipient email in **Settings**

> Alerts fire on the **first** blocked attempt and every **5th** attempt after that per device-domain pair, preventing notification flooding.

---

## 🧩 How DNS Filtering Works

```
Device makes request → DNS query sent to NetWatch (port 53)
       ↓
NetWatchResolver.resolve() receives query via dnslib
       ↓
db.is_domain_blocked() checks exact match + subdomain match
       ↓
  BLOCKED?  →  Return empty reply — site never loads
  ALLOWED?  →  Forward to 8.8.8.8 — return real answer
       ↓
Log to database + optionally send alert
```

**Subdomain matching** is automatic — blocking `pornhub.com` also blocks `www.pornhub.com`, `images.pornhub.com`, etc.

---

## 🏷️ Domain Categories

| Category | Examples |
|----------|---------|
| `search` | google.com, bing.com, duckduckgo.com |
| `social` | facebook.com, instagram.com, twitter.com, reddit.com |
| `media` | youtube.com, netflix.com, spotify.com, twitch.tv |
| `development` | github.com, stackoverflow.com, gitlab.com |
| `shopping` | amazon.com, ebay.com, etsy.com |
| `news` | bbc.com, cnn.com, reuters.com |
| `business` | zoom.us, slack.com, microsoft.com |
| `adult` | blocked — keyword + lookup matching |
| `gambling` | blocked — keyword + lookup matching |
| `malware` | blocked — known hosts + keyword heuristics |

---

## 🛠️ Troubleshooting

| Error | Fix |
|-------|-----|
| `No module named 'dnslib'` | `pip install dnslib` |
| `No module named 'database'` | You have an old `app.py` — use the correct version where imports are `from utils.database import ...` |
| `No module named 'domain_categorizer'` | Same — old `app.py`. Correct import: `from utils.domain_categorizer import DomainCategorizer` |
| Permission denied on port 53 | Windows: run terminal as Administrator. Linux/Mac: `sudo python app.py` |
| Address already in use — port 53 | Another DNS service is running. Stop it or change the port in `utils/dns_server.py` |
| Address already in use — port 5000 | Change port in `app.py`: `app.run(port=5001)` |
| MAC shows as `unknown` | Normal on Windows — `/proc/net/arp` doesn't exist. Devices still tracked by IP. |
| Dashboard shows no data | Use `/api/simulate` to inject test events, or use Demo Mode (see above) |

---

## 📋 Quick Reference

| Action | Command |
|--------|---------|
| Activate venv (Windows) | `venv\Scripts\activate` |
| Activate venv (Mac/Linux) | `source venv/bin/activate` |
| Install packages | `pip install flask dnslib requests python-dotenv` |
| Start app (Windows admin) | `python app.py` |
| Start app (Linux/Mac) | `sudo python app.py` |
| Deactivate venv | `deactivate` |

| Resource | URL |
|----------|-----|
| Dashboard | http://localhost:5000 |
| Stats API | http://localhost:5000/api/stats |
| Logs API | http://localhost:5000/api/logs |
| Devices | http://localhost:5000/api/devices |
| Blocked Domains | http://localhost:5000/api/blocked-domains |
| Export CSV | http://localhost:5000/api/export/csv |

---

## ⚖️ Privacy & Ethics

- ✅ Records **domain names only** — not URLs, page content, or passwords
- ✅ All data stored **locally** — nothing sent to third parties
- ✅ No physical location tracking of any kind
- ❌ **Do not deploy on networks you don't own or administer**
- ❌ Monitoring users without their knowledge may violate privacy laws in your jurisdiction

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
