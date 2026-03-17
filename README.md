# 🛡 Netwatch

### Network Monitoring & Website Filtering System

**Version 1.0 • 2025**

---

## 📌 Overview

Netwatch is an open-source, Python-based **network monitoring and DNS-level website filtering system** designed for:

- Home networks  
- Small offices  
- Schools  
- Public Wi-Fi hotspots  

It intercepts DNS queries, checks them against a blocklist, logs activity, and displays everything on a real-time web dashboard.

> ⚠️ **Note:** Netwatch only monitors domain names (DNS level). It does **not** collect page content, credentials, or personal data.

---

## 🚀 Features

- 📊 Real-time DNS request monitoring  
- 🚫 Domain blocklist (adult, gambling, malware, social, custom)  
- 🖥 Per-device tracking (IP + MAC)  
- 🌐 Web-based dashboard with charts & logs  
- 🔔 Email & Telegram alerts  
- 📁 CSV export of logs  
- ⚙️ Dual DNS modes: Proxy & Passive Sniffer  

---

## 🏗 System Architecture

| File            | Component              | Role |
|-----------------|----------------------|------|
| `app.py`        | Flask Web App        | Dashboard UI + API (port 5000) |
| `database.py`   | Database Layer       | SQLite schema & initialization |
| `dns_engine.py` | DNS Engine           | DNS proxy/sniffer |
| `alerts.py`     | Alert Dispatcher     | Sends email/Telegram alerts |

---

## ⚙️ System Requirements

### Software

- Python **3.8+** (3.11 recommended)
- pip
- Git (optional)
- Browser (Chrome, Firefox, Edge, Safari)

### Dependencies

- flask
- dnslib
- requests
- python-dotenv
- scapy *(optional)*

---

## 🧰 Installation Guide

### 1️⃣ Install Python

```bash
python --version
```

---

### 2️⃣ Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/netwatch.git
cd netwatch
```

---

### 3️⃣ Create Virtual Environment

```bash
python -m venv venv
```

Activate:

**Windows**
```bash
venv\Scripts\activate
```

**Mac/Linux**
```bash
source venv/bin/activate
```

---

### 4️⃣ Install Dependencies

```bash
pip install flask dnslib requests python-dotenv
```

Optional:
```bash
pip install scapy
```

---

### 5️⃣ Configure Environment (Optional)

```bash
cp .env.example .env
```

Edit `.env`:

```env
NETWATCH_DB=netwatch.db

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

TELEGRAM_TOKEN=your-token
TELEGRAM_CHAT_ID=your-chat-id
```

---

### 6️⃣ Initialize Database

```bash
python database.py
```

---

### 7️⃣ Start Dashboard

```bash
python app.py
```

Open:

👉 http://localhost:5000

---

### 8️⃣ Start DNS Engine

```bash
python dns_engine.py --mode proxy --port 5353 --upstream 8.8.8.8
```

---

### 9️⃣ Start Alerts (Optional)

```bash
python alerts.py
```

---

## 📁 Project Structure

```bash
netwatch/
├── app.py
├── database.py
├── dns_engine.py
├── alerts.py
├── requirements.txt
├── .env.example
├── .env
├── netwatch.db
└── templates/
    └── dashboard.html
```

---

## 🛡 Netwatch v1.0

**Network Monitoring & Website Filtering System**
