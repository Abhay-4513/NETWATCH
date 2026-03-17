# 🛡 Netwatch

### Network Monitoring & Website Filtering System

---

## 📌 Overview

Netwatch is a Python-based network monitoring and DNS filtering system with a real-time dashboard.

---

## 🚀 Features

- Real-time DNS monitoring  
- Website blocking (DNS level)  
- Device tracking  
- Web dashboard  
- Modular utility-based architecture  

---

## 📁 Project Structure

```bash
netwatch/
├── app.py
├── netwatch.db
├── requirements.txt
├── templates/
│   └── dashboard.html
└── utils/
    ├── alert_manager.py
    ├── database.py
    ├── device_tracker.py
    ├── dns_monitor.py
    ├── dns_server.py
    ├── domain_categorizer.py
```

---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/netwatch.git
cd netwatch
```

```bash
python -m venv venv
venv\Scripts\activate   # Windows
```

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Project

```bash
python app.py
```

Open:

http://localhost:5000

---

## 🧩 Modules

| File | Purpose |
|------|--------|
| app.py | Main Flask app |
| dns_server.py | DNS handling |
| dns_monitor.py | DNS traffic monitor |
| device_tracker.py | Tracks devices |
| domain_categorizer.py | Categorizes domains |
| alert_manager.py | Handles alerts |
| database.py | DB operations |

---

## 🛡 Notes

- Uses SQLite database (`netwatch.db`)
- Dashboard UI inside `templates/`
- Utility modules organized in `utils/`

---

## 📌 Future Improvements

- Add authentication  
- Improve UI  
- Deploy online  
- Add analytics  

---

## 🛡 Netwatch

Network Monitoring System
