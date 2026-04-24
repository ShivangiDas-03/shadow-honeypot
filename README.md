# 🍯 Deception-Based Security System — Honeypot

A lightweight Python honeypot built with Flask that detects and logs unauthorized access attempts using three layered traps: a fake login page, a dummy admin API, and a bait file reference.

---

## 🚀 Features

- **Trap 1 – Fake Login Page** (`/admin/login`): A convincing admin portal that captures any credentials submitted by intruders.
- **Trap 2 – Dummy Admin API** (`/api/v1/admin/users`, `/api/v1/admin/config`): Fake REST endpoints that return realistic-looking data to keep attackers engaged while logging their activity.
- **Trap 3 – Bait File** (`/backup/db_export.csv`): A fake database export URL embedded in the API response. If accessed, it signals high-confidence malicious intent.
- **Alert Dashboard** (`/monitor/alerts`): View all captured alerts in JSON format.

All interactions are logged to `honeypot_alerts.log` and printed to the console in real time.

---

## 🛠️ Requirements

- Python 3.8+
- Flask

Install dependencies:

```bash
pip install flask
```

---

## ▶️ Running the Honeypot

```bash
python honeypot.py
```

The server starts on `http://127.0.0.1:5000`. You'll see:

```
Honeypot System — Running
================================
Trap 1  (Fake Login)  : http://127.0.0.1:5000/admin/login
Trap 2  (Fake API)    : http://127.0.0.1:5000/api/v1/admin/users
Trap 3  (Bait File)   : http://127.0.0.1:5000/backup/db_export.csv
Monitor (Alerts)      : http://127.0.0.1:5000/monitor/alerts
================================
```

---

## 📁 Project Structure

```
honeypot/
├── honeypot.py          # Main application
├── .gitignore           # Excludes log files and cache
└── README.md            # This file
```

> `honeypot_alerts.log` is auto-generated at runtime and excluded from version control.

---

## 📋 Alert Log Format

Each alert is stored as a JSON line:

```json
{
  "timestamp": "2026-04-02T14:44:30Z",
  "trap": "FAKE_LOGIN_ATTEMPT",
  "source_ip": "192.168.1.10",
  "details": {
    "username": "admin",
    "password_hash": "fcf4de896d04f162...",
    "user_agent": "Mozilla/5.0 ...",
    "note": "Credentials submitted to honeypot login"
  }
}
```

Passwords are **never stored in plaintext** — only a truncated SHA-256 hash is logged.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research and defensive monitoring only**. Deploy it only on infrastructure you own or have explicit permission to monitor. Unauthorized use may violate local laws.

---

## 📄 License

MIT License — feel free to use, modify, and distribute with attribution.
