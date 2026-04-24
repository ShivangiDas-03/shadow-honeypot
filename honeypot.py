"""
Deception-Based Security System — Honeypot
============================================
Presents three traps:
  1. A fake login endpoint (Flask web route)
  2. A dummy admin API that looks real but does nothing
  3. A hidden "bait" file reference in the fake API response

Any interaction with these traps is logged as a suspicious event.
All alerts are written to honeypot_alerts.log and printed to console.
"""

from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import json
import os
import hashlib

app = Flask(__name__)
ALERT_LOG = "honeypot_alerts.log"


# ─── Alert Logger ─────────────────────────────────────────────────────────────

def log_alert(trap_name: str, ip: str, details: dict):
    """Record a suspicious interaction."""
    alert = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "trap": trap_name,
        "source_ip": ip,
        "details": details,
    }
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")

    print(f"\n{'!'*55}")
    print(f"  [ALERT] Trap triggered: {trap_name}")
    print(f"  Source IP  : {ip}")
    print(f"  Time       : {alert['timestamp']}")
    for k, v in details.items():
        print(f"  {k:<12}: {v}")
    print(f"{'!'*55}\n")


def get_ip():
    return request.remote_addr or "unknown"


# ─── Trap 1: Fake Login Page ──────────────────────────────────────────────────

FAKE_LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Admin Login — Internal Portal</title>
<style>
  body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
         display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .box { background: #16213e; padding: 40px; border-radius: 8px; width: 320px;
         box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
  h2   { text-align: center; margin-bottom: 24px; color: #e94560; }
  input { width: 100%; padding: 10px; margin: 8px 0 16px; border: 1px solid #444;
          background: #0f3460; color: #eee; border-radius: 4px; box-sizing: border-box; }
  button { width: 100%; padding: 10px; background: #e94560; color: white;
           border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }
  .err { color: #ff6b6b; text-align: center; margin-top: 12px; }
  small { color: #888; display: block; text-align: center; margin-top: 14px; }
</style>
</head>
<body>
<div class="box">
  <h2>🔐 Admin Portal</h2>
  <form method="POST" action="/admin/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="admin" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="••••••••" required>
    <button type="submit">Sign In</button>
  </form>
  {% if error %}<p class="err">{{ error }}</p>{% endif %}
  <small>Internal use only — unauthorized access is monitored</small>
</div>
</body>
</html>
"""

@app.route("/admin/login", methods=["GET"])
def fake_login_get():
    """Visiting the login page is itself suspicious — it is not linked from anywhere."""
    log_alert(
        trap_name="FAKE_LOGIN_PAGE",
        ip=get_ip(),
        details={
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "note": "Agent visited hidden admin login page",
        }
    )
    return render_template_string(FAKE_LOGIN_HTML, error=None)


@app.route("/admin/login", methods=["POST"])
def fake_login_post():
    """Capture any credentials submitted to the fake login."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Hash the password before logging — never store plaintext
    pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16] + "..."

    log_alert(
        trap_name="FAKE_LOGIN_ATTEMPT",
        ip=get_ip(),
        details={
            "username": username,
            "password_hash": pw_hash,
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "note": "Credentials submitted to honeypot login",
        }
    )
    # Always fail — never grant access
    return render_template_string(FAKE_LOGIN_HTML, error="Invalid credentials. Access denied.")


# ─── Trap 2: Dummy Admin API ──────────────────────────────────────────────────

@app.route("/api/v1/admin/users", methods=["GET"])
def fake_api_users():
    """
    Fake endpoint that looks like a real user-management API.
    Returns dummy data — any request here is flagged.
    """
    log_alert(
        trap_name="FAKE_API_ENDPOINT",
        ip=get_ip(),
        details={
            "endpoint": "/api/v1/admin/users",
            "method": "GET",
            "auth_header": request.headers.get("Authorization", "none"),
            "note": "Probe of undocumented admin API endpoint",
        }
    )
    # Return convincing-looking fake data to keep attacker engaged
    return jsonify({
        "status": "ok",
        "users": [
            {"id": 1, "username": "admin",   "role": "superadmin", "last_login": "2025-03-30T08:12:00Z"},
            {"id": 2, "username": "jsmith",  "role": "editor",     "last_login": "2025-03-29T14:45:00Z"},
            {"id": 3, "username": "bjones",  "role": "viewer",     "last_login": "2025-03-28T09:10:00Z"},
        ],
        "_note": "See /backup/db_export.csv for full dump"   # bait reference → Trap 3
    })


@app.route("/api/v1/admin/config", methods=["GET", "POST"])
def fake_api_config():
    """Another dummy endpoint — attackers often probe /config after finding /users."""
    log_alert(
        trap_name="FAKE_API_CONFIG",
        ip=get_ip(),
        details={
            "endpoint": "/api/v1/admin/config",
            "method": request.method,
            "body": request.get_data(as_text=True)[:200],
            "note": "Attempt to read or modify system configuration via honeypot",
        }
    )
    return jsonify({"error": "Forbidden", "code": 403}), 403


# ─── Trap 3: Bait File ────────────────────────────────────────────────────────

@app.route("/backup/db_export.csv", methods=["GET"])
def bait_file():
    """
    The fake API response referenced this URL.
    Any request here means the attacker followed the bait — high-confidence malicious intent.
    """
    log_alert(
        trap_name="BAIT_FILE_ACCESS",
        ip=get_ip(),
        details={
            "resource": "/backup/db_export.csv",
            "referer": request.headers.get("Referer", "direct"),
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "note": "HIGH CONFIDENCE — attacker followed bait reference to fake DB export",
        }
    )
    # Return a fake CSV to make attacker believe they found something
    fake_csv = (
        "id,username,email,password_hash\n"
        "1,admin,admin@internal.local,<redacted>\n"
        "2,jsmith,j.smith@internal.local,<redacted>\n"
    )
    return fake_csv, 200, {"Content-Type": "text/csv"}


# ─── Alert Dashboard ──────────────────────────────────────────────────────────

@app.route("/monitor/alerts", methods=["GET"])
def show_alerts():
    """Simple dashboard — view all honeypot alerts (not a trap itself)."""
    if not os.path.exists(ALERT_LOG):
        return jsonify({"message": "No alerts yet.", "alerts": []})

    alerts = []
    with open(ALERT_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))

    return jsonify({
        "total_alerts": len(alerts),
        "alerts": alerts
    })


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Honeypot System — Running")
    print("  ================================")
    print("  Trap 1  (Fake Login)  : http://127.0.0.1:5000/admin/login")
    print("  Trap 2  (Fake API)    : http://127.0.0.1:5000/api/v1/admin/users")
    print("  Trap 3  (Bait File)   : http://127.0.0.1:5000/backup/db_export.csv")
    print("  Monitor (Alerts)      : http://127.0.0.1:5000/monitor/alerts")
    print("  ================================\n")
    app.run(debug=False, port=5000)
