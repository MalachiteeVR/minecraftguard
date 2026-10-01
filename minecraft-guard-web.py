#!/usr/bin/env python3
import html
import ipaddress
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, request, redirect, url_for, session, render_template_string, flash

DEFAULT_WORKDIR = Path("/opt/minecraft-guard")
WORKDIR = Path(os.getenv("MINECRAFT_GUARD_WORKDIR", str(DEFAULT_WORKDIR)))
ENV = WORKDIR / ".env"

if ENV.exists():
    for line in ENV.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

WORKDIR = Path(os.getenv("MINECRAFT_GUARD_WORKDIR", str(DEFAULT_WORKDIR)))
DB = WORKDIR / "blacklist.db"
HOST = os.getenv("MINECRAFT_GUARD_WEB_HOST", "127.0.0.1")
PORT = int(os.getenv("MINECRAFT_GUARD_WEB_PORT", "8080"))
HASH = os.getenv("MINECRAFT_GUARD_ADMIN_PASSWORD_HASH", "")
SESSION_TTL = max(60, int(os.getenv("MINECRAFT_GUARD_SESSION_TTL", "3600")))

app = Flask(__name__)
app.secret_key = os.getenv("MINECRAFT_GUARD_SECRET_KEY", "")
app.permanent_session_lifetime = timedelta(seconds=SESSION_TTL)

if not app.secret_key:
    raise SystemExit("[ERROR] MINECRAFT_GUARD_SECRET_KEY is missing from .env")


def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    return c


def init():
    WORKDIR.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            blocked_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            source TEXT NOT NULL,
            abuse_score INTEGER,
            usage_type TEXT,
            country_code TEXT,
            isp TEXT,
            domain TEXT,
            notes TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY,
            added_at TEXT NOT NULL,
            notes TEXT
        )""")


def clean_ip(value):
    try:
        addr = ipaddress.ip_address(value.strip())
        return str(addr) if addr.version == 4 and addr.is_global else None
    except ValueError:
        return None


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("admin"):
            return f(*args, **kwargs)
        return redirect(url_for("login", next=request.path))
    return wrapper


STYLE = """<style>
body{font:15px Segoe UI,Arial;background:#0d1117;color:#e6edf3;margin:0}
nav{padding:16px 24px;background:#161b22;display:flex;gap:18px}
nav b{margin-right:auto;font-size:20px}a{color:#58a6ff}
.wrap{max-width:1200px;margin:28px auto;padding:0 18px}
.box,table{background:#161b22;border:1px solid #30363d;border-radius:12px}
.box{padding:18px;margin:18px 0}table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #30363d;text-align:left}
input,button{padding:10px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#fff}
button{background:#238636;cursor:pointer}.danger{background:#da3633}.warn{background:#9e6a03}
.flash{padding:12px;background:#1f6feb33;margin-bottom:12px}.muted{color:#8b949e}
.grid{display:flex;gap:14px}.card{padding:18px;background:#161b22;border:1px solid #30363d;border-radius:12px;min-width:180px}
.num{font-size:32px;font-weight:bold}
</style>"""

BASE = """<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Minecraft Guard</title>""" + STYLE + """</head><body>
<nav><b>🛡 Minecraft Guard</b><a href='/'>Dashboard</a><a href='/blacklist'>Blacklist</a>
<a href='/whitelist'>Whitelist</a><a href='/logout'>Logout</a></nav>
<div class=wrap>{% for x in get_flashed_messages() %}<div class=flash>{{x}}</div>{% endfor %}
{{body|safe}}</div></body></html>"""


def page(body):
    return render_template_string(BASE, body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not HASH:
            return "Admin password is not configured.", 503
        from werkzeug.security import check_password_hash
        if check_password_hash(HASH, request.form.get("password", "")):
            session.permanent = True
            session["admin"] = 1
            next_url = request.args.get("next", "/")
            if not next_url.startswith("/"):
                next_url = "/"
            return redirect(next_url)
        flash("Invalid password.")
    return render_template_string(STYLE + """
<div style='max-width:400px;margin:100px auto'><div class=box>
<h1>Minecraft Guard</h1><form method=post>
<input type=password name=password placeholder=Password style='width:100%;box-sizing:border-box'>
<br><br><button style='width:100%'>Login</button></form></div></div>""")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
@auth
def home():
    with db() as c:
        b = c.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
        w = c.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
    return page(
        f"<h1>Dashboard</h1><p class=muted>Shared database is refreshed by the web process every 5 seconds.</p>"
        f"<div class=grid><div class=card>Blacklisted<div class=num>{b}</div></div>"
        f"<div class=card>Whitelisted<div class=num>{w}</div></div></div>"
        f"<div class=box><b>Shared DB:</b> {esc(DB)}<br>"
        "Guard independently synchronizes firewall state every 5 seconds.</div>"
    )


@app.get("/blacklist")
@auth
def blacklist():
    with db() as c:
        rows = c.execute("SELECT * FROM blacklist ORDER BY blocked_at DESC").fetchall()
    html_out = """<h1>Blacklist</h1><div class=box>
<form method=post action=/blacklist/add><input name=ip placeholder='IP address' required>
<input name=notes value='Manual web-console block'> <button class=danger>Block IP</button>
</form></div><table><tr><th>IP</th><th>Blocked</th><th>Source</th><th>Notes</th><th></th></tr>"""
    for row in rows:
        ip = esc(row["ip"])
        html_out += (
            f"<tr><td>{ip}</td><td>{esc(row['blocked_at'])}</td>"
            f"<td>{esc(row['source'])}</td><td>{esc(row['notes'])}</td>"
            f"<td><form method=post action=/blacklist/remove><input type=hidden name=ip value='{ip}'>"
            "<button class=danger>Unblock</button></form></td></tr>"
        )
    return page(html_out + "</table>")


@app.post("/blacklist/add")
@auth
def add_blacklist():
    value = clean_ip(request.form.get("ip", ""))
    if not value:
        flash("Invalid public IPv4 address.")
    else:
        now = datetime.now(timezone.utc).isoformat()
        notes = request.form.get("notes") or "Manual web-console block"
        with db() as c:
            c.execute(
                """INSERT INTO blacklist
                (ip,blocked_at,updated_at,source,abuse_score,usage_type,country_code,isp,domain,notes)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET updated_at=excluded.updated_at,
                source=excluded.source,notes=excluded.notes""",
                (value, now, now, "minecraft-guard/web", None, None, None, None, None, notes),
            )
            c.execute("DELETE FROM whitelist WHERE ip=?", (value,))
        flash(f"{value} written to the shared blacklist. Guard will enforce it within 5 seconds.")
    return redirect("/blacklist")


@app.post("/blacklist/remove")
@auth
def remove_blacklist():
    value = clean_ip(request.form.get("ip", ""))
    if value:
        with db() as c:
            c.execute("DELETE FROM blacklist WHERE ip=?", (value,))
        flash(f"{value} removed from the shared blacklist. Guard will remove its firewall rule within 5 seconds.")
    return redirect("/blacklist")


@app.get("/whitelist")
@auth
def whitelist():
    with db() as c:
        rows = c.execute("SELECT * FROM whitelist ORDER BY added_at DESC").fetchall()
    html_out = """<h1>Whitelist</h1><div class=box>
<form method=post action=/whitelist/add><input name=ip placeholder='IP address' required>
<input name=notes value='Manual web-console whitelist'> <button>Add to whitelist</button>
</form></div><table><tr><th>IP</th><th>Added</th><th>Notes</th><th></th></tr>"""
    for row in rows:
        ip = esc(row["ip"])
        html_out += (
            f"<tr><td>{ip}</td><td>{esc(row['added_at'])}</td><td>{esc(row['notes'])}</td>"
            f"<td><form method=post action=/whitelist/remove><input type=hidden name=ip value='{ip}'>"
            "<button class=warn>Remove</button></form></td></tr>"
        )
    return page(html_out + "</table>")


@app.post("/whitelist/add")
@auth
def add_whitelist():
    value = clean_ip(request.form.get("ip", ""))
    if not value:
        flash("Invalid public IPv4 address.")
    else:
        now = datetime.now(timezone.utc).isoformat()
        notes = request.form.get("notes") or "Manual web-console whitelist"
        with db() as c:
            c.execute(
                """INSERT INTO whitelist(ip,added_at,notes) VALUES (?,?,?)
                ON CONFLICT(ip) DO UPDATE SET added_at=excluded.added_at,
                notes=excluded.notes""",
                (value, now, notes),
            )
            c.execute("DELETE FROM blacklist WHERE ip=?", (value,))
        flash(f"{value} written to the shared whitelist and removed from blacklist. Guard syncs within 5 seconds.")
    return redirect("/whitelist")


@app.post("/whitelist/remove")
@auth
def remove_whitelist():
    value = clean_ip(request.form.get("ip", ""))
    if value:
        with db() as c:
            c.execute("DELETE FROM whitelist WHERE ip=?", (value,))
    return redirect("/whitelist")


def db_watcher():
    last_blacklist = None
    last_whitelist = None
    while True:
        try:
            with db() as c:
                blacklist_ips = tuple(r[0] for r in c.execute("SELECT ip FROM blacklist ORDER BY ip"))
                whitelist_ips = tuple(r[0] for r in c.execute("SELECT ip FROM whitelist ORDER BY ip"))
            if blacklist_ips != last_blacklist or whitelist_ips != last_whitelist:
                print(
                    f"[WEB] Shared DB refreshed: {len(blacklist_ips)} blacklist, "
                    f"{len(whitelist_ips)} whitelist entries"
                )
                last_blacklist = blacklist_ips
                last_whitelist = whitelist_ips
        except Exception as exc:
            print(f"[WEB] DB refresh failed: {exc}")
        time.sleep(5)


if __name__ == "__main__":
    init()
    if not HASH:
        raise SystemExit("[ERROR] MINECRAFT_GUARD_ADMIN_PASSWORD_HASH is missing from .env")
    threading.Thread(target=db_watcher, daemon=True, name="MinecraftGuard-Web-DBSync").start()
    app.run(host=HOST, port=PORT, debug=False)
