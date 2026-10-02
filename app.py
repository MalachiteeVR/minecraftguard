import base64
import ipaddress
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from mcstatus import JavaServer

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PANEL_DB", os.path.join(APP_DIR, "panel.sqlite3"))
HAPROXY_SOCKET = os.environ.get("HAPROXY_SOCKET", "/run/haproxy/admin.sock")
HA_LOG = os.environ.get("HA_LOG", "/var/log/haproxy.log")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
MINECRAFT_TARGET = os.environ.get("MINECRAFT_TARGET", "127.0.0.1:25565")

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET", "change-this-before-exposing")

HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Malachite Minecraft Control</title>
<style>
:root{color-scheme:dark;--bg:#0b0f14;--panel:#121923;--line:#273445;--text:#edf3f8;--muted:#8fa0b3;--green:#55d187;--red:#ff6b6b;--blue:#65a9ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#162231 0,#0b0f14 45%);font:14px system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text)}
.wrap{max-width:1400px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:20px}.brand h1{margin:0;font-size:25px}.brand p{margin:5px 0 0;color:var(--muted)}
.grid{display:grid;grid-template-columns:1.4fr .8fr;gap:16px}.panel{background:rgba(18,25,35,.94);border:1px solid var(--line);border-radius:14px;padding:17px;box-shadow:0 10px 30px #0005}.wide{grid-column:1/-1}
h2{font-size:16px;margin:0 0 14px}.status{display:flex;align-items:center;gap:9px}.dot{width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green)}.dot.off{background:var(--red);box-shadow:0 0 12px var(--red)}
.server{display:flex;gap:15px;align-items:center}.icon{width:72px;height:72px;border-radius:10px;background:#0a0e13}.server h3{margin:0 0 7px;font-size:19px}.motd{white-space:pre-wrap;color:#cdd8e4}.stats{display:flex;gap:22px;margin-top:8px;color:var(--muted)}.stats b{color:var(--text)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.empty{text-align:center;color:var(--muted);padding:24px}
button{border:0;border-radius:8px;padding:8px 12px;font-weight:650;cursor:pointer;background:var(--blue);color:#07101b}button.red{background:var(--red);color:#180707}button.dark{background:#273445;color:var(--text)}button.green{background:var(--green);color:#07150d}
form.inline{display:inline}.pill{display:inline-block;padding:3px 8px;border-radius:999px;background:#243043;color:#bcd0e5;font-size:12px}.danger{color:var(--red)}.muted{color:var(--muted)}.toolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:10px}.login{max-width:420px;margin:15vh auto}.login input{width:100%;padding:12px;background:#0c131c;border:1px solid var(--line);border-radius:8px;color:var(--text);margin:8px 0 12px}.notice{padding:10px 12px;background:#2b2020;border:1px solid #613636;border-radius:8px;color:#ffb3b3;margin-bottom:12px}
@media(max-width:900px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}}
</style></head><body><div class="wrap">
{% if not authed %}<div class="panel login"><h1>Malachite Control</h1><p class="muted">Manual Minecraft relay management.</p>{% if error %}<div class="notice">{{error}}</div>{% endif %}
<form method="post" action="/login"><label>Password</label><input name="password" type="password" autofocus><button>Sign in</button></form></div>
{% else %}
<div class="top"><div class="brand"><h1>Malachite Minecraft Control</h1><p>Manual connection control. No automatic blocking or whitelist.</p></div><form method="post" action="/logout"><button class="dark">Log out</button></form></div>
<div class="grid">
<section class="panel"><h2>Server</h2><div class="server">
{% if server.icon %}<img class="icon" src="{{server.icon}}" alt="Server icon">{% else %}<div class="icon"></div>{% endif %}
<div><h3>{{server.motd or 'Minecraft server'}}</h3><div class="stats"><span>Status <b>{{'ONLINE' if server.online else 'OFFLINE'}}</b></span><span>Players <b>{{server.players_online}} / {{server.players_max}}</b></span><span>Ping <b>{{server.latency}} ms</b></span></div><div class="stats"><span>Version <b>{{server.version or 'Unknown'}}</b></span><span>Target <b>{{target}}</b></span></div></div>
</div></section>
<section class="panel"><h2>Relay</h2><div class="status"><span class="dot {{'' if haproxy else 'off'}}"></span><b>HAProxy {{'running' if haproxy else 'unavailable'}}</b></div><div class="stats"><span>Active connections <b>{{connections|length}}</b></span><span>Blocked IPs <b>{{blocked|length}}</b></span></div></section>
<section class="panel wide"><div class="toolbar"><h2>Current Connections</h2><button class="dark" onclick="location.reload()">Refresh</button></div>
<table><thead><tr><th>Client</th><th>Source port</th><th>Destination</th><th>Session</th><th>Action</th></tr></thead><tbody>
{% for c in connections %}<tr><td><b>{{c.ip}}</b></td><td>{{c.port}}</td><td>{{c.dst}}</td><td><span class="pill">{{c.session}}</span></td><td>
<form class="inline" method="post" action="/connection/{{c.session}}/close" onsubmit="return confirm('Close this connection?')"><button class="red">Close</button></form>
<form class="inline" method="post" action="/block/{{c.ip}}" onsubmit="return confirm('Block {{c.ip}}? This will also close its current connections.')"><button class="dark">Block IP</button></form></td></tr>
{% else %}<tr><td colspan="5" class="empty">No active Minecraft connections.</td></tr>{% endfor %}</tbody></table></section>
<section class="panel"><div class="toolbar"><h2>Blocked IPs</h2></div><table><thead><tr><th>IP</th><th>Action</th></tr></thead><tbody>
{% for ip in blocked %}<tr><td class="danger"><b>{{ip}}</b></td><td><form method="post" action="/unblock/{{ip}}" onsubmit="return confirm('Unblock {{ip}}?')"><button class="green">Unblock</button></form></td></tr>
{% else %}<tr><td colspan="2" class="empty">No manually blocked IPs.</td></tr>{% endfor %}</tbody></table></section>
<section class="panel"><div class="toolbar"><h2>Recent Connection Log</h2></div><table><thead><tr><th>Time</th><th>Client</th><th>Result</th></tr></thead><tbody>
{% for row in logs %}<tr><td>{{row.time if row.time else row.ts}}</td><td><b>{{row.ip}}</b>{% if row.port %}<span class="muted">:{{row.port}}</span>{% endif %}</td><td>{{row.result}}</td></tr>
{% else %}<tr><td colspan="3" class="empty">No connection log entries yet.</td></tr>{% endfor %}</tbody></table></section>
</div>{% endif %}</div></body></html>"""

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS connections_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT NOT NULL,
            port INTEGER, raw TEXT, result TEXT NOT NULL DEFAULT 'connection logged')""")
        con.execute("""CREATE TABLE IF NOT EXISTS blocked_ips(
            ip TEXT PRIMARY KEY, created_at TEXT NOT NULL)""")
        con.commit()

def run_cmd(args, timeout=5):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def haproxy_cmd(command):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
    s.connect(HAPROXY_SOCKET); s.sendall((command + "\n").encode())
    chunks=[]
    while True:
        try:
            data=s.recv(65536)
            if not data: break
            chunks.append(data)
        except socket.timeout: break
    s.close()
    return b"".join(chunks).decode(errors="replace")

def haproxy_ok():
    try: return "HAProxy" in haproxy_cmd("show info")
    except Exception: return False

def current_connections():
    try: raw=haproxy_cmd("show sess")
    except Exception: return []
    rows=[]
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"): continue
        sid=line.split()[0]
        if not re.fullmatch(r"0x[0-9a-fA-F]+", sid): continue
        ips=re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        if not ips: continue
        ip,port=ips[0]
        try: ipaddress.ip_address(ip)
        except ValueError: continue
        dst=ips[1][0]+":"+ips[1][1] if len(ips)>1 else "25565"
        rows.append({"session":sid,"ip":ip,"port":int(port),"dst":dst})
    return rows

def close_session(sid):
    if not re.fullmatch(r"0x[0-9a-fA-F]+", sid): raise ValueError("Invalid session")
    return haproxy_cmd("shutdown session "+sid)

def valid_ip(value):
    try: return str(ipaddress.ip_address(value))
    except ValueError: raise ValueError("Invalid IP address")

def blocked_ips():
    with db() as con:
        return [r["ip"] for r in con.execute("SELECT ip FROM blocked_ips ORDER BY created_at DESC")]

def firewall_block(ip):
    ip=valid_ip(ip)
    if run_cmd(["iptables","-C","INPUT","-s",ip,"-j","DROP"]).returncode != 0:
        r=run_cmd(["iptables","-I","INPUT","1","-s",ip,"-j","DROP"])
        if r.returncode != 0: raise RuntimeError(r.stderr.strip() or "iptables failed")
    with db() as con:
        con.execute("INSERT OR REPLACE INTO blocked_ips(ip,created_at) VALUES(?,?)",(ip,datetime.now(timezone.utc).isoformat())); con.commit()
    for c in current_connections():
        if c["ip"]==ip:
            try: close_session(c["session"])
            except Exception: pass

def firewall_unblock(ip):
    ip=valid_ip(ip)
    while run_cmd(["iptables","-D","INPUT","-s",ip,"-j","DROP"]).returncode == 0: pass
    with db() as con:
        con.execute("DELETE FROM blocked_ips WHERE ip=?",(ip,)); con.commit()

LOG_RE=re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)\b")

def ingest_logs():
    if not os.path.exists(HA_LOG): return
    try:
        with open(HA_LOG,"r",errors="replace") as f: lines=f.readlines()[-2000:]
    except OSError: return
    with db() as con:
        existing={r[0] for r in con.execute("SELECT raw FROM connections_log WHERE raw IS NOT NULL ORDER BY id DESC LIMIT 3000")}
        for line in lines:
            m=LOG_RE.search(line)
            if not m: continue
            raw=line.rstrip()
            if raw in existing: continue
            con.execute("INSERT INTO connections_log(ts,ip,port,raw,result) VALUES(?,?,?,?,?)",
                        (datetime.now(timezone.utc).isoformat(),m.group("ip"),int(m.group("port")),raw,"connection logged"))
        con.commit()

def log_worker():
    while True:
        try: ingest_logs()
        except Exception: pass
        time.sleep(1)

def server_status():
    try:
        host,port=MINECRAFT_TARGET.rsplit(":",1)
        status=JavaServer(host,int(port),timeout=2).status()
        return {"online":True,"motd":status.description,"players_online":status.players.online,
                "players_max":status.players.max,"latency":round(status.latency),
                "version":status.version.name,"icon":status.icon}
    except Exception:
        return {"online":False,"motd":"","players_online":0,"players_max":0,"latency":0,"version":"","icon":None}

def require_auth(): return (not PANEL_PASSWORD) or session.get("auth") is True

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if not PANEL_PASSWORD or request.form.get("password")==PANEL_PASSWORD:
            session["auth"]=True; return redirect(url_for("index"))
        return render_template_string(HTML,authed=False,error="Invalid password")
    return render_template_string(HTML,authed=False,error=None)

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/")
def index():
    if not require_auth(): return redirect(url_for("login"))
    ingest_logs()
    with db() as con: logs=con.execute("SELECT * FROM connections_log ORDER BY id DESC LIMIT 40").fetchall()
    return render_template_string(HTML,authed=True,error=None,connections=current_connections(),
        blocked=blocked_ips(),logs=logs,server=server_status(),haproxy=haproxy_ok(),target=MINECRAFT_TARGET)

@app.post("/connection/<sid>/close")
def close(sid):
    if not require_auth(): return redirect(url_for("login"))
    try: close_session(sid)
    except Exception: pass
    return redirect(url_for("index"))

@app.post("/block/<ip>")
def block(ip):
    if not require_auth(): return redirect(url_for("login"))
    try: firewall_block(ip)
    except Exception: pass
    return redirect(url_for("index"))

@app.post("/unblock/<ip>")
def unblock(ip):
    if not require_auth(): return redirect(url_for("login"))
    try: firewall_unblock(ip)
    except Exception: pass
    return redirect(url_for("index"))

@app.get("/api/status")
def api_status():
    if not require_auth(): return jsonify({"error":"unauthorized"}),401
    ingest_logs()
    with db() as con: logs=[dict(r) for r in con.execute("SELECT id,ts,ip,port,result FROM connections_log ORDER BY id DESC LIMIT 100")]
    return jsonify({"server":server_status(),"haproxy":haproxy_ok(),"connections":current_connections(),
                    "blocked":blocked_ips(),"logs":logs})

init_db()
threading.Thread(target=log_worker,daemon=True).start()

if __name__=="__main__":
    app.run(host="127.0.0.1",port=int(os.environ.get("PORT","8080")),debug=False)
