#!/usr/bin/env python3
"""Malachite Minecraft Guard, Linux relay edition.

Runs on the Linux relay in front of the Windows Minecraft server.
Provides a web panel, HAProxy/session logs, Minecraft status, manual
blacklist/whitelist management, and relay-side iptables enforcement.
"""
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for

BASE = os.getenv("GUARD_DIR", "/opt/minecraft-guard")
DB = os.getenv("GUARD_DB", os.path.join(BASE, "guard.db"))
GUARD_LOG = os.getenv("GUARD_LOG", os.path.join(BASE, "guard.log"))
HA_LOG = os.getenv("HA_LOG", "/var/log/haproxy.log")
HA_SOCKET = os.getenv("HAPROXY_SOCKET", "/run/haproxy/admin.sock")
BACKEND = os.getenv("MINECRAFT_TARGET", "100.87.154.87:25565")
PUBLIC_PORT = int(os.getenv("MINECRAFT_PUBLIC_PORT", "25565"))
WEB_HOST = os.getenv("GUARD_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("GUARD_WEB_PORT", "8080"))
PASSWORD = os.getenv("PANEL_PASSWORD", "")
SECRET = os.getenv("PANEL_SECRET", "") or os.urandom(32).hex()
CHAIN = "MINECRAFT_GUARD"

os.makedirs(BASE, exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(GUARD_LOG), logging.StreamHandler()])
log = logging.getLogger("minecraft-guard")
app = Flask(__name__)
app.secret_key = SECRET


def now(): return datetime.now(timezone.utc).isoformat()


def ip_ok(value):
    try: return str(ipaddress.ip_address(value.strip()))
    except ValueError: raise ValueError("Invalid IP address")


def cmd(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=8)


class Store:
    def __init__(self):
        os.makedirs(os.path.dirname(DB), exist_ok=True)
        with self.c() as c:
            c.execute("CREATE TABLE IF NOT EXISTS blacklist(ip TEXT PRIMARY KEY, created TEXT, source TEXT, notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS whitelist(ip TEXT PRIMARY KEY, created TEXT, notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, level TEXT, event TEXT, ip TEXT, details TEXT)")
            c.commit()

    def c(self):
        c = sqlite3.connect(DB, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def event(self, level, event, ip="", details=""):
        with self.c() as c:
            c.execute("INSERT INTO events(ts,level,event,ip,details) VALUES(?,?,?,?,?)", (now(), level, event, ip, details)); c.commit()

    def blocked(self):
        with self.c() as c: return [dict(r) for r in c.execute("SELECT * FROM blacklist ORDER BY created DESC")]

    def whitelisted(self):
        with self.c() as c: return [dict(r) for r in c.execute("SELECT * FROM whitelist ORDER BY created DESC")]

    def is_blocked(self, ip):
        with self.c() as c: return c.execute("SELECT 1 FROM blacklist WHERE ip=?", (ip,)).fetchone() is not None

    def is_white(self, ip):
        with self.c() as c: return c.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,)).fetchone() is not None

    def block(self, ip, source, notes):
        with self.c() as c:
            c.execute("INSERT OR REPLACE INTO blacklist(ip,created,source,notes) VALUES(?,?,?,?)", (ip, now(), source, notes)); c.commit()

    def unblock(self, ip):
        with self.c() as c: c.execute("DELETE FROM blacklist WHERE ip=?", (ip,)); c.commit()

    def white(self, ip, notes):
        with self.c() as c:
            c.execute("INSERT OR REPLACE INTO whitelist(ip,created,notes) VALUES(?,?,?)", (ip, now(), notes)); c.commit()

    def unwhite(self, ip):
        with self.c() as c: c.execute("DELETE FROM whitelist WHERE ip=?", (ip,)); c.commit()

    def events(self, limit=250):
        with self.c() as c: return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

store = Store()


def fw_setup():
    if os.geteuid() != 0: log.warning("Not running as root; iptables changes may fail")
    r = cmd(["iptables", "-N", CHAIN])
    if r.returncode and "Chain already exists" not in r.stderr: log.warning("iptables chain: %s", r.stderr.strip())
    cmd(["iptables", "-F", CHAIN])
    for row in store.whitelisted(): cmd(["iptables", "-A", CHAIN, "-s", row["ip"], "-j", "RETURN"])
    for row in store.blocked(): cmd(["iptables", "-A", CHAIN, "-s", row["ip"], "-j", "DROP"])
    for proto in ("tcp", "udp"):
        check = cmd(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(PUBLIC_PORT), "-j", CHAIN])
        if check.returncode: cmd(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(PUBLIC_PORT), "-j", CHAIN])


def fw_block(ip):
    if store.is_white(ip): return False, "IP is whitelisted"
    r = cmd(["iptables", "-C", CHAIN, "-s", ip, "-j", "DROP"])
    if r.returncode:
        r = cmd(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
        if r.returncode: return False, r.stderr.strip() or "iptables failed"
    return True, "blocked at relay"


def fw_unblock(ip):
    while cmd(["iptables", "-C", CHAIN, "-s", ip, "-j", "DROP"]).returncode == 0:
        if cmd(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"]).returncode: break
    return True, "unblocked"


def ha(command):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3); s.connect(HA_SOCKET); s.sendall((command + "\n").encode()); out=[]
    while True:
        try:
            b=s.recv(65536)
            if not b: break
            out.append(b)
        except socket.timeout: break
    s.close(); return b"".join(out).decode(errors="replace")


def ha_ok():
    try: return "HAProxy" in ha("show info")
    except Exception: return False


def sessions():
    try: raw=ha("show sess")
    except Exception: return []
    out=[]
    for line in raw.splitlines():
        sid=line.split()[0] if line.split() else ""
        if not re.fullmatch(r"0x[0-9a-fA-F]+", sid): continue
        pairs=re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        if not pairs: continue
        ip,port=pairs[0]
        try: ip_ok(ip)
        except ValueError: continue
        dst=(pairs[1][0]+":"+pairs[1][1]) if len(pairs)>1 else BACKEND
        out.append({"session":sid,"ip":ip,"port":port,"dst":dst})
    return out


def close_session(sid):
    if not re.fullmatch(r"0x[0-9a-fA-F]+", sid): raise ValueError("Invalid session")
    return ha("shutdown session " + sid)


def close_ip(ip):
    for row in sessions():
        if row["ip"] == ip:
            try: close_session(row["session"])
            except Exception: pass


def tail(path, lines=250):
    try:
        if not os.path.exists(path): return f"{path} does not exist."
        with open(path, "rb") as f:
            f.seek(0,2); size=f.tell(); f.seek(max(0,size-1024*1024)); data=f.read().decode(errors="replace")
        return "\n".join(data.splitlines()[-lines:])
    except Exception as e: return f"Unable to read {path}: {e}"


def varint(n):
    b=bytearray()
    while True:
        x=n&127; n>>=7
        if n: x|=128
        b.append(x)
        if not n: return bytes(b)


def read_varint(sock):
    result=0; shift=0
    while True:
        b=sock.recv(1)
        if not b: raise ConnectionError("closed")
        x=b[0]; result|=(x&127)<<shift
        if not x&128: return result
        shift+=7
        if shift>35: raise ValueError("bad VarInt")


def status_ping():
    host,port=BACKEND.rsplit(":",1); port=int(port); started=time.monotonic()
    with socket.create_connection((host,port),3) as s:
        a=host.encode(); payload=varint(0)+varint(763)+varint(len(a))+a+port.to_bytes(2,"big")+varint(1)
        s.sendall(varint(len(payload))+payload); s.sendall(b"\x01\x00")
        n=read_varint(s); data=b""
        while len(data)<n:
            x=s.recv(n-len(data))
            if not x: raise ConnectionError("closed")
            data+=x
    i=0
    _,i=read_vi(data,i); ln,i=read_vi(data,i); obj=json.loads(data[i:i+ln].decode())
    return {"online":True,"latency":round((time.monotonic()-started)*1000,1),"status":obj,"error":None}


def read_vi(data,i):
    result=0; shift=0
    while True:
        x=data[i]; i+=1; result|=(x&127)<<shift
        if not x&128: return result,i
        shift+=7

STATUS={"online":False,"latency":None,"status":{},"error":"Not checked yet"}

def status_worker():
    global STATUS
    while True:
        try: STATUS=status_ping()
        except Exception as e: STATUS={"online":False,"latency":None,"status":{},"error":str(e)}
        time.sleep(10)


HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Malachite Minecraft Guard</title><style>
:root{--bg:#0b1020;--p:#121a2b;--p2:#0d1525;--line:#26324a;--t:#edf2f7;--m:#9aa8bd;--g:#35d07f;--r:#ff5d6c;--b:#78a9ff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:14px system-ui,sans-serif}.wrap{max-width:1500px;margin:auto;padding:22px}.top{padding:20px 0}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.card{background:var(--p);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}h1{margin:0}h2{font-size:17px}.small{color:var(--m);font-size:12px}.stat{font-size:26px;font-weight:700;margin-top:6px}.good{color:var(--g)}.bad{color:var(--r)}input{background:var(--p2);color:var(--t);border:1px solid var(--line);padding:9px;border-radius:7px;width:100%}button{background:#22314a;color:var(--t);border:1px solid var(--line);padding:9px 12px;border-radius:7px;cursor:pointer}button:hover{filter:brightness(1.2)}.danger{color:#ff9da6}.safe{color:#78e5a9}form.inline{display:flex;gap:7px}.wide{grid-column:1/-1}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--m);font-size:12px}pre{background:#080d18;padding:12px;border-radius:8px;max-height:420px;overflow:auto;white-space:pre-wrap;word-break:break-word}.notice{padding:10px;background:#101b31;border-left:4px solid var(--b);border-radius:6px;margin-bottom:14px}.login{max-width:420px;margin:80px auto}@media(max-width:900px){.grid,.two{grid-template-columns:1fr}.wide{grid-column:auto}}
</style></head><body><div class="wrap"><div class="top"><h1>Malachite Minecraft Guard</h1><div class="small">Linux relay • HAProxy • iptables • Minecraft status</div></div>
{% if not authed %}<section class="card login"><h2>Relay Control Panel</h2><p class="small">Sign in to manage blacklist and whitelist rules.</p>{% if error %}<div class="notice">{{error}}</div>{% endif %}<form method="post" action="/login"><input name="password" type="password" placeholder="Panel password" autofocus required><br><br><button>Sign in</button></form></section>{% else %}
<div class="notice"><b>Relay enforcement:</b> rules are applied on this Linux relay before traffic reaches {{backend}}. <form style="float:right" method="post" action="/logout"><button>Log out</button></form><div style="clear:both"></div></div>
<div class="grid"><section class="card"><div class="small">Minecraft status</div><div class="stat {{'good' if status.online else 'bad'}}">{{'ONLINE' if status.online else 'OFFLINE'}}</div><div class="small">{% if status.online %}{{status.latency}} ms{% else %}{{status.error}}{% endif %}</div></section><section class="card"><div class="small">Players</div><div class="stat">{{status.status.get('players',{}).get('online',0)}} / {{status.status.get('players',{}).get('max','?')}}</div></section><section class="card"><div class="small">Blacklisted</div><div class="stat bad">{{blocked|length}}</div></section><section class="card"><div class="small">Whitelisted</div><div class="stat good">{{whitelist|length}}</div></section></div>
<div class="two"><section class="card"><h2>Manual blacklist</h2><form method="post" action="/block" class="inline"><input name="ip" placeholder="IP address" required><input name="notes" placeholder="Reason / notes"><button class="danger">Block IP</button></form></section><section class="card"><h2>Whitelist</h2><form method="post" action="/whitelist" class="inline"><input name="ip" placeholder="IP address" required><input name="notes" placeholder="Reason / notes"><button class="safe">Whitelist IP</button></form></section></div>
<section class="card wide"><h2>Current HAProxy connections</h2><table><tr><th>Client</th><th>Port</th><th>Destination</th><th>Session</th><th>Actions</th></tr>{% for c in connections %}<tr><td>{{c.ip}}</td><td>{{c.port}}</td><td>{{c.dst}}</td><td>{{c.session}}</td><td><form class="inline" method="post" action="/connection/{{c.session}}/close"><button>Close</button></form><form class="inline" method="post" action="/block/{{c.ip}}"><button class="danger">Block IP</button></form></td></tr>{% else %}<tr><td colspan="5" class="small">No active connections.</td></tr>{% endfor %}</table></section>
<div class="two"><section class="card"><h2>Blacklist</h2><table><tr><th>IP</th><th>Source</th><th>Notes</th><th></th></tr>{% for x in blocked %}<tr><td>{{x.ip}}</td><td>{{x.source}}</td><td>{{x.notes}}</td><td><form method="post" action="/unblock/{{x.ip}}"><button>Remove</button></form></td></tr>{% else %}<tr><td colspan="4" class="small">No blocked IPs.</td></tr>{% endfor %}</table></section><section class="card"><h2>Whitelist</h2><table><tr><th>IP</th><th>Notes</th><th></th></tr>{% for x in whitelist %}<tr><td>{{x.ip}}</td><td>{{x.notes}}</td><td><form method="post" action="/unwhitelist/{{x.ip}}"><button>Remove</button></form></td></tr>{% else %}<tr><td colspan="3" class="small">No whitelisted IPs.</td></tr>{% endfor %}</table></section></div>
<section class="card"><h2>Guard event log</h2><pre>{% for x in events %}{{x.ts}} [{{x.level}}] {{x.event}}{% if x.ip %} {{x.ip}}{% endif %}{% if x.details %} | {{x.details}}{% endif %}
{% endfor %}</pre></section><section class="card"><h2>HAProxy log</h2><pre>{{ha_log}}</pre></section><section class="card"><h2>Guard log</h2><pre>{{guard_log}}</pre></section>
{% endif %}</div></body></html>'''


def auth(): return not PASSWORD or session.get("auth") is True

def page():
    if not auth(): return render_template_string(HTML, authed=False, error=None)
    return render_template_string(HTML, authed=True, error=None, status=STATUS, backend=BACKEND,
        blocked=store.blocked(), whitelist=store.whitelisted(), events=store.events(),
        connections=sessions(), ha_log=tail(HA_LOG), guard_log=tail(GUARD_LOG))

@app.route("/login", methods=["GET","POST"])
def login():
    if not PASSWORD: return redirect("/")
    if request.method == "POST":
        if request.form.get("password", "") == PASSWORD: session["auth"]=True; return redirect("/")
        return render_template_string(HTML, authed=False, error="Invalid password.")
    return page()

@app.post("/logout")
def logout(): session.clear(); return redirect("/login")

@app.get("/")
def index(): return page()

@app.get("/api/status")
def api_status():
    if not auth(): return jsonify({"error":"unauthorized"}),401
    return jsonify(STATUS)

@app.post("/block")
def block():
    if not auth(): return redirect("/login")
    try: ip=ip_ok(request.form.get("ip",""))
    except ValueError as e: return str(e),400
    if store.is_white(ip): return "IP is whitelisted. Remove it from the whitelist first.",409
    ok,msg=fw_block(ip)
    if not ok: return msg,500
    notes=request.form.get("notes","").strip() or "Manual web block"
    store.block(ip,"Manual Web",notes); store.event("WARN","MANUAL_BLOCK",ip,notes); close_ip(ip)
    return redirect("/")

@app.post("/block/<ip>")
def block_path(ip):
    if not auth(): return redirect("/login")
    try: ip=ip_ok(ip)
    except ValueError as e: return str(e),400
    if store.is_white(ip): return "IP is whitelisted.",409
    ok,msg=fw_block(ip)
    if not ok: return msg,500
    store.block(ip,"Manual Web","Blocked from connection list"); store.event("WARN","MANUAL_BLOCK",ip,"Connection list"); close_ip(ip)
    return redirect("/")

@app.post("/unblock/<ip>")
def unblock(ip):
    if not auth(): return redirect("/login")
    try: ip=ip_ok(ip)
    except ValueError as e: return str(e),400
    fw_unblock(ip); store.unblock(ip); store.event("INFO","MANUAL_UNBLOCK",ip,"Web panel"); return redirect("/")

@app.post("/whitelist")
def whitelist():
    if not auth(): return redirect("/login")
    try: ip=ip_ok(request.form.get("ip",""))
    except ValueError as e: return str(e),400
    notes=request.form.get("notes","").strip() or "Manual whitelist"
    store.white(ip,notes); fw_unblock(ip); store.unblock(ip); store.event("INFO","WHITELIST_ADD",ip,notes); return redirect("/")

@app.post("/unwhitelist/<ip>")
def unwhitelist(ip):
    if not auth(): return redirect("/login")
    try: ip=ip_ok(ip)
    except ValueError as e: return str(e),400
    store.unwhite(ip); store.event("INFO","WHITELIST_REMOVE",ip,"Web panel"); return redirect("/")

@app.post("/connection/<sid>/close")
def close(sid):
    if not auth(): return redirect("/login")
    try: close_session(sid)
    except Exception as e: return str(e),400
    store.event("INFO","SESSION_CLOSE",details=sid); return redirect("/")


def main():
    fw_setup()
    threading.Thread(target=status_worker, daemon=True).start()
    log.info("Minecraft Guard relay starting: backend=%s web=%s:%s", BACKEND, WEB_HOST, WEB_PORT)
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, debug=False, use_reloader=False)

if __name__ == "__main__": main()
