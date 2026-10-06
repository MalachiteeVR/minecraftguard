#!/usr/bin/env python3
"""Malachite Minecraft Guard web panel."""
import ipaddress, os, sqlite3, subprocess
from pathlib import Path
from flask import Flask, redirect, render_template_string, request, session, url_for, jsonify

BASE = Path(os.getenv("GUARD_DIR", "/opt/minecraft-guard"))
DB = Path(os.getenv("GUARD_DB", str(BASE / "guard.db")))
LOG = Path(os.getenv("GUARD_LOG", "/var/log/minecraft-guard.log"))
GUARD = Path(os.getenv("GUARD_SCRIPT", str(BASE / "minecraft-guard.py")))
PYTHON = os.getenv("GUARD_PYTHON", str(BASE / "venv/bin/python"))
HOST = os.getenv("GUARD_WEB_HOST", "0.0.0.0")
PORT = int(os.getenv("GUARD_WEB_PORT", "2555"))
PASSWORD = os.getenv("PANEL_PASSWORD", "")
app = Flask(__name__)
app.secret_key = os.getenv("PANEL_SECRET", os.urandom(32).hex())

def ok(): return not PASSWORD or session.get("ok") is True

def tail():
    try:
        with LOG.open("rb") as f:
            f.seek(0,2); size=f.tell(); f.seek(max(0,size-1048576))
            return "\n".join(f.read().decode("utf8","replace").splitlines()[-300:])
    except Exception as exc: return f"Unable to read Guard log: {exc}"

def load_lists():
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory=sqlite3.Row
            blocked=[dict(r) for r in conn.execute("SELECT ip,created,source,notes FROM blacklist ORDER BY created DESC")]
            whitelist=[dict(r) for r in conn.execute("SELECT ip,created,notes FROM whitelist ORDER BY created DESC")]
            return blocked,whitelist,None
    except Exception as exc: return [],[],f"Unable to read Guard database: {exc}"

def run_guard(action, ip):
    try: ip=str(ipaddress.ip_address(ip.strip()))
    except ValueError: return False,"Invalid IP address"
    try:
        r=subprocess.run([PYTHON,str(GUARD),action,ip],capture_output=True,text=True,timeout=20)
    except Exception as exc: return False,f"Unable to run Guard: {exc}"
    output=(r.stdout or r.stderr or "").strip()
    return r.returncode==0,output or ("Success" if r.returncode==0 else "Guard command failed")

HTML="""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Malachite Minecraft Guard</title><style>
body{font-family:system-ui;background:#101114;color:#eee;margin:0;padding:20px}main{max-width:1250px;margin:auto}
section{background:#191b20;border:1px solid #30333a;border-radius:10px;padding:16px;margin:12px 0}
input,button{background:#0e0f12;color:#eee;border:1px solid #454954;border-radius:6px;padding:8px}button{cursor:pointer}
table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #30333a;text-align:left}
.log{background:#08090b;padding:12px;border-radius:6px;white-space:pre-wrap;overflow:auto;max-height:600px;font:12px monospace}
.actions{display:flex;gap:6px;flex-wrap:wrap}.muted{color:#999}
</style></head><body><main><h1>Malachite Minecraft Guard</h1>
<p class="muted">Linux relay panel. Guard log updates every 5 seconds.</p>
{% if message %}<section><b>{{message}}</b></section>{% endif %}
<section><h2>Manual IP Control</h2><form method="post" action="/action" class="actions">
<input name="ip" placeholder="IP address" required><button name="action" value="block">Block</button>
<button name="action" value="unblock">Unblock</button><button name="action" value="whitelist-add">Whitelist Add</button>
<button name="action" value="whitelist-remove">Whitelist Remove</button></form></section>
<section><h2>Blocked IPs ({{blocked|length}})</h2><table><tr><th>IP</th><th>Source</th><th>Created</th><th>Reason</th><th>Action</th></tr>
{% for x in blocked %}<tr><td>{{x.ip}}</td><td>{{x.source}}</td><td>{{x.created}}</td><td>{{x.notes}}</td><td>
<form method="post" action="/action"><input type="hidden" name="ip" value="{{x.ip}}"><button name="action" value="unblock">Unblock</button></form></td></tr>
{% else %}<tr><td colspan="5" class="muted">No blocked IPs.</td></tr>{% endfor %}</table></section>
<section><h2>Whitelist ({{whitelist|length}})</h2><table><tr><th>IP</th><th>Added</th><th>Notes</th><th>Action</th></tr>
{% for x in whitelist %}<tr><td>{{x.ip}}</td><td>{{x.created}}</td><td>{{x.notes}}</td><td>
<form method="post" action="/action"><input type="hidden" name="ip" value="{{x.ip}}"><button name="action" value="whitelist-remove">Remove</button></form></td></tr>
{% else %}<tr><td colspan="4" class="muted">No whitelisted IPs.</td></tr>{% endfor %}</table></section>
<section><h2>minecraft-guard.py Log</h2><div id="guard-log" class="log">{{log}}</div></section></main>
<script>
async function refreshLog(){try{const r=await fetch('/log',{cache:'no-store'});if(!r.ok)return;const d=await r.json();
const b=document.getElementById('guard-log');const bottom=b.scrollHeight-b.scrollTop-b.clientHeight<24;b.textContent=d.log;if(bottom)b.scrollTop=b.scrollHeight;}catch(e){}}
setInterval(refreshLog,5000);
</script></body></html>"""

@app.route("/login",methods=["GET","POST"])
def login():
    if not PASSWORD:return redirect(url_for("index"))
    if request.method=="POST" and request.form.get("password")==PASSWORD:
        session["ok"]=True; return redirect(url_for("index"))
    return '<form method="post" style="max-width:350px;margin:80px auto;font:16px sans-serif"><h2>Malachite Guard</h2><input type="password" name="password" placeholder="Password" autofocus><button>Login</button></form>'

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/")
def index():
    if not ok(): return redirect(url_for("login"))
    blocked,whitelist,db_error=load_lists()
    return render_template_string(HTML,blocked=blocked,whitelist=whitelist,log=tail(),message=request.args.get("message") or db_error)

@app.route("/log")
def log_endpoint():
    if not ok(): return jsonify({"log":""}),401
    return jsonify({"log":tail()})

@app.route("/action",methods=["POST"])
def action():
    if not ok(): return redirect(url_for("login"))
    name=request.form.get("action",""); ip=request.form.get("ip","")
    if name not in {"block","unblock","whitelist-add","whitelist-remove"}:
        return redirect(url_for("index",message="Invalid action"))
    good,out=run_guard("--"+name,ip)
    return redirect(url_for("index",message=("OK: " if good else "ERROR: ")+out))

if __name__=="__main__": app.run(host=HOST,port=PORT)
