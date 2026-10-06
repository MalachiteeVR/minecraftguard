#!/usr/bin/env python3
"""Malachite Minecraft Guard web panel.
The Guard daemon owns monitoring/enforcement. This app displays its log and
uses minecraft-guard.py CLI commands for manual block/whitelist actions.
"""
import ipaddress,os,sqlite3,subprocess
from pathlib import Path
from flask import Flask,redirect,render_template_string,request,session,url_for
BASE=Path(os.getenv('GUARD_DIR','/var/lib/minecraft-guard')); DB=Path(os.getenv('GUARD_DB',str(BASE/'blacklist.db'))); LOG=Path(os.getenv('GUARD_LOG','/var/log/minecraft-guard.log')); GUARD=Path(os.getenv('GUARD_SCRIPT','/opt/minecraft-guard/minecraft-guard.py')); PYTHON=os.getenv('GUARD_PYTHON','/opt/minecraft-guard/venv/bin/python'); HOST=os.getenv('GUARD_WEB_HOST','0.0.0.0'); PORT=int(os.getenv('GUARD_WEB_PORT','2555')); PASSWORD=os.getenv('PANEL_PASSWORD',''); app=Flask(__name__); app.secret_key=os.getenv('PANEL_SECRET',os.urandom(32).hex())
def ok():return not PASSWORD or session.get('ok') is True
def tail():
 try:
  with LOG.open('rb') as f:f.seek(0,2);n=f.tell();f.seek(max(0,n-1048576));return '\n'.join(f.read().decode('utf8','replace').splitlines()[-300:])
 except Exception as e:return f'Unable to read Guard log: {e}'
def run_guard(action,ip):
 try:ip=str(ipaddress.ip_address(ip.strip()))
 except ValueError:return False,'Invalid IP address'
 r=subprocess.run([PYTHON,str(GUARD),action,ip],capture_output=True,text=True,timeout=20);out=(r.stdout or r.stderr or '').strip();return r.returncode==0,out or ('Success' if r.returncode==0 else 'Guard command failed')
HTML='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5"><title>Malachite Minecraft Guard</title><style>body{font-family:system-ui;background:#101114;color:#eee;margin:0;padding:20px}main{max-width:1250px;margin:auto}section{background:#191b20;border:1px solid #30333a;border-radius:10px;padding:16px;margin:12px 0}input,button{background:#0e0f12;color:#eee;border:1px solid #454954;border-radius:6px;padding:8px}button{cursor:pointer}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #30333a;text-align:left}.log{background:#08090b;padding:12px;border-radius:6px;white-space:pre-wrap;overflow:auto;max-height:600px;font:12px monospace}.actions{display:flex;gap:6px;flex-wrap:wrap}.muted{color:#999}</style></head><body><main><h1>Malachite Minecraft Guard</h1><p class="muted">Linux relay panel. Guard log refreshes every 5 seconds.</p>{% if message %}<section><b>{{message}}</b></section>{% endif %}<section><h2>Manual IP Control</h2><form method="post" action="/action" class="actions"><input name="ip" placeholder="IP address" required><button name="action" value="block">Block</button><button name="action" value="unblock">Unblock</button><button name="action" value="whitelist-add">Whitelist Add</button><button name="action" value="whitelist-remove">Whitelist Remove</button></form></section><section><h2>Blocked IPs ({{blocked|length}})</h2><table><tr><th>IP</th><th>Source</th><th>Score</th><th>Usage</th><th>Reason</th><th>Action</th></tr>{% for x in blocked %}<tr><td>{{x.ip}}</td><td>{{x.source}}</td><td>{{x.abuse_score if x.abuse_score is not none else ''}}</td><td>{{x.usage_type}}</td><td>{{x.notes}}</td><td><form method="post" action="/action"><input type="hidden" name="ip" value="{{x.ip}}"><button name="action" value="unblock">Unblock</button></form></td></tr>{% else %}<tr><td colspan="6" class="muted">No blocked IPs.</td></tr>{% endfor %}</table></section><section><h2>Whitelist ({{whitelist|length}})</h2><table><tr><th>IP</th><th>Added</th><th>Notes</th><th>Action</th></tr>{% for x in whitelist %}<tr><td>{{x.ip}}</td><td>{{x.added_at}}</td><td>{{x.notes}}</td><td><form method="post" action="/action"><input type="hidden" name="ip" value="{{x.ip}}"><button name="action" value="whitelist-remove">Remove</button></form></td></tr>{% else %}<tr><td colspan="4" class="muted">No whitelisted IPs.</td></tr>{% endfor %}</table></section><section><h2>minecraft-guard.py Log</h2><div class="log">{{log}}</div></section></main></body></html>'''
@app.route('/login',methods=['GET','POST'])
def login():
 if not PASSWORD:return redirect(url_for('index'))
 if request.method=='POST' and request.form.get('password')==PASSWORD:session['ok']=True;return redirect(url_for('index'))
 return '<form method="post" style="max-width:350px;margin:80px auto;font:16px sans-serif"><h2>Malachite Guard</h2><input type="password" name="password" placeholder="Password" autofocus><button>Login</button></form>'
@app.route('/logout')
def logout():session.clear();return redirect(url_for('login'))
@app.route('/')
def index():
 if not ok():return redirect(url_for('login'))
 with sqlite3.connect(DB) as c:
  c.row_factory=sqlite3.Row;blocked=[dict(x) for x in c.execute('SELECT * FROM blacklist ORDER BY blocked_at DESC')];whitelist=[dict(x) for x in c.execute('SELECT * FROM whitelist ORDER BY added_at DESC')]
 return render_template_string(HTML,blocked=blocked,whitelist=whitelist,log=tail(),message=request.args.get('message'))
@app.route('/action',methods=['POST'])
def action():
 if not ok():return redirect(url_for('login'))
 a=request.form.get('action','');ip=request.form.get('ip','');allowed={'block','unblock','whitelist-add','whitelist-remove'}
 if a not in allowed:return redirect(url_for('index',message='Invalid action'))
 good,out=run_guard('--'+a,ip);return redirect(url_for('index',message=('OK: ' if good else 'ERROR: ')+out))
if __name__=='__main__':app.run(host=HOST,port=PORT)