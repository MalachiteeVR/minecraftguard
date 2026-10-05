#!/usr/bin/env python3
"""Malachite Minecraft Guard, Linux relay edition. UFW-only firewall control."""
import ipaddress,json,logging,os,re,socket,sqlite3,subprocess,threading,time
from datetime import datetime,timezone
from flask import Flask,jsonify,redirect,render_template_string,request,session

BASE=os.getenv("GUARD_DIR","/opt/minecraft-guard"); DB=os.getenv("GUARD_DB",f"{BASE}/guard.db")
GLOG=os.getenv("GUARD_LOG",f"{BASE}/guard.log"); HLOG=os.getenv("HA_LOG","/var/log/haproxy.log")
HSOCK=os.getenv("HAPROXY_SOCKET","/run/haproxy/admin.sock"); BACKEND=os.getenv("MINECRAFT_TARGET","100.87.154.87:25565")
PORT=int(os.getenv("MINECRAFT_PUBLIC_PORT","25565")); WHOST=os.getenv("GUARD_WEB_HOST","0.0.0.0"); WPORT=int(os.getenv("GUARD_WEB_PORT","2555"))
PASSWORD=os.getenv("PANEL_PASSWORD",""); SECRET=os.getenv("PANEL_SECRET","") or os.urandom(32).hex()
os.makedirs(BASE,exist_ok=True)
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s",handlers=[logging.FileHandler(GLOG),logging.StreamHandler()]);log=logging.getLogger("minecraft-guard")
app=Flask(__name__);app.secret_key=SECRET

def now():return datetime.now(timezone.utc).isoformat()
def ip_ok(v):
    try:return str(ipaddress.ip_address(v.strip()))
    except ValueError:raise ValueError("Invalid IP address")
def cmd(a):return subprocess.run(a,capture_output=True,text=True,timeout=8)

class Store:
    def __init__(self):
        os.makedirs(os.path.dirname(DB),exist_ok=True)
        with self.c() as c:
            c.execute("CREATE TABLE IF NOT EXISTS blacklist(ip TEXT PRIMARY KEY,created TEXT,source TEXT,notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS whitelist(ip TEXT PRIMARY KEY,created TEXT,notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,level TEXT,event TEXT,ip TEXT,details TEXT)");c.commit()
    def c(self):
        c=sqlite3.connect(DB,timeout=10);c.row_factory=sqlite3.Row;return c
    def event(self,l,e,ip="",d=""):
        with self.c() as c:c.execute("INSERT INTO events(ts,level,event,ip,details) VALUES(?,?,?,?,?)",(now(),l,e,ip,d));c.commit()
    def blocked(self):
        with self.c() as c:return [dict(r) for r in c.execute("SELECT * FROM blacklist ORDER BY created DESC")]
    def white(self):
        with self.c() as c:return [dict(r) for r in c.execute("SELECT * FROM whitelist ORDER BY created DESC")]
    def isblocked(self,ip):
        with self.c() as c:return c.execute("SELECT 1 FROM blacklist WHERE ip=?",(ip,)).fetchone() is not None
    def iswhite(self,ip):
        with self.c() as c:return c.execute("SELECT 1 FROM whitelist WHERE ip=?",(ip,)).fetchone() is not None
    def block(self,ip,src,n):
        with self.c() as c:c.execute("INSERT OR REPLACE INTO blacklist VALUES(?,?,?,?)",(ip,now(),src,n));c.commit()
    def unblock(self,ip):
        with self.c() as c:c.execute("DELETE FROM blacklist WHERE ip=?",(ip,));c.commit()
    def addwhite(self,ip,n):
        with self.c() as c:c.execute("INSERT OR REPLACE INTO whitelist VALUES(?,?,?)",(ip,now(),n));c.commit()
    def unwhite(self,ip):
        with self.c() as c:c.execute("DELETE FROM whitelist WHERE ip=?",(ip,));c.commit()
    def events(self,n=250):
        with self.c() as c:return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(n,))]
store=Store()

def ufw_ok():
    r=cmd(["ufw","status"]);return r.returncode==0
def ufw_rule(action,ip,proto,insert=False):
    rule=["ufw",action,"from",ip,"to","any","port",str(PORT),"proto",proto]
    if insert:rule[1:1]=["insert","1"]
    r=cmd(rule)
    if r.returncode:log.error("UFW %s %s/%s: %s",action,ip,proto,r.stderr.strip() or r.stdout.strip())
    return r.returncode==0
def ufw_delete(action,ip,proto):
    r=cmd(["ufw","delete",action,"from",ip,"to","any","port",str(PORT),"proto",proto]);return r.returncode==0 or "Could not delete" in r.stdout+r.stderr

def firewall_setup():
    if os.geteuid()!=0:log.error("Guard must run as root for UFW management");return False
    if not ufw_ok():log.error("UFW is unavailable or failed");return False
    for proto in ("tcp","udp"):
        r=cmd(["ufw","allow",f"{PORT}/{proto}"])
        if r.returncode:log.error("Could not allow Minecraft %s: %s",proto,r.stderr.strip() or r.stdout.strip());return False
    for x in store.white():whitelist_ip(x["ip"])
    for x in store.blocked():
        if not store.iswhite(x["ip"]):block_ip(x["ip"])
    return True

def block_ip(ip):
    if store.iswhite(ip):return False,"IP is whitelisted"
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):
        ufw_delete("allow",ip,p);ufw_delete("deny",ip,p)
        if not ufw_rule("deny",ip,p,True):return False,"UFW failed to add block"
    return True,"blocked"
def unblock_ip(ip):
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):ufw_delete("deny",ip,p)
    return True,"unblocked"
def whitelist_ip(ip):
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):
        ufw_delete("deny",ip,p);ufw_delete("allow",ip,p)
        if not ufw_rule("allow",ip,p,True):return False,"UFW failed to add whitelist"
    return True,"whitelisted"
def unwhitelist_ip(ip):
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):ufw_delete("allow",ip,p)
    return True,"removed"

def ha(c):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3);s.connect(HSOCK);s.sendall((c+"\n").encode());o=[]
    while True:
        try:
            b=s.recv(65536)
            if not b:break
            o.append(b)
        except socket.timeout:break
    s.close();return b"".join(o).decode(errors="replace")
def sessions():
    try:r=ha("show sess")
    except Exception:return []
    out=[]
    for line in r.splitlines():
        f=line.split();sid=f[0] if f else ""
        if not re.fullmatch(r"0x[0-9a-fA-F]+",sid):continue
        q=re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)",line)
        if not q:continue
        ip,port=q[0]
        try:ip_ok(ip)
        except ValueError:continue
        out.append({"session":sid,"ip":ip,"port":port,"dst":q[1][0]+":"+q[1][1] if len(q)>1 else BACKEND})
    return out
def close_session(sid):
    if not re.fullmatch(r"0x[0-9a-fA-F]+",sid):raise ValueError("Invalid session")
    return ha("shutdown session "+sid)
def close_ip(ip):
    for x in sessions():
        if x["ip"]==ip:
            try:close_session(x["session"])
            except Exception:pass
def tail(p,n=250):
    try:
        if not os.path.exists(p):return f"{p} does not exist."
        with open(p,"rb") as f:
            f.seek(0,2);z=f.tell();f.seek(max(0,z-1048576));d=f.read().decode(errors="replace")
        return "\n".join(d.splitlines()[-n:])
    except Exception as e:return str(e)
def vi(n):
    b=bytearray()
    while True:
        x=n&127;n>>=7
        if n:x|=128
        b.append(x)
        if not n:return bytes(b)
def rvi(s):
    n=sh=0
    while True:
        b=s.recv(1)
        if not b:raise ConnectionError("closed")
        x=b[0];n|=(x&127)<<sh
        if not x&128:return n
        sh+=7
def readvi(d,i):
    n=sh=0
    while True:
        x=d[i];i+=1;n|=(x&127)<<sh
        if not x&128:return n,i
        sh+=7
def ping():
    h,p=BACKEND.rsplit(":",1);p=int(p);t=time.monotonic()
    with socket.create_connection((h,p),3) as s:
        a=h.encode();pay=vi(0)+vi(763)+vi(len(a))+a+p.to_bytes(2,"big")+vi(1);s.sendall(vi(len(pay))+pay+b"\x01\x00")
        n=rvi(s);d=b""
        while len(d)<n:
            x=s.recv(n-len(d))
            if not x:raise ConnectionError("closed")
            d+=x
    i=0;_,i=readvi(d,i);ln,i=readvi(d,i);return {"online":1,"latency":round((time.monotonic()-t)*1000,1),"status":json.loads(d[i:i+ln]),"error":None}
STATUS={"online":0,"latency":None,"status":{},"error":"Not checked yet"}
def worker():
    global STATUS
    while True:
        try:STATUS=ping()
        except Exception as e:STATUS={"online":0,"latency":None,"status":{},"error":str(e)}
        time.sleep(10)

HTML="""<!doctype html><html><head><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Malachite Guard</title><style>body{font:14px sans-serif;background:#111;color:#eee;max-width:1200px;margin:auto;padding:20px}section{background:#222;padding:15px;margin:10px 0;border-radius:8px}input,button{padding:8px;margin:3px;background:#111;color:#eee;border:1px solid #555}table{width:100%}td,th{padding:7px;text-align:left;border-bottom:1px solid #444}.ok{color:#4f4}.bad{color:#f66}pre{background:#080808;padding:10px;max-height:400px;overflow:auto}.row{display:flex;gap:8px}.row>*{flex:1}</style></head><body><h1>Malachite Minecraft Guard</h1><p>UFW relay firewall • HAProxy • Minecraft status</p>{% if not authed %}<section><h2>Login</h2>{% if error %}<p class=bad>{{error}}</p>{% endif %}<form method=post action=/login><input name=password type=password placeholder=\"Panel password\" required><button>Sign in</button></form></section>{% else %}<section><b>Backend:</b> {{backend}}<form style=\"float:right\" method=post action=/logout><button>Log out</button></form></section><div class=row><section><b>Status</b><h2 class={{'ok' if status.online else 'bad'}}>{{'ONLINE' if status.online else 'OFFLINE'}}</h2>{% if status.online %}{{status.latency}} ms{% else %}{{status.error}}{% endif %}</section><section><b>Players</b><h2>{{status.status.get('players',{}).get('online',0)}} / {{status.status.get('players',{}).get('max','?')}}</h2></section><section><b>Blacklisted</b><h2 class=bad>{{blocked|length}}</h2></section><section><b>Whitelisted</b><h2 class=ok>{{whitelist|length}}</h2></section></div><section><h2>Blacklist / Whitelist</h2><div class=row><form method=post action=/block><input name=ip placeholder=\"IP address\" required><input name=notes placeholder=\"Notes\"><button>Block</button></form><form method=post action=/whitelist><input name=ip placeholder=\"IP address\" required><input name=notes placeholder=\"Notes\"><button>Whitelist</button></form></div></section><section><h2>Active HAProxy connections</h2><table><tr><th>IP</th><th>Port</th><th>Destination</th><th>Action</th></tr>{% for c in connections %}<tr><td>{{c.ip}}</td><td>{{c.port}}</td><td>{{c.dst}}</td><td><form method=post action=/connection/{{c.session}}/close><button>Close</button></form><form method=post action=/block/{{c.ip}}><button>Block IP</button></form></td></tr>{% else %}<tr><td colspan=4>No active connections.</td></tr>{% endfor %}</table></section><div class=row><section><h2>Blacklist</h2><table>{% for x in blocked %}<tr><td>{{x.ip}}</td><td>{{x.notes}}</td><td><form method=post action=/unblock/{{x.ip}}><button>Remove</button></form></td></tr>{% else %}<tr><td>None</td></tr>{% endfor %}</table></section><section><h2>Whitelist</h2><table>{% for x in whitelist %}<tr><td>{{x.ip}}</td><td>{{x.notes}}</td><td><form method=post action=/unwhitelist/{{x.ip}}><button>Remove</button></form></td></tr>{% else %}<tr><td>None</td></tr>{% endfor %}</table></section></div><section><h2>Events</h2><pre>{% for x in events %}{{x.ts}} [{{x.level}}] {{x.event}}{% if x.ip %} {{x.ip}}{% endif %}{% if x.details %} | {{x.details}}{% endif %}\n{% endfor %}</pre></section><section><h2>HAProxy log</h2><pre>{{ha_log}}</pre></section><section><h2>Guard log</h2><pre>{{guard_log}}</pre></section>{% endif %}</body></html>"""
def auth():return not PASSWORD or session.get("auth") is True
def page(error=None):
    if not auth():return render_template_string(HTML,authed=False,error=error)
    return render_template_string(HTML,authed=True,status=STATUS,backend=BACKEND,blocked=store.blocked(),whitelist=store.white(),events=store.events(),connections=sessions(),ha_log=tail(HLOG),guard_log=tail(GLOG),error=error)
@app.route("/login",methods=["GET","POST"])
def login():
    if not PASSWORD:return redirect("/")
    if request.method=="POST":
        if request.form.get("password","")==PASSWORD:session["auth"]=True;return redirect("/")
        return render_template_string(HTML,authed=False,error="Invalid password.")
    return page()
@app.post("/logout")
def logout():session.clear();return redirect("/login")
@app.get("/")
def index():return page()
@app.get("/api/status")
def api_status():
    if not auth():return jsonify({"error":"unauthorized"}),401
    return jsonify(STATUS)
@app.post("/block")
def block():
    if not auth():return redirect("/login")
    try:ip=ip_ok(request.form.get("ip",""))
    except ValueError as e:return str(e),400
    if store.iswhite(ip):return "IP is whitelisted. Remove it from the whitelist first.",409
    ok,msg=block_ip(ip)
    if not ok:return msg,500
    notes=request.form.get("notes","").strip() or "Manual Web block";store.block(ip,"Manual Web",notes);store.event("WARN","MANUAL_BLOCK",ip,notes);close_ip(ip);return redirect("/")
@app.post("/block/<ip>")
def block_path(ip):
    if not auth():return redirect("/login")
    try:ip=ip_ok(ip)
    except ValueError as e:return str(e),400
    if store.iswhite(ip):return "IP is whitelisted.",409
    ok,msg=block_ip(ip)
    if not ok:return msg,500
    store.block(ip,"Manual Web","Blocked from connection list");store.event("WARN","MANUAL_BLOCK",ip,"Connection list");close_ip(ip);return redirect("/")
@app.post("/unblock/<ip>")
def unblock(ip):
    if not auth():return redirect("/login")
    try:ip=ip_ok(ip)
    except ValueError as e:return str(e),400
    ok,msg=unblock_ip(ip)
    if not ok:return msg,500
    store.unblock(ip);store.event("INFO","MANUAL_UNBLOCK",ip,"Web panel");return redirect("/")
@app.post("/whitelist")
def whitelist():
    if not auth():return redirect("/login")
    try:ip=ip_ok(request.form.get("ip",""))
    except ValueError as e:return str(e),400
    notes=request.form.get("notes","").strip() or "Manual whitelist";ok,msg=whitelist_ip(ip)
    if not ok:return msg,500
    store.addwhite(ip,notes);store.unblock(ip);store.event("INFO","WHITELIST_ADD",ip,notes);return redirect("/")
@app.post("/unwhitelist/<ip>")
def unwhitelist(ip):
    if not auth():return redirect("/login")
    try:ip=ip_ok(ip)
    except ValueError as e:return str(e),400
    ok,msg=unwhitelist_ip(ip)
    if not ok:return msg,500
    store.unwhite(ip);store.event("INFO","WHITELIST_REMOVE",ip,"Web panel");return redirect("/")
@app.post("/connection/<sid>/close")
def close(sid):
    if not auth():return redirect("/login")
    try:close_session(sid)
    except Exception as e:return str(e),400
    store.event("INFO","SESSION_CLOSE",details=sid);return redirect("/")

def main():
    if not firewall_setup():log.warning("Firewall setup did not complete successfully")
    threading.Thread(target=worker,daemon=True).start();log.info("Minecraft Guard relay starting: backend=%s web=%s:%s",BACKEND,WHOST,WPORT);app.run(host=WHOST,port=WPORT,threaded=True,debug=False,use_reloader=False)
if __name__=="__main__":main()
