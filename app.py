#!/usr/bin/env python3
"""Malachite Minecraft Guard, Linux relay edition. UFW + AbuseIPDB monitoring."""
import ipaddress,json,logging,os,re,socket,sqlite3,subprocess,threading,time
import requests
from datetime import datetime,timezone
from flask import Flask,jsonify,redirect,render_template_string,request,session

BASE=os.getenv("GUARD_DIR","/opt/minecraft-guard"); DB=os.getenv("GUARD_DB",f"{BASE}/guard.db")
GLOG=os.getenv("GUARD_LOG",f"{BASE}/guard.log"); HLOG=os.getenv("HA_LOG","/var/log/haproxy.log")
HSOCK=os.getenv("HAPROXY_SOCKET","/run/haproxy/admin.sock"); BACKEND=os.getenv("MINECRAFT_TARGET","100.87.154.87:25565")
UFW_LOG=os.getenv("UFW_LOG","/var/log/ufw.log")
ABUSEIPDB_KEY=os.getenv("ABUSEIPDB_API_KEY",""); ABUSE_THRESHOLD=int(os.getenv("ABUSEIPDB_THRESHOLD","10"))
ABUSE_MAX_AGE=int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS","90")); ABUSE_CACHE_HOURS=int(os.getenv("ABUSEIPDB_CACHE_HOURS","24"))
PORT=int(os.getenv("MINECRAFT_PUBLIC_PORT","25565")); HOST=os.getenv("GUARD_WEB_HOST","0.0.0.0")
WEBPORT=int(os.getenv("GUARD_WEB_PORT","2555")); PASSWORD=os.getenv("PANEL_PASSWORD","")
SECRET=os.getenv("PANEL_SECRET","") or os.urandom(32).hex()
os.makedirs(BASE,exist_ok=True)
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s",handlers=[logging.FileHandler(GLOG),logging.StreamHandler()])
log=logging.getLogger("minecraft-guard"); app=Flask(__name__); app.secret_key=SECRET

def cmd(a): return subprocess.run(a,capture_output=True,text=True,timeout=8)
def now(): return datetime.now(timezone.utc).isoformat()
def ip_ok(v):
    try:return str(ipaddress.ip_address(v.strip()))
    except ValueError:raise ValueError("Invalid IP address")

class Store:
    def __init__(self):
        os.makedirs(os.path.dirname(DB),exist_ok=True)
        with self.c() as c:
            c.execute("CREATE TABLE IF NOT EXISTS blacklist(ip TEXT PRIMARY KEY,created TEXT,source TEXT,notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS whitelist(ip TEXT PRIMARY KEY,created TEXT,notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts TEXT,level TEXT,event TEXT,ip TEXT,details TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS reputation(ip TEXT PRIMARY KEY,checked REAL,score INTEGER,usage_type TEXT,isp TEXT,country TEXT,total_reports INTEGER)")
    def c(self):
        c=sqlite3.connect(DB,timeout=10);c.row_factory=sqlite3.Row;return c
    def rows(self,q,a=()):
        with self.c() as c:return [dict(x) for x in c.execute(q,a)]
    def blocked(self):return self.rows("SELECT * FROM blacklist ORDER BY created DESC")
    def white(self):return self.rows("SELECT * FROM whitelist ORDER BY created DESC")
    def iswhite(self,ip):return bool(self.rows("SELECT ip FROM whitelist WHERE ip=?",(ip,)))
    def isblocked(self,ip):return bool(self.rows("SELECT ip FROM blacklist WHERE ip=?",(ip,)))
    def event(self,l,e,ip="",d=""):
        with self.c() as c:c.execute("INSERT INTO events(ts,level,event,ip,details) VALUES(?,?,?,?,?)",(now(),l,e,ip,d))
    def events(self,n=250):return self.rows("SELECT * FROM events ORDER BY id DESC LIMIT ?",(n,))
    def block(self,ip,src,n):
        with self.c() as c:c.execute("INSERT OR REPLACE INTO blacklist VALUES(?,?,?,?)",(ip,now(),src,n))
    def unblock(self,ip):
        with self.c() as c:c.execute("DELETE FROM blacklist WHERE ip=?",(ip,))
    def addwhite(self,ip,n):
        with self.c() as c:c.execute("INSERT OR REPLACE INTO whitelist VALUES(?,?,?)",(ip,now(),n))
    def delwhite(self,ip):
        with self.c() as c:c.execute("DELETE FROM whitelist WHERE ip=?",(ip,))
    def reputation(self,ip):
        with self.c() as c:
            r=c.execute("SELECT * FROM reputation WHERE ip=?",(ip,)).fetchone()
            return dict(r) if r else None
    def save_reputation(self,ip,score,usage,isp,country,reports):
        with self.c() as c:c.execute("INSERT OR REPLACE INTO reputation VALUES(?,?,?,?,?,?,?)",(ip,time.time(),score,usage,isp,country,reports))
store=Store()

def ufw_ok():
    r=cmd(["ufw","status"]);return r.returncode==0
def ufw(action,ip,proto,insert=False):
    rule=["ufw",action,"from",ip,"to","any","port",str(PORT),"proto",proto]
    if insert:rule[1:1]=["insert","1"]
    r=cmd(rule)
    if r.returncode:log.error("UFW %s %s/%s: %s",action,ip,proto,r.stderr.strip() or r.stdout.strip())
    return r.returncode==0
def ufw_del(action,ip,proto):
    rule=["ufw","delete",action,"from",ip,"to","any","port",str(PORT),"proto",proto]
    r=cmd(rule);return r.returncode==0 or "Could not delete" in r.stdout+r.stderr

def firewall_setup():
    if os.geteuid()!=0 or not ufw_ok():
        log.error("Guard requires working UFW and root privileges")
        return False
    for p in ("tcp","udp"):
        cmd(["ufw","delete","allow",f"{PORT}/{p}"])
        r=cmd(["ufw","allow","log",f"{PORT}/{p}"])
        if r.returncode:
            log.error("Failed to configure UFW logging rule for %s/%s",PORT,p)
            return False
    if cmd(["ufw","logging","medium"]).returncode:
        log.error("Failed to enable UFW medium logging")
        return False
    for x in store.white():
        for p in ("tcp","udp"):ufw_del("deny",x["ip"],p);ufw_del("allow",x["ip"],p);ufw("allow",x["ip"],p,True)
    for x in store.blocked():
        if store.iswhite(x["ip"]):continue
        for p in ("tcp","udp"):ufw_del("deny",x["ip"],p);ufw("deny",x["ip"],p,True)
    return True

def block_ip(ip):
    if store.iswhite(ip):return False,"IP is whitelisted"
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):
        ufw_del("allow",ip,p);ufw_del("deny",ip,p)
        if not ufw("deny",ip,p,True):return False,"UFW failed to add block"
    return True,"blocked"
def unblock_ip(ip):
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):ufw_del("deny",ip,p)
    return True,"unblocked"
def whitelist_ip(ip):
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):
        ufw_del("deny",ip,p);ufw_del("allow",ip,p)
        if not ufw("allow",ip,p,True):return False,"UFW failed to add whitelist"
    return True,"whitelisted"
def unwhitelist_ip(ip):
    if not ufw_ok():return False,"UFW is unavailable"
    for p in ("tcp","udp"):ufw_del("allow",ip,p)
    return True,"removed"

def ha(c):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3);s.connect(HSOCK);s.sendall((c+"\n").encode());o=[]
    while 1:
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
        ip,port=q[0];out.append({"session":sid,"ip":ip,"port":port,"dst":q[1][0]+":"+q[1][1] if len(q)>1 else BACKEND})
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
        with open(p,"rb") as f:f.seek(0,2);z=f.tell();f.seek(max(0,z-1048576));d=f.read().decode(errors="replace")
        return "\n".join(d.splitlines()[-n:])
    except Exception as e:return str(e)

def is_public_ip(ip):
    try:return ipaddress.ip_address(ip).is_global
    except ValueError:return False

def abuse_check(ip):
    if not ABUSEIPDB_KEY or not is_public_ip(ip) or store.iswhite(ip):return None
    cached=store.reputation(ip)
    if cached and time.time()-cached["checked"] < ABUSE_CACHE_HOURS*3600:return cached
    try:
        r=requests.get("https://api.abuseipdb.com/api/v2/check",headers={"Accept":"application/json","Key":ABUSEIPDB_KEY},params={"ipAddress":ip,"maxAgeInDays":ABUSE_MAX_AGE},timeout=8)
        if r.status_code!=200:
            store.event("ERROR","ABUSEIPDB_ERROR",ip,f"HTTP {r.status_code}");log.error("AbuseIPDB check failed for %s: HTTP %s",ip,r.status_code);return None
        d=r.json().get("data",{});score=int(d.get("abuseConfidenceScore") or 0);usage=str(d.get("usageType") or "")
        isp=str(d.get("isp") or "");country=str(d.get("countryCode") or "");reports=int(d.get("totalReports") or 0)
        store.save_reputation(ip,score,usage,isp,country,reports)
        store.event("INFO","ABUSEIPDB_CHECK",ip,f"score={score}% usage={usage} reports={reports} isp={isp} country={country}")
        return {"score":score,"usage_type":usage,"isp":isp,"country":country,"total_reports":reports}
    except Exception as e:
        store.event("ERROR","ABUSEIPDB_ERROR",ip,str(e));log.error("AbuseIPDB check failed for %s: %s",ip,e);return None

def inspect_ip(ip):
    try:ip=ip_ok(ip)
    except ValueError:return
    if not is_public_ip(ip) or store.iswhite(ip) or store.isblocked(ip):return
    result=abuse_check(ip)
    if not result:return
    usage=result["usage_type"].lower()
    datacenter="data center/web hosting/transit" in usage or "data center" in usage or "web hosting" in usage or usage=="hosting"
    if result["score"]>=ABUSE_THRESHOLD or datacenter:
        reason=[]
        if result["score"]>=ABUSE_THRESHOLD:reason.append(f"abuse score {result['score']}% >= {ABUSE_THRESHOLD}%")
        if datacenter:reason.append(f"datacenter/hosting usage: {result['usage_type']}")
        details="; ".join(reason)+f"; reports={result['total_reports']}; isp={result['isp']}"
        ok,msg=block_ip(ip)
        if ok:
            store.block(ip,"AbuseIPDB",details);store.event("WARN","ABUSEIPDB_AUTO_BLOCK",ip,details);close_ip(ip);log.warning("Automatically blocked %s: %s",ip,details)
        else:store.event("ERROR","ABUSEIPDB_BLOCK_FAILED",ip,msg)

def parse_ufw_line(line):
    if "UFW " not in line or f"DPT={PORT}" not in line:return None
    if not re.search(r"UFW\s+(?:ALLOW|BLOCK|REJECT)\s+",line):return None
    sm=re.search(r"\bSRC=([^\s]+)",line)
    if not sm:return None
    proto=re.search(r"\bPROTO=([^\s]+)",line)
    return sm.group(1),proto.group(1) if proto else "?"

def ufw_monitor():
    if not ABUSEIPDB_KEY:log.warning("AbuseIPDB checking disabled: ABUSEIPDB_API_KEY is not configured")
    pos=0
    try:pos=os.path.getsize(UFW_LOG)
    except OSError:pass
    while 1:
        try:
            if not os.path.exists(UFW_LOG):time.sleep(2);continue
            size=os.path.getsize(UFW_LOG)
            if size<pos:pos=0
            with open(UFW_LOG,"r",errors="replace") as f:
                f.seek(pos)
                for line in f:
                    pos=f.tell();parsed=parse_ufw_line(line)
                    if not parsed:continue
                    ip,proto=parsed
                    store.event("INFO","UFW_CONNECTION",ip,f"port={PORT} proto={proto}")
                    inspect_ip(ip)
        except Exception as e:log.error("UFW monitor error: %s",e)
        time.sleep(1)

def vi(n):
    b=bytearray()
    while 1:
        x=n&127;n>>=7
        if n:x|=128
        b.append(x)
        if not n:return bytes(b)
def rvi(s):
    n=sh=0
    while 1:
        b=s.recv(1)
        if not b:raise ConnectionError("closed")
        x=b[0];n|=(x&127)<<sh
        if not x&128:return n
        sh+=7
def readvi(d,i):
    n=sh=0
    while 1:
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
    while 1:
        try:STATUS=ping()
        except Exception as e:STATUS={"online":0,"latency":None,"status":{},"error":str(e)}
        time.sleep(10)

HTML="""<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><title>Malachite Guard</title><style>body{font:14px sans-serif;background:#111;color:#eee;max-width:1200px;margin:auto;padding:20px}section{background:#222;padding:15px;margin:10px 0;border-radius:8px}input,button{padding:8px;margin:3px;background:#111;color:#eee;border:1px solid #555}table{width:100%}td,th{padding:7px;text-align:left;border-bottom:1px solid #444}pre{white-space:pre-wrap;max-height:350px;overflow:auto}</style></head><body><h1>Malachite Minecraft Guard</h1>
{% if not authed %}<section><form method=post action=/login><input name=password type=password placeholder="Panel password" required><button>Sign in</button></form></section>
{% else %}<section><b>Backend:</b> {{backend}} | <b>Minecraft:</b> {{'ONLINE' if status.online else 'OFFLINE'}} | <b>Latency:</b> {{status.latency or status.error}} | <form method=post action=/logout><button>Log out</button></form></section>
<section><b>Players:</b> {{status.status.get('players',{}).get('online',0)}} / {{status.status.get('players',{}).get('max','?')}}<br><b>Blocked:</b> {{blocked|length}} &nbsp; <b>Whitelisted:</b> {{white|length}}<br><b>AbuseIPDB:</b> {{'Enabled' if abuse_enabled else 'Disabled'}} &nbsp; <b>Auto-block:</b> score &gt;= {{abuse_threshold}}% or datacenter/hosting</section>
<section><h2>Block / whitelist</h2><form method=post action=/block><input name=ip placeholder=IP required><input name=notes placeholder=reason><button>Block</button></form>
<form method=post action=/whitelist><input name=ip placeholder=IP required><input name=notes placeholder=notes><button>Whitelist</button></form></section>
<section><h2>Connections</h2><table><tr><th>IP</th><th>Port</th><th>Destination</th><th>Action</th></tr>{% for x in conns %}<tr><td>{{x.ip}}</td><td>{{x.port}}</td><td>{{x.dst}}</td><td><form method=post action="/connection/{{x.session}}/close"><button>Close</button></form><form method=post action="/block/{{x.ip}}"><button>Block</button></form></td></tr>{% else %}<tr><td colspan=4>None</td></tr>{% endfor %}</table></section>
<section><h2>Blacklist</h2><table>{% for x in blocked %}<tr><td>{{x.ip}}</td><td>{{x.source}}</td><td>{{x.notes}}</td><td><form method=post action="/unblock/{{x.ip}}"><button>Remove</button></form></td></tr>{% else %}<tr><td>None</td></tr>{% endfor %}</table></section>
<section><h2>Whitelist</h2><table>{% for x in white %}<tr><td>{{x.ip}}</td><td>{{x.notes}}</td><td><form method=post action="/unwhitelist/{{x.ip}}"><button>Remove</button></form></td></tr>{% else %}<tr><td>None</td></tr>{% endfor %}</table></section>
<section><h2>Web Logger</h2><table><tr><th>Time</th><th>Level</th><th>Event</th><th>IP</th><th>Details</th></tr>{% for x in events %}<tr><td>{{x.ts}}</td><td>{{x.level}}</td><td>{{x.event}}</td><td>{{x.ip}}</td><td>{{x.details}}</td></tr>{% else %}<tr><td colspan=5>None</td></tr>{% endfor %}</table></section>
<section><h2>Logs</h2><pre>{{hlog}}</pre><pre>{{glog}}</pre></section>{% endif %}</body></html>"""
def auth():return not PASSWORD or session.get("auth") is True
def page():
    if not auth():return render_template_string(HTML,authed=False,error=None)
    return render_template_string(HTML,authed=True,status=STATUS,backend=BACKEND,blocked=store.blocked(),white=store.white(),conns=sessions(),events=store.events(),abuse_enabled=bool(ABUSEIPDB_KEY),abuse_threshold=ABUSE_THRESHOLD,hlog=tail(HLOG),glog=tail(GLOG))
@app.route("/login",methods=["GET","POST"])
def login():
    if not PASSWORD:return redirect("/")
    if request.method=="POST":
        if request.form.get("password","")==PASSWORD:session["auth"]=True;return redirect("/")
        return render_template_string(HTML,authed=False,error="Invalid password")
    return page()
@app.post("/logout")
def logout():session.clear();return redirect("/login")
@app.get("/")
def index():return page()
@app.get("/api/status")
def api_status():
    if not auth():return jsonify(error="unauthorized"),401
    return jsonify(STATUS)
@app.post("/block")
def block():
    if not auth():return redirect("/login")
    try:ip=ip_ok(request.form.get("ip",""))
    except ValueError as e:return str(e),400
    if store.iswhite(ip):return "IP is whitelisted",409
    ok,msg=block_ip(ip)
    if not ok:return msg,500
    n=request.form.get("notes","").strip() or "Manual web block";store.block(ip,"Manual Web",n);store.event("WARN","MANUAL_BLOCK",ip,n);close_ip(ip);return redirect("/")
@app.post("/block/<ip>")
def block_path(ip):
    if not auth():return redirect("/login")
    try:ip=ip_ok(ip)
    except ValueError as e:return str(e),400
    ok,msg=block_ip(ip)
    if not ok:return msg,500
    store.block(ip,"Manual Web","Connection list");store.event("WARN","MANUAL_BLOCK",ip,"Connection list");close_ip(ip);return redirect("/")
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
    n=request.form.get("notes","").strip() or "Manual whitelist";ok,msg=whitelist_ip(ip)
    if not ok:return msg,500
    store.addwhite(ip,n);store.unblock(ip);store.event("INFO","WHITELIST_ADD",ip,n);return redirect("/")
@app.post("/unwhitelist/<ip>")
def unwhitelist(ip):
    if not auth():return redirect("/login")
    try:ip=ip_ok(ip)
    except ValueError as e:return str(e),400
    ok,msg=unwhitelist_ip(ip)
    if not ok:return msg,500
    store.delwhite(ip);store.event("INFO","WHITELIST_REMOVE",ip);return redirect("/")
@app.post("/connection/<sid>/close")
def close(sid):
    if not auth():return redirect("/login")
    try:close_session(sid)
    except Exception as e:return str(e),400
    store.event("INFO","SESSION_CLOSE",details=sid);return redirect("/")
def main():
    if not firewall_setup():
        log.critical("Firewall setup failed; refusing to start")
        raise SystemExit(1)
    threading.Thread(target=worker,daemon=True).start()
    threading.Thread(target=ufw_monitor,daemon=True).start()
    log.info("Guard starting: backend=%s web=%s:%s firewall=ufw",BACKEND,HOST,WEBPORT)
    app.run(host=HOST,port=WEBPORT,threaded=True,debug=False,use_reloader=False)
if __name__=="__main__":main()
