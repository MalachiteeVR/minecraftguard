import os,re,sys,time,sqlite3,argparse,subprocess,ipaddress
from pathlib import Path
from datetime import datetime,timezone
import requests
WORKDIR=Path(os.getenv('MINECRAFT_GUARD_WORKDIR',r'C:\Minecraft')); ENV_FILE=WORKDIR/'.env'; DB_FILE=WORKDIR/'blacklist.db'
FIREWALL_LOG=Path(os.getenv('MINECRAFT_GUARD_FIREWALL_LOG',r'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'))
PORT=int(os.getenv('MINECRAFT_GUARD_PORT','25565')); SCAN=int(os.getenv('MINECRAFT_GUARD_SCAN_INTERVAL','3')); SYNC=int(os.getenv('MINECRAFT_GUARD_DB_SYNC_INTERVAL','5'))
THRESHOLD=int(os.getenv('ABUSE_SCORE_THRESHOLD','10')); DATACENTER=os.getenv('DATACENTER_USAGE_TYPE','Data Center/Web Hosting/Transit')
def load_dotenv():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding='utf-8-sig').splitlines():
            line=line.strip()
            if line and not line.startswith('#') and '=' in line:
                k,v=line.split('=',1); os.environ[k.strip()]=v.strip().strip('"'')

class GuardDB:
    def __init__(self,p): self.p=p; self.init()
    def c(self):
        x=sqlite3.connect(self.p,timeout=10); x.execute('PRAGMA busy_timeout=10000'); return x
    def init(self):
        with self.c() as x:
            x.execute('CREATE TABLE IF NOT EXISTS blacklist (ip TEXT PRIMARY KEY,blocked_at TEXT NOT NULL,updated_at TEXT NOT NULL,source TEXT NOT NULL,abuse_score INTEGER,usage_type TEXT,country_code TEXT,isp TEXT,domain TEXT,notes TEXT)')
            x.execute('CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY,added_at TEXT NOT NULL,notes TEXT)')
    def blocked(self):
        with self.c() as x:return {r[0] for r in x.execute('SELECT ip FROM blacklist')}
    def white(self):
        with self.c() as x:return {r[0] for r in x.execute('SELECT ip FROM whitelist')}
    def is_white(self,ip): return ip in self.white()
    def is_blocked(self,ip): return ip in self.blocked()
    def add_block(self,ip,score=None,usage=None,country=None,isp=None,domain=None,notes=None,source='minecraft-guard/AbuseIPDB'):
        n=datetime.now(timezone.utc).isoformat()
        with self.c() as x:x.execute('INSERT INTO blacklist(ip,blocked_at,updated_at,source,abuse_score,usage_type,country_code,isp,domain,notes) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET updated_at=excluded.updated_at,source=excluded.source,abuse_score=excluded.abuse_score,usage_type=excluded.usage_type,country_code=excluded.country_code,isp=excluded.isp,domain=excluded.domain,notes=excluded.notes',(ip,n,n,source,score,usage,country,isp,domain,notes))
    def remove_block(self,ip):
        with self.c() as x:x.execute('DELETE FROM blacklist WHERE ip=?',(ip,))
    def add_white(self,ip,notes='Manual Whitelist'):
        n=datetime.now(timezone.utc).isoformat()
        with self.c() as x:x.execute('INSERT INTO whitelist(ip,added_at,notes) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET added_at=excluded.added_at,notes=excluded.notes',(ip,n,notes))
    def remove_white(self,ip):
        with self.c() as x:x.execute('DELETE FROM whitelist WHERE ip=?',(ip,))
    def lists(self):
        with self.c() as x:return x.execute('SELECT ip,blocked_at,updated_at,source,abuse_score,usage_type,country_code,isp,domain,notes FROM blacklist ORDER BY blocked_at DESC').fetchall(),x.execute('SELECT ip,added_at,notes FROM whitelist ORDER BY added_at DESC').fetchall()

def public(ip):
    try:return ipaddress.ip_address(ip).version==4 and ipaddress.ip_address(ip).is_global
    except:return False

def fw(args):return subprocess.run(['netsh','advfirewall','firewall']+args,capture_output=True,text=True,timeout=15)
def rname(ip):return f'MinecraftGuard_Block_{ip}'
def block(ip):
    if not public(ip):return False
    n=rname(ip); q=fw(['show','rule',f'name={n}'])
    if q.returncode==0 and 'No rules match' not in q.stdout+q.stderr:return True
    q=fw(['add','rule',f'name={n}','dir=in','action=block','protocol=TCP',f'localport={PORT}',f'remoteip={ip}'])
    if q.returncode==0: print(f'[FIREWALL] Blocked {ip} TCP/{PORT}');return True
    print(f'[ERROR] Firewall block failed: {q.stderr.strip()}');return False

def unblock(ip):
    q=fw(['delete','rule',f'name={rname(ip)}'])
    if q.returncode==0 or 'No rules match' in q.stdout+q.stderr: print(f'[FIREWALL] Unblocked {ip}');return True
    print(f'[ERROR] Firewall unblock failed: {q.stderr.strip()}');return False

def sync(db,applied):
    desired=db.blocked()-db.white()
    for ip in desired-applied:
        if block(ip):applied.add(ip)
    for ip in applied-desired:
        if unblock(ip):applied.discard(ip)
    return applied

def netstat_ips():
    out=set()
    try:
        s=subprocess.run(['netstat','-ano','-p','tcp'],capture_output=True,text=True,check=True).stdout
        rx=re.compile(rf'^\s*TCP\s+\S+:{PORT}\s+(\d{{1,3}}(?:\.\d{{1,3}}){{3}}):\d+\s+ESTABLISHED',re.M)
        for m in rx.finditer(s):
            if public(m.group(1)):out.add(m.group(1))
    except:pass
    return out

def log_ips(pos):
    out=set()
    if not FIREWALL_LOG.exists():return out,pos
    try:
        with FIREWALL_LOG.open('r',encoding='utf-8',errors='ignore') as f:f.seek(pos); lines=f.readlines(); pos=f.tell()
        for line in lines:
            p=line.split()
            if len(p)>=8 and p[7]==str(PORT) and public(p[4]):out.add(p[4])
    except Exception as e:print('[WARN] firewall log:',e)
    return out,pos

def abuse(ip,key):
    try:
        r=requests.get('https://api.abuseipdb.com/api/v2/check',headers={'Key':key,'Accept':'application/json'},params={'ipAddress':ip,'maxAgeInDays':'90','verbose':''},timeout=10)
        return r.json().get('data') if r.status_code==200 else None
    except:return None

def discord(url,title,color,fields):
    if url:
        try:requests.post(url,json={'embeds':[{'title':title,'color':color,'fields':fields,'timestamp':datetime.now(timezone.utc).isoformat()}]},timeout=5)
        except:pass

def process(ip,db,key,hook):
    if db.is_white(ip) or db.is_blocked(ip):return
    d=abuse(ip,key)
    if not d:return
    score=d.get('abuseConfidenceScore',0); usage=d.get('usageType','Unknown'); country=d.get('countryCode','Unknown'); isp=d.get('isp','Unknown'); domain=d.get('domain','N/A'); reasons=[]
    if score>=THRESHOLD:reasons.append(f'Abuse score {score}% >= threshold {THRESHOLD}%')
    if usage==DATACENTER:reasons.append(f"Usage type '{usage}' matched policy")
    if reasons:
        reason='; '.join(reasons); db.add_block(ip,score,usage,country,isp,domain,reason); block(ip); discord(hook,f'Blocked: {ip}',0xE74C3C,[{'name':'IP','value':ip},{'name':'Reason','value':reason}])

def main():
    load_dotenv(); db=GuardDB(DB_FILE); ap=argparse.ArgumentParser(); ap.add_argument('--list',action='store_true');ap.add_argument('--block');ap.add_argument('--unblock');ap.add_argument('--whitelist-add');ap.add_argument('--whitelist-remove');ap.add_argument('--whitelist-list',action='store_true');a=ap.parse_args()
    if a.list or a.whitelist_list:
        b,w=db.lists(); print(b if a.list else w);return
    if a.block:db.add_block(a.block,notes='Manual CLI block',source='minecraft-guard/manual');block(a.block);return
    if a.unblock:db.remove_block(a.unblock);unblock(a.unblock);return
    if a.whitelist_add:db.add_white(a.whitelist_add);db.remove_block(a.whitelist_add);unblock(a.whitelist_add);return
    if a.whitelist_remove:db.remove_white(a.whitelist_remove);return
    key=os.getenv('ABUSEIPDB_API_KEY'); hook=os.getenv('DISCORD_WEBHOOK_URL')
    if not key:sys.exit('[ERROR] ABUSEIPDB_API_KEY is missing.')
    applied=set();seen=set();pos=FIREWALL_LOG.stat().st_size if FIREWALL_LOG.exists() else 0
    print(f'[GUARD] DB sync every {SYNC}s. Firewall: Windows Defender Firewall. Minecraft TCP/{PORT}.')
    while True:
        try:
            applied=sync(db,applied); ips,pos=log_ips(pos);ips|=netstat_ips()
            for ip in ips-seen:seen.add(ip);process(ip,db,key,hook)
            time.sleep(SYNC)
        except KeyboardInterrupt:return
        except Exception as e:print('[ERROR]',e);time.sleep(3)

if __name__=='__main__':main()
