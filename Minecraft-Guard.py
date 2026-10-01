import os
import re
import time
import sqlite3
import argparse
import subprocess
import secrets
import threading
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from pathlib import Path
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("Missing dependency: requests")
    print("Install with: python -m pip install -r requirements.txt")
    raise

WORKDIR = Path(os.getenv("MINECRAFT_GUARD_WORKDIR", r"C:\Minecraft"))
ENV_FILE = WORKDIR / ".env"
DB_FILE = WORKDIR / "minecraft-guard.db"
AUDIT_LOG = WORKDIR / "minecraft-guard-web-audit.log"

MINECRAFT_PORT = int(os.getenv("MINECRAFT_GUARD_PORT", "25565"))
SCAN_INTERVAL_SECONDS = int(os.getenv("MINECRAFT_GUARD_SCAN_INTERVAL", "5"))
ABUSE_SCORE_THRESHOLD = int(os.getenv("MINECRAFT_GUARD_ABUSE_THRESHOLD", "75"))
DATACENTER_USAGE_TYPE = os.getenv("MINECRAFT_GUARD_DATACENTER_TYPE", "Data Center/Web Hosting/Transit")
WEB_ENABLED = os.getenv("MINECRAFT_GUARD_WEB", "1").lower() not in ("0", "false", "no")
WEB_HOST = os.getenv("MINECRAFT_GUARD_WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("MINECRAFT_GUARD_WEB_PORT", "8080"))
WEB_ADMIN_PASSWORD = os.getenv("MINECRAFT_GUARD_ADMIN_PASSWORD", "")
WEB_SESSION_TTL = int(os.getenv("MINECRAFT_GUARD_SESSION_TTL", "3600"))
FIREWALL_LOG = Path(os.getenv("MINECRAFT_GUARD_FIREWALL_LOG", r"C:\path\to\your\pfirewall.log"))

def load_dotenv():
    if not ENV_FILE.exists():
        return
    try:
        for line in ENV_FILE.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"\''))
    except Exception as exc:
        print(f"[WARN] Could not read {ENV_FILE}: {exc}")

load_dotenv()
MINECRAFT_PORT = int(os.getenv("MINECRAFT_GUARD_PORT", str(MINECRAFT_PORT)))
SCAN_INTERVAL_SECONDS = int(os.getenv("MINECRAFT_GUARD_SCAN_INTERVAL", str(SCAN_INTERVAL_SECONDS)))
ABUSE_SCORE_THRESHOLD = int(os.getenv("MINECRAFT_GUARD_ABUSE_THRESHOLD", str(ABUSE_SCORE_THRESHOLD)))
DATACENTER_USAGE_TYPE = os.getenv("MINECRAFT_GUARD_DATACENTER_TYPE", DATACENTER_USAGE_TYPE)
WEB_ENABLED = os.getenv("MINECRAFT_GUARD_WEB", "1").lower() not in ("0", "false", "no")
WEB_HOST = os.getenv("MINECRAFT_GUARD_WEB_HOST", WEB_HOST)
WEB_PORT = int(os.getenv("MINECRAFT_GUARD_WEB_PORT", str(WEB_PORT)))
WEB_ADMIN_PASSWORD = os.getenv("MINECRAFT_GUARD_ADMIN_PASSWORD", WEB_ADMIN_PASSWORD)
WEB_SESSION_TTL = int(os.getenv("MINECRAFT_GUARD_SESSION_TTL", str(WEB_SESSION_TTL))
FIREWALL_LOG = Path(os.getenv("MINECRAFT_GUARD_FIREWALL_LOG", str(FIREWALL_LOG)))

class GuardDB:
    def __init__(self, path):
        self.path = path
        self._init()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _init(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY, blocked_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                source TEXT NOT NULL, abuse_score INTEGER, usage_type TEXT,
                country_code TEXT, isp TEXT, domain TEXT, notes TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS whitelist (
                ip TEXT PRIMARY KEY, added_at TEXT NOT NULL, notes TEXT)""")
            c.commit()

    def is_blocked(self, ip):
        with self._conn() as c:
            return c.execute("SELECT 1 FROM blacklist WHERE ip=?", (ip,)).fetchone() is not None

    def is_whitelisted(self, ip):
        with self._conn() as c:
            return c.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,)).fetchone() is not None

    def add_blacklist(self, ip, score=None, usage=None, country=None, isp=None, domain=None, notes=""):
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute("""INSERT INTO blacklist
                (ip,blocked_at,updated_at,source,abuse_score,usage_type,country_code,isp,domain,notes)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET updated_at=excluded.updated_at,
                abuse_score=excluded.abuse_score, usage_type=excluded.usage_type,
                country_code=excluded.country_code, isp=excluded.isp,
                domain=excluded.domain, notes=excluded.notes""",
                (ip, now, now, "Minecraft-Guard", score, usage, country, isp, domain, notes))
            c.commit()

    def remove_blacklist(self, ip):
        with self._conn() as c:
            c.execute("DELETE FROM blacklist WHERE ip=?", (ip,))
            c.commit()

    def add_whitelist(self, ip, notes=""):
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO whitelist VALUES (?,?,?)",
                      (ip, datetime.now(timezone.utc).isoformat(), notes))
            c.commit()

    def remove_whitelist(self, ip):
        with self._conn() as c:
            c.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
            c.commit()

    def blacklisted(self):
        with self._conn() as c:
            return c.execute("SELECT ip,blocked_at,abuse_score,usage_type,notes FROM blacklist ORDER BY blocked_at DESC").fetchall()

    def whitelisted(self):
        with self._conn() as c:
            return c.execute("SELECT ip,added_at,notes FROM whitelist ORDER BY added_at DESC").fetchall()

    def counts(self):
        with self._conn() as c:
            return (c.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0],
                    c.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0])

    def audit(self, action, ip="", detail=""):
        try:
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()}\t{action}\t{ip}\t{detail}\n")
        except OSError:
            pass

def public_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a,b,c,d = map(int, parts)
    except ValueError:
        return False
    if any(x < 0 or x > 255 for x in (a,b,c,d)):
        return False
    if a in (10,127) or a >= 224 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if a == 169 and b == 254:
        return False
    return True

def firewall_block(ip):
    rule = f"MinecraftGuard_Block_{ip}"
    ps = f"if (-not (Get-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName '{rule}' -Direction Inbound -Action Block -RemoteAddress '{ip}' -Enabled True }}"
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, check=True)
        return True
    except Exception as exc:
        print(f"[ERROR] Firewall block failed for {ip}: {exc}")
        return False

def firewall_unblock(ip):
    rule = f"MinecraftGuard_Block_{ip}"
    ps = f"Remove-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue"
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, check=True)
        return True
    except Exception as exc:
        print(f"[ERROR] Firewall unblock failed for {ip}: {exc}")
        return False

def netstat_ips():
    found = set()
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, check=True).stdout
        rx = re.compile(rf"^\s*TCP\s+\S+:{MINECRAFT_PORT}\s+(\d{{1,3}}(?:\.\d{{1,3}}){{3}}):\d+\s+ESTABLISHED", re.MULTILINE)
        for m in rx.finditer(out):
            if public_ipv4(m.group(1)):
                found.add(m.group(1))
    except Exception:
        pass
    return found

def abuse_check(ip, key):
    if not key:
        return None
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": "90"},
                         timeout=10)
        return r.json().get("data") if r.status_code == 200 else None
    except Exception:
        return None

_sessions = {}
_sessions_lock = threading.Lock()

def new_session():
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = time.time() + WEB_SESSION_TTL
    return token

def valid_session(token):
    if not token:
        return False
    with _sessions_lock:
        expiry = _sessions.get(token)
        if expiry is None:
            return False
        if expiry < time.time():
            _sessions.pop(token, None)
            return False
        return True

def cookie_token(headers):
    for part in headers.get("Cookie", "").split(";"):
        if part.strip().startswith("mg_session="):
            return part.strip().split("=", 1)[1]
    return ""

def page(title, body):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(title)} - Minecraft-Guard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{font-family:system-ui;background:#0f1115;color:#eee;margin:0}}
nav{{padding:16px 22px;background:#181c24;display:flex;gap:18px;flex-wrap:wrap}}
a{{color:#8ab4ff;text-decoration:none}}main{{max-width:1100px;margin:28px auto;padding:0 16px}}
.card{{background:#181c24;border:1px solid #2b3240;border-radius:12px;padding:18px;margin:14px 0;overflow:auto}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #2b3240;text-align:left}}
input,button{{padding:9px;border-radius:7px;border:1px solid #3a4353;background:#10131a;color:#eee}}
button{{cursor:pointer}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
</style></head><body><nav><b>Minecraft-Guard</b>
<a href="/">Dashboard</a><a href="/blacklist">Blacklist</a><a href="/whitelist">Whitelist</a>
<a href="/connections">Connections</a><a href="/logout">Logout</a></nav>{body}</body></html>"""

class WebHandler(BaseHTTPRequestHandler):
    db = None

    def log_message(self, *_):
        pass

    def send(self, code, body, headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k,v in (headers or {}).items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, target, cookie=None):
        headers = {"Location": target}
        if cookie:
            headers["Set-Cookie"] = cookie
        self.send(303, "", headers)

    def authed(self):
        return valid_session(cookie_token(self.headers))

    def require_auth(self):
        if not self.authed():
            self.redirect("/login")
            return False
        return True

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            self.send(200, page("Login", '<main><div class="card"><h1>Admin Login</h1><form method="post"><input type="password" name="password" placeholder="Password" autofocus><button>Login</button></form></div></main>'))
            return
        if path == "/logout":
            token = cookie_token(self.headers)
            with _sessions_lock:
                _sessions.pop(token, None)
            self.redirect("/login", "mg_session=; Max-Age=0; HttpOnly; SameSite=Strict")
            return
        if not self.require_auth():
            return
        if path == "/":
            black, white = self.db.counts()
            active = len(netstat_ips())
            body = f'<main><h1>Frontend Relay Console</h1><div class="grid"><div class="card"><h2>{black}</h2>Blocked IPs</div><div class="card"><h2>{white}</h2>Whitelisted IPs</div><div class="card"><h2>{active}</h2>Active public connections</div></div><div class="card"><p>This console manages the frontend/relay host firewall and local policy database. It does not edit Minecraft backend ban files.</p></div></main>'
            self.send(200, page("Dashboard", body))
            return
        if path == "/blacklist":
            rows = "".join(
                f"<tr><td>{html.escape(r[0])}</td><td>{html.escape(str(r[1]))}</td><td>{r[2] or ''}</td><td>{html.escape(r[3] or '')}</td><td><form method='post' action='/unblock'><input type='hidden' name='ip' value='{html.escape(r[0])}'><button>Unblock</button></form></td></tr>"
                for r in self.db.blacklisted())
            body = f"<main><div class='card'><h1>Blacklist</h1><form method='post' action='/block'><input name='ip' placeholder='Public IPv4'><button>Block</button></form></div><div class='card'><table><tr><th>IP</th><th>Blocked</th><th>Score</th><th>Usage</th><th>Action</th></tr>{rows}</table></div></main>"
            self.send(200, page("Blacklist", body))
            return
        if path == "/whitelist":
            rows = "".join(
                f"<tr><td>{html.escape(r[0])}</td><td>{html.escape(str(r[1]))}</td><td><form method='post' action='/whitelist-remove'><input type='hidden' name='ip' value='{html.escape(r[0])}'><button>Remove</button></form></td></tr>"
                for r in self.db.whitelisted())
            body = f"<main><div class='card'><h1>Whitelist</h1><form method='post' action='/whitelist-add'><input name='ip' placeholder='IP address'><button>Add</button></form></div><div class='card'><table><tr><th>IP</th><th>Added</th><th>Action</th></tr>{rows}</table></div></main>"
            self.send(200, page("Whitelist", body))
            return
        if path == "/connections":
            rows = "".join(f"<tr><td>{html.escape(ip)}</td><td>TCP {MINECRAFT_PORT}</td></tr>" for ip in sorted(netstat_ips()))
            body = f"<main><div class='card'><h1>Active Relay Connections</h1><table><tr><th>Remote IP</th><th>Destination</th></tr>{rows or '<tr><td colspan=2>None</td></tr>'}</table></div></main>"
            self.send(200, page("Connections", body))
            return
        self.send(404, page("Not Found", "<main><div class='card'><h1>404</h1></div></main>"))

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode(errors="replace"))
        if path == "/login":
            password = form.get("password", [""])[0]
            if WEB_ADMIN_PASSWORD and secrets.compare_digest(password, WEB_ADMIN_PASSWORD):
                token = new_session()
                self.redirect("/", f"mg_session={token}; Max-Age={WEB_SESSION_TTL}; HttpOnly; SameSite=Strict")
            else:
                self.send(401, page("Login", '<main><div class="card"><h1>Login failed</h1><form method="post"><input type="password" name="password"><button>Login</button></form></div></main>'))
            return
        if not self.require_auth():
            return
        ip = form.get("ip", [""])[0].strip()
        if not public_ipv4(ip):
            self.send(400, page("Bad IP", "<main><div class='card'><h1>Invalid public IPv4 address</h1></div></main>"))
            return
        if path == "/block":
            firewall_block(ip)
            self.db.add_blacklist(ip, notes="Web console manual block")
            self.db.audit("BLOCK", ip, "web console")
            self.redirect("/blacklist")
        elif path == "/unblock":
            firewall_unblock(ip)
            self.db.remove_blacklist(ip)
            self.db.audit("UNBLOCK", ip, "web console")
            self.redirect("/blacklist")
        elif path == "/whitelist-add":
            self.db.add_whitelist(ip)
            firewall_unblock(ip)
            self.db.remove_blacklist(ip)
            self.db.audit("WHITELIST_ADD", ip, "web console")
            self.redirect("/whitelist")
        elif path == "/whitelist-remove":
            self.db.remove_whitelist(ip)
            self.db.audit("WHITELIST_REMOVE", ip, "web console")
            self.redirect("/whitelist")
        else:
            self.send(404, page("Not Found", "<main><div class='card'><h1>404</h1></div></main>"))

def start_web(db):
    if not WEB_ENABLED:
        return None
    if not WEB_ADMIN_PASSWORD:
        print("[WEB] Disabled because MINECRAFT_GUARD_ADMIN_PASSWORD is not set.")
        return None
    WebHandler.db = db
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), WebHandler)
    threading.Thread(target=server.serve_forever, name="MinecraftGuard-Web", daemon=True).start()
    print(f"[WEB] Admin console listening on http://{WEB_HOST}:{WEB_PORT}")
    return server

def process_ip(ip, api_key, db):
    if db.is_whitelisted(ip) or db.is_blocked(ip):
        return
    data = abuse_check(ip, api_key)
    if not data:
        return
    score = int(data.get("abuseConfidenceScore", 0) or 0)
    usage = data.get("usageType", "Unknown")
    reasons = []
    if score >= ABUSE_SCORE_THRESHOLD:
        reasons.append(f"abuse score {score}%")
    if usage == DATACENTER_USAGE_TYPE:
        reasons.append(f"usage type {usage}")
    if reasons and firewall_block(ip):
        reason = ", ".join(reasons)
        db.add_blacklist(ip, score, usage, data.get("countryCode"), data.get("isp"), data.get("domain"), reason)
        db.audit("AUTO_BLOCK", ip, reason)
        print(f"[BLOCK] {ip}: {reason}")

def monitor(db):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[ERROR] ABUSEIPDB_API_KEY is missing.")
        return
    seen = set()
    while True:
        for ip in netstat_ips():
            if ip not in seen:
                seen.add(ip)
                process_ip(ip, api_key, db)
        time.sleep(SCAN_INTERVAL_SECONDS)

def main():
    parser = argparse.ArgumentParser(description="Minecraft-Guard frontend/relay network manager")
    parser.add_argument("--block", metavar="IP")
    parser.add_argument("--unblock", metavar="IP")
    parser.add_argument("--whitelist-add", metavar="IP")
    parser.add_argument("--whitelist-remove", metavar="IP")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()

    db = GuardDB(DB_FILE)
    start_web(db)

    if args.block:
        if public_ipv4(args.block):
            firewall_block(args.block)
            db.add_blacklist(args.block, notes="CLI manual block")
            print(f"Blocked {args.block}")
        return
    if args.unblock:
        if public_ipv4(args.unblock):
            firewall_unblock(args.unblock)
            db.remove_blacklist(args.unblock)
            print(f"Unblocked {args.unblock}")
        return
    if args.whitelist_add:
        db.add_whitelist(args.whitelist_add)
        firewall_unblock(args.whitelist_add)
        db.remove_blacklist(args.whitelist_add)
        return
    if args.whitelist_remove:
        db.remove_whitelist(args.whitelist_remove)
        return
    if args.list:
        for row in db.blacklisted():
            print(row)
        return
    monitor(db)

if __name__ == "__main__":
    main()
