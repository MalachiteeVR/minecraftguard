#!/usr/bin/env python3
"""Malachite Minecraft Guard Linux relay daemon with AbuseIPDB integration."""
import ipaddress, logging, os, sqlite3, subprocess, sys, time
from datetime import datetime, timezone
import requests

BASE = os.getenv("GUARD_DIR", "/opt/minecraft-guard")
DB = os.getenv("GUARD_DB", f"{BASE}/guard.db")
LOG = os.getenv("GUARD_LOG", "/var/log/minecraft-guard.log")
PORT = int(os.getenv("MINECRAFT_PUBLIC_PORT", "25565"))
CHECK_INTERVAL = int(os.getenv("GUARD_INTERVAL", "5"))

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSE_THRESHOLD = int(os.getenv("ABUSEIPDB_THRESHOLD", "90"))
ABUSE_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))
ABUSE_CACHE_SECONDS = int(os.getenv("ABUSEIPDB_CACHE_SECONDS", "86400"))
ABUSE_TIMEOUT = int(os.getenv("ABUSEIPDB_TIMEOUT", "10"))

os.makedirs(BASE, exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(LOG), logging.StreamHandler()])
log = logging.getLogger("minecraft-guard")

def now():
    return datetime.now(timezone.utc).isoformat()

def ip_ok(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError("Invalid IP address")

def public_ip(value):
    ip = ipaddress.ip_address(value)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified)

def cmd(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10)

class Store:
    def __init__(self):
        with self.conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS blacklist(ip TEXT PRIMARY KEY,created TEXT,source TEXT,notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS whitelist(ip TEXT PRIMARY KEY,created TEXT,notes TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts TEXT,level TEXT,event TEXT,ip TEXT,details TEXT)")
            c.execute("""CREATE TABLE IF NOT EXISTS abuse_cache(
                ip TEXT PRIMARY KEY, checked REAL NOT NULL, confidence INTEGER NOT NULL,
                reports INTEGER NOT NULL, details TEXT)""")

    def conn(self):
        c = sqlite3.connect(DB, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def blocked(self):
        with self.conn() as c:
            return [dict(x) for x in c.execute("SELECT * FROM blacklist ORDER BY created DESC")]

    def white(self):
        with self.conn() as c:
            return [dict(x) for x in c.execute("SELECT * FROM whitelist ORDER BY created DESC")]

    def iswhite(self, ip):
        with self.conn() as c:
            return c.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,)).fetchone() is not None

    def isblocked(self, ip):
        with self.conn() as c:
            return c.execute("SELECT 1 FROM blacklist WHERE ip=?", (ip,)).fetchone() is not None

    def block(self, ip, source="manual", notes=""):
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO blacklist VALUES(?,?,?,?)", (ip, now(), source, notes))

    def unblock(self, ip):
        with self.conn() as c:
            c.execute("DELETE FROM blacklist WHERE ip=?", (ip,))

    def addwhite(self, ip, notes=""):
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO whitelist VALUES(?,?,?)", (ip, now(), notes))

    def delwhite(self, ip):
        with self.conn() as c:
            c.execute("DELETE FROM whitelist WHERE ip=?", (ip,))

    def event(self, level, event, ip="", details=""):
        with self.conn() as c:
            c.execute("INSERT INTO events(ts,level,event,ip,details) VALUES(?,?,?,?,?)",
                      (now(), level, event, ip, details))

    def abuse_get(self, ip):
        with self.conn() as c:
            row = c.execute("SELECT * FROM abuse_cache WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else None

    def abuse_put(self, ip, confidence, reports, details):
        with self.conn() as c:
            c.execute("""INSERT OR REPLACE INTO abuse_cache
                         (ip,checked,confidence,reports,details) VALUES(?,?,?,?,?)""",
                      (ip, time.time(), confidence, reports, details))

store = Store()

def ufw_ok():
    return cmd(["ufw", "status"]).returncode == 0

def ufw_rule(action, ip, proto, insert=False):
    args = ["ufw"]
    if insert:
        args += ["insert", "1"]
    args += [action, "from", ip, "to", "any", "port", str(PORT), "proto", proto]
    r = cmd(args)
    if r.returncode:
        log.error("UFW %s %s/%s failed: %s", action, ip, proto, (r.stderr or r.stdout).strip())
    return r.returncode == 0

def ufw_delete(action, ip, proto):
    r = cmd(["ufw", "delete", action, "from", ip, "to", "any", "port", str(PORT), "proto", proto])
    return r.returncode == 0 or "Could not delete" in (r.stdout + r.stderr)

def block_ip(ip, source="manual", notes=""):
    ip = ip_ok(ip)
    if store.iswhite(ip):
        return False, "IP is whitelisted"
    for proto in ("tcp", "udp"):
        ufw_delete("allow", ip, proto)
        ufw_delete("deny", ip, proto)
        if not ufw_rule("deny", ip, proto, True):
            return False, "UFW block failed"
    store.block(ip, source, notes)
    store.event("WARN", "BLOCK", ip, f"source={source} {notes}".strip())
    log.warning("Blocked %s (%s)", ip, source)
    return True, "blocked"

def unblock_ip(ip):
    ip = ip_ok(ip)
    for proto in ("tcp", "udp"):
        ufw_delete("deny", ip, proto)
    store.unblock(ip)
    store.event("INFO", "UNBLOCK", ip)
    log.info("Unblocked %s", ip)
    return True, "unblocked"

def whitelist_add(ip, notes=""):
    ip = ip_ok(ip)
    for proto in ("tcp", "udp"):
        ufw_delete("deny", ip, proto)
        ufw_delete("allow", ip, proto)
        if not ufw_rule("allow", ip, proto, True):
            return False, "UFW whitelist failed"
    store.addwhite(ip, notes)
    store.unblock(ip)
    store.event("INFO", "WHITELIST_ADD", ip, notes)
    log.info("Whitelisted %s", ip)
    return True, "whitelisted"

def whitelist_remove(ip):
    ip = ip_ok(ip)
    for proto in ("tcp", "udp"):
        ufw_delete("allow", ip, proto)
    store.delwhite(ip)
    store.event("INFO", "WHITELIST_REMOVE", ip)
    log.info("Removed %s from whitelist", ip)
    return True, "removed"

def abuse_check(ip):
    if not ABUSE_API_KEY:
        return None
    try:
        parsed = ipaddress.ip_address(ip)
        if not public_ip(parsed):
            return None
    except ValueError:
        return None

    cached = store.abuse_get(ip)
    if cached and time.time() - cached["checked"] < ABUSE_CACHE_SECONDS:
        return cached["confidence"], cached["reports"]

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": ABUSE_MAX_AGE_DAYS},
            timeout=ABUSE_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        store.abuse_put(ip, confidence, reports, str(data))
        log.info("AbuseIPDB: %s%% confidence, %s reports", confidence, reports)
        return confidence, reports
    except Exception as exc:
        log.error("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None

def inspect_ip(ip):
    if not ABUSE_API_KEY or store.iswhite(ip) or store.isblocked(ip):
        return
    result = abuse_check(ip)
    if result is None:
        return
    confidence, reports = result
    if confidence >= ABUSE_THRESHOLD:
        notes = f"AbuseIPDB: {confidence}% confidence, {reports} reports; threshold={ABUSE_THRESHOLD}%"
        ok, _ = block_ip(ip, source="abuseipdb", notes=notes)
        if ok:
            log.warning("Automatically blocked %s", ip)
            store.event("WARN", "AUTO_BLOCK", ip, notes)

def configure_firewall():
    if os.geteuid() != 0 or not ufw_ok():
        log.error("Guard requires root and working UFW")
        return False
    for proto in ("tcp", "udp"):
        cmd(["ufw", "delete", "allow", f"{PORT}/{proto}"])
        r = cmd(["ufw", "allow", "log", f"{PORT}/{proto}"])
        if r.returncode:
            log.error("Could not configure UFW logging for %s", proto)
            return False
    cmd(["ufw", "logging", "medium"])
    for row in store.white():
        whitelist_add(row["ip"], row.get("notes", ""))
    for row in store.blocked():
        if not store.iswhite(row["ip"]):
            block_ip(row["ip"], row.get("source", "saved"), row.get("notes", ""))
    return True

def parse_ufw(line):
    if f"DPT={PORT}" not in line or "UFW " not in line:
        return None
    parts = line.split()
    src = next((x[4:] for x in parts if x.startswith("SRC=")), None)
    proto = next((x[6:] for x in parts if x.startswith("PROTO=")), "?")
    if not src:
        return None
    try:
        return ip_ok(src), proto
    except ValueError:
        return None

def monitor():
    path = os.getenv("UFW_LOG", "/var/log/ufw.log")
    pos = os.path.getsize(path) if os.path.exists(path) else 0
    while True:
        try:
            if not os.path.exists(path):
                time.sleep(CHECK_INTERVAL)
                continue
            size = os.path.getsize(path)
            if size < pos:
                pos = 0
            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    pos = f.tell()
                    parsed = parse_ufw(line)
                    if not parsed:
                        continue
                    ip, proto = parsed
                    store.event("INFO", "CONNECTION", ip, f"port={PORT} proto={proto}")
                    log.info("Connection from %s to port %s/%s", ip, PORT, proto)
                    inspect_ip(ip)
        except Exception as exc:
            log.error("Monitor error: %s", exc)
        time.sleep(CHECK_INTERVAL)

def main():
    if len(sys.argv) > 1:
        action = sys.argv[1]
        if action in ("--block", "--unblock", "--whitelist-add", "--whitelist-remove") and len(sys.argv) < 3:
            print("IP address required", file=sys.stderr)
            return 2
        try:
            if action == "--block": ok, msg = block_ip(sys.argv[2])
            elif action == "--unblock": ok, msg = unblock_ip(sys.argv[2])
            elif action == "--whitelist-add": ok, msg = whitelist_add(sys.argv[2])
            elif action == "--whitelist-remove": ok, msg = whitelist_remove(sys.argv[2])
            elif action == "--list":
                print("Blacklist:")
                for row in store.blocked(): print(row["ip"], row["source"], row["notes"])
                return 0
            elif action == "--whitelist-list":
                print("Whitelist:")
                for row in store.white(): print(row["ip"], row["notes"])
                return 0
            else:
                print("Usage: minecraft-guard.py [--block IP|--unblock IP|--whitelist-add IP|--whitelist-remove IP|--list|--whitelist-list]")
                return 2
            print(msg)
            return 0 if ok else 1
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if not configure_firewall():
        return 1
    log.info("Malachite Minecraft Guard started; checking UFW every %ss", CHECK_INTERVAL)
    if ABUSE_API_KEY:
        log.info("AbuseIPDB enabled; threshold=%s%%, maxAge=%sd, cache=%ss",
                 ABUSE_THRESHOLD, ABUSE_MAX_AGE_DAYS, ABUSE_CACHE_SECONDS)
    else:
        log.warning("AbuseIPDB disabled: ABUSEIPDB_API_KEY is not configured")
    monitor()

if __name__ == "__main__":
    raise SystemExit(main())
