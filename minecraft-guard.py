#!/usr/bin/env python3
"""Malachite Minecraft Guard public TCP pre-filter and AbuseIPDB relay."""
import ipaddress
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

import requests

BASE = os.getenv("GUARD_DIR", "/opt/minecraft-guard")
DB = os.getenv("GUARD_DB", f"{BASE}/guard.db")
LOG = os.getenv("GUARD_LOG", "/var/log/minecraft-guard.log")
PUBLIC_HOST = os.getenv("GUARD_BIND_HOST", "0.0.0.0")
PUBLIC_PORT = int(os.getenv("MINECRAFT_PUBLIC_PORT", "25565"))
HAPROXY_HOST = os.getenv("HAPROXY_HOST", "127.0.0.1")
HAPROXY_PORT = int(os.getenv("HAPROXY_PORT", "25566"))
BACKLOG = int(os.getenv("GUARD_BACKLOG", "256"))
CONNECT_TIMEOUT = float(os.getenv("GUARD_CONNECT_TIMEOUT", "10"))

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSE_THRESHOLD = int(os.getenv("ABUSEIPDB_THRESHOLD", "90"))
ABUSE_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))
ABUSE_CACHE_SECONDS = int(os.getenv("ABUSEIPDB_CACHE_SECONDS", "86400"))
ABUSE_TIMEOUT = int(os.getenv("ABUSEIPDB_TIMEOUT", "10"))
BLOCK_DATACENTERS = os.getenv("BLOCK_DATACENTERS", "true").strip().lower() in ("1", "true", "yes", "on")

os.makedirs(BASE, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG), logging.StreamHandler()],
)
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
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


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
                reports INTEGER NOT NULL, usage_type TEXT, isp TEXT, domain TEXT, details TEXT)""")
            # Migrate an existing Guard database created before hosting metadata was stored.
            columns = {row[1] for row in c.execute("PRAGMA table_info(abuse_cache)")}
            for name, definition in (
                ("usage_type", "TEXT"),
                ("isp", "TEXT"),
                ("domain", "TEXT"),
            ):
                if name not in columns:
                    c.execute(f"ALTER TABLE abuse_cache ADD COLUMN {name} {definition}")

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
            c.execute("INSERT INTO events(ts,level,event,ip,details) VALUES(?,?,?,?,?)", (now(), level, event, ip, details))

    def abuse_get(self, ip):
        with self.conn() as c:
            row = c.execute("SELECT * FROM abuse_cache WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else None

    def abuse_put(self, ip, confidence, reports, usage_type, isp, domain, details):
        with self.conn() as c:
            c.execute("""INSERT OR REPLACE INTO abuse_cache
                (ip,checked,confidence,reports,usage_type,isp,domain,details)
                VALUES(?,?,?,?,?,?,?,?)""", (ip, time.time(), confidence, reports, usage_type, isp, domain, details))


store = Store()


def ufw_ok():
    return cmd(["ufw", "status"]).returncode == 0


def ufw_rule(action, ip, proto, insert=False):
    args = ["ufw"]
    if insert:
        args += ["insert", "1"]
    args += [action, "from", ip, "to", "any", "port", str(PUBLIC_PORT), "proto", proto]
    r = cmd(args)
    if r.returncode:
        log.error("UFW %s %s/%s failed: %s", action, ip, proto, (r.stderr or r.stdout).strip())
    return r.returncode == 0


def ufw_delete(action, ip, proto):
    r = cmd(["ufw", "delete", action, "from", ip, "to", "any", "port", str(PUBLIC_PORT), "proto", proto])
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
        log.info("AbuseIPDB cache: %s%% confidence, %s reports, usage=%s, isp=%s for %s", cached["confidence"], cached["reports"], cached.get("usage_type") or "unknown", cached.get("isp") or "unknown", ip)
        return cached["confidence"], cached["reports"], cached.get("usage_type") or "", cached.get("isp") or "", cached.get("domain") or ""

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
        usage_type = str(data.get("usageType") or "")
        isp = str(data.get("isp") or "")
        domain = str(data.get("domain") or "")
        store.abuse_put(ip, confidence, reports, usage_type, isp, domain, str(data))
        log.info("AbuseIPDB: %s%% confidence, %s reports, usage=%s, isp=%s", confidence, reports, usage_type or "unknown", isp or "unknown")
        return confidence, reports, usage_type, isp, domain
    except Exception as exc:
        log.error("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None


def is_datacenter(usage_type, isp="", domain=""):
    """Return True for AbuseIPDB address space classified as hosting/datacenter.

    AbuseIPDB's check endpoint exposes usageType values such as
    'Data Center/Web Hosting/Transit'. We intentionally use that structured
    field first, with a conservative provider-name fallback for records whose
    usageType is blank.
    """
    normalized = (usage_type or "").strip().lower()
    if normalized in {
        "data center/web hosting/transit",
        "data center",
        "web hosting",
        "hosting",
        "transit",
    }:
        return True

    # Only use provider-name hints when AbuseIPDB did not provide a usage type.
    # This avoids blocking ordinary ISPs merely because their names contain a
    # generic word such as 'network' or 'communications'.
    if normalized:
        return False

    provider = f"{isp} {domain}".lower()
    hosting_markers = (
        "amazon web services", "amazon.com", "aws", "microsoft azure",
        "azure", "google cloud", "google llc", "digitalocean", "digital ocean",
        "linode", "akamai", "vultr", "hetzner", "ovh", "oracle cloud",
        "contabo", "choopa", "rackspace", "leaseweb", "hostwinds",
        "scaleway", "upcloud", "ionos", "hostinger", "cloudsigma",
    )
    return any(marker in provider for marker in hosting_markers)


def inspect_ip(ip):
    if store.iswhite(ip):
        log.info("Whitelisted connection: %s", ip)
        return True
    if store.isblocked(ip):
        log.warning("Blocked connection rejected: %s", ip)
        return False

    if not ABUSE_API_KEY:
        log.info("No AbuseIPDB key configured; allowing %s", ip)
        return True

    result = abuse_check(ip)
    if result is None:
        # Do not turn an AbuseIPDB outage into a Minecraft outage.
        return True

    confidence, reports, usage_type, isp, domain = result

    if BLOCK_DATACENTERS and is_datacenter(usage_type, isp, domain):
        notes = f"AbuseIPDB usageType={usage_type or 'unknown'}, ISP={isp or 'unknown'}, domain={domain or 'unknown'}"
        ok, _ = block_ip(ip, source="datacenter", notes=notes)
        if ok:
            log.warning("Automatically blocked datacenter/hosting IP %s: %s", ip, notes)
            store.event("WARN", "AUTO_BLOCK_DATACENTER", ip, notes)
        return False

    if confidence >= ABUSE_THRESHOLD:
        notes = f"AbuseIPDB: {confidence}% confidence, {reports} reports; threshold={ABUSE_THRESHOLD}%"
        ok, _ = block_ip(ip, source="abuseipdb", notes=notes)
        if ok:
            log.warning("Automatically blocked %s", ip)
            store.event("WARN", "AUTO_BLOCK", ip, notes)
        return False

    log.info("Allowed %s: AbuseIPDB %s%% confidence, %s reports, usage=%s, isp=%s", ip, confidence, reports, usage_type or "unknown", isp or "unknown")
    return True


def configure_firewall():
    if os.geteuid() != 0 or not ufw_ok():
        log.error("Guard requires root and working UFW")
        return False

    cmd(["ufw", "delete", "allow", f"{PUBLIC_PORT}/udp"])
    cmd(["ufw", "allow", f"{PUBLIC_PORT}/tcp"])
    cmd(["ufw", "logging", "medium"])

    for row in store.white():
        if not store.isblocked(row["ip"]):
            whitelist_add(row["ip"], row.get("notes", ""))

    return True


def proxy_copy(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client, address):
    ip = address[0]
    try:
        ip = ip_ok(ip)
    except ValueError:
        client.close()
        return

    log.info("Incoming TCP connection from %s:%s", ip, address[1])
    store.event("INFO", "CONNECTION", ip, f"port={PUBLIC_PORT} proto=tcp")

    try:
        if not inspect_ip(ip):
            client.close()
            return

        upstream = socket.create_connection((HAPROXY_HOST, HAPROXY_PORT), timeout=CONNECT_TIMEOUT)
        upstream.settimeout(None)
        client.settimeout(None)
        log.info("Allowed %s; forwarding to HAProxy %s:%s", ip, HAPROXY_HOST, HAPROXY_PORT)

        t = threading.Thread(target=proxy_copy, args=(client, upstream), daemon=True)
        t.start()
        proxy_copy(upstream, client)
        t.join(timeout=2)
    except Exception as exc:
        log.error("Proxy failure for %s: %s", ip, exc)
    finally:
        try:
            client.close()
        except OSError:
            pass
        try:
            upstream.close()
        except (NameError, OSError):
            pass


def run_proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((PUBLIC_HOST, PUBLIC_PORT))
        server.listen(BACKLOG)
        log.info("Guard TCP pre-filter listening on %s:%s; HAProxy upstream %s:%s", PUBLIC_HOST, PUBLIC_PORT, HAPROXY_HOST, HAPROXY_PORT)
        while True:
            client, address = server.accept()
            threading.Thread(target=handle_client, args=(client, address), daemon=True).start()


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

    if ABUSE_API_KEY:
        log.info("AbuseIPDB enabled; threshold=%s%%, maxAge=%sd, cache=%ss, block_datacenters=%s", ABUSE_THRESHOLD, ABUSE_MAX_AGE_DAYS, ABUSE_CACHE_SECONDS, BLOCK_DATACENTERS)
    else:
        log.warning("AbuseIPDB disabled: ABUSEIPDB_API_KEY is not configured")

    run_proxy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
