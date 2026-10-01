#!/usr/bin/env python3
import argparse
import ipaddress
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

WORKDIR = Path(os.getenv("MINECRAFT_GUARD_WORKDIR", "/opt/minecraft-guard"))
DB_FILE = WORKDIR / "blacklist.db"
PORT = int(os.getenv("MINECRAFT_GUARD_PORT", "25565"))
SYNC = int(os.getenv("MINECRAFT_GUARD_DB_SYNC_INTERVAL", "5"))
THRESHOLD = int(os.getenv("ABUSE_SCORE_THRESHOLD", "10"))
DATACENTER = os.getenv("DATACENTER_USAGE_TYPE", "Data Center/Web Hosting/Transit")
CHAIN = "MINECRAFT_GUARD"


def load_dotenv():
    env_file = WORKDIR / ".env"
    if env_file.exists():
        for raw in env_file.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


class GuardDB:
    def __init__(self, path):
        self.path = path
        self.init()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def init(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                source TEXT NOT NULL,
                abuse_score INTEGER,
                usage_type TEXT,
                country_code TEXT,
                isp TEXT,
                domain TEXT,
                notes TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS whitelist (
                ip TEXT PRIMARY KEY,
                added_at TEXT NOT NULL,
                notes TEXT
            )""")

    def blocked(self):
        with self.connect() as db:
            return {r[0] for r in db.execute("SELECT ip FROM blacklist")}

    def white(self):
        with self.connect() as db:
            return {r[0] for r in db.execute("SELECT ip FROM whitelist")}

    def is_white(self, ip):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,)).fetchone() is not None

    def is_blocked(self, ip):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM blacklist WHERE ip=?", (ip,)).fetchone() is not None

    def add_block(self, ip, score=None, usage=None, country=None, isp=None,
                  domain=None, notes=None, source="minecraft-guard/AbuseIPDB"):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute(
                """INSERT INTO blacklist
                (ip, blocked_at, updated_at, source, abuse_score, usage_type,
                 country_code, isp, domain, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                updated_at=excluded.updated_at, source=excluded.source,
                abuse_score=excluded.abuse_score, usage_type=excluded.usage_type,
                country_code=excluded.country_code, isp=excluded.isp,
                domain=excluded.domain, notes=excluded.notes""",
                (ip, now, now, source, score, usage, country, isp, domain, notes),
            )

    def remove_block(self, ip):
        with self.connect() as db:
            db.execute("DELETE FROM blacklist WHERE ip=?", (ip,))

    def add_white(self, ip, notes="Manual Whitelist"):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute(
                """INSERT INTO whitelist(ip, added_at, notes) VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET added_at=excluded.added_at,
                notes=excluded.notes""",
                (ip, now, notes),
            )

    def remove_white(self, ip):
        with self.connect() as db:
            db.execute("DELETE FROM whitelist WHERE ip=?", (ip,))


def valid_public_ipv4(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and addr.is_global
    except ValueError:
        return False


def iptables(args, check=False):
    return subprocess.run(
        ["iptables", "-w", "5"] + args,
        capture_output=True,
        text=True,
        timeout=15,
        check=check,
    )


def ensure_firewall_chain():
    result = iptables(["-N", CHAIN])
    if result.returncode != 0 and "Chain already exists" not in result.stderr:
        raise RuntimeError(f"Could not create {CHAIN}: {result.stderr.strip()}")

    iptables(["-F", CHAIN])

    jump = ["-I", "INPUT", "1", "-p", "tcp", "--dport", str(PORT), "-j", CHAIN]
    existing = iptables(["-C", "INPUT", "-p", "tcp", "--dport", str(PORT), "-j", CHAIN])
    if existing.returncode != 0:
        iptables(jump)

    print(f"[FIREWALL] {CHAIN} active before other INPUT rules for TCP/{PORT}")


def current_firewall_ips():
    result = iptables(["-S", CHAIN])
    if result.returncode != 0:
        return set()
    found = set()
    for line in result.stdout.splitlines():
        match = re.search(r"^-A\s+" + re.escape(CHAIN) + r"\s+-s\s+(\d+\.\d+\.\d+\.\d+)\s+-j\s+DROP$", line.strip())
        if match:
            found.add(match.group(1))
    return found


def firewall_block(ip):
    if not valid_public_ipv4(ip):
        return False
    if ip in current_firewall_ips():
        return True
    result = iptables(["-A", CHAIN, "-s", ip, "-j", "DROP"])
    if result.returncode == 0:
        print(f"[FIREWALL] Blocked {ip} TCP/{PORT}")
        return True
    print(f"[ERROR] iptables block failed for {ip}: {result.stderr.strip()}")
    return False


def firewall_unblock(ip):
    while True:
        result = iptables(["-D", CHAIN, "-s", ip, "-j", "DROP"])
        if result.returncode != 0:
            break
    if result.returncode == 0 or "Bad rule" in result.stderr or "No chain/target" in result.stderr:
        print(f"[FIREWALL] Unblocked {ip}")
        return True
    return True


def sync_firewall(db):
    desired = db.blocked() - db.white()
    applied = current_firewall_ips()

    for ip in desired - applied:
        firewall_block(ip)

    for ip in applied - desired:
        firewall_unblock(ip)


def connected_client_ips():
    clients = set()
    try:
        result = subprocess.run(["ss", "-Htn", "state", "established"],
                                capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[2]
            remote = fields[3]
            if not local.rsplit(":", 1)[-1] == str(PORT):
                continue
            remote_ip = remote.rsplit(":", 1)[0]
            if remote_ip.startswith("[") and remote_ip.endswith("]"):
                remote_ip = remote_ip[1:-1]
            if valid_public_ipv4(remote_ip):
                clients.add(remote_ip)
    except Exception as exc:
        print(f"[WARN] Could not inspect connections: {exc}")
    return clients


def abuse_check(ip, api_key):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=10,
        )
        if response.status_code == 200:
            return response.json().get("data")
    except requests.RequestException as exc:
        print(f"[WARN] AbuseIPDB check failed for {ip}: {exc}")
    return None


def process_client(ip, db, api_key):
    if db.is_white(ip) or db.is_blocked(ip):
        return

    data = abuse_check(ip, api_key)
    if not data:
        return

    score = int(data.get("abuseConfidenceScore", 0) or 0)
    usage = data.get("usageType", "Unknown")
    country = data.get("countryCode", "Unknown")
    isp = data.get("isp", "Unknown")
    domain = data.get("domain", "N/A")
    reasons = []

    if score >= THRESHOLD:
        reasons.append(f"Abuse score {score}% >= {THRESHOLD}%")
    if usage == DATACENTER:
        reasons.append(f"usage type '{usage}' matched policy")

    if reasons:
        reason = "; ".join(reasons)
        db.add_block(ip, score, usage, country, isp, domain, reason)
        firewall_block(ip)
        print(f"[GUARD] Automatically blocked {ip}: {reason}")


def main():
    load_dotenv()

    if os.geteuid() != 0:
        sys.exit("[ERROR] minecraft-guard must run as root so it can manage iptables.")

    db = GuardDB(DB_FILE)

    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--block")
    parser.add_argument("--unblock")
    parser.add_argument("--whitelist-add")
    parser.add_argument("--whitelist-remove")
    args = parser.parse_args()

    if args.list:
        with db.connect() as conn:
            for row in conn.execute("SELECT * FROM blacklist ORDER BY blocked_at DESC"):
                print(row)
        return

    if args.block:
        db.remove_white(args.block)
        db.add_block(args.block, notes="Manual CLI block", source="minecraft-guard/manual")
        firewall_block(args.block)
        return

    if args.unblock:
        db.remove_block(args.unblock)
        firewall_unblock(args.unblock)
        return

    if args.whitelist_add:
        db.add_white(args.whitelist_add)
        db.remove_block(args.whitelist_add)
        firewall_unblock(args.whitelist_add)
        return

    if args.whitelist_remove:
        db.remove_white(args.whitelist_remove)
        return

    ensure_firewall_chain()
    sync_firewall(db)

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    seen = set()

    print(f"[GUARD] Running. DB sync every {SYNC}s. Monitoring TCP/{PORT}.")
    print(f"[GUARD] Shared database: {DB_FILE}")

    while True:
        try:
            sync_firewall(db)

            clients = connected_client_ips()
            for ip in clients - seen:
                process_client(ip, db, api_key) if api_key else None

            seen = clients
            time.sleep(SYNC)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"[ERROR] {exc}")
            time.sleep(SYNC)


if __name__ == "__main__":
    main()
