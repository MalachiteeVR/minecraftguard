import os
import re
import sys
import time
import json
import sqlite3
import argparse
import subprocess
import requests
from pathlib import Path
from datetime import datetime, timezone

# --- CONFIGURATION ---
WORKDIR = Path(r"C:\Minecraft")
ENV_FILE = WORKDIR / ".env"
DB_FILE = WORKDIR / "blacklist.db"
FIREWALL_LOG = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
MINECRAFT_BANNED_IPS_FILE = Path(r"C:\Minecraft\MCSS\servers\server54\banned-ips.json")

MINECRAFT_PORT = 25565
SCAN_INTERVAL_SECONDS = 3
ABUSE_SCORE_THRESHOLD = 10
DATACENTER_USAGE_TYPE = "Data Center/Web Hosting/Transit"

def load_dotenv():
    if not ENV_FILE.exists():
        return
    try:
        content = ENV_FILE.read_text(encoding="utf-8-sig")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip('"\'')
    except Exception as e:
        print(f"[WARN] Failed to read .env file: {e}")

class GuardDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
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
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    ip TEXT PRIMARY KEY,
                    added_at TEXT NOT NULL,
                    notes TEXT
                )
            """)
            conn.commit()

    # --- Blacklist Operations ---
    def is_blocked(self, ip):
        with self._get_conn() as conn:
            row = conn.execute("SELECT 1 FROM blacklist WHERE ip = ?", (ip,)).fetchone()
            return row is not None

    def add_blacklist_ip(self, ip, score=None, usage_type=None, country=None, isp=None, domain=None, notes=None):
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO blacklist 
                (ip, blocked_at, updated_at, source, abuse_score, usage_type, country_code, isp, domain, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    abuse_score=excluded.abuse_score,
                    usage_type=excluded.usage_type,
                    notes=excluded.notes
            """, (ip, now, now, "minecraft-guard/AbuseIPDB", score, usage_type, country, isp, domain, notes))
            conn.commit()

    def remove_blacklist_ip(self, ip):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
            conn.commit()

    def get_all_blacklisted(self):
        with self._get_conn() as conn:
            return conn.execute("SELECT ip, blocked_at, abuse_score, usage_type, notes FROM blacklist").fetchall()

    # --- Whitelist Operations ---
    def is_whitelisted(self, ip):
        with self._get_conn() as conn:
            row = conn.execute("SELECT 1 FROM whitelist WHERE ip = ?", (ip,)).fetchone()
            return row is not None

    def add_whitelist_ip(self, ip, notes="Manual Whitelist"):
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO whitelist (ip, added_at, notes)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET added_at=excluded.added_at, notes=excluded.notes
            """, (ip, now, notes))
            conn.commit()

    def remove_whitelist_ip(self, ip):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
            conn.commit()

    def get_all_whitelisted(self):
        with self._get_conn() as conn:
            return conn.execute("SELECT ip, added_at, notes FROM whitelist").fetchall()

# --- MINECRAFT SERVER BANNED-IPS.JSON MANAGEMENT ---
def add_ip_to_minecraft_banned_json(ip, reason="Auto-blocked by Minecraft Guard"):
    if not MINECRAFT_BANNED_IPS_FILE.parent.exists():
        return

    banned_list = []
    if MINECRAFT_BANNED_IPS_FILE.exists():
        try:
            content = MINECRAFT_BANNED_IPS_FILE.read_text(encoding="utf-8")
            if content.strip():
                banned_list = json.loads(content)
        except Exception as e:
            print(f"[WARN] Could not parse {MINECRAFT_BANNED_IPS_FILE}: {e}")

    for entry in banned_list:
        if isinstance(entry, dict) and entry.get("ip") == ip:
            return  # Already in json

    now_formatted = datetime.now().strftime("%Y-%m-%d %H:%M:%S %z")
    new_entry = {
        "ip": ip,
        "created": now_formatted if now_formatted.endswith(('+', '-')) else f"{now_formatted} +0000",
        "source": "MinecraftGuard",
        "expires": "forever",
        "reason": reason
    }
    banned_list.append(new_entry)

    try:
        MINECRAFT_BANNED_IPS_FILE.write_text(json.dumps(banned_list, indent=2), encoding="utf-8")
        print(f"[MC-SERVER] Added {ip} to banned-ips.json")
    except Exception as e:
        print(f"[ERROR] Failed writing to banned-ips.json: {e}")

def remove_ip_from_minecraft_banned_json(ip):
    if not MINECRAFT_BANNED_IPS_FILE.exists():
        return

    try:
        content = MINECRAFT_BANNED_IPS_FILE.read_text(encoding="utf-8")
        if not content.strip():
            return
        banned_list = json.loads(content)
    except Exception as e:
        print(f"[WARN] Could not parse {MINECRAFT_BANNED_IPS_FILE}: {e}")
        return

    updated_list = [entry for entry in banned_list if isinstance(entry, dict) and entry.get("ip") != ip]

    if len(updated_list) != len(banned_list):
        try:
            MINECRAFT_BANNED_IPS_FILE.write_text(json.dumps(updated_list, indent=2), encoding="utf-8")
            print(f"[MC-SERVER] Removed {ip} from banned-ips.json")
        except Exception as e:
            print(f"[ERROR] Failed updating banned-ips.json: {e}")

def is_public_ipv4(ip_str):
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    o1, o2, _, _ = octets
    if o1 == 10: return False
    if o1 == 172 and 16 <= o2 <= 31: return False
    if o1 == 192 and o2 == 168: return False
    if o1 == 127: return False
    if o1 == 100 and 64 <= o2 <= 127: return False  # Tailscale CGNAT
    if o1 == 169 and o2 == 254: return False
    if o1 >= 224: return False
    return True

def get_ips_from_firewall_log(last_pos):
    detected_ips = set()
    if not FIREWALL_LOG.exists():
        return detected_ips, last_pos

    try:
        with open(FIREWALL_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_pos)
            lines = f.readlines()
            new_pos = f.tell()

            for line in lines:
                if line.startswith("#"):
                    continue
                parts = line.strip().split()
                if len(parts) >= 8:
                    src_ip = parts[4]
                    dst_port = parts[7]

                    if dst_port == str(MINECRAFT_PORT) and is_public_ipv4(src_ip):
                        detected_ips.add(src_ip)

            return detected_ips, new_pos
    except Exception as e:
        print(f"[WARN] Log parsing error: {e}")
        return detected_ips, last_pos

def get_remote_ipv4s_netstat():
    ips = set()
    try:
        cmd = ["netstat", "-ano", "-p", "tcp"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        pattern = re.compile(rf'^\s*TCP\s+\S+:{MINECRAFT_PORT}\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+\s+ESTABLISHED', re.MULTILINE)
        for match in pattern.finditer(res.stdout):
            ip = match.group(1)
            if is_public_ipv4(ip):
                ips.add(ip)
    except Exception:
        pass
    return ips

def block_ip_windows_firewall(ip):
    rule_name = f"MinecraftGuard_Block_{ip}"
    cmd = [
        "powershell", "-Command",
        f"if (-not (Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue)) {{ "
        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Block -RemoteAddress '{ip}' -Enabled True "
        f"}}"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[FIREWALL] Blocked {ip} in Windows Firewall.")
    except Exception as e:
        print(f"[ERROR] Failed to add firewall rule for {ip}: {e}")

def unblock_ip_windows_firewall(ip):
    rule_name = f"MinecraftGuard_Block_{ip}"
    cmd = [
        "powershell", "-Command",
        f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[FIREWALL] Removed rule for {ip} from Windows Firewall.")
    except Exception as e:
        print(f"[ERROR] Failed to remove firewall rule for {ip}: {e}")

def check_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {})
        else:
            return None
    except Exception:
        return None

def send_discord_webhook(webhook_url, title, color, fields):
    if not webhook_url:
        return
    payload = {
        "embeds": [{
            "title": title,
            "color": color,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass

def process_ip(ip, api_key, db, webhook_url):
    if db.is_whitelisted(ip):
        print(f"[WHITELIST] {ip} is whitelisted. Skipping checks.")
        return

    if db.is_blocked(ip):
        return

    print(f"[DETECTED PROBE/SCAN] {ip} -> Checking AbuseIPDB...")
    data = check_abuseipdb(ip, api_key)

    if not data:
        print(f"[WARN] Could not check {ip}.")
        return

    score = data.get("abuseConfidenceScore", 0)
    usage = data.get("usageType", "Unknown")
    country = data.get("countryCode", "Unknown")
    isp = data.get("isp", "Unknown")
    domain = data.get("domain", "N/A")

    should_block = False
    reasons = []

    if score >= ABUSE_SCORE_THRESHOLD:
        should_block = True
        reasons.append(f"Abuse score {score}% >= threshold {ABUSE_SCORE_THRESHOLD}%")

    if usage == DATACENTER_USAGE_TYPE:
        should_block = True
        reasons.append(f"Usage type '{usage}' matched policy")

    fields = [
        {"name": "IP Address", "value": ip, "inline": True},
        {"name": "Country", "value": country, "inline": True},
        {"name": "Abuse Score", "value": f"{score}%", "inline": True},
        {"name": "Usage Type", "value": usage, "inline": True},
        {"name": "ISP", "value": isp, "inline": True},
        {"name": "Domain", "value": domain, "inline": True}
    ]

    if should_block:
        reason_str = "; ".join(reasons)
        print(f"[ACTION] Blocking {ip}: {reason_str}")
        block_ip_windows_firewall(ip)
        add_ip_to_minecraft_banned_json(ip, reason=reason_str)
        db.add_blacklist_ip(ip, score=score, usage_type=usage, country=country, isp=isp, domain=domain, notes=reason_str)
        fields.append({"name": "Action", "value": f"Blocked ({reason_str})", "inline": False})
        send_discord_webhook(webhook_url, f"🚨 Scanner/IP Blocked: {ip}", 0xE74C3C, fields)
    else:
        print(f"[ACTION] Allowed connection/scan from {ip}")
        fields.append({"name": "Action", "value": "Allowed Connection", "inline": False})
        send_discord_webhook(webhook_url, f"✅ Connection Allowed: {ip}", 0x2ECC71, fields)

def main():
    parser = argparse.ArgumentParser(description="Minecraft Guard CLI & Monitoring Daemon")
    parser.add_argument("--list", action="store_true", help="List all currently blocked IPs")
    parser.add_argument("--block", type=str, metavar="IP", help="Manually block an IP address")
    parser.add_argument("--unblock", type=str, metavar="IP", help="Manually unblock an IP address")
    parser.add_argument("--whitelist-add", type=str, metavar="IP", help="Add an IP address to the whitelist")
    parser.add_argument("--whitelist-remove", type=str, metavar="IP", help="Remove an IP address from the whitelist")
    parser.add_argument("--whitelist-list", action="store_true", help="List all whitelisted IPs")
    
    args = parser.parse_args()
    db = GuardDB(DB_FILE)

    # --- CLI COMMAND EXECUTION ---
    if args.list:
        rows = db.get_all_blacklisted()
        print(f"\n--- Currently Blocked IPs ({len(rows)}) ---")
        for r in rows:
            print(f"IP: {r[0]} | Blocked: {r[1]} | Score: {r[2]}% | Usage: {r[3]} | Reason: {r[4]}")
        return

    if args.whitelist_list:
        rows = db.get_all_whitelisted()
        print(f"\n--- Whitelisted IPs ({len(rows)}) ---")
        for r in rows:
            print(f"IP: {r[0]} | Added: {r[1]} | Notes: {r[2]}")
        return

    if args.block:
        ip = args.block
        print(f"Manually blocking {ip}...")
        block_ip_windows_firewall(ip)
        add_ip_to_minecraft_banned_json(ip, reason="Manual CLI block")
        db.add_blacklist_ip(ip, notes="Manual CLI block")
        print(f"Successfully blocked {ip}.")
        return

    if args.unblock:
        ip = args.unblock
        print(f"Unblocking {ip}...")
        unblock_ip_windows_firewall(ip)
        remove_ip_from_minecraft_banned_json(ip)
        db.remove_blacklist_ip(ip)
        print(f"Successfully unblocked {ip}.")
        return

    if args.whitelist_add:
        ip = args.whitelist_add
        print(f"Adding {ip} to whitelist...")
        db.add_whitelist_ip(ip)
        if db.is_blocked(ip):
            unblock_ip_windows_firewall(ip)
            remove_ip_from_minecraft_banned_json(ip)
            db.remove_blacklist_ip(ip)
            print(f"Removed existing block rule for whitelisted IP {ip}.")
        print(f"Successfully whitelisted {ip}.")
        return

    if args.whitelist_remove:
        ip = args.whitelist_remove
        print(f"Removing {ip} from whitelist...")
        db.remove_whitelist_ip(ip)
        print(f"Successfully removed {ip} from whitelist.")
        return

    # --- DAEMON MONITORING LOOP ---
    load_dotenv()
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    print("=" * 68)
    print(" Minecraft Guard - Full Scan Detector (WFP Log + Netstat)")
    print("=" * 68)
    print(f"Monitoring log: {FIREWALL_LOG}")
    print(f"Minecraft Port: {MINECRAFT_PORT}")
    print(f"MC Server Banlist: {MINECRAFT_BANNED_IPS_FILE}")

    if not api_key:
        print("[ERROR] ABUSEIPDB_API_KEY is missing.")
        sys.exit(1)

    seen_ips = set()
    log_pos = FIREWALL_LOG.stat().st_size if FIREWALL_LOG.exists() else 0

    try:
        while True:
            fw_ips, log_pos = get_ips_from_firewall_log(log_pos)
            netstat_ips = get_remote_ipv4s_netstat()
            all_detected = fw_ips.union(netstat_ips)

            for ip in sorted(all_detected):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    process_ip(ip, api_key, db, webhook_url)

            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[STOP] Guard stopped.")

if __name__ == "__main__":
    main()