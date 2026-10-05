#!/usr/bin/env bash
set -euo pipefail

APP=/opt/minecraft-guard
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=/etc/minecraft-guard.env

apt-get update
apt-get install -y python3-venv rsyslog ufw haproxy
mkdir -p "$APP"
cp "$REPO_DIR/app.py" "$REPO_DIR/requirements.txt" "$APP/"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip
"$APP/venv/bin/pip" install -r "$APP/requirements.txt"

# HAProxy admin socket is used for current-session viewing and closing.
if ! grep -q 'stats socket /run/haproxy/admin.sock' /etc/haproxy/haproxy.cfg; then
    sed -i '/^global$/a\    stats socket /run/haproxy/admin.sock mode 660 level admin' /etc/haproxy/haproxy.cfg
fi

# Send HAProxy local0 logs to the panel's log file.
cat >/etc/rsyslog.d/49-minecraft-haproxy.conf <<'EOF'
local0.*    /var/log/haproxy.log
& stop
EOF

# Keep UFW kernel firewall messages in a dedicated log for the Guard monitor.
cat >/etc/rsyslog.d/48-minecraft-ufw.conf <<'EOF'
:msg, contains, "UFW "    /var/log/ufw.log
& stop
EOF

touch /var/log/haproxy.log /var/log/ufw.log
chmod 640 /var/log/haproxy.log /var/log/ufw.log
systemctl restart rsyslog
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl restart haproxy

# UFW replaces direct iptables management. Preserve SSH/Tailscale access before enabling it.
ufw allow OpenSSH
ufw allow from 100.64.0.0/10 to any port 2555 proto tcp
ufw logging medium
ufw delete allow 25565/tcp || true
ufw delete allow 25565/udp || true
ufw allow log 25565/tcp
ufw allow log 25565/udp
ufw --force enable

# Read existing credentials from the dedicated environment file when possible.
ABUSE_KEY=""
PANEL_PASS=""
PANEL_SECRET=""
if [[ -f "$ENV_FILE" ]]; then
    eval "$(python3 - "$ENV_FILE" <<'PY'
import shlex, sys
path=sys.argv[1]
vals={}
try:
    for raw in open(path, encoding='utf-8'):
        line=raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k,v=line.split('=',1)
        k=k.strip()
        try:
            parsed=shlex.split(v, posix=True)
            vals[k]=parsed[0] if parsed else ''
        except ValueError:
            pass
except OSError:
    pass
for k in ('ABUSEIPDB_API_KEY','PANEL_PASSWORD','PANEL_SECRET'):
    if k in vals:
        print(f'{k}={shlex.quote(vals[k])}')
PY
)"
    ABUSE_KEY="${ABUSEIPDB_API_KEY:-}"
    PANEL_PASS="${PANEL_PASSWORD:-}"
    PANEL_SECRET="${PANEL_SECRET:-}"
fi

# Migrate values from the old systemd unit if the environment file did not exist yet.
if [[ -z "$ABUSE_KEY" || -z "$PANEL_PASS" ]]; then
    OLD_UNIT="$(systemctl cat minecraft-guard.service 2>/dev/null || true)"
    if [[ -n "$OLD_UNIT" ]]; then
        eval "$(printf '%s\n' "$OLD_UNIT" | python3 -c '
import shlex,sys,re
text=sys.stdin.read()
vals={}
for line in text.splitlines():
    m=re.match(r"^Environment=(.*)$",line.strip())
    if not m: continue
    try: parts=shlex.split(m.group(1), posix=True)
    except ValueError: continue
    for part in parts:
        if "=" in part:
            k,v=part.split("=",1)
            vals[k]=v
for k in ("ABUSEIPDB_API_KEY","PANEL_PASSWORD","PANEL_SECRET"):
    if vals.get(k): print(f"{k}={shlex.quote(vals[k])}")
')"
        ABUSE_KEY="${ABUSEIPDB_API_KEY:-$ABUSE_KEY}"
        PANEL_PASS="${PANEL_PASSWORD:-$PANEL_PASS}"
        PANEL_SECRET="${PANEL_SECRET:-$PANEL_SECRET}"
    fi
fi

if [[ -z "$ABUSE_KEY" ]]; then
    read -r -s -p "AbuseIPDB API key (leave blank to disable automatic reputation blocking): " ABUSE_KEY
    echo
fi
if [[ -z "$PANEL_PASS" || "$PANEL_PASS" == "CHANGE_ME" ]]; then
    read -r -s -p "Panel password (leave blank for no password): " PANEL_PASS
    echo
fi
if [[ -z "$PANEL_SECRET" ]]; then
    PANEL_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
fi

# Write secrets to a root-only systemd EnvironmentFile instead of embedding them in the unit.
# Values are double-quoted and escaped for systemd's EnvironmentFile parser.
python3 - "$ENV_FILE" "$ABUSE_KEY" "$PANEL_PASS" "$PANEL_SECRET" <<'PY'
import os, sys
path, abuse, password, secret = sys.argv[1:]
for name, value in (("ABUSEIPDB_API_KEY", abuse), ("PANEL_PASSWORD", password), ("PANEL_SECRET", secret)):
    if "\n" in value or "\r" in value:
        raise SystemExit(f"{name} cannot contain a newline")
def esc(v):
    return '"' + v.replace('\\','\\\\').replace('"','\\"') + '"'
tmp=path+'.tmp'
with open(tmp,'w',encoding='utf-8') as f:
    f.write('# Malachite Minecraft Guard secrets. Root-readable only.\n')
    f.write(f'ABUSEIPDB_API_KEY={esc(abuse)}\n')
    f.write(f'PANEL_PASSWORD={esc(password)}\n')
    f.write(f'PANEL_SECRET={esc(secret)}\n')
os.chmod(tmp,0o600)
os.replace(tmp,path)
PY

cat >/etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Malachite Minecraft Guard Linux Relay
After=network-online.target haproxy.service rsyslog.service ufw.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP
EnvironmentFile=$ENV_FILE
Environment=MINECRAFT_TARGET=100.87.154.87:25565
Environment=MINECRAFT_PUBLIC_PORT=25565
Environment=GUARD_WEB_HOST=0.0.0.0
Environment=GUARD_WEB_PORT=2555
Environment=HAPROXY_SOCKET=/run/haproxy/admin.sock
Environment=HA_LOG=/var/log/haproxy.log
Environment=UFW_LOG=/var/log/ufw.log
Environment=ABUSEIPDB_THRESHOLD=10
Environment=ABUSEIPDB_MAX_AGE_DAYS=90
Environment=ABUSEIPDB_CACHE_HOURS=24
ExecStart=$APP/venv/bin/gunicorn --workers 1 --threads 8 --bind 0.0.0.0:2555 app:app
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now minecraft-guard

# Verify the service came up instead of silently leaving a broken installation behind.
systemctl is-active --quiet minecraft-guard

printf '\nMalachite Minecraft Guard installed on the Linux relay.\n'
printf 'Panel: http://RELAY-IP:2555\n'
printf 'Backend: 100.87.154.87:25565\n'
printf 'Firewall: UFW\n'
printf 'UFW connection log: /var/log/ufw.log\n'
printf 'AbuseIPDB: score >= 10%% OR datacenter/hosting => automatic block\n'
printf 'Credentials: %s (root-readable only)\n' "$ENV_FILE"
