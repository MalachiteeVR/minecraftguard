#!/usr/bin/env bash
set -euo pipefail

APP=/opt/minecraft-guard
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=/etc/minecraft-guard.env

if [[ $EUID -ne 0 ]]; then
    echo "Run this installer as root."
    exit 1
fi

# Stop and remove every previous Guard installation before installing the current tree.
systemctl disable --now minecraft-guard.service minecraft-guard-panel.service 2>/dev/null || true
rm -f /etc/systemd/system/minecraft-guard.service /etc/systemd/system/minecraft-guard-panel.service
systemctl daemon-reload
rm -rf "$APP"
mkdir -p "$APP"

apt-get update
apt-get install -y python3-venv rsyslog ufw haproxy

cp "$REPO_DIR/minecraft-guard.py" "$APP/minecraft-guard.py"
cp "$REPO_DIR/app.py" "$APP/app.py"
cp "$REPO_DIR/requirements.txt" "$APP/requirements.txt"
chmod 755 "$APP/minecraft-guard.py"

python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip
"$APP/venv/bin/pip" install -r "$APP/requirements.txt"

# Preserve credentials in a root-only environment file. Ask only when values are missing.
ABUSE_KEY=""
PANEL_PASS=""
PANEL_SECRET=""
if [[ -f "$ENV_FILE" ]]; then
    ABUSE_KEY="$(sed -n 's/^ABUSEIPDB_API_KEY=//p' "$ENV_FILE" | head -n1 | sed 's/^"//;s/"$//' || true)"
    PANEL_PASS="$(sed -n 's/^PANEL_PASSWORD=//p' "$ENV_FILE" | head -n1 | sed 's/^"//;s/"$//' || true)"
    PANEL_SECRET="$(sed -n 's/^PANEL_SECRET=//p' "$ENV_FILE" | head -n1 | sed 's/^"//;s/"$//' || true)"
fi
if [[ -z "$ABUSE_KEY" ]]; then
    read -r -s -p "AbuseIPDB API key (blank to disable): " ABUSE_KEY
    echo
fi
if [[ -z "$PANEL_PASS" ]]; then
    read -r -s -p "Panel password (blank for no password): " PANEL_PASS
    echo
fi
if [[ -z "$PANEL_SECRET" ]]; then
    PANEL_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
fi

python3 - "$ENV_FILE" "$ABUSE_KEY" "$PANEL_PASS" "$PANEL_SECRET" <<'PY'
import os, sys
path, abuse, password, secret = sys.argv[1:]
for name, value in (("ABUSEIPDB_API_KEY", abuse), ("PANEL_PASSWORD", password), ("PANEL_SECRET", secret)):
    if "\n" in value or "\r" in value:
        raise SystemExit(f"{name} cannot contain a newline")
def esc(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
tmp = path + '.tmp'
with open(tmp, 'w', encoding='utf-8') as f:
    f.write('# Malachite Minecraft Guard secrets. Root-readable only.\n')
    f.write(f'ABUSEIPDB_API_KEY={esc(abuse)}\n')
    f.write(f'PANEL_PASSWORD={esc(password)}\n')
    f.write(f'PANEL_SECRET={esc(secret)}\n')
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

# Configure logging used by minecraft-guard.py.
cat >/etc/rsyslog.d/48-minecraft-ufw.conf <<'EOF'
:msg, contains, "UFW "    /var/log/ufw.log
& stop
EOF
mkdir -p /var/log
touch /var/log/ufw.log /var/log/minecraft-guard.log
chmod 640 /var/log/ufw.log /var/log/minecraft-guard.log
systemctl restart rsyslog

# UFW is the firewall authority for the relay.
ufw allow OpenSSH
ufw allow from 100.64.0.0/10 to any port 2555 proto tcp
ufw logging medium
ufw delete allow 25565/tcp || true
ufw delete allow 25565/udp || true
ufw allow log 25565/tcp
ufw allow log 25565/udp
ufw --force enable

# Keep the existing HAProxy relay and its admin socket.
if ! grep -q 'stats socket /run/haproxy/admin.sock' /etc/haproxy/haproxy.cfg; then
    sed -i '/^global$/a\    stats socket /run/haproxy/admin.sock mode 660 level admin' /etc/haproxy/haproxy.cfg
fi
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl restart haproxy

cat >/etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Malachite Minecraft Guard Linux Relay
After=network-online.target rsyslog.service ufw.service haproxy.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP
EnvironmentFile=$ENV_FILE
Environment=GUARD_DIR=$APP
Environment=GUARD_DB=$APP/guard.db
Environment=GUARD_LOG=/var/log/minecraft-guard.log
Environment=UFW_LOG=/var/log/ufw.log
Environment=MINECRAFT_PUBLIC_PORT=25565
ExecStart=$APP/venv/bin/python $APP/minecraft-guard.py
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/minecraft-guard-panel.service <<EOF
[Unit]
Description=Malachite Minecraft Guard Web Panel
After=network-online.target minecraft-guard.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP
EnvironmentFile=$ENV_FILE
Environment=GUARD_DIR=$APP
Environment=GUARD_DB=$APP/guard.db
Environment=GUARD_SCRIPT=$APP/minecraft-guard.py
Environment=GUARD_PYTHON=$APP/venv/bin/python
Environment=GUARD_LOG=/var/log/minecraft-guard.log
Environment=GUARD_WEB_HOST=0.0.0.0
Environment=GUARD_WEB_PORT=2555
ExecStart=$APP/venv/bin/gunicorn --workers 1 --threads 8 --bind 0.0.0.0:2555 app:app
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now minecraft-guard.service minecraft-guard-panel.service

systemctl is-active --quiet minecraft-guard.service
systemctl is-active --quiet minecraft-guard-panel.service

printf '\nMalachite Minecraft Guard Linux relay installed.\n'
printf 'Panel: http://RELAY-IP:2555\n'
printf 'Minecraft relay: TCP/UDP 25565\n'
printf 'Guard daemon: every 5 seconds\n'
printf 'Credentials: %s\n' "$ENV_FILE"
