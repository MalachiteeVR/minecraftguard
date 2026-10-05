#!/usr/bin/env bash
set -euo pipefail

APP=/opt/minecraft-guard
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

ABUSE_KEY=""
PANEL_PASS=""
if systemctl cat minecraft-guard.service >/dev/null 2>&1; then
    EXISTING_ENV="$(systemctl show minecraft-guard.service -p Environment --value 2>/dev/null || true)"
    ABUSE_KEY="$(printf '%s\n' "$EXISTING_ENV" | tr ' ' '\n' | sed -n 's/^ABUSEIPDB_API_KEY=//p' | head -n1 || true)"
    PANEL_PASS="$(printf '%s\n' "$EXISTING_ENV" | tr ' ' '\n' | sed -n 's/^PANEL_PASSWORD=//p' | head -n1 || true)"
fi
if [[ -z "$ABUSE_KEY" ]]; then
    read -r -s -p "AbuseIPDB API key (leave blank to disable automatic reputation blocking): " ABUSE_KEY
    echo
fi
if [[ -z "$PANEL_PASS" || "$PANEL_PASS" == "CHANGE_ME" ]]; then
    read -r -s -p "Panel password (leave blank for no password): " PANEL_PASS
    echo
fi

SECRET="$("$APP/venv/bin/python" -c 'import secrets; print(secrets.token_hex(32))')"

cat >/etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Malachite Minecraft Guard Linux Relay
After=network-online.target haproxy.service rsyslog.service ufw.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP
Environment=MINECRAFT_TARGET=100.87.154.87:25565
Environment=MINECRAFT_PUBLIC_PORT=25565
Environment=GUARD_WEB_HOST=0.0.0.0
Environment=GUARD_WEB_PORT=2555
Environment=PANEL_PASSWORD=$PANEL_PASS
Environment=PANEL_SECRET=$SECRET
Environment=HAPROXY_SOCKET=/run/haproxy/admin.sock
Environment=HA_LOG=/var/log/haproxy.log
Environment=UFW_LOG=/var/log/ufw.log
Environment=ABUSEIPDB_API_KEY=$ABUSE_KEY
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

echo
echo "Malachite Minecraft Guard installed on the Linux relay."
echo "Panel: http://RELAY-IP:2555"
echo "Backend: 100.87.154.87:25565"
echo "Firewall: UFW"
echo "UFW connection log: /var/log/ufw.log"
echo "AbuseIPDB: score > 10% OR Data Center/Web Hosting/Transit => automatic block"
echo "Panel password and AbuseIPDB key are kept in the systemd environment, not GitHub."
