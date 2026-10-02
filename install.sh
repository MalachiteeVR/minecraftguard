#!/usr/bin/env bash
set -euo pipefail
APP=/opt/minecraft-panel
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
apt-get update
apt-get install -y python3-venv rsyslog iptables
mkdir -p "$APP"
cp "$REPO_DIR/app.py" "$REPO_DIR/requirements.txt" "$APP/"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip
"$APP/venv/bin/pip" install -r "$APP/requirements.txt"

if ! grep -q '^    stats socket /run/haproxy/admin.sock' /etc/haproxy/haproxy.cfg; then
    sed -i '/^global$/a\    stats socket /run/haproxy/admin.sock mode 660 level admin' /etc/haproxy/haproxy.cfg
fi

cat >/etc/rsyslog.d/49-minecraft-haproxy.conf <<'EOF'
local0.*    /var/log/haproxy.log
& stop
EOF
touch /var/log/haproxy.log
chmod 640 /var/log/haproxy.log
systemctl restart rsyslog
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl restart haproxy

SECRET="$("$APP/venv/bin/python" -c 'import secrets; print(secrets.token_hex(32))')"
cat >/etc/systemd/system/minecraft-panel.service <<EOF
[Unit]
Description=Malachite Minecraft Manual Control Panel
After=network-online.target haproxy.service rsyslog.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP
Environment=PANEL_PASSWORD=CHANGE_ME
Environment=PANEL_SECRET=$SECRET
Environment=MINECRAFT_TARGET=127.0.0.1:25565
ExecStart=$APP/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8080 app:app
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now minecraft-panel
echo
echo "Panel installed at http://127.0.0.1:8080"
echo "Set PANEL_PASSWORD in /etc/systemd/system/minecraft-panel.service"
echo "Then run: systemctl daemon-reload && systemctl restart minecraft-panel"
