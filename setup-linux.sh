#!/usr/bin/env bash
set -euo pipefail
APP_DIR=/opt/minecraft-guard
USER=minecraft-guard
DOMAIN=""
EMAIL=""
while [ $# -gt 0 ]; do case "$1" in --domain) DOMAIN="$2"; shift 2;; --email) EMAIL="$2"; shift 2;; *) echo "Usage: sudo $0 --domain guard.example.com --email admin@example.com"; exit 1;; esac; done
[ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || { echo "Domain and email are required."; exit 1; }
[ "$EUID" -eq 0 ] || { echo "Run as root."; exit 1; }
apt-get update
apt-get install -y python3 python3-venv python3-pip nginx certbot python3-certbot-nginx ufw
id "$USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$USER"
mkdir -p "$APP_DIR"
chown -R "$USER:$USER" "$APP_DIR"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
read -r -s -p "Admin password (12+ chars): " P1; echo
read -r -s -p "Confirm password: " P2; echo
[ "$P1" = "$P2" ] || { echo "Passwords do not match."; exit 1; }
[ ${#P1} -ge 12 ] || { echo "Password must be at least 12 characters."; exit 1; }
HASH=$(python3 -c 'import hashlib,secrets,sys; p=sys.argv[1].encode(); s=secrets.token_bytes(16); n,r,q=16384,8,1; d=hashlib.scrypt(p,salt=s,n=n,r=r,p=q,dklen=32); print(f"scrypt${n},{r},{q}${s.hex()}${d.hex()}")' "$P1")
unset P1 P2
cat > "$APP_DIR/.env" <<EOF
MINECRAFT_GUARD_WORKDIR=$APP_DIR
MINECRAFT_GUARD_WEB=1
MINECRAFT_GUARD_WEB_HOST=127.0.0.1
MINECRAFT_GUARD_WEB_PORT=8080
MINECRAFT_GUARD_ADMIN_PASSWORD_HASH=$HASH
MINECRAFT_GUARD_PORT=25565
MINECRAFT_GUARD_SCAN_INTERVAL=5
MINECRAFT_GUARD_ABUSE_THRESHOLD=75
EOF
chown "$USER:$USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"
cat > /etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Minecraft-Guard frontend relay manager
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/Minecraft-Guard.py --monitor
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$APP_DIR
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/nginx/sites-available/minecraft-guard <<EOF
server {
 listen 80;
 listen [::]:80;
 server_name $DOMAIN;
 location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;
 }
}
EOF
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/minecraft-guard /etc/nginx/sites-enabled/minecraft-guard
nginx -t
systemctl daemon-reload
systemctl enable --now minecraft-guard
systemctl reload nginx
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
certbot --nginx --non-interactive --agree-tos --redirect --hsts --staple-ocsp -m "$EMAIL" -d "$DOMAIN"
systemctl enable --now certbot.timer || true
systemctl restart minecraft-guard
echo "Minecraft-Guard is live at https://$DOMAIN"