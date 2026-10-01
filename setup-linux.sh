#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/minecraft-guard"
SERVICE_USER="minecraft-guard"
REPO_URL="https://github.com/MalachiteeVR/minecraftguard.git"
BRANCH="main"
DOMAIN=""
EMAIL=""

usage() {
  echo "Usage: sudo $0 --domain guard.example.com --email admin@example.com [--repo-url URL] [--branch BRANCH]"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || usage
[ "$EUID" -eq 0 ] || { echo "Run as root."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends git python3 python3-venv python3-pip nginx certbot python3-certbot-nginx iptables iproute2 ca-certificates

if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch --depth 1 origin "$BRANCH"
  git -C "$APP_DIR" checkout -B "$BRANCH" "origin/$BRANCH"
  git -C "$APP_DIR" reset --hard "origin/$BRANCH"
elif [ ! -f "$APP_DIR/Minecraft-Guard.py" ]; then
  rm -rf "$APP_DIR"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --disable-pip-version-check --no-cache-dir -r "$APP_DIR/requirements.txt"

read -r -s -p "Admin password (12+ chars): " P1; echo
read -r -s -p "Confirm password: " P2; echo
[ "$P1" = "$P2" ] || { unset P1 P2; echo "Passwords do not match."; exit 1; }
[ ${#P1} -ge 12 ] || { unset P1 P2; echo "Password must be at least 12 characters."; exit 1; }

HASH=$(python3 -c 'import hashlib,secrets,sys; p=sys.argv[1].encode(); s=secrets.token_bytes(16); n,r,q=16384,8,1; d=hashlib.scrypt(p,salt=s,n=n,r=r,p=q,dklen=32); print("scrypt$%d,%d,%d$%s$%s" % (n,r,q,s.hex(),d.hex()))' "$P1")
unset P1 P2

read -r -s -p "AbuseIPDB API key (leave blank to disable automatic reputation checks): " ABUSEIPDB_API_KEY; echo

cat > "$APP_DIR/.env" <<EOF
MINECRAFT_GUARD_WORKDIR=$APP_DIR
MINECRAFT_GUARD_WEB=1
MINECRAFT_GUARD_WEB_HOST=127.0.0.1
MINECRAFT_GUARD_WEB_PORT=8080
MINECRAFT_GUARD_ADMIN_PASSWORD_HASH=$HASH
MINECRAFT_GUARD_PORT=25565
MINECRAFT_GUARD_SCAN_INTERVAL=5
MINECRAFT_GUARD_ABUSE_THRESHOLD=75
ABUSEIPDB_API_KEY=$ABUSEIPDB_API_KEY
EOF
unset ABUSEIPDB_API_KEY
chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

cat > /etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Minecraft-Guard frontend relay manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
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
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

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
        proxy_http_version 1.1;
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
systemctl enable --now nginx
systemctl restart nginx

certbot --nginx --non-interactive --agree-tos --redirect --hsts --staple-ocsp -m "$EMAIL" -d "$DOMAIN"
systemctl enable --now certbot.timer || true
systemctl restart minecraft-guard

echo
echo "Minecraft-Guard relay installed."
echo "Repository: $REPO_URL"
echo "Application: $APP_DIR"
echo "Web console: https://$DOMAIN"
echo "Service: systemctl status minecraft-guard"
echo "Firewall: iptables chain MINECRAFT_GUARD"
