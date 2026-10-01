#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/minecraft-guard"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$APP_DIR/.env"
SERVICE_USER="minecraft-guard"

echo "== Minecraft-Guard Linux installer =="

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script with sudo: sudo ./setup-linux.sh"
  exit 1
fi

for f in minecraft-guard.py minecraft-guard-web.py requirements.txt; do
  [[ -f "$REPO_DIR/$f" ]] || { echo "Missing $REPO_DIR/$f"; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip iptables

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$APP_DIR"
cp "$REPO_DIR/minecraft-guard.py" "$APP_DIR/minecraft-guard.py"
cp "$REPO_DIR/minecraft-guard-web.py" "$APP_DIR/minecraft-guard-web.py"
cp "$REPO_DIR/requirements.txt" "$APP_DIR/requirements.txt"

if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

if [[ ! -f "$ENV_FILE" ]]; then
  SECRET="$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")"
  cat > "$ENV_FILE" <<EOF
MINECRAFT_GUARD_WORKDIR=$APP_DIR
MINECRAFT_GUARD_PORT=25565
MINECRAFT_GUARD_DB_SYNC_INTERVAL=5
MINECRAFT_GUARD_WEB_HOST=127.0.0.1
MINECRAFT_GUARD_WEB_PORT=8080
MINECRAFT_GUARD_SESSION_TTL=3600
MINECRAFT_GUARD_SECRET_KEY=$SECRET
MINECRAFT_GUARD_ADMIN_PASSWORD_HASH=
ABUSEIPDB_API_KEY=
ABUSE_SCORE_THRESHOLD=10
DATACENTER_USAGE_TYPE=Data Center/Web Hosting/Transit
EOF
  echo "Created $ENV_FILE"
fi

# The web console and SQLite database are owned by the service account.
# The firewall manager runs as root because it must modify iptables.
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
touch "$APP_DIR/blacklist.db"
chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/blacklist.db"
chmod 600 "$ENV_FILE"
chmod 664 "$APP_DIR/blacklist.db"

cat > /etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Minecraft-Guard iptables firewall manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/minecraft-guard.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/minecraft-guard-web.service <<EOF
[Unit]
Description=Minecraft-Guard web console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/minecraft-guard-web.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable minecraft-guard.service minecraft-guard-web.service

echo "Installation complete."
echo "Edit $ENV_FILE before starting the services."
echo "Start with: sudo systemctl start minecraft-guard minecraft-guard-web"
