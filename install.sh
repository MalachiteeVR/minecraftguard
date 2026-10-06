#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/minecraft-guard"
ENV_FILE="/etc/minecraft-guard.env"
BACKUP_DIR="/var/backups/minecraft-guard"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "== Malachite Minecraft Guard installer =="

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run this installer as root: sudo ./install.sh"
    exit 1
fi

required_files=("minecraft-guard.py" "app.py" "requirements.txt")
for f in "${required_files[@]}"; do
    [[ -f "$SCRIPT_DIR/$f" ]] || { echo "ERROR: Missing $f"; exit 1; }
done

echo "[1/10] Stopping existing services..."
systemctl stop minecraft-guard-panel.service 2>/dev/null || true
systemctl stop minecraft-guard.service 2>/dev/null || true

echo "[2/10] Backing up existing Guard database..."
mkdir -p "$BACKUP_DIR"
if [[ -f "$APP_DIR/guard.db" ]]; then
    cp -a "$APP_DIR/guard.db" \
        "$BACKUP_DIR/guard.db.$(date +%Y%m%d-%H%M%S).bak"
fi

echo "[3/10] Removing previous application files..."
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"

echo "[4/10] Installing application..."
install -m 0755 "$SCRIPT_DIR/minecraft-guard.py" "$APP_DIR/minecraft-guard.py"
install -m 0644 "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
install -m 0644 "$SCRIPT_DIR/requirements.txt" "$APP_DIR/requirements.txt"

# Restore the newest database backup into the new install.
latest_db="$(ls -1t "$BACKUP_DIR"/guard.db.*.bak 2>/dev/null | head -n1 || true)"
if [[ -n "$latest_db" ]]; then
    cp -a "$latest_db" "$APP_DIR/guard.db"
fi

echo "[5/10] Installing Python environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "[6/10] Creating log/config directories..."
touch /var/log/minecraft-guard.log
chmod 0640 /var/log/minecraft-guard.log
chown root:root /var/log/minecraft-guard.log

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<'EOF'
ABUSEIPDB_API_KEY=
ABUSEIPDB_THRESHOLD=90
ABUSEIPDB_MAX_AGE_DAYS=90
ABUSEIPDB_CACHE_SECONDS=86400
ABUSEIPDB_TIMEOUT=10
PANEL_PASSWORD=CHANGE_ME
PANEL_SECRET=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
EOF
    chmod 0600 "$ENV_FILE"
    echo "Created $ENV_FILE. Add your AbuseIPDB key before starting production traffic."
else
    chmod 0600 "$ENV_FILE"
    echo "Keeping existing $ENV_FILE."
fi

echo "[7/10] Installing systemd services..."
cat > /etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Malachite Minecraft Guard Linux Relay
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/minecraft-guard.py
Restart=always
RestartSec=3
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/minecraft-guard-panel.service <<EOF
[Unit]
Description=Malachite Minecraft Guard Web Panel
After=network-online.target minecraft-guard.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 1 --threads 8 --bind 0.0.0.0:2555 app:app
Restart=always
RestartSec=3
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable minecraft-guard.service minecraft-guard-panel.service

echo "[8/10] Configuring UFW..."
ufw allow OpenSSH >/dev/null || true
ufw allow from 100.64.0.0/10 to any port 2555 proto tcp >/dev/null || true
ufw allow 25565/tcp >/dev/null || true
ufw allow 25565/udp >/dev/null || true
ufw --force enable >/dev/null

echo "[9/10] Starting services..."
systemctl restart minecraft-guard.service
systemctl restart minecraft-guard-panel.service

echo "[10/10] Verifying..."
for _ in {1..30}; do
    if systemctl is-active --quiet minecraft-guard.service &&
       systemctl is-active --quiet minecraft-guard-panel.service &&
       ss -lnt '( sport = :2555 )' | grep -q LISTEN; then
        break
    fi
    sleep 1
done

if ! systemctl is-active --quiet minecraft-guard.service; then
    echo "ERROR: minecraft-guard.service failed."
    systemctl status minecraft-guard.service --no-pager -l || true
    exit 1
fi

if ! systemctl is-active --quiet minecraft-guard-panel.service; then
    echo "ERROR: minecraft-guard-panel.service failed."
    systemctl status minecraft-guard-panel.service --no-pager -l || true
    exit 1
fi

if ! ss -lnt '( sport = :2555 )' | grep -q LISTEN; then
    echo "ERROR: Guard panel is not listening on port 2555."
    systemctl status minecraft-guard-panel.service --no-pager -l || true
    exit 1
fi

echo
echo "Installation complete."
echo "Guard:  $(systemctl is-active minecraft-guard.service)"
echo "Panel:  $(systemctl is-active minecraft-guard-panel.service)"
echo "Panel:  http://<relay-ip>:2555"
echo "Relay:  TCP/UDP 25565"
echo
echo "AbuseIPDB configuration:"
grep -E '^(ABUSEIPDB_THRESHOLD|ABUSEIPDB_MAX_AGE_DAYS|ABUSEIPDB_CACHE_SECONDS|ABUSEIPDB_TIMEOUT)=' "$ENV_FILE" || true
echo "API key: configured=$(grep -q '^ABUSEIPDB_API_KEY=.\+' "$ENV_FILE" && echo yes || echo no)"
