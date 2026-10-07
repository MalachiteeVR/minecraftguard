#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/minecraft-guard"
ENV_FILE="/etc/minecraft-guard.env"
BACKUP_DIR="/var/backups/minecraft-guard"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

PUBLIC_PORT=25565
HAPROXY_PORT=25566

 echo "== Malachite Minecraft Guard installer =="

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run this installer as root: sudo ./install.sh"
    exit 1
fi

required_files=("minecraft-guard.py" "app.py" "requirements.txt")
for f in "${required_files[@]}"; do
    [[ -f "$SCRIPT_DIR/$f" ]] || { echo "ERROR: Missing $f"; exit 1; }
done

echo "[1/11] Stopping existing services..."
systemctl stop minecraft-guard-panel.service 2>/dev/null || true
systemctl stop minecraft-guard.service 2>/dev/null || true
systemctl stop haproxy.service 2>/dev/null || true

# Preserve the existing database before replacing the application directory.
echo "[2/11] Backing up existing Guard database..."
mkdir -p "$BACKUP_DIR"
if [[ -f "$APP_DIR/guard.db" ]]; then
    cp -a "$APP_DIR/guard.db" "$BACKUP_DIR/guard.db.$(date +%Y%m%d-%H%M%S).bak"
fi

# Keep the environment file outside APP_DIR so git/installer updates cannot erase secrets.
echo "[3/11] Installing application files..."
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
install -m 0755 "$SCRIPT_DIR/minecraft-guard.py" "$APP_DIR/minecraft-guard.py"
install -m 0644 "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
install -m 0644 "$SCRIPT_DIR/requirements.txt" "$APP_DIR/requirements.txt"

latest_db="$(ls -1t "$BACKUP_DIR"/guard.db.*.bak 2>/dev/null | head -n1 || true)"
if [[ -n "$latest_db" ]]; then
    cp -a "$latest_db" "$APP_DIR/guard.db"
fi

echo "[4/11] Installing Python environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "[5/11] Installing HAProxy..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y haproxy

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<'EOF'
ABUSEIPDB_API_KEY=
ABUSEIPDB_THRESHOLD=90
ABUSEIPDB_MAX_AGE_DAYS=90
ABUSEIPDB_CACHE_SECONDS=86400
ABUSEIPDB_TIMEOUT=10
GUARD_BIND_HOST=0.0.0.0
MINECRAFT_PUBLIC_PORT=25565
HAPROXY_HOST=127.0.0.1
HAPROXY_PORT=25566
GUARD_BACKLOG=256
GUARD_CONNECT_TIMEOUT=10
PANEL_PASSWORD=CHANGE_ME
PANEL_SECRET=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
EOF
    echo "Created $ENV_FILE. Add your AbuseIPDB key if you want reputation blocking."
else
    # Add only missing settings. Existing passwords, secrets, and API keys are preserved.
    declare -A defaults=(
        [ABUSEIPDB_API_KEY]=""
        [ABUSEIPDB_THRESHOLD]="90"
        [ABUSEIPDB_MAX_AGE_DAYS]="90"
        [ABUSEIPDB_CACHE_SECONDS]="86400"
        [ABUSEIPDB_TIMEOUT]="10"
        [GUARD_BIND_HOST]="0.0.0.0"
        [MINECRAFT_PUBLIC_PORT]="25565"
        [HAPROXY_HOST]="127.0.0.1"
        [HAPROXY_PORT]="25566"
        [GUARD_BACKLOG]="256"
        [GUARD_CONNECT_TIMEOUT]="10"
    )
    for key in "${!defaults[@]}"; do
        if ! grep -qE "^${key}=" "$ENV_FILE"; then
            printf '%s=%s\n' "$key" "${defaults[$key]}" >> "$ENV_FILE"
        fi
    done
fi
chmod 0600 "$ENV_FILE"

# HAProxy is no longer public on 25565. Guard owns 25565 and forwards approved TCP sessions here.
echo "[6/11] Configuring HAProxy on loopback:${HAPROXY_PORT}..."
cp -a "$HAPROXY_CFG" "$HAPROXY_CFG.backup.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
cat > "$HAPROXY_CFG" <<EOF
# Managed by Malachite Minecraft Guard

global
    log /dev/log local0
    log /dev/log local1 notice
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 10s
    timeout client 1h
    timeout server 1h

frontend minecraft_guard_upstream
    bind 127.0.0.1:${HAPROXY_PORT}
    mode tcp
    default_backend minecraft_home

backend minecraft_home
    mode tcp
    server home 100.87.154.87:25565 check
EOF

haproxy -c -f "$HAPROXY_CFG"

# UFW must allow the Guard's public TCP listener. UDP 25565 is intentionally removed.
echo "[7/11] Configuring UFW..."
ufw allow OpenSSH >/dev/null || true
ufw allow from 100.64.0.0/10 to any port 2555 proto tcp >/dev/null || true
ufw allow ${PUBLIC_PORT}/tcp >/dev/null || true
ufw delete allow ${PUBLIC_PORT}/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null

cat > /etc/systemd/system/minecraft-guard.service <<EOF
[Unit]
Description=Malachite Minecraft Guard TCP Pre-Filter
After=network-online.target ufw.service haproxy.service
Wants=network-online.target
Requires=haproxy.service

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
systemctl enable haproxy.service minecraft-guard.service minecraft-guard-panel.service

echo "[8/11] Starting HAProxy..."
systemctl restart haproxy.service

if ! systemctl is-active --quiet haproxy.service; then
    echo "ERROR: HAProxy failed to start."
    systemctl status haproxy.service --no-pager -l || true
    exit 1
fi

echo "[9/11] Starting Guard and panel..."
systemctl restart minecraft-guard.service
systemctl restart minecraft-guard-panel.service

echo "[10/11] Verifying listeners..."
for _ in {1..30}; do
    if systemctl is-active --quiet haproxy.service &&
       systemctl is-active --quiet minecraft-guard.service &&
       systemctl is-active --quiet minecraft-guard-panel.service &&
       ss -lnt '( sport = :25565 or sport = :25566 or sport = :2555 )' | grep -q ':25565' &&
       ss -lnt '( sport = :25566 )' | grep -q '127.0.0.1:25566' &&
       ss -lnt '( sport = :2555 )' | grep -q LISTEN; then
        break
    fi
    sleep 1
done

if ! systemctl is-active --quiet haproxy.service; then
    echo "ERROR: HAProxy is not running."
    systemctl status haproxy.service --no-pager -l || true
    exit 1
fi

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

if ! ss -lnt '( sport = :25565 )' | grep -q LISTEN; then
    echo "ERROR: Guard is not listening on public port 25565."
    systemctl status minecraft-guard.service --no-pager -l || true
    exit 1
fi

if ! ss -lnt '( sport = :25566 )' | grep -q '127.0.0.1:25566'; then
    echo "ERROR: HAProxy is not listening on 127.0.0.1:25566."
    systemctl status haproxy.service --no-pager -l || true
    exit 1
fi

if ! ss -lnt '( sport = :2555 )' | grep -q LISTEN; then
    echo "ERROR: Guard panel is not listening on port 2555."
    systemctl status minecraft-guard-panel.service --no-pager -l || true
    exit 1
fi

echo "[11/11] Final configuration:"
echo "  Guard:    public TCP 0.0.0.0:${PUBLIC_PORT}"
echo "  HAProxy:  loopback TCP 127.0.0.1:${HAPROXY_PORT}"
echo "  Backend:  100.87.154.87:25565"
echo "  Panel:    0.0.0.0:2555"
echo "  UDP:      ${PUBLIC_PORT} not configured"
echo "  Guard:    $(systemctl is-active minecraft-guard.service)"
echo "  HAProxy:  $(systemctl is-active haproxy.service)"
echo "  Panel:    $(systemctl is-active minecraft-guard-panel.service)"
echo "  AbuseIPDB key configured: $(grep -q '^ABUSEIPDB_API_KEY=.\+' "$ENV_FILE" && echo yes || echo no)"
echo

echo "Installation complete."
