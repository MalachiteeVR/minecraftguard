# Malachite Minecraft Manual Control Panel

Manual control panel for the Minecraft HAProxy relay.

## Features
- Current HAProxy Minecraft connections.
- Close one selected connection.
- Manually block an IP with iptables.
- Blocking an IP also closes its current HAProxy sessions.
- Manually unblock an IP.
- Persistent connection history in SQLite.
- Minecraft Java server status: online/offline, MOTD, player count, latency, version and icon.
- No automatic blocking.
- No whitelist.
- No behavior-based decisions.

## Install
After HAProxy is already working:
    sudo bash install.sh

Then edit:
    sudo nano /etc/systemd/system/minecraft-panel.service

Set PANEL_PASSWORD, then:
    sudo systemctl daemon-reload
    sudo systemctl restart minecraft-panel

The app listens only on 127.0.0.1:8080. Use Nginx/HTTPS or a private tunnel for browser access.

The service runs as root because the operator-requested block/unblock actions require iptables and the HAProxy admin socket.
