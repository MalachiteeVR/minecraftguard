# Malachite Minecraft Guard

Linux relay control panel for a Minecraft server behind HAProxy.

## Relay layout

```text
Internet
   |
   v
Linux relay :25565
   |  iptables / Minecraft Guard
   |  HAProxy
   v
Tailscale
   |
   v
Windows Minecraft server 100.87.154.87:25565
```

The relay version is intentionally different from the original Windows guard. It does not use the Windows Firewall, Windows `netstat`, or the Windows `banned-ips.json` file.

## Features

- Live Minecraft Java status ping
- Player count, latency and version information
- Current HAProxy Minecraft sessions
- Close individual HAProxy sessions
- Manual IP blacklist
- Manual IP unblock/remove
- Persistent blacklist in SQLite
- Manual IP whitelist
- Whitelist takes precedence over blocking
- Guard event log
- HAProxy log viewer
- Relay-side enforcement through a dedicated `MINECRAFT_GUARD` iptables chain
- Optional panel password
- Runs directly on the Linux relay

## Install

After HAProxy is configured and the repository is cloned:

```bash
sudo bash install.sh
```

The installer configures the HAProxy admin socket, HAProxy logging, Python environment and a `minecraft-guard` systemd service.

The default Minecraft backend is:

```text
100.87.154.87:25565
```

The panel listens on:

```text
0.0.0.0:8080
```

Set the panel password in:

```text
/etc/systemd/system/minecraft-guard.service
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart minecraft-guard
```

## Updating

The repository is the source of the application. After the relay has been migrated to the new `minecraft-guard` service, updates are:

```bash
git pull
sudo systemctl restart minecraft-guard
```

A running Python process cannot load changed source code without being restarted. The SQLite database remains persistent across updates.

## Configuration

The service defaults can be changed in its systemd environment:

```text
MINECRAFT_TARGET=100.87.154.87:25565
MINECRAFT_PUBLIC_PORT=25565
GUARD_WEB_HOST=0.0.0.0
GUARD_WEB_PORT=8080
PANEL_PASSWORD=...
PANEL_SECRET=...
HAPROXY_SOCKET=/run/haproxy/admin.sock
HA_LOG=/var/log/haproxy.log
```

## Important

Run the guard as root because relay-side iptables management and the HAProxy admin socket require elevated privileges.

Do not expose the management panel directly to the public Internet without a password and an appropriate network access policy.
