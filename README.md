# Minecraft-Guard

Minecraft-Guard is frontend/relay-side network management software for a Minecraft deployment.

Architecture:

Internet -> FRONTEND / RELAY SERVER -> Minecraft backend

The program belongs on the frontend/relay server. It manages that host's network policy and its own SQLite policy database.

It does not edit Minecraft backend ban files or backend configuration.

## Features

- Windows Firewall IP block and unblock
- Linux iptables IP block and unblock
- Local blacklist and whitelist database
- AbuseIPDB checks
- Password-protected web administration console
- Active relay connection view
- Audit logging
- CLI controls

## Install

Install Python dependencies:

    python -m pip install -r requirements.txt

Copy .env.example to .env and configure the password and AbuseIPDB key.

The web console defaults to 127.0.0.1:8080. If remote access is needed, put it behind a trusted reverse proxy or VPN.

## Run

    python Minecraft-Guard.py --monitor

The process needs permission to create Windows Firewall rules on Windows.

## Linux relay deployment

The repository is designed to be cloned directly onto the frontend/relay server. The Linux installer is intentionally lightweight and uses a shallow Git clone, a small Python virtual environment, nginx, and systemd.

### One-command-style setup

On a fresh Debian/Ubuntu relay:

    git clone --depth 1 https://github.com/MalachiteeVR/minecraftguard.git
    cd minecraftguard
    sudo chmod +x setup-linux.sh
    sudo ./setup-linux.sh --domain guard.example.com --email admin@example.com

You can also let the installer clone the repository itself. This is useful when setup-linux.sh has been copied to the relay separately:

    sudo ./setup-linux.sh --domain guard.example.com --email admin@example.com

By default it clones:

    https://github.com/MalachiteeVR/minecraftguard.git

The installer accepts a different repository or branch if needed:

    sudo ./setup-linux.sh --domain guard.example.com --email admin@example.com --repo-url https://github.com/MalachiteeVR/minecraftguard.git --branch main

The application is installed at:

    /opt/minecraft-guard

The Git checkout is kept there so the relay can be updated from Git later.

### What the installer does

- installs only the required Debian/Ubuntu packages
- uses a shallow Git clone to minimize download size
- creates a dedicated minecraft-guard service account
- creates a Python virtual environment
- installs Python requirements without pip's package cache
- runs the application through systemd
- binds the Python console to 127.0.0.1:8080
- puts nginx in front of the application
- obtains and installs a Let's Encrypt certificate
- redirects HTTP to HTTPS
- enables HSTS
- enables automatic certificate renewal
- generates a salted scrypt password hash
- stores the generated .env with mode 600
- installs iptables/iproute2 for Linux firewall enforcement
- gives only the firewall network capability needed by the Minecraft-Guard service

The public URL is:

    https://guard.example.com

The installer requires an AbuseIPDB API key because automatic reputation checks are part of the monitor. The Linux deployment therefore does not install a monitor that immediately exits because its API key is missing.

The Python console is never directly exposed to the Internet. Only nginx is public.

### Updating the relay from Git

After a new version is committed:

    cd /opt/minecraft-guard
    sudo git fetch --depth 1 origin main
    sudo git reset --hard origin/main
    sudo systemctl restart minecraft-guard

Do not run git reset --hard if you keep local changes in the checkout.

### Password storage

The setup script hashes the administrator password with Python's built-in scrypt implementation. The plaintext password is not written to .env; only the salted password hash is stored.

### Linux firewall enforcement

On Linux, Minecraft-Guard uses a dedicated iptables chain named `MINECRAFT_GUARD`. Blocked public IPv4 addresses are added to that chain with a DROP rule, while removing or whitelisting an address removes its Minecraft-Guard rule.

The Python service is not run as root. The systemd unit grants it only `CAP_NET_ADMIN`, which is required to manage the iptables rules. The application also uses `ss` on Linux to discover active TCP connections.

The database remains the policy source of truth. On startup, Minecraft-Guard rebuilds its dedicated chain from the saved blacklist instead of modifying Minecraft's `banned-ips.json` or other backend files.

The installer does not use UFW for Minecraft-Guard's IP policy. It only configures nginx/HTTPS and the application service. Do not manually flush or repurpose the `MINECRAFT_GUARD` chain while Minecraft-Guard is running.
