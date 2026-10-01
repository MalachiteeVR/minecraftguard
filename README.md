# Minecraft-Guard

Minecraft-Guard is frontend/relay-side network management software for a Minecraft deployment.

Architecture:

Internet -> FRONTEND / RELAY SERVER -> Minecraft backend

The program belongs on the frontend/relay server. It manages that host's Windows Firewall and its own SQLite policy database.

It does not edit Minecraft backend ban files or backend configuration.

## Features

- Windows Firewall IP block and unblock
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

The process needs permission to create Windows Firewall rules.

## Linux public HTTPS deployment

For a Debian/Ubuntu frontend server, copy the repository to the server and run:

    sudo chmod +x setup-linux.sh
    sudo ./setup-linux.sh --domain guard.example.com --email admin@example.com

Before running it, make sure the DNS A/AAAA record for the chosen domain points to the frontend server and that ports 80 and 443 are reachable from the Internet.

The setup script:

- installs Python, nginx, Certbot and UFW
- creates a dedicated service account
- runs Minecraft-Guard through systemd
- binds the Python console to localhost only
- puts nginx in front of it
- obtains and installs a Let's Encrypt certificate
- redirects HTTP to HTTPS
- enables HSTS
- enables automatic certificate renewal
- generates a salted scrypt password hash instead of storing the administrator password
- stores the generated environment file with mode 600
- opens TCP 80/443 in UFW for the web console

The public URL is:

    https://guard.example.com

The Python console is never directly exposed to the Internet. Only nginx is public.

### Password storage

The setup script hashes the administrator password with Python's built-in scrypt implementation. The plaintext password is not written to `.env`; only the salted password hash is stored.

### Important

The Linux setup is for the frontend web deployment. The current IP blocking implementation in Minecraft-Guard.py was originally written around Windows PowerShell firewall commands, so Linux firewall enforcement should be treated as a separate platform backend rather than assuming those commands work on Linux.
