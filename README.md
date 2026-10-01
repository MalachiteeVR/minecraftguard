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
