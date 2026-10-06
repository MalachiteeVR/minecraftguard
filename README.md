# Malachite Minecraft Guard AbuseIPDB package

Includes the Linux Guard daemon, panel, dependencies, and environment template.

AbuseIPDB defaults:
- threshold: 90%
- maxAgeInDays: 90
- cache: 24 hours
- whitelist bypasses AbuseIPDB
- private/reserved addresses are skipped
- API failures do not stop Guard

The web page does not refresh every 5 seconds. Only the log endpoint is polled every 5 seconds.

After copying files:
1. Update /etc/minecraft-guard.env with your API key.
2. Install dependencies with the existing venv:
   /opt/minecraft-guard/venv/bin/pip install -r /opt/minecraft-guard/requirements.txt
3. Copy minecraft-guard.py and app.py into /opt/minecraft-guard.
4. Restart both services.
