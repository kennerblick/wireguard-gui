"""Zentrale Konfiguration: alles, was aus Umgebungsvariablen gelesen wird.

Reines Konstanten-Modul ohne Flask-Abhaengigkeit - kann von jedem anderen
Modul gefahrlos importiert werden, ohne Zirkelbezuege zu riskieren.
"""

import os
import re

DB_PATH = "/data/db/wgacl.db"
SSH_KEY = "/data/ssh/id_ed25519"
SSH_CONTROL_DIR = os.path.dirname(SSH_KEY)


def _env_with_legacy_fallback(new_name: str, old_name: str, default: str = "") -> str:
    """Liest new_name, faellt sonst auf old_name zurueck (mit Hinweis).

    Die ISURFER_*-Variablen aus frueheren Versionen (benannt nach einem
    konkreten Server) wurden zu generischen WG_SERVER_*-Namen umbenannt.
    Bestehende .env-Dateien mit den alten Namen funktionieren dank dieses
    Fallbacks unveraendert weiter.
    """
    val = os.environ.get(new_name)
    if val is not None:
        return val
    val = os.environ.get(old_name)
    if val is not None:
        print(f"[app] HINWEIS: {old_name} ist veraltet, bitte in der .env auf {new_name} umbenennen.")
        return val
    return default


WG_SERVER_TUNNEL_IP = _env_with_legacy_fallback("WG_SERVER_TUNNEL_IP", "ISURFER_WG_IP", "10.250.0.1")
WG_SERVER_SSH_USER = _env_with_legacy_fallback("WG_SERVER_SSH_USER", "ISURFER_SSH_USER", "root")
WG_SERVER_ENDPOINT = _env_with_legacy_fallback("WG_SERVER_ENDPOINT", "ISURFER_ENDPOINT", "")
TARGET_WG_INTERFACE = os.environ.get("TARGET_WG_INTERFACE", "wg0")

EXEC_MODE = os.environ.get("EXEC_MODE", "ssh").strip().lower()
if EXEC_MODE not in ("ssh", "local"):
    print(f"[app] WARNUNG: unbekannter EXEC_MODE={EXEC_MODE!r} - falle zurueck auf 'ssh'.")
    EXEC_MODE = "ssh"
print(f"[app] Ausfuehrungsmodus: {EXEC_MODE}")

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_USER or not ADMIN_PASSWORD:
    print(
        "[app] WARNUNG: ADMIN_USER/ADMIN_PASSWORD nicht gesetzt - "
        "die Web-UI ist ohne Anmeldung erreichbar (siehe README/.env.example)."
    )

FLASK_SECRET = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

VALID_PROTOCOLS = {"tcp", "udp", "all"}
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-()]{1,64}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9 _.\-()]{1,64}$")
TAG_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-()]{1,64}$")

SYSLOG_PORT_LINUX = os.environ.get("PROVISION_SYSLOG_PORT_LINUX", "5141")
SYSLOG_PORT_MIKROTIK = os.environ.get("PROVISION_SYSLOG_PORT_MIKROTIK", "5140")


def _parse_ip_range(env_name: str, default: str) -> tuple:
    """Liest env_name als 'start-end' (letztes Oktett des Subnetzes, z.B.
    '201-245') fuer suggest_free_ip()'s Typ-Bereiche. Ungueltiger Wert faellt
    mit Warnung auf den Standard zurueck, statt beim Start abzustuerzen."""
    raw = os.environ.get(env_name, default)
    try:
        start_s, end_s = raw.split("-", 1)
        start, end = int(start_s), int(end_s)
        if start > end:
            raise ValueError("start > end")
        return start, end
    except ValueError:
        print(f"[app] WARNUNG: {env_name}={raw!r} ungueltig (erwartet 'start-end'), nutze Standard {default!r}.")
        start_s, end_s = default.split("-", 1)
        return int(start_s), int(end_s)


# Feste IP-Bereiche (letztes Oktett) je Client-Typ innerhalb des WG-Subnetzes -
# "Client bereitstellen" schlaegt je gewaehltem Typ die naechste freie IP aus
# dem passenden Bereich vor (siehe provisioning.suggest_free_ip()), statt
# irgendeine freie IP im gesamten Subnetz zu nehmen. Ueberschreibbar, falls
# ein Deployment eine andere Aufteilung als diese (aus einer echten
# Produktiv-Config abgeleitete) Standardaufteilung nutzt.
IP_RANGE_SERVER = _parse_ip_range("IP_RANGE_SERVER", "11-50")
IP_RANGE_ROUTER = _parse_ip_range("IP_RANGE_ROUTER", "100-150")
IP_RANGE_CLIENT = _parse_ip_range("IP_RANGE_CLIENT", "201-245")
IP_RANGES_BY_KIND = {"server": IP_RANGE_SERVER, "router": IP_RANGE_ROUTER, "client": IP_RANGE_CLIENT}

BUILTIN_SERVICES = [
    # name, protocol, port  (port=None -> alle Ports)
    ("SSH", "tcp", 22),
    ("RDP", "tcp", 3389),
    ("HTTPS-Alt (8443)", "tcp", 8443),
    ("PostgreSQL", "tcp", 5432),
    ("Proxmox VE", "tcp", 8006),
    ("HTTP", "tcp", 80),
    ("HTTPS", "tcp", 443),
    ("Alle Ports", "all", None),
]

# Tags, die "Client bereitstellen" automatisch je Plattform vergibt.
PROVISION_PLATFORM_TAGS = {
    "linux": "linux",
    "windows": "windows",
    "mikrotik": "mikrotik",
}
