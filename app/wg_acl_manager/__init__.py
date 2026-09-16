"""wg-acl-manager: WireGuard-Peer-Firewall-ACL-Verwaltung.

Aufbau: ein einzelnes globales Flask-Objekt `app` (kein Application-Factory-
mit-mehreren-Instanzen-Pattern - fuer diese Groessenordnung unnoetige
Komplexitaet), Routen liegen nach Zustaendigkeit sortiert in `routes/`,
Geschaeftslogik in den uebrigen Modulen:

- config.py       - Umgebungsvariablen/Konstanten
- db.py           - SQLite-Zugriff, Schema, Migrationen
- auth.py         - optionale HTTP-Basic-Auth
- wireguard.py    - WireGuard-Config/Status lesen, Remote-Ausfuehrung (SSH/lokal)
- firewall.py     - iptables-Script-Generierung/-Interpretation
- acl.py          - DB-Regeln <-> Firewall uebersetzen (inkl. Gruppen-Aufloesung)
- tags.py         - Gruppen ("alle MikroTiks" usw.)
- provisioning.py - Setup-Skripte fuer neue Clients, Peer-Registrierung

Cross-Modul-Aufrufe erfolgen als `from . import wireguard` und dann
`wireguard.run_on_target(...)`, NICHT `from .wireguard import run_on_target`.
Grund: Tests ersetzen solche Funktionen per `monkeypatch.setattr(wireguard,
"run_on_target", ...)` - das wirkt nur, wenn Aufrufer die Funktion ueber das
Modul-Objekt referenzieren statt eine lokal importierte Kopie des Namens zu
halten.
"""

from flask import Flask

from . import config

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET

from . import auth  # noqa: E402,F401  (registriert before_request)
from . import db  # noqa: E402,F401  (registriert teardown_appcontext)
from . import routes  # noqa: E402,F401  (registriert alle @app.route(...))


def create_app():
    """Gibt die konfigurierte Flask-App zurueck.

    Bei EXEC_MODE=local wird hier einmalig reapply_all_on_startup()
    angestossen (siehe acl.py) - bewusst erst hier und nicht bereits beim
    reinen Modul-Import, damit ein Test-Import von wg_acl_manager-Submodulen
    niemals unbeabsichtigt echte WireGuard-/iptables-Befehle ausloest.
    """
    if config.EXEC_MODE == "local":
        from . import acl
        with app.app_context():
            acl.reapply_all_on_startup()
    return app
