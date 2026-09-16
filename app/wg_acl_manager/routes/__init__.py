"""Importieren dieses Pakets registriert alle Routen auf der App (siehe
wg_acl_manager/__init__.py) - jedes Submodul haengt seine @app.route(...)
-Funktionen beim eigenen Import an.
"""

from . import dashboard, maintenance, netzplan, networks, provisioning, services, tags  # noqa: F401
