"""Dashboard: reiner Status-Ueberblick (WireGuard-Peers, Firewall-Hook,
IP-Forwarding), gruppiert nach WG-Server/Router/Externe Server/Clients -
dieselbe Kategorisierung wie auf der Berechtigungen-Seite (clients.kind),
plus die verwalteten Netze direkt unter ihrem Router. Client- und
Regel-Verwaltung liegt in routes/permissions.py, Gruppen-Zuordnung in
routes/tags.py."""

from flask import render_template

from .. import acl, app, config, firewall, networks, wireguard
from ..db import get_db

GROUP_LABELS = [("router", "MikroTik-Router"), ("server", "Externe Server"), ("client", "Clients")]


@app.route("/")
def index():
    db = get_db()
    peers, wg_error = wireguard.fetch_wg_status()
    hook_chain = firewall.detect_hook_chain() if wg_error is None else None
    ip_forward = firewall.check_ip_forward() if wg_error is None else None

    clients = db.execute("SELECT * FROM clients ORDER BY label").fetchall()
    client_by_ip = {c["wg_ip"]: c for c in clients}
    client_networks = {c["id"]: networks.list_client_networks(db, c["id"]) for c in clients}

    # Fuer den "Berechtigungen"-Dialog je System (Klick auf eine Dashboard-
    # Zeile) - dieselben Daten, die auch die Berechtigungen-Seite fuer die
    # Karten braucht, siehe acl.build_rules_context().
    rules_ctx = acl.build_rules_context(db)

    groups = {"router": [], "server": [], "client": []}
    unmatched = []

    if peers:
        config_peers = wireguard.fetch_wg_peers_from_config()
        pubkey_to_name = {}
        pubkey_to_ownip = {}
        for cp in config_peers:
            if cp.get("name"):
                pubkey_to_name[cp["pubkey"]] = cp["name"]
            own_ip = wireguard.peer_own_ip(cp)
            if own_ip:
                pubkey_to_ownip[cp["pubkey"]] = own_ip

        for p in peers:
            p["name"] = pubkey_to_name.get(p["pubkey"], "")
            client = client_by_ip.get(pubkey_to_ownip.get(p["pubkey"]))
            if client:
                p["client"] = client
                groups[client["kind"]].append(p)
            else:
                unmatched.append(p)

    return render_template(
        "index.html",
        wg_error=wg_error,
        hook_chain=hook_chain,
        ip_forward=ip_forward,
        wg_interface=config.TARGET_WG_INTERFACE,
        wg_server_ip=config.WG_SERVER_TUNNEL_IP,
        group_labels=GROUP_LABELS,
        groups=groups,
        unmatched=unmatched,
        client_networks=client_networks,
        rules_by_client=rules_ctx["rules_by_client"],
        services_flat=rules_ctx["services_flat"],
        all_tags=rules_ctx["all_tags"],
        known_destinations=rules_ctx["known_destinations"],
        known_networks=rules_ctx["known_networks"],
    )
