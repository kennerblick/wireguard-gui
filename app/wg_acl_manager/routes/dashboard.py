"""Dashboard: reiner Status-Ueberblick (WireGuard-Peers, Firewall-Hook,
IP-Forwarding). Client- und Regel-Verwaltung liegt in routes/permissions.py,
Gruppen-Zuordnung in routes/tags.py."""

from flask import render_template

from .. import app, config, firewall, wireguard


@app.route("/")
def index():
    peers, wg_error = wireguard.fetch_wg_status()
    hook_chain = firewall.detect_hook_chain() if wg_error is None else None
    ip_forward = firewall.check_ip_forward() if wg_error is None else None

    if peers:
        pubkey_to_name, _ = wireguard.peer_lookup_maps()
        for p in peers:
            p["name"] = pubkey_to_name.get(p["pubkey"], "")

    return render_template(
        "index.html",
        peers=peers,
        wg_error=wg_error,
        hook_chain=hook_chain,
        ip_forward=ip_forward,
        wg_interface=config.TARGET_WG_INTERFACE,
    )
