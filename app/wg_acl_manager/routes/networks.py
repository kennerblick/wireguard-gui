"""Verwaltete Netze pro Client bearbeiten (Berechtigungen-Seite): LANs
hinter einem Peer (typischerweise MikroTik) hinterlegen/aendern."""

from flask import flash, redirect, request, url_for

from .. import app, networks, wireguard
from ..db import get_db


@app.route("/clients/<int:client_id>/networks/set", methods=["POST"])
def set_client_networks(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("permissions"))

    raw = request.form.get("networks", "")
    lines = [part for chunk in raw.splitlines() for part in chunk.split(",")]
    # Nur Router duerfen NEUE verwaltete Netze bekommen - Leeren (Cleanup
    # einer versehentlich falsch zugeordneten Zeile) bleibt fuer JEDEN Client
    # jederzeit moeglich, unabhaengig vom Typ.
    if any(part.strip() for part in lines) and client["kind"] != "router":
        flash(
            f"{client['label']} ist nicht als Router markiert - verwaltete Netze koennen nur "
            f"Routern zugeordnet werden. Erst den Typ auf 'Router' setzen.",
            "error",
        )
        return redirect(url_for("permissions"))
    errors = networks.set_client_networks(db, client_id, lines)
    if errors:
        flash(f"Ungueltige Netze ignoriert: {', '.join(errors)}", "error")

    current_networks = [row["cidr"] for row in networks.list_client_networks(db, client_id)]
    peers = wireguard.fetch_wg_peers_from_config()
    peer = next((p for p in peers if wireguard.peer_own_ip(p) == client["wg_ip"]), None)
    if peer is None:
        flash(
            f"{client['label']}: Netze gespeichert, aber Peer nicht in der Ziel-Config gefunden - "
            f"AllowedIPs auf dem Server wurden NICHT aktualisiert. Bitte manuell pruefen.",
            "error",
        )
        return redirect(url_for("permissions"))

    allowed_ips = ",".join([f"{client['wg_ip']}/32", *current_networks])
    ok, out = wireguard.set_peer_allowed_ips(peer["pubkey"], allowed_ips)
    if ok:
        flash(f"{client['label']}: verwaltete Netze gespeichert und AllowedIPs auf dem Server aktualisiert.", "success")
    else:
        flash(f"{client['label']}: Netze gespeichert, aber AllowedIPs-Update auf dem Server fehlgeschlagen: {out}", "error")
    return redirect(url_for("permissions"))
