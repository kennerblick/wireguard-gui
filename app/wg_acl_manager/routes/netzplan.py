"""Netzplan: grafische Uebersicht der ACLs + Schnellzugriff-Matrix fuer
"Alle Ports"-Freigaben zwischen Peers.
"""

import datetime
import json

from flask import flash, redirect, render_template, request, url_for

from .. import acl, app, firewall, wireguard
from ..db import get_db


@app.route("/netzplan")
def netzplan():
    db = get_db()
    nodes, edges = acl.build_netzplan_data(db)

    restricted_clients = db.execute(
        "SELECT * FROM clients WHERE restricted = 1 ORDER BY label"
    ).fetchall()
    all_clients = db.execute("SELECT * FROM clients ORDER BY label").fetchall()

    _, ip_to_name = wireguard.peer_lookup_maps()
    target_by_ip = {c["wg_ip"]: c["label"] for c in all_clients}
    for ip, name in ip_to_name.items():
        target_by_ip.setdefault(ip, name)
    all_targets = [{"ip": ip, "label": label} for ip, label in sorted(target_by_ip.items(), key=lambda kv: kv[1])]

    all_ports_service_id = acl.get_all_ports_service_id(db)
    client_targets = {}
    if all_ports_service_id is not None:
        for c in restricted_clients:
            rows = db.execute(
                "SELECT dest_ip FROM rules WHERE client_id = ? AND service_id = ? AND dest_tag_id IS NULL",
                (c["id"], all_ports_service_id),
            ).fetchall()
            client_targets[c["id"]] = [row["dest_ip"] for row in rows]

    return render_template(
        "netzplan.html",
        nodes=nodes,
        edges=edges,
        restricted_clients=restricted_clients,
        all_clients_json=json.dumps([
            {"id": c["id"], "label": c["label"], "wg_ip": c["wg_ip"]} for c in restricted_clients
        ]),
        all_targets_json=json.dumps(all_targets),
        client_targets_json=json.dumps(client_targets),
    )


@app.route("/netzplan/permissions/set", methods=["POST"])
def set_full_access_targets():
    db = get_db()
    client_id = int(request.form["client_id"])
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("netzplan"))
    if not client["restricted"]:
        flash(f"{client['label']} ist uneingeschraenkt - hat bereits Zugriff auf alles.", "error")
        return redirect(url_for("netzplan"))

    all_ports_service_id = acl.get_all_ports_service_id(db)
    if all_ports_service_id is None:
        flash("Dienst 'Alle Ports' nicht gefunden - Datenbank inkonsistent.", "error")
        return redirect(url_for("netzplan"))

    desired = set()
    for raw_ip in request.form.getlist("targets"):
        ip = raw_ip.strip()
        if not ip or ip == client["wg_ip"]:
            continue
        if firewall.validate_dest_ip(ip) is None:
            flash(f"Ungueltiges Ziel ignoriert: {ip!r}", "error")
            continue
        desired.add(ip)

    existing_rows = db.execute(
        "SELECT id, dest_ip FROM rules WHERE client_id = ? AND service_id = ? AND dest_tag_id IS NULL",
        (client_id, all_ports_service_id),
    ).fetchall()
    existing_by_ip = {row["dest_ip"]: row["id"] for row in existing_rows}

    added, removed = acl.diff_target_sets(set(existing_by_ip.keys()), desired)

    for ip in added:
        db.execute(
            "INSERT INTO rules (client_id, dest_ip, service_id, created_at) VALUES (?, ?, ?, ?)",
            (client_id, ip, all_ports_service_id, datetime.datetime.utcnow().isoformat()),
        )
    for ip in removed:
        db.execute("DELETE FROM rules WHERE id = ?", (existing_by_ip[ip],))
    if added or removed:
        db.commit()
        ok, out = acl.apply_client(db, client)
        if ok:
            flash(
                f"{client['label']}: {len(added)} Ziel(e) hinzugefuegt, {len(removed)} entfernt, angewendet.",
                "success",
            )
        else:
            flash(f"{client['label']}: Aenderungen gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    else:
        flash("Keine Aenderung.", "success")
    return redirect(url_for("netzplan"))
