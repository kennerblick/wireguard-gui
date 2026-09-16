"""Berechtigungen: Clients anlegen/importieren/entfernen und ihre Firewall-
Regeln pflegen - alles, was frueher Teil des Dashboards war, plus die
Schnellzugriff-Matrix fuer "volle Freigabe", frueher Teil des Netzplans.
Reine Gruppen-Zuordnung (welcher Client traegt welches Tag) liegt in
routes/tags.py - hier wird eine Gruppe nur noch als Regel-Ziel ausgewaehlt.
"""

import datetime
import ipaddress
import json
import sqlite3

from flask import flash, redirect, render_template, request, url_for

from .. import acl, app, config, firewall, networks, tags, wireguard
from ..db import get_db


@app.route("/permissions")
def permissions():
    db = get_db()
    clients = db.execute("SELECT * FROM clients ORDER BY wg_ip").fetchall()
    rules = db.execute(
        """
        SELECT r.id, r.client_id, r.dest_ip, r.dest_tag_id, t.name AS tag_name,
               s.name AS service_name, s.protocol, s.port
        FROM rules r
        JOIN services s ON r.service_id = s.id
        LEFT JOIN tags t ON t.id = r.dest_tag_id
        ORDER BY r.dest_ip
        """
    ).fetchall()
    rules_by_client = {}
    for r in rules:
        rules_by_client.setdefault(r["client_id"], []).append(r)

    services_flat = db.execute("SELECT * FROM services ORDER BY is_builtin DESC, name").fetchall()

    ip_labels = acl.build_ip_label_map(db)
    known_destinations = sorted(ip_labels.items(), key=lambda kv: kv[1])
    known_networks = [
        (row["cidr"], f"LAN hinter {row['client_label']}")
        for row in networks.all_networks_with_client(db)
    ]

    all_tags = tags.list_tags(db)
    client_tag_ids = {c["id"]: tags.get_client_tag_ids(db, c["id"]) for c in clients}
    client_tag_names = {
        c["id"]: sorted(t["name"] for t in all_tags if t["id"] in client_tag_ids[c["id"]])
        for c in clients
    }
    client_networks = {c["id"]: networks.list_client_networks(db, c["id"]) for c in clients}

    restricted_clients = [c for c in clients if c["restricted"]]
    _, ip_to_name = wireguard.peer_lookup_maps()
    target_by_ip = {c["wg_ip"]: c["label"] for c in clients}
    for ip, name in ip_to_name.items():
        target_by_ip.setdefault(ip, name)
    all_targets = [{"ip": ip, "label": label} for ip, label in sorted(target_by_ip.items(), key=lambda kv: kv[1])]

    all_ports_service_id = acl.get_all_ports_service_id(db)
    full_access_targets = {}
    if all_ports_service_id is not None:
        for c in restricted_clients:
            rows = db.execute(
                "SELECT dest_ip FROM rules WHERE client_id = ? AND service_id = ? AND dest_tag_id IS NULL",
                (c["id"], all_ports_service_id),
            ).fetchall()
            full_access_targets[c["id"]] = [row["dest_ip"] for row in rows]

    return render_template(
        "permissions.html",
        clients=clients,
        rules_by_client=rules_by_client,
        services_flat=services_flat,
        wg_interface=config.TARGET_WG_INTERFACE,
        known_destinations=known_destinations,
        known_networks=known_networks,
        all_tags=all_tags,
        client_tag_names=client_tag_names,
        client_networks=client_networks,
        restricted_clients=restricted_clients,
        all_clients_json=json.dumps([
            {"id": c["id"], "label": c["label"], "wg_ip": c["wg_ip"]} for c in restricted_clients
        ]),
        all_targets_json=json.dumps(all_targets),
        full_access_targets_json=json.dumps(full_access_targets),
    )


@app.route("/clients/import", methods=["POST"])
def import_peers():
    db = get_db()
    imported, skipped, ambiguous = acl.import_peers_from_config(db)
    if imported:
        flash(
            f"{imported} Peer(s) aus der WireGuard-Config importiert (eingeschraenkt, ohne Regeln - "
            f"wie beim manuellen Hinzufuegen). Zugriffsrechte bitte anhand der tatsaechlichen Firewall-Regeln "
            f"('Wartung' -> 'Firewall-Regeln') nachtragen, bevor du 'Anwenden' klickst. "
            f"{skipped} bereits vorhanden.",
            "success",
        )
    else:
        flash(f"Keine neuen Peers gefunden ({skipped} bereits vorhanden, oder Config nicht lesbar).", "success")
    if ambiguous:
        flash(
            f"{len(ambiguous)} Peer(s) NICHT importiert, da ihre eigene Tunnel-IP nicht sicher "
            f"ermittelbar ist (AllowedIPs deckt ein ganzes Subnetz ab, z.B. ein Admin-Rechner mit "
            f"Zugriff auf alle Peers): {', '.join(ambiguous)}. Bitte im [Peer]-Block dieser Clients auf "
            f"dem Zielserver eine zweite Kommentarzeile '#IP: x.x.x.x' mit der tatsaechlichen eigenen "
            f"IP ergaenzen und danach erneut importieren.",
            "error",
        )
    return redirect(url_for("permissions"))


@app.route("/clients/add", methods=["POST"])
def add_client():
    db = get_db()
    wg_ip_raw = request.form["wg_ip"].strip()
    label = request.form["label"].strip()
    restricted = 1 if request.form.get("restricted") == "on" else 0
    try:
        wg_ip = str(ipaddress.ip_address(wg_ip_raw))
    except ValueError:
        flash(f"Ungueltige Tunnel-IP: {wg_ip_raw!r}", "error")
        return redirect(url_for("permissions"))
    try:
        db.execute(
            "INSERT INTO clients (wg_ip, label, restricted) VALUES (?, ?, ?)",
            (wg_ip, label, restricted),
        )
        db.commit()
        flash(f"Client {label} ({wg_ip}) hinzugefuegt.", "success")
    except sqlite3.IntegrityError:
        flash(f"Ein Client mit IP {wg_ip} existiert bereits.", "error")
    return redirect(url_for("permissions"))


@app.route("/clients/<int:client_id>/toggle", methods=["POST"])
def toggle_client(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("permissions"))
    new_val = 0 if client["restricted"] else 1
    db.execute("UPDATE clients SET restricted = ? WHERE id = ?", (new_val, client_id))
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = acl.apply_client(db, client)
    if ok:
        flash(f"{client['label']}: Einschraenkung {'aktiviert' if new_val else 'deaktiviert'} und angewendet.", "success")
    else:
        flash(f"{client['label']}: Aenderung gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("permissions"))


@app.route("/clients/<int:client_id>/wg_ip/set", methods=["POST"])
def set_client_wg_ip(client_id):
    """Korrigiert die gespeicherte Tunnel-IP eines Clients nachtraeglich -
    z.B. wenn "Peers importieren" vor der Ambiguitaets-Erkennung (siehe
    wireguard.peer_own_ip()) faelschlich eine Netzwerk-Adresse statt der
    echten Peer-IP uebernommen hatte. Baut die Firewall-Chain unter der
    alten IP zurueck und unter der neuen frisch auf - ein reines Update der
    DB-Spalte wuerde eine verwaiste Chain unter der alten (falschen) IP
    zuruecklassen, die nie zum tatsaechlichen Traffic passt."""
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("permissions"))

    raw = request.form.get("wg_ip", "").strip()
    try:
        new_ip = str(ipaddress.ip_address(raw))
    except ValueError:
        flash(f"Ungueltige Tunnel-IP: {raw!r}", "error")
        return redirect(url_for("permissions"))

    old_ip = client["wg_ip"]
    if new_ip == old_ip:
        flash("Keine Aenderung.", "success")
        return redirect(url_for("permissions"))

    hook_chain = firewall.detect_hook_chain()
    wireguard.run_on_target(firewall.build_remove_script(old_ip, hook_chain))
    try:
        db.execute("UPDATE clients SET wg_ip = ? WHERE id = ?", (new_ip, client_id))
        db.commit()
    except sqlite3.IntegrityError:
        flash(f"Ein Client mit IP {new_ip} existiert bereits.", "error")
        return redirect(url_for("permissions"))

    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = acl.apply_client(db, client)
    if ok:
        flash(f"{client['label']}: Tunnel-IP von {old_ip} auf {new_ip} geaendert und angewendet.", "success")
    else:
        flash(f"{client['label']}: IP geaendert, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("permissions"))


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
def delete_client(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client:
        hook_chain = firewall.detect_hook_chain()
        wireguard.run_on_target(firewall.build_remove_script(client["wg_ip"], hook_chain))
        db.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        db.commit()
        flash(f"Client {client['label']} entfernt, Firewall-Regeln zurueckgebaut.", "success")
    return redirect(url_for("permissions"))


@app.route("/rules/add", methods=["POST"])
def add_rule():
    db = get_db()
    client_id = int(request.form["client_id"])
    service_id = int(request.form["service_id"])
    dest_tag_raw = request.form.get("dest_tag_id", "").strip()

    if dest_tag_raw:
        try:
            dest_tag_id = int(dest_tag_raw)
        except ValueError:
            flash("Ungueltige Gruppe.", "error")
            return redirect(url_for("permissions"))
        dest_ip = ""  # Sentinel: Ziel ist eine Gruppe, siehe db.run_migrations()
    else:
        dest_ip_raw = request.form.get("dest_ip", "").strip()
        dest_ip = firewall.validate_dest_ip(dest_ip_raw)
        if dest_ip is None:
            flash(f"Ungueltige Ziel-IP/CIDR: {dest_ip_raw!r}", "error")
            return redirect(url_for("permissions"))
        dest_tag_id = None

    db.execute(
        "INSERT INTO rules (client_id, dest_ip, dest_tag_id, service_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (client_id, dest_ip, dest_tag_id, service_id, datetime.datetime.utcnow().isoformat()),
    )
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = acl.apply_client(db, client)
    if ok:
        flash("Regel hinzugefuegt und angewendet.", "success")
    else:
        flash(f"Regel gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("permissions"))


@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
def delete_rule(rule_id):
    db = get_db()
    rule = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if not rule:
        return redirect(url_for("permissions"))
    client_id = rule["client_id"]
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = acl.apply_client(db, client)
    if ok:
        flash("Regel entfernt und angewendet.", "success")
    else:
        flash(f"Regel entfernt, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("permissions"))


@app.route("/apply/<int:client_id>", methods=["POST"])
def apply_single(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("permissions"))
    ok, out = acl.apply_client(db, client)
    flash(f"{client['label']}: {'erfolgreich angewendet' if ok else 'Fehler: ' + out}",
          "success" if ok else "error")
    return redirect(url_for("permissions"))


@app.route("/apply_all", methods=["POST"])
def apply_all():
    db = get_db()
    clients = db.execute("SELECT * FROM clients").fetchall()
    errors = []
    for client in clients:
        ok, out = acl.apply_client(db, client)
        if not ok:
            errors.append(f"{client['label']}: {out}")
    if errors:
        flash("Fehler bei: " + "; ".join(errors), "error")
    else:
        flash(f"Alle {len(clients)} Clients erfolgreich angewendet.", "success")
    return redirect(url_for("permissions"))


@app.route("/permissions/full-access/set", methods=["POST"])
def set_full_access_targets():
    db = get_db()
    client_id = int(request.form["client_id"])
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("permissions"))
    if not client["restricted"]:
        flash(f"{client['label']} ist uneingeschraenkt - hat bereits Zugriff auf alles.", "error")
        return redirect(url_for("permissions"))

    all_ports_service_id = acl.get_all_ports_service_id(db)
    if all_ports_service_id is None:
        flash("Dienst 'Alle Ports' nicht gefunden - Datenbank inkonsistent.", "error")
        return redirect(url_for("permissions"))

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
    return redirect(url_for("permissions"))
