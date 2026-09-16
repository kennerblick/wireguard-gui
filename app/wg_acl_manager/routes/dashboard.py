"""Dashboard: Status-Uebersicht, Clients- und Regel-Verwaltung."""

import datetime
import sqlite3

from flask import flash, redirect, render_template, request, url_for

from .. import acl, app, config, firewall, networks, tags, wireguard
from ..db import get_db


@app.route("/")
def index():
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

    peers, wg_error = wireguard.fetch_wg_status()
    services_flat = db.execute("SELECT * FROM services ORDER BY is_builtin DESC, name").fetchall()
    hook_chain = firewall.detect_hook_chain() if wg_error is None else None
    ip_forward = firewall.check_ip_forward() if wg_error is None else None

    if peers:
        pubkey_to_name, _ = wireguard.peer_lookup_maps()
        for p in peers:
            p["name"] = pubkey_to_name.get(p["pubkey"], "")

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

    return render_template(
        "index.html",
        clients=clients,
        rules_by_client=rules_by_client,
        peers=peers,
        wg_error=wg_error,
        services_flat=services_flat,
        hook_chain=hook_chain,
        ip_forward=ip_forward,
        wg_interface=config.TARGET_WG_INTERFACE,
        known_destinations=known_destinations,
        known_networks=known_networks,
        all_tags=all_tags,
        client_tag_ids=client_tag_ids,
        client_tag_names=client_tag_names,
        client_networks=client_networks,
    )


@app.route("/clients/import", methods=["POST"])
def import_peers():
    db = get_db()
    imported, skipped = acl.import_peers_from_config(db)
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
    return redirect(url_for("index"))


@app.route("/clients/add", methods=["POST"])
def add_client():
    db = get_db()
    wg_ip = request.form["wg_ip"].strip()
    label = request.form["label"].strip()
    restricted = 1 if request.form.get("restricted") == "on" else 0
    try:
        db.execute(
            "INSERT INTO clients (wg_ip, label, restricted) VALUES (?, ?, ?)",
            (wg_ip, label, restricted),
        )
        db.commit()
        flash(f"Client {label} ({wg_ip}) hinzugefuegt.", "success")
    except sqlite3.IntegrityError:
        flash(f"Ein Client mit IP {wg_ip} existiert bereits.", "error")
    return redirect(url_for("index"))


@app.route("/clients/<int:client_id>/toggle", methods=["POST"])
def toggle_client(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("index"))
    new_val = 0 if client["restricted"] else 1
    db.execute("UPDATE clients SET restricted = ? WHERE id = ?", (new_val, client_id))
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = acl.apply_client(db, client)
    if ok:
        flash(f"{client['label']}: Einschraenkung {'aktiviert' if new_val else 'deaktiviert'} und angewendet.", "success")
    else:
        flash(f"{client['label']}: Aenderung gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("index"))


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
    return redirect(url_for("index"))


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
            return redirect(url_for("index"))
        dest_ip = ""  # Sentinel: Ziel ist eine Gruppe, siehe db.run_migrations()
    else:
        dest_ip_raw = request.form.get("dest_ip", "").strip()
        dest_ip = firewall.validate_dest_ip(dest_ip_raw)
        if dest_ip is None:
            flash(f"Ungueltige Ziel-IP/CIDR: {dest_ip_raw!r}", "error")
            return redirect(url_for("index"))
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
    return redirect(url_for("index"))


@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
def delete_rule(rule_id):
    db = get_db()
    rule = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if not rule:
        return redirect(url_for("index"))
    client_id = rule["client_id"]
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = acl.apply_client(db, client)
    if ok:
        flash("Regel entfernt und angewendet.", "success")
    else:
        flash(f"Regel entfernt, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("index"))


@app.route("/apply/<int:client_id>", methods=["POST"])
def apply_single(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("index"))
    ok, out = acl.apply_client(db, client)
    flash(f"{client['label']}: {'erfolgreich angewendet' if ok else 'Fehler: ' + out}",
          "success" if ok else "error")
    return redirect(url_for("index"))


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
    return redirect(url_for("index"))
