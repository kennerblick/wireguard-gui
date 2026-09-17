"""'Client bereitstellen': Setup-Skript generieren (Schritt 1) und den
fertigen Peer auf dem Ziel-Server registrieren (Schritt 2).
"""

import ipaddress
import sqlite3

from flask import Response, flash, redirect, render_template, request, url_for

from .. import app, config, networks, provisioning, tags, wireguard
from ..db import get_db


def _parse_networks(raw: str):
    """Zerlegt ein Mehrzeilen-/Komma-getrenntes Textarea-Feld in validierte
    CIDRs. Gibt (gueltige_cidrs, ungueltige_rohtexte) zurueck."""
    lines = [part for chunk in raw.splitlines() for part in chunk.split(",")]
    valid, invalid = [], []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        cidr = networks.validate_network_cidr(line)
        if cidr is None:
            invalid.append(line)
        else:
            valid.append(cidr)
    return valid, invalid


@app.route("/provision")
def provision():
    db = get_db()
    kind = request.args.get("kind", "client").strip().lower()
    if kind not in ("server", "router", "client"):
        kind = "client"
    suggested_ip, ip_error = provisioning.suggest_free_ip(db, kind)
    return render_template("provision.html", suggested_ip=suggested_ip, ip_error=ip_error, kind=kind)


@app.route("/provision/script")
def provision_script():
    platform = request.args.get("platform", "linux").strip().lower()
    label = request.args.get("label", "").strip()
    ip_raw = request.args.get("ip", "").strip()

    if not config.LABEL_RE.match(label):
        flash("Ungueltiger Name (erlaubt: Buchstaben, Zahlen, Leerzeichen, . _ - ( )).", "error")
        return redirect(url_for("provision"))
    try:
        ip_obj = ipaddress.ip_address(ip_raw)
    except ValueError:
        flash(f"Ungueltige IP: {ip_raw!r}", "error")
        return redirect(url_for("provision"))

    info = wireguard.fetch_wg_interface_info()
    address = info.get("address")
    if not address:
        flash("Konnte Subnetz/Interface-Config des Ziels nicht lesen.", "error")
        return redirect(url_for("provision"))
    try:
        network = ipaddress.ip_interface(address).network
    except ValueError:
        flash(f"Ungueltige Address-Zeile in der Ziel-Config: {address!r}", "error")
        return redirect(url_for("provision"))

    ok, hub_pubkey = wireguard.run_on_target(f"wg show {config.TARGET_WG_INTERFACE} public-key")
    if not ok or not hub_pubkey.strip():
        flash(f"Konnte Public Key des Ziel-Servers nicht ermitteln: {hub_pubkey}", "error")
        return redirect(url_for("provision"))
    hub_pubkey = hub_pubkey.strip()

    hub_endpoint = config.WG_SERVER_ENDPOINT
    if ":" not in hub_endpoint:
        flash(
            "WG_SERVER_ENDPOINT ist nicht (korrekt, Format host:port) gesetzt - "
            "wird fuer die Client-Config benoetigt.",
            "error",
        )
        return redirect(url_for("provision"))

    syslog_host = str(ipaddress.ip_interface(address).ip)
    ip_str = str(ip_obj)
    network_cidr = str(network)
    managed_networks, invalid_networks = _parse_networks(request.args.get("networks", ""))
    if invalid_networks:
        flash(f"Ungueltige verwaltete Netze ignoriert: {', '.join(invalid_networks)}", "error")

    if platform == "linux":
        content = provisioning.render_linux_script(label, ip_str, hub_pubkey, hub_endpoint, network_cidr, syslog_host)
        filename = f"setup-wg-client-{label}.sh"
        mimetype = "text/x-shellscript"
    elif platform == "windows":
        content = provisioning.render_windows_script(label, ip_str, hub_pubkey, hub_endpoint, network_cidr)
        filename = f"setup-wg-client-{label}.ps1"
        mimetype = "text/plain"
    elif platform == "mikrotik":
        content = provisioning.render_mikrotik_script(
            label, ip_str, hub_pubkey, hub_endpoint, network_cidr, syslog_host,
            managed_networks=managed_networks,
        )
        filename = f"mikrotik-setup-{label}.rsc"
        mimetype = "text/plain"
    else:
        flash(f"Unbekannte Plattform: {platform!r}", "error")
        return redirect(url_for("provision"))

    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/clients/<int:client_id>/allowedips-script")
def client_allowedips_script(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("permissions"))
    if client["system"] not in ("windows", "linux"):
        flash(
            f"{client['label']}: Kein Update-Skript verfuegbar (System "
            f"{client['system'] or 'unbekannt'!r} - nur Windows/Linux unterstuetzt).",
            "error",
        )
        return redirect(url_for("permissions"))

    info = wireguard.fetch_wg_interface_info()
    address = info.get("address")
    mesh_cidr = None
    if address:
        try:
            mesh_cidr = str(ipaddress.ip_interface(address).network)
        except ValueError:
            mesh_cidr = None
    if not mesh_cidr:
        flash("Konnte Mesh-Subnetz des Ziel-Servers nicht ermitteln.", "error")
        return redirect(url_for("permissions"))

    managed_cidrs = sorted({row["cidr"] for row in networks.all_networks_with_client(db)})
    allowed_ips_csv = ",".join([mesh_cidr] + managed_cidrs)

    if client["system"] == "windows":
        content = provisioning.render_windows_allowedips_update(client["label"], allowed_ips_csv)
        filename = f"update-allowedips-{client['label']}.ps1"
        mimetype = "text/plain"
    else:
        content = provisioning.render_linux_allowedips_update(allowed_ips_csv)
        filename = f"update-allowedips-{client['label']}.sh"
        mimetype = "text/x-shellscript"

    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/provision/register", methods=["POST"])
def provision_register():
    db = get_db()
    label = request.form.get("label", "").strip()
    ip_raw = request.form.get("ip", "").strip()
    pubkey_raw = request.form.get("pubkey", "").strip()
    platform = request.form.get("platform", "").strip().lower()
    system = platform if platform in ("windows", "linux", "mikrotik") else None
    kind = request.form.get("kind", "client").strip().lower()
    if kind not in ("server", "router", "client"):
        kind = "client"

    if not config.LABEL_RE.match(label):
        flash("Ungueltiger Name (erlaubt: Buchstaben, Zahlen, Leerzeichen, . _ - ( )).", "error")
        return redirect(url_for("provision"))
    try:
        ip_obj = ipaddress.ip_address(ip_raw)
    except ValueError:
        flash(f"Ungueltige IP: {ip_raw!r}", "error")
        return redirect(url_for("provision"))
    pubkey = provisioning.validate_wg_pubkey(pubkey_raw)
    if pubkey is None:
        flash("Ungueltiger Public Key (muss ein Base64-kodierter 32-Byte-Wert sein).", "error")
        return redirect(url_for("provision"))
    managed_networks, invalid_networks = _parse_networks(request.form.get("networks", ""))
    if invalid_networks:
        flash(f"Ungueltige verwaltete Netze ignoriert: {', '.join(invalid_networks)}", "error")
    if managed_networks and kind != "router":
        # Verwaltete Netze machen nur bei einem Router Sinn - unabhaengig vom
        # gewaehlten Typ automatisch hochstufen, statt einen Client mit einem
        # verwaisten Netz anzulegen (genau die Art von falscher Zuordnung,
        # die die Typ-Unterscheidung eigentlich verhindern soll).
        kind = "router"

    ok, out = provisioning.register_peer_on_target(pubkey, str(ip_obj), label, extra_networks=managed_networks)
    if not ok:
        flash(f"Peer-Registrierung auf dem Server fehlgeschlagen: {out}", "error")
        return redirect(url_for("provision"))

    try:
        db.execute(
            "INSERT INTO clients (wg_ip, label, restricted, kind, system) VALUES (?, ?, 1, ?, ?)",
            (str(ip_obj), label, kind, system),
        )
        db.commit()
        client_id = db.execute("SELECT id FROM clients WHERE wg_ip = ?", (str(ip_obj),)).fetchone()["id"]

        # Automatisches Gruppen-Tag passend zur gewaehlten Plattform - reduziert
        # manuelle Schritte (Punkt "minimiere die manuell notwendigen Schritte"),
        # frei im Nachhinein unter "Gruppen" aenderbar/entfernbar.
        tag_name = config.PROVISION_PLATFORM_TAGS.get(platform)
        if tag_name:
            tag_id = tags.get_or_create_tag(db, tag_name)
            tags.set_client_tags(db, client_id, {tag_id})

        if managed_networks:
            networks.set_client_networks(db, client_id, managed_networks)

        flash(
            f"Peer {label} ({ip_obj}) auf dem Server registriert und als eingeschraenkter "
            f"Client ohne Regeln angelegt"
            + (f" (Gruppe {tag_name!r} zugewiesen)" if tag_name else "")
            + (f", verwaltet Netz(e) {', '.join(managed_networks)}" if managed_networks else "")
            + ". Zugriffsrechte unter 'Berechtigungen' ergaenzen.",
            "success",
        )
    except sqlite3.IntegrityError:
        flash(
            f"Peer {label} ({ip_obj}) auf dem Server registriert. Ein Client mit dieser IP "
            f"existierte in der App bereits - Datensatz nicht veraendert.",
            "success",
        )
    return redirect(url_for("provision"))
