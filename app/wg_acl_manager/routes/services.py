"""Dienste-Katalog (Protokoll/Port-Kombinationen, die eine ACL-Regel erlauben kann)."""

import sqlite3

from flask import flash, redirect, render_template, request, url_for

from .. import app, config
from ..db import get_db


@app.route("/services")
def services():
    db = get_db()
    all_services = db.execute("SELECT * FROM services ORDER BY is_builtin DESC, name").fetchall()
    return render_template("services.html", services=all_services)


@app.route("/services/add", methods=["POST"])
def add_service():
    db = get_db()
    name = request.form["name"].strip()
    protocol = request.form["protocol"].strip().lower()
    port_raw = request.form.get("port", "").strip()

    if not config.SERVICE_NAME_RE.match(name):
        flash("Ungueltiger Dienstname (erlaubt: Buchstaben, Zahlen, Leerzeichen, . _ - ( )).", "error")
        return redirect(url_for("services"))
    if protocol not in config.VALID_PROTOCOLS:
        flash(f"Ungueltiges Protokoll: {protocol!r}", "error")
        return redirect(url_for("services"))

    port = None
    if port_raw:
        m = config.SERVICE_PORT_RE.match(port_raw)
        if not m:
            flash("Port muss eine Zahl (1-65535) oder ein Bereich wie 2500-3300 sein.", "error")
            return redirect(url_for("services"))
        start, end = int(m.group(1)), int(m.group(2)) if m.group(2) else None
        if end is None:
            if not (1 <= start <= 65535):
                flash("Port muss eine Zahl zwischen 1 und 65535 sein.", "error")
                return redirect(url_for("services"))
            port = start
        else:
            if not (1 <= start < end <= 65535):
                flash("Portbereich muss innerhalb 1-65535 liegen, mit Start kleiner als Ende.", "error")
                return redirect(url_for("services"))
            port = f"{start}-{end}"
    if protocol == "all":
        port = None

    try:
        db.execute(
            "INSERT INTO services (name, protocol, port, is_builtin) VALUES (?, ?, ?, 0)",
            (name, protocol, port),
        )
        db.commit()
        flash(f"Dienst {name} hinzugefuegt.", "success")
    except sqlite3.IntegrityError:
        flash(f"Ein Dienst namens {name} existiert bereits.", "error")
    return redirect(url_for("services"))


@app.route("/services/<int:service_id>/delete", methods=["POST"])
def delete_service(service_id):
    db = get_db()
    service = db.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if service and service["is_builtin"]:
        flash("Standarddienste koennen nicht geloescht werden.", "error")
    elif service:
        in_use = db.execute("SELECT COUNT(*) c FROM rules WHERE service_id = ?", (service_id,)).fetchone()["c"]
        if in_use:
            flash(f"Dienst wird noch in {in_use} Regel(n) verwendet - erst dort entfernen.", "error")
        else:
            db.execute("DELETE FROM services WHERE id = ?", (service_id,))
            db.commit()
            flash("Dienst geloescht.", "success")
    return redirect(url_for("services"))
