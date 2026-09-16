"""Netzplan: rein grafische Uebersicht der ACLs (inkl. WG-Server-Knoten und
gruppierter Gruppen-Knoten). Berechtigungsverwaltung liegt in
routes/permissions.py - hier wird nur noch dargestellt, nichts geaendert."""

from flask import render_template

from .. import acl, app
from ..db import get_db


@app.route("/netzplan")
def netzplan():
    db = get_db()
    nodes, edges = acl.build_netzplan_data(db)
    return render_template("netzplan.html", nodes=nodes, edges=edges)
