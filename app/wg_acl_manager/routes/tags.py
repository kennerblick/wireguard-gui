"""Gruppen-Verwaltung ("Tags"): Katalog anlegen/loeschen, UND die
Zuordnung von Clients zu einer Gruppe - beides ausschliesslich hier, nicht
mehr verteilt auf Dashboard/Berechtigungen. Die Mitgliederliste einer
Gruppe wird direkt beim Anhaken/Abhaken uebernommen (kein Speichern-Button,
siehe tags.html)."""

from flask import flash, redirect, render_template, request, url_for

from .. import app, tags as tags_module
from ..db import get_db


@app.route("/tags")
def tags():
    db = get_db()
    all_tags = tags_module.tags_with_member_counts(db)
    all_clients = db.execute("SELECT id, label, wg_ip FROM clients ORDER BY label").fetchall()
    member_ids_by_tag = {t["id"]: tags_module.get_tag_member_ids(db, t["id"]) for t in all_tags}
    return render_template(
        "tags.html",
        tags=all_tags,
        all_clients=all_clients,
        member_ids_by_tag=member_ids_by_tag,
    )


@app.route("/tags/add", methods=["POST"])
def add_tag():
    db = get_db()
    name = request.form.get("name", "").strip()
    ok, error = tags_module.create_tag(db, name)
    if ok:
        flash(f"Gruppe {name!r} angelegt.", "success")
    else:
        flash(error, "error")
    return redirect(url_for("tags"))


@app.route("/tags/<int:tag_id>/delete", methods=["POST"])
def delete_tag(tag_id):
    db = get_db()
    tag = db.execute("SELECT * FROM tags WHERE id = ?", (tag_id,)).fetchone()
    if tag:
        tags_module.delete_tag(db, tag_id)
        flash(
            f"Gruppe {tag['name']!r} geloescht. Regeln, die auf diese Gruppe zielten, wurden mit entfernt - "
            f"betroffene Clients bei Bedarf erneut 'anwenden'.",
            "success",
        )
    return redirect(url_for("tags"))


@app.route("/tags/<int:tag_id>/members/set", methods=["POST"])
def set_tag_members(tag_id):
    db = get_db()
    tag = db.execute("SELECT * FROM tags WHERE id = ?", (tag_id,)).fetchone()
    if not tag:
        flash("Gruppe nicht gefunden.", "error")
        return redirect(url_for("tags"))
    client_ids = set()
    for raw in request.form.getlist("client_ids"):
        try:
            client_ids.add(int(raw))
        except ValueError:
            continue
    tags_module.set_tag_members(db, tag_id, client_ids)
    flash(f"Mitglieder von {tag['name']!r} aktualisiert.", "success")
    return redirect(url_for("tags"))
