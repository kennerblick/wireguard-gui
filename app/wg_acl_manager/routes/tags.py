"""Gruppen-Verwaltung ("Tags"): Katalog anlegen/loeschen + pro Client zuordnen."""

from flask import flash, redirect, render_template, request, url_for

from .. import app, tags as tags_module
from ..db import get_db


@app.route("/tags")
def tags():
    db = get_db()
    all_tags = tags_module.tags_with_member_counts(db)
    members_by_tag = {t["id"]: tags_module.tag_members(db, t["id"]) for t in all_tags}
    return render_template("tags.html", tags=all_tags, members_by_tag=members_by_tag)


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


@app.route("/clients/<int:client_id>/tags/set", methods=["POST"])
def set_client_tags(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("index"))
    tag_ids = set()
    for raw in request.form.getlist("tag_ids"):
        try:
            tag_ids.add(int(raw))
        except ValueError:
            continue
    tags_module.set_client_tags(db, client_id, tag_ids)
    flash(f"Gruppen fuer {client['label']} aktualisiert.", "success")
    return redirect(url_for("index"))
