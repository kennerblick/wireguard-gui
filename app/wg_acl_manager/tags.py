"""Tags: freie Gruppierung von Clients (z.B. "mikrotik", "server"), Ziel
fuer Gruppen-ACL-Regeln ("erlaube Zugriff auf alle MikroTiks"). Ein Client
kann mehrere Tags tragen, ein Tag kann von mehreren Regeln referenziert
werden.
"""

import sqlite3

from . import config


def list_tags(db):
    return db.execute("SELECT * FROM tags ORDER BY name").fetchall()


def get_or_create_tag(db, name: str) -> int:
    """Gibt die id des Tags zurueck, legt es bei Bedarf an."""
    row = db.execute("SELECT id FROM tags WHERE name = ?", (name,)).fetchone()
    if row:
        return row["id"]
    cur = db.execute("INSERT INTO tags (name) VALUES (?)", (name,))
    db.commit()
    return cur.lastrowid


def create_tag(db, name: str):
    """Legt ein neues Tag an. Gibt (ok, fehlertext_oder_None) zurueck."""
    name = name.strip()
    if not config.TAG_NAME_RE.match(name):
        return False, "Ungueltiger Name (erlaubt: Buchstaben, Zahlen, Leerzeichen, . _ - ( ))."
    try:
        db.execute("INSERT INTO tags (name) VALUES (?)", (name,))
        db.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, f"Ein Tag namens {name!r} existiert bereits."


def delete_tag(db, tag_id: int):
    """Loescht ein Tag. Regeln, die auf dieses Tag zeigten, werden dank
    ON DELETE CASCADE mit entfernt (siehe rules.dest_tag_id-Definition) -
    betroffene Clients muessen danach erneut "angewendet" werden, damit die
    Firewall das nachvollzieht."""
    db.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
    db.commit()


def get_client_tag_ids(db, client_id: int) -> set:
    rows = db.execute("SELECT tag_id FROM client_tags WHERE client_id = ?", (client_id,)).fetchall()
    return {row["tag_id"] for row in rows}


def set_client_tags(db, client_id: int, tag_ids: set):
    """Ersetzt die komplette Tag-Zuordnung eines Clients durch tag_ids."""
    db.execute("DELETE FROM client_tags WHERE client_id = ?", (client_id,))
    for tag_id in tag_ids:
        db.execute(
            "INSERT OR IGNORE INTO client_tags (client_id, tag_id) VALUES (?, ?)",
            (client_id, tag_id),
        )
    db.commit()


def tag_member_ips(db, tag_id: int, exclude_client_id=None):
    """Tunnel-IPs aller Clients mit diesem Tag (ohne den angegebenen Client)."""
    query = """
        SELECT c.wg_ip FROM clients c
        JOIN client_tags ct ON ct.client_id = c.id
        WHERE ct.tag_id = ?
    """
    params = [tag_id]
    if exclude_client_id is not None:
        query += " AND c.id != ?"
        params.append(exclude_client_id)
    return [row["wg_ip"] for row in db.execute(query, params).fetchall()]


def tags_with_member_counts(db):
    """Alle Tags mit Anzahl zugeordneter Clients, fuer die Uebersichtsseite."""
    return db.execute(
        """
        SELECT t.id, t.name, COUNT(ct.client_id) AS member_count
        FROM tags t
        LEFT JOIN client_tags ct ON ct.tag_id = t.id
        GROUP BY t.id
        ORDER BY t.name
        """
    ).fetchall()


def tag_members(db, tag_id: int):
    """Client-Zeilen (id, label, wg_ip), die dieses Tag tragen."""
    return db.execute(
        """
        SELECT c.id, c.label, c.wg_ip
        FROM clients c
        JOIN client_tags ct ON ct.client_id = c.id
        WHERE ct.tag_id = ?
        ORDER BY c.label
        """,
        (tag_id,),
    ).fetchall()
