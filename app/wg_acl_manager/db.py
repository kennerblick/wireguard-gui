"""SQLite-Datenzugriff: eine Verbindung pro Request (Flask `g`), Schema und
additive Migrationen fuer bereits bestehende Datenbanken.
"""

import os
import sqlite3

from flask import g

from . import app, config

_db_ready = False


def get_db():
    """Liefert die Request-lokale DB-Verbindung; initialisiert das Schema
    beim allerersten Zugriff (lazy statt beim Modul-Import - so hat auch ein
    Test-Import dieses Moduls keinen Seiteneffekt auf das Dateisystem)."""
    global _db_ready
    if not _db_ready:
        init_db()
        _db_ready = True
    if "db" not in g:
        g.db = sqlite3.connect(config.DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    db = sqlite3.connect(config.DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wg_ip TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL,
            restricted INTEGER NOT NULL DEFAULT 1,
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER,
            is_builtin INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS client_tags (
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (client_id, tag_id)
        );

        CREATE TABLE IF NOT EXISTS client_networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            cidr TEXT NOT NULL,
            UNIQUE(client_id, cidr)
        );

        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            dest_ip TEXT NOT NULL,
            dest_tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
            service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS apply_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL,
            output TEXT
        );
        """
    )
    run_migrations(db)
    cur = db.execute("SELECT COUNT(*) FROM services")
    if cur.fetchone()[0] == 0:
        for name, proto, port in config.BUILTIN_SERVICES:
            db.execute(
                "INSERT INTO services (name, protocol, port, is_builtin) VALUES (?, ?, ?, 1)",
                (name, proto, port),
            )
    db.commit()
    db.close()


def run_migrations(db):
    """Additive Schema-Aenderungen fuer bereits bestehende Datenbanken.

    Fuer eine neu angelegte DB deckt bereits das CREATE TABLE oben alle
    Spalten ab - hier wird nur nachgezogen, was eine schon existierende DB
    (aelterer Stand) noch nicht hat. Jede Migration prueft vorher, ob sie
    noetig ist, und ist damit gefahrlos wiederholt ausfuehrbar.

    Gruppen-Regeln (rules.dest_tag_id) speichern in dest_ip den Sentinel-
    Wert "" statt NULL - das erspart eine riskante Aenderung der
    bestehenden "dest_ip TEXT NOT NULL"-Constraint (SQLite kann eine
    Spalten-Constraint nicht per ALTER TABLE lockern, nur per kompletter
    Tabellen-Neuerstellung). Anwendungscode behandelt dest_ip == "" und
    dest_tag_id IS NOT NULL einheitlich als "Ziel ist eine Gruppe" (siehe
    acl.resolve_rule_targets()).
    """
    existing_columns = {row["name"] for row in db.execute("PRAGMA table_info(rules)").fetchall()}
    if "dest_tag_id" not in existing_columns:
        db.execute("ALTER TABLE rules ADD COLUMN dest_tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE")
