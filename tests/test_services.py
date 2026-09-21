import sqlite3

import pytest

from wg_acl_manager import config, db


@pytest.fixture
def conn(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    yield connection
    connection.close()


def test_fresh_db_seeds_veeam_builtin_services(conn):
    vbr = conn.execute("SELECT * FROM services WHERE name = 'Veeam VBR'").fetchone()
    assert vbr["protocol"] == "tcp"
    assert vbr["port"] == 10006
    assert vbr["is_builtin"] == 1

    data_mover = conn.execute("SELECT * FROM services WHERE name = 'Veeam Data Mover'").fetchone()
    assert data_mover["protocol"] == "tcp"
    assert data_mover["port"] == "2500-3300"
    assert data_mover["is_builtin"] == 1


def test_migration_backfills_veeam_into_existing_db_without_touching_other_rows(conn):
    # Simuliert eine DB von vor der Veeam-Erweiterung: Zeilen entfernen, wie
    # sie ein Deployment haette, das init_db() nur einmal vor dem Update
    # durchlaufen hat.
    conn.execute("DELETE FROM services WHERE name LIKE 'Veeam%'")
    conn.execute("INSERT INTO services (name, protocol, port, is_builtin) VALUES ('Grafana', 'tcp', 3000, 0)")
    conn.commit()

    db.run_migrations(conn)
    conn.commit()

    assert conn.execute("SELECT id FROM services WHERE name = 'Veeam VBR'").fetchone() is not None
    assert conn.execute("SELECT id FROM services WHERE name = 'Veeam Data Mover'").fetchone() is not None
    # Bestehender eigener Dienst bleibt unangetastet (weiterhin is_builtin=0).
    grafana = conn.execute("SELECT * FROM services WHERE name = 'Grafana'").fetchone()
    assert grafana["is_builtin"] == 0
    assert grafana["port"] == 3000
    # Kein Duplikat der unveraenderten Standarddienste.
    assert conn.execute("SELECT COUNT(*) c FROM services WHERE name = 'SSH'").fetchone()["c"] == 1
