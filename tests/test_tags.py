import sqlite3

import pytest

from wg_acl_manager import acl, config, db, tags


@pytest.fixture
def conn(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    yield connection
    connection.close()


def add_client(conn, wg_ip, label, restricted=1):
    conn.execute(
        "INSERT INTO clients (wg_ip, label, restricted) VALUES (?, ?, ?)",
        (wg_ip, label, restricted),
    )
    conn.commit()
    return conn.execute("SELECT id FROM clients WHERE wg_ip = ?", (wg_ip,)).fetchone()["id"]


def get_service_id(conn, name):
    return conn.execute("SELECT id FROM services WHERE name = ?", (name,)).fetchone()["id"]


def test_create_tag_validates_name(conn):
    ok, err = tags.create_tag(conn, "mikrotik")
    assert ok is True
    assert err is None

    ok, err = tags.create_tag(conn, "$$invalid$$")
    assert ok is False
    assert "Buchstaben" in err


def test_create_tag_rejects_duplicate(conn):
    tags.create_tag(conn, "server")
    ok, err = tags.create_tag(conn, "server")
    assert ok is False
    assert "existiert bereits" in err


def test_get_or_create_tag_is_idempotent(conn):
    id1 = tags.get_or_create_tag(conn, "linux")
    id2 = tags.get_or_create_tag(conn, "linux")
    assert id1 == id2
    assert len(tags.list_tags(conn)) == 1


def test_set_and_get_client_tags(conn):
    client_id = add_client(conn, "10.250.0.11", "RouterA")
    tag_a = tags.get_or_create_tag(conn, "mikrotik")
    tag_b = tags.get_or_create_tag(conn, "branch-office")

    tags.set_client_tags(conn, client_id, {tag_a, tag_b})
    assert tags.get_client_tag_ids(conn, client_id) == {tag_a, tag_b}

    # Erneutes Setzen ersetzt komplett, statt zu addieren.
    tags.set_client_tags(conn, client_id, {tag_a})
    assert tags.get_client_tag_ids(conn, client_id) == {tag_a}


def test_tag_member_ips_excludes_given_client(conn):
    tag_id = tags.get_or_create_tag(conn, "mikrotik")
    router_a = add_client(conn, "10.250.0.11", "RouterA")
    router_b = add_client(conn, "10.250.0.12", "RouterB")
    tags.set_client_tags(conn, router_a, {tag_id})
    tags.set_client_tags(conn, router_b, {tag_id})

    assert set(tags.tag_member_ips(conn, tag_id)) == {"10.250.0.11", "10.250.0.12"}
    assert tags.tag_member_ips(conn, tag_id, exclude_client_id=router_a) == ["10.250.0.12"]


def test_tags_with_member_counts(conn):
    tag_id = tags.get_or_create_tag(conn, "mikrotik")
    empty_tag_id = tags.get_or_create_tag(conn, "unused")
    router_a = add_client(conn, "10.250.0.11", "RouterA")
    tags.set_client_tags(conn, router_a, {tag_id})

    counts = {row["id"]: row["member_count"] for row in tags.tags_with_member_counts(conn)}
    assert counts[tag_id] == 1
    assert counts[empty_tag_id] == 0


def test_delete_tag_cascades_to_client_tags_and_rules(conn):
    tag_id = tags.get_or_create_tag(conn, "mikrotik")
    router_a = add_client(conn, "10.250.0.11", "RouterA")
    tags.set_client_tags(conn, router_a, {tag_id})
    admin = add_client(conn, "10.250.0.201", "Admin")
    conn.execute(
        "INSERT INTO rules (client_id, dest_ip, dest_tag_id, service_id, created_at) VALUES (?, '', ?, ?, 'now')",
        (admin, tag_id, get_service_id(conn, "HTTPS")),
    )
    conn.commit()

    tags.delete_tag(conn, tag_id)

    assert tags.get_client_tag_ids(conn, router_a) == set()
    remaining_rules = conn.execute("SELECT * FROM rules WHERE client_id = ?", (admin,)).fetchall()
    assert remaining_rules == []


def test_resolve_rule_targets_expands_group_rule_to_members_excluding_self(conn):
    mikrotik_tag = tags.get_or_create_tag(conn, "mikrotik")
    router_a = add_client(conn, "10.250.0.11", "RouterA")
    router_b = add_client(conn, "10.250.0.12", "RouterB")
    admin = add_client(conn, "10.250.0.201", "Admin")
    tags.set_client_tags(conn, router_a, {mikrotik_tag})
    tags.set_client_tags(conn, router_b, {mikrotik_tag})
    # Admin gehoert selbst auch zur Gruppe - darf sich nicht selbst als Ziel bekommen.
    tags.set_client_tags(conn, admin, {mikrotik_tag})

    raw_rules = [{"dest_ip": "", "dest_tag_id": mikrotik_tag, "protocol": "tcp", "port": 443}]
    resolved = acl.resolve_rule_targets(conn, admin, raw_rules)

    resolved_ips = {r["dest_ip"] for r in resolved}
    assert resolved_ips == {"10.250.0.11", "10.250.0.12"}
    assert all(r["protocol"] == "tcp" and r["port"] == 443 for r in resolved)


def test_resolve_rule_targets_empty_group_yields_no_rows(conn):
    empty_tag = tags.get_or_create_tag(conn, "unused")
    raw_rules = [{"dest_ip": "", "dest_tag_id": empty_tag, "protocol": "tcp", "port": 22}]
    assert acl.resolve_rule_targets(conn, client_id=1, raw_rules=raw_rules) == []


def test_resolve_rule_targets_passes_through_plain_ip_and_any_rules(conn):
    raw_rules = [
        {"dest_ip": "10.250.0.50", "dest_tag_id": None, "protocol": "tcp", "port": 22},
        {"dest_ip": "any", "dest_tag_id": None, "protocol": "all", "port": None},
    ]
    resolved = acl.resolve_rule_targets(conn, client_id=1, raw_rules=raw_rules)
    assert resolved == [
        {"dest_ip": "10.250.0.50", "protocol": "tcp", "port": 22},
        {"dest_ip": "any", "protocol": "all", "port": None},
    ]
