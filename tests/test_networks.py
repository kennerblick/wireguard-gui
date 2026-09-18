import base64
import ipaddress
import sqlite3

import pytest

from wg_acl_manager import acl, config, db, networks, provisioning, wireguard


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


def test_validate_network_cidr_accepts_and_normalizes():
    assert networks.validate_network_cidr("192.168.88.0/24") == "192.168.88.0/24"
    assert networks.validate_network_cidr("  10.0.0.0/8  ") == "10.0.0.0/8"


def test_validate_network_cidr_rejects_garbage_and_any():
    assert networks.validate_network_cidr("any") is None
    assert networks.validate_network_cidr("") is None
    assert networks.validate_network_cidr("not-an-ip") is None


def test_set_client_networks_replaces_and_reports_invalid_entries(conn):
    router = add_client(conn, "10.250.0.11", "RouterA")
    errors = networks.set_client_networks(conn, router, ["192.168.88.0/24", "garbage", "192.168.5.0/24"])
    assert errors == ["garbage"]
    assert {r["cidr"] for r in networks.list_client_networks(conn, router)} == {
        "192.168.88.0/24",
        "192.168.5.0/24",
    }

    # Erneutes Setzen ersetzt komplett, statt zu addieren.
    networks.set_client_networks(conn, router, ["10.0.0.0/8"])
    assert [r["cidr"] for r in networks.list_client_networks(conn, router)] == ["10.0.0.0/8"]


def test_all_networks_with_client_joins_label(conn):
    router = add_client(conn, "10.250.0.11", "RouterA")
    networks.set_client_networks(conn, router, ["192.168.88.0/24"])
    rows = networks.all_networks_with_client(conn)
    assert len(rows) == 1
    assert rows[0]["cidr"] == "192.168.88.0/24"
    assert rows[0]["client_label"] == "RouterA"


def test_delete_client_cascades_networks(conn):
    router = add_client(conn, "10.250.0.11", "RouterA")
    networks.set_client_networks(conn, router, ["192.168.88.0/24"])
    conn.execute("DELETE FROM clients WHERE id = ?", (router,))
    conn.commit()
    assert networks.list_client_networks(conn, router) == []


def test_peer_managed_networks_excludes_own_ip_and_mesh_subnet():
    wg_network = ipaddress.ip_network("10.250.0.0/24")
    peer = {"allowed_ips": "10.250.0.11/32, 192.168.88.0/24"}
    assert wireguard.peer_managed_networks(peer, "10.250.0.11", wg_network) == ["192.168.88.0/24"]


def test_peer_managed_networks_excludes_full_mesh_access():
    wg_network = ipaddress.ip_network("10.250.0.0/24")
    admin_peer = {"allowed_ips": "10.250.0.0/24"}
    assert wireguard.peer_managed_networks(admin_peer, "10.250.0.201", wg_network) == []


def test_peer_managed_networks_without_wg_network_still_excludes_own_ip():
    peer = {"allowed_ips": "10.250.0.11/32, 192.168.88.0/24"}
    assert wireguard.peer_managed_networks(peer, "10.250.0.11", None) == ["192.168.88.0/24"]


def test_register_peer_on_target_includes_extra_networks_in_allowed_ips(monkeypatch):
    captured = {}

    def fake_run_on_target(script, timeout=15):
        captured["script"] = script
        return True, "ok"

    monkeypatch.setattr(wireguard, "run_on_target", fake_run_on_target)
    valid_pubkey = base64.b64encode(b"y" * 32).decode()
    ok, out = provisioning.register_peer_on_target(
        valid_pubkey, "10.250.0.210", "RouterB", extra_networks=["192.168.5.0/24"]
    )
    assert ok is True
    assert "allowed-ips 10.250.0.210/32,192.168.5.0/24" in captured["script"]
    assert "AllowedIPs = 10.250.0.210/32,192.168.5.0/24" in captured["script"]


def test_import_peers_from_config_autodetects_managed_networks(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row

    sample_config = """
[Interface]
PrivateKey = xxx
Address = 10.250.0.1/24
ListenPort = 51820

[Peer]
#RouterB
PublicKey = pubkey-routerb==
AllowedIPs = 10.250.0.12/32, 192.168.5.0/24
"""
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (True, sample_config))

    imported, skipped, ambiguous = acl.import_peers_from_config(conn)
    assert imported == 1
    assert skipped == 0
    assert ambiguous == []

    client_id = conn.execute("SELECT id FROM clients WHERE wg_ip = '10.250.0.12'").fetchone()["id"]
    cidrs = {r["cidr"] for r in networks.list_client_networks(conn, client_id)}
    assert cidrs == {"192.168.5.0/24"}
    conn.close()


def test_import_peers_from_config_skips_ambiguous_own_ip(monkeypatch, tmp_path):
    """Ein Peer mit weiterreichendem Zugriff (AllowedIPs deckt ein ganzes
    Subnetz ab) und ohne explizite '#IP:'-Kommentarzeile darf NICHT mit der
    Netzwerk-Adresse als (falscher) eigener IP importiert werden - siehe
    wireguard.peer_own_ip()."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row

    sample_config = """
[Interface]
PrivateKey = xxx
Address = 10.250.0.1/24
ListenPort = 51820

[Peer]
#PC-Admin
PublicKey = pubkey-admin==
AllowedIPs = 10.250.0.0/24
"""
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (True, sample_config))

    imported, skipped, ambiguous = acl.import_peers_from_config(conn)
    assert imported == 0
    assert skipped == 0
    assert ambiguous == ["PC-Admin"]
    assert conn.execute("SELECT COUNT(*) AS n FROM clients").fetchone()["n"] == 0
    conn.close()


def test_set_peer_allowed_ips_rewrites_only_matching_peer_block(monkeypatch):
    """Echter End-to-End-Test des awk-basierten Config-Rewrites: ruft die
    echte set_peer_allowed_ips() mit EXEC_MODE=local (echtes bash/awk) auf
    und prueft, dass nur die AllowedIPs-Zeile des passenden PublicKey-Blocks
    ersetzt wird, alle anderen Peers/Zeilen unveraendert bleiben. "wg" selbst
    gibt es in dieser Sandbox nicht - dafuer ein No-Op-Stub vor den echten
    PATH haengen, nur der awk-Config-Rewrite wird real ausgefuehrt."""
    import os

    iface = "wgtest"
    conf_dir = "/etc/wireguard"
    conf_path = f"{conf_dir}/{iface}.conf"
    pubkey_a = base64.b64encode(b"a" * 32).decode()
    pubkey_b = base64.b64encode(b"b" * 32).decode()
    # /etc/wireguard existiert nur, wenn wireguard-tools tatsaechlich
    # installiert ist. Fuer den Test selbst anlegen statt vorauszusetzen -
    # aber auf einem CI-Runner ohne root fehlt dafuer grundsaetzlich das
    # Schreibrecht unter /etc (PermissionError, kein fehlendes Verzeichnis) -
    # dieser Test braucht echten Dateisystemzugriff auf den realen
    # WireGuard-Pfad und wird dort uebersprungen statt die Suite rot zu machen.
    created_conf_dir = not os.path.isdir(conf_dir)
    if created_conf_dir:
        try:
            os.makedirs(conf_dir)
        except PermissionError:
            pytest.skip("Keine Schreibrechte fuer /etc/wireguard in dieser Umgebung (z.B. CI ohne root).")
    with open(conf_path, "w") as f:
        f.write(
            "[Interface]\n"
            "PrivateKey = xxx\n"
            "Address = 10.250.0.1/24\n\n"
            "[Peer]\n"
            "#RouterA\n"
            f"PublicKey = {pubkey_a}\n"
            "AllowedIPs = 10.250.0.11/32\n\n"
            "[Peer]\n"
            "#RouterB\n"
            f"PublicKey = {pubkey_b}\n"
            "AllowedIPs = 10.250.0.12/32\n"
        )
    try:
        monkeypatch.setattr(config, "EXEC_MODE", "local")
        monkeypatch.setattr(config, "TARGET_WG_INTERFACE", iface)

        import stat

        fake_bin = os.path.dirname(conf_path) + "/fakebin-" + iface
        os.makedirs(fake_bin, exist_ok=True)
        wg_stub = os.path.join(fake_bin, "wg")
        with open(wg_stub, "w") as f:
            f.write("#!/bin/bash\nexit 0\n")
        os.chmod(wg_stub, os.stat(wg_stub).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")

        allowed_ips_csv = "10.250.0.12/32,192.168.5.0/24"
        ok, out = wireguard.set_peer_allowed_ips(pubkey_b, allowed_ips_csv)
        assert ok is True, out

        updated = open(conf_path).read()
        assert "AllowedIPs = 10.250.0.11/32" in updated  # RouterA unveraendert
        assert f"AllowedIPs = {allowed_ips_csv}" in updated  # RouterB aktualisiert
        assert updated.count("[Peer]") == 2
    finally:
        import shutil
        os.remove(conf_path)
        shutil.rmtree(fake_bin, ignore_errors=True)
        if created_conf_dir:
            shutil.rmtree(conf_dir, ignore_errors=True)
