from wg_acl_manager import acl, wireguard

SAMPLE_CONFIG = """
[Interface]
PrivateKey = xxx
Address = 10.250.0.1/24
ListenPort = 51820

[Peer]
#Buero-Router
PublicKey = pubkey-router==
AllowedIPs = 10.250.0.5/32

[Peer]
PublicKey = pubkey-no-name==
AllowedIPs = 10.250.0.6/32

[Peer]
#Mitarbeiter Max
PublicKey = pubkey-max==
AllowedIPs = 10.250.0.210/32, 10.250.0.211/32

[Peer]
#PC-Admin
#IP: 10.250.0.201
PublicKey = pubkey-admin==
AllowedIPs = 10.250.0.0/24
"""


def test_fetch_wg_peers_from_config_parses_name_pubkey_allowed_ips(monkeypatch):
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (True, SAMPLE_CONFIG))
    peers = wireguard.fetch_wg_peers_from_config()
    assert len(peers) == 4
    assert peers[0] == {
        "name": "Buero-Router",
        "pubkey": "pubkey-router==",
        "allowed_ips": "10.250.0.5/32",
        "actual_ip": None,
    }
    assert peers[1]["name"] is None
    assert peers[2]["name"] == "Mitarbeiter Max"
    assert peers[2]["allowed_ips"] == "10.250.0.210/32, 10.250.0.211/32"


def test_fetch_wg_peers_from_config_parses_explicit_ip_comment(monkeypatch):
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (True, SAMPLE_CONFIG))
    peers = wireguard.fetch_wg_peers_from_config()
    admin_peer = peers[3]
    assert admin_peer["name"] == "PC-Admin"
    assert admin_peer["allowed_ips"] == "10.250.0.0/24"
    assert admin_peer["actual_ip"] == "10.250.0.201"


def test_peer_own_ip_prefers_explicit_ip_over_allowed_ips_network():
    peer = {"allowed_ips": "10.250.0.0/24", "actual_ip": "10.250.0.201"}
    assert wireguard.peer_own_ip(peer) == "10.250.0.201"


def test_peer_own_ip_falls_back_to_allowed_ips_when_no_explicit_ip():
    peer = {"allowed_ips": "10.250.0.5/32", "actual_ip": None}
    assert wireguard.peer_own_ip(peer) == "10.250.0.5"


def test_fetch_wg_peers_from_config_empty_on_failure(monkeypatch):
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (False, "no such file"))
    assert wireguard.fetch_wg_peers_from_config() == []


def test_peer_lookup_maps_builds_pubkey_and_ip_maps(monkeypatch):
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (True, SAMPLE_CONFIG))
    pubkey_to_name, ip_to_name = wireguard.peer_lookup_maps()
    assert pubkey_to_name == {
        "pubkey-router==": "Buero-Router",
        "pubkey-max==": "Mitarbeiter Max",
        "pubkey-admin==": "PC-Admin",
    }
    assert ip_to_name == {
        "10.250.0.5": "Buero-Router",
        "10.250.0.210": "Mitarbeiter Max",
        # Aus dem "#IP:"-Kommentar, NICHT aus AllowedIPs=10.250.0.0/24 (das
        # waere sonst faelschlich "10.250.0.0" - der eigentliche Bug hier.
        "10.250.0.201": "PC-Admin",
    }
    # Peer ohne Namens-Kommentar taucht bewusst nicht auf.
    assert "pubkey-no-name==" not in pubkey_to_name
    assert "10.250.0.6" not in ip_to_name
    assert "10.250.0.0" not in ip_to_name


def test_diff_target_sets():
    added, removed = acl.diff_target_sets({"10.0.0.1", "10.0.0.2"}, {"10.0.0.2", "10.0.0.3"})
    assert added == {"10.0.0.3"}
    assert removed == {"10.0.0.1"}
