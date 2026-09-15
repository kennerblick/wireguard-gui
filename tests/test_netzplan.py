import app as app_module

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
"""


def test_fetch_wg_peers_from_config_parses_name_pubkey_allowed_ips(monkeypatch):
    monkeypatch.setattr(app_module, "run_on_target", lambda script, timeout=15: (True, SAMPLE_CONFIG))
    peers = app_module.fetch_wg_peers_from_config()
    assert len(peers) == 3
    assert peers[0] == {
        "name": "Buero-Router",
        "pubkey": "pubkey-router==",
        "allowed_ips": "10.250.0.5/32",
    }
    assert peers[1]["name"] is None
    assert peers[2]["name"] == "Mitarbeiter Max"
    assert peers[2]["allowed_ips"] == "10.250.0.210/32, 10.250.0.211/32"


def test_fetch_wg_peers_from_config_empty_on_failure(monkeypatch):
    monkeypatch.setattr(app_module, "run_on_target", lambda script, timeout=15: (False, "no such file"))
    assert app_module.fetch_wg_peers_from_config() == []


def test_peer_lookup_maps_builds_pubkey_and_ip_maps(monkeypatch):
    monkeypatch.setattr(app_module, "run_on_target", lambda script, timeout=15: (True, SAMPLE_CONFIG))
    pubkey_to_name, ip_to_name = app_module.peer_lookup_maps()
    assert pubkey_to_name == {
        "pubkey-router==": "Buero-Router",
        "pubkey-max==": "Mitarbeiter Max",
    }
    assert ip_to_name == {
        "10.250.0.5": "Buero-Router",
        "10.250.0.210": "Mitarbeiter Max",
    }
    # Peer ohne Namens-Kommentar taucht bewusst nicht auf.
    assert "pubkey-no-name==" not in pubkey_to_name
    assert "10.250.0.6" not in ip_to_name


def test_diff_target_sets():
    added, removed = app_module.diff_target_sets({"10.0.0.1", "10.0.0.2"}, {"10.0.0.2", "10.0.0.3"})
    assert added == {"10.0.0.3"}
    assert removed == {"10.0.0.1"}
