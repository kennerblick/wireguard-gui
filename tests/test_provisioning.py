import base64
import sqlite3

from wg_acl_manager import config, db, provisioning, wireguard

VALID_PUBKEY = base64.b64encode(b"x" * 32).decode()


def test_validate_wg_pubkey_accepts_valid_key():
    assert provisioning.validate_wg_pubkey(VALID_PUBKEY) == VALID_PUBKEY
    assert provisioning.validate_wg_pubkey(f"  {VALID_PUBKEY}  ") == VALID_PUBKEY


def test_validate_wg_pubkey_rejects_wrong_length_or_garbage():
    assert provisioning.validate_wg_pubkey("not-base64-!!!") is None
    assert provisioning.validate_wg_pubkey(base64.b64encode(b"short").decode()) is None
    assert provisioning.validate_wg_pubkey("") is None


def test_fetch_wg_interface_info_parses_address_and_listen_port(monkeypatch):
    sample = "[Interface]\nPrivateKey = xxx\nAddress = 10.250.0.1/24\nListenPort = 51820\n\n[Peer]\n#x\n"
    monkeypatch.setattr(wireguard, "run_on_target", lambda script, timeout=15: (True, sample))
    info = wireguard.fetch_wg_interface_info()
    assert info == {"address": "10.250.0.1/24", "listen_port": "51820"}


def test_suggest_free_ip_skips_used_addresses_within_kind_range(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("INSERT INTO clients (wg_ip, label, restricted) VALUES ('10.250.0.201', 'a', 1)")
    conn.commit()

    monkeypatch.setattr(wireguard, "fetch_wg_interface_info", lambda: {"address": "10.250.0.1/24"})
    monkeypatch.setattr(
        wireguard,
        "fetch_wg_peers_from_config",
        lambda: [{"name": "x", "pubkey": "k", "allowed_ips": "10.250.0.202/32", "actual_ip": None}],
    )

    ip, err = provisioning.suggest_free_ip(conn, kind="client")
    assert err is None
    # .201 = DB-Client, .202 = Peer laut Config -> .203 ist die naechste freie
    # IP im Client-Bereich (Standard 201-245).
    assert ip == "10.250.0.203"
    conn.close()


def test_suggest_free_ip_uses_separate_range_per_kind(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    monkeypatch.setattr(wireguard, "fetch_wg_interface_info", lambda: {"address": "10.250.0.1/24"})
    monkeypatch.setattr(wireguard, "fetch_wg_peers_from_config", lambda: [])

    server_ip, err = provisioning.suggest_free_ip(conn, kind="server")
    assert err is None
    assert server_ip == "10.250.0.11"

    router_ip, err = provisioning.suggest_free_ip(conn, kind="router")
    assert err is None
    assert router_ip == "10.250.0.101"

    client_ip, err = provisioning.suggest_free_ip(conn, kind="client")
    assert err is None
    assert client_ip == "10.250.0.201"
    conn.close()


def test_suggest_free_ip_reports_error_when_kind_range_exhausted(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    # /29 ist zu klein, um die (Standard-)Client-IPs .201-.245 ueberhaupt zu
    # enthalten - Bereich gilt als komplett ausgeschoepft statt irgendeine
    # andere freie Adresse im Subnetz vorzuschlagen.
    monkeypatch.setattr(wireguard, "fetch_wg_interface_info", lambda: {"address": "10.250.0.1/29"})
    monkeypatch.setattr(wireguard, "fetch_wg_peers_from_config", lambda: [])

    ip, err = provisioning.suggest_free_ip(conn, kind="client")
    assert ip is None
    assert "client-Bereich" in err
    conn.close()


def test_suggest_free_ip_reports_error_without_address(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row

    monkeypatch.setattr(wireguard, "fetch_wg_interface_info", lambda: {})
    ip, err = provisioning.suggest_free_ip(conn)
    assert ip is None
    assert err
    conn.close()


def test_render_linux_script_substitutes_all_tokens_and_includes_syslog():
    script = provisioning.render_linux_script(
        "Mitarbeiter Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820",
        "10.250.0.0/24", "10.250.0.1",
    )
    assert "@@" not in script
    assert "Mitarbeiter Max" in script
    assert "Address = 10.250.0.210/24" in script
    assert f"PublicKey = {VALID_PUBKEY}" in script
    assert "Endpoint = 203.0.113.5:51820" in script
    assert "AllowedIPs = 10.250.0.0/24" in script
    assert "@10.250.0.1:5141" in script  # rsyslog-Zielzeile (single @ = UDP)


def test_render_linux_script_without_syslog_host_omits_block():
    script = provisioning.render_linux_script(
        "Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24", None
    )
    assert "@@" not in script
    assert "rsyslog" not in script


def test_render_linux_script_validates_reused_private_key_before_trusting_it():
    # In Produktion aufgetreten: eine bereits vorhandene, aber leere/kaputte
    # /etc/wireguard/privatekey (Ueberbleibsel eines fehlgeschlagenen
    # frueheren Versuchs) wurde nur auf blosse Existenz geprueft ("-f") und
    # damit blind wiederverwendet - "wg-quick up" scheiterte danach mit
    # "Line unrecognized: `PrivateKey='" (leerer Wert). Reuse muss zusaetzlich
    # pruefen, dass sich daraus tatsaechlich ein Public Key ableiten laesst.
    script = provisioning.render_linux_script(
        "Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24", None
    )
    assert "[ -s /etc/wireguard/privatekey ]" in script
    assert "wg pubkey < /etc/wireguard/privatekey > /etc/wireguard/publickey" in script
    assert "[ -f /etc/wireguard/privatekey ]" not in script


def test_render_windows_script_substitutes_tokens():
    script = provisioning.render_windows_script(
        "Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24"
    )
    assert "@@" not in script
    assert '$TunnelIP = "10.250.0.210"' in script
    assert f'$HubPubKey = "{VALID_PUBKEY}"' in script
    assert '$HubEndpoint = "203.0.113.5:51820"' in script


def test_render_windows_script_explains_service_reinstall_for_later_changes():
    # In Produktion aufgetreten: Tunnel laeuft per /installtunnelservice als
    # Windows-Dienst und liest seine Config nur beim (Neu-)Anlegen des
    # Dienstes ein (aus einem intern gespeicherten Abbild), nicht bei jedem
    # Start - ein blosser Restart-Service uebernimmt eine spaeter geaenderte
    # AllowedIPs-Zeile (z.B. neu freigegebenes Netz) NICHT. Der Hinweis muss
    # daher deinstallieren+neu installieren empfehlen, nicht nur neu starten.
    script = provisioning.render_windows_script(
        "Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24"
    )
    assert "@@" not in script
    assert "/uninstalltunnelservice $Label" in script
    assert "/installtunnelservice '$ConfigFile'" in script
    assert "Restart-Service" not in script


def test_render_windows_script_auto_installs_wireguard_if_missing():
    script = provisioning.render_windows_script(
        "Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24"
    )
    assert "winget install" in script
    assert "WireGuard.WireGuard" in script
    assert "download.wireguard.com/windows-client/wireguard-installer.exe" in script


def test_render_windows_allowedips_update_substitutes_tokens_and_reinstalls_service():
    script = provisioning.render_windows_allowedips_update("pcphilipp", "10.250.0.0/24,192.168.3.0/24")
    assert "@@" not in script
    assert "$ConfigFile = 'C:\\WireGuard-Configs\\pcphilipp.conf'" in script
    assert "$NewAllowedIPs = '10.250.0.0/24,192.168.3.0/24'" in script
    # Muss den Dienst neu anlegen (nicht nur neu starten), da WireGuard die
    # Config sonst nicht neu einliest - siehe render_windows_script-Hinweis.
    assert "/uninstalltunnelservice $Label" in script
    assert "/installtunnelservice $ConfigFile" in script
    assert "Restart-Service" not in script


def test_render_linux_allowedips_update_substitutes_tokens_and_reloads_tunnel():
    script = provisioning.render_linux_allowedips_update("10.250.0.0/24,192.168.3.0/24")
    assert "@@" not in script
    assert 'NEW_ALLOWED="10.250.0.0/24,192.168.3.0/24"' in script
    assert "systemctl restart wg-quick@wg0" in script
    assert "wg-quick up wg0" in script


def test_render_mikrotik_script_splits_endpoint_host_and_port():
    script = provisioning.render_mikrotik_script(
        "Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24", "10.250.0.1"
    )
    assert "@@" not in script
    assert "endpoint-address=203.0.113.5" in script
    assert "endpoint-port=51820" in script
    assert "address=10.250.0.210/24" in script
    assert "remote=10.250.0.1 remote-port=5140" in script


def test_render_ubuntu_desktop_config_substitutes_tokens_and_placeholders_private_key():
    conf = provisioning.render_ubuntu_desktop_config(
        "Mitarbeiter Max", "10.250.0.210", VALID_PUBKEY, "203.0.113.5:51820", "10.250.0.0/24"
    )
    assert "@@" not in conf
    assert "Address = 10.250.0.210/24" in conf
    assert f"PublicKey = {VALID_PUBKEY}" in conf
    assert "Endpoint = 203.0.113.5:51820" in conf
    assert "AllowedIPs = 10.250.0.0/24" in conf
    # Im Unterschied zu den anderen Plattform-Templates wird hier NIE ein
    # echter privater Schluessel eingesetzt - diese App sieht ihn nie, der
    # Public Key kam bereits fertig vom Aufrufer.
    assert "PrivateKey = <HIER_DEINEN_PRIVATEN_SCHLUESSEL_EINTRAGEN>" in conf


def test_register_peer_on_target_builds_expected_script(monkeypatch):
    captured = {}

    def fake_run_on_target(script, timeout=15):
        captured["script"] = script
        return True, "ok"

    monkeypatch.setattr(wireguard, "run_on_target", fake_run_on_target)
    ok, out = provisioning.register_peer_on_target(VALID_PUBKEY, "10.250.0.210", "Max")
    assert ok is True
    assert f"wg set wg0 peer {VALID_PUBKEY} allowed-ips 10.250.0.210/32" in captured["script"]
    assert "#Max" in captured["script"]
    assert f"PublicKey = {VALID_PUBKEY}" in captured["script"]
