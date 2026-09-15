import app as app_module

SAMPLE_DOCKER_USER = """-N DOCKER-USER
-A DOCKER-USER -s 10.250.0.11/32 -d 10.250.0.1/32 -p tcp --dport 22 -j ACCEPT
-A DOCKER-USER -s 10.250.0.11/32 -j DROP
-A DOCKER-USER -m state --state RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -j RETURN
"""


def test_annotate_ips_appends_known_names():
    text = "-A DOCKER-USER -s 10.250.0.11/32 -d 10.250.0.1/32 -j ACCEPT"
    labels = {"10.250.0.11": "RouterRWVT", "10.250.0.1": "isurfer-hub"}
    annotated = app_module.annotate_ips(text, labels)
    assert "10.250.0.11/32 (RouterRWVT)" in annotated
    assert "10.250.0.1/32 (isurfer-hub)" in annotated


def test_annotate_ips_leaves_unknown_ips_untouched():
    text = "-A FORWARD -s 10.0.0.99/32 -j DROP"
    annotated = app_module.annotate_ips(text, {})
    assert annotated == text


def test_parse_iptables_rules_extracts_simple_rules():
    rules = app_module.parse_iptables_rules(SAMPLE_DOCKER_USER)
    simple = [r for r in rules if r["simple"]]
    # ACCEPT-Regel, DROP-Regel und die unbedingte "-j RETURN" sind alle
    # "einfach" (kein -m/!) - nur die state-Regel wird ausgeklammert.
    assert len(simple) == 3

    accept_rule = simple[0]
    assert accept_rule["src"] == "10.250.0.11/32"
    assert accept_rule["dst"] == "10.250.0.1/32"
    assert accept_rule["proto"] == "tcp"
    assert accept_rule["port"] == "22"
    assert accept_rule["target"] == "ACCEPT"

    drop_rule = simple[1]
    assert drop_rule["src"] == "10.250.0.11/32"
    assert drop_rule["dst"] is None
    assert drop_rule["target"] == "DROP"


def test_parse_iptables_rules_flags_rules_with_modules_as_not_simple():
    rules = app_module.parse_iptables_rules(SAMPLE_DOCKER_USER)
    non_simple_targets = [r["raw"] for r in rules if not r["simple"]]
    assert any("-m state" in raw for raw in non_simple_targets)
    # Die Chain-Deklaration selbst (-N) wird komplett ignoriert, nicht als Regel gezaehlt.
    assert not any(raw.startswith("-N") for raw in [r["raw"] for r in rules])


def test_build_ip_label_map_prefers_config_name_over_client_label(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "test.db"))
    app_module.init_db()
    import sqlite3
    db = sqlite3.connect(app_module.DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute(
        "INSERT INTO clients (wg_ip, label, restricted) VALUES ('10.250.0.11', 'Mein eigener Name', 1)"
    )
    db.commit()

    monkeypatch.setattr(
        app_module,
        "run_on_target",
        lambda script, timeout=15: (True, "[Peer]\n#RouterRWVT\nPublicKey = x=\nAllowedIPs = 10.250.0.11/32\n"),
    )
    labels = app_module.build_ip_label_map(db)
    assert labels["10.250.0.11"] == "RouterRWVT"
    db.close()
