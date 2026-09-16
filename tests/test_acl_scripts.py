from wg_acl_manager.firewall import (
    build_apply_script,
    build_remove_script,
    chain_name,
    chain_name_to_ip,
    validate_dest_ip,
)


def test_chain_name_roundtrip():
    assert chain_name("10.250.0.12") == "WGACL_10_250_0_12"
    assert chain_name_to_ip(chain_name("10.250.0.12")) == "10.250.0.12"


def test_validate_dest_ip_any_variants():
    assert validate_dest_ip("any") == "any"
    assert validate_dest_ip("ANY") == "any"
    assert validate_dest_ip("  ") == "any"
    assert validate_dest_ip("0.0.0.0/0") == "any"


def test_validate_dest_ip_accepts_valid_ip_and_cidr():
    assert validate_dest_ip("10.250.0.12") == "10.250.0.12"
    assert validate_dest_ip("10.250.0.0/24") == "10.250.0.0/24"
    assert validate_dest_ip(" 10.250.0.12 ") == "10.250.0.12"


def test_validate_dest_ip_rejects_garbage_and_injection_attempts():
    assert validate_dest_ip("not-an-ip") is None
    assert validate_dest_ip("10.0.0.1; rm -rf /") is None
    assert validate_dest_ip("10.0.0.1 && reboot") is None
    assert validate_dest_ip("$(reboot)") is None
    assert validate_dest_ip("10.0.0.1`id`") is None


def test_build_apply_script_contains_accept_and_drop_rules():
    rules = [{"dest_ip": "10.250.0.12", "protocol": "tcp", "port": 22}]
    script = build_apply_script("10.250.0.210", rules, "DOCKER-USER")

    assert "iptables -N WGACL_10_250_0_210" in script
    assert "iptables -F WGACL_10_250_0_210" in script
    assert "iptables -A WGACL_10_250_0_210 -d 10.250.0.12 -p tcp --dport 22 -j ACCEPT" in script
    assert "iptables -A WGACL_10_250_0_210 -j DROP" in script
    assert "DOCKER-USER" in script
    # DROP muss vor der Hook-Insert-Regel stehen, sonst faellt der Client durch.
    assert script.index("-j DROP") < script.index("-j WGACL_10_250_0_210\n")


def test_build_apply_script_any_destination_has_no_dest_filter():
    rules = [{"dest_ip": "any", "protocol": "tcp", "port": 443}]
    script = build_apply_script("10.250.0.210", rules, "FORWARD")
    assert "-d any" not in script
    assert "-p tcp --dport 443 -j ACCEPT" in script


def test_build_apply_script_all_protocol_has_no_port_filter():
    rules = [{"dest_ip": "10.250.0.1", "protocol": "all", "port": None}]
    script = build_apply_script("10.250.0.210", rules, "FORWARD")
    assert "iptables -A WGACL_10_250_0_210 -d 10.250.0.1 -j ACCEPT" in script


def test_build_apply_script_ensures_established_related_return_rule():
    rules = [{"dest_ip": "10.250.0.12", "protocol": "tcp", "port": 22}]
    script = build_apply_script("10.250.0.210", rules, "DOCKER-USER")

    assert "-m state --state ESTABLISHED,RELATED -j ACCEPT" in script
    # Muss auf Position 1 stehen (vor jeder Peer-Chain), die eigene
    # Sprungregel des Clients dagegen explizit erst auf Position 2 - sonst
    # wuerde ein spaeterer Client mit einem bare "-I hook_chain" die
    # Established-Regel wieder von Position 1 verdraengen.
    assert "iptables -I DOCKER-USER 1 -i" in script
    assert "iptables -I DOCKER-USER 2 -i" in script
    assert script.index("iptables -I DOCKER-USER 1") < script.index("iptables -I DOCKER-USER 2")


def test_build_remove_script_flushes_and_deletes_chain():
    script = build_remove_script("10.250.0.210", "DOCKER-USER")
    chain = "WGACL_10_250_0_210"
    assert f"iptables -D DOCKER-USER" in script
    assert f"iptables -F {chain}" in script
    assert f"iptables -X {chain}" in script
