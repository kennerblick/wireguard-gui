import app as app_module


def test_detect_hook_chain_prefers_docker_user(monkeypatch):
    monkeypatch.setattr(app_module, "run_on_target", lambda script, timeout=15: (True, ""))
    assert app_module.detect_hook_chain() == "DOCKER-USER"


def test_detect_hook_chain_falls_back_to_forward(monkeypatch):
    monkeypatch.setattr(app_module, "run_on_target", lambda script, timeout=15: (False, ""))
    assert app_module.detect_hook_chain() == "FORWARD"


def test_list_remote_wgacl_chains_parses_output(monkeypatch):
    monkeypatch.setattr(
        app_module, "run_on_target", lambda script, timeout=15: (True, "WGACL_10_250_0_1\nWGACL_10_250_0_2\n")
    )
    ok, chains = app_module.list_remote_wgacl_chains()
    assert ok is True
    assert chains == ["WGACL_10_250_0_1", "WGACL_10_250_0_2"]


def test_list_remote_wgacl_chains_reports_ssh_failure(monkeypatch):
    monkeypatch.setattr(app_module, "run_on_target", lambda script, timeout=15: (False, "Timeout"))
    ok, err = app_module.list_remote_wgacl_chains()
    assert ok is False
    assert err == "Timeout"


def test_run_on_target_local_mode_executes_directly(monkeypatch):
    monkeypatch.setattr(app_module, "EXEC_MODE", "local")
    ok, out = app_module.run_on_target("echo -n hello-local")
    assert ok is True
    assert out == "hello-local"


def test_run_on_target_local_mode_reports_failure(monkeypatch):
    monkeypatch.setattr(app_module, "EXEC_MODE", "local")
    ok, out = app_module.run_on_target("exit 1")
    assert ok is False
