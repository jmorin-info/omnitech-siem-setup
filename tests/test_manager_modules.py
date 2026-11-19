"""Terminal module actions cannot turn into arbitrary commands or leak tokens."""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from manager.modules import catalogue, build_module_command, validate_api


def test_catalogue_contains_only_module_metadata():
    items = catalogue()
    assert {item["id"] for item in items} == {"watchguard", "unifi", "paloalto"}
    assert all(item["status"] == "preview" for item in items)
    assert all(set(item) == {"id", "name", "revision", "status", "default_port", "supported_format"} for item in items)


def test_install_is_a_plan_by_default_and_token_stays_out_of_arguments(monkeypatch):
    monkeypatch.setenv("GRAYLOG_API_TOKEN", "sample-sensitive-token")
    argv = build_module_command(ROOT, "install", "unifi", "https://siem.example.net/api")
    assert argv[:4] == [sys.executable, str(ROOT / "tools" / "omni-integrations.py"), "install", "unifi"]
    assert "--apply" not in argv
    assert argv[-4:] == ["--port", "1522", "--bind", "127.0.0.1"]
    assert "sample-sensitive-token" not in " ".join(argv)


def test_explicit_apply_and_custom_network_values():
    argv = build_module_command(ROOT, "install", "watchguard", "https://siem.example.net/api/",
                                port=45121, bind="192.0.2.10", apply=True, ca=str(ROOT / "public-ca.crt"))
    assert argv[-1] == "--apply"
    assert argv[argv.index("--port") + 1] == "45121"
    assert argv[argv.index("--bind") + 1] == "192.0.2.10"
    assert argv[argv.index("--api") + 1] == "https://siem.example.net/api"


def test_uninstall_requires_exact_owned_installation_id_at_runtime():
    argv = build_module_command(ROOT, "uninstall", "paloalto", "http://127.0.0.1:9000/api", installation_id="a" * 24)
    assert argv[-2:] == ["--installation-id", "a" * 24]
    assert "--apply" not in argv and "--port" not in argv
    with pytest.raises(ValueError):
        build_module_command(ROOT, "uninstall", "paloalto", "http://127.0.0.1:9000/api", installation_id="not-an-id")


@pytest.mark.parametrize("api", ["http://remote.example.net/api", "https://user:secret@siem.example.net/api",
                                 "https://siem.example.net/api?token=secret", "https://siem.example.net/api#fragment",
                                 "https://siem.example.net/", "https://siem.example.net/api\n"])
def test_unsafe_api_urls_are_rejected(api):
    with pytest.raises(ValueError):
        validate_api(api)


@pytest.mark.parametrize("kwargs", [
    {"action": "shell"}, {"module_id": "../../etc"}, {"module_id": "unknown"},
    {"action": "plan", "apply": True}, {"port": 80}, {"port": True},
    {"bind": "192.0.2.10; touch /tmp/file"}, {"ca": "relative-ca.crt"},
    {"installation_id": "a" * 24},
])
def test_invalid_action_inputs_are_rejected_before_execution(kwargs):
    defaults = {"source_root": ROOT, "action": "install", "module_id": "watchguard", "api": "https://siem.example.net/api"}
    defaults.update(kwargs)
    with pytest.raises(ValueError):
        build_module_command(**defaults)
