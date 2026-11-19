"""Portable installer safety and core deployment regressions, without system writes."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import os
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = spec_from_file_location(name, ROOT / path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("omni_install", "tools/install-platform.py")
firewall = load("omni_firewall", "tools/render-firewall.py")


def valid_config():
    config = {key: "configured" for key in installer.REQUIRED}
    config.update({key: "test-unique-install-secret" for key in installer.SECRET_KEYS})
    config.update(SIEM_FQDN="siem.example.test", SIEM_HOSTNAME="siem", SIEM_DOMAIN="example.test",
                  SIEM_IFACE="ens18", SIEM_IP="192.0.2.10", SIEM_GW="192.0.2.1",
                  DNS1="192.0.2.53", DNS2="192.0.2.54", NET_ADMIN="192.0.2.0/24", NET_BEATS="198.51.100.0/24")
    return config


def test_install_allowlist_excludes_destructive_and_site_response_operations():
    scripts = [script for _, script in installer.PHASES]
    assert "71-soc-console.sh" in scripts
    assert scripts.index("04-graylog.sh") < scripts.index("07-inputs.sh")
    assert scripts.index("07-inputs.sh") < scripts.index("10-graylog-model.sh")
    assert not any("purge" in script for script in scripts)
    assert not set(scripts).intersection({"36-soar.sh", "69-ad-response.sh", "38-vuln-scan.sh", "22-alert-routing.sh"})


def test_existing_install_is_detected(tmp_path):
    config = tmp_path / "server.conf"
    assert installer.existing_install([config]) == []
    config.write_text("# user config\n")
    assert installer.existing_install([config]) == [str(config)]


def test_configuration_validation_does_not_print_secret(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    config = valid_config()
    assert installer.validate_config(config) == []
    config["DATA_DISK"] = "/dev/sdb"
    assert any("ALLOW_FORMAT" in error for error in installer.validate_config(config))
    config["GRAYLOG_ADMIN_PASS"] = "CHANGEME"
    assert all("test-unique-install-secret" not in error for error in installer.validate_config(config))


def test_current_ssh_source_must_survive_firewall(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.5 5000 192.0.2.10 22")
    assert any("SSH client" in error for error in installer.validate_config(valid_config()))


def test_firewall_uses_only_site_addresses_and_preserves_other_tables():
    text = firewall.render({"NET_ADMIN": "192.0.2.0/24", "NET_BEATS": "198.51.100.0/24"})
    assert "flush ruleset" not in text
    assert "flush table inet omni_siem" in text
    assert "tcp dport { 80, 443 } ip saddr 192.0.2.0/24" in text
    assert "10.33." not in text
    assert "redirect" not in text


@pytest.mark.parametrize("bad", ["not-a-subnet", "192.0.2.1; accept", "$(echo leak)"])
def test_firewall_rejects_configuration_injection(bad):
    with pytest.raises(ValueError):
        firewall.render({"NET_ADMIN": bad})


def test_optional_triage_config_has_tenant_values_and_no_reference_exclusions(tmp_path):
    config = valid_config()
    config.update(SMTP_RELAY="smtp.example.test", SMTP_FROM="siem@example.test", ALERT_EMAIL="soc@example.test")
    path = tmp_path / "triage.env"
    installer.prepare_triage(config, path)
    text = path.read_text()
    assert "MAIL_RECIPIENTS=soc@example.test" in text
    assert "TRIAGE_FP_ENTITIES=\n" in text
    assert "10.94." not in text
    before = path.read_bytes()
    installer.prepare_triage(config, path)
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="bash platform fixtures run on Linux")
@pytest.mark.parametrize("os_id,version,suite", [("ubuntu", "22.04", "jammy"), ("ubuntu", "24.04", "noble"), ("debian", "12", "bookworm"), ("debian", "13", "bookworm")])
def test_platform_repository_selection(tmp_path, os_id, version, suite):
    release = tmp_path / "os-release"
    release.write_text(f'ID={os_id}\nVERSION_ID="{version}"\n')
    command = 'source "$1"; omni_platform "$2"; printf "%s" "$OMNI_MONGO_SUITE"'
    result = subprocess.run(["bash", "-c", command, "test", str(ROOT / "lib-platform.sh"), str(release)], capture_output=True, text=True, check=True)
    assert result.stdout == suite


def test_compose_versions_match_native_reference():
    versions = dict(line.split("=", 1) for line in (ROOT / "stack-versions.env").read_text().splitlines() if line and not line.startswith("#"))
    compose = (ROOT / "docker/docker-compose.yml").read_text()
    assert "image: mongo:" + versions["MONGODB_PACKAGE_VERSION"] in compose
    assert "image: opensearchproject/opensearch:" + versions["OPENSEARCH_PACKAGE_VERSION"] in compose
    assert "image: graylog/graylog:" + versions["GRAYLOG_PACKAGE_VERSION"].removesuffix("-1") in compose
    assert "profiles: [analytics]" in compose
