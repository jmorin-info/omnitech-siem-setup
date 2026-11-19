"""Portable installer safety and core deployment regressions, without system writes."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import os
import json
import shlex
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
    config.update(OS_HEAP="4g", GL_HEAP="2g", MONGO_CACHE_GB="1")
    return config


def test_install_allowlist_excludes_destructive_and_site_response_operations():
    scripts = [script for _, script in installer.PHASES]
    assert "71-soc-console.sh" in scripts
    assert scripts.index("04-graylog.sh") < scripts.index("07-inputs.sh")
    assert scripts.index("07-inputs.sh") < scripts.index("10-graylog-model.sh")
    assert not any("purge" in script for script in scripts)
    assert not set(scripts).intersection({"36-soar.sh", "69-ad-response.sh", "38-vuln-scan.sh", "22-alert-routing.sh"})


def test_optional_triage_precedes_detection_routing_and_verification_is_last():
    phases = [name for name, _ in installer.installation_phases(["triage", "triage"])]
    assert phases.index("pipelines") < phases.index("triage") < phases.index("detections")
    assert phases.count("triage") == 1
    assert phases[-1] == "verification" and phases.index("backups") < phases.index("verification")


def test_memory_budget_rejects_32gb_defaults_on_a_16gb_vm():
    config = valid_config()
    config.update(OS_HEAP="12g", GL_HEAP="4g")
    assert installer.resource_blockers(config, 16 * 1024 * 1024)
    assert installer.resource_blockers(config, 32 * 1024 * 1024) == []
    config.update(OS_HEAP="4096m", GL_HEAP="2g")
    assert installer.resource_blockers(config, 16 * 1024 * 1024) == []
    config["MONGO_CACHE_GB"] = "NaN"
    assert installer.resource_blockers(config, 16 * 1024 * 1024)
    config["OS_HEAP"] = "wrong"
    assert len(installer.resource_blockers(config, 16 * 1024 * 1024)) == 2


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


def test_ubuntu2604_requires_explicit_experimental_option():
    assert installer.platform_check("ubuntu", "26.04")[0]
    blockers, warnings = installer.platform_check("ubuntu", "26.04", True)
    assert not blockers and any("noble" in warning for warning in warnings)
    assert installer.platform_check("ubuntu", "99.04", True)[0]


@pytest.mark.skipif(os.name == "nt", reason="bash platform fixtures run on Linux")
def test_ubuntu2604_repository_requires_opt_in(tmp_path):
    release = tmp_path / "os-release"
    release.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
    command = 'source "$1"; omni_platform "$2" || exit; printf "%s" "$OMNI_MONGO_SUITE"'
    argv = ["bash", "-c", command, "test", str(ROOT / "lib-platform.sh"), str(release)]
    env = {**os.environ, "OMNI_EXPERIMENTAL_UBUNTU_2604": "0"}
    assert subprocess.run(argv, env=env, capture_output=True).returncode != 0
    env["OMNI_EXPERIMENTAL_UBUNTU_2604"] = "1"
    result = subprocess.run(argv, env=env, capture_output=True, text=True, check=True)
    assert result.stdout == "noble" and "EXPERIMENTAL" in result.stderr


@pytest.mark.parametrize("release,blocked", [
    ("6.8.0-99-generic", False), ("6.18.9", False), ("6.19.0-generic", True),
    ("6.20.1", True), ("7.0.0", True), ("7.0.13-generic", True),
    ("7.0.14-rc1", True), ("7.0.14-generic", False), ("7.1.0", False),
])
def test_mongodb_kernel_guard_matches_shell(release, blocked):
    assert bool(installer.kernel_blocker(release, "fixture", "")) == blocked
    if os.name != "nt":
        command = 'source "$1"; omni_mongodb_kernel_check "$2" fixture ""'
        result = subprocess.run(["bash", "-c", command, "test", str(ROOT / "lib-platform.sh"), release], capture_output=True)
        assert (result.returncode != 0) == blocked


@pytest.mark.parametrize("release,kernel_version,signature,blocked", [
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.0.14", False),
    ("7.0.0-1017-azure", "#17~24.04.1-Ubuntu SMP", "Ubuntu 7.0.0-1017.17~24.04.1-azure 7.0.14", False),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.0.15", False),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.0.13", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.0.14-rc1", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu malformed", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Debian 7.0.0-38.38-generic 7.0.14", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-99.99-generic 7.0.14", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-38.38-lowlatency 7.0.14", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 6.8.0-38.38-generic 7.0.14", True),
    ("7.0.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.1.0", True),
    ("7.0.0-38-generic", "#Debian SMP", "Ubuntu 7.0.0-38.38-generic 7.0.14", True),
    ("6.19.0-38-generic", "#38-Ubuntu SMP", "Ubuntu 6.19.0-38.38-generic 7.0.14", True),
    ("6.8.0-generic", "#Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.0.13", False),
    ("7.1.0-generic", "#Ubuntu SMP", "Ubuntu 7.0.0-38.38-generic 7.0.13", False),
])
def test_ubuntu_kernel_uses_running_kernel_upstream_signature(release, kernel_version, signature, blocked):
    assert bool(installer.kernel_blocker(release, kernel_version, signature)) == blocked
    if os.name != "nt":
        command = 'source "$1"; omni_mongodb_kernel_check "$2" "$3" "$4"'
        result = subprocess.run(["bash", "-c", command, "test", str(ROOT / "lib-platform.sh"),
                                 release, kernel_version, signature], capture_output=True)
        assert (result.returncode != 0) == blocked, result.stderr


def test_kernel_guard_reads_ubuntu_metadata_automatically(tmp_path, monkeypatch):
    signature = tmp_path / "version_signature"
    signature.write_text("Ubuntu 7.0.0-38.38-generic 7.0.14\n")
    monkeypatch.setattr(installer.platform, "version", lambda: "#38-Ubuntu SMP")
    monkeypatch.setattr(installer, "Path", lambda _: signature)
    assert installer.kernel_blocker("7.0.0-38-generic") is None
    signature.write_text("Ubuntu 7.0.0-38.38-generic 7.0.13\n")
    assert "upstream 7.0.13" in installer.kernel_blocker("7.0.0-38-generic")
    signature.unlink()
    assert installer.kernel_blocker("7.0.0-38-generic")


@pytest.mark.skipif(os.name == "nt", reason="trusted configuration is read by bash")
def test_secret_generation_preserves_credentials_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "existing_install", lambda: [])
    path = tmp_path / "00-vars.env"
    path.write_text("# site comment\nGRAYLOG_ADMIN_PASS='dummy-chosen-admin'\nMONGO_ADMIN_PASS='dummy-existing-mongo'\n"
                    "MONGO_GRAYLOG_PASS='CHANGEME'\nOPENSEARCH_BOOTSTRAP_PASS=''\nCUSTOM_SITE='preserve me'\n")
    keys = installer.generate_missing_secrets(path)
    assert keys == ["MONGO_GRAYLOG_PASS", "OPENSEARCH_BOOTSTRAP_PASS"]
    values = installer.load_config(path)
    assert values["GRAYLOG_ADMIN_PASS"] == "dummy-chosen-admin"
    assert values["MONGO_ADMIN_PASS"] == "dummy-existing-mongo"
    assert values["CUSTOM_SITE"] == "preserve me"
    assert "# site comment" in path.read_text()
    assert values[keys[0]] != values[keys[1]]
    for key in keys:
        assert len(values[key]) >= 40
        assert any(c.isupper() for c in values[key]) and any(c.islower() for c in values[key])
        assert any(c.isdigit() for c in values[key]) and "!" in values[key]
    assert path.stat().st_mode & 0o077 == 0
    before = path.read_bytes()
    assert installer.generate_missing_secrets(path) == []
    assert path.read_bytes() == before
    monkeypatch.setattr(installer, "existing_install", lambda: ["/etc/mongod.conf"])
    with pytest.raises(ValueError, match="fresh installation only"):
        installer.generate_missing_secrets(path)
    assert path.read_bytes() == before


@pytest.fixture
def installation_sandbox(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    script = root / "phase.sh"
    script.write_text("# pristine source\n")
    subprocess.run(["git", "add", "phase.sh"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "fixture"], cwd=root, check=True)
    config = root / "00-vars.env"
    config.write_text("\n".join(key + "=" + shlex.quote(value) for key, value in valid_config().items()) + "\n")
    config.chmod(0o600)
    cpu, memory, release = (tmp_path / name for name in ("cpu", "memory", "os-release"))
    cpu.write_text("flags : avx\n")
    memory.write_text("MemTotal: 33554432 kB\n")
    release.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
    state = tmp_path / "state" / "install-state.json"
    mapping = {"/proc/cpuinfo": cpu, "/proc/meminfo": memory, "/etc/os-release": release,
               "/var/lib/omni-siem/install-state.json": state, "/etc/omni-siem/instance.json": tmp_path / "instance.json"}
    monkeypatch.setattr(installer, "ROOT", root)
    monkeypatch.setattr(installer, "PHASES", (("test", "phase.sh"),))
    monkeypatch.setattr(installer, "Path", lambda value: mapping.get(str(value), Path(value)))
    monkeypatch.setattr(installer, "read_os", lambda: ("ubuntu", "26.04"))
    monkeypatch.setattr(installer, "load_config", lambda _: valid_config())
    monkeypatch.setattr(installer, "existing_install", lambda: [])
    monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(installer.platform, "release", lambda: "6.8.0-generic")
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    return root, script, state


def test_local_patch_installation_preserves_sources_without_committing(installation_sandbox, monkeypatch, capsys):
    root, script, state = installation_sandbox
    script.write_text("# reviewed local source\n")
    before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root)
    assert installer.main(["--plan", "--experimental-ubuntu-2604"]) == 0
    assert any("locally modified" in error for error in json.loads(capsys.readouterr().out)["blockers"])
    flags = ["--experimental-ubuntu-2604", "--allow-local-changes"]
    assert installer.main(["--plan", *flags]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["blockers"] == [] and not state.exists()
    real_run = subprocess.run
    def phase_run(argv, **kwargs):
        if argv[0] == "bash":
            assert kwargs["env"]["OMNI_EXPERIMENTAL_UBUNTU_2604"] == "1"
            return subprocess.CompletedProcess(argv, 0)
        return real_run(argv, **kwargs)
    monkeypatch.setattr(subprocess, "run", phase_run)
    assert installer.main(["--apply", *flags]) == 0
    assert json.loads(state.read_text())["completed_phases"] == ["test"]
    assert script.read_text() == "# reviewed local source\n"
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root) == before
    snapshot = state.parent / "install-sources" / plan["source_fingerprint"]
    patch = (snapshot / "local.patch").read_bytes()
    assert b"reviewed local source" in patch
    installer.snapshot_local_changes(root, snapshot, before.decode().strip(), installer.source_inventory(root)[1])
    assert (snapshot / "local.patch").read_bytes() == patch
    script.write_text("# changed after installation\n")
    capsys.readouterr()
    with pytest.raises(ValueError, match="resolve the plan"):
        installer.main(["--apply", "--resume", *flags])
    assert any("resume requires" in error for error in json.loads(capsys.readouterr().out)["blockers"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX child umask")
def test_private_operator_umask_keeps_secrets_private_and_service_paths_readable(installation_sandbox):
    root, script, state = installation_sandbox
    script.write_text("mkdir runtime\ntouch runtime/public\n")
    previous = os.umask(0o077)
    try:
        assert installer.main(["--apply", "--experimental-ubuntu-2604", "--allow-local-changes"]) == 0
        current = os.umask(0o077)
        assert current == 0o077
    finally:
        os.umask(previous)
    assert (root / "runtime").stat().st_mode & 0o777 == 0o755
    assert (root / "runtime/public").stat().st_mode & 0o777 == 0o644
    assert (root / "00-vars.env").stat().st_mode & 0o077 == 0
    assert state.stat().st_mode & 0o077 == 0


@pytest.mark.skipif(os.name != "posix", reason="Bash verification fixture")
def test_resume_reruns_read_only_verification_without_reprovisioning(installation_sandbox, monkeypatch):
    root, script, state = installation_sandbox
    monkeypatch.setattr(installer, "PHASES", (("verification", "phase.sh"),))
    script.write_text("echo checked >> checks.log\n")
    flags = ["--apply", "--experimental-ubuntu-2604", "--allow-local-changes"]
    assert installer.main(flags) == 0
    assert installer.main([*flags, "--resume"]) == 0
    assert (root / "checks.log").read_text().splitlines() == ["checked", "checked"]
    assert json.loads(state.read_text())["completed_phases"] == ["verification"]
