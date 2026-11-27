"""SSH operations execute only declared argv and never persist credentials."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

import pytest

from manager.operations import Manager, redact
from manager.storage import lock
from manager.configuration import Configuration
from manager.cli import Terminal
from manager.inventory import inventory

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def manager(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "00-vars.env.example").write_bytes((ROOT / "00-vars.env.example").read_bytes())
    return Manager(source, tmp_path / "state", tmp_path / "update-state")


@pytest.mark.parametrize("action,params", [
    ("shell", {}), ("install_apply", {"source": "/other"}), ("update_fetch", {"remote": "https://other.test"}),
    ("update_apply", {"target": "main"}), ("update_plan", {"target": "a"*40, "command": "rm -rf"}),
    ("update_stage", {"target": "--help"}), ("update_fetch", {"ref": "main; touch /tmp/injected"}),
    ("update_rollback", {"transaction": "../../other"}), ("install_apply", {"triage": "false"}),
])
def test_unknown_operations_and_parameters_cannot_launch_process(manager, monkeypatch, action, params):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(ValueError):
        manager.run(action, params, confirmed=True)


def test_mutation_requires_confirmation(manager):
    with pytest.raises(ValueError, match="confirmation"):
        manager.run("install_apply", {})
    with pytest.raises(ValueError, match="confirmation"):
        manager.run("install_apply", {}, confirmed="OUI")


def test_installation_options_are_explicit_and_generation_is_separate(manager):
    argv, env = manager.command("install_plan", {"experimental_ubuntu_2604": True, "allow_local_changes": True})
    assert "--experimental-ubuntu-2604" in argv and "--allow-local-changes" in argv
    assert "--plan" in argv and "--apply" not in argv and env == {}
    for key in ("experimental_ubuntu_2604", "allow_local_changes"):
        with pytest.raises(ValueError):
            manager.command("install_apply", {key: "true"})
    argv, _ = manager.command("install_secrets", {})
    assert argv[-1] == "--generate-secrets" and "--apply" not in argv
    with pytest.raises(ValueError, match="confirmation"):
        manager.run("install_secrets", {})
    with pytest.raises(ValueError):
        manager.command("install_secrets", {"allow_local_changes": True})


def test_preserves_existing_updater_state_by_explicit_path(manager):
    argv, env = manager.command("update_plan", {"target": "a"*40})
    assert argv[argv.index("--state-dir")+1] == str(manager.updater_state)
    assert env == {}
    assert "--target" in argv and argv[-1] == "a"*40


def test_module_token_is_only_in_environment(manager):
    argv, env = manager.command("module_install", {"module": "watchguard", "api": "https://siem.test/api", "api_token": "dummy-sensitive-token"})
    assert "dummy-sensitive-token" not in repr(argv)
    assert env == {"GRAYLOG_API_TOKEN": "dummy-sensitive-token"}
    assert argv[-1] == "--apply"


def test_module_uninstall_has_a_read_only_plan_before_explicit_application(manager):
    params = {"module": "watchguard", "api": "https://siem.test/api", "api_token": "dummy-sensitive-token", "installation_id": "a"*24}
    argv, _ = manager.command("module_uninstall_plan", params)
    assert "uninstall" in argv
    assert "--apply" not in argv
    argv, _ = manager.command("module_uninstall", params)
    assert argv[-1] == "--apply"


def test_redaction_handles_transformed_credentials_and_terminal_controls():
    secret = "dummy$private/pass"
    values = [secret, quote(secret, safe=""), base64.b64encode((secret+":token").encode()).decode()]
    result = redact("\x1b[31m " + " ".join(values) + " mongodb://dummy-user:dummy-pass@localhost", [secret])
    assert all(value not in result for value in values)
    assert "dummy-pass" not in result
    assert "\x1b" not in result


def test_redaction_handles_json_escaped_passwords():
    secret = 'dummy-private-"quoted\\é'
    for ascii_only in (False, True):
        rendered = json.dumps({"credential": secret}, ensure_ascii=ascii_only)
        result = json.loads(redact(rendered, [secret]))
        assert result["credential"] == "[masqué]"


def test_actual_job_streams_redacted_output_and_private_journal(manager, monkeypatch):
    secret = "dummy-private-job-value"
    monkeypatch.setattr(manager, "command", lambda action, params: ([sys.executable, "-c", 'import os,json;print(json.dumps({"token":os.environ["GRAYLOG_API_TOKEN"],"target":"a"*40}))'], {"GRAYLOG_API_TOKEN": secret}))
    emitted = []
    job = manager.run("install_plan", {}, emit=emitted.append)
    assert job["status"] == "success"
    assert job["result"]["target"] == "a"*40
    assert secret not in repr(job) + repr(emitted)
    journal = manager.state / "jobs" / (job["id"] + ".json")
    assert secret not in journal.read_text()
    if os.name == "posix":
        assert journal.stat().st_mode & 0o077 == 0


def test_failed_child_is_reported_as_failed(manager, monkeypatch):
    monkeypatch.setattr(manager, "command", lambda action, params: ([sys.executable, "-c", "raise SystemExit(7)"], {}))
    job = manager.run("install_plan", {})
    assert job["status"] == "failed"
    assert job["returncode"] == 7


@pytest.mark.skipif(os.name != "posix", reason="Unix child process group lifecycle")
def test_interrupt_stops_owned_child_and_records_incomplete_operation(manager, monkeypatch):
    monkeypatch.setattr(manager, "command", lambda action, params: ([sys.executable, "-c", 'import time;print("ready",flush=True);time.sleep(30)'], {}))
    def interrupt(line):
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        manager.run("install_plan", {}, emit=interrupt)
    assert not (manager.state / "operation.lock").exists()
    assert manager.history()[0]["status"] == "interrupted"


def test_job_directory_symlink_is_refused(manager, tmp_path):
    if os.name == "nt":
        pytest.skip("requires symlink privileges")
    manager.state.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (manager.state / "jobs").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolique"):
        manager.run("install_plan", {})
    assert not list(outside.iterdir())


def test_configuration_cannot_change_while_operation_owns_lock(manager):
    configuration = Configuration(manager.source, manager.state)
    with lock(manager.state):
        with pytest.raises(ValueError, match="opération"):
            configuration.save({"SIEM_HOSTNAME": "other"}, {})
    assert not configuration.path.exists()


def test_terminal_cancellation_does_not_execute_or_write(manager, monkeypatch):
    terminal = Terminal(manager.source, manager.state, manager.updater_state)
    monkeypatch.setattr("manager.cli.confirm", lambda question: False)
    monkeypatch.setattr(terminal.manager, "run", lambda *a, **k: pytest.fail("cancelled operation"))
    assert terminal.run("install_apply") is None
    assert not manager.state.exists()


def test_catalogue_accounts_for_every_tracked_file_once():
    data = inventory(ROOT)
    paths = [path for component in data["components"] for path in component["files"]]
    assert len(paths) == len(set(paths)) == data["tracked_files"]
    assert all((ROOT / component["documentation"]).exists() for component in data["components"])
    assert any("purge" in row["path"] and "destructive" in row["policy"] for row in data["scripts"])


def test_inventory_mode_works_without_tty_or_mutations(tmp_path):
    state = tmp_path / "unused"
    process = subprocess.run([sys.executable, str(ROOT / "tools/omni-manager.py"), "--inventory", "--state-dir", str(state)], capture_output=True, text=True)
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["tracked_files"] > 700
    assert not state.exists()


def test_inventory_accepts_extracted_candidate_without_git_metadata(tmp_path):
    from manager.inventory import inventory

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "INSTALLATION.md").write_text("guide", encoding="utf-8")
    (tmp_path / "sample.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "ignored").write_text("metadata", encoding="utf-8")

    data = inventory(tmp_path)

    assert data["tracked_files"] == 2
    assert sum(component["file_count"] for component in data["components"]) == 2
    assert all(".git/ignored" not in path for component in data["components"] for path in component["files"])


@pytest.mark.skipif(os.name != "posix", reason="requires a Linux terminal")
def test_real_terminal_menu_exits_without_creating_state(tmp_path):
    import shutil
    import shlex
    script = shutil.which("script")
    if not script:
        pytest.skip("script utility unavailable")
    state = tmp_path / "unused"
    command = shlex.join([sys.executable, str(ROOT / "tools/omni-manager.py"), "--state-dir", str(state)])
    process = subprocess.run([script, "-q", "-e", "-c", command, "/dev/null"], input="0\n", capture_output=True, text=True, timeout=15)
    assert process.returncode == 0, process.stderr
    assert "Administration locale SSH" in process.stdout
    assert not state.exists()
