"""Rehome installed code and known runtime references without touching databases."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adoption", ROOT / "tools/adopt-installation.py")
adoption = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adoption)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()


@pytest.fixture
def site(tmp_path, monkeypatch):
    old = tmp_path / "home/operator/project"
    old.mkdir(parents=True)
    git(old, "init", "-q", "-b", "main", "--template=")
    git(old, "config", "user.name", "Tests")
    git(old, "config", "user.email", "tests@example.invalid")
    for relative in (*adoption.MARKERS, ".gitignore", "README.md"):
        path = old / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("00-vars.env\n.venv/\n" if relative == ".gitignore" else "# fixture\n")
    git(old, "add", ".")
    git(old, "commit", "-qm", "Installed fixture")
    (old / "00-vars.env").write_text("GRAYLOG_ADMIN_PASS='fixture-local-only'\n")
    (old / "00-vars.env").chmod(0o600)
    root = tmp_path / "system"
    root.mkdir()
    target = tmp_path / "opt/omni-siem/repository"
    state = tmp_path / "state"
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    return old, target, root, state


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    return path


def test_discovery_is_bounded_does_not_follow_links_and_reports_ambiguity(site):
    old, _, root, _ = site
    (root / "alias").symlink_to(old, target_is_directory=True)
    result = adoption.discover([old.parent.parent, root])
    assert result["candidates"] == [str(old)] and not result["truncated"]
    assert adoption.discover([old.parent.parent], limit=1)["truncated"]


def test_partial_installation_is_copied_at_same_revision_with_private_config(site):
    old, target, root, state = site
    metadata = write(root, "var/lib/omni-siem/install-state.json", json.dumps({
        "source_root": str(old), "completed_phases": ["base", "mongodb"], "profile": "core-soc"}))
    database = write(root, "etc/mongod.conf", "storage:\n  dbPath: /home/mongodb\n")
    report = adoption.plan(old, target, root)
    assert report["blockers"] == [] and report["services"] == [] and not target.exists()
    result = adoption.apply(report, state)
    assert result["status"] == "applied" and old.is_dir() and not old.is_symlink()
    assert git(old, "rev-parse", "HEAD") == git(target, "rev-parse", "HEAD")
    assert (target / "00-vars.env").stat().st_mode & 0o777 == 0o600
    assert (target / "00-vars.env").read_bytes() == (old / "00-vars.env").read_bytes()
    assert json.loads(metadata.read_text())["completed_phases"] == ["base", "mongodb"]
    assert json.loads(metadata.read_text())["source_root"] == str(target)
    assert "/home/mongodb" in database.read_text()
    adoption.rollback(result["transaction"], True, state=state)
    assert json.loads(metadata.read_text())["source_root"] == str(old)
    assert target.is_dir() and old.is_dir()


def test_only_existing_known_units_are_repointed_and_previously_active_ones_restarted(site):
    old, target, root, state = site
    unit = write(root, "etc/systemd/system/omni-mobile-api.service", f"[Service]\nExecStart=/usr/bin/python3 {old}/mobile/omni-mobile-api.py\n")
    inactive = write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nExecStart=/bin/bash {old}/install.sh\n")
    report = adoption.plan(old, target, root)
    commands = []
    status = lambda name: {"ActiveState": "active" if name == "omni-mobile-api.service" else "inactive", "Type": "simple"}
    result = adoption.apply(report, state, run=commands.append, status=status)
    assert str(target) in unit.read_text() and str(target) in inactive.read_text()
    assert commands == [["systemctl", "daemon-reload"], ["systemctl", "restart", "omni-mobile-api.service"]]
    assert not (root / "etc/systemd/system/oms-xdr.service").exists()
    assert result["status"] == "applied"


@pytest.mark.parametrize("case", ["modified", "staged", "target_exists", "cron", "unknown_unit", "runtime_data", "config_path"])
def test_unsafe_or_ambiguous_layouts_have_blockers_before_any_copy(site, case):
    old, target, root, state = site
    if case == "modified":
        (old / "README.md").write_text("site edit")
    elif case == "staged":
        write(old, "new.py", "# local")
        git(old, "add", "new.py")
    elif case == "target_exists":
        target.mkdir(parents=True)
    elif case == "cron":
        write(root, "etc/cron.d/custom", f"* * * * * root {old}/install.sh\n")
    elif case == "unknown_unit":
        write(root, "etc/systemd/system/site.service", f"[Service]\nExecStart=/bin/bash {old}/install.sh\n")
    elif case == "runtime_data":
        write(old, "private-data/state.json", "{}")
        write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nWorkingDirectory={old}/private-data\n")
    else:
        (old / "00-vars.env").write_text("DATA_MOUNT='" + str(old / "data") + "'\n")
    report = adoption.plan(old, target, root)
    assert report["blockers"]
    with pytest.raises(ValueError):
        adoption.apply(report, state)
    assert not state.exists()


def test_failed_restart_restores_runtime_files_and_old_checkout_is_retained(site):
    old, target, root, state = site
    unit = write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nExecStart=/bin/bash {old}/install.sh\n")
    before = unit.read_bytes()
    report = adoption.plan(old, target, root)
    failed = []
    def run(argv):
        if argv[1] == "restart" and not failed:
            failed.append(True)
            raise RuntimeError("simulated restart failure")
    with pytest.raises(RuntimeError):
        adoption.apply(report, state, run=run, status=lambda _: {"ActiveState": "active", "Type": "simple"})
    assert unit.read_bytes() == before and old.is_dir()
    record = json.loads(next(state.glob("*/transaction.json")).read_text())
    assert record["status"] == "rolled_back"


def test_running_oneshot_is_not_interrupted(site):
    old, target, root, state = site
    write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nExecStart=/bin/bash {old}/install.sh\n")
    with pytest.raises(ValueError, match="settle"):
        adoption.apply(adoption.plan(old, target, root), state, status=lambda _: {"ActiveState": "active", "Type": "oneshot"})
    assert not target.exists()


def test_native_backup_keeps_its_timer_and_receives_the_moved_private_config(site):
    old, target, root, state = site
    unit = write(root, "etc/systemd/system/siem-backup.service", '[Service]\nType=oneshot\nEnvironment="OMNI_CONFIG_FILE='
                 + str(old / "00-vars.env") + '"\nExecStart=/usr/local/sbin/siem-backup.sh\n')
    timer = write(root, "etc/systemd/system/siem-backup.timer", "[Timer]\nOnCalendar=*-*-* 02:30:00\n")
    before = timer.read_bytes()
    report = adoption.plan(old, target, root)
    assert not report["blockers"] and report["services"] == ["siem-backup.service"]
    commands = []
    result = adoption.apply(report, state, run=commands.append,
                            status=lambda _: {"ActiveState": "inactive", "Type": "oneshot"})
    assert str(target / "00-vars.env") in unit.read_text()
    assert timer.read_bytes() == before and commands == [["systemctl", "daemon-reload"]]
    adoption.rollback(result["transaction"], True, state=state, run=commands.append)
    assert str(old / "00-vars.env") in unit.read_text()


def test_enabled_unit_alias_is_kept_and_target_unit_is_repointed(site):
    old, target, root, state = site
    unit = write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nExecStart=/bin/bash {old}/install.sh\n")
    enabled = root / "etc/systemd/system/multi-user.target.wants/oms-demo.service"
    enabled.parent.mkdir()
    enabled.symlink_to(unit)
    report = adoption.plan(old, target, root)
    assert report["blockers"] == [] and len(report["files"]) == 1
    adoption.apply(report, state, run=lambda _: None,
                   status=lambda _: {"ActiveState": "active", "Type": "simple"})
    assert enabled.is_symlink() and enabled.resolve() == unit and str(target) in unit.read_text()


def test_service_reading_changed_environment_is_restarted_even_with_external_backend(site):
    old, target, root, state = site
    write(root, "etc/default/omni-mobile", "OMNI_REPO_DIR=" + str(old) + "\n")
    unit = write(root, "etc/systemd/system/omni-mobile-api.service", "[Service]\nEnvironmentFile=-/etc/default/omni-mobile\nExecStart=/opt/site-console/python /opt/site-console/api.py\n")
    before = unit.read_bytes()
    report = adoption.plan(old, target, root)
    assert not report["blockers"] and report["services"] == [unit.name]
    commands = []
    adoption.apply(report, state, run=commands.append,
                   status=lambda _: {"ActiveState": "active", "Type": "simple"})
    assert unit.read_bytes() == before
    assert ["systemctl", "restart", unit.name] in commands


def test_python_environment_is_prepared_before_any_service_path_changes(site):
    old, target, root, state = site
    unit = write(root, "etc/systemd/system/omni-mobile-api.service", f"[Service]\nExecStart={old}/mobile/.venv/bin/python {old}/mobile/omni-mobile-api.py\n")
    report = adoption.plan(old, target, root)
    assert report["venvs"] == ["mobile"]
    before = unit.read_bytes()
    commands = []
    def fail_build(argv):
        commands.append(argv)
        assert unit.read_bytes() == before
        if "venvs" in argv:
            raise RuntimeError("venv dependency unavailable")
    with pytest.raises(RuntimeError):
        adoption.apply(report, state, run=fail_build,
                       status=lambda _: {"ActiveState": "inactive", "Type": "simple"})
    assert unit.read_bytes() == before
    assert commands[0][1].endswith("tools/omni-deploy.py") and "--no-verify" in commands[0]


def test_user_state_inside_old_checkout_is_not_repointed_to_an_empty_directory(site):
    old, target, root, _ = site
    write(root, "etc/default/omni-mobile", "SOC_MODULES_DIR='" + str(old / "local-state/modules") + "'\n")
    assert adoption.plan(old, target, root)["blockers"]


def test_similar_directory_names_are_not_rewritten(site):
    old, target, root, _ = site
    unit = write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nExecStart=/bin/bash {old}-other/install.sh\n")
    report = adoption.plan(old, target, root)
    assert report["files"] == [] and report["services"] == []
    assert str(old) + "-other" in unit.read_text()


def test_rollback_refuses_site_changes_after_success(site):
    old, target, root, state = site
    result = adoption.apply(adoption.plan(old, target, root), state)
    (target / "00-vars.env").write_text("new site configuration")
    with pytest.raises(ValueError, match="changed after"):
        adoption.rollback(result["transaction"], True, state=state)


def test_reports_do_not_include_credentials_or_runtime_file_contents(site):
    old, target, root, _ = site
    write(root, "etc/default/omni-mobile", "MITRE_LOOKUP='" + str(old / "lookups/mitre.csv") + "'\nGRAYLOG_API_TOKEN='fixture-private-token'\n")
    report = adoption.public(adoption.plan(old, target, root))
    text = json.dumps(report)
    assert "fixture-private-token" not in text and "fixture-local-only" not in text


def test_manual_recovery_restores_an_interrupted_write(site):
    old, target, root, state = site
    unit = write(root, "etc/systemd/system/oms-demo.service", f"[Service]\nExecStart=/bin/bash {old}/install.sh\n")
    result = adoption.apply(adoption.plan(old, target, root), state, run=lambda _: None,
                            status=lambda _: {"ActiveState": "inactive", "Type": "simple"})
    journal = state / result["transaction"] / "transaction.json"
    record = json.loads(journal.read_text())
    record["status"] = "applying"
    journal.write_text(json.dumps(record))
    adoption.rollback(result["transaction"], True, recover=True, state=state, run=lambda _: None)
    assert str(old) in unit.read_text()
