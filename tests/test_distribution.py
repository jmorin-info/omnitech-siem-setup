"""Real Git snapshots, safe bootstrap and collector failure/rollback contracts."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tarfile
import io

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("release_builder", "tools/build-release.py")
launcher = load("package_launcher", "distribution/launcher.py")
agent = load("package_agent", "tools/install-linux-agent.py")


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()


@pytest.fixture
def packaged(tmp_path):
    source = tmp_path / "original"
    source.mkdir()
    git(source, "init", "--quiet", "--initial-branch=main", "--template=")
    git(source, "config", "user.name", "Release Test")
    git(source, "config", "user.email", "release@example.invalid")
    (source / "old.txt").write_text("not in the released tree")
    git(source, "add", ".")
    git(source, "commit", "-qm", "Previous revision")
    old = git(source, "rev-parse", "HEAD")
    (source / "old.txt").unlink()
    (source / ".gitignore").write_text("00-vars.env\ntracked.log\n")
    (source / "tracked.log").write_text("tracked fixture")
    (source / "00-vars.env.example").write_text("GRAYLOG_ADMIN_PASS='CHANGEME'\n")
    (source / "distribution").mkdir()
    (source / "distribution/version.json").write_text('{"version":"0.1.0-rc.1"}')
    (source / "distribution/launcher.py").write_text("# release launcher fixture\n")
    (source / "LICENSE").write_text("GPL fixture\n")
    git(source, "add", "--all")
    git(source, "add", "--force", "tracked.log")
    git(source, "commit", "-qm", "Release fixture")
    git(source, "config", "http.extraHeader", "Authorization: fixture-not-distributed")
    (source / "00-vars.env").write_text("not-distributed")
    snap = tmp_path / "snapshot"
    sha = git(source, "rev-parse", "HEAD")
    count = builder.snapshot(source, snap, sha)
    return source, snap, sha, old, count


def test_snapshot_contains_every_tracked_file_without_local_config_or_history(packaged):
    source, snap, sha, old, count = packaged
    assert count == len(git(source, "ls-files").splitlines())
    assert git(snap, "rev-parse", "HEAD") == sha
    assert git(snap, "status", "--porcelain") == ""
    assert git(snap, "ls-files") == git(source, "ls-files")
    assert (snap / "tracked.log").read_text() == "tracked fixture"
    assert not (snap / "00-vars.env").exists()
    assert "fixture-not-distributed" not in (snap / ".git/config").read_text()
    assert old not in git(snap, "rev-list", "HEAD")
    git(snap, "fsck", "--no-reflogs")


def test_bootstrap_real_commit_and_site_config_are_preserved(packaged, tmp_path, monkeypatch):
    _, snap, sha, _, _ = packaged
    active = tmp_path / "site/repository"
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    plan = launcher.initialize(active, False, snap)
    assert plan["package_revision"] == sha and not active.exists()
    launcher.initialize(active, True, snap)
    assert git(active, "rev-parse", "HEAD") == sha
    assert git(active, "remote", "get-url", "origin") == launcher.REMOTE
    assert (active / "00-vars.env").stat().st_mode & 0o777 == 0o600
    assert not git(active, "status", "--porcelain")
    (active / "00-vars.env").write_text("site-owned")
    with pytest.raises(launcher.DistributionError, match="already exists"):
        launcher.initialize(active, True, snap)
    assert (active / "00-vars.env").read_text() == "site-owned"


@pytest.mark.parametrize("path", ["/", "/opt", "/usr/local/site", "/etc/omni/repository", "relative/path", "/opt/../etc/site"])
def test_unsafe_installation_paths_are_refused(path):
    with pytest.raises(launcher.DistributionError):
        launcher.safe_root(Path(path))


def test_package_status_distinguishes_payload_and_active_checkout(packaged, tmp_path):
    _, snap, sha, _, _ = packaged
    result = launcher.status(tmp_path / "absent", snap)
    assert not result["initialized"] and result["package_revision"] == sha


@pytest.mark.skipif(not shutil.which("dpkg-deb"), reason="Debian package builder required")
def test_package_build_with_private_operator_umask_has_public_payload_modes(packaged, tmp_path):
    source, _, _, _, _ = packaged
    out = tmp_path / "artifacts"
    previous = os.umask(0o077)
    try:
        builder.build(source, out, ["deb"])
    finally:
        os.umask(previous)
    package = next(out.glob("*.deb"))
    raw = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert archive.getmember(".").mode == 0o755
        assert archive.getmember("./usr/share/doc/omni-siem/copyright").mode == 0o644
        assert archive.getmember("./usr/share/omni-siem/source/distribution").mode == 0o755


@pytest.mark.parametrize("target", ['192.0.2.1" bad="yes', "$(touch /tmp/no)", "host;true", "999.999.1.1", "host..test", "-host", "2001:db8::1"])
def test_collector_receiver_cannot_inject_rsyslog_or_shell(target):
    with pytest.raises(ValueError):
        agent.render(target, 1519)


def test_agent_plan_is_read_only(tmp_path):
    config, state = tmp_path / "etc/site.conf", tmp_path / "state"
    result = agent.deploy("siem.example.test", 1519, config=config, state=state)
    assert not config.exists() and not state.exists()
    assert result["delivery_proof"].startswith("not verified")
    assert "authpriv" in agent.render("192.0.2.1", 1519).decode()


def test_site_owned_collector_and_duplicate_legacy_are_refused(tmp_path):
    config = tmp_path / "site.conf"
    config.write_text("site-owned")
    with pytest.raises(ValueError, match="owned by the site"):
        agent.deploy("192.0.2.1", 1519, config=config)
    config.unlink()
    (tmp_path / "60-omni-forward.conf").touch()
    with pytest.raises(ValueError, match="duplicate"):
        agent.deploy("192.0.2.1", 1519, config=config)


def fake_collector(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(agent.shutil, "which", lambda _: "/usr/bin/tool")
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
    monkeypatch.setattr(agent.socket, "create_connection", lambda *_args, **_kwargs: Connection())
    monkeypatch.setattr(agent.subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0))


def test_collector_failed_validation_restores_original_and_records_rollback(tmp_path, monkeypatch):
    fake_collector(monkeypatch)
    config, state = tmp_path / "site.conf", tmp_path / "state"
    before = agent.render("192.0.2.1", 1519)
    config.write_bytes(before)
    monkeypatch.setattr(agent, "command", lambda _argv: (_ for _ in ()).throw(RuntimeError("invalid rsyslog")))
    with pytest.raises(RuntimeError):
        agent.deploy("192.0.2.2", 1519, True, config, state)
    assert config.read_bytes() == before
    report = json.loads(next(state.glob("*/transaction.json")).read_text())
    assert report["status"] == "rolled_back"
    assert next(state.glob("*/before.conf")).stat().st_mode & 0o777 == 0o600


def test_collector_manual_rollback_preserves_later_site_edits(tmp_path, monkeypatch):
    fake_collector(monkeypatch)
    monkeypatch.setattr(agent, "command", lambda _: None)
    config, state = tmp_path / "site.conf", tmp_path / "state"
    result = agent.deploy("192.0.2.1", 1519, True, config, state)
    transaction = result["transaction"]
    config.write_bytes(agent.render("192.0.2.2", 1519))
    with pytest.raises(ValueError, match="changed after"):
        agent.rollback(transaction, True, config, state)
    config.write_bytes(agent.render("192.0.2.1", 1519))
    assert agent.rollback(transaction, False, config, state)["mode"] == "rollback_plan"
    agent.rollback(transaction, True, config, state)
    assert not config.exists()


def test_collector_interrupted_apply_has_explicit_recovery(tmp_path, monkeypatch):
    fake_collector(monkeypatch)
    monkeypatch.setattr(agent, "command", lambda _: None)
    config, state = tmp_path / "site.conf", tmp_path / "state"
    result = agent.deploy("192.0.2.1", 1519, True, config, state)
    journal = state / result["transaction"] / "transaction.json"
    record = json.loads(journal.read_text())
    record["status"] = "applying"
    journal.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="cannot be rolled back"):
        agent.rollback(result["transaction"], True, config, state)
    agent.rollback(result["transaction"], True, config, state, recover=True)
    assert not config.exists()
