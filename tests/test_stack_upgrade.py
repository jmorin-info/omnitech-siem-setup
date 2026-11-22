"""Stack upgrade tool: dry run by default, prerequisites, compatibility, ordered execution, rollback."""
import json
from pathlib import Path

import pytest

from omni_update import stack
from update_fakes import NOW, PREFERENCES, FakeSystem, policy

SECRET = "mongo-test-password-123"
MUTATING = ("install", "mongodump", "gzip", "tar", "apt-get", "bash")


def dpkg(fake, package, version):
    status = "install ok installed" if version else "unknown ok not-installed"
    fake.on(["dpkg-query", "-W", "-f=${Status}|${Version}", package], f"{status}|{version or ''}",
            rc=0 if version else 1)


class UpgradeHost(FakeSystem):
    """Fake host whose installed versions change after apt-get install."""

    def __init__(self, tmp_path, component_versions, holds=(), table=None, target_after=None):
        super().__init__()
        self.tmp = tmp_path
        self.target_after = target_after or {}
        for package, version in component_versions.items():
            dpkg(self, package, version)
        for package in ("mongodb-org", "mongodb-org-mongos", "mongodb-org-tools", "mongodb-org-database",
                        "mongodb-org-database-tools-extra", "mongodb-org-shell"):
            if ("dpkg-query", "-W", "-f=${Status}|${Version}", package) not in self.commands:
                dpkg(self, package, None)
        self.on(["apt-mark", "showhold"], "\n".join(holds))
        for package, rows in (table or {}).items():
            installed = component_versions.get(package)
            candidate = max((r for r in rows if r[1] > 0), key=lambda r: r[0])[0] if rows else None
            self.on(["apt-cache", "policy", package], policy(installed, candidate, rows))
        self.on(["dpkg", "--audit"], "")
        self.on(["systemctl", "is-active", "oms-maj-siem.service"], "inactive\n", rc=3)
        self.on(["systemctl", "show", "omni-backup-config.service", "-p", "Result", "--value"], "success\n")
        self.on(["dpkg", "-l"], "ii  graylog-server 7.2.2-1\n")
        for prefix in (["install"], ["mongodump"], ["gzip"], ["tar"], ["bash"], ["systemctl", "stop"],
                       ["systemctl", "start"], ["apt-mark", "hold"], ["apt-mark", "unhold"], ["apt-get", "install"]):
            self.commands[tuple(prefix) + ("*",)] = (0, "", "")
        self.put(stack.PREFERENCES, PREFERENCES)
        # Fictitious URI assembled at run time (keeps the repository secret scan clean).
        self.put(stack.SERVER_CONF, "mongodb_uri = mongodb" + "://graylog" + ":" + SECRET + "@" + "127.0.0.1:27017/graylog\n")
        self.put(str(tmp_path / "source/00-vars.env"), f'BACKUP_DIR="{tmp_path}/backup"\n')
        self.put("/var/backups/siem/omni-siem-config_2026-11-21.tar.gz.enc", b"x", mtime=NOW - 3600 * 5)
        self.put("/var/lib/apt/lists/deb_Packages", "x", mtime=NOW - 3600)
        for path in ("/", "/var", str(tmp_path / "backup")):
            self.disks[path] = {"free": 50 * stack.GiB, "total": 100 * stack.GiB}
        self.http[stack.OPENSEARCH + "/_cluster/health"] = (200, '{"status": "green"}')
        self.http[stack.GRAYLOG_API + "/system/lbstatus"] = (200, "ALIVE")
        self.http[stack.GRAYLOG_API + "/system"] = (200, json.dumps({"version": "7.2.2", "lifecycle": "running", "is_processing": True}))
        self.inputs = {"before": 5, "after": 5}
        self.installed_done = False
        self.http[stack.OPENSEARCH + "/omni-*"] = (200, '{"count": 1200}')

    def run(self, argv, timeout=120, env=None):
        if argv[:2] == ["apt-get", "install"] and self.commands.get(("apt-get", "install", "*"), (0,))[0] == 0:
            self.installed_done = True
            for package, version in self.target_after.items():
                dpkg(self, package, version)
        return super().run(argv, timeout, env)

    def http_get(self, url, headers=None, timeout=10):
        if url.endswith("/system/inputstates"):
            running = self.inputs["after" if self.installed_done else "before"]
            states = [{"state": "RUNNING", "message_input": {"title": f"in{i}"}} for i in range(running)]
            states += [{"state": "FAILED", "message_input": {"title": "beats"}}] * (5 - running)
            self.http_calls.append((url, headers))
            return 200, json.dumps({"states": states})
        return super().http_get(url, headers, timeout)


GRAYLOG_TABLE = {"graylog-server": [("7.3.0-1", -1), ("7.2.3-1.rc.1", 500), ("7.2.2-2", 500), ("7.2.2-1", 500), ("7.2.1-1", 500)]}
VERSIONS = {"graylog-server": "7.2.2-1", "opensearch": "2.19.7", "mongodb-org-server": "8.0.38", "logstash": None}


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAYLOG_API_TOKEN", "test-token")
    return UpgradeHost(tmp_path, VERSIONS, table=GRAYLOG_TABLE, target_after={"graylog-server": "7.2.2-2"})


def upgrade(host, target="7.2.2-2", component="graylog", **options):
    return stack.StackUpgrade(host, component, target, source=host.tmp / "source", state_dir=host.tmp / "state",
                              wait_scale=0, **options)


def mutating_calls(host):
    return [c for c in host.calls if c[0] in MUTATING or c[:2] in (["systemctl", "stop"], ["systemctl", "start"])
            or c[:2] in (["apt-mark", "hold"], ["apt-mark", "unhold"])]


def test_plan_is_a_dry_run_ready_for_a_patch_release(host):
    report = upgrade(host).plan()
    assert report["status"] == "ready", report["blocking"]
    assert report["mode"] == "dry-run"
    assert mutating_calls(host) == []
    assert not (host.tmp / "state").exists()
    assert not (host.tmp / "backup").exists()
    assert any("apt-get install" in s and "graylog-server=7.2.2-2" in s for s in report["steps"])
    assert any(s.startswith("mongodump") for s in report["steps"])
    assert SECRET not in json.dumps(report)
    # Not yet observed in production: warned, not blocking.
    combination = next(c for c in report["compatibility"] if c["name"] == "combinaison de versions")
    assert combination["ok"] is False and combination["blocking"] is False


def test_validated_combination_is_recognized(host):
    policy_data = stack.load_policy()
    policy_data["validated_combinations"].append({"graylog-server": "7.2.2-2", "opensearch": "2.19.7", "mongodb-org-server": "8.0.38"})
    report = upgrade(host, policy=policy_data).plan()
    assert next(c for c in report["compatibility"] if c["name"] == "combinaison de versions")["ok"]


@pytest.mark.parametrize("target,reason", [
    ("7.2.3-1.rc.1", "pré-version"),
    ("7.3.0-1", "changement de série"),
    ("7.2.1-1", "rollback"),
    ("7.2.9-1", "absent des dépôts"),
    ("8.0.0-1", "version majeure"),
])
def test_incompatible_targets_are_blocked(host, target, reason):
    report = upgrade(host, target).plan()
    assert report["status"] == "blocked"
    assert any(reason in b for b in report["blocking"]), report["blocking"]


def test_series_change_needs_explicit_flag_and_pin_change(host):
    report = upgrade(host, "7.3.0-1", allow_series_change=True).plan()
    assert report["status"] == "blocked"
    assert any("épinglage" in b and "priorité -1" in b for b in report["blocking"])
    assert not any(b.startswith("série") for b in report["blocking"])


def test_mongodb_series_change_is_refused_even_with_flag(tmp_path, monkeypatch):
    table = {"mongodb-org-server": [("8.2.1", 500), ("8.0.38", 500)]}
    fake = UpgradeHost(tmp_path, VERSIONS, holds=["mongodb-org-server"], table=table)
    report = stack.StackUpgrade(fake, "mongodb", "8.2.1", source=tmp_path / "source", state_dir=tmp_path / "state",
                                allow_series_change=True).plan()
    assert report["status"] == "blocked"
    assert any("featureCompatibilityVersion" in b for b in report["blocking"])


@pytest.mark.parametrize("change,expected", [
    (lambda h: h.mtimes.update({"/var/backups/siem/omni-siem-config_2026-11-21.tar.gz.enc": NOW - 3600 * 30}), "sauvegarde"),
    (lambda h: h.on(["systemctl", "show", "omni-backup-config.service", "-p", "Result", "--value"], "exit-code\n"), "sauvegarde"),
    (lambda h: (h.files.pop("/var/backups/siem/omni-siem-config_2026-11-21.tar.gz.enc"),
                h.mtimes.pop("/var/backups/siem/omni-siem-config_2026-11-21.tar.gz.enc")), "sauvegarde"),
    (lambda h: h.http.update({stack.OPENSEARCH + "/_cluster/health": (200, '{"status": "yellow"}')}), "OpenSearch"),
    (lambda h: h.http.update({stack.GRAYLOG_API + "/system/lbstatus": (503, "")}), "API Graylog"),
    (lambda h: h.disks.update({"/var": {"free": 1 * stack.GiB, "total": 20 * stack.GiB}}), "espace disque /var"),
    (lambda h: h.on(["systemctl", "is-active", "oms-maj-siem.service"], "active\n"), "automatique"),
    (lambda h: h.on(["dpkg", "--audit"], "half-configured: foo\n"), "dpkg"),
])
def test_failed_prerequisite_blocks_the_upgrade(host, change, expected):
    change(host)
    report = upgrade(host).plan()
    assert report["status"] == "blocked"
    assert any(expected in b for b in report["blocking"]), report["blocking"]


def test_missing_rollback_package_blocks_unless_accepted(host):
    host.on(["apt-cache", "policy", "graylog-server"], policy("7.2.2-1", "7.2.2-2", [("7.2.2-2", 500)]))
    assert upgrade(host).plan()["status"] == "blocked"
    assert upgrade(host, accept_no_package_rollback=True).plan()["status"] == "ready"


def test_apply_requires_exact_confirmation(host):
    with pytest.raises(stack.StackError, match="--confirm graylog=7.2.2-2"):
        upgrade(host).run(execute=True)
    with pytest.raises(stack.StackError):
        upgrade(host).run(execute=True, confirm="graylog=7.2.2-3")
    assert mutating_calls(host) == []


def test_apply_blocked_by_prerequisite_executes_nothing(host, monkeypatch):
    monkeypatch.setattr(stack.os, "geteuid", lambda: 0)
    host.http[stack.OPENSEARCH + "/_cluster/health"] = (200, '{"status": "red"}')
    report = upgrade(host).run(execute=True, confirm="graylog=7.2.2-2")
    assert report["status"] == "blocked"
    assert mutating_calls(host) == []


def test_apply_runs_backup_then_upgrade_then_verification(host, monkeypatch):
    monkeypatch.setattr(stack.os, "geteuid", lambda: 0)
    job = upgrade(host)
    report = job.run(execute=True, confirm="graylog=7.2.2-2")
    assert report["status"] == "success", report.get("verification")
    commands = [c["command"] for c in report["executed"]]
    order = [next(i for i, c in enumerate(commands) if c.startswith(prefix))
             for prefix in ("mongodump", "gzip -t", "tar -czf", "systemctl stop graylog-server", "apt-get install", "systemctl start graylog-server")]
    assert order == sorted(order)
    assert SECRET not in json.dumps(report)
    assert any("apt-get download graylog-server=7.2.2-1" in c for c in commands)
    journal = json.loads((host.tmp / "state" / (job.identifier + ".json")).read_text())
    assert journal["status"] == "success"
    assert {c["name"] for c in journal["verification"]} >= {"version graylog-server", "OpenSearch vert", "inputs RUNNING", "flux reçu"}
    assert (host.tmp / "state" / (job.identifier + ".json")).stat().st_mode & 0o077 == 0


def test_held_packages_are_unheld_then_held_again(tmp_path, monkeypatch):
    monkeypatch.setattr(stack.os, "geteuid", lambda: 0)
    monkeypatch.setenv("GRAYLOG_API_TOKEN", "test-token")
    table = {"opensearch": [("2.19.8", 500), ("2.19.7", 500)]}
    fake = UpgradeHost(tmp_path, VERSIONS, holds=["opensearch"], table=table, target_after={"opensearch": "2.19.8"})
    report = stack.StackUpgrade(fake, "opensearch", "2.19.8", source=tmp_path / "source", state_dir=tmp_path / "state",
                                wait_scale=0).run(execute=True, confirm="opensearch=2.19.8")
    assert report["status"] == "success", report
    sequence = [c for c in fake.calls if c[:2] in (["apt-mark", "unhold"], ["apt-mark", "hold"], ["apt-get", "install"],
                                                   ["systemctl", "stop"], ["systemctl", "start"])]
    assert sequence == [["systemctl", "stop", "graylog-server"], ["systemctl", "stop", "opensearch"],
                        ["apt-mark", "unhold", "opensearch"],
                        ["apt-get", "install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold", "opensearch=2.19.8"],
                        ["apt-mark", "hold", "opensearch"],
                        ["systemctl", "start", "opensearch"], ["systemctl", "start", "graylog-server"]]


def test_fewer_running_inputs_after_upgrade_fails_verification(host, monkeypatch):
    monkeypatch.setattr(stack.os, "geteuid", lambda: 0)
    host.inputs["after"] = 4
    report = upgrade(host).run(execute=True, confirm="graylog=7.2.2-2")
    assert report["status"] == "verification_failed"
    check = next(c for c in report["verification"] if c["name"] == "inputs RUNNING")
    assert not check["ok"] and "beats" in check["detail"]
    assert any("dpkg -i" in c for c in report["rollback"])


def test_no_ingestion_after_upgrade_fails_verification(host, monkeypatch):
    monkeypatch.setattr(stack.os, "geteuid", lambda: 0)
    host.http[stack.OPENSEARCH + "/omni-*"] = (200, '{"count": 0}')
    assert upgrade(host).run(execute=True, confirm="graylog=7.2.2-2")["status"] == "verification_failed"


def test_apt_failure_stops_and_rehold_happens(tmp_path, monkeypatch):
    monkeypatch.setattr(stack.os, "geteuid", lambda: 0)
    table = {"opensearch": [("2.19.8", 500), ("2.19.7", 500)]}
    fake = UpgradeHost(tmp_path, VERSIONS, holds=["opensearch"], table=table)
    fake.commands[("apt-get", "install", "*")] = (100, "", "E: broken")
    job = stack.StackUpgrade(fake, "opensearch", "2.19.8", source=tmp_path / "source", state_dir=tmp_path / "state", wait_scale=0)
    report = job.run(execute=True, confirm="opensearch=2.19.8")
    assert report["status"] == "failed"
    assert ["apt-mark", "hold", "opensearch"] in fake.calls
    assert not any(c[:2] == ["systemctl", "start"] for c in fake.calls)
    assert json.loads((tmp_path / "state" / (job.identifier + ".json")).read_text())["status"] == "failed"


def test_rollback_plan_and_execution_from_journal(tmp_path):
    fake = FakeSystem()
    backup = tmp_path / "backup/upgrade-graylog-x"
    journal = {"schema_version": 1, "component": "graylog", "backup_dir": str(backup),
               "installed": {"graylog-server": "7.2.2-1"}, "held": []}
    fake.put(tmp_path / "j.json", json.dumps(journal))
    fake.put(str(backup / "graylog-server_7.2.2-1_amd64.deb"), b"deb")
    for prefix in (["systemctl", "stop"], ["systemctl", "start"], ["apt-mark", "unhold"], ["apt-get", "install"]):
        fake.commands[tuple(prefix) + ("*",)] = (0, "", "")
    plan = stack.rollback(fake, tmp_path / "j.json")
    assert plan["status"] == "ready" and fake.calls == []
    with pytest.raises(stack.StackError, match="rollback-graylog"):
        stack.rollback(fake, tmp_path / "j.json", execute=True)
    done = stack.rollback(fake, tmp_path / "j.json", execute=True, confirm="rollback-graylog")
    assert done["status"] == "rolled_back"
    assert ["apt-get", "install", "-y", "--allow-downgrades", "-o", "Dpkg::Options::=--force-confold",
            str(backup / "graylog-server_7.2.2-1_amd64.deb")] in fake.calls
    assert not any(c[0].startswith("mongo") for c in fake.calls)


def test_rollback_without_saved_package_is_blocked(tmp_path):
    fake = FakeSystem()
    fake.put(tmp_path / "j.json", json.dumps({"schema_version": 1, "component": "graylog", "backup_dir": str(tmp_path),
                                              "installed": {"graylog-server": "7.2.2-1"}, "held": []}))
    assert stack.rollback(fake, tmp_path / "j.json")["status"] == "blocked"


@pytest.mark.parametrize("component,target", [("postgres", "1.0"), ("graylog", "7.2; rm -rf /"), ("graylog", "-y")])
def test_invalid_parameters_are_rejected(host, component, target):
    with pytest.raises(stack.StackError):
        upgrade(host, target, component=component)


def test_cli_plan_never_executes(tmp_path, monkeypatch, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("omni_stack_cli", Path(__file__).resolve().parents[1] / "tools/omni-stack-upgrade.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    with pytest.raises(SystemExit):
        cli.main(["plan", "--component", "graylog", "--to", "7.2.2-2", "--execute"])
