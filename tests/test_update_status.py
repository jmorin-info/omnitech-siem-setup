"""Read-only status aggregation: stable JSON schema, per-layer verdicts, no mutation."""
import json
from pathlib import Path
import subprocess

import pytest

from omni_update import status, versions
from omni_update.stack import CONFIG_BACKUP_GLOB, GRAYLOG_API, OPENSEARCH, PREFERENCES as PREFS_PATH
from update_fakes import NOW, PREFERENCES, FakeSystem, policy

ROOT = Path(__file__).resolve().parents[1]
READ_ONLY_COMMANDS = {("apt", "list"), ("apt-mark", "showhold"), ("apt-config", "dump"), ("apt-cache", "policy"),
                      ("systemctl", "show"), ("dpkg-query", "-W")}
UPGRADABLE = """Listing...
base-files/stable 13.8+deb13u8 amd64 [upgradable from: 13.8+deb13u7]
openssl/stable-security 3.5.1-1+deb13u2 amd64 [upgradable from: 3.5.1-1+deb13u1]
graylog-server/stable 7.2.2-2 amd64 [upgradable from: 7.2.2-1]
"""
APT_CONFIG = '''APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Package-Blacklist:: "graylog-server";
Unattended-Upgrade::Package-Blacklist:: "opensearch";
Unattended-Upgrade::Package-Blacklist:: "mongodb-org-server";
'''


def healthy(source):
    fake = FakeSystem()
    fake.on(["apt", "list", "--upgradable"], UPGRADABLE)
    fake.on(["apt-mark", "showhold"], "opensearch\nmongodb-org-server\n")
    fake.on(["apt-config", "dump"], APT_CONFIG)
    fake.on(["systemctl", "show", "oms-maj-siem.timer", "-p", "NextElapseUSecRealtime", "--value"], "Sun 2026-11-22 04:39:18 CET\n")
    fake.on(["systemctl", "show", "omni-backup-config.service", "-p", "Result", "--value"], "success\n")
    fake.on(["apt-cache", "policy", "graylog-server"], policy("7.2.2-1", "7.2.2-2", [("7.3.0-1", -1), ("7.2.2-2", 500), ("7.2.2-1", 500)]))
    fake.on(["apt-cache", "policy", "opensearch"], policy("2.19.7", "2.19.7", [("2.19.7", 500)]))
    fake.on(["apt-cache", "policy", "mongodb-org-server"], policy("8.0.38", "8.0.38", [("8.0.38", 500)]))
    fake.on(["apt-cache", "policy", "logstash"], policy(None, None, []))
    fake.put(PREFS_PATH, PREFERENCES)
    fake.put("/var/lib/apt/lists/deb_Packages", "x", mtime=NOW - 3600)
    fake.put("/var/log/unattended-upgrades/unattended-upgrades.log", "x", mtime=NOW - 3600 * 6)
    fake.put("/var/log/oms-maj-siem.log", "2026-11-15 04:48:59 RESULTAT : OK\n")
    fake.put(CONFIG_BACKUP_GLOB.replace("*", "2026-11-21"), b"x", mtime=NOW - 3600 * 4)
    fake.put("/backup/mongo/graylog-mongo-20261121-0200.archive.gz", b"x", mtime=NOW - 3600 * 10)
    fake.put(str(source / "00-vars.env"), 'BACKUP_DIR="/backup"\nDATA_MOUNT="/data"\nGRAYLOG_ADMIN_PASS="not-read"\n')
    for path in ("/", "/var", "/data", "/backup"):
        fake.disks[path] = {"free": 50 * 1024 ** 3, "total": 100 * 1024 ** 3}
    fake.http[OPENSEARCH + "/_cluster/health"] = (200, '{"status": "green"}')
    fake.http[OPENSEARCH + "/"] = (200, '{"version": {"number": "2.19.7"}}')
    fake.http[GRAYLOG_API + "/system/lbstatus"] = (200, "ALIVE")
    fake.http[OPENSEARCH + "/_cat/snapshots/graylog_fs?format=json"] = (200, json.dumps(
        [{"id": "oms-sel-1", "status": "SUCCESS", "end_epoch": str(int(NOW - 3600 * 12))}]))
    return fake


@pytest.fixture
def repo(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "stack-versions.env").write_text("GRAYLOG_PACKAGE_VERSION=7.2.2-1\nOPENSEARCH_PACKAGE_VERSION=2.19.7\n"
                                              "MONGODB_PACKAGE_VERSION=8.0.38\n")
    return source


def real_files(fake, source):
    """Expose a real directory tree through the fake (reference inventories)."""
    for path in source.rglob("*"):
        if path.is_file():
            fake.files.setdefault(str(path), path.read_bytes())
    return fake


def test_json_document_has_a_stable_schema(repo, tmp_path):
    fake = real_files(healthy(repo), repo)
    report = status.collect(fake, repo, tmp_path / "updater")
    assert report["schema_version"] == 1
    assert report["read_only"] is True
    assert [entry["id"] for entry in report["layers"]] == list(status.LAYERS)
    for entry in report["layers"]:
        assert set(entry) == {"id", "title", "status", "summary", "items", "errors"}
        assert entry["status"] in status.RANK
        for element in entry["items"]:
            assert {"name", "status", "detail"} <= set(element)
            assert element["status"] in status.RANK
    assert report["overall"] == status.worst(e["status"] for e in report["layers"])
    json.loads(status.to_json(report))
    assert "not-read" not in status.to_json(report)


def test_collection_runs_only_read_only_commands(repo, tmp_path):
    fake = real_files(healthy(repo), repo)
    status.collect(fake, repo, tmp_path / "updater")
    for call in fake.calls:
        if call[0] == "git":
            assert set(call) & {"rev-parse", "status", "rev-list", "for-each-ref"}
            continue
        if call[-1] == "--version" or (len(call) > 2 and call[1:3] == ["-m", "pip"]):
            assert "install" not in call
            continue
        assert tuple(call[:2]) in READ_ONLY_COMMANDS, call
    assert not (tmp_path / "updater").exists()


def test_os_layer_counts_security_updates_and_reboot(repo):
    fake = healthy(repo)
    fake.put("/var/run/reboot-required", "")
    fake.put("/var/run/reboot-required.pkgs", "linux-image-6.12.118\n")
    entry = status.collect_os(fake)
    pending = entry["items"][0]
    assert pending["available"] == 3 and pending["security"] == 1 and pending["status"] == "attention"
    reboot = next(i for i in entry["items"] if i["name"] == "redémarrage requis")
    assert reboot["status"] == "attention" and "linux-image" in reboot["detail"]
    weekly = next(i for i in entry["items"] if "oms-maj-siem" in i["name"])
    assert weekly["status"] == "ok" and "04:39" in weekly["detail"]


@pytest.mark.parametrize("line,expected", [("RESULTAT : A VERIFIER", "attention"), ("RESULTAT : ANNULE (prealables)", "action"),
                                           ("RESULTAT : rien a faire", "ok")])
def test_weekly_update_result_is_reported(repo, line, expected):
    fake = healthy(repo)
    fake.put("/var/log/oms-maj-siem.log", "2026-11-15 04:48:59 " + line + "\n")
    weekly = next(i for i in status.collect_os(fake)["items"] if "oms-maj-siem" in i["name"])
    assert weekly["status"] == expected


def test_stale_apt_lists_and_auto_reboot_are_flagged(repo):
    fake = healthy(repo)
    fake.mtimes["/var/lib/apt/lists/deb_Packages"] = NOW - 86400 * 9
    fake.on(["apt-config", "dump"], APT_CONFIG.replace('Automatic-Reboot "false"', 'Automatic-Reboot "true"'))
    items = {i["name"]: i for i in status.collect_os(fake)["items"]}
    assert items["listes apt"]["status"] == "action"
    assert items["unattended-upgrades"]["status"] == "attention"


def test_stack_layer_compares_production_with_reference(repo):
    fake = real_files(healthy(repo), repo)
    entry = status.collect_stack(fake, repo)
    items = {i["name"]: i for i in entry["items"]}
    assert items["graylog-server"]["available"] == "7.2.2-2"
    assert items["graylog-server"]["status"] == "info"
    assert "7.3.0-1" in items["graylog-server"]["detail"]
    assert items["opensearch"]["held"] is True and items["opensearch"]["pin"] == "2.19.*"
    assert items["mongodb-org-server"]["status"] == "ok"
    assert entry["summary"] == "conforme à la référence"
    assert items["OpenSearch en service"]["status"] == "ok"


def test_stack_gap_with_reference_is_attention(repo):
    (repo / "stack-versions.env").write_text("GRAYLOG_PACKAGE_VERSION=7.2.3-1\nOPENSEARCH_PACKAGE_VERSION=2.19.7\nMONGODB_PACKAGE_VERSION=8.0.38\n")
    fake = real_files(healthy(repo), repo)
    entry = status.collect_stack(fake, repo)
    assert entry["status"] == "attention"
    assert "graylog-server" in entry["summary"]


def test_pin_mirror_drift_is_detected(repo):
    (repo / "deploye/apt").mkdir(parents=True)
    (repo / "deploye/apt/oms-siem-series").write_text(PREFERENCES.replace("7.2.*", "7.1.*"))
    fake = real_files(healthy(repo), repo)
    mirror = next(i for i in status.collect_stack(fake, repo)["items"] if i["name"].startswith("miroir"))
    assert mirror["status"] == "attention"


def test_health_layer_requires_recent_verified_backup(repo):
    fake = healthy(repo)
    items = {i["name"]: i for i in status.collect_health(fake, repo)["items"]}
    assert items["sauvegarde de configuration vérifiée"]["status"] == "ok"
    assert items["snapshot OpenSearch"]["status"] == "ok"
    fake.on(["systemctl", "show", "omni-backup-config.service", "-p", "Result", "--value"], "exit-code\n")
    fake.http[OPENSEARCH + "/_cluster/health"] = (200, '{"status": "red"}')
    fake.mtimes["/backup/mongo/graylog-mongo-20261121-0200.archive.gz"] = NOW - 86400 * 99
    items = {i["name"]: i for i in status.collect_health(fake, repo)["items"]}
    assert items["sauvegarde de configuration vérifiée"]["status"] == "action"
    assert items["cluster OpenSearch"]["status"] == "action"
    assert items["mongodump natif (08-backup.sh)"]["status"] == "attention"


def test_snapshot_check_follows_repository_configured_for_oms_snap_siem(repo):
    fake = healthy(repo)
    fake.put("/etc/oms-snap-siem.conf", "GARDER=3\nDEPOT=graylog_fs_data\n")
    items = {i["name"]: i for i in status.collect_health(fake, repo)["items"]}
    assert items["snapshot OpenSearch"]["status"] == "inconnu"
    assert "graylog_fs_data" in items["snapshot OpenSearch"]["detail"]
    fake.http[OPENSEARCH + "/_cat/snapshots/graylog_fs_data?format=json"] = (200, json.dumps(
        [{"id": "oms-sel-2", "status": "SUCCESS", "end_epoch": str(int(NOW - 3600))}]))
    items = {i["name"]: i for i in status.collect_health(fake, repo)["items"]}
    assert items["snapshot OpenSearch"]["status"] == "ok"
    assert "dépôt graylog_fs_data" in items["snapshot OpenSearch"]["detail"]


def test_content_layer_reads_catalogue_and_manifest_drift(tmp_path):
    fake = FakeSystem()
    source = tmp_path
    fake.put(source / "integrations/catalog.json", json.dumps({"schema_version": 1, "modules": [{"id": "unifi", "manifest": "unifi/manifest.json"}]}))
    fake.put(source / "integrations/unifi/manifest.json", json.dumps({"id": "unifi", "revision": 3, "status": "preview"}))
    fake.put(source / "manifeste-deploye.txt", "# c\n/usr/local/sbin/a\tdeploye/sbin/a\n/usr/local/sbin/b\tdeploye/sbin/b\n/usr/local/sbin/c\tdeploye/sbin/c\n")
    fake.put("/usr/local/sbin/a", b"same")
    fake.put(source / "deploye/sbin/a", b"same")
    fake.put("/usr/local/sbin/b", b"prod")
    fake.put(source / "deploye/sbin/b", b"repo")
    entry = status.collect_content(fake, source, graylog={"unifi": 2})
    items = {i["name"]: i for i in entry["items"]}
    assert items["intégration unifi"]["status"] == "info" and "r2" in items["intégration unifi"]["detail"]
    manifest = items["code déployé (manifeste)"]
    assert manifest["identical"] == 1 and manifest["different"] == ["deploye/sbin/b"] and manifest["absent"] == ["/usr/local/sbin/c"]
    assert status.collect_content(fake, source)["items"][0]["detail"].endswith("GRAYLOG_API_TOKEN)")


def test_graylog_installations_use_get_only(monkeypatch):
    fake = FakeSystem()
    fake.http["http://127.0.0.1:9000/api/system/content_packs/*"] = (200, json.dumps({"installations": [{"content_pack_revision": 2}]}))
    result = status.graylog_installations(fake, "tok", source=ROOT)
    assert set(result) == {"watchguard", "unifi", "paloalto"} and set(result.values()) == {2}
    assert all(url.endswith("/installations") for url, _ in fake.http_calls)


def test_broken_layer_does_not_hide_the_others(repo, tmp_path, monkeypatch):
    fake = real_files(healthy(repo), repo)
    monkeypatch.setattr(status, "collect_os", lambda system: 1 / 0)
    report = status.collect(fake, repo, tmp_path / "u")
    os_layer = next(e for e in report["layers"] if e["id"] == "os")
    assert os_layer["status"] == "inconnu" and os_layer["errors"] == ["ZeroDivisionError"]
    assert next(e for e in report["layers"] if e["id"] == "stack")["status"] != "inconnu"


def test_code_layer_reports_local_changes_and_downloaded_candidate(tmp_path):
    def git(repo, *args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()
    source = tmp_path / "src"
    source.mkdir()
    git(source, "init", "-q")
    git(source, "config", "user.email", "t@example.invalid")
    git(source, "config", "user.name", "t")
    (source / "a.py").write_text("1\n")
    git(source, "add", ".")
    git(source, "commit", "-q", "-m", "a")
    base = git(source, "rev-parse", "HEAD")
    (source / "a.py").write_text("2\n")
    git(source, "commit", "-q", "-am", "b")
    newer = git(source, "rev-parse", "HEAD")
    git(source, "checkout", "-q", base)
    (source / "a.py").write_text("local\n")
    state = tmp_path / "state"
    subprocess.check_call(["git", "init", "-q", "--bare", str(state / "repository.git")])
    git(state / "repository.git", "fetch", "-q", str(source), newer)
    git(state / "repository.git", "update-ref", "refs/omni/candidates/" + newer, newer)
    from omni_update.system import System
    entry = status.collect_code(System(), source, state)
    items = {i["name"]: i for i in entry["items"]}
    assert items["révision installée"]["local_changes"] == 1
    assert items["candidat téléchargé"]["available"] == newer


def test_text_rendering_lists_every_layer(repo, tmp_path):
    fake = real_files(healthy(repo), repo)
    text = status.render_text(status.collect(fake, repo, tmp_path / "u"))
    for title in status.TITLES.values():
        assert title in text
    assert "lecture seule" in text


@pytest.mark.parametrize("a,b,expected", [("7.1.10-1", "7.1.9-1", 1), ("1:8.19.25-1", "8.19.99", 1), ("2.19.7", "2.19.7", 0),
                                          ("1.0~rc1", "1.0", -1), ("7.2.2-1", "7.2.2-2", -1), ("1.0a", "1.0+", -1),
                                          ("8.0.38", "8.0.4", 1)])
def test_debian_version_ordering(a, b, expected):
    assert versions.compare(a, b) == expected


def test_pin_evaluation():
    stanzas = versions.parse_preferences(PREFERENCES)
    assert versions.allowed_by_pin(stanzas, "graylog-server", "7.2.9-1") is True
    assert versions.allowed_by_pin(stanzas, "graylog-server", "7.3.0-1") is False
    assert versions.allowed_by_pin(stanzas, "mongodb-org-tools", "8.0.40") is True
    assert versions.allowed_by_pin(stanzas, "nginx", "1.0") is None
    assert versions.pinned_pattern(stanzas, "mongodb-org-server") == "8.0.*"


def test_status_cli_json_is_parseable(monkeypatch, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("omni_status_cli", ROOT / "tools/omni-update-status.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    fake = FakeSystem()
    monkeypatch.setattr(cli, "System", lambda: fake)
    assert cli.main(["--json", "--layer", "content", "--exit-code"]) in (0, 1)
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == 1 and [e["id"] for e in data["layers"]] == ["content"]


@pytest.mark.parametrize("journal,expected", [
    ("2026-11-11 06:01:11 === oms-maj-siem --simuler (h) ===\n", "attention"),
    ("2026-11-15 04:38:41 === oms-maj-siem normal (h) ===\n", None),
])
def test_missed_weekly_run_is_detected(repo, journal, expected):
    import datetime as dt
    fake = healthy(repo)
    last = dt.datetime(2026, 11, 15, 4, 38, 41).timestamp()
    for clock, verdict in ((last + 86400 * 6, "ok"), (last + 86400 * 9, "attention")):
        fake.clock = clock
        fake.put("/var/log/oms-maj-siem.log", journal + "2026-11-15 04:48:59 RESULTAT : OK\n")
        check = next(i for i in status.collect_os(fake)["items"] if i["name"] == "passage réel d'oms-maj-siem")
        assert check["status"] == (expected or verdict)
        if expected is None and verdict == "attention":
            assert "Persistent=false" in check["detail"]


def test_stale_threat_intel_feed_is_flagged():
    fake = FakeSystem()
    fake.put("/etc/graylog/lookup/ti-c2-ip.csv", "ip,malware\n1.2.3.4,QakBot\n", mtime=NOW - 3600)
    fake.put("/etc/graylog/lookup/ti-mal-domain.csv", "domain,source\na.example,urlhaus\n", mtime=NOW - 86400 * 31)
    items = {i["name"]: i for i in status.threat_intel_feeds(fake)}
    assert items["flux CTI Feodo Tracker (IP de C2)"]["status"] == "ok"
    stale = items["flux CTI URLhaus (domaines malveillants)"]
    assert stale["status"] == "attention" and "figé" in stale["detail"]
    fake.put("/etc/graylog/lookup/ti-c2-ip.csv", "ip,malware\n", mtime=NOW - 3600)
    assert status.threat_intel_feeds(fake)[0]["status"] == "attention"
