"""Relocalisation du dépôt de snapshots (tools/migrer-depot-snapshots.sh), hors ligne.

OpenSearch, systemctl, df et journalctl sont simulés : aucun appel réseau, aucune
écriture hors du répertoire temporaire.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "migrer-depot-snapshots.sh"
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("jq"), reason="Bash/jq requis")

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
state_path = os.environ["FAKE_STATE"]
state = json.load(open(state_path))
out = args[args.index("-o") + 1]
method = args[args.index("-X") + 1] if "-X" in args else "GET"
url = next(a for a in args if a.startswith("http"))
path = url.split("9200", 1)[1] or "/"
data = args[args.index("-d") + 1] if "-d" in args else None
with open(os.environ["FAKE_CALLS"], "a") as log:
    log.write(json.dumps([method, path]) + "\n")
def reply(code, body):
    open(out, "w").write(json.dumps(body) if not isinstance(body, str) else body)
    json.dump(state, open(state_path, "w"))
    sys.stdout.write(str(code)); sys.exit(0)
if not state.get("up", True):
    sys.stdout.write("000"); sys.exit(7)
if path == "/":
    reply(200, {"name": "fake"})
if path == "/_cluster/health":
    reply(200, {"status": state["health"]})
if path == "/_snapshot/_status":
    reply(200, {"snapshots": [{}] * state.get("running", 0)})
if path.startswith("/_cat/indices"):
    reply(200, "omni-winsec_1 4102444800000 1073741824\nomni-autre_1 4102444800000 1073741824\n")
if path == "/_nodes/settings":
    ligne = next(l for l in open(os.environ["OPENSEARCH_YML"]) if l.startswith("path.repo"))
    repo = json.loads(ligne.split(":", 1)[1]) if state.get("restarted") else state["repo_at_boot"]
    reply(200, {"nodes": {"n1": {"settings": {"path": {"repo": repo}}}}})
m = re.fullmatch(r"/_snapshot/([^/]+)(/.*)?", path)
if m:
    repo, rest = m.group(1), m.group(2) or ""
    repos = state["repos"]
    if rest == "" and method == "GET":
        reply(200, {repo: repos[repo]}) if repo in repos else reply(404, {"error": "repository_missing"})
    if rest == "" and method == "PUT":
        body = json.loads(data)
        loc = body["settings"]["location"]
        ligne = next(l for l in open(os.environ["OPENSEARCH_YML"]) if l.startswith("path.repo"))
        if loc not in json.loads(ligne.split(":", 1)[1]) or not state.get("restarted"):
            reply(500, {"error": "repository_exception: location not in path.repo"})
        repos[repo] = body; state["snaps"].setdefault(repo, [])
        reply(200, {"acknowledged": True})
    if rest == "" and method == "DELETE":
        repos.pop(repo, None); reply(200, {"acknowledged": True})
    if rest == "/_verify":
        reply(200, {"nodes": {}})
    if rest == "/_all":
        reply(200, {"snapshots": state["snaps"].get(repo, [])})
reply(404, {"error": "unexpected " + method + " " + path})
'''

FAKE_SYSTEMCTL = r'''#!/usr/bin/env python3
import json, os, re, sys
state_path = os.environ["FAKE_STATE"]
state = json.load(open(state_path))
args = sys.argv[1:]
with open(os.environ["FAKE_CALLS"], "a") as log:
    log.write(json.dumps(["systemctl"] + args) + "\n")
if args[0] == "is-active":
    print("inactive"); sys.exit(3)
if args[:2] == ["restart", "opensearch.service"]:
    state["restarts"] = state.get("restarts", 0) + 1
    state["restarted"] = True
    state["up"] = not os.environ.get("FAKE_RESTART_DOWN")
if args[:2] == ["start", "oms-snap-siem.service"]:
    conf = open(os.environ["SNAP_CONF"]).read()
    repo = re.search(r"^DEPOT=(.*)$", conf, re.M).group(1)
    snaps = state["snaps"].setdefault(repo, [])
    snaps.append({"snapshot": "oms-sel-2026112%d-0130" % len(snaps), "state": "SUCCESS", "shards": {"failed": 0}})
json.dump(state, open(state_path, "w"))
'''

FAKE_DF = r'''#!/bin/bash
case "$*" in
  *pcent*) printf 'Uti%%\n 40%%\n' ;;
  *avail*) printf 'Disp\n 4000G\n' ;;
  *size*) printf 'Taille\n 7300G\n' ;;
esac
'''

SNAP_BIN_NEW = 'REPO="$DEPOT"\n'


@pytest.fixture
def env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("curl", FAKE_CURL), ("systemctl", FAKE_SYSTEMCTL), ("df", FAKE_DF),
                       ("journalctl", "#!/bin/bash\nexit 0\n"), ("sleep", "#!/bin/bash\nexit 0\n")):
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    yml = tmp_path / "opensearch.yml"
    yml.write_text('cluster.name: graylog\npath.repo: ["/home/siem-backup/opensearch-snapshots"]\nhttp.port: 9200\n')
    conf = tmp_path / "oms-snap-siem.conf"
    conf.write_text('GARDER=3\nLIBRE_MIN_PCT=15\nSELECTION="omni-winsec:21 gl-events:0"\n')
    snap_bin = tmp_path / "oms-snap-siem"
    snap_bin.write_text(SNAP_BIN_NEW)
    new_path = tmp_path / "data" / "siem-backup" / "opensearch-snapshots"
    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "health": "green", "repo_at_boot": ["/home/siem-backup/opensearch-snapshots"],
        "repos": {"graylog_fs": {"type": "fs", "settings": {"location": "/home/siem-backup/opensearch-snapshots"}}},
        "snaps": {"graylog_fs": [{"snapshot": "oms-sel-20261122-0130", "state": "SUCCESS", "shards": {"failed": 0}}]}}))
    calls = tmp_path / "calls.jsonl"
    variables = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_STATE": str(state),
                 "FAKE_CALLS": str(calls), "OPENSEARCH_YML": str(yml), "SNAP_CONF": str(conf),
                 "SNAP_BIN": str(snap_bin), "MIGR_ETAT": str(tmp_path / "etat"),
                 "NOUVEAU_CHEMIN": str(new_path), "POINT_MONTAGE": "/", "MIGR_TEST_MODE": "1",
                 "OMNI_SIEM_HOME": str(tmp_path / "absent"), "ATTENTE_API_S": "0", "ATTENTE_VERT_S": "0"}

    def run(*args, **extra):
        return subprocess.run(["bash", str(SCRIPT), *args], env={**variables, **extra},
                              capture_output=True, text=True, timeout=60)

    def read_state():
        return json.loads(state.read_text())

    def methods():
        if not calls.exists():
            return []
        return [json.loads(line) for line in calls.read_text().splitlines()]

    return {"run": run, "state": read_state, "calls": methods, "yml": yml, "conf": conf,
            "snap_bin": snap_bin, "new": new_path, "tmp": tmp_path}


def test_plan_is_read_only(env):
    before = (env["yml"].read_text(), env["conf"].read_text())
    result = env["run"]()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "redémarrage d'OpenSearch nécessaire" in result.stdout
    assert "premier snapshot complet estimé : ~1 Go" in result.stdout
    assert (env["yml"].read_text(), env["conf"].read_text()) == before
    assert all(call[0] == "GET" for call in env["calls"]() if call[0] != "systemctl")
    assert not any(call[:2] == ["systemctl", "restart"] for call in env["calls"]())
    assert not env["new"].exists()


def test_plan_blocks_when_robot_not_deployed(env):
    env["snap_bin"].write_text("REPO=graylog_fs\n")
    result = env["run"]()
    assert result.returncode == 2
    assert "ne gère pas DEPOT" in result.stdout


def test_apply_keeps_old_path_registers_new_repo_and_switches_config(env):
    result = env["run"]("--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    line = next(l for l in env["yml"].read_text().splitlines() if l.startswith("path.repo"))
    assert json.loads(line.split(":", 1)[1]) == ["/home/siem-backup/opensearch-snapshots", str(env["new"])]
    assert "cluster.name: graylog" in env["yml"].read_text()
    state = env["state"]()
    assert state["restarts"] == 1
    assert set(state["repos"]) == {"graylog_fs", "graylog_fs_data"}
    assert state["repos"]["graylog_fs_data"]["settings"] == {"location": str(env["new"]), "compress": True}
    conf = env["conf"].read_text()
    assert f"DEPOT=graylog_fs_data\nDEPOT_CHEMIN={env['new']}\n" in conf
    assert "LIBRE_MIN_PCT=25" in conf and "LIBRE_ARRET_PCT=15" in conf and "LIBRE_MIN_PCT=15" not in conf
    assert len(state["snaps"]["graylog_fs_data"]) == 1
    assert len(state["snaps"]["graylog_fs"]) == 1          # ancien dépôt intact
    assert not any(c[0] == "DELETE" for c in env["calls"]())
    # Idempotence : second passage sans redémarrage.
    again = env["run"]("--apply", "--sans-snapshot")
    assert again.returncode == 0, again.stdout + again.stderr
    assert env["state"]()["restarts"] == 1
    assert env["conf"].read_text().count("DEPOT=") == 1


def test_apply_restores_configuration_when_opensearch_does_not_come_back(env):
    original = env["yml"].read_text()
    result = env["run"]("--apply", FAKE_RESTART_DOWN="1")
    assert result.returncode != 0
    assert "configuration d'origine restaurée" in result.stderr
    assert env["yml"].read_text() == original
    assert env["state"]()["restarts"] == 2
    assert "DEPOT=" not in env["conf"].read_text()


def test_apply_refused_when_cluster_not_green(env):
    state = env["state"]()
    state["health"] = "yellow"
    (env["tmp"] / "state.json").write_text(json.dumps(state))
    result = env["run"]("--apply")
    assert result.returncode != 0
    assert "restart" not in json.dumps(env["calls"]())


def test_retirement_requires_three_successful_snapshots(env):
    assert env["run"]("--apply").returncode == 0
    refused = env["run"]("--retirer-ancien")
    assert refused.returncode != 0
    assert "1 snapshot(s) oms-sel réussi(s), 3 requis" in refused.stdout
    assert "graylog_fs" in env["state"]()["repos"]
    for _ in range(2):
        subprocess.run(["systemctl", "start", "oms-snap-siem.service"], env={
            **os.environ, "PATH": f"{env['tmp'] / 'bin'}:{os.environ['PATH']}",
            "FAKE_STATE": str(env["tmp"] / "state.json"), "FAKE_CALLS": str(env["tmp"] / "calls.jsonl"),
            "SNAP_CONF": str(env["conf"])}, check=True)
    accepted = env["run"]("--retirer-ancien")
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert set(env["state"]()["repos"]) == {"graylog_fs_data"}
    assert "rm -rf" in accepted.stdout          # affiché, jamais exécuté


def test_rollback_restores_config_and_unregisters_new_repo(env):
    before = env["conf"].read_text()
    assert env["run"]("--apply").returncode == 0
    result = env["run"]("--rollback")
    assert result.returncode == 0, result.stdout + result.stderr
    assert env["conf"].read_text() == before
    assert set(env["state"]()["repos"]) == {"graylog_fs"}
    assert env["state"]()["restarts"] == 1          # pas de redémarrage sans --avec-redemarrage
    full = env["run"]("--rollback", "--avec-redemarrage")
    assert full.returncode == 0, full.stdout + full.stderr
    assert str(env["new"]) not in env["yml"].read_text()
    assert env["state"]()["restarts"] == 2


def test_oms_snap_siem_reads_repository_from_configuration(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "curl").write_text('#!/bin/bash\necho "$@" >> "$FAKE_CALLS"\necho \'{"snapshots":[]}\'\n')
    (bindir / "curl").chmod(0o755)
    conf = tmp_path / "conf"
    conf.write_text(f"DEPOT=graylog_fs_data\nDEPOT_CHEMIN={tmp_path}\n")
    calls = tmp_path / "calls"
    result = subprocess.run(["bash", str(ROOT / "deploye" / "sbin" / "oms-snap-siem"), "--etat"],
                            env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_CALLS": str(calls),
                                 "OMS_SNAP_CONF": str(conf), "OMS_SNAP_ETAT": str(tmp_path / "etat"),
                                 "OMS_SNAP_JOURNAL": str(tmp_path / "log")},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "/_snapshot/graylog_fs_data/_all" in calls.read_text()
    assert f"{tmp_path} libre" in result.stdout
