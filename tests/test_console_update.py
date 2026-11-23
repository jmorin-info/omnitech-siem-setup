"""Mise à jour en un clic (omni_update/console.py) : détection, plan, application et retour arrière.

Tout est hors ligne : dépôt « GitHub » factice (dépôt nu local) joint par
url.<base>.insteadOf (l'URL HTTPS attendue reste celle contrôlée par l'outil), dépôt
installé temporaire, racine de déploiement factice (omni-deploy n'y lance aucune commande
système), systemctl factice, sondes HTTP et contrôle de santé injectés.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy import engine as deploy_engine  # noqa: E402
from omni_update import console  # noqa: E402
from omni_update.system import System  # noqa: E402

REMOTE = "https://git.example.invalid/omni/omnitech-siem-setup.git"
RID = "20261123-100000-0000000a"
RID2 = "20261123-110000-0000000b"

FAKE_SYSTEMCTL = r'''#!/usr/bin/env python3
import os, sys
d = os.path.dirname(os.path.abspath(__file__))
def lst(name):
    try:
        return [l.strip() for l in open(os.path.join(d, name)) if l.strip()]
    except OSError:
        return []
a = sys.argv[1:]
open(os.path.join(d, "systemctl.log"), "a").write(" ".join(a) + "\n")
if a[0] == "is-active":
    if a[-1] in lst("active"):
        print("active"); sys.exit(0)
    print("inactive"); sys.exit(3)
if a[0] == "restart":
    if a[-1] in lst("fail-restart"):        # panne ponctuelle : le redémarrage suivant réussit
        open(os.path.join(d, "fail-restart"), "w").write("\n".join(u for u in lst("fail-restart") if u != a[-1]))
        sys.exit(1)
    sys.exit(0)
if a[0] == "list-units":
    state = [x.split("=", 1)[1] for x in a if x.startswith("--state=")][0]
    for u in lst(state):
        print(u + " loaded " + state + " x")
    sys.exit(0)
if a[0] == "show":
    print("success"); sys.exit(0)
'''

CONSOLE_FILES = ["index.html", "app-boot.js", "app-csp.js", "app-loader.js", "app.js", "app-v3.js", "chart.min.js",
                 "sw.js", "manifest.webmanifest", "icons/icon-192.png"]


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL,
                                   env={**os.environ, "LC_ALL": "C"}).decode().strip()


def write(repo, name, text, mode=0o644):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def commit(repo, message):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class FakeSystem(System):
    def __init__(self):
        self.opensearch = "green"

    def http_get(self, url, headers=None, timeout=10):
        if url.endswith("/_cluster/health"):
            return 200, json.dumps({"status": self.opensearch})
        if url.endswith("/system/lbstatus"):
            return 200, "ALIVE"
        return None, ""

    def hostname(self):
        return "hote-de-test"


class Health:
    """Contrôle de santé injecté : en échec à partir de l'appel n° fail_from (1 = premier)."""

    def __init__(self):
        self.calls = 0
        self.fail_from = None

    def __call__(self):
        self.calls += 1
        bad = self.fail_from is not None and self.calls >= self.fail_from
        return {"checks": [{"name": "service:oms-demo.service", "status": "echec" if bad else "ok"},
                           {"name": "opensearch:sante", "status": "ok"}]}


@pytest.fixture
def env(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "user.name", "Tests")
    git(work, "config", "user.email", "tests@example.invalid")
    write(work, "manifeste-deploye.txt", "# manifeste de test\n"
          "/etc/systemd/system/oms-demo.service\tdeploye/systemd/oms-demo.service\n"
          "/usr/local/sbin/omni-demo\tdeploye/sbin/omni-demo\n")
    write(work, "deploye/sbin/omni-demo", "#!/bin/sh\necho v1\n", 0o755)
    write(work, "deploye/systemd/oms-demo.service",
          "[Service]\nExecStart=/usr/bin/python3 /opt/omni-siem/repository/oms-demo/run.py\n")
    write(work, "oms-demo/run.py", "print('v1')\n")
    write(work, "run-tests.sh", "#!/usr/bin/env bash\necho suite factice\ntest ! -f FAIL-TESTS\n", 0o755)
    write(work, "CHANGELOG.md", "# Journal\n\n## [Non publié]\n")
    write(work, ".gitignore", "__pycache__/\n.venv/\n00-vars.env\n")
    write(work, "tools/deploy-console.py", (ROOT / "tools/deploy-console.py").read_text(encoding="utf-8"), 0o755)
    for name in CONSOLE_FILES:
        write(work, "mobile/soc/" + name, f"/* {name} v1 */\n")
    write(work, "integrations/catalog.json", json.dumps({"schema_version": 1, "modules": [
        {"id": "watchguard", "manifest": "watchguard/manifest.json"}]}))
    write(work, "integrations/watchguard/manifest.json",
          (ROOT / "integrations/watchguard/manifest.json").read_text(encoding="utf-8"))
    v1 = commit(work, "v1")
    mirror = tmp_path / "mirror.git"
    subprocess.check_call(["git", "clone", "-q", "--bare", str(work), str(mirror)])
    home = tmp_path / "home" / "repository"
    home.parent.mkdir()
    subprocess.check_call(["git", "clone", "-q", str(mirror), str(home)])
    git(home, "remote", "set-url", "origin", REMOTE)
    git(home, "config", "user.name", "Tests")
    git(home, "config", "user.email", "tests@example.invalid")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.file://" + str(mirror) + ".insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", REMOTE)
    # v2 publiée sur le « GitHub » factice
    write(work, "deploye/sbin/omni-demo", "#!/bin/sh\necho v2\n", 0o755)
    write(work, "oms-demo/run.py", "print('v2')\n")
    write(work, "mobile/soc/app.js", "/* app.js v2 */\n")
    write(work, "CHANGELOG.md", "# Journal\n\n## [Non publié]\n\n- Nouveauté de la v2.\n")
    v2 = commit(work, "v2 : robot et console")
    git(work, "push", "-q", str(mirror), "main")
    sysd = tmp_path / "sysd"
    sysd.mkdir()
    (sysd / "systemctl").write_text(FAKE_SYSTEMCTL)
    (sysd / "systemctl").chmod(0o755)
    (sysd / "active").write_text("oms-demo.service\n")
    backup = tmp_path / "backups"
    backup.mkdir()
    (backup / "omni-siem-config_test.tar.gz.enc").write_bytes(b"x")
    variables = {
        "UPDATE_REPO": str(home), "UPDATE_EXPECTED_REMOTE": REMOTE, "UPDATE_STATE_DIR": str(tmp_path / "state"),
        "SOC_ADMIN_DIR": str(tmp_path / "admin"), "UPDATE_DEPLOY_ROOT": str(tmp_path / "root"),
        "UPDATE_DEPLOY_STATE": str(tmp_path / "deploy-state"), "UPDATE_SYSTEMCTL": str(sysd / "systemctl"),
        "UPDATE_TEST_PYTHON": sys.executable, "UPDATE_TEST_USER": "aucun", "UPDATE_TEST_TIMEOUT": "120",
        "UPDATE_BACKUP_GLOB": str(backup / "omni-siem-config_*.tar.gz.enc"), "UPDATE_DISK_PATHS": str(tmp_path),
        "UPDATE_SETTLE_SECONDS": "0", "UPDATE_GIT_TIMEOUT": "60", "OMNI_TEST_MODE": "1"}
    cfg = console.load_config(str(tmp_path / "absent.conf"), variables)
    # production factice alignée sur v1 (moteur omni-deploy réel, racine factice)
    deploy_engine.Deployer(home, home=home, root=str(tmp_path / "root"),
                           state_dir=str(tmp_path / "deploy-state")).apply(["robots", "systemd", "console"])
    health = Health()
    updater = console.ConsoleUpdater(cfg, system=FakeSystem(), health=health, sleep=lambda s: None)
    return {"tmp": tmp_path, "work": work, "mirror": mirror, "home": home, "root": tmp_path / "root", "v1": v1,
            "v2": v2, "cfg": cfg, "updater": updater, "health": health, "sysd": sysd}


def robot(e):
    return (e["root"] / "usr/local/sbin/omni-demo").read_text()


def app_js(e):
    return (e["root"] / "var/www/siem-soc/app.js").read_text()


def submit(e, kind="update_apply", rid=RID, params=None, request=None):
    cfg = e["cfg"]
    if params is None:
        params = {"target": e["v2"], "confirm": e["v2"][:12], "console": True, "restart": True, "modules": [],
                  "plan_read": True}
    req = {"id": rid, "action": kind, "params": params, "status": "transmise", "self_service": True,
           "requested_by": "alice", "decided_by": "alice", "motif": "mise à jour mensuelle"}
    req.update(request or {})
    (cfg["admin_dir"] / "requests").mkdir(parents=True, exist_ok=True)
    (cfg["admin_dir"] / "requests" / (rid + ".json")).write_text(json.dumps(req))
    queue = cfg["state"] / "queue"
    queue.mkdir(parents=True, exist_ok=True)
    (queue / (rid + ".json")).write_text(json.dumps({"id": rid, "kind": kind, "params": params}))
    return e["updater"].run_queue()[0]


def published(e, name):
    return json.loads((e["cfg"]["admin_dir"] / "update" / name).read_text())


# ------------------------------------------------------------------ détection et plan
def test_check_detects_update_without_touching_the_worktree(env):
    report = env["updater"].check()
    assert report["fetch"]["ok"] is True and report["update_available"] is True
    assert report["installed"]["rev"] == env["v1"] and report["available"]["rev"] == env["v2"]
    assert report["can_apply"] is True, report["blocking"]
    assert [c["subject"] for c in report["commits"]] == ["v2 : robot et console"]
    assert "- Nouveauté de la v2." in report["changelog"]
    cats = report["changes"]["categories"]
    assert cats["robots"] == ["deploye/sbin/omni-demo"] and cats["console"] == ["mobile/soc/app.js"]
    assert report["restarts"] == ["oms-demo.service"]
    assert report["tests"]["status"] == "ok"
    assert report["options"]["console"]["available"] is True
    assert report["options"]["modules"][0]["installable"] is False      # aucun jeton : jamais installable
    # lecture seule : HEAD, arbre et production inchangés ; état publié pour la console
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]
    assert git(env["home"], "status", "--porcelain") == ""
    assert robot(env) == "#!/bin/sh\necho v1\n"
    assert published(env, "status.json")["available"]["short"] == env["v2"][:12]


def test_tests_are_cached_per_candidate(env):
    env["updater"].check()
    marker = env["cfg"]["state"] / "tests" / (env["v2"] + ".json")
    first = json.loads(marker.read_text())["at"]
    env["updater"].check()
    assert json.loads(marker.read_text())["at"] == first


def test_dirty_tree_blocks(env):
    (env["home"] / "oms-demo/run.py").write_text("print('modifié localement')\n")
    report = env["updater"].check()
    arbre = [c for c in report["checks"] if c["id"] == "arbre"][0]
    assert arbre["status"] == "echec" and report["can_apply"] is False


def test_divergent_history_is_refused(env):
    write(env["home"], "local.txt", "commit local\n")
    commit(env["home"], "commit local non poussé")
    report = env["updater"].check()
    assert report["can_apply"] is False
    assert [c for c in report["checks"] if c["id"] == "avance_rapide"][0]["status"] == "echec"


def test_modified_remote_cannot_be_used_as_source(env):
    git(env["home"], "remote", "set-url", "origin", "https://git.example.invalid/autre/depot.git")
    report = env["updater"].check()
    assert report["fetch"]["ok"] is False and report["fetch"]["error"] == "remote_refuse"
    assert report["can_apply"] is False


def test_token_in_insteadof_is_refused(env, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "url.https://user:s3cr3t-valeur@git.example.invalid/.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "https://autre.invalid/")
    report = env["updater"].check()
    assert report["fetch"]["error"] == "remote_refuse"
    assert "s3cr3t" not in json.dumps(report)


def test_unreachable_remote_is_classified(env, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.https://127.0.0.1:9/x.git.insteadOf")   # port fermé
    report = env["updater"].check()
    assert report["fetch"]["ok"] is False and report["fetch"]["error"] == "network_unavailable"
    assert report["can_apply"] is False


def test_failing_candidate_tests_block(env):
    write(env["work"], "FAIL-TESTS", "1\n")
    commit(env["work"], "casse les tests")
    git(env["work"], "push", "-q", str(env["mirror"]), "main")
    report = env["updater"].check()
    assert report["tests"]["status"] == "echec" and report["can_apply"] is False
    assert "suite factice" in "\n".join(report["tests"]["tail"])


@pytest.mark.parametrize("path", ["requirements.txt", "python-locks/mobile.txt", "stack-versions.env", "migrations/001.sql"])
def test_manual_review_changes_refuse_one_click(env, path):
    write(env["work"], path, "x==1\n")
    commit(env["work"], "changement sensible")
    git(env["work"], "push", "-q", str(env["mirror"]), "main")
    report = env["updater"].check(run_tests=False)
    assert path in report["changes"]["categories"]["revue_manuelle"] and report["can_apply"] is False


def test_numbered_scripts_are_reported_never_run(env):
    write(env["work"], "42-nouveau.sh", "#!/bin/sh\ntouch " + str(env["tmp"] / "LANCE") + "\n", 0o755)
    commit(env["work"], "script numéroté")
    git(env["work"], "push", "-q", str(env["mirror"]), "main")
    report = env["updater"].check()
    assert report["changes"]["categories"]["scripts_numerotes"] == ["42-nouveau.sh"]
    assert report["can_apply"] is True
    target = report["available"]["rev"]
    params = {"target": target, "confirm": target[:12], "console": True, "restart": True, "modules": [], "plan_read": True}
    assert submit(env, params=params)["status"] == "terminee"
    assert not (env["tmp"] / "LANCE").exists()


def test_dynamic_prerequisites_block(env):
    env["updater"].system.opensearch = "yellow"
    (env["sysd"] / "activating").write_text("omni-m365-fetch.service\nomni-console-update.service\n")
    report = env["updater"].check()
    states = {c["id"]: c["status"] for c in report["checks"]}
    assert states["opensearch"] == "echec" and states["activation"] == "echec"
    detail = [c for c in report["checks"] if c["id"] == "activation"][0]["detail"]
    assert "omni-console-update" not in detail          # sa propre unité est ignorée


# ------------------------------------------------------------------ application et retours arrière
def test_apply_then_manual_rollback(env):
    env["updater"].check()
    result = submit(env)
    assert result["status"] == "terminee", published(env, "run.json")
    assert git(env["home"], "rev-parse", "HEAD") == env["v2"]
    assert robot(env) == "#!/bin/sh\necho v2\n" and app_js(env) == "/* app.js v2 */\n"
    assert "restart -- oms-demo.service" in (env["sysd"] / "systemctl.log").read_text()
    run = published(env, "run.json")
    assert run["prev_rev"] == env["v1"] and run["rollback_available"] is True
    assert [s["id"] for s in run["steps"]] == ["recherche", "verifications", "sauvegarde", "fusion", "deploiement",
                                               "console", "redemarrages", "sante"]
    assert git(env["home"], "rev-parse", "refs/omni-console-update/avant-" + RID) == env["v1"]
    # une tentative refusée ensuite (rien à appliquer) n'empêche pas d'annuler la mise à jour effective
    again = {"target": env["v2"], "confirm": env["v2"][:12], "console": True, "restart": True, "modules": [],
             "plan_read": True}
    assert submit(env, rid="20261123-103000-0000000e", params=again)["status"] == "refusee"
    assert published(env, "last_apply.json")["id"] == RID
    # retour arrière manuel de la dernière mise à jour
    params = {"run_id": RID, "confirm": env["v1"][:12]}
    result = submit(env, "update_rollback", RID2, params)
    assert result["status"] == "restauree", published(env, "run.json")
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]
    assert robot(env) == "#!/bin/sh\necho v1\n" and app_js(env) == "/* app.js v1 */\n"
    # une seconde demande de retour arrière est sans objet
    assert submit(env, "update_rollback", "20261123-120000-0000000c", params)["status"] == "refusee"


def _fail_deploy(monkeypatch, components):
    original = deploy_engine.Deployer.apply

    def apply(self, wanted, pattern=None):
        if list(wanted) == components:
            raise deploy_engine.DeployError("panne simulée")
        return original(self, wanted, pattern)
    monkeypatch.setattr(deploy_engine.Deployer, "apply", apply)


@pytest.mark.parametrize("step", ["fusion", "deploiement", "console", "redemarrages", "sante"])
def test_failure_at_each_step_rolls_back_everything(env, monkeypatch, step):
    env["updater"].check()
    if step == "fusion":
        original = console.git

        def failing(cfg, *args, **kw):
            if args and args[0] == "merge":
                raise console.OU.UpdateError("Git operation failed: merge (git_error)")
            return original(cfg, *args, **kw)
        monkeypatch.setattr(console, "git", failing)
    elif step == "deploiement":
        _fail_deploy(monkeypatch, ["robots", "apt", "systemd"])
    elif step == "console":
        _fail_deploy(monkeypatch, ["console"])
    elif step == "redemarrages":
        (env["sysd"] / "fail-restart").write_text("oms-demo.service\n")
    else:
        env["health"].fail_from = 2          # santé correcte avant, régression après
    result = submit(env)
    run = published(env, "run.json")
    assert result["status"] == "annulee", run
    failed = [s for s in run["steps"] if s["status"] == "echec"]
    assert failed and failed[0]["id"] == step
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]
    assert git(env["home"], "status", "--porcelain") == ""
    assert robot(env) == "#!/bin/sh\necho v1\n" and app_js(env) == "/* app.js v1 */\n"
    assert any(s["id"] == "rb:git" and s["status"] == "ok" for s in run["steps"])


def test_rollback_refused_when_tree_changed_since_update(env):
    env["updater"].check()
    assert submit(env)["status"] == "terminee"
    (env["home"] / "oms-demo/run.py").write_text("print('retouche')\n")
    result = submit(env, "update_rollback", RID2, {"run_id": RID, "confirm": env["v1"][:12]})
    assert result["status"] == "refusee"
    assert git(env["home"], "rev-parse", "HEAD") == env["v2"]


def test_rollback_requires_matching_confirmation(env):
    env["updater"].check()
    submit(env)
    result = submit(env, "update_rollback", RID2, {"run_id": RID, "confirm": "0" * 12})
    assert result["status"] == "refusee" and git(env["home"], "rev-parse", "HEAD") == env["v2"]


@pytest.mark.parametrize("change", [
    {"request": {"self_service": False}},
    {"request": {"status": "en_attente"}},
    {"request": {"decided_by": "mallory"}},
    {"request": {"params": {"target": "0" * 40}}},
    {"params": {"confirm": "ffffffffffff"}},
    {"params": {"plan_read": False}},
    {"params": {"modules": ["../etc"]}},
])
def test_invalid_or_tampered_jobs_are_refused(env, change):
    env["updater"].check()
    params = {"target": env["v2"], "confirm": env["v2"][:12], "console": True, "restart": True, "modules": [],
              "plan_read": True}
    params.update(change.get("params", {}))
    request = dict(change.get("request", {}))
    if "params" in request:
        request["params"] = dict(params, **request["params"])
    result = submit(env, params=params, request=request)
    assert result["status"] == "refusee"
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]


def test_target_not_on_branch_is_refused(env):
    write(env["work"], "x.txt", "branche annexe\n")
    git(env["work"], "checkout", "-q", "-b", "annexe")
    other = commit(env["work"], "hors main")
    git(env["work"], "push", "-q", str(env["mirror"]), "annexe")
    params = {"target": other, "confirm": other[:12], "console": True, "restart": True, "modules": [], "plan_read": True}
    assert submit(env, params=params)["status"] == "refusee"
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]


def test_uninstallable_module_option_is_refused(env):
    env["updater"].check()
    params = {"target": env["v2"], "confirm": env["v2"][:12], "console": True, "restart": True,
              "modules": ["watchguard"], "plan_read": True}
    assert submit(env, params=params)["status"] == "refusee"
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]


def test_concurrent_update_is_refused_by_lock(env):
    env["cfg"]["state"].mkdir(parents=True, exist_ok=True)
    with open(env["cfg"]["state"] / "update.lock", "a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        assert submit(env)["status"] == "refusee"
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]


def test_interrupted_update_blocks_and_can_be_rolled_back(env):
    env["updater"].check()
    git(env["home"], "merge", "-q", "--ff-only", env["v2"])           # coupure juste après la fusion
    state = env["cfg"]["state"]
    run = {"id": RID, "kind": "apply", "status": "en_cours", "target": env["v2"], "prev_rev": env["v1"],
           "deploy_transactions": [], "restarted": [], "was_active": [], "steps": []}
    (state / "runs").mkdir(parents=True, exist_ok=True)
    for path in (state / "run.json", state / "runs" / (RID + ".json")):
        path.write_text(json.dumps(run))
    report = env["updater"].check(do_fetch=False, run_tests=False)
    assert report["last_run"]["status"] == "interrompue"
    assert published(env, "run.json")["status"] == "interrompue"
    result = submit(env, "update_rollback", RID2, {"run_id": RID, "confirm": env["v1"][:12]})
    assert result["status"] == "restauree"
    assert git(env["home"], "rev-parse", "HEAD") == env["v1"]


def test_config_refuses_production_paths_in_test_mode(tmp_path):
    with pytest.raises(console.ConsoleUpdateError):
        console.load_config(str(tmp_path / "absent.conf"), {"OMNI_TEST_MODE": "1", "UPDATE_STATE_DIR": str(tmp_path)})
    with pytest.raises(console.ConsoleUpdateError):
        console.load_config(str(tmp_path / "absent.conf"), {"OMNI_TEST_MODE": "1", "UPDATE_REPO": str(tmp_path),
                                                             "UPDATE_STATE_DIR": str(tmp_path / "s"),
                                                             "SOC_ADMIN_DIR": str(tmp_path / "a"),
                                                             "UPDATE_DEPLOY_ROOT": "/"})


def test_config_refuses_credentials_in_expected_remote(tmp_path):
    with pytest.raises(console.ConsoleUpdateError):
        console.load_config(str(tmp_path / "absent.conf"), {"UPDATE_EXPECTED_REMOTE": "https://x" + ":jeton" + "@github.com/a/b.git",
                                                             "UPDATE_STATE_DIR": str(tmp_path / "s")})


def test_units_are_versioned_and_listed():
    manifest = (ROOT / "manifeste-deploye.txt").read_text(encoding="utf-8")
    for name in ("omni-console-update.service", "omni-console-update.path", "omni-console-update-check.service",
                 "omni-console-update-check.timer", "omni-console-update-check.path"):
        assert f"/etc/systemd/system/{name}\tdeploye/systemd/{name}" in manifest
    check = (ROOT / "deploye/systemd/omni-console-update-check.service").read_text(encoding="utf-8")
    assert "check --from-request" in check and "ProtectSystem=full" in check
    assert "/var/lib/omni-console-update/queue" in (ROOT / "deploye/systemd/omni-console-update.path").read_text()


def test_cli_status_is_read_only(env, tmp_path):
    conf = tmp_path / "cli.conf"
    conf.write_text("\n".join(f"{k}={v}" for k, v in {
        "UPDATE_REPO": env["home"], "UPDATE_STATE_DIR": env["cfg"]["state"], "SOC_ADMIN_DIR": env["cfg"]["admin_dir"],
        "UPDATE_DEPLOY_ROOT": env["root"], "UPDATE_EXPECTED_REMOTE": REMOTE}.items()) + "\n")
    out = subprocess.run([sys.executable, str(ROOT / "tools/omni-console-update.py"), "--config", str(conf), "status"],
                         capture_output=True, text=True, timeout=60, env={**os.environ, "OMNI_TEST_MODE": "1"})
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["locked"] is False


@pytest.mark.parametrize("stderr,reason", [
    ("git@github.com: Permission denied (publickey).", "authentication_required"),
    ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", "authentication_required"),
    ("Host key verification failed.", "host_key_unverified"),
])
def test_git_failures_are_classified_without_echo(stderr, reason):
    assert console.OU.classify_git_error(stderr) == reason


def test_module_status_uses_read_token_and_offers_only_uninstalled_modules(env, tmp_path):
    secret_file = tmp_path / "graylog.tok"
    secret_file.write_text("valeur-de-test\n")
    env["cfg"].update(integration_token_file=str(secret_file), integration_api="http://127.0.0.1:9000/api",
                      integration_bind="192.0.2.10")
    seen = []

    def http_get(url, headers=None, timeout=10):
        if "/system/content_packs/" in url:
            seen.append(headers["Authorization"])
            return 200, json.dumps({"installations": []})
        return FakeSystem.http_get(env["updater"].system, url, headers, timeout)
    env["updater"].system.http_get = http_get
    report = env["updater"].check(run_tests=False)
    module = report["options"]["modules"][0]
    assert module["installed"] is False and module["installable"] is True
    import base64
    assert base64.b64decode(seen[0].split()[1]).decode() == "valeur-de-test:" + "token"
    assert "valeur-de-test" not in json.dumps(report)
