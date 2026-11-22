"""Plan, sauvegarde, application et retour arrière de omni-deploy, en racine factice."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

import omni_deploy.engine as engine_module

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy.engine import (DEFAULT_HOME, LEGACY_HOME, PLACEHOLDER, Deployer, DeployError,  # noqa: E402
                                parse_manifest)

LONG_UNIT = "[Service]\nExecStart=/usr/local/sbin/omni-demo --serve\n[Install]\nWantedBy=multi-user.target\n"
ONESHOT_UNIT = "[Service]\nType=oneshot\nExecStart=/usr/local/sbin/omni-batch\n"
TIMER = "[Timer]\nOnCalendar=hourly\n"


class FakeRunner:
    """Consigne les commandes ; échoue une fois sur demande ; simule la création d'un venv."""

    def __init__(self, fail=(), inactive=()):
        self.calls, self.fail, self.inactive = [], set(fail), set(inactive)

    def __call__(self, argv, timeout=900):
        self.calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-active"]:
            return (3, "inactive") if argv[2] in self.inactive else (0, "active")
        for key in (tuple(argv[:2]), tuple(argv[:3])):
            if key in self.fail:
                self.fail.discard(key)  # échec unique : la commande réussit au retour arrière
                return 1, "échec simulé"
        if argv[1:3] == ["-m", "venv"]:
            (Path(argv[3]) / "bin").mkdir(parents=True)
            (Path(argv[3]) / "bin/python").write_text("")
        return 0, ""


def write(path: Path, text: str, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "repo"
    write(repo / "deploye/sbin/omni-demo", "#!/bin/sh\necho demo /opt/omni-siem/repository/00-vars.env\n", 0o755)
    write(repo / "deploye/sbin/omni-batch", "#!/bin/sh\necho batch\n", 0o755)
    write(repo / "deploye/systemd/omni-demo.service", LONG_UNIT)
    write(repo / "deploye/systemd/omni-batch.service", ONESHOT_UNIT)
    write(repo / "deploye/systemd/omni-batch.timer", TIMER)
    write(repo / "deploye/systemd/omni-demo.service.d/hardening.conf", "[Service]\nNoNewPrivileges=true\n")
    write(repo / "deploye/nginx/omni-sec-headers.conf", "add_header X-Test 1;\n")
    write(repo / "deploye/apt/oms-siem-series", "Package: graylog-server\nPin: version 7.2.*\n")
    for name in ("mobile", "oms-xdr", "oms-graph", "oms-ml"):
        (repo / name).mkdir(parents=True, exist_ok=True)
    for name in ("mobile", "oms-xdr", "oms-graph", "oms-ml"):
        write(repo / name / "requirements.txt", "requests>=2.31\n")
    lines = ["# test",
             "/usr/local/sbin/omni-demo\tdeploye/sbin/omni-demo",
             "/usr/local/sbin/omni-batch\tdeploye/sbin/omni-batch",
             "/etc/systemd/system/omni-demo.service\tdeploye/systemd/omni-demo.service",
             "/etc/systemd/system/omni-batch.service\tdeploye/systemd/omni-batch.service",
             "/etc/systemd/system/omni-batch.timer\tdeploye/systemd/omni-batch.timer",
             "/etc/systemd/system/omni-demo.service.d/hardening.conf\tdeploye/systemd/omni-demo.service.d/hardening.conf",
             "/etc/nginx/snippets/omni-sec-headers.conf\tdeploye/nginx/omni-sec-headers.conf",
             "/etc/apt/preferences.d/oms-siem-series\tdeploye/apt/oms-siem-series"]
    write(repo / "manifeste-deploye.txt", "\n".join(lines) + "\n")
    return repo


def make(source, tmp_path, runner=None, home=None):
    return Deployer(source, home=home or source, root=tmp_path / "root", runner=runner or FakeRunner())


def files_of(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "omni-siem-deploy" not in p.parts)


def test_plan_is_read_only_and_lists_actions(source, tmp_path):
    deployer = make(source, tmp_path)
    plan = deployer.plan(["robots", "systemd", "nginx"])
    assert not (tmp_path / "root").exists()
    assert {item["state"] for item in plan["files"]} == {"creer"}
    assert "systemctl daemon-reload" in plan["actions"]
    assert any(action.startswith("nginx -t") for action in plan["actions"])
    assert deployer.run_command.calls == []
    # Le dépôt de test n'est pas le dépôt canonique : simple avertissement en racine factice.
    assert not plan["blockers"]


def test_all_excludes_apt_unless_explicit(source, tmp_path):
    deployer = make(source, tmp_path)
    assert "apt" not in deployer.normalize(["all"])
    assert deployer.normalize(["apt"]) == ["apt"]
    assert "apt" in deployer.normalize(["all", "apt"])
    with pytest.raises(DeployError, match="composant inconnu"):
        deployer.normalize(["shell"])


def test_apply_creates_files_with_modes_and_is_idempotent(source, tmp_path):
    deployer = make(source, tmp_path)
    report = deployer.apply(["robots", "systemd", "nginx"])
    root = tmp_path / "root"
    assert report["transaction"] and report["result"] == "appliqué"
    assert (root / "usr/local/sbin/omni-demo").stat().st_mode & 0o777 == 0o755
    assert (root / "etc/systemd/system/omni-demo.service").stat().st_mode & 0o777 == 0o644
    assert (root / "etc/systemd/system/omni-demo.service.d/hardening.conf").is_file()
    again = deployer.plan(["robots", "systemd", "nginx"])
    assert {item["state"] for item in again["files"]} == {"identique"}
    second = deployer.apply(["robots", "systemd", "nginx"])
    assert second["transaction"] is None and second["result"] == "rien à déployer"
    assert len(deployer.history()) == 1


def test_replacement_is_backed_up_and_rollback_restores_bytes_and_mode(source, tmp_path):
    root = tmp_path / "root"
    original = write(root / "usr/local/sbin/omni-demo", "#!/bin/sh\necho ancienne version\n", 0o700)
    deployer = make(source, tmp_path)
    plan = deployer.plan(["robots"])
    assert {i["target"]: i["state"] for i in plan["files"]}["/usr/local/sbin/omni-demo"] == "remplacer"
    transaction = deployer.apply(["robots"])["transaction"]
    assert "demo" in original.read_text() and original.stat().st_mode & 0o777 == 0o700
    journal = json.loads((deployer.state / "transactions" / transaction / "journal.json").read_text())
    record = next(r for r in journal["files"] if r["target"] == "/usr/local/sbin/omni-demo")
    backup = deployer.state / "transactions" / transaction / record["backup"]
    assert backup.read_text() == "#!/bin/sh\necho ancienne version\n"
    steps = deployer.rollback(transaction)["steps"]
    assert {"target": "/usr/local/sbin/omni-demo", "operation": "restaurer"} in steps
    assert {"target": "/usr/local/sbin/omni-batch", "operation": "supprimer"} in steps
    result = deployer.rollback(transaction, apply=True)
    assert result["status"] == "restauree" and not result["problems"]
    assert original.read_text() == "#!/bin/sh\necho ancienne version\n"
    assert original.stat().st_mode & 0o777 == 0o700
    assert not (root / "usr/local/sbin/omni-batch").exists()
    with pytest.raises(DeployError, match="déjà restaurée"):
        deployer.rollback(transaction, apply=True)


def test_rollback_refuses_files_changed_after_transaction(source, tmp_path):
    deployer = make(source, tmp_path)
    transaction = deployer.apply(["robots"])["transaction"]
    write(tmp_path / "root/usr/local/sbin/omni-demo", "modifié à la main\n", 0o755)
    plan = deployer.rollback(transaction)
    assert plan["conflicts"] == ["/usr/local/sbin/omni-demo : modifié depuis la transaction"]
    with pytest.raises(DeployError, match="refusé"):
        deployer.rollback(transaction, apply=True)
    assert (tmp_path / "root/usr/local/sbin/omni-demo").read_text() == "modifié à la main\n"


def test_failed_post_action_rolls_everything_back(source, tmp_path):
    root = tmp_path / "root"
    previous = write(root / "etc/nginx/snippets/omni-sec-headers.conf", "add_header X-Old 1;\n")
    runner = FakeRunner(fail={("nginx", "-t")})
    deployer = make(source, tmp_path, runner)
    with pytest.raises(DeployError, match="annulé"):
        deployer.apply(["robots", "nginx"])
    assert previous.read_text() == "add_header X-Old 1;\n"
    assert not (root / "usr/local/sbin/omni-demo").exists()
    assert ["systemctl", "reload", "nginx"] not in runner.calls[:runner.calls.index(["nginx", "-t"])]
    status = deployer.history()[0]["status"]
    assert status == "annulee_automatiquement"
    assert not (deployer.state / "deploy.lock").exists()


def test_restarts_only_long_running_units_and_changed_timers(source, tmp_path):
    deployer = make(source, tmp_path)
    plan = deployer.plan(["robots", "systemd"])
    assert plan["restarts"] == ["omni-batch.timer", "omni-demo.service"]
    # Robot seul : seul le service long qui l'exécute est concerné ; le oneshot attend son timer.
    root = tmp_path / "root"
    write(root / "usr/local/sbin/omni-batch", "ancien\n", 0o755)
    write(root / "usr/local/sbin/omni-demo", "ancien\n", 0o755)
    deployer.apply(["systemd"])
    write(root / "usr/local/sbin/omni-demo", "ancien\n", 0o755)
    plan = deployer.plan(["robots"])
    assert plan["restarts"] == ["omni-demo.service"]


def test_system_mode_skips_inactive_services(source, tmp_path):
    runner = FakeRunner(inactive={"omni-demo.service"})
    deployer = make(source, tmp_path, runner)
    deployer.system = True  # comportement système, cibles toujours sous la racine factice
    deployer.source = deployer.home = source.resolve()
    journal = {"id": "a" * 32, "files": [], "venvs": []}
    deployer.state.mkdir(parents=True, mode=0o700)
    deployer._post_actions(journal, {"systemd"}, ["omni-demo.service"])
    assert ["systemctl", "restart", "omni-demo.service"] not in runner.calls
    assert "non redémarré (inactif) : omni-demo.service" in journal["actions"]


@pytest.mark.parametrize("content,reason", [
    (f"#!/bin/sh\n. {LEGACY_HOME}/00-vars.env\n", "ancien chemin"),
    (f"url=https://user:{PLACEHOLDER}@host/\n", "mot de passe masqué"),
])
def test_unsafe_sources_block_the_whole_deployment(source, tmp_path, content, reason):
    write(source / "deploye/sbin/omni-batch", content, 0o755)
    deployer = make(source, tmp_path)
    plan = deployer.plan(["robots"])
    assert any(reason in blocker for blocker in plan["blockers"])
    with pytest.raises(DeployError, match="refusé"):
        deployer.apply(["robots"])
    assert not (tmp_path / "root/usr/local/sbin").exists()


def test_symlinked_target_is_refused(source, tmp_path):
    root = tmp_path / "root"
    (root / "usr/local/sbin").mkdir(parents=True)
    (root / "usr/local/sbin/omni-demo").symlink_to(tmp_path / "ailleurs")
    plan = make(source, tmp_path).plan(["robots"])
    assert any("lien symbolique" in blocker for blocker in plan["blockers"])


def test_target_inside_canonical_home_is_refused(source, tmp_path):
    home = tmp_path / "root/opt/omni-siem/repository"
    home.mkdir(parents=True)
    with open(source / "manifeste-deploye.txt", "a", encoding="utf-8") as stream:
        stream.write("/opt/omni-siem/repository/x\tdeploye/sbin/omni-demo\n")
    deployer = Deployer(source, home="/opt/omni-siem/repository", root=tmp_path / "root", runner=FakeRunner())
    deployer.home = home
    plan = deployer.plan(["opt"])
    assert any("dépôt canonique" in blocker for blocker in plan["blockers"])


def test_home_is_rendered_into_deployed_files(source, tmp_path):
    deployer = make(source, tmp_path, home="/srv/omni")
    deployer.apply(["robots"])
    text = (tmp_path / "root/usr/local/sbin/omni-demo").read_text()
    assert "/srv/omni/00-vars.env" in text and DEFAULT_HOME not in text


def test_manifest_parser_rejects_unsafe_lines():
    entries, errors = parse_manifest("\n".join([
        "/usr/local/sbin/a\tdeploye/sbin/a", "/usr/local/sbin/a\tdeploye/sbin/b", "/root/x\tdeploye/x",
        "relative\tdeploye/x", "/usr/local/sbin/../x\tdeploye/x", "/usr/local/sbin/c\t/abs/c", "sans-tabulation"]))
    assert len(entries) == 2
    assert len(errors) == 6
    assert any("double" in e for e in errors)


def test_venvs_are_built_marked_and_rolled_back(source, tmp_path):
    runner = FakeRunner()
    deployer = make(source, tmp_path, runner)
    states = {item["venv"]: item["state"] for item in deployer.plan(["venvs"])["venvs"]}
    assert set(states.values()) == {"construire"}
    first = deployer.apply(["venvs"])["transaction"]
    assert {item["state"] for item in deployer.plan(["venvs"])["venvs"]} == {"identique"}
    assert any(call[-2:] == ["-r", str(source / "oms-ml/requirements.txt")] for call in runner.calls)
    write(source / "oms-ml/requirements.txt", "requests>=2.31\nnumpy>=1.26\n")
    states = {item["venv"]: item["state"] for item in deployer.plan(["venvs"])["venvs"]}
    assert states["oms-ml"] == "reconstruire" and states["oms-xdr"] == "identique"
    (source / "oms-ml/.venv/ancien").write_text("x")
    second = deployer.apply(["venvs"])["transaction"]
    assert not (source / "oms-ml/.venv/ancien").exists()
    assert list(source.glob("oms-ml/.venv.prev-*"))
    deployer.rollback(second, apply=True)
    assert (source / "oms-ml/.venv/ancien").exists() and not list(source.glob("oms-ml/.venv.prev-*"))
    assert first != second


def test_failed_venv_build_restores_previous_venv(source, tmp_path):
    runner = FakeRunner()
    deployer = make(source, tmp_path, runner)
    deployer.apply(["venvs"])
    (source / "mobile/.venv/garde").write_text("x")
    write(source / "oms-ml/requirements.txt", "numpy>=1.26\n")
    (source / "oms-ml/.venv/garde").write_text("x")
    runner.fail = {(str(source / "oms-ml/.venv/bin/python"), "-m")}
    with pytest.raises(DeployError, match="annulé"):
        deployer.apply(["venvs"])
    assert (source / "oms-ml/.venv/garde").exists()


def test_lock_prevents_concurrent_runs(source, tmp_path):
    deployer = make(source, tmp_path)
    deployer.state.mkdir(parents=True, mode=0o700)
    (deployer.state / "deploy.lock").write_text("123")
    with pytest.raises(DeployError, match="en cours"):
        deployer.apply(["robots"])


def test_real_repository_plan_in_fake_root_covers_console_assets(tmp_path):
    deployer = Deployer(ROOT, home=ROOT, root=tmp_path / "root", runner=FakeRunner())
    # SEAL SLA has a separate runtime, outside the canonical repository.
    missing = deployer.plan(["all"])
    # Hors racine factice, le moteur accepte un exécutable présent sur l'hôte (cas du serveur
    # de production, où ce runtime existe) : le blocage n'est attendu que s'il est absent.
    host_has_runtime = Path("/opt/oms-seal-sla/.venv/bin/python").exists()
    expected = [] if host_has_runtime else ["oms-seal-sla.service : exécutable /opt/oms-seal-sla/.venv/bin/python absent"]
    assert missing["blockers"] == expected
    write(tmp_path / "root/opt/oms-seal-sla/.venv/bin/python", "", 0o755)
    plan = deployer.plan(["all"])
    assert not plan["blockers"], plan["blockers"]
    console = [item for item in plan["files"] if item["component"] == "console"]
    manifest_console = sum(1 for line in (ROOT / "manifeste-deploye.txt").read_text().splitlines()
                           if line.startswith("/var/www/"))
    assert len(console) > manifest_console
    targets = [item["target"] for item in console if item["target"].startswith("/var/www/siem-soc/")]
    assert targets[-1] == "/var/www/siem-soc/sw.js" and targets[-2] == "/var/www/siem-soc/index.html"
    assert not any(item["component"] == "apt" for item in plan["files"])


def test_manifest_check_passes_on_repository():
    result = subprocess.run([sys.executable, str(ROOT / "tools/check-manifest.py")], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout


def test_cli_plan_and_apply_in_fake_root(tmp_path):
    tool = [sys.executable, str(ROOT / "tools/omni-deploy.py"), "--root", str(tmp_path / "root"), "--home", str(ROOT)]
    plan = subprocess.run(tool + ["deploy", "robots"], capture_output=True, text=True)
    assert plan.returncode == 0 and "Plan seul" in plan.stdout
    assert not (tmp_path / "root/usr").exists()
    applied = subprocess.run(tool + ["deploy", "robots", "--apply", "--json"], capture_output=True, text=True)
    assert applied.returncode == 0, applied.stderr
    transaction = json.loads(applied.stdout)["transaction"]
    rollback = subprocess.run(tool + ["rollback", transaction, "--apply"], capture_output=True, text=True)
    assert rollback.returncode == 0 and "restauree" in rollback.stdout
    sbin = tmp_path / "root/usr/local/sbin"
    assert not sbin.exists() or not any(sbin.iterdir())


def test_identical_unit_with_wrong_mode_is_fixed_and_rollback_restores_mode(source, tmp_path):
    root = tmp_path / "root"
    unit = write(root / "etc/systemd/system/omni-demo.service", LONG_UNIT, 0o600)
    deployer = make(source, tmp_path)
    plan = deployer.plan(["systemd"], "*/omni-demo.service")
    assert [item["state"] for item in plan["files"]] == ["droits"]
    assert plan["restarts"] == []  # un changement de droits ne redémarre rien
    transaction = deployer.apply(["systemd"], "*/omni-demo.service")["transaction"]
    assert unit.stat().st_mode & 0o777 == 0o644 and unit.read_text() == LONG_UNIT
    assert deployer.rollback(transaction)["steps"] == [{"target": "/etc/systemd/system/omni-demo.service",
                                                         "operation": "restaurer_droits"}]
    deployer.rollback(transaction, apply=True)
    assert unit.stat().st_mode & 0o777 == 0o600


def test_unit_carrying_a_secret_keeps_its_restrictive_mode(source, tmp_path):
    text = "[Service]\nEnvironment=API_TOKEN=valeur\nExecStart=/usr/local/sbin/omni-demo\n"
    write(source / "deploye/systemd/omni-demo.service", text)
    write(tmp_path / "root/etc/systemd/system/omni-demo.service", text, 0o600)
    plan = make(source, tmp_path).plan(["systemd"], "*/omni-demo.service")
    assert plan["files"][0]["state"] == "identique"


def test_filter_limits_targets(source, tmp_path):
    plan = make(source, tmp_path).plan(["robots", "systemd"], "*/omni-batch*")
    assert {item["target"] for item in plan["files"]} == {
        "/usr/local/sbin/omni-batch", "/etc/systemd/system/omni-batch.service", "/etc/systemd/system/omni-batch.timer"}


def test_unit_pointing_to_missing_venv_is_blocked_unless_built_together(source, tmp_path):
    home = source
    write(source / "deploye/systemd/omni-demo.service.d/50-depot-reference.conf",
          f"[Service]\nExecStart=\nExecStart={home}/oms-ml/.venv/bin/python -m oms_ml.run\n")
    with open(source / "manifeste-deploye.txt", "a", encoding="utf-8") as stream:
        stream.write("/etc/systemd/system/omni-demo.service.d/50-depot-reference.conf\t"
                     "deploye/systemd/omni-demo.service.d/50-depot-reference.conf\n")
    deployer = make(source, tmp_path)
    plan = deployer.plan(["systemd"])
    assert any("venv" in blocker and "absent" in blocker for blocker in plan["blockers"])
    together = deployer.plan(["venvs", "systemd"])
    assert not any("venv" in blocker for blocker in together["blockers"])
    assert "omni-demo.service" in together["restarts"]


def test_legacy_reference_in_base_unit_is_a_warning_not_a_blocker(source, tmp_path):
    write(source / "deploye/systemd/omni-batch.service", f"[Service]\nType=oneshot\nExecStart=/bin/bash {LEGACY_HOME}/x.sh\n")
    plan = make(source, tmp_path).plan(["robots", "systemd"])
    assert not plan["blockers"]
    assert next(i for i in plan["files"] if i["target"].endswith("omni-batch.service")).get("note")


def test_unit_whose_executable_is_missing_is_blocked(source, tmp_path):
    deployer = make(source, tmp_path)
    plan = deployer.plan(["systemd"])
    assert "omni-demo.service : exécutable /usr/local/sbin/omni-demo absent" in plan["blockers"]
    with pytest.raises(DeployError, match="refusé"):
        deployer.apply(["systemd"])
    assert not (tmp_path / "root/etc").exists()
    assert not deployer.plan(["robots", "systemd"])["blockers"]


def test_dropin_reset_defines_the_effective_executable(source, tmp_path):
    write(source / "deploye/systemd/omni-demo.service.d/50-depot-reference.conf",
          "[Service]\nExecStart=\nExecStart=/opt/autre/bin/python app.py\n")
    assert make(source, tmp_path).effective_exec("omni-demo.service") == ["/opt/autre/bin/python"]


def test_restarted_service_that_fails_triggers_rollback_and_restart(source, tmp_path, monkeypatch):
    monkeypatch.setattr(engine_module, "SETTLE_SECONDS", 0)
    monkeypatch.setattr(engine_module.os, "geteuid", lambda: 0)  # CI sans root : cibles en racine factice

    class Flapping(FakeRunner):
        def __init__(self):
            super().__init__()
            self.restarted = 0

        def __call__(self, argv, timeout=900):
            if argv[:2] == ["systemctl", "restart"]:
                self.restarted += 1
            if argv[:2] == ["systemctl", "is-active"] and self.restarted == 1:
                self.calls.append(list(argv))
                return 3, "failed"
            return super().__call__(argv, timeout)

    root = tmp_path / "root"
    write(root / "usr/local/sbin/omni-demo", "ancien\n", 0o755)
    runner = Flapping()
    deployer = make(source, tmp_path, runner)
    deployer.system = True
    with pytest.raises(DeployError, match="annulé"):
        deployer.apply(["robots"])
    assert (root / "usr/local/sbin/omni-demo").read_text() == "ancien\n"
    assert runner.restarted == 2  # relancé au retour arrière car il tournait avant
    assert deployer.history()[0]["status"] == "annulee_automatiquement"
