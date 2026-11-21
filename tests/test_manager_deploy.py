"""Entrées du gestionnaire SSH pour le déploiement et le contrôle de santé : argv fermés."""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from manager.operations import DEPLOY_COMPONENTS, Manager, WRITES
from manager.cli import ACTION_LABELS, DEPLOY_LABELS
from omni_deploy.engine import COMPONENTS

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def manager(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    return Manager(source, tmp_path / "state", tmp_path / "update-state")


def test_component_lists_stay_aligned_with_the_engine():
    assert set(DEPLOY_COMPONENTS) == {"all", *COMPONENTS}
    assert set(DEPLOY_LABELS) == set(DEPLOY_COMPONENTS)
    for action in ("deploy_plan", "deploy_apply", "deploy_rollback_plan", "deploy_rollback", "deploy_history", "health_check"):
        assert action in ACTION_LABELS


def test_plan_and_apply_build_closed_argv(manager):
    argv, env = manager.command("deploy_plan", {"component": "robots"})
    assert argv[1].endswith("tools/omni-deploy.py") and argv[-2:] == ["deploy", "robots"] and env == {}
    assert argv[argv.index("--home") + 1] == str(manager.source)
    argv, _ = manager.command("deploy_apply", {"component": "all"})
    assert argv[-3:] == ["deploy", "all", "--apply"]
    argv, _ = manager.command("deploy_rollback_plan", {"transaction": "a" * 32})
    assert argv[-2:] == ["rollback", "a" * 32]
    argv, _ = manager.command("deploy_rollback", {"transaction": "b" * 32})
    assert argv[-3:] == ["rollback", "b" * 32, "--apply"]
    argv, _ = manager.command("health_check", {})
    assert argv[1].endswith("tools/omni-healthcheck.py") and "--apply" not in argv


@pytest.mark.parametrize("action,params", [
    ("deploy_plan", {"component": "robots; reboot"}), ("deploy_apply", {"component": "../etc"}),
    ("deploy_apply", {"component": "robots", "root": "/"}), ("deploy_rollback", {"transaction": "../../x"}),
    ("deploy_rollback", {"transaction": "A" * 32}), ("health_check", {"config": "/etc/shadow"}),
])
def test_unknown_parameters_never_start_a_process(manager, monkeypatch, action, params):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("ne doit pas s'exécuter"))
    with pytest.raises(ValueError):
        manager.run(action, params, confirmed=True)


def test_writes_require_confirmation_and_reads_do_not(manager):
    assert {"deploy_apply", "deploy_rollback"} <= WRITES
    assert not {"deploy_plan", "deploy_rollback_plan", "deploy_history", "health_check"} & WRITES
    with pytest.raises(ValueError, match="confirmation"):
        manager.run("deploy_apply", {"component": "robots"})
    with pytest.raises(ValueError, match="confirmation"):
        manager.run("deploy_rollback", {"transaction": "c" * 32}, confirmed="OUI")
