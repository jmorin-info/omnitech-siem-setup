"""SSH manager entries for the update layers: closed argv, read-only, no stack execution."""
import builtins
import subprocess
import sys

import pytest

from manager.cli import ACTION_LABELS, Terminal
from manager.operations import ACTIONS, WRITES, Manager, UPDATE_LAYER_ACTIONS


@pytest.fixture
def manager(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    return Manager(source, tmp_path / "state", tmp_path / "update-state")


def test_update_layer_actions_are_registered_read_only_and_labelled():
    assert set(UPDATE_LAYER_ACTIONS) <= set(ACTIONS)
    assert not set(UPDATE_LAYER_ACTIONS) & WRITES
    assert all(action in ACTION_LABELS for action in UPDATE_LAYER_ACTIONS)


def test_status_and_audit_commands(manager):
    argv, env = manager.command("status_all", {})
    assert argv == [sys.executable, str(manager.source / "tools/omni-update-status.py"), "--source", str(manager.source),
                    "--updater-state-dir", str(manager.updater_state)] and env == {}
    argv, _ = manager.command("pydeps_audit", {})
    assert argv == [sys.executable, str(manager.source / "tools/omni-pydeps.py"), "audit"]


def test_stack_plan_command_is_plan_only(manager):
    argv, _ = manager.command("stack_plan", {"component": "graylog", "target": "7.2.2-2"})
    assert argv == [sys.executable, str(manager.source / "tools/omni-stack-upgrade.py"), "plan", "--component", "graylog",
                    "--to", "7.2.2-2"]
    assert "--execute" not in argv and "apply" not in argv


@pytest.mark.parametrize("params", [{"component": "postgres", "target": "1"}, {"component": "graylog", "target": "7.2; reboot"},
                                    {"component": "graylog", "target": "--execute"}, {"component": "graylog"},
                                    {"component": "graylog", "target": "7.2.2-2", "execute": True}])
def test_invalid_stack_parameters_never_start_a_process(manager, monkeypatch, params):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(ValueError):
        manager.run("stack_plan", params)


def test_menu_entries_route_to_read_only_actions(tmp_path, monkeypatch, capsys):
    terminal = Terminal.__new__(Terminal)
    terminal.manager = Manager(tmp_path / "s", tmp_path / "st", tmp_path / "u")
    called = []
    terminal.run = lambda action, params=None: called.append((action, params)) or {"status": "success"}
    answers = iter(["opensearch", "2.19.8"])
    monkeypatch.setattr(builtins, "input", lambda *_: next(answers))
    terminal.update_layers(10)
    terminal.update_layers(12)
    terminal.update_layers(11)
    assert called == [("status_all", None), ("pydeps_audit", None),
                      ("stack_plan", {"component": "opensearch", "target": "2.19.8"})]
    output = capsys.readouterr().out
    assert "tmux" in output and "--confirm opensearch=2.19.8" in output
