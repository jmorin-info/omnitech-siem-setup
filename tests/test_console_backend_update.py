"""Managed backend activation preserves tenant edits and restores failed updates."""
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("backend_activate", Path(__file__).resolve().parents[1] / "tools/manage-console-backend.py")
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


@pytest.fixture
def managed(tmp_path):
    directory = tmp_path / "app"
    directory.mkdir()
    target = directory / "omni-mobile-api.py"
    target.write_text("VERSION = 1\n")
    (directory / "backend.json").write_text(json.dumps({"sha256": backend.digest(target)}))
    source = tmp_path / "candidate.py"
    source.write_text("VERSION = 2\n")
    return source, directory, target


def test_activate_records_verified_code(managed):
    source, directory, target = managed
    assert backend.activate(source, directory, restart=lambda: None, health=lambda: None)
    assert target.read_bytes() == source.read_bytes()
    assert json.loads((directory / "backend.json").read_text())["sha256"] == backend.digest(target)


def test_local_edit_blocks_activation(managed):
    source, directory, target = managed
    target.write_text("TENANT = True\n")
    with pytest.raises(ValueError, match="local changes"):
        backend.activate(source, directory)
    assert "TENANT" in target.read_text()


def test_failed_health_restores_old_backend_and_metadata(managed):
    source, directory, target = managed
    before = (directory / "backend.json").read_bytes()
    restarts = []
    def fail():
        raise RuntimeError("health failure")
    with pytest.raises(RuntimeError, match="health failure"):
        backend.activate(source, directory, restart=lambda: restarts.append(True), health=fail)
    assert target.read_text() == "VERSION = 1\n"
    assert (directory / "backend.json").read_bytes() == before
    assert len(restarts) == 2
