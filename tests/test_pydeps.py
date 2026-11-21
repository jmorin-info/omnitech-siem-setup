"""Python venv lock files and drift audit (offline, fake pip)."""
import json
from pathlib import Path

import pytest

from omni_update import pydeps
from update_fakes import FakeSystem

ROOT = Path(__file__).resolve().parents[1]
ENTRY = {"id": "oms-xdr", "requirements": "oms-xdr/requirements.txt", "lock": "python-locks/oms-xdr.txt",
         "venv_candidates": ["/missing/.venv", "/srv/oms-xdr/.venv"], "ignore": ["oms-xdr"]}


def host(installed, lock="requests==2.34.2\npyyaml==6.0.3\n", requirements="requests>=2.31\nPyYAML>=6.0\n"):
    fake = FakeSystem()
    fake.put("/src/python-locks/oms-xdr.txt", lock) if lock is not None else None
    fake.put("/src/oms-xdr/requirements.txt", requirements)
    fake.put("/srv/oms-xdr/.venv/bin/python", "")
    fake.on(["/srv/oms-xdr/.venv/bin/python", "--version"], "Python 3.13.5\n")
    fake.on(["/srv/oms-xdr/.venv/bin/python", "-m", "pip", "list", "--format=json", "--disable-pip-version-check", "--no-input"],
            json.dumps([{"name": n, "version": v} for n, v in installed.items()]))
    return fake


def test_conforming_venv_is_ok_and_ignores_tooling_and_project():
    fake = host({"requests": "2.34.2", "PyYAML": "6.0.3", "pip": "26.1", "oms-xdr": "1.0.0"})
    result = pydeps.audit_venv(ENTRY, "/src", fake)
    assert result["status"] == "ok", result
    assert result["venv"] == "/srv/oms-xdr/.venv"
    assert result["unpinned_requirements"] == ["pyyaml", "requests"]


def test_drift_is_reported_in_detail():
    fake = host({"requests": "2.35.0", "urllib3": "2.7.0"})
    result = pydeps.audit_venv(ENTRY, "/src", fake)
    assert result["status"] == "attention"
    assert result["mismatched"] == [{"name": "requests", "locked": "2.34.2", "installed": "2.35.0"}]
    assert result["missing"] == ["pyyaml"]
    assert result["extra"] == ["urllib3"]


def test_missing_lock_and_missing_venv():
    assert pydeps.audit_venv(ENTRY, "/src", host({"requests": "1"}, lock=None))["detail"].startswith("aucun fichier")
    fake = host({})
    fake.files.pop("/srv/oms-xdr/.venv/bin/python")
    result = pydeps.audit_venv(ENTRY, "/src", fake)
    assert result["status"] == "attention" and result["venv"] is None
    assert pydeps.audit_venv({**ENTRY, "optional": True}, "/src", fake)["status"] == "info"


def test_requirement_absent_from_lock_is_flagged():
    fake = host({"requests": "2.34.2", "pyyaml": "6.0.3"}, requirements="requests\nPyYAML\nnumpy>=1\n")
    result = pydeps.audit_venv(ENTRY, "/src", fake)
    assert result["requirements_not_in_lock"] == ["numpy"]
    assert result["status"] == "attention"


def test_pip_is_called_offline():
    fake = host({"requests": "2.34.2", "pyyaml": "6.0.3"})
    pydeps.audit_venv(ENTRY, "/src", fake)
    pip_calls = [c for c in fake.calls if "pip" in c]
    assert pip_calls and all("install" not in c for c in pip_calls)


def test_lock_rendering_round_trips():
    text = pydeps.render_lock(ENTRY, {"requests": "2.34.2", "pip": "26", "oms-xdr": "1.0.0", "pyyaml": "6.0.3"}, "2026-11-21", "/srv")
    assert pydeps.parse_lock(text) == {"pyyaml": "6.0.3", "requests": "2.34.2"}
    assert text.startswith("# Verrouillage du venv oms-xdr")


def test_vulnerability_scan_is_explicit_and_degrades_without_pip_audit():
    fake = host({})
    assert pydeps.vulnerability_scan(ENTRY, "/src", fake)["status"] == "inconnu"
    fake.on(["pip-audit", "--version"], "pip-audit 2.9\n")
    fake.commands[("pip-audit", "--requirement", "*")] = (1, json.dumps({"dependencies": [
        {"name": "requests", "version": "2.0", "vulns": [{"id": "PYSEC-1"}]}, {"name": "idna", "version": "3", "vulns": []}]}), "")
    result = pydeps.vulnerability_scan(ENTRY, "/src", fake)
    assert result["status"] == "attention" and result["vulnerabilities"][0]["ids"] == ["PYSEC-1"]


def test_repository_inventory_and_locks_are_consistent():
    from omni_update.system import System
    entries = pydeps.load_inventory(ROOT, System())
    assert {e["id"] for e in entries} >= {"mobile", "oms-xdr", "oms-graph", "oms-ml"}
    for entry in entries:
        lock = ROOT / entry["lock"]
        assert lock.is_file(), entry["lock"]
        pins = pydeps.parse_lock(lock.read_text())
        assert pins, entry["id"]
        if entry.get("requirements"):
            for name, _ in pydeps.parse_requirements((ROOT / entry["requirements"]).read_text()):
                assert name in pins, (entry["id"], name)


@pytest.mark.parametrize("bad", [{"schema_version": 2, "venvs": []}, {"schema_version": 1, "venvs": [{"id": "A"}]},
                                 {"schema_version": 1, "venvs": [{"id": "a"}, {"id": "a"}]}])
def test_invalid_inventory_is_rejected(bad):
    fake = FakeSystem().put("/src/python-locks/venvs.json", json.dumps(bad))
    with pytest.raises(ValueError):
        pydeps.load_inventory("/src", fake)


def test_direct_dependencies_declared_in_inventory_must_be_locked():
    entry = {**ENTRY, "requirements": None, "direct": ["pywebpush"]}
    result = pydeps.audit_venv(entry, "/src", host({"requests": "2.34.2", "pyyaml": "6.0.3"}))
    assert result["requirements_not_in_lock"] == ["pywebpush"] and result["status"] == "attention"
