"""Publication refuses incomplete, wrong-source and unsuccessful qualification."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_gate", ROOT / "tools/release-channel.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
REVISION = "a" * 40


def receipt():
    return {"passed":True, "distribution_package":True, "adoption":{"passed":True},
            "integrations":{"passed":True}, "source_revision":REVISION}


@pytest.mark.parametrize("field", ["passed", "distribution_package", "adoption", "integrations", "source_revision"])
def test_incomplete_or_wrong_revision_receipt_blocks_publication(field):
    good = receipt()
    gate.validate_receipt(good, REVISION)
    bad = copy.deepcopy(good)
    bad.pop(field)
    with pytest.raises(ValueError):
        gate.validate_receipt(bad, REVISION)


@pytest.mark.parametrize("failure", [None, "checks", "packages", "vm_revision", "vm_failed", "expired_receipt", "receipt_failed"])
def test_actual_workflow_proof_contract(monkeypatch, failure):
    runs = [{"path":".github/workflows/" + path, "head_sha":REVISION, "conclusion":"success", "event":"push", "id":n}
            for n, path in enumerate(("check.yml", "distribution.yml"), 10)]
    if failure == "checks":runs[0]["event"] = "pull_request"
    if failure == "packages":runs[1]["conclusion"] = "failure"
    vm = {"path":".github/workflows/ubuntu-vm.yml", "head_sha":REVISION, "event":"workflow_dispatch", "conclusion":"success"}
    if failure == "vm_revision":vm["head_sha"] = "b" * 40
    if failure == "vm_failed":vm["conclusion"] = "failure"
    artifact = {"name":"ubuntu-2604-acceptance", "expired":failure == "expired_receipt", "id":100}
    def api(path):
        if "head_sha" in path:return {"workflow_runs":runs}
        if path.endswith("/artifacts"):return {"artifacts":[artifact]}
        return vm
    monkeypatch.setattr(gate, "api", api)
    data = receipt()
    if failure == "receipt_failed":data["passed"] = False
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("ubuntu-vm-report.json", json.dumps(data))
    monkeypatch.setattr(gate.subprocess, "check_output", lambda *a, **k:archive.getvalue())
    if failure:
        with pytest.raises(ValueError):gate.qualified(REVISION, "42")
    else:
        assert gate.qualified(REVISION, "42")["vm_run"] == 42


def test_signing_workflow_never_receives_secrets_from_a_pull_request():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/signed-repositories.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch", "schedule"}
    assert workflow["jobs"]["prepare"]["if"] == "github.ref == 'refs/heads/main'"
    assert workflow["jobs"]["prepare"]["environment"] == "release-signing"
    assert workflow["jobs"]["prepare"]["permissions"] == {"contents":"write", "actions":"read"}
    assert workflow["jobs"]["sign"]["needs"] == "prepare"
    assert workflow["jobs"]["sign"]["environment"] == "release-signing"
    cleanup = workflow["jobs"]["sign"]["steps"][-1]
    assert cleanup["if"] == "always()" and "--cleanup" in cleanup["run"]


def test_a_matching_revision_cannot_hide_modified_draft_bytes(tmp_path):
    (tmp_path / "release.json").write_bytes(b'claimed-source-revision')
    (tmp_path / "package.deb").write_bytes(b'qualified-build')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        for path in tmp_path.iterdir():
            z.writestr(path.name, path.read_bytes())
    gate.compare_build_archive(tmp_path, archive.getvalue())
    (tmp_path / "package.deb").write_bytes(b'changed-package')
    with pytest.raises(ValueError, match="build bytes"):
        gate.compare_build_archive(tmp_path, archive.getvalue())
