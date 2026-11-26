"""A VM job cannot succeed without a valid, successful persisted acceptance report."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "posix", reason="Bash VM harness")
@pytest.mark.parametrize("case", ["passed", "invalid-json", "missing", "core-failed", "module-failed", "transport-failed"])
def test_vm_report_gates_actual_shell_exit_status(tmp_path, case):
    source = (ROOT / "tools/test-ubuntu-vm.sh").read_text()
    start = source.index('if python3 - "$WORK/report.json"')
    script = source[start:].replace("python3", shlex.quote(sys.executable))
    (tmp_path / "image-sha256").write_text("a" * 64)
    if case != "missing":
        (tmp_path / "report.json").write_text("invalid" if case == "invalid-json" else json.dumps({"passed": case != "core-failed"}))
    (tmp_path / "integrations.json").write_text(json.dumps({"passed": case != "module-failed"}))
    report = tmp_path / "final.json"
    header = 'set -euo pipefail\nWORK="$1"\nREPORT="$2"\nINSTALL_CODE=0\nVERIFY_CODE="$3"\nINTEGRATION_CODE=0\n'
    process = subprocess.run(["bash", "-c", header + script, "test", str(tmp_path), str(report),
                              "255" if case == "transport-failed" else "0"], capture_output=True, text=True)
    assert (process.returncode == 0) == (case == "passed")
    assert ("fresh installation passed" in process.stdout) == (case == "passed")
    if report.exists():
        assert json.loads(report.read_text())["passed"] == (case == "passed")


@pytest.mark.skipif(os.name != "posix", reason="Bash VM harness")
@pytest.mark.parametrize("case", ["drill-passed", "drill-failed", "drill-missing", "drill-exit"])
def test_vm_report_gates_the_optional_restore_drill(tmp_path, case):
    source = (ROOT / "tools/test-ubuntu-vm.sh").read_text()
    script = source[source.index('if python3 - "$WORK/report.json"'):].replace("python3", shlex.quote(sys.executable))
    (tmp_path / "image-sha256").write_text("a" * 64)
    (tmp_path / "report.json").write_text(json.dumps({"passed": True}))
    (tmp_path / "integrations.json").write_text(json.dumps({"passed": True}))
    if case != "drill-missing":
        (tmp_path / "drill.json").write_text(json.dumps({"reussi": case != "drill-failed", "rto": {"valide": True}}))
    report = tmp_path / "final.json"
    header = ('set -euo pipefail\nWORK="$1"\nREPORT="$2"\nINSTALL_CODE=0\nVERIFY_CODE=0\nINTEGRATION_CODE=0\n'
              'DRILL_ENABLED=1\nDRILL_CODE="$3"\n')
    process = subprocess.run(["bash", "-c", header + script, "test", str(tmp_path), str(report),
                              "1" if case == "drill-exit" else "0"], capture_output=True, text=True)
    assert (process.returncode == 0) == (case == "drill-passed")
    final = json.loads(report.read_text())
    assert final["passed"] == (case == "drill-passed") and "restore_drill" in final


@pytest.mark.skipif(os.name != "posix", reason="Bash VM harness")
@pytest.mark.parametrize("case", ["passed", "failed", "missing", "invalid", "exit-error"])
def test_package_report_requires_successful_adoption_acceptance(tmp_path, case):
    source = (ROOT / "tools/test-ubuntu-vm.sh").read_text()
    script = source[source.index('if python3 - "$WORK/report.json"'):].replace("python3", shlex.quote(sys.executable))
    (tmp_path / "image-sha256").write_text("a" * 64)
    (tmp_path / "report.json").write_text('{"passed":true}')
    (tmp_path / "integrations.json").write_text('{"passed":true}')
    if case != "missing":
        (tmp_path / "adoption.json").write_text("invalid" if case == "invalid" else json.dumps({"passed": case != "failed"}))
    report = tmp_path / "final.json"
    header = ('set -euo pipefail\nWORK="$1"\nREPORT="$2"\nINSTALL_CODE=0\nVERIFY_CODE=0\nINTEGRATION_CODE=0\n'
              'OMNI_VM_PACKAGE=1\nADOPTION_CODE="$3"\n')
    process = subprocess.run(["bash", "-c", header + script, "test", str(tmp_path), str(report),
                              "1" if case == "exit-error" else "0"], capture_output=True, text=True)
    assert (process.returncode == 0) == (case == "passed")
    assert json.loads(report.read_text())["passed"] == (case == "passed")
