#!/usr/bin/env python3
"""Rehome and roll back a real fixture service in the isolated acceptance VM only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def call(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    if result.returncode:
        # Only our adoption command's bounded diagnostics are included. Never dump
        # arbitrary verification logs or configuration from the test guest.
        detail = result.stderr[-600:] if argv[0] == "omni-siem" else ""
        raise RuntimeError("isolated adoption check failed: " + Path(argv[0]).name + " " + detail)
    return result.stdout


def main():
    spec = importlib.util.spec_from_file_location("adoption_vm_guard", ROOT / "tools/test-integration-vm.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    guard.isolated_configuration()
    target = Path("/opt/omni-siem/repository")
    unit = Path("/etc/systemd/system/omni-adoption-probe.service")
    output = Path("/root/adoption-acceptance.json")
    if target.exists() or unit.exists():
        raise ValueError("the isolated adoption fixture destination must be absent")
    original_sha = call(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip()
    secret_hash = hashlib.sha256((ROOT / "00-vars.env").read_bytes()).hexdigest()
    # Force a real venv reconstruction rather than merely testing a system Python path.
    call([sys.executable, "-m", "venv", str(ROOT / "mobile/.venv")])
    unit.write_text("[Unit]\nDescription=Isolated adoption acceptance fixture\n[Service]\nType=simple\nUser=nobody\nExecStart="
                    + str(ROOT / "mobile/.venv/bin/python") + " "
                    + str(ROOT / "tests/fixtures/adoption-service.py") + "\n")
    unit.chmod(0o644)
    call(["systemctl", "daemon-reload"])
    call(["systemctl", "start", unit.name])
    record = {"passed": False, "checks": []}
    try:
        plan = json.loads(call(["omni-siem", "adopt", "--from", str(ROOT), "--plan"]))
        if plan["blockers"]:
            record["blockers"] = plan["blockers"]
            raise ValueError("adoption plan blocked in the isolated fixture")
        result = json.loads(call(["omni-siem", "adopt", "--from", str(ROOT), "--apply"]))
        if result["status"] != "applied":
            raise ValueError("adoption did not apply")
        record["checks"].append("known running service repointed and restarted")
        assert call(["git", "-C", str(target), "rev-parse", "HEAD"]).strip() == original_sha
        assert hashlib.sha256((target / "00-vars.env").read_bytes()).hexdigest() == secret_hash
        assert ROOT.is_dir() and not ROOT.is_symlink()
        assert str(target) in unit.read_text()
        call([str(target / "mobile/.venv/bin/python"), "-c", "import pywebpush"])
        call(["systemctl", "is-active", "--quiet", unit.name])
        call([sys.executable, str(target / "tools/verify-installation.py"), "--output", "/root/adopted-platform.json"])
        record["checks"].append("same revision, private configuration, old checkout retained and platform acceptance passed")
        call(["omni-siem", "adopt", "--rollback", result["transaction"], "--apply"])
        assert str(ROOT) in unit.read_text() and target.is_dir()
        call(["systemctl", "is-active", "--quiet", unit.name])
        call([sys.executable, str(ROOT / "tools/verify-installation.py"), "--output", "/root/restored-platform.json"])
        record["checks"].append("rollback restored runtime references and platform acceptance passed")
        record["passed"] = True
    except Exception as error:
        record["failure"] = str(error)
        raise
    finally:
        call(["systemctl", "stop", unit.name])
        unit.unlink()
        call(["systemctl", "daemon-reload"])
        output.write_text(json.dumps(record, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
