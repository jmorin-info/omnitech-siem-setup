#!/usr/bin/env python3
"""Activate code only for a backend installed and fingerprinted by this installer."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def healthy():
    for _ in range(10):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8090/m/api/vapid", timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError("console backend health check failed")


def activate(source, directory, restart=None, health=None):
    target, marker = directory / "omni-mobile-api.py", directory / "backend.json"
    if target.is_symlink() or marker.is_symlink():
        raise ValueError("refusing a symlink for managed backend code or metadata")
    recorded = json.loads(marker.read_text())
    if digest(target) != recorded["sha256"]:
        raise ValueError("managed backend has local changes; preserve and reconcile them before updating")
    if digest(source) == recorded["sha256"]:
        return False
    compile(source.read_text(encoding="utf-8"), str(source), "exec")
    restart = restart or (lambda: subprocess.run(["systemctl", "restart", "omni-mobile-api.service"], check=True))
    health = health or healthy
    backup = directory / ("omni-mobile-api.py.before-" + recorded["sha256"][:16])
    shutil.copy2(target, backup)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
        handle.write(source.read_bytes())
        candidate = Path(handle.name)
    candidate.chmod(0o644)
    try:
        os.replace(candidate, target)
        restart()
        health()
        marker.write_text(json.dumps({"sha256": digest(target)}, indent=2) + "\n")
        marker.chmod(0o600)
    except BaseException:
        shutil.copy2(backup, target)
        restart()
        raise
    finally:
        candidate.unlink(missing_ok=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, default=Path("/opt/omni-siem/console"))
    parser.add_argument("--record", action="store_true", help="record an already verified fresh installation")
    args = parser.parse_args()
    marker = args.directory / "backend.json"
    if args.record:
        if marker.exists():
            raise ValueError("backend ownership metadata already exists")
        target = args.directory / "omni-mobile-api.py"
        if digest(target) != digest(args.source):
            raise ValueError("installed backend differs from the source")
        marker.write_text(json.dumps({"sha256": digest(target)}, indent=2) + "\n")
        marker.chmod(0o600)
    else:
        print("Backend updated." if activate(args.source, args.directory) else "Backend already current.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Backend activation failed: " + str(exc))
