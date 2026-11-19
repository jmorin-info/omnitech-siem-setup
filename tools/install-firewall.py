#!/usr/bin/env python3
"""Persist a dedicated nftables include and apply only the SIEM table atomically."""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid


def read_original(path):
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("symlinked firewall configuration is refused: " + str(path))
    if not path.exists():
        return {"exists": False, "data": None, "mode": 0o600}
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("firewall configuration must be a regular file: " + str(path))
    return {"exists": True, "data": path.read_bytes(), "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid}


def atomic_write(path, data, mode, original=None):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".omni-firewall-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        if original and original["exists"] and hasattr(os, "chown"):
            os.chown(temporary, original["uid"], original["gid"])
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def with_include(original, config, fragment):
    text = original.decode("utf-8")
    # An existing wildcard include already loads the dedicated fragment.
    for match in re.finditer(r'(?m)^\s*include\s+"([^"\r\n]+)"\s*;?(?:[ \t]*#.*)?$', text):
        pattern = match[1]
        if not pattern.startswith("/"):
            pattern = (config.parent / pattern).as_posix()
        if fnmatch.fnmatchcase(fragment.as_posix(), pattern):
            return original
    if re.search(r"(?m)^\s*(?:(?:add|create)\s+)?table\s+inet\s+omni_siem\b", text):
        raise ValueError("existing boot configuration declares omni_siem inline; review its migration before adding the managed include")
    suffix = ("" if not text or text.endswith("\n") else "\n")
    suffix += '\n# Managed OMNI SIEM table; existing configuration retained.\ninclude "' + fragment.as_posix() + '"\n'
    return original + suffix.encode()


def backup_originals(directory, originals):
    if directory.parent.is_symlink():
        raise ValueError("symlinked firewall backup directory is refused")
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)
    manifest = {}
    for name, (path, original) in originals.items():
        manifest[name] = {key: value for key, value in original.items() if key != "data"}
        manifest[name]["path"] = str(path)
        if original["exists"]:
            atomic_write(directory / name, original["data"], 0o600)
    atomic_write(directory / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode(), 0o600)


def restore_originals(originals):
    for path, original in originals.values():
        if original["exists"]:
            atomic_write(path, original["data"], original["mode"], original)
        else:
            path.unlink(missing_ok=True)


def install(candidate, config=Path("/etc/nftables.conf"),
            fragment=Path("/etc/nftables.d/omni-siem.nft"),
            backup_root=Path("/var/backups/omni-siem/nftables")):
    candidate, config, fragment, backup_root = map(Path, (candidate, config, fragment, backup_root))
    originals = {"nftables.conf": (config, read_original(config)),
                 "omni-siem.nft": (fragment, read_original(fragment))}
    data = candidate.read_bytes()
    # The caller supplies the site's rendered table, never a global ruleset.
    if re.search(rb"\bflush\s+ruleset\b", data) or b"flush table inet omni_siem" not in data:
        raise ValueError("the candidate must replace only the dedicated omni_siem table")
    boot = with_include(originals["nftables.conf"][1]["data"] or b"", config, fragment)
    subprocess.run(["nft", "-c", "-f", str(candidate)], check=True)
    service = subprocess.run(["systemctl", "is-enabled", "nftables"], capture_output=True, text=True)
    previous_enabled = service.stdout.strip()
    directory = backup_root / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex)
    backup_originals(directory, originals)
    enable_changed = False
    try:
        atomic_write(fragment, data, 0o600, originals["omni-siem.nft"][1])
        old_config = originals["nftables.conf"][1]
        if old_config["data"] != boot:
            atomic_write(config, boot, old_config["mode"], old_config)
        # Checking the boot file is read-only, even if its original content flushes.
        subprocess.run(["nft", "-c", "-f", str(config)], check=True)
        subprocess.run(["systemctl", "enable", "nftables"], check=True)
        enable_changed = previous_enabled != "enabled"
        # nft -f applies a single atomic transaction. Never load the global boot file.
        subprocess.run(["nft", "-f", str(candidate)], check=True)
    except BaseException:
        restore_originals(originals)
        if enable_changed:
            subprocess.run(["systemctl", "disable", "nftables"], check=False, capture_output=True)
            if previous_enabled == "enabled-runtime":
                subprocess.run(["systemctl", "enable", "--runtime", "nftables"], check=False, capture_output=True)
        raise
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("firewall installation requires root")
    try:
        directory = install(args.candidate)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("Firewall installation failed: " + str(exc), file=sys.stderr)
        return 1
    print("Dedicated SIEM firewall applied; previous boot configuration retained. Backup: " + str(directory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
