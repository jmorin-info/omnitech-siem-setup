#!/usr/bin/env python3
"""Plan/apply a bounded auth-log forwarder; preserve existing site configuration."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile

CONFIG = Path("/etc/rsyslog.d/60-omni-package.conf")
STATE = Path("/var/lib/omni-siem-agent")
MARKER = "# Managed by omni-siem package agent\n"


def receiver(value):
    try:
        address = ipaddress.ip_address(value)
        if address.version != 4:
            raise ValueError("this collector profile requires IPv4 or a DNS hostname")
        return str(address)
    except ValueError:
        if len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
            raise ValueError("receiver must be an IPv4 address or DNS hostname") from None
        if all(c in "0123456789." for c in value) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
            raise ValueError("invalid receiver address") from None
        return value


def render(target, port):
    target = receiver(target)
    if not 1 <= port <= 65535:
        raise ValueError("port must be from 1 to 65535")
    return (MARKER + '# Internal TCP transport; no TLS in this profile.\n'
            'if ($syslogfacility-text == "authpriv" or $syslogfacility-text == "auth") then {\n'
            f'  action(type="omfwd" target="{target}" port="{port}" protocol="tcp"\n'
            '    TCP_Framing="octet-counted" KeepAlive="on" action.resumeRetryCount="-1"\n'
            '    queue.type="LinkedList" queue.size="10000")\n}\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=300)
    if result.returncode:
        raise RuntimeError("command failed: " + Path(argv[0]).name + " (exit " + str(result.returncode) + "); site configuration restored when possible")


def atomic(path, data, mode=0o644):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
    try:
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def old_config(path):
    if path.is_symlink():
        raise ValueError("symlinked agent configuration is refused")
    before = path.read_bytes() if path.exists() else None
    if before is not None and not before.startswith(MARKER.encode()):
        raise ValueError("configuration is owned by the site; inspect it instead of overwriting")
    return before


def deploy(target, port, apply=False, config=CONFIG, state=STATE):
    if not apply:
        return _deploy(target, port, False, config, state)
    if os.geteuid() != 0:
        raise ValueError("apply requires root")
    import fcntl
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.chmod(0o700)
    with (state / "agent.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _deploy(target, port, True, config, state)


def _deploy(target, port, apply=False, config=CONFIG, state=STATE):
    data = render(target, port)
    before = old_config(config)
    if (config.parent / "60-omni-forward.conf").exists():
        raise ValueError("legacy OMNI forwarder already exists; review it to avoid duplicate collection")
    manager = next((name for name in ("apt-get", "dnf") if shutil.which(name)), None)
    plan = {"mode": "apply" if apply else "plan", "receiver": target, "port": port,
            "transport": "TCP, plaintext; internal trusted network only", "package_manager": manager,
            "configuration": str(config), "changed": before != data,
            "collected": ["auth", "authpriv"], "audit_rules": "not modified; use the reviewed auditd kit separately",
            "prerequisites": ["Linux with systemd and apt-get or dnf", "Syslog TCP receiver and firewall configured on the SIEM (92-linux.sh, port 1519 by default)"],
            "delivery_proof": "not verified; confirm this host's messages in Graylog and the SOC after deployment"}
    if not apply:
        return plan
    if os.geteuid() != 0 or not manager or not shutil.which("systemctl"):
        raise ValueError("apply requires root, systemd and apt-get or dnf")
    # Refuse an unreachable destination before changing any package/configuration.
    try:
        with socket.create_connection((target, port), timeout=5):
            pass
    except OSError:
        raise ValueError("receiver TCP port is unreachable; configure collection and firewall first") from None
    if not shutil.which("rsyslogd"):
        command([manager, "install", "-y", "rsyslog"])
    if before == data:
        plan["status"] = "unchanged"
        return plan
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.chmod(0o700)
    transaction = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = state / transaction
    backup.mkdir(mode=0o700)
    was_active = subprocess.run(["systemctl", "is-active", "--quiet", "rsyslog"], capture_output=True).returncode == 0
    if before is not None:
        atomic(backup / "before.conf", before, 0o600)
    record = {"id": transaction, "path": str(config), "before_exists": before is not None,
              "before_sha256": digest(before) if before is not None else None,
              "before_mode": config.stat().st_mode & 0o777 if before is not None else 0o644,
              "after_sha256": digest(data), "was_active": was_active, "status": "applying"}
    atomic(backup / "transaction.json", (json.dumps(record, indent=2) + "\n").encode(), 0o600)
    config.parent.mkdir(parents=True, exist_ok=True)
    if old_config(config) != before:
        record["status"] = "conflict"
        atomic(backup / "transaction.json", (json.dumps(record, indent=2) + "\n").encode(), 0o600)
        raise RuntimeError("agent configuration changed during the operation")
    try:
        atomic(config, data)
        command(["rsyslogd", "-N1"])
        command(["systemctl", "restart" if was_active else "start", "rsyslog"])
    except Exception:
        if before is None:
            config.unlink(missing_ok=True)
        else:
            atomic(config, before, record["before_mode"])
        restored = subprocess.run(["systemctl", "restart" if was_active else "stop", "rsyslog"], capture_output=True).returncode == 0
        record["status"] = "rolled_back" if restored else "rollback_incomplete"
        atomic(backup / "transaction.json", (json.dumps(record, indent=2) + "\n").encode(), 0o600)
        raise
    record["status"] = "applied"
    atomic(backup / "transaction.json", (json.dumps(record, indent=2) + "\n").encode(), 0o600)
    plan.update(status="applied", transaction=transaction, journal=str(backup / "transaction.json"))
    return plan


def rollback(transaction, apply=False, config=CONFIG, state=STATE, recover=False):
    if not apply:
        return _rollback(transaction, False, config, state, recover)
    if os.geteuid() != 0:
        raise ValueError("rollback requires root")
    import fcntl
    with (state / "agent.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _rollback(transaction, True, config, state, recover)


def _rollback(transaction, apply=False, config=CONFIG, state=STATE, recover=False):
    if not re.fullmatch(r"[0-9]{8}T[0-9]{12}Z", transaction):
        raise ValueError("invalid agent transaction")
    backup = state / transaction
    record = json.loads((backup / "transaction.json").read_text())
    if record.get("status") != ("applying" if recover else "applied") or record.get("path") != str(config):
        raise ValueError("transaction cannot be rolled back")
    current = old_config(config)
    if current is None or digest(current) != record["after_sha256"]:
        raise ValueError("agent configuration changed after deployment; refusing to overwrite it")
    previous = (backup / "before.conf").read_bytes() if record["before_exists"] else None
    if previous is not None and digest(previous) != record["before_sha256"]:
        raise ValueError("backup checksum mismatch")
    result = {"mode": "rollback" if apply else "rollback_plan", "transaction": transaction,
              "packages": "retained", "configuration": str(config)}
    if apply:
        if os.geteuid() != 0:
            raise ValueError("rollback requires root")
        if previous is None:
            config.unlink()
        else:
            atomic(config, previous, record["before_mode"])
        try:
            command(["rsyslogd", "-N1"])
            command(["systemctl", "restart" if record["was_active"] else "stop", "rsyslog"])
        except Exception:
            atomic(config, current)
            raise
        record["status"] = "rolled_back"
        atomic(backup / "transaction.json", (json.dumps(record, indent=2) + "\n").encode(), 0o600)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver")
    parser.add_argument("--port", type=int, default=1519)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--rollback", metavar="TRANSACTION")
    operation.add_argument("--recover", metavar="TRANSACTION", help="restore an interrupted transaction whose installed file still matches")
    args = parser.parse_args(argv)
    transaction = args.rollback or args.recover
    if transaction and args.receiver or not transaction and not args.receiver:
        parser.error("choose --receiver HOST, --rollback TRANSACTION or --recover TRANSACTION")
    result = rollback(transaction, args.apply, recover=bool(args.recover)) if transaction else deploy(args.receiver, args.port, args.apply)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("Agent operation refused: " + str(error))
