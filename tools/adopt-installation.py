#!/usr/bin/env python3
"""Discover and rehome a clean project checkout without moving database data."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STATE = Path("/var/lib/omni-siem-adoption")
MARKERS = ("install.sh", "lib-graylog.sh", "mobile/omni-mobile-api.py", "tools/omni-deploy.py")
VENVS = {"mobile", "oms-xdr", "oms-graph", "oms-ml"}
PATH_KEYS = {"MITRE_LOOKUP", "OMS_GRAPH_DIR", "OMNI_SIEM_HOME", "OMNI_REPO_DIR", "UPDATE_REPO"}


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("adoption_builder", "tools/build-release.py")
launcher = load("adoption_launcher", "distribution/launcher.py")


def git(source, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(["git", "--no-replace-objects", "-c", "safe.directory=" + str(source),
                             "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(source), *args],
                            capture_output=True, env=env, timeout=180)
    if result.returncode:
        raise ValueError("Git validation failed; source checkout was not changed")
    return result.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def discover(roots=(Path("/home"), Path("/root"), Path("/opt"), Path("/srv")), limit=10000):
    found, visited, truncated = [], 0, False
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for current, dirs, _files in os.walk(root, followlinks=False):
            visited += 1
            path = Path(current)
            if visited > limit:
                truncated = True
                break
            if all((path / marker).is_file() for marker in MARKERS) and (path / ".git").exists():
                found.append(str(path))
                dirs[:] = []
                continue
            dirs[:] = sorted(d for d in dirs if d not in {".git", ".venv", "node_modules", "__pycache__", ".cache"}
                             and not (path / d).is_symlink() and len((path / d).relative_to(root).parts) <= 4)
        if truncated:
            break
    return {"candidates": sorted(set(found)), "truncated": truncated,
            "scope": "bounded scan of /home, /root, /opt and /srv; use --from for any other directory"}


def read(path):
    if path.is_symlink():
        raise ValueError("symlink requires review: " + str(path))
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("file too large for automatic review: " + str(path))
    return path.read_bytes()


def meaningful(data):
    return b"\n".join(line for line in data.splitlines() if not line.lstrip().startswith(b"#"))


def plan(source, target, system_root=Path("/")):
    source, target = launcher.safe_root(source), launcher.safe_root(target)
    blockers, files, services, venvs = [], [], set(), set()
    if source == target or source in target.parents or target in source.parents:
        raise ValueError("source and destination must be separate directories")
    if target.exists():
        blockers.append("destination already exists; no automatic merge or overwrite")
    if not all((source / item).is_file() for item in MARKERS):
        raise ValueError("source is not a supported OMNI project checkout")
    if git(source, "rev-parse", "--show-toplevel").decode().strip() != str(source):
        raise ValueError("source must be the checkout root")
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    entries = [entry for entry in git(source, "ls-tree", "-rz", revision).split(b"\0") if entry]
    tracked = set()
    source_size = 0
    for entry in entries:
        metadata, name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        relative = name.decode()
        tracked.add(relative)
        path = source / relative
        try:
            if mode not in {"100644", "100755"} or kind != "blob" or path.resolve() != path:
                raise ValueError("unsupported tracked entry")
            data = path.read_bytes()
            source_size += len(data)
            # hash-object without --path/--filters never executes a configured clean filter.
            actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest().encode()
            if actual.decode() != oid or bool(path.stat().st_mode & 0o111) != (mode == "100755"):
                blockers.append("local tracked changes require reconciliation: " + relative)
        except (OSError, ValueError):
            blockers.append("tracked file missing, linked or unsupported: " + relative)
    if git(source, "diff", "--cached", "--name-only", "--no-ext-diff", "--no-textconv").strip():
        blockers.append("staged changes require reconciliation")
    config = source / "00-vars.env"
    if not config.is_file() or config.is_symlink():
        blockers.append("private site configuration 00-vars.env is missing or linked")
    elif str(source).encode() in meaningful(read(config)):
        blockers.append("site configuration contains paths inside the old checkout; separate code paths from data before adoption")
    old, new = str(source).encode(), str(target).encode()
    old_path = re.compile(re.escape(old) + rb"(?=/|[\s\"':;]|$)")
    roots = ("etc/systemd/system", "etc/default", "etc/cron.d", "etc/crontab", "etc/cron.hourly",
             "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron/crontabs",
             "etc/nginx", "etc/logstash", "etc/rc.local", "etc/environment", "usr/local/sbin",
             "usr/lib/systemd/system", "run/systemd/system")
    for relative_root in roots:
        directory = system_root / relative_root
        if not directory.exists():
            continue
        candidates = sorted(directory.rglob("*")) if directory.is_dir() else [directory]
        for path in candidates:
            if not path.is_file():
                continue
            try:
                data = read(path)
            except ValueError:
                # Do not dereference an arbitrary linked configuration.
                if path.is_symlink() and path.resolve().is_file():
                    if old_path.search(path.resolve().read_bytes()):
                        blockers.append("linked runtime reference requires review: " + str(path))
                else:
                    blockers.append("runtime file cannot be reviewed: " + str(path))
                continue
            if not old_path.search(meaningful(data)):
                continue
            unit = next((part[:-2] if part.endswith(".d") else part for part in path.relative_to(directory).parts
                         if re.fullmatch(r"(?:(?:omni|oms)-[A-Za-z0-9@_.-]+|siem-backup)\.service(?:\.d)?", part)), None)
            supported = relative_root == "etc/systemd/system" and unit is not None
            if supported:
                services.add(unit)
                for relative in re.findall(re.escape(str(source)) + r"/([A-Za-z0-9_./-]+)", meaningful(data).decode(errors="replace")):
                    if ".venv" in Path(relative).parts:
                        continue
                    candidate = source / relative
                    if candidate.is_file() and relative not in tracked and relative not in {"00-vars.env", "oms-xdr/config.yaml"}:
                        blockers.append("untracked runtime file requires a migration rule: " + relative)
                    if candidate.is_dir() and not any(name.startswith(relative.rstrip("/") + "/") for name in tracked):
                        blockers.append("local runtime data directory requires explicit migration: " + relative)
                for project in re.findall(re.escape(str(source)) + r"/([^/\s]+)/\.venv/", data.decode(errors="replace")):
                    if project in VENVS:
                        venvs.add(project)
                    else:
                        blockers.append("unknown Python environment: " + project)
            if relative_root == "etc/default" and path.name.startswith(("omni-", "oms-")):
                affected_keys = [line.split(b"=", 1)[0].strip().decode(errors="replace") for line in data.splitlines()
                                 if old in line and not line.lstrip().startswith(b"#") and b"=" in line]
                supported = bool(affected_keys) and all(key in PATH_KEYS for key in affected_keys)
            if relative_root == "usr/local/sbin" and path.name.startswith(("omni-", "oms-")):
                candidate = source / "deploye/sbin" / path.name
                supported = candidate.is_file() and data.replace(old, b"@ROOT@") == candidate.read_bytes().replace(
                    b"/opt/omni-siem/repository", b"@ROOT@").replace(b"/root/omnitech-siem-setup", b"@ROOT@")
            if not supported:
                blockers.append("unmanaged runtime reference requires review: " + str(path))
                continue
            for relative in re.findall(re.escape(str(source)) + r"/([A-Za-z0-9_./-]+)", meaningful(data).decode(errors="replace")):
                if ".venv" in Path(relative).parts:
                    continue
                candidate = source / relative
                if candidate.is_file() and relative not in tracked and relative not in {"00-vars.env", "oms-xdr/config.yaml"}:
                    blockers.append("untracked runtime file requires a migration rule: " + relative)
                if candidate.is_dir() and not any(name.startswith(relative.rstrip("/") + "/") for name in tracked):
                    blockers.append("local runtime data directory requires explicit migration: " + relative)
            if any(char.isspace() for char in str(source) + str(target)):
                blockers.append("runtime paths with whitespace require explicit service configuration")
            details = path.stat()
            after = old_path.sub(lambda _: new, data)
            files.append({"path": str(path), "before_sha256": sha(data), "after_sha256": sha(after),
                          "mode": details.st_mode & 0o777, "uid": details.st_uid, "gid": details.st_gid,
                          "_before": data, "_after": after})
    # A partial installation keeps its completed phases and instance identity.
    for relative in ("etc/omni-siem/instance.json", "var/lib/omni-siem/install-state.json"):
        path = system_root / relative
        if path.is_file():
            data = read(path)
            record = json.loads(data)
            if record.get("source_root") == str(source):
                record["source_root"] = str(target)
                after = (json.dumps(record, indent=2) + "\n").encode()
                files.append({"path": str(path), "before_sha256": sha(data), "after_sha256": sha(after),
                              "mode": path.stat().st_mode & 0o777, "uid": path.stat().st_uid, "gid": path.stat().st_gid,
                              "_before": data, "_after": after})
    runtime = []
    for relative in ("00-vars.env", "oms-xdr/config.yaml"):
        path = source / relative
        if relative not in tracked and path.is_file():
            if str(source).encode() in meaningful(read(path)):
                blockers.append("local runtime config contains old paths; review before adoption: " + relative)
            runtime.append(relative)
    parent = target.parent
    while not parent.exists():
        parent = parent.parent
    minimum_free = source_size * 2 + (len(venvs) + 1) * 512 * 1024 * 1024
    free = shutil.disk_usage(parent).free
    if free < minimum_free:
        blockers.append("insufficient free space for code, temporary copy and Python environments")
    return {"source": str(source), "target": str(target), "revision": revision, "_scan_root": str(system_root),
            "tracked_files": len(tracked), "source_bytes": source_size, "files": files,
            "services": sorted(services), "venvs": sorted(venvs), "runtime_files": runtime,
            "free_bytes": free, "minimum_free_bytes_estimate": minimum_free,
            "blockers": sorted(set(blockers)), "database_data": "not moved; MongoDB/OpenSearch paths and mounts are preserved",
            "old_checkout": "retained; never deleted or replaced by a link"}


def public(report):
    return {**{k: v for k, v in report.items() if not k.startswith("_")},
            "files": [{k: v for k, v in item.items() if not k.startswith("_")} for item in report["files"]]}


def atomic(path, data, mode, owner=None):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
    try:
        temporary.chmod(mode)
        if owner is not None:
            os.chown(temporary, *owner)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=1200)
    if result.returncode:
        raise RuntimeError("adoption command failed: " + Path(argv[0]).name + " (exit " + str(result.returncode) + ")")


def service_state(unit):
    proc = subprocess.run(["systemctl", "show", unit, "--property=ActiveState,Type"], capture_output=True, text=True, check=True)
    return dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)


def apply(report, state=STATE, run=command, status=service_state):
    if os.geteuid() != 0 or report["blockers"]:
        raise ValueError("adoption requires root and a plan without blockers")
    import fcntl
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.chmod(0o700)
    with (state / "adoption.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source, target = Path(report["source"]), Path(report["target"])
        if target.exists() or git(source, "rev-parse", "HEAD").decode().strip() != report["revision"]:
            raise ValueError("source or target changed after planning")
        checked = plan(source, target, Path(report["_scan_root"]))
        # Free disk space varies normally; all source/runtime decisions must remain unchanged.
        if checked["blockers"] or any(checked[key] != report[key] for key in ("files", "services", "venvs", "runtime_files")):
            raise ValueError("source or runtime configuration changed after planning")
        active = []
        for unit in report["services"]:
            current = status(unit)
            if current.get("ActiveState") not in ("active", "inactive") or current.get("ActiveState") == "active" and current.get("Type") == "oneshot":
                raise ValueError("service must settle before adoption: " + unit)
            if current.get("ActiveState") == "active":
                active.append(unit)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = state / stamp
        backup.mkdir(mode=0o700)
        journal = {**public(report), "id": stamp, "status": "preparing", "active": active, "applied_files": []}
        journal["site_config_sha256"] = sha(read(source / "00-vars.env"))
        save = lambda: atomic(backup / "transaction.json", (json.dumps(journal, indent=2) + "\n").encode(), 0o600)
        save()
        # Private configuration and each runtime fragment are backed up before any reconfiguration.
        for i, item in enumerate(report["files"]):
            if read(Path(item["path"])) != item["_before"]:
                raise ValueError("runtime configuration changed after planning")
            atomic(backup / (str(i) + ".before"), item["_before"], 0o600)
        launcher.public_parents(target.parent)
        temporary = Path(tempfile.mkdtemp(prefix=".omni-adopt-", dir=target.parent))
        try:
            # Snapshot the actual installed revision, not the package revision: moving is not upgrading.
            builder.git = git
            builder.snapshot(source, temporary / "repo", report["revision"])
            for relative in report["runtime_files"]:
                destination = temporary / "repo" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                atomic(destination, read(source / relative), 0o600)
            os.rename(temporary / "repo", target)
        finally:
            shutil.rmtree(temporary)
        try:
            for project in report["venvs"]:
                run([sys.executable, str(ROOT / "tools/omni-deploy.py"), "--home", str(target),
                     "deploy", "venvs", "--filtre", str(target / project / ".venv"), "--apply", "--no-verify"])
            journal["status"] = "applying"
            save()
            for i, item in enumerate(report["files"]):
                if read(Path(item["path"])) != item["_before"]:
                    raise ValueError("runtime configuration changed during adoption")
                journal["applied_files"].append(i)
                save()
                atomic(Path(item["path"]), item["_after"], item["mode"], (item["uid"], item["gid"]))
            if report["services"]:
                run(["systemctl", "daemon-reload"])
            for unit in active:
                run(["systemctl", "restart", unit])
                if status(unit).get("ActiveState") != "active":
                    raise RuntimeError("service did not remain active: " + unit)
            journal["status"] = "applied"
            save()
        except Exception:
            failures = []
            for i in reversed(journal["applied_files"]):
                item = report["files"][i]
                path = Path(item["path"])
                if path.read_bytes() not in (item["_before"], item["_after"]):
                    failures.append(item["path"])
                    continue
                atomic(path, item["_before"], item["mode"], (item["uid"], item["gid"]))
            try:
                if report["services"]:
                    run(["systemctl", "daemon-reload"])
                for unit in active:
                    run(["systemctl", "restart", unit])
            except Exception:
                failures.append("service restoration")
            journal.update(status="rollback_incomplete" if failures else "rolled_back", restoration_problems=failures)
            save()
            raise
        return {**public(report), "status": journal["status"], "transaction": stamp,
                "journal": str(backup / "transaction.json"),
                "verification": "active services checked; run a full health check and observe scheduled jobs before retiring the old checkout"}


def rollback(transaction, apply=False, recover=False, state=STATE, run=command):
    if not re.fullmatch(r"[0-9]{8}T[0-9]{12}Z", transaction):
        raise ValueError("invalid adoption transaction")
    backup = state / transaction
    journal = json.loads(read(backup / "transaction.json"))
    allowed = ("preparing", "applying") if recover else ("applied",)
    if journal.get("status") not in allowed:
        raise ValueError("adoption transaction cannot be restored in its current state")
    target = Path(journal["target"])
    if target.exists() and (git(target, "rev-parse", "HEAD").decode().strip() != journal["revision"] or
                            sha(read(target / "00-vars.env")) != journal["site_config_sha256"]):
        raise ValueError("active code or site configuration changed after adoption; reconcile before rollback")
    for i in journal["applied_files"]:
        item = journal["files"][i]
        current = sha(read(Path(item["path"])))
        if current not in ({item["before_sha256"], item["after_sha256"]} if recover else {item["after_sha256"]}):
            raise ValueError("runtime configuration changed after adoption")
        if sha(read(backup / (str(i) + ".before"))) != item["before_sha256"]:
            raise ValueError("adoption backup checksum mismatch")
    result = {"transaction": transaction, "mode": "rollback" if apply else "rollback_plan",
              "target": str(target), "old_checkout": "retained", "database_data": "untouched"}
    if apply:
        if os.geteuid() != 0:
            raise ValueError("rollback requires root")
        import fcntl
        with (state / "adoption.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for i in reversed(journal["applied_files"]):
                item = journal["files"][i]
                atomic(Path(item["path"]), read(backup / (str(i) + ".before")), item["mode"], (item["uid"], item["gid"]))
            try:
                if journal["services"]:
                    run(["systemctl", "daemon-reload"])
                for unit in journal["active"]:
                    run(["systemctl", "restart", unit])
            except Exception:
                journal["status"] = "rollback_incomplete"
                atomic(backup / "transaction.json", (json.dumps(journal, indent=2) + "\n").encode(), 0o600)
                raise
            journal["status"] = "rolled_back"
            atomic(backup / "transaction.json", (json.dumps(journal, indent=2) + "\n").encode(), 0o600)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="source", type=Path)
    parser.add_argument("--to", type=Path, default=Path("/opt/omni-siem/repository"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--plan", action="store_true")
    restore = parser.add_mutually_exclusive_group()
    restore.add_argument("--rollback")
    restore.add_argument("--recover")
    args = parser.parse_args(argv)
    if args.rollback or args.recover:
        if args.source:
            parser.error("--from cannot be combined with rollback/recovery")
        print(json.dumps(rollback(args.rollback or args.recover, args.apply, bool(args.recover)), indent=2))
        return 0
    if not args.source:
        discovery = discover()
        candidates = [path for path in discovery["candidates"] if Path(path) != args.to]
        if len(candidates) != 1 or discovery["truncated"]:
            print(json.dumps({**discovery, "blockers": ["select exactly one source with --from; incomplete or ambiguous discovery is never applied"]}, indent=2))
            return 1 if args.apply else 0
        args.source = Path(candidates[0])
    report = plan(args.source, args.to)
    print(json.dumps(apply(report) if args.apply else public(report), indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("Adoption refused or failed: " + str(error))
