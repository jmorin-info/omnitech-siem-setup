#!/usr/bin/env python3
"""Prepare and apply reversible application-code updates without provisioning a SIEM.

plan is read-only. fetch and stage prepare a pinned candidate in a separate state
directory. apply-code never changes site configuration, Git HEAD or databases.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit
import uuid

DEFAULT_REMOTE = "https://github.com/jmorin-info/omnitech-siem-setup.git"
CORE = {"02-mongodb.sh", "03-opensearch.sh", "04-graylog.sh", "docker/docker-compose.yml", "deploye/apt/oms-siem-series", "versions.json", "stack-versions.env", "lib-platform.sh"}
CODE_FILES = {"mobile/omni-mobile-api.py", "triage/omni-alert-triage", "triage/omni-alert-digest",
              "tools/omni-manager.py", "tools/omni-integrations.py", "tools/omni-update.py", "tools/deploy-console.py",
              "tools/manage-console-backend.py", "tools/install-console.sh", "tools/verify-installation.py", "tools/omni-soc-kpi.py", "71-soc-console.sh"}
CODE_PREFIXES = ("manager/", "mobile/soc/", "mobile/www/", "oms-xdr/oms_xdr/", "oms-ml/oms_ml/", "oms-graph/oms_graph/", "omni_update/", "omni_integrations/", "integrations/")
CONFIG_SUFFIXES = (".env", ".yaml", ".yml", ".csv", ".key", ".pem", ".pfx", ".p12", ".cred")


class UpdateError(RuntimeError):
    pass


GIT_TIMEOUT_SECONDS = 300

# Classified Git failures. Git output is never echoed verbatim: a remote URL or a
# local path may contain sensitive data. LC_ALL=C makes the patterns locale-proof
# (a French locale prints "impossible de trouver la reference distante").
GIT_FAILURES = (
    ("unsafe_repository", ("dubious ownership", "safe.directory")),
    ("host_key_unverified", ("host key verification failed",)),
    ("ref_not_found", ("couldn't find remote ref", "could not find remote ref", "unknown revision",
                       "not a valid ref", "invalid refspec")),
    ("authentication_required", ("could not read username", "authentication failed", "terminal prompts disabled",
                                 "http basic: access denied", "403", "401",
                                 "permission denied (publickey")),
    ("repository_not_found", ("repository not found", "does not appear to be a git repository",
                              "not found", "no such file or directory")),
    ("network_unavailable", ("could not resolve host", "failed to connect", "could not connect", "connection refused",
                             "connection timed out", "network is unreachable", "operation timed out",
                             "temporary failure in name resolution", "ssl", "tls", "gnutls", "proxy")),
)


def classify_git_error(stderr):
    text = (stderr or "").lower()
    for reason, needles in GIT_FAILURES:
        if any(needle in text for needle in needles):
            return reason
    return "git_error"


def git(repo, *args, binary=False, check=True, timeout=None):
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANGUAGE": "C",
           "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    operation = next((a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] != "-c")), "git")
    try:
        process = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env,
                                 timeout=timeout)
    except subprocess.TimeoutExpired:
        raise UpdateError("Git operation failed: " + operation + " (network_unavailable: timeout after "
                          + str(timeout) + " s)")
    if check and process.returncode:
        # Do not echo command output: remote URLs or local files can contain secrets.
        reason = classify_git_error(process.stderr.decode("utf-8", errors="replace"))
        raise UpdateError("Git operation failed: " + operation + " (" + reason + ")")
    if not check:
        return process.returncode
    return process.stdout if binary else process.stdout.decode("utf-8", errors="strict").strip()


def read_json(path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def write_json(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def atomic(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    try:
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def safe_path(root, relative):
    parts = PurePosixPath(relative).parts
    if not parts or relative.startswith("/") or ".." in parts or "\\" in relative or ":" in relative:
        raise UpdateError("Unsafe relative file path")
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise UpdateError("Refusing to follow symlink: " + relative)
    return path


def managed(path):
    # Integration packages are distribution code; local state remains in Graylog.
    # Environment, credentials and tenant configuration are never copied.
    if any(part in {".git", ".venv", "__pycache__"} for part in PurePosixPath(path).parts):
        return False
    if path.endswith(CONFIG_SUFFIXES) or "secret" in PurePosixPath(path).name.lower():
        return False
    return path in CODE_FILES or path.startswith(CODE_PREFIXES)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    return sha(path.read_bytes()) if path.is_file() else None


def resolve(repo, revision):
    if not revision or revision.startswith("-") or re.search(r"[^A-Za-z0-9_./-]", revision):
        raise UpdateError("Invalid Git revision")
    return git(repo, "rev-parse", "--verify", revision + "^{commit}")


def repository(source, state, target, base):
    for repo in (source, state / "repository.git"):
        if not repo.exists():
            continue
        try:
            candidate = resolve(repo, target)
            resolve(repo, base)
            return repo, candidate
        except UpdateError:
            continue
    raise UpdateError("Target/base unavailable locally; run fetch first (plan never fetches)")


def current_revision(source, state):
    head = resolve(source, "HEAD")
    current = read_json(state / "current.json", {})
    if current:
        if current.get("source_root") != str(source.resolve()) or current.get("source_head") != head:
            raise UpdateError("Updater state belongs to a different checkout or Git HEAD; reconcile before continuing")
    return current.get("code_revision", head), head


def tracked(repo, revision):
    result = {}
    raw = git(repo, "ls-tree", "-rz", revision, binary=True)
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        result[name.decode()] = (mode, kind, object_id)
    return result


def content(repo, item):
    if item is None:
        return None
    if item[0] not in {"100644", "100755"} or item[1] != "blob":
        raise UpdateError("Unsupported repository entry (symlink/submodule)")
    return git(repo, "cat-file", "blob", item[2], binary=True)


def plan(source, state, target):
    source = source.resolve()
    base, head = current_revision(source, state)
    repo, candidate = repository(source, state, target, base)
    if git(repo, "merge-base", "--is-ancestor", base, candidate, check=False):
        raise UpdateError("Target must descend from the installed code revision; use rollback for an owned previous update")
    before, after = tracked(repo, base), tracked(repo, candidate)
    changed = [p for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)]
    code, withheld, conflicts = [], [], []
    # Check every managed file, including unchanged ones, before claiming alignment.
    for path in sorted(before.keys() | after.keys()):
        if not managed(path):
            continue
        expected = content(repo, before.get(path))
        try:
            actual_path = safe_path(source, path)
            actual = actual_path.read_bytes() if actual_path.is_file() else None
            if actual_path.exists() and not actual_path.is_file():
                conflicts.append(path)
            elif actual != expected:
                conflicts.append(path)
        except (UpdateError, OSError):
            conflicts.append(path)
    for path in changed:
        (code if managed(path) else withheld).append(path)
    migrations = [p for p in changed if p in CORE or p.startswith(("migrations/", "docker/migrations/"))
                  or PurePosixPath(p).name in {"pyproject.toml", "poetry.lock", "uv.lock"}
                  or re.fullmatch(r"requirements[^/]*\.txt", PurePosixPath(p).name)
                  or p.startswith("python-locks/")
                  or PurePosixPath(p).name.startswith("Dockerfile")]
    return {"schema_version": 1, "source_root": str(source), "source_head": head,
            "base_code_revision": base, "target": candidate, "code_files": code,
            "preserved_or_manual_files": withheld, "conflicts": sorted(set(conflicts)),
            "migration_review_required": migrations,
            "can_apply_code": not conflicts and not migrations,
            "scope": "application code and static assets only; Git HEAD, runtime publication, configuration and databases unchanged"}


@contextlib.contextmanager
def lock(state):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = state / "update.lock"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise UpdateError("Updater already locked; inspect a previous interrupted update before removing update.lock")
    try:
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        yield
    finally:
        path.unlink(missing_ok=True)


def validate_remote(remote):
    parsed = urlsplit(remote)
    try:
        _ = parsed.port
    except ValueError:
        raise UpdateError("Remote must be an HTTPS repository URL without embedded credentials/query")
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or "@" in parsed.netloc or parsed.query or parsed.fragment
            or any(ord(c) < 33 or ord(c) == 127 for c in remote)):
        raise UpdateError("Remote must be an HTTPS repository URL without embedded credentials/query")
    return remote


def validate_ref(ref):
    if (not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,200}", ref)
            or ".." in ref or "//" in ref or ref.endswith((".", "/", ".lock")) or "/." in ref or "@{" in ref):
        raise UpdateError("Invalid remote ref")
    return ref


def fetch(source, state, remote, ref, timeout=GIT_TIMEOUT_SECONDS):
    """Download one remote ref into the private cache; never touches the checkout.

    Guarantees covered by tests/test_updater_fetch.py: credentials in the URL and
    malformed refs are refused before any state is created; a missing ref, an
    unreachable network or a timeout fail with a classified message and release
    the lock; the fetched candidate and the installed baseline are both pinned by
    refs so that a later "git gc" cannot make planning fail offline.
    """
    validate_remote(remote)
    validate_ref(ref)
    source = source.resolve()
    base, _ = current_revision(source, state) if (state / "current.json").exists() else (resolve(source, "HEAD"), None)
    with lock(state):
        cache = state / "repository.git"
        if not (cache / "HEAD").exists():
            cache.mkdir(mode=0o700, exist_ok=True)
            git(cache, "init", "--bare", "--quiet")
        git(cache, "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=60",
            "fetch", "--no-tags", "--no-recurse-submodules", "--", remote, ref, timeout=timeout)
        target = resolve(cache, "FETCH_HEAD")
        git(cache, "update-ref", "refs/omni/candidates/" + target, target)
        # Import the source baseline so subsequent planning is fully offline.
        git(cache, "fetch", "--no-tags", "--no-recurse-submodules", "--", str(source), "HEAD", timeout=timeout)
        head = resolve(cache, "FETCH_HEAD")
        git(cache, "update-ref", "refs/omni/base/" + head, head)
        if base != head and git(cache, "cat-file", "-e", base + "^{commit}", check=False) == 0:
            git(cache, "update-ref", "refs/omni/base/" + base, base)
        descends = git(cache, "merge-base", "--is-ancestor", base, target, check=False) == 0
        return {"target": target, "remote": remote, "ref": ref, "installed_code_revision": base,
                "descends_from_installed": descends,
                "next": ("plan --target " + target) if descends else
                        "target does not descend from the installed revision (divergent history): plan will refuse it"}


def stage(source, state, target):
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise UpdateError("stage/apply-code require the full pinned commit SHA returned by plan/fetch")
    information = plan(source, state, target)
    repo, _ = repository(source, state, target, information["base_code_revision"])
    destination = state / "releases" / target
    manifest_path = state / "releases" / (target + ".json")
    if destination.exists():
        verify_stage(state, target)
        return destination
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="candidate-", dir=destination.parent))
    manifest = {}
    try:
        raw = git(repo, "archive", "--format=tar", target, binary=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive:
                path = safe_path(temporary, member.name.rstrip("/"))
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    data = archive.extractfile(member).read()
                    path.write_bytes(data)
                    path.chmod(0o555 if member.mode & 0o111 else 0o444)
                    manifest[member.name] = sha(data)
                else:
                    raise UpdateError("Candidate contains a symlink/submodule/unsupported archive entry")
        os.replace(temporary, destination)
        write_json(manifest_path, {"target": target, "files": manifest})
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return destination


def verify_stage(state, target):
    directory = state / "releases" / target
    manifest = read_json(state / "releases" / (target + ".json"))
    if not manifest or manifest.get("target") != target:
        raise UpdateError("Candidate manifest missing; stage the pinned target first")
    paths = list(directory.rglob("*"))
    if any(p.is_symlink() for p in paths):
        raise UpdateError("Staged candidate contains a symlink")
    actual = {p.relative_to(directory).as_posix() for p in paths if p.is_file()}
    if actual != set(manifest["files"]):
        raise UpdateError("Staged candidate inventory changed")
    for relative, expected in manifest["files"].items():
        if file_hash(safe_path(directory, relative)) != expected:
            raise UpdateError("Staged candidate integrity check failed")
    return directory


def validate_candidate(directory):
    """Parse application sources without importing/running candidate code."""
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if not path.is_file() or not managed(relative):
            continue
        data = path.read_bytes()
        try:
            if path.suffix == ".py" or re.match(rb"^#![^\n]*python", data):
                ast.parse(data.decode("utf-8"), filename=relative)
            elif path.suffix in {".json", ".webmanifest"}:
                json.loads(data.decode("utf-8"))
            elif path.suffix == ".sh" or re.match(rb"^#![^\n]*(?:bash|/sh)\b", data):
                result = subprocess.run(["bash", "-n"], input=data, capture_output=True)
                if result.returncode:
                    raise UpdateError("Shell syntax validation failed: " + relative)
        except (SyntaxError, ValueError, UnicodeError):
            raise UpdateError("Candidate source syntax validation failed: " + relative)


def restore(source, state, transaction, interrupted=False):
    journal_path = state / "backups" / transaction / "transaction.json"
    journal = read_json(journal_path)
    if not journal or journal.get("source_root") != str(source.resolve()):
        raise UpdateError("Unknown transaction for this installation")
    if journal.get("status") == "rolled_back":
        return {"transaction": transaction, "status": "already_rolled_back"}
    current_state = read_json(state / "current.json", {})
    if interrupted and current_state and current_state.get("transaction") != transaction and current_state != journal["previous_state"]:
        raise UpdateError("Another transaction is active; interrupted recovery refused")
    if not interrupted and current_state.get("transaction") != transaction:
        raise UpdateError("Only the latest applied transaction may be rolled back")
    for item in journal["files"]:
        path = safe_path(source, item["path"])
        current = file_hash(path)
        acceptable = {item["after"]}
        if interrupted:
            acceptable.add(item["before"])
        if current not in acceptable:
            raise UpdateError("Local file changed after update; rollback refused: " + item["path"])
        if item["before"] is not None:
            backup = safe_path(journal_path.parent / "files", item["path"])
            if file_hash(backup) != item["before"]:
                raise UpdateError("Backup integrity check failed")
    for item in reversed(journal["files"]):
        path = safe_path(source, item["path"])
        if item["before"] is None:
            path.unlink(missing_ok=True)
        else:
            backup = safe_path(journal_path.parent / "files", item["path"])
            data = backup.read_bytes()
            if sha(data) != item["before"]:
                raise UpdateError("Backup integrity check failed")
            atomic(path, data, item["mode"])
    if journal["previous_state"] is None:
        (state / "current.json").unlink(missing_ok=True)
    else:
        write_json(state / "current.json", journal["previous_state"])
    journal["status"] = "rolled_back"
    write_json(journal_path, journal)
    return {"transaction": transaction, "status": "rolled_back", "scope": "owned code files only; no database rollback"}


def apply_code(source, state, target):
    with lock(state):
        information = plan(source, state, target)
        if not re.fullmatch(r"[0-9a-f]{40}", target):
            raise UpdateError("apply-code requires a pinned full SHA")
        if not information["can_apply_code"]:
            raise UpdateError("Local code changes or dependency/migration changes require manual review; inspect plan")
        staged = verify_stage(state, target)
        validate_candidate(staged)
        if not information["code_files"]:
            return {"status": "no_code_changes", "plan": information}
        transaction = uuid.uuid4().hex
        backup_root = state / "backups" / transaction
        journal = {"schema_version": 1, "transaction": transaction, "source_root": str(source.resolve()),
                   "target": target, "status": "applying", "files": [],
                   "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "previous_state": read_json(state / "current.json")}
        for relative in information["code_files"]:
            source_path, target_path = safe_path(source, relative), safe_path(staged, relative)
            before = source_path.read_bytes() if source_path.is_file() else None
            after = target_path.read_bytes() if target_path.is_file() else None
            mode = stat.S_IMODE(source_path.stat().st_mode) if before is not None else (0o755 if target_path.exists() and target_path.stat().st_mode & 0o111 else 0o644)
            if before is not None:
                atomic(safe_path(backup_root / "files", relative), before, 0o600)
            journal["files"].append({"path": relative, "before": sha(before) if before is not None else None,
                                     "after": sha(after) if after is not None else None, "mode": mode})
        write_json(backup_root / "transaction.json", journal)
        try:
            for item in journal["files"]:
                path = safe_path(source, item["path"])
                if file_hash(path) != item["before"]:
                    raise UpdateError("Source changed during update")
                if item["after"] is None:
                    path.unlink()
                else:
                    data = safe_path(staged, item["path"]).read_bytes()
                    if sha(data) != item["after"]:
                        raise UpdateError("Candidate changed during update")
                    atomic(path, data, item["mode"])
            write_json(state / "current.json", {"source_root": str(source.resolve()), "source_head": information["source_head"],
                                               "code_revision": target, "transaction": transaction})
            journal["status"] = "applied"
            write_json(backup_root / "transaction.json", journal)
        except BaseException:
            restore(source, state, transaction, interrupted=True)
            raise
        return {"status": "applied_code", "transaction": transaction, "files": len(journal["files"]), "scope": information["scope"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "fetch", "stage", "apply-code", "rollback", "recover", "status"], nargs="?", default="plan")
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/omni-siem-updater"))
    parser.add_argument("--target", help="commit/tag/ref for plan; pinned full SHA for stage/apply-code")
    parser.add_argument("--remote", default=DEFAULT_REMOTE)
    parser.add_argument("--ref", default="main")
    parser.add_argument("--transaction")
    args = parser.parse_args(argv)
    source, state = args.source.resolve(), args.state_dir.resolve()
    if source == state or source in state.parents or state in source.parents:
        raise UpdateError("State directory and source checkout must be separate directory trees")
    if args.command in {"plan", "stage", "apply-code"} and not args.target:
        parser.error("--target is required (fetch prints a pinned target)")
    if args.command == "plan":
        result = plan(source, state, args.target)
    elif args.command == "fetch":
        result = fetch(source, state, args.remote, args.ref)
    elif args.command == "stage":
        with lock(state):
            result = {"staged": str(stage(source, state, args.target)), "target": args.target}
    elif args.command == "apply-code":
        result = apply_code(source, state, args.target)
    elif args.command in {"rollback", "recover"}:
        if not args.transaction or not re.fullmatch(r"[0-9a-f]{32}", args.transaction):
            parser.error("--transaction must be the transaction ID returned by apply-code")
        with lock(state):
            if args.command == "recover":
                journal = read_json(state / "backups" / args.transaction / "transaction.json", {})
                if journal.get("status") != "applying":
                    raise UpdateError("recover requires an interrupted transaction marked applying")
            result = restore(source, state, args.transaction, interrupted=args.command == "recover")
    else:
        result = {"source_root": str(source), "source_head": resolve(source, "HEAD"), "update": read_json(state / "current.json"),
                  "lock_present": (state / "update.lock").exists()}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (UpdateError, OSError, ValueError) as exc:
        raise SystemExit("Update refused: " + str(exc))
