#!/usr/bin/python3
"""Stable package entry point. Package upgrades never mutate the active checkout."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

PAYLOAD = Path("/usr/share/omni-siem/source")
REMOTE = "https://github.com/jmorin-info/omnitech-siem-setup.git"
DEFAULT_ROOT = Path("/opt/omni-siem/repository")


class DistributionError(RuntimeError):
    pass


def git(root, *args):
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0"}
    # No credentials, inherited repository selection or external hooks.
    for key in list(env):
        if key.startswith("GIT_") and key not in {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT"}:
            env.pop(key)
    trust = ["-c", "safe.directory=" + str(PAYLOAD)] if root == PAYLOAD else []
    result = subprocess.run(["git", *trust, "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
                            capture_output=True, text=True, env=env, timeout=300, umask=0o022)
    if result.returncode:
        raise DistributionError("Git operation failed; no repository files were overwritten")
    return result.stdout.strip()


def safe_root(root):
    if not root.is_absolute() or ".." in root.parts:
        raise DistributionError("--root must be an absolute installation directory")
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise DistributionError("symlinked installation paths are refused")
    root = root.resolve()
    protected = (Path("/usr"), Path("/etc"), Path("/bin"), Path("/sbin"), Path("/lib"), Path("/var/lib"))
    if len(root.parts) < 3 or any(root == p or p in root.parents for p in protected) or root == PAYLOAD or PAYLOAD in root.parents:
        raise DistributionError("choose a dedicated directory under /opt, /srv or a site-owned path")
    return root


def initialize(root, apply=False, payload=PAYLOAD):
    root = safe_root(root)
    target = git(payload, "rev-parse", "HEAD")
    plan = {"action": "initialize", "root": str(root), "package_revision": target,
            "apply": apply, "configuration": "00-vars.env created privately from the example; edit before installing",
            "services_changed": False}
    if root.exists():
        raise DistributionError("installation directory already exists; select it with --root and use the update tools")
    if not apply:
        return plan
    if os.geteuid() != 0:
        raise DistributionError("initialization requires root")
    missing = []
    parent = root.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
    temporary = Path(tempfile.mkdtemp(prefix=".omni-init-", dir=root.parent))
    try:
        # A new shallow checkout with the real upstream commit, never a synthetic commit.
        git(root.parent, "clone", "--no-local", "--single-branch", "--branch", "main", str(payload), str(temporary / "repo"))
        candidate = temporary / "repo"
        git(candidate, "remote", "set-url", "origin", REMOTE)
        if git(candidate, "rev-parse", "HEAD") != target or git(candidate, "status", "--porcelain"):
            raise DistributionError("packaged checkout verification failed")
        config = candidate / "00-vars.env"
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write((candidate / "00-vars.env.example").read_bytes())
        os.rename(candidate, root)
    finally:
        shutil.rmtree(temporary)
    return plan


def status(root, payload=PAYLOAD):
    package_revision = git(payload, "rev-parse", "HEAD")
    result = {"package": json.loads((payload / "distribution/version.json").read_text()),
              "package_revision": package_revision, "active_root": str(root), "initialized": root.is_dir(),
              "policy": "apt/dnf update the distribution only; active services and databases require an explicit reviewed deployment"}
    if root.is_dir():
        result.update(active_revision=git(root, "rev-parse", "HEAD"),
                      tracked_changes=bool(git(root, "status", "--porcelain", "--untracked-files=no")))
        result["package_matches_active"] = result["active_revision"] == package_revision and not result["tracked_changes"]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="active site checkout; preserved across package upgrades")
    parser.add_argument("command", choices=("version", "status", "init", "configure", "install", "update", "modules", "catalogue", "health", "agent"))
    args, rest = parser.parse_known_args(argv)
    root = safe_root(args.root)
    if args.command in {"version", "status", "init"}:
        if args.command == "init":
            if rest not in ([], ["--plan"], ["--apply"]):
                parser.error("init accepts --plan (default) or --apply")
            result = initialize(root, apply=rest == ["--apply"])
        else:
            if rest:
                parser.error("unexpected arguments")
            result = json.loads((PAYLOAD / "distribution/version.json").read_text()) if args.command == "version" else status(root)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if args.command in {"configure", "install", "update", "modules", "health"} and not root.is_dir():
        raise DistributionError("run omni-siem init --plan then sudo omni-siem init --apply, or select an existing checkout with --root")
    source = root if root.is_dir() else PAYLOAD
    commands = {"configure": ["tools/omni-manager.py"], "update": ["tools/omni-manager.py"],
                "install": ["tools/install-platform.py"], "modules": ["tools/omni-integrations.py"],
                "catalogue": ["tools/omni-manager.py", "--inventory"],
                "health": ["tools/omni-healthcheck.py", "--config", str(source / "00-vars.env")],
                "agent": ["tools/install-linux-agent.py"]}
    command = commands[args.command]
    # All arguments remain separate argv entries: no shell evaluation.
    env = dict(os.environ)
    if source == PAYLOAD:
        # The packaged, root-owned read-only tree is trusted only for this invocation.
        # Never disable Git's ownership check globally or trust arbitrary site paths.
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0=str(PAYLOAD))
    return subprocess.call([sys.executable, str(source / command[0]), *command[1:], *rest], cwd=source, env=env)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DistributionError as error:
        print("Operation refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, subprocess.SubprocessError):
        # Detailed subprocess output can contain site credentials.
        print("Operation refused or failed. Check the selected path, permissions and prerequisites; the package never reprovisions an existing SIEM.", file=sys.stderr)
        raise SystemExit(1)
