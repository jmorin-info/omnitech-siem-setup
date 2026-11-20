#!/usr/bin/env python3
"""Plan or install a fresh core SOC. Never run every numbered script.

python3 tools/install-platform.py [--plan | --apply] [--resume] [--with triage]
An existing host is refused except when resuming this install's recorded phases.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PHASES = (
    ("base", "01-base.sh"),
    ("preflight", "00-preflight.sh"),
    ("mongodb", "02-mongodb.sh"),
    ("opensearch", "03-opensearch.sh"),
    ("graylog", "04-graylog.sh"),
    ("proxy", "05-nginx-tls.sh"),
    ("firewall", "06-firewall.sh"),
    ("inputs", "07-inputs.sh"),
    ("model", "10-graylog-model.sh"),
    ("enrichment", "11-graylog-enrichment.sh"),
    ("pipelines", "12-graylog-pipelines.sh"),
    ("detections", "13-graylog-alerts.sh"),
    ("dashboards", "14-graylog-dashboards.sh"),
    ("console", "71-soc-console.sh"),
    ("backups", "08-backup.sh"),
    ("verification", "tools/verify-installation.py"),
)
OPTIONAL = {"triage": ("triage", "38-alert-triage.sh")}
SECRET_KEYS = ("GRAYLOG_ADMIN_PASS", "MONGO_ADMIN_PASS", "MONGO_GRAYLOG_PASS", "OPENSEARCH_BOOTSTRAP_PASS")
GENERATED_SECRET_KEYS = ("MONGO_ADMIN_PASS", "MONGO_GRAYLOG_PASS", "OPENSEARCH_BOOTSTRAP_PASS")
REQUIRED = ("SIEM_FQDN", "SIEM_HOSTNAME", "SIEM_DOMAIN", "SIEM_IP", "SIEM_PREFIX", "SIEM_GW", "SIEM_IFACE",
            "DNS1", "DNS2", "NTP1", "NTP2", "NET_ADMIN", "NET_BEATS", "OS_HEAP", "GL_HEAP",
            "MONGO_CACHE_GB", "JOURNAL_SIZE", "DATA_MOUNT", "BACKUP_DIR", "RETENTION_DAYS", "SMTP_RELAY", "SMTP_FROM", "ALERT_EMAIL")


def installation_phases(extras):
    phases = list(PHASES)
    for extra in dict.fromkeys(extras):
        phases.insert(next(index for index, (name, _) in enumerate(phases) if name == "detections"), OPTIONAL[extra])
    return phases


def load_config(path):
    # The same trusted shell config is sourced by the existing provisioning scripts.
    # Capture it privately; never print environment or secret values.
    command = 'set -e; set -a; source "$1"; exec python3 -c \'import json,os; print(json.dumps(dict(os.environ)))\''
    proc = subprocess.run(["bash", "-c", command, "omni-config", str(path)], capture_output=True, text=True)
    if proc.returncode:
        raise ValueError("site configuration could not be loaded (check its shell syntax)")
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise ValueError("site configuration must contain assignments only") from None


def validate_config(config):
    errors = []
    for key in (*REQUIRED, *SECRET_KEYS):
        value = config.get(key, "")
        if not value or "CHANGEME" in value or (key in SECRET_KEYS and len(value) < 12):
            errors.append(key + " must be configured")
    for key in ("SIEM_FQDN", "SIEM_HOSTNAME", "SIEM_DOMAIN", "SIEM_IFACE"):
        value = config.get(key, "")
        if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_" for c in value):
            errors.append(key + " contains unsupported characters")
    for key in ("SIEM_IP", "SIEM_GW", "DNS1", "DNS2"):
        try:
            if ipaddress.ip_address(config.get(key, "")).version != 4:
                raise ValueError()
        except ValueError:
            errors.append(key + " must be an IPv4 address")
    for key in ("NET_ADMIN", "NET_BEATS", "WEB_NET"):
        if key == "WEB_NET" and not config.get(key):
            continue
        try:
            ipaddress.ip_network(config.get(key, ""), strict=False)
        except ValueError:
            errors.append(key + " must be an IP subnet")
    if config.get("DATA_DISK") and config.get("ALLOW_FORMAT_DATA_DISK", "0") != "1":
        errors.append("DATA_DISK must be empty for pre-mounted storage, or explicitly authorized with ALLOW_FORMAT_DATA_DISK=1")
    if config.get("THP_MODE", "preserve") not in ("preserve", "enable", "disable"):
        errors.append("THP_MODE must be preserve, enable or disable")
    timeout = config.get("BACKUP_SNAPSHOT_TIMEOUT_SECONDS", "3600")
    if not re.fullmatch(r"[1-9][0-9]*", timeout) or not 1 <= int(timeout) <= 86400:
        errors.append("BACKUP_SNAPSHOT_TIMEOUT_SECONDS must be an integer from1 to86400")
    ssh_source = os.environ.get("SSH_CONNECTION", "").split()
    if ssh_source:
        try:
            if ipaddress.ip_address(ssh_source[0]) not in ipaddress.ip_network(config["NET_ADMIN"], strict=False):
                errors.append("current SSH client is outside NET_ADMIN; firewall installation would disconnect it")
        except (KeyError, ValueError):
            errors.append("cannot validate SSH client against NET_ADMIN")
    return errors


def resource_blockers(config, total_kib):
    errors, heap_gib = [], {}
    for key in ("OS_HEAP", "GL_HEAP"):
        match = re.fullmatch(r"([1-9][0-9]*)([gGmM])", config.get(key, ""))
        if not match:
            errors.append(key + " must be a JVM size such as 4g or 2048m")
        else:
            heap_gib[key] = int(match[1]) * (1 if match[2].lower() == "g" else 1 / 1024)
    cache = config.get("MONGO_CACHE_GB", "")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", cache) or float(cache) < 0.25:
        errors.append("MONGO_CACHE_GB must be a number of at least 0.25")
    elif len(heap_gib) == 2 and sum(heap_gib.values()) + float(cache) + 3 > total_kib / (1024 * 1024):
        errors.append("configured JVM heaps plus MongoDB cache leave less than3GB for the OS and services; reduce OS_HEAP/GL_HEAP or allocate more RAM")
    return errors


def read_os(path=Path("/etc/os-release")):
    values = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return values.get("ID"), values.get("VERSION_ID")


def existing_install(paths=None):
    paths = paths if paths is not None else [Path("/etc/graylog/server/server.conf"), Path("/etc/mongod.conf"), Path("/etc/opensearch/opensearch.yml")]
    return [str(path) for path in paths if path.exists()]


def platform_check(os_id, version, experimental=False):
    if (os_id, version) == ("ubuntu", "26.04"):
        if not experimental:
            return ["Ubuntu 26.04 requires --experimental-ubuntu-2604; Ubuntu 24.04 is the supported Ubuntu target"], []
        return [], ["EXPERIMENTAL Ubuntu 26.04: Graylog/MongoDB 8.0 do not list this OS; using MongoDB noble packages without a vendor support guarantee"]
    supported = (("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12"), ("debian", "13"))
    return ([] if (os_id, version) in supported else ["supported install platforms: Ubuntu 22.04/24.04, Debian 12/13 amd64"]), []


def kernel_blocker(release, kernel_version=None, version_signature=None):
    # Ubuntu keeps uname -r at 7.0.0 even after upstream fixes are backported.
    # Match MongoDB 8.0.38's SERVER-131779 handling of the running Ubuntu kernel.
    effective = release
    kernel_version = platform.version() if kernel_version is None else kernel_version
    if release.startswith("7.0.") and "Ubuntu" in kernel_version:
        if version_signature is None:
            try:
                version_signature = Path("/proc/version_signature").read_text().splitlines()[0]
            except (OSError, IndexError):
                version_signature = ""
        signature = re.fullmatch(r"Ubuntu\s+(7\.0\.\d+\S*)\s+(7\.0\.\d+\S*)\s*", version_signature)
        if signature:
            # The second field includes Ubuntu's upload number after its ABI.
            # Ignore stale or unrelated fixture metadata instead of trusting it.
            running = re.sub(r"^(\d+\.\d+\.\d+-\d+)\.[^-]+", r"\1", signature[1])
            if running == release:
                effective = signature[2]
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", effective)
    if match:
        version = tuple(int(value or 0) for value in match.groups())
        if (6, 19, 0) <= version < (7, 0, 14) or version == (7, 0, 14) and "rc" in effective:
            detail = release + (" (upstream " + effective + ")" if effective != release else "")
            return "MongoDB 8.0 cannot run on kernel " + detail + "; use a compatible kernel (7.0.14+ fixes the affected 6.19–7.0.13 range)"
    return None


def source_inventory(root):
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    manifest = {}
    for name in sorted(filter(None, names)):
        path = root / name
        if path.is_symlink():
            raise ValueError("symlinked installation sources are refused: " + name)
        manifest[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    fingerprint = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return fingerprint, manifest


def generate_missing_secrets(path):
    if path.is_symlink():
        raise ValueError("symlinked configuration is refused")
    if not path.exists():
        raise ValueError("create 00-vars.env from 00-vars.env.example first")
    if existing_install():
        raise ValueError("secret generation is for a fresh installation only; no credentials are rotated on existing services")
    config = load_config(path)
    # OpenSearch's package checks all four character classes during bootstrap.
    updates = {key: "Aa1!" + secrets.token_urlsafe(36) for key in GENERATED_SECRET_KEYS
               if not config.get(key) or "CHANGEME" in config[key]}
    if not updates:
        return []
    lines, found = [], set()
    for line in path.read_text().splitlines():
        match = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=", line)
        if match and match[1] in updates:
            lines.append(match[1] + "=" + shlex.quote(updates[match[1]]))
            found.add(match[1])
        else:
            lines.append(line)
    lines.extend(key + "=" + shlex.quote(value) for key, value in updates.items() if key not in found)
    temporary = path.with_name(".00-vars.generate-" + secrets.token_hex(8))
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            output.write("\n".join(lines) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return sorted(updates)


def write_private(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with os.fdopen(os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    os.replace(temp, path)


def snapshot_local_changes(root, directory, revision, manifest):
    write_private(directory / "manifest.json", {"source_revision": revision, "files": manifest})
    patch = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=root)
    path = directory / "local.patch"
    if path.is_symlink():
        raise ValueError("symlinked source snapshot is refused")
    if path.exists():
        if path.read_bytes() != patch:
            raise ValueError("existing source snapshot differs; inspect it before retrying")
        return
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(patch)


def prepare_triage(config, path=Path("/etc/omni-alert-triage.env")):
    """Create a neutral tenant config before the optional legacy installer runs."""
    if path.exists():
        return
    values = {"SMTP_HOST": config["SMTP_RELAY"], "SMTP_PORT": config.get("SMTP_PORT", "25"),
              "SMTP_FROM": config["SMTP_FROM"], "MAIL_RECIPIENTS": config["ALERT_EMAIL"],
              "OMNI_SOC_URL": "https://" + config["SIEM_FQDN"] + "/soc/",
              "TRIAGE_TOKEN": secrets.token_hex(32), "QUICK_SECRET": secrets.token_hex(32),
              "TRIAGE_FP_ENTITIES": "", "TRIAGE_DEDUP_SECONDS": "3600",
              "MAIL_SCORE_THRESHOLD": "80", "GRAY_SCORE_THRESHOLD": "70", "OMNI_TRIAGE_LLM_REDACT": "true"}
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("triage config values cannot contain newlines")
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
        stream.write("\n".join(key + "=" + value for key, value in values.items()) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--experimental-ubuntu-2604", action="store_true", help="explicitly try Ubuntu 26.04 using the noble MongoDB 8 repository")
    parser.add_argument("--allow-local-changes", action="store_true", help="preserve and fingerprint reviewed local source edits, without requiring a Git commit")
    parser.add_argument("--generate-secrets", action="store_true", help="generate missing MongoDB/OpenSearch technical passwords locally, then exit")
    parser.add_argument("--with", dest="extras", choices=tuple(OPTIONAL), action="append", default=[])
    args = parser.parse_args(argv)
    config_path = ROOT / "00-vars.env"
    if config_path.is_symlink():
        raise ValueError("symlinked site configuration is refused")
    if args.generate_secrets:
        if args.plan or args.apply or args.resume:
            parser.error("--generate-secrets is a separate explicit operation; run --plan afterwards")
        generated = generate_missing_secrets(config_path)
        print(json.dumps({"generated_keys": generated, "values": "kept only in 00-vars.env; existing credentials preserved"}))
        return 0
    cfg = load_config(config_path) if config_path.exists() else {}
    blockers = validate_config(cfg) if cfg else ["create 00-vars.env from 00-vars.env.example"]
    os_id, os_version = read_os() if Path("/etc/os-release").exists() else (platform.system(), platform.release())
    os_blockers, warnings = platform_check(os_id, os_version, args.experimental_ubuntu_2604)
    blockers.extend(os_blockers)
    kernel_error = kernel_blocker(platform.release()) if os_id in ("ubuntu", "debian") else None
    if kernel_error:
        blockers.append(kernel_error)
    if platform.machine().lower() not in ("x86_64", "amd64"):
        blockers.append("this profile currently supports amd64 only")
    if Path("/proc/cpuinfo").exists() and "avx" not in Path("/proc/cpuinfo").read_text().split():
        blockers.append("MongoDB requires CPU AVX support")
    if Path("/proc/meminfo").exists():
        total_kib = int(Path("/proc/meminfo").read_text().split("MemTotal:", 1)[1].split()[0])
        if total_kib < 15 * 1024 * 1024:
            blockers.append("core SOC profile requires at least16GB host RAM (adjust JVM heaps to host capacity)")
        if cfg:
            blockers.extend(resource_blockers(cfg, total_kib))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True)
    source_fingerprint, source_manifest = source_inventory(ROOT)
    if dirty.strip() and not args.allow_local_changes:
        blockers.append("tracked installation sources are locally modified; inspect git diff then use --allow-local-changes to preserve and snapshot them (no local commit required)")
    elif dirty.strip():
        warnings.append("Reviewed local source changes will be preserved and snapshotted; no Git reset, commit or overwrite is performed")
    phases = installation_phases(args.extras)
    state_path = Path("/var/lib/omni-siem/install-state.json")
    metadata_path = Path("/etc/omni-siem/instance.json")
    state = json.loads(state_path.read_text()) if state_path.exists() else None
    config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest() if config_path.exists() else None
    identity = {"source_root": str(ROOT), "source_revision": revision, "profile": "core-soc", "config_sha256": config_sha, "extras": sorted(set(args.extras))}
    if not args.resume or args.allow_local_changes or args.experimental_ubuntu_2604 or state and "source_fingerprint" in state:
        identity.update(source_fingerprint=source_fingerprint, experimental_ubuntu_2604=args.experimental_ubuntu_2604)
    if args.resume:
        if not state or any(state.get(key) != value for key, value in identity.items()):
            blockers.append("resume requires the same source revision, config and optional components as the recorded installation")
    elif existing_install() or metadata_path.exists() or state:
        blockers.append("an installation already exists; use the updater or resume this installer, never reprovision an existing SIEM")
    plan = {"mode": "apply" if args.apply else "plan", "profile": "core-soc", "platform": f"{os_id}:{os_version}",
            "source_revision": revision, "steps": [{"phase": name, "script": script} for name, script in phases],
            "blockers": blockers, "warnings": warnings, "source_fingerprint": source_fingerprint,
            "external_components": ["M365/SEAL/vendor collectors need their own credentials and source configuration", "ML/XDR/graph, SOAR and active scans are not enabled by this profile"],
            "database_policy": "fresh install only; no existing database upgrade or overwrite"}
    print(json.dumps(plan, indent=2, ensure_ascii=False), flush=True)
    if not args.apply:
        return 0
    if blockers:
        raise ValueError("installation refused: resolve the plan's blockers")
    if os.geteuid() != 0:
        raise ValueError("apply requires root")
    if config_path.stat().st_mode & 0o077:
        raise ValueError("00-vars.env must be readable by root only (chmod600)")
    if not state:
        state = {"schema_version": 1, **identity, "allow_local_changes": args.allow_local_changes,
                 "completed_phases": [], "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        if args.allow_local_changes:
            snapshot = state_path.parent / "install-sources" / source_fingerprint
            snapshot_local_changes(ROOT, snapshot, revision, source_manifest)
    write_private(state_path, state)
    child_env = dict(os.environ, OMNI_FRESH_INSTALL="1")
    child_env["OMNI_EXPERIMENTAL_UBUNTU_2604"] = "1" if args.experimental_ubuntu_2604 else "0"
    for name, script in phases:
        if name in state["completed_phases"] and name != "verification":
            continue
        if source_inventory(ROOT)[0] != source_fingerprint:
            raise ValueError("installation sources changed during execution; stop and review before resuming")
        state["current_phase"] = name
        write_private(state_path, state)
        if name == "triage":
            prepare_triage(cfg)
        interpreter = sys.executable if script.endswith(".py") else "bash"
        # Package keyrings and parent directories must remain readable by services,
        # even when the operator uses umask077. Secret files set private modes explicitly.
        result = subprocess.run([interpreter, str(ROOT / script)], cwd=ROOT, env=child_env, umask=0o022)
        if result.returncode:
            raise ValueError(f"phase {name} failed (exit{result.returncode}); repair it and resume with the same options")
        if name not in state["completed_phases"]:
            state["completed_phases"].append(name)
        write_private(state_path, state)
    state["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_private(state_path, state)
    write_private(metadata_path, {"schema_version": 1, "source_root": str(ROOT), "source_revision": revision,
                                  "profile": "core-soc", "installed_at": state["finished_at"]})
    print("Core SOC installation completed. Open https://" + cfg["SIEM_FQDN"] + "/soc/ . See docs/INSTALLATION.md for acceptance checks.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("Installation failed: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
