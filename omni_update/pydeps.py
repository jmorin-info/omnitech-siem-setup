"""Python virtual environments: lock files and drift audit (read-only).

The inventory python-locks/venvs.json lists each venv, the requirements file
that declares its direct dependencies (when one exists) and the lock file that
records the exact versions validated in production. The audit compares the
venv content ("pip list", which neither downloads nor installs anything) with
the lock. Vulnerability scanning is delegated to pip-audit when the operator
installs it and asks for it explicitly, because it queries a remote database.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

INVENTORY = "python-locks/venvs.json"
ALWAYS_IGNORED = {"pip", "setuptools", "wheel", "pkg-resources"}


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def load_inventory(source, system):
    text = system.read(Path(source) / INVENTORY)
    data = json.loads(text) if text else None
    if not data or data.get("schema_version") != 1 or not isinstance(data.get("venvs"), list):
        raise ValueError("Inventaire des venvs absent ou invalide : " + INVENTORY)
    identifiers = [entry["id"] for entry in data["venvs"]]
    if len(identifiers) != len(set(identifiers)) or any(not re.fullmatch(r"[a-z][a-z0-9-]*", i) for i in identifiers):
        raise ValueError("Identifiants de venv invalides ou dupliqués")
    return data["venvs"]


def parse_lock(text):
    pins = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;]+)", line)
        if match:
            pins[normalize(match.group(1))] = match.group(2)
    return pins


def parse_requirements(text):
    """Direct requirements: [(name, specifier)] ; '-r' includes are ignored here."""
    result = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)", line)
        if match:
            result.append((normalize(match.group(1)), match.group(3).split(";")[0].strip()))
    return result


def resolve_venv(entry, source, system):
    for candidate in entry.get("venv_candidates", []):
        path = candidate.replace("{source}", str(source))
        if system.exists(Path(path) / "bin" / "python"):
            return path
    return None


def installed_packages(system, venv):
    code, stdout, _ = system.run([str(Path(venv) / "bin" / "python"), "-m", "pip", "list", "--format=json",
                                  "--disable-pip-version-check", "--no-input"], timeout=120,
                                 env={"PIP_NO_INDEX": "1"})
    if code != 0:
        return None
    try:
        return {normalize(item["name"]): item["version"] for item in json.loads(stdout)}
    except (ValueError, KeyError, TypeError):
        return None


def python_version(system, venv):
    code, stdout, stderr = system.run([str(Path(venv) / "bin" / "python"), "--version"], timeout=30)
    return (stdout or stderr).strip() if code == 0 else None


def audit_venv(entry, source, system):
    ignored = ALWAYS_IGNORED | {normalize(name) for name in entry.get("ignore", [])}
    result = {"id": entry["id"], "description": entry.get("description", ""), "venv": None,
              "lock": entry.get("lock"), "requirements": entry.get("requirements"),
              "status": "inconnu", "missing": [], "extra": [], "mismatched": [], "unpinned_requirements": [],
              "requirements_not_in_lock": [], "detail": ""}
    lock_text = system.read(Path(source) / entry["lock"]) if entry.get("lock") else None
    pins = {name: version for name, version in parse_lock(lock_text).items() if name not in ignored}
    requirements = []
    if entry.get("requirements"):
        requirements = parse_requirements(system.read(Path(source) / entry["requirements"]))
    # Direct dependencies declared in the inventory when the component has no
    # requirements file (console backend: pywebpush, see 65-mobile-pwa.sh).
    requirements += [(normalize(name), "") for name in entry.get("direct", [])]
    result["unpinned_requirements"] = sorted(name for name, spec in requirements if not spec.startswith("=="))
    result["requirements_not_in_lock"] = sorted(name for name, _ in requirements if lock_text and name not in pins
                                                and name not in ignored)
    venv = resolve_venv(entry, source, system)
    result["venv"] = venv
    if not venv:
        result["status"] = "info" if entry.get("optional") else "attention"
        result["detail"] = "venv introuvable sur cet hôte"
        return result
    result["python"] = python_version(system, venv)
    packages = installed_packages(system, venv)
    if packages is None:
        result["detail"] = "pip list impossible dans ce venv"
        return result
    packages = {name: version for name, version in packages.items() if name not in ignored}
    result["installed_count"] = len(packages)
    if lock_text is None:
        result["status"] = "attention"
        result["detail"] = "aucun fichier de verrouillage : versions non reproductibles"
        return result
    result["missing"] = sorted(name for name in pins if name not in packages)
    result["extra"] = sorted(name for name in packages if name not in pins)
    result["mismatched"] = [{"name": name, "locked": pins[name], "installed": packages[name]}
                            for name in sorted(pins) if name in packages and packages[name] != pins[name]]
    if result["missing"] or result["mismatched"] or result["extra"] or result["requirements_not_in_lock"]:
        result["status"] = "attention"
        result["detail"] = "le venv diffère du verrouillage"
    else:
        result["status"] = "ok"
        result["detail"] = "conforme au verrouillage (%d paquets)" % len(pins)
    return result


def render_lock(entry, packages, generated_on, origin):
    ignored = ALWAYS_IGNORED | {normalize(name) for name in entry.get("ignore", [])}
    lines = ["# Verrouillage du venv " + entry["id"] + " - versions exactes relevées le " + generated_on,
             "# Origine : " + origin,
             "# Régénérer : python3 tools/omni-pydeps.py lock --venv " + entry["id"] + " --write",
             "# Réinstaller à l'identique : <venv>/bin/pip install --no-deps -r " + entry["lock"]]
    lines += [name + "==" + version for name, version in sorted(packages.items()) if name not in ignored]
    return "\n".join(lines) + "\n"


def vulnerability_scan(entry, source, system):
    """Explicit, network-dependent scan through pip-audit when installed."""
    code, _, _ = system.run(["pip-audit", "--version"], timeout=30)
    if code != 0:
        return {"id": entry["id"], "status": "inconnu", "detail": "pip-audit non installé : scan de vulnérabilités non réalisé"}
    code, stdout, _ = system.run(["pip-audit", "--requirement", str(Path(source) / entry["lock"]), "--no-deps",
                                  "--disable-pip", "--format", "json", "--progress-spinner", "off"], timeout=600)
    try:
        data = json.loads(stdout)
    except ValueError:
        return {"id": entry["id"], "status": "inconnu", "detail": "pip-audit sans résultat exploitable (réseau ?)"}
    dependencies = data.get("dependencies", data if isinstance(data, list) else [])
    findings = [{"name": item.get("name"), "version": item.get("version"),
                 "ids": [vuln.get("id") for vuln in item.get("vulns", [])]}
                for item in dependencies if item.get("vulns")]
    return {"id": entry["id"], "status": "attention" if findings else "ok", "vulnerabilities": findings,
            "detail": "%d paquet(s) vulnérable(s)" % len(findings) if findings else "aucune vulnérabilité connue"}
