#!/usr/bin/env python3
"""Contrôle hors ligne de manifeste-deploye.txt (CI et poste de travail).

Vérifie : format <cible><TAB><source>, cibles dans les répertoires autorisés et
uniques, sources suivies par Git, aucune source référençant l'ancien emplacement
du dépôt (sauf unité de base recopiée de la production, signalée si aucun drop-in
50-depot-reference.conf ne la repointe), aucun mot de passe masqué par synchro-manifeste.sh, et chaque fichier de
deploye/sbin et deploye/systemd présent dans le manifeste. Code 1 si un défaut.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy.engine import LEGACY_HOME, MANIFEST, PLACEHOLDER, parse_manifest  # noqa: E402


def check(root: Path):
    entries, errors = parse_manifest((root / MANIFEST).read_text(encoding="utf-8"))
    warnings, targets = [], {target for target, _ in entries}
    tracked = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0"))
    for target, source in entries:
        path = root / source
        if source not in tracked or not path.is_file():
            errors.append(f"source absente ou non suivie : {source}")
            continue
        data = path.read_bytes()
        if LEGACY_HOME.encode() in data:
            unit = target.removeprefix("/etc/systemd/system/").split("/")[0].removesuffix(".d")
            dropin = f"/etc/systemd/system/{unit}.d/50-depot-reference.conf"
            if not target.startswith("/etc/systemd/system/"):
                errors.append(f"{source} référence l'ancien emplacement {LEGACY_HOME}")
            elif dropin not in targets:
                warnings.append(f"{source} référence {LEGACY_HOME} sans drop-in de repointage")
        if PLACEHOLDER.encode() in data:
            errors.append(f"{source} contient un mot de passe masqué ({PLACEHOLDER}) : non déployable")
    listed = {source for _, source in entries}
    for name in sorted(tracked):
        if name.startswith(("deploye/sbin/", "deploye/systemd/")) and name not in listed:
            errors.append(f"{name} n'est pas dans le manifeste (relancer generer-manifeste.sh sur le serveur)")
    return entries, errors, warnings


def main():
    entries, errors, warnings = check(ROOT)
    for warning in warnings:
        print("AVERT  " + warning)
    for error in errors:
        print("ERREUR " + error)
    print(f"{len(entries)} entrées, {len(errors)} défaut(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
