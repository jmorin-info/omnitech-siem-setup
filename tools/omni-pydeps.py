#!/usr/bin/env python3
"""Verrouillage et audit des dépendances Python des venvs (python-locks/venvs.json).

  audit [--venv ID] [--json] [--vuln]   compare chaque venv à son verrouillage (lecture seule)
  lock  --venv ID [--write]             relève les versions exactes du venv (stdout ou fichier du dépôt)

--vuln lance pip-audit s'il est installé (interroge une base distante : réseau requis).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omni_update import pydeps  # noqa: E402
from omni_update.system import System  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["audit", "lock"])
    parser.add_argument("--venv", help="identifiant du venv (voir python-locks/venvs.json)")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--vuln", action="store_true", help="scan pip-audit explicite (réseau)")
    parser.add_argument("--write", action="store_true", help="écrire le fichier de verrouillage dans le dépôt")
    args = parser.parse_args(argv)
    system = System()
    entries = pydeps.load_inventory(args.source, system)
    if args.venv:
        entries = [e for e in entries if e["id"] == args.venv]
        if not entries:
            parser.error("venv inconnu : " + args.venv)
    if args.command == "lock":
        if len(entries) != 1:
            parser.error("lock exige --venv")
        entry = entries[0]
        venv = pydeps.resolve_venv(entry, args.source, system)
        packages = pydeps.installed_packages(system, venv) if venv else None
        if packages is None:
            print("venv introuvable ou pip list impossible", file=sys.stderr)
            return 1
        text = pydeps.render_lock(entry, packages, dt.date.today().isoformat(), venv)
        if args.write:
            (args.source / entry["lock"]).write_text(text, encoding="utf-8")
            print("écrit : " + entry["lock"])
        else:
            print(text, end="")
        return 0
    results = [pydeps.audit_venv(entry, args.source, system) for entry in entries]
    if args.vuln:
        for entry, result in zip(entries, results):
            result["vulnerability_scan"] = pydeps.vulnerability_scan(entry, args.source, system)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(f"[{result['status']}] {result['id']} ({result['venv'] or 'venv absent'}) : {result['detail']}")
            for key, label in (("mismatched", "versions différentes"), ("missing", "absents du venv"),
                               ("extra", "non verrouillés"), ("unpinned_requirements", "bornes ouvertes")):
                if result.get(key):
                    values = [f"{m['name']} {m['locked']} -> {m['installed']}" if isinstance(m, dict) else m for m in result[key]]
                    print(f"    {label} : " + ", ".join(values))
            if result.get("vulnerability_scan"):
                print("    vulnérabilités : " + result["vulnerability_scan"]["detail"])
    return 0 if all(r["status"] in {"ok", "info"} for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
