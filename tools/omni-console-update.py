#!/usr/bin/env python3
"""Mise à jour de l'environnement depuis la console SOC (voir docs/UPDATES.md, section 13).

  omni-console-update.py status                 état publié (lecture seule)
  omni-console-update.py plan [--tests]         plan et vérifications sur origin/main déjà récupéré,
                                                sans git fetch ni publication (lecture seule)
  omni-console-update.py check [--no-fetch] [--no-tests] [--force-tests]
                                                git fetch (arbre de travail intact), plan, tests
                                                hors ligne dans une copie temporaire, publication
                                                de status.json pour la console (unité -check)
  omni-console-update.py run-queue              traite les demandes transmises par
                                                omni-soc-admin-exec (unité omni-console-update)

Configuration : /etc/default/omni-console-update (ou OMNI_CONSOLE_UPDATE_CONFIG).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from omni_update import console  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="fichier de configuration (défaut : /etc/default/omni-console-update)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    plan = commands.add_parser("plan")
    plan.add_argument("--tests", action="store_true", help="exécuter aussi la suite de tests du candidat")
    check = commands.add_parser("check")
    check.add_argument("--no-fetch", action="store_true")
    check.add_argument("--no-tests", action="store_true")
    check.add_argument("--force-tests", action="store_true")
    check.add_argument("--from-request", action="store_true",
                       help="déclenché par la console : consomme le fichier check-request")
    commands.add_parser("run-queue")
    args = parser.parse_args(argv)
    cfg = console.load_config(args.config)
    updater = console.ConsoleUpdater(cfg)
    if args.command == "status":
        result = console.status(cfg)
    elif args.command == "plan":
        try:
            target = console.rev(cfg, console.upstream_ref(cfg))
        except console.OU.UpdateError:
            target = None
        result = updater.plan(target, run_tests=args.tests)
    elif args.command == "check":
        if args.from_request:
            (console.publish_dir(cfg) / "check-request").unlink(missing_ok=True)
        result = updater.check(do_fetch=not args.no_fetch, run_tests=not args.no_tests, force_tests=args.force_tests)
    else:
        result = updater.run_queue()
    print(json.dumps(result, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (console.ConsoleUpdateError, console.OU.UpdateError, OSError, ValueError) as exc:
        print("Mise à jour refusée : " + str(exc), file=sys.stderr)
        raise SystemExit(1)
