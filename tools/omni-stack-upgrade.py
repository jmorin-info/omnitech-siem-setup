#!/usr/bin/env python3
"""Montée de version paramétrée de la pile (Graylog, OpenSearch, MongoDB, Logstash).

Par défaut : plan (dry-run) en lecture seule. L'exécution exige --execute et
--confirm <composant>=<version>. À lancer dans tmux/screen : une coupure SSH ne
doit pas interrompre apt. Runbook : docs/UPDATES.md, section « Pile ».

  plan     --component graylog --to 7.2.2-2
  apply    --component graylog --to 7.2.2-2 --execute --confirm graylog=7.2.2-2
  rollback --journal /var/lib/omni-siem-stack-upgrade/<id>.json [--execute --confirm rollback-graylog]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omni_update import stack  # noqa: E402
from omni_update.system import System  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["plan", "apply", "rollback"])
    parser.add_argument("--component", choices=sorted(stack.COMPONENTS))
    parser.add_argument("--to", dest="target", help="version de paquet cible exacte (apt-cache policy)")
    parser.add_argument("--execute", action="store_true", help="exécuter réellement (sinon dry-run)")
    parser.add_argument("--confirm", help="confirmation explicite : <composant>=<version> ou rollback-<composant>")
    parser.add_argument("--journal", type=Path, help="journal d'une montée précédente (rollback)")
    parser.add_argument("--backup-dir", type=Path, help="racine des sauvegardes (défaut : BACKUP_DIR de 00-vars.env)")
    parser.add_argument("--state-dir", type=Path, default=stack.STATE_DIR)
    parser.add_argument("--allow-series-change", action="store_true", help="accepter un changement de série après revue")
    parser.add_argument("--allow-prerelease", action="store_true", help="accepter une pré-version (environnement de test)")
    parser.add_argument("--accept-no-package-rollback", action="store_true",
                        help="accepter l'absence du paquet de la version installée (retour arrière impossible)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    system = System()
    try:
        if args.command == "rollback":
            if not args.journal:
                parser.error("rollback exige --journal")
            report = stack.rollback(system, args.journal, execute=args.execute, confirm=args.confirm)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 0 if report["status"] in {"ready", "rolled_back"} else 1
        if not args.component or not args.target:
            parser.error("--component et --to sont requis")
        if args.command == "plan" and args.execute:
            parser.error("plan est en lecture seule : utiliser apply --execute")
        upgrade = stack.StackUpgrade(system, args.component, args.target, source=ROOT, state_dir=args.state_dir,
                                     backup_dir=args.backup_dir, allow_prerelease=args.allow_prerelease,
                                     allow_series_change=args.allow_series_change,
                                     accept_no_package_rollback=args.accept_no_package_rollback)
        report = upgrade.run(execute=args.command == "apply" and args.execute, confirm=args.confirm)
    except stack.StackError as error:
        print("Refusé : " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else stack.render(report))
    if args.command == "apply" and not args.execute:
        print("\nDry-run : rien n'a été exécuté. Ajouter --execute --confirm " + args.component + "=" + args.target)
    return 0 if report["status"] in {"ready", "success"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
