#!/usr/bin/env python3
"""Déploiement des composants maison depuis le dépôt canonique (plan par défaut).

  omni-deploy.py deploy [COMPOSANT ...] [--apply]   plan, ou application transactionnelle
  omni-deploy.py rollback TRANSACTION [--apply]     plan, ou retour arrière d'une transaction
  omni-deploy.py history                            transactions enregistrées
  omni-deploy.py verify                             contrôle de santé de bout en bout (lecture seule)
  omni-deploy.py components                         liste des composants

Composants : all, venvs, robots, etc, opt, logstash, systemd, nginx, console, et apt
(préférences APT, uniquement sur demande explicite : jamais incluses dans « all »).
--root DIR désigne une racine factice : aucune commande système n'est lancée.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy.engine import COMPONENTS, DEFAULT_HOME, DEFAULT_STATE, Deployer, DeployError  # noqa: E402
from omni_deploy import health  # noqa: E402

STATE_LABELS = {"identique": "identique", "creer": "à créer", "remplacer": "à remplacer", "bloque": "BLOQUÉ",
                "droits": "droits à corriger",
                "construire": "à construire", "reconstruire": "à reconstruire"}


def render_plan(report, verbose=False):
    lines = [f"Dépôt source : {report['source']}", f"Dépôt canonique (OMNI_SIEM_HOME) : {report['home']}",
             f"Racine : {report['root']}" + ("" if report["system"] else " (factice : aucune commande système)"),
             "Composants : " + ", ".join(report["components"]),
             "Bilan : " + ", ".join(f"{STATE_LABELS.get(k, k)} {v}" for k, v in sorted(report["counts"].items()))]
    for item in report["venvs"]:
        if verbose or item["state"] != "identique":
            lines.append(f"  [venv] {STATE_LABELS[item['state']]:<15} {item['path']}" + (f" ({item['reason']})" if item.get("reason") else ""))
    for item in report["files"]:
        if verbose or item["state"] != "identique":
            lines.append(f"  [{item['component']}] {STATE_LABELS[item['state']]:<15} {item['target']} <- {item['source']}"
                         + (f" ({item['reason']})" if item.get("reason") else ""))
    for title, key in (("Actions associées", "actions"), ("Blocages", "blockers"), ("Avertissements", "warnings"), ("Notes", "notes")):
        if report.get(key):
            lines.append(title + " :")
            lines.extend("  - " + value for value in report[key])
    if report.get("transaction"):
        lines.append("Transaction : " + report["transaction"])
        lines.append("Retour arrière : python3 tools/omni-deploy.py rollback " + report["transaction"] + " [--apply]")
    elif report["mode"] == "plan":
        lines.append("Plan seul. Appliquer : sudo python3 tools/omni-deploy.py deploy "
                     + " ".join(report["components"]) + (f" --filtre '{report['pattern']}'" if report.get("pattern") else "")
                     + " --apply")
    if report.get("result"):
        lines.append("Résultat : " + report["result"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", help=f"dépôt canonique (défaut : $OMNI_SIEM_HOME ou {DEFAULT_HOME})")
    parser.add_argument("--root", default="/", help="racine des cibles (racine factice pour les essais)")
    parser.add_argument("--state-dir", help=f"journal des transactions (défaut : {DEFAULT_STATE})")
    parser.add_argument("--json", action="store_true", help="sortie JSON")
    commands = parser.add_subparsers(dest="command", required=True)
    deploy = commands.add_parser("deploy", help="plan ou application")
    deploy.add_argument("components", nargs="*", default=["all"], metavar="COMPOSANT")
    deploy.add_argument("--apply", action="store_true", help="appliquer après lecture du plan")
    deploy.add_argument("--verbose", action="store_true", help="lister aussi les fichiers identiques")
    deploy.add_argument("--filtre", metavar="MOTIF", help="limiter aux cibles correspondant au motif (ex. '*/oms-graph.service.d/*')")
    deploy.add_argument("--no-verify", action="store_true", help="ne pas lancer le contrôle de santé après application")
    rollback = commands.add_parser("rollback", help="plan ou retour arrière d'une transaction")
    rollback.add_argument("transaction")
    rollback.add_argument("--apply", action="store_true")
    rollback.add_argument("--force", action="store_true", help="écraser aussi les fichiers modifiés depuis la transaction")
    commands.add_parser("history", help="transactions enregistrées")
    commands.add_parser("verify", help="contrôle de santé (lecture seule)")
    commands.add_parser("components", help="liste des composants")
    for command in commands.choices.values():
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="sortie JSON")
    args = parser.parse_args(argv)

    if args.command == "components":
        print("\n".join(("all",) + COMPONENTS))
        return 0
    deployer = Deployer(ROOT, home=args.home, root=args.root, state_dir=args.state_dir,
                        emit=None if args.json else (lambda line: print("  " + line, flush=True)))
    if args.command == "verify":
        return verify(Path(deployer.home), args.json)
    if args.command == "history":
        entries = deployer.history()
        if args.json:
            print(json.dumps(entries, indent=2, ensure_ascii=False))
        else:
            for item in entries:
                print(f"{item['id']}  {item['created_at']}  {item['status']:<24} {','.join(item['components'] or [])}  "
                      f"{item['files']} fichier(s), {item['venvs']} venv(s)")
            if not entries:
                print("Aucune transaction enregistrée.")
        return 0
    if args.command == "rollback":
        report = deployer.rollback(args.transaction, apply=args.apply, force=args.force)
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(f"Transaction {report['transaction']} ({report['status']})")
            for step in report["steps"]:
                print(f"  {step['operation']:<16} {step.get('target') or step.get('venv')}")
            for conflict in report["conflicts"]:
                print("  CONFLIT " + conflict)
            for unit in report["restarts"]:
                print("  redémarrage si actif : " + unit)
            print("Plan seul. Appliquer : ajouter --apply" if report["mode"] == "plan" else "Résultat : " + report["status"])
        return 0 if not report.get("problems") else 1
    report = deployer.apply(args.components, args.filtre) if args.apply else deployer.plan(args.components, args.filtre)
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_plan(report))
    if report["mode"] == "plan":
        return 0 if not report["blockers"] else 2
    if report.get("transaction") and deployer.system and not args.no_verify:
        print("\nContrôle de santé après déploiement :")
        return verify(Path(deployer.home), args.json)
    return 0


def verify(home: Path, as_json=False):
    config = health.load_site_config(home / "00-vars.env")
    report = health.summarize(health.evaluate(config, ROOT))
    print(json.dumps(report, indent=2, ensure_ascii=False) if as_json else health.render_text(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DeployError, OSError, ValueError) as exc:
        print("Déploiement refusé ou en échec : " + str(exc), file=sys.stderr)
        raise SystemExit(1)
