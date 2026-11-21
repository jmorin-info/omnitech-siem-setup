#!/usr/bin/env python3
"""État des mises à jour de toutes les couches, en lecture seule (texte ou JSON).

Couches : code du dépôt, paquets OS et sécurité, pile Graylog/OpenSearch/MongoDB,
dépendances Python des venvs, contenus de détection et intégrations, pré-requis
(santé, disque, sauvegardes). N'installe, ne télécharge et ne redémarre rien.
Schéma JSON : docs/UPDATES.md, section « Point d'entrée unique ».
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omni_update import status  # noqa: E402
from omni_update.system import System  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="sortie JSON stable (schema_version 1)")
    parser.add_argument("--layer", action="append", choices=status.LAYERS, help="limiter à une ou plusieurs couches")
    parser.add_argument("--source", type=Path, default=ROOT,
                        help="dépôt installé examiné par la couche code et lu pour 00-vars.env (défaut : ce dépôt) ; "
                             "les inventaires de référence viennent toujours du dépôt de cet outil")
    parser.add_argument("--updater-state-dir", type=Path, default=Path("/var/lib/omni-siem-updater"))
    parser.add_argument("--graylog", action="store_true",
                        help="lire aussi les révisions de Content Packs installées (GET, jeton dans GRAYLOG_API_TOKEN)")
    parser.add_argument("--exit-code", action="store_true",
                        help="code retour 0 si ok/info, 1 si attention/inconnu, 2 si action requise")
    args = parser.parse_args(argv)
    system = System()
    graylog = None
    if args.graylog:
        token = os.environ.get("GRAYLOG_API_TOKEN")
        if not token:
            parser.error("--graylog exige la variable GRAYLOG_API_TOKEN (jeton en lecture)")
        graylog = status.graylog_installations(system, token, source=args.source)
    report = status.collect(system, args.source.resolve(), args.updater_state_dir, layers=tuple(args.layer or status.LAYERS),
                            graylog=graylog, repository=ROOT)
    print(status.to_json(report) if args.json else status.render_text(report))
    if args.exit_code:
        return {"ok": 0, "info": 0, "attention": 1, "inconnu": 1, "action": 2}.get(report["overall"], 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
