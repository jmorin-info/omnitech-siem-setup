#!/usr/bin/env python3
"""Contrôle de santé de bout en bout de la plateforme, en lecture seule.

À lancer après une installation, un déploiement ou un redémarrage :
  sudo python3 tools/omni-healthcheck.py [--json] [--config CHEMIN/00-vars.env]
Code de sortie : 0 si aucun contrôle critique n'échoue, 1 sinon.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy import health  # noqa: E402
from omni_deploy.engine import DEFAULT_HOME  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    home = Path(os.environ.get("OMNI_SIEM_HOME") or DEFAULT_HOME)
    parser.add_argument("--config", type=Path, default=home / "00-vars.env",
                        help="fichier du site (défaut : $OMNI_SIEM_HOME/00-vars.env)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = health.summarize(health.evaluate(health.load_site_config(args.config), ROOT))
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else health.render_text(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
