"""Rend le paquet oms_ml importable même hors install editable.

Les tests n'ouvrent AUCUNE connexion OpenSearch : ils ciblent les fonctions
pures (train_score sur matrice synthétique ; status/load_labels/alert_features).
"""
from __future__ import annotations

import sys
from pathlib import Path

# /…/oms-ml (parent du dossier tests/) doit être sur le path pour `import oms_ml`.
_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
