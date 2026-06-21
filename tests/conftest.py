"""Chargement du backend mobile pour test SANS démarrer le serveur.

omni-mobile-api.py ne *bind* le socket que sous `if __name__ == "__main__"` :
l'import par chemin est donc sûr. Le flag de rédaction `REDACT` est figé à
l'import depuis CONF (fichier /etc/default/omni-mobile), pas depuis l'env — on
le force ici à True au niveau du module (les helpers lisent le global au moment
de l'appel) et on réinitialise les tables de correspondance avant chaque test.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

# /…/omnitech-siem-setup/mobile/omni-mobile-api.py (ce conftest est sous tests/)
_API = Path(__file__).resolve().parents[1] / "mobile" / "omni-mobile-api.py"


def _load_api():
    # Cohérent avec l'intention MOBILE_REDACT=1 (documenté), même si CONF lit le
    # fichier : le levier réel est l'attribut de module forcé plus bas.
    os.environ.setdefault("MOBILE_REDACT", "1")
    spec = importlib.util.spec_from_file_location("omni_mobile_api", str(_API))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # n'ouvre AUCUN socket (pas de __main__)
    return mod


@pytest.fixture
def api():
    """Module backend avec rédaction ACTIVE et tables vierges pour chaque test."""
    if not _API.exists():
        pytest.skip(f"backend mobile introuvable : {_API}")
    mod = _load_api()
    mod.REDACT = True
    mod._RD_MAP.clear()
    mod._RD_REV.clear()
    return mod
