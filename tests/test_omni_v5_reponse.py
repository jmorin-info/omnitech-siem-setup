"""Garde-fous de omni-v5-reponse (tools/omni-v5-reponse), hors ligne : aucun appel réseau, cibles fictives."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "tools" / "omni-v5-reponse" / "omni_v5_reponse.py"
CIBLES = """# cibles fictives du test
dc DC01
dc DC02
ip 192.0.2.10
hote-rx ^SRV-HERITAGE => serveur à ne jamais toucher
hote-rx ESET => console antivirus
hote-rx VCENTER|ESXI|VEEAM|PKI|NPS|FICHIERS|NAS => serveur d'infrastructure
compte compte-supervision
compte msol_0123456789ab
leurre svc-exemple-leurre
"""


def charger(tmp_path, monkeypatch, cibles=CIBLES):
    fichier = tmp_path / "cibles-protegees"
    if cibles is not None:
        fichier.write_text(cibles, encoding="utf-8")
    monkeypatch.setenv("REPONSE_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("REPONSE_CONF", str(tmp_path / "absent.env"))
    monkeypatch.setenv("REPONSE_CIBLES", str(fichier))
    monkeypatch.setenv("REPONSE_DOMAINES_UPN", "exemple.fr")
    spec = importlib.util.spec_from_file_location("omni_v5_reponse_test", CODE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CAS = [
    ("isoler_poste_eset", "DC01", False), ("isoler_poste_eset", "dc02.exemple.fr", False),
    ("isoler_poste_eset", "SRV-AD-03", False), ("isoler_poste_eset", "192.0.2.10", False),
    ("isoler_poste_eset", "192.0.2.50", False), ("isoler_poste_eset", "SRV-HERITAGE-01", False),
    ("isoler_poste_eset", "SRV-ESET", False), ("isoler_poste_eset", "SIEM-01", False),
    ("isoler_poste_eset", "VCENTER", False), ("isoler_poste_eset", "EXEMPLE\\DC01$", False),
    ("isoler_poste_eset", "POSTE;rm -rf", False), ("isoler_poste_eset", "", False),
    ("isoler_poste_eset", "POSTE-COMPTA-01", True), ("isoler_poste_eset", "poste-test-pc.exemple.fr", True),
    ("desactiver_compte_ad", "adm-exemple", False), ("desactiver_compte_ad", "EXEMPLE\\adm-x", False),
    ("desactiver_compte_ad", "svc-exemple-leurre", False), ("desactiver_compte_ad", "svc_appli", False),
    ("desactiver_compte_ad", "krbtgt", False), ("desactiver_compte_ad", "Administrateur", False),
    ("desactiver_compte_ad", "compte-supervision", False), ("desactiver_compte_ad", "gMSA-SAUV$", False),
    ("desactiver_compte_ad", "MSOL_0123456789ab", False), ("desactiver_compte_ad", "001122334455", False),
    ("desactiver_compte_ad", "jdupont@exemple.fr", False),
    ("desactiver_compte_ad", "jdupont", True), ("desactiver_compte_ad", "marie.martin", True),
    ("revoquer_sessions_entra", "adm-x@exemple.fr", False),
    ("revoquer_sessions_entra", "svc-exemple-leurre@exemple.fr", False),
    ("revoquer_sessions_entra", "breakglass1@exemple.fr", False),
    ("revoquer_sessions_entra", "Sync_DC01_abc@exemple.onmicrosoft.com", False),
    ("revoquer_sessions_entra", "x_mail.example#EXT#@exemple.onmicrosoft.com", False),
    ("revoquer_sessions_entra", "partenaire@autre.example", False),
    ("revoquer_sessions_entra", "jdupont", False),
    ("revoquer_sessions_entra", "jean.dupont@exemple.fr", True),
    ("revoquer_sessions_entra", "Test.V5@EXEMPLE.FR", True),
    ("action_inconnue", "x", False),
]


def test_garde_fous(tmp_path, monkeypatch):
    m = charger(tmp_path, monkeypatch)
    ecarts = [(a, c, att) for a, c, att in CAS if m.garde_fou(a, c)[0] != att]
    assert not ecarts


def test_motif_compte_leurre(tmp_path, monkeypatch):
    m = charger(tmp_path, monkeypatch)
    ok, motif = m.garde_fou("desactiver_compte_ad", "svc-exemple-leurre")
    assert not ok and "leurre" in motif


@pytest.mark.parametrize("contenu", [None, "", "# commentaire seul\n", "inconnu valeur\n", "ip pas-une-ip\n", "dc\n"])
def test_demarrage_refuse_sans_cibles_valides(tmp_path, contenu):
    """Sans fichier de cibles lisible et non vide, le service s'arrête (code 78) au lieu de démarrer sans garde-fous."""
    fichier = tmp_path / "cibles-protegees"
    if contenu is not None:
        fichier.write_text(contenu, encoding="utf-8")
    env = dict(os.environ, REPONSE_ETAT=str(tmp_path / "etat"), REPONSE_CONF=str(tmp_path / "absent.env"),
               REPONSE_CIBLES=str(fichier))
    r = subprocess.run([sys.executable, "-I", "-c", "import runpy, sys; runpy.run_path(sys.argv[1])", str(CODE)],
                       env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 78
    assert "démarrage refusé" in r.stderr
