"""Gabarit de la table de zones SEAL (seal/graylog/gabarit_zone_portes.py), sans réseau."""
from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("gabarit_zone_portes", ROOT / "seal/graylog/gabarit_zone_portes.py")
gz = importlib.util.module_from_spec(_spec)
sys.modules["gabarit_zone_portes"] = gz
_spec.loader.exec_module(gz)


@pytest.mark.parametrize("brut,attendu", [("0.279e3", "279"), ("285", "285"), ("0.12982e5", "12982"),
                                          (285.0, "285"), ("porte", None)])
def test_normalisation_identique_a_la_regle_pipeline(brut, attendu):
    assert gz.obfi_normalise(brut) == attendu


def _faux_opensearch():
    pages = [
        {"aggregations": {"portes": {"after_key": {"site": "b", "obfi": "x"}, "buckets": [
            {"key": {"site": "bx-seal-omega", "obfi": "0.279e3"}, "doc_count": 10,
             "libelle": {"buckets": [{"key": "ENTREE"}]}},
            {"key": {"site": "bx-qa-seal-vm", "obfi": "285"}, "doc_count": 2, "libelle": {"buckets": []}}]}}},
        {"aggregations": {"portes": {"buckets": []}}},
    ]
    appels = []

    def appel(chemin, corps):
        appels.append((chemin, corps))
        return pages[len(appels) - 1]
    return appel, appels


def test_gabarit_puis_table_ne_garde_que_les_zones_renseignees(tmp_path):
    appel, appels = _faux_opensearch()
    gab = tmp_path / "gabarit.csv"
    assert gz.main(["gabarit", "--sortie", str(gab)], appel=appel) == 0
    assert all(ch.endswith("/_search") for ch, _ in appels)
    lignes = list(csv.DictReader(gab.open(encoding="utf-8")))
    assert [r["SITE_OBFI"] for r in lignes] == ["bx-qa-seal-vm:285", "bx-seal-omega:279"]
    assert all(r["ZONE_PATH"] == "" for r in lignes)
    # l'opérateur renseigne une zone ; un nouveau gabarit la conserve
    lignes[1]["ZONE_PATH"] = "Bâtiment A/Accueil"
    with gab.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=gz.ENTETE_GABARIT)
        w.writeheader()
        w.writerows(lignes)
    appel2, _ = _faux_opensearch()
    gab2 = tmp_path / "gabarit2.csv"
    gz.main(["gabarit", "--sortie", str(gab2), "--existant", str(gab)], appel=appel2)
    assert "Bâtiment A/Accueil" in gab2.read_text(encoding="utf-8")
    table = tmp_path / "table.csv"
    assert gz.main(["table", "--gabarit", str(gab2), "--sortie", str(table)]) == 0
    assert table.read_text(encoding="utf-8").splitlines() == ["SITE_OBFI,ZONE_PATH", "bx-seal-omega:279,Bâtiment A/Accueil"]


def test_table_vide_code_retour_1(tmp_path):
    gab = tmp_path / "g.csv"
    gab.write_text("SITE_OBFI,ZONE_PATH,PORTE_LIBELLE,EVENEMENTS\nbx-qa-seal-vm:1,,,3\n", encoding="utf-8")
    assert gz.main(["table", "--gabarit", str(gab), "--sortie", str(tmp_path / "t.csv")]) == 1


def test_gabarit_livre_a_l_entete_attendue():
    lignes = list(csv.reader((ROOT / "seal/graylog/omni-seal-zone.gabarit.csv").open(encoding="utf-8")))
    assert lignes[0] == gz.ENTETE_GABARIT and len(lignes) > 1
