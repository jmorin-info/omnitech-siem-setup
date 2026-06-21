"""fpscore — gating supervisé des labels, SANS OpenSearch.

Le store de cas (cases.json) est écrit dans un fichier temporaire. On vérifie :
  - load_labels ne retient que les cas qualifiés (true/false_positive) ;
  - status : gating ready=False sous le minimum OU à classe unique, True dès que
    le minimum ET les 2 classes sont réunis ;
  - train court-circuite (aucun appel réseau) tant que ready est faux ;
  - alert_features : fonction pure (risque, one-hot tag, géo, heure, hors-heures).
"""
from __future__ import annotations

import json

import pytest

from oms_ml import fpscore


def _write_cases(tmp_path, cases: dict) -> str:
    p = tmp_path / "cases.json"
    p.write_text(json.dumps(cases), encoding="utf-8")
    return str(p)


def test_load_labels_filtre_qualifies(tmp_path):
    cf = _write_cases(tmp_path, {
        "tp1": {"disposition": "true_positive"},
        "fp1": {"disposition": "false_positive"},
        "open": {"disposition": None},
        "wip": {"status": "investigating"},          # pas de disposition
        "bad": {"disposition": "benign_positive"},   # valeur hors vocabulaire
    })
    labels = fpscore.load_labels(cf)
    assert labels == {"tp1": 1, "fp1": 0}


def test_load_labels_fichier_absent():
    assert fpscore.load_labels("/tmp/oms-ml-store-inexistant-xyz.json") == {}


def test_status_pas_assez_de_labels(tmp_path):
    cf = _write_cases(tmp_path, {
        "tp1": {"disposition": "true_positive"},
        "fp1": {"disposition": "false_positive"},
    })
    st = fpscore.status(cf, min_labels=30)
    assert st["ready"] is False
    assert st["labeled"] == 2
    assert st["true_positive"] == 1 and st["false_positive"] == 1
    assert st["missing"] == 28


def test_status_classe_unique_non_ready(tmp_path):
    # au-dessus du minimum MAIS une seule classe -> on n'entraîne pas.
    cases = {"tp%d" % i: {"disposition": "true_positive"} for i in range(40)}
    cf = _write_cases(tmp_path, cases)
    st = fpscore.status(cf, min_labels=30)
    assert st["labeled"] == 40 and st["missing"] == 0
    assert st["false_positive"] == 0
    assert st["ready"] is False, "classe unique ne doit jamais être 'ready'"


def test_status_deux_classes_pret(tmp_path):
    cases = {}
    for i in range(20):
        cases["tp%d" % i] = {"disposition": "true_positive"}
    for i in range(15):
        cases["fp%d" % i] = {"disposition": "false_positive"}
    cases["noise"] = {"status": "open"}              # ignoré
    cf = _write_cases(tmp_path, cases)
    st = fpscore.status(cf, min_labels=30)
    assert st["labeled"] == 35
    assert st["true_positive"] == 20 and st["false_positive"] == 15
    assert st["missing"] == 0
    assert st["ready"] is True


def test_train_court_circuite_sans_reseau(tmp_path):
    # ready False -> train doit retourner trained=False SANS toucher OpenSearch.
    cf = _write_cases(tmp_path, {"tp1": {"disposition": "true_positive"}})
    # URL volontairement injoignable : si elle était appelée, le test le révélerait
    # (mais le gating doit court-circuiter avant tout appel réseau).
    out = fpscore.train("http://127.0.0.1:9/never", "omni-x", cf, min_labels=30)
    assert out["trained"] is False
    assert out["ready"] is False
    assert out["labeled"] == 1


def test_alert_features_pure():
    voc: dict = {}
    f1 = fpscore.alert_features(
        {"risk_score": 80, "alert_tag": "brute_force",
         "src_ip_country_code": "RU", "timestamp": "2026-06-21T23:10:00Z"}, voc)
    # [risk, tag_id, has_geo, hour, off_hours]
    assert f1[0] == 80.0
    assert f1[2] == 1.0                # géo présente
    assert f1[3] == 23.0              # heure
    assert f1[4] == 1.0              # 23h -> hors-heures
    # même tag -> même id (one-hot stable) ; pas de géo + 09h -> heures ouvrées
    f2 = fpscore.alert_features(
        {"risk_score": 10, "alert_tag": "brute_force",
         "timestamp": "2026-06-21T09:00:00Z"}, voc)
    assert f2[1] == f1[1], "id de tag instable pour le même alert_tag"
    assert f2[2] == 0.0 and f2[4] == 0.0
    assert len(fpscore.FEATURE_NAMES) == len(f1)


def test_alert_features_timestamp_invalide():
    voc: dict = {}
    f = fpscore.alert_features({"risk_score": None, "alert_tag": None, "timestamp": "x"}, voc)
    assert f[0] == 0.0           # risk_score None -> 0
    assert f[3] == 0.0          # heure non parsable -> 0
    assert f[4] == 1.0         # 0h considéré hors-heures (< 7)
