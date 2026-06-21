"""anomaly.train_score — détection non-supervisée par entité, SANS OpenSearch.

Matrice synthétique : une population « normale » homogène + une entité nettement
déviante. On vérifie : l'entité déviante ressort en tête, scores bornés 0-100,
tri décroissant, ml_reason renseigné pour l'anomalie, et explicabilité (la raison
cite une feature réellement déviante).
"""
from __future__ import annotations

import random

import pytest

from oms_ml import anomaly, features

FEAT = features.FEATURES


def _population(n_normal: int = 24, seed: int = 7):
    """n_normal entités homogènes + 1 entité franchement anormale, en dernier."""
    rnd = random.Random(seed)
    matrix, ents = [], []
    for i in range(n_normal):
        # profil « normal » : faible volume, ~0 détection, 1 pays/IP/source.
        matrix.append([
            float(100 + rnd.randint(-8, 8)),  # ev_total
            float(rnd.randint(0, 1)),         # ev_detections
            float(rnd.randint(0, 1)),         # n_alert_tags
            0.0,                              # n_techniques
            10.0 + rnd.random(),              # risk_max
            25.0 + rnd.random() * 5,          # risk_sum
            1.0,                              # n_src_ip
            1.0,                              # n_countries
            1.0,                              # n_event_sources
            float(rnd.randint(1, 2)),         # n_peers
        ])
        ents.append("host-normal-%02d" % i)
    # entité déviante : explosion détections / techniques / pays / pairs.
    matrix.append([6000.0, 450.0, 28.0, 19.0, 100.0, 9500.0, 130.0, 15.0, 9.0, 70.0])
    ents.append("host-ANORMAL")
    return matrix, ents


def test_entite_deviante_en_tete():
    matrix, ents = _population()
    res = anomaly.train_score(FEAT, matrix, ents)
    assert res, "résultat vide"
    assert res[0]["entity"] == "host-ANORMAL", "l'entité déviante ne sort pas en tête"


def test_scores_bornes_et_tries():
    matrix, ents = _population()
    res = anomaly.train_score(FEAT, matrix, ents)
    assert len(res) == len(ents)
    for r in res:
        assert 0.0 <= r["ml_score"] <= 100.0, "score hors bornes 0-100"
    scores = [r["ml_score"] for r in res]
    assert scores == sorted(scores, reverse=True), "résultats non triés par score décroissant"
    # l'anomalie injectée doit recevoir le score maximal (=100 après normalisation rang).
    assert res[0]["ml_score"] == pytest.approx(100.0)


def test_ml_reason_explicable():
    matrix, ents = _population()
    res = anomaly.train_score(FEAT, matrix, ents)
    top = res[0]
    assert top["ml_reason"] and top["ml_reason"] != "profil dans la norme", \
        "ml_reason vide pour l'anomalie"
    assert "z=" in top["ml_reason"], "explicabilité (z-score) absente de ml_reason"
    # le dict features est complet et indexé par nom de feature.
    assert set(top["features"].keys()) == set(FEAT)


def test_population_normale_sans_fausse_alerte():
    # population homogène SANS anomalie -> raisons « dans la norme » majoritaires.
    rnd = random.Random(3)
    matrix, ents = [], []
    for i in range(20):
        matrix.append([float(100 + rnd.randint(-3, 3)), 0.0, 0.0, 0.0,
                       10.0, 25.0, 1.0, 1.0, 1.0, 1.0])
        ents.append("h%02d" % i)
    res = anomaly.train_score(FEAT, matrix, ents)
    norm = sum(1 for r in res if r["ml_reason"] == "profil dans la norme")
    assert norm >= len(res) // 2, "trop de fausses raisons sur population homogène"


def test_matrice_vide():
    assert anomaly.train_score(FEAT, [], []) == []


def test_persistance_optionnelle(tmp_path):
    matrix, ents = _population()
    mp = tmp_path / "sub" / "anomaly_host.pkl"
    res = anomaly.train_score(FEAT, matrix, ents, model_path=str(mp))
    assert res and mp.exists(), "le modèle n'a pas été persistant"
    import joblib
    blob = joblib.load(mp)
    assert {"scaler", "model", "features", "mean", "std"} <= set(blob)
    assert blob["features"] == FEAT
