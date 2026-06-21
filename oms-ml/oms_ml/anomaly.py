"""Détection d'anomalie non-supervisée par entité (IsolationForest).

Entraînable SANS label : apprend le comportement « normal » de la population
d'entités sur la fenêtre, puis attribue un ml_score 0-100 (haut = anormal).
Explicabilité : pour chaque entité anormale, on remonte les features qui
s'écartent le plus de la moyenne de population (z-score) -> ml_reason lisible.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

log = logging.getLogger("oms-ml.anomaly")

# Libellés FR des features pour la narration analyste.
LABELS = {
    "ev_total": "volume d'événements",
    "ev_detections": "nombre de détections",
    "n_alert_tags": "diversité des détections",
    "n_techniques": "diversité ATT&CK",
    "risk_max": "risque max",
    "risk_sum": "risque cumulé",
    "n_src_ip": "IP sources distinctes",
    "n_countries": "pays sources distincts",
    "n_event_sources": "sources de log distinctes",
    "n_peers": "entités liées distinctes",
}


def _scores_to_100(raw: np.ndarray) -> np.ndarray:
    """IsolationForest.score_samples : plus c'est BAS, plus c'est anormal.
    On inverse et on normalise en 0-100 (rang relatif robuste aux outliers)."""
    inv = -raw
    lo, hi = inv.min(), inv.max()
    if hi - lo < 1e-9:
        return np.zeros_like(inv)
    return (inv - lo) / (hi - lo) * 100.0


def train_score(features: list[str], matrix: list[list[float]], entities: list[str],
                contamination: Any = "auto", n_estimators: int = 200,
                model_path: str | None = None) -> list[dict[str, Any]]:
    """Entraîne IsolationForest sur la population et score chaque entité.

    Retourne une liste de dicts triée par ml_score décroissant :
        {entity, ml_score, ml_reason, features:{...}}
    """
    X = np.asarray(matrix, dtype=float)
    if X.shape[0] == 0:
        return []

    # Features de SIEM à queue lourde (volumes, cumuls) : un gros émetteur (pare-feu)
    # écraserait tout. log1p compresse la magnitude brute -> on score l'anomalie de
    # FORME relative, pas la simple taille. Les features restent >= 0 (counts/sum).
    Xlog = np.log1p(X)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(Xlog)

    iso = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(Xs)
    scores = _scores_to_100(iso.score_samples(Xs))

    # Statistiques de population pour l'explicabilité (z-score par feature).
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-9] = 1.0

    results: list[dict[str, Any]] = []
    for i, ent in enumerate(entities):
        z = (X[i] - mean) / std
        # top-3 features qui tirent l'entité vers le haut (déviation positive).
        top = np.argsort(z)[::-1][:3]
        reasons = [
            f"{LABELS.get(features[j], features[j])}={int(X[i][j])} (z={z[j]:+.1f})"
            for j in top if z[j] > 1.0
        ]
        results.append({
            "entity": ent,
            "ml_score": round(float(scores[i]), 1),
            "ml_reason": " ; ".join(reasons) if reasons else "profil dans la norme",
            "features": {features[j]: X[i][j] for j in range(len(features))},
        })

    results.sort(key=lambda d: d["ml_score"], reverse=True)

    if model_path:
        try:
            Path(model_path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"scaler": scaler, "model": iso, "features": features,
                         "mean": mean, "std": std}, model_path)
            log.info("Modèle persistant : %s", model_path)
        except OSError as exc:
            log.warning("Persistance modèle impossible (%s) : %s", model_path, exc)

    return results
