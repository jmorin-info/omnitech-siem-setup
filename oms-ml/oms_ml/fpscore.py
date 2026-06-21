"""Réduction de faux positifs SUPERVISÉE — labels = disposition analyste des cas.

Label : un cas clôturé porte une `disposition` ('true_positive' | 'false_positive').
  y = 1  -> alerte réelle (vrai positif)
  y = 0  -> faux positif (bruit)
Features par alerte (depuis le doc OpenSearch) : risque, alert_tag, source,
présence géo, heure, hors-heures. Modèle : GradientBoosting (sklearn, local).

GATING : sans un minimum de labels des DEUX classes, on n'entraîne pas — on
rapporte l'état (« en attente de N labels »). C'est le comportement correct
tant que les analystes n'ont pas qualifié assez de cas dans la console SOC.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger("oms-ml.fpscore")


def load_labels(cases_file: str) -> dict[str, int]:
    """Lit le store de cas -> {event_id: y}. Ne garde que les cas qualifiés."""
    p = Path(cases_file)
    if not p.exists():
        log.info("Store de cas absent : %s", cases_file)
        return {}
    try:
        cases = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Lecture cas échouée : %s", exc)
        return {}
    labels: dict[str, int] = {}
    for cid, c in cases.items():
        disp = (c or {}).get("disposition")
        if disp == "true_positive":
            labels[cid] = 1
        elif disp == "false_positive":
            labels[cid] = 0
    return labels


def _fetch_docs(os_url: str, index: str, ids: list[str]) -> dict[str, dict[str, Any]]:
    """Récupère les documents d'alerte par _id (terms ids)."""
    if not ids:
        return {}
    body = {"size": len(ids), "query": {"ids": {"values": ids}}}
    try:
        r = requests.post(f"{os_url.rstrip('/')}/{index}/_search", json=body, timeout=60)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
    except requests.RequestException as exc:
        log.error("Récupération docs échouée : %s", exc)
        return {}
    return {h["_id"]: h.get("_source", {}) for h in hits}


# Vocabulaire alert_tag -> index (one-hot compact, complété à la volée).
def alert_features(src: dict[str, Any], tag_vocab: dict[str, int]) -> list[float]:
    tag = str(src.get("alert_tag", "none"))
    tag_vocab.setdefault(tag, len(tag_vocab))
    ts = str(src.get("timestamp", ""))
    hour = 0
    try:
        hour = int(ts[11:13]) if len(ts) >= 13 else 0
    except ValueError:
        hour = 0
    return [
        float(src.get("risk_score") or 0),
        float(tag_vocab[tag]),
        1.0 if src.get("src_ip_country_code") else 0.0,
        float(hour),
        1.0 if (hour < 7 or hour >= 20) else 0.0,   # hors-heures ouvrées
    ]


FEATURE_NAMES = ["risk_score", "alert_tag_id", "has_geo", "hour", "off_hours"]


def status(cases_file: str, min_labels: int) -> dict[str, Any]:
    """État du jeu de labels (sans entraîner) — pour le reporting/console."""
    labels = load_labels(cases_file)
    pos = sum(1 for v in labels.values() if v == 1)
    neg = sum(1 for v in labels.values() if v == 0)
    ready = len(labels) >= min_labels and pos > 0 and neg > 0
    return {"labeled": len(labels), "true_positive": pos, "false_positive": neg,
            "min_labels": min_labels, "ready": ready,
            "missing": max(0, min_labels - len(labels))}


def train(os_url: str, index: str, cases_file: str, min_labels: int,
          model_path: str | None = None) -> dict[str, Any]:
    """Entraîne le classifieur FP si assez de labels ; sinon rapporte l'attente."""
    st = status(cases_file, min_labels)
    if not st["ready"]:
        log.info("FP supervisé en attente de labels : %s qualifiés (besoin %s, 2 classes).",
                 st["labeled"], min_labels)
        return {"trained": False, **st}

    # Import tardif : sklearn seulement quand on entraîne réellement.
    import joblib
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import cross_val_score

    labels = load_labels(cases_file)
    docs = _fetch_docs(os_url, index, list(labels.keys()))
    tag_vocab: dict[str, int] = {}
    X, y = [], []
    for cid, label in labels.items():
        if cid in docs:
            X.append(alert_features(docs[cid], tag_vocab))
            y.append(label)
    if len(set(y)) < 2 or len(y) < min_labels:
        return {"trained": False, **status(cases_file, min_labels),
                "note": "docs introuvables ou classe unique après jointure OpenSearch"}

    Xa, ya = np.asarray(X, float), np.asarray(y, int)
    clf = GradientBoostingClassifier(random_state=42)
    # AUC en validation croisée (honnêteté sur la perf, vu le faible volume).
    try:
        auc = float(cross_val_score(clf, Xa, ya, cv=min(5, sum(ya), len(ya) - sum(ya)),
                                    scoring="roc_auc").mean())
    except ValueError:
        auc = float("nan")
    clf.fit(Xa, ya)

    if model_path:
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": clf, "tag_vocab": tag_vocab, "features": FEATURE_NAMES}, model_path)
        log.info("Modèle FP persistant : %s (AUC cv≈%.2f)", model_path, auc)

    return {"trained": True, "n": len(y), "auc_cv": auc, **st}
