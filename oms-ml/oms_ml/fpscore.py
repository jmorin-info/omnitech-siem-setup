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


def alert_entity(src: dict[str, Any]) -> str:
    """Entité portée par l'alerte : hôte émetteur (source) ou compte AD, selon dispo."""
    for f in ("source", "winlogbeat_winlog_event_data_TargetUserName", "user", "host"):
        v = src.get(f)
        if v:
            return str(v)
    return ""


def entity_context(os_url: str, index: str, docs: dict[str, dict[str, Any]],
                   window: str = "30d") -> dict[str, dict[str, Any]]:
    """Historique de détection PAR ENTITÉ (best-effort, une requête par entité).

    Pour chaque entité des cas labellisés : volume de détections, comptes par
    alert_tag et diversité de tags sur `window`. C'est ce CONTEXTE qui permet de
    distinguer VP/FP À L'INTÉRIEUR d'un même alert_tag — la allowlist déterministe
    (81) gère déjà « ce tag est toujours bénin » ; le modèle doit apprendre « ce
    tag est routinier SUR CETTE entité (FP) mais anormal sur une autre (VP) ».
    Échec OpenSearch -> entité absente de la map -> features contextuelles à 0
    (dégradation gracieuse : le modèle retombe sur les seules features intrinsèques)."""
    entities = {alert_entity(s) for s in docs.values()}
    entities.discard("")
    out: dict[str, dict[str, Any]] = {}
    for ent in entities:
        body = {
            "size": 0,
            "track_total_hits": True,   # sinon hits.total plafonne à 10000 -> ratio > 1 possible
            "query": {"bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": f"now-{window}"}}},
                    {"exists": {"field": "alert_tag"}},
                ],
                # l'entité peut être un hôte (source) OU un compte (TargetUserName)
                "should": [
                    {"term": {"source": ent}},
                    {"term": {"winlogbeat_winlog_event_data_TargetUserName": ent}},
                ],
                "minimum_should_match": 1,
            }},
            "aggs": {
                "tags": {"terms": {"field": "alert_tag", "size": 50}},
                "distinct": {"cardinality": {"field": "alert_tag"}},
            },
        }
        try:
            r = requests.post(f"{os_url.rstrip('/')}/{index}/_search", json=body, timeout=30)
            r.raise_for_status()
            data = r.json()
            det = int(data.get("hits", {}).get("total", {}).get("value", 0))
            buckets = data.get("aggregations", {}).get("tags", {}).get("buckets", [])
            same_tag = {b["key"]: int(b["doc_count"]) for b in buckets}
            distinct = int(data.get("aggregations", {}).get("distinct", {}).get("value", 0))
            out[ent] = {"det": det, "same_tag": same_tag, "distinct": distinct}
        except requests.RequestException as exc:
            log.warning("Contexte entité indisponible (%s) : %s", ent, exc)
    return out


# Vocabulaire alert_tag -> index (encodage compact, complété à la volée).
def alert_features(src: dict[str, Any], tag_vocab: dict[str, int],
                   ctx: dict[str, dict[str, Any]] | None = None) -> list[float]:
    """5 features INTRINSÈQUES (de l'alerte) + 3 CONTEXTUELLES (historique entité).

    `ctx` absent -> les 3 features contextuelles valent 0 (fonction restable, et
    dégradation gracieuse si l'enrichissement OpenSearch échoue)."""
    tag = str(src.get("alert_tag", "none"))
    tag_vocab.setdefault(tag, len(tag_vocab))
    ts = str(src.get("timestamp", ""))
    try:
        hour = int(ts[11:13]) if len(ts) >= 13 else 0
    except ValueError:
        hour = 0

    # --- contexte de l'entité (historique 30 j) ---
    c = (ctx or {}).get(alert_entity(src), {})
    ent_det = float(c.get("det", 0))                          # volume de détections de l'entité
    same_tag = float(c.get("same_tag", {}).get(tag, 0))       # occurrences de CE tag sur l'entité
    distinct = float(c.get("distinct", 0))                    # diversité de tags de l'entité
    # part de ce tag dans l'activité de l'entité : ~1 = l'entité ne fait QUE ça
    # (routinier -> FP) ; faible avec forte diversité = compromission large (-> VP)
    same_tag_ratio = min(1.0, same_tag / ent_det) if ent_det > 0 else 0.0

    return [
        float(src.get("risk_score") or 0),
        float(tag_vocab[tag]),
        1.0 if src.get("src_ip_country_code") else 0.0,
        float(hour),
        1.0 if (hour < 7 or hour >= 20) else 0.0,   # hors-heures ouvrées
        ent_det,                                    # contexte : volume de l'entité
        same_tag_ratio,                             # contexte : routine du tag pour l'entité
        distinct,                                   # contexte : diversité (large -> VP)
    ]


FEATURE_NAMES = ["risk_score", "alert_tag_id", "has_geo", "hour", "off_hours",
                 "ent_det_30d", "ent_same_tag_ratio", "ent_distinct_tags_30d"]


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
    ctx = entity_context(os_url, index, docs)   # historique par entité (best-effort)
    tag_vocab: dict[str, int] = {}
    X, y = [], []
    for cid, label in labels.items():
        if cid in docs:
            X.append(alert_features(docs[cid], tag_vocab, ctx))
            y.append(label)
    if len(set(y)) < 2 or len(y) < min_labels:
        return {"trained": False, **status(cases_file, min_labels),
                "note": "docs introuvables ou classe unique après jointure OpenSearch"}

    Xa, ya = np.asarray(X, float), np.asarray(y, int)
    # Régularisation pour FAIBLE VOLUME (~quelques dizaines de labels) : arbres peu
    # profonds -> limite le surapprentissage. Hyperparamètres à ré-affiner quand le
    # corpus de cas qualifiés grandira.
    clf = GradientBoostingClassifier(random_state=42, max_depth=2)
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
