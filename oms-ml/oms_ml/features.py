"""Extraction de features par entité depuis OpenSearch (omni-*).

Une seule requête `terms` (sur le champ d'entité) avec des sous-agrégations
construit la matrice de features — efficace, un seul aller-retour par type d'entité.
Toutes les features sont des agrégations propres (count / cardinality / max / sum),
sans script field, pour rester robustes au mapping réel.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger("oms-ml.features")

# Ordre des features = ordre des colonnes de la matrice (stable pour le scaler/modèle).
FEATURES: list[str] = [
    "ev_total",          # volume total d'événements
    "ev_detections",     # événements porteurs d'un alert_tag (détections)
    "n_alert_tags",      # diversité des détections (cardinalité alert_tag)
    "n_techniques",      # diversité ATT&CK (cardinalité mitre_technique)
    "risk_max",          # risque max atteint
    "risk_sum",          # risque cumulé
    "n_src_ip",          # nb d'IP sources distinctes
    "n_countries",       # nb de pays sources distincts (voyage/diffusion)
    "n_event_sources",   # nb de sources de log distinctes touchées
    "n_peers",           # nb d'entités « en face » distinctes (comptes vus / hôtes vus)
]


def _aggs(peer_field: str) -> dict[str, Any]:
    """Sous-agrégations communes ; `peer_field` = entité opposée (compte<->hôte)."""
    return {
        "ev_detections": {"filter": {"exists": {"field": "alert_tag"}}},
        "n_alert_tags": {"cardinality": {"field": "alert_tag"}},
        "n_techniques": {"cardinality": {"field": "mitre_technique"}},
        "risk_max": {"max": {"field": "risk_score"}},
        "risk_sum": {"sum": {"field": "risk_score"}},
        "n_src_ip": {"cardinality": {"field": "src_ip"}},
        "n_countries": {"cardinality": {"field": "src_ip_country_code"}},
        "n_event_sources": {"cardinality": {"field": "event_source"}},
        "n_peers": {"cardinality": {"field": peer_field}},
    }


# Champ « pair » (entité opposée) selon le type d'entité scoré.
PEER = {
    "source": "winlogbeat_winlog_event_data_TargetUserName",
    "winlogbeat_winlog_event_data_TargetUserName": "source",
}


def extract(os_url: str, index: str, group_by: str, window: str,
            size: int = 1000) -> tuple[list[str], list[list[float]], list[str]]:
    """Retourne (noms_features, matrice, entités) pour le type d'entité `group_by`.

    matrice[i] = vecteur de features de l'entité entités[i].
    """
    peer = PEER.get(group_by, "source")
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{window}"}}}]}},
        "aggs": {
            "ent": {
                "terms": {"field": group_by, "size": size},
                "aggs": _aggs(peer),
            }
        },
    }
    try:
        r = requests.post(f"{os_url.rstrip('/')}/{index}/_search", json=body, timeout=120)
        r.raise_for_status()
        buckets = r.json().get("aggregations", {}).get("ent", {}).get("buckets", [])
    except requests.RequestException as exc:
        log.error("Extraction OpenSearch échouée (%s) : %s", group_by, exc)
        return FEATURES, [], []

    matrix: list[list[float]] = []
    entities: list[str] = []
    for b in buckets:
        key = b.get("key")
        if key in (None, "", "null", "-"):
            continue
        row = [
            float(b.get("doc_count", 0)),
            float(b.get("ev_detections", {}).get("doc_count", 0)),
            float(b.get("n_alert_tags", {}).get("value", 0)),
            float(b.get("n_techniques", {}).get("value", 0)),
            float(b.get("risk_max", {}).get("value") or 0),
            float(b.get("risk_sum", {}).get("value") or 0),
            float(b.get("n_src_ip", {}).get("value", 0)),
            float(b.get("n_countries", {}).get("value", 0)),
            float(b.get("n_event_sources", {}).get("value", 0)),
            float(b.get("n_peers", {}).get("value", 0)),
        ]
        matrix.append(row)
        entities.append(str(key))
    log.info("%d entités extraites (group_by=%s, window=%s)", len(entities), group_by, window)
    return FEATURES, matrix, entities
