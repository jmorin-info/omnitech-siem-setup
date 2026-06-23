"""Extraction passive des arêtes du graphe depuis OpenSearch (omni-*).

DEFENSIF : on lit la télémétrie de logons déjà collectée pour reconstituer, sans
aucune sonde AD, deux relations d'exposition :

  - HasSession : (compte -> hôte) où le compte s'est authentifié INTERACTIVEMENT
    (EID 4624, LogonType console/RDP/cached) -> ses identifiants y sont exposés.
  - AdminTo    : (compte -> hôte) où le compte a reçu des privilèges spéciaux
    (EID 4672, Subject) -> il est administrateur de cet hôte.

Une requête `terms` imbriquée (compte -> hôtes) par type d'arête, agrégations
propres uniquement (pas de script field). Champ hôte canonique = `source`.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger("oms-graph.opensearch")

ED = "winlogbeat_winlog_event_data"


def _terms_edges(os_url: str, index: str, body: dict[str, Any],
                 acct_key: str) -> list[tuple[str, str, int]]:
    """Exécute l'agrégation et renvoie une liste d'arêtes (compte, hôte, poids)."""
    try:
        r = requests.post(f"{os_url.rstrip('/')}/{index}/_search", json=body, timeout=120)
        r.raise_for_status()
        buckets = r.json().get("aggregations", {}).get("acct", {}).get("buckets", [])
    except requests.RequestException as exc:
        log.error("Extraction OpenSearch échouée (%s) : %s", acct_key, exc)
        return []
    edges: list[tuple[str, str, int]] = []
    for ab in buckets:
        acct = ab.get("key")
        for hb in ab.get("host", {}).get("buckets", []):
            host = hb.get("key")
            if acct and host:
                edges.append((str(acct), str(host), int(hb.get("doc_count", 0))))
    return edges


def _base_filter(event_id: int, window: str, extra: list | None = None) -> list:
    f = [{"term": {"winlogbeat_winlog_event_id": event_id}},
         {"range": {"timestamp": {"gte": f"now-{window}"}}}]
    if extra:
        f += extra
    return f


def _must_not(system_accounts: list[str], patterns: list[str], acct_field: str) -> list:
    # Exclut les comptes système (liste exacte) et les comptes virtuels (motifs
    # wildcard insensibles à la casse : machine $, MSSQL$..., DWM-n...) : ce ne sont
    # pas des cibles de vol d'identifiants latéral.
    mn: list = [{"terms": {acct_field: system_accounts}}]
    for p in patterns or []:
        mn.append({"wildcard": {acct_field: {"value": p, "case_insensitive": True}}})
    return mn


def has_session_edges(os_url: str, index: str, window: str, logon_types: list[str],
                      system_accounts: list[str], patterns: list[str]
                      ) -> list[tuple[str, str, int]]:
    """(compte -> hôte) : sessions interactives (creds exposés sur l'hôte)."""
    acct = f"{ED}_TargetUserName"
    body = {
        "size": 0,
        "query": {"bool": {
            "filter": _base_filter(4624, window, [{"terms": {f"{ED}_LogonType": logon_types}}]),
            "must_not": _must_not(system_accounts, patterns, acct),
        }},
        "aggs": {"acct": {"terms": {"field": acct, "size": 2000},
                          "aggs": {"host": {"terms": {"field": "source", "size": 300}}}}},
    }
    return _terms_edges(os_url, index, body, acct)


def recent_triggers(os_url: str, index: str, tags: list[str], window: str
                    ) -> list[dict]:
    """Leurres déclenchés récemment (Pilier 1) = déclencheurs de réponse (Pilier 3).
    Extrait pour chacun : tag, hôte source, IP source, compte concerné."""
    body = {
        "size": 50, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"terms": {"alert_tag": tags}},
            {"range": {"timestamp": {"gte": f"now-{window}"}}}]}},
        "_source": ["timestamp", "alert_tag", "source", f"{ED}_IpAddress",
                    f"{ED}_TargetUserName", f"{ED}_ServiceName", f"{ED}_QueryName"],
    }
    try:
        r = requests.post(f"{os_url.rstrip('/')}/{index}/_search", json=body, timeout=60)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
    except requests.RequestException as exc:
        log.error("Lecture des déclencheurs échouée : %s", exc)
        return []
    out = []
    for h in hits:
        s = h.get("_source", {})
        ip = s.get(f"{ED}_IpAddress")
        out.append({
            "tag": s.get("alert_tag"), "ts": s.get("timestamp"),
            "source_host": s.get("source"),
            "source_ip": ip if ip and ip not in ("-", "::1", "127.0.0.1") else None,
            "account": s.get(f"{ED}_TargetUserName") or s.get(f"{ED}_ServiceName"),
            "decoy": s.get(f"{ED}_QueryName") or s.get(f"{ED}_TargetUserName") or s.get(f"{ED}_ServiceName"),
        })
    return out


def admin_to_edges(os_url: str, index: str, window: str,
                   system_accounts: list[str], patterns: list[str]
                   ) -> list[tuple[str, str, int]]:
    """(compte -> hôte) : privilèges spéciaux = administrateur de l'hôte (EID 4672)."""
    acct = f"{ED}_SubjectUserName"
    body = {
        "size": 0,
        "query": {"bool": {
            "filter": _base_filter(4672, window),
            "must_not": _must_not(system_accounts, patterns, acct),
        }},
        "aggs": {"acct": {"terms": {"field": acct, "size": 2000},
                          "aggs": {"host": {"terms": {"field": "source", "size": 300}}}}},
    }
    return _terms_edges(os_url, index, body, acct)
