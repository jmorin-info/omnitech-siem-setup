"""Client de données OMS-XDR.

Lecture  : OpenSearch local (terms agg) — déploiement intégré sur la VM SIEM,
           comme les services omni-*. Filtrage par stream id + fenêtre temporelle.
Écriture : input GELF du SIEM (HTTP 12201 par défaut, TCP si proto=tcp).
"""
from __future__ import annotations

import json
import logging
import socket
import time
from typing import Any

import requests

log = logging.getLogger("oms-xdr.graylog")


class GraylogClient:
    def __init__(self, cfg: dict) -> None:
        self.streams: dict[str, str] = cfg.get("streams", {})
        # Lecture via OpenSearch local (intégration sur la VM SIEM, comme les services omni-*)
        self.os_url = cfg.get("opensearch", "http://127.0.0.1:9200").rstrip("/")
        self.index = cfg.get("index", "omni-*")
        gelf = cfg.get("output_gelf", {})
        self.gelf_host = gelf.get("host", "127.0.0.1")
        self.gelf_port = int(gelf.get("port", 12201))
        self.gelf_proto = gelf.get("proto", "http")

    # ------------------------------------------------------------------
    #  Lecture (OpenSearch)
    # ------------------------------------------------------------------
    def _os_search(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            r = requests.post(f"{self.os_url}/{self.index}/_search", json=body, timeout=60)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            log.error("Recherche OpenSearch échouée: %s", exc)
            return {}

    def _filters(self, query: str, stream_key: str, minutes: int) -> dict[str, Any]:
        must = [{"query_string": {"query": query, "analyze_wildcard": True}}]
        filt: list[dict] = [{"range": {"timestamp": {"gte": f"now-{minutes}m"}}}]
        sid = self.streams.get(stream_key) if stream_key else None
        if sid:
            filt.append({"term": {"streams": sid}})
        return {"bool": {"must": must, "filter": filt}}

    def aggregate(self, query: str, stream_key: str, group_by: str,
                  minutes: int) -> dict[str, int]:
        """Retourne {valeur_entite: count} pour la fenêtre (terms agg OpenSearch)."""
        body = {"size": 0, "query": self._filters(query, stream_key, minutes),
                "aggs": {"e": {"terms": {"field": group_by, "size": 2000}}}}
        buckets = self._os_search(body).get("aggregations", {}).get("e", {}).get("buckets", [])
        return {str(b["key"]): int(b["doc_count"]) for b in buckets
                if b.get("key") not in (None, "", "null")}

    def distinct_aggregate(self, query: str, stream_key: str, group_by: str,
                           distinct_field: str, minutes: int) -> dict[str, int]:
        """Retourne {valeur_entite: nb de valeurs DISTINCTES de distinct_field}.

        Sert le discriminant 'spray' (une IP échouant sur N COMPTES distincts) au
        lieu d'un simple volume d'échecs (qui confond la rotation de mot de passe
        d'un seul compte avec une vraie attaque horizontale)."""
        body = {"size": 0, "query": self._filters(query, stream_key, minutes),
                "aggs": {"e": {"terms": {"field": group_by, "size": 2000},
                               "aggs": {"d": {"cardinality": {"field": distinct_field}}}}}}
        buckets = self._os_search(body).get("aggregations", {}).get("e", {}).get("buckets", [])
        return {str(b["key"]): int(b.get("d", {}).get("value", 0)) for b in buckets
                if b.get("key") not in (None, "", "null")}

    # ------------------------------------------------------------------
    #  Écriture (GELF — HTTP par défaut ; TCP \0 si proto=tcp)
    # ------------------------------------------------------------------
    def send_gelf(self, payload: dict[str, Any]) -> bool:
        payload.setdefault("version", "1.1")
        payload.setdefault("host", "oms-xdr")
        payload.setdefault("timestamp", time.time())
        if self.gelf_proto == "http":
            # Réutilise l'input GELF HTTP existant du SIEM (POST /gelf, non TLS, local).
            try:
                r = requests.post(f"http://{self.gelf_host}:{self.gelf_port}/gelf",
                                  json=payload, timeout=10)
                r.raise_for_status()
                return True
            except requests.RequestException as exc:
                log.error("Envoi GELF HTTP échoué %s:%s — %s", self.gelf_host, self.gelf_port, exc)
                return False
        data = (json.dumps(payload) + "\0").encode("utf-8")
        try:
            with socket.create_connection((self.gelf_host, self.gelf_port), 10) as s:
                s.sendall(data)
            return True
        except OSError as exc:
            log.error("Envoi GELF échoué %s:%s — %s", self.gelf_host, self.gelf_port, exc)
            return False
