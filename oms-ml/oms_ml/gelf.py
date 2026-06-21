"""Réinjection des scores ML dans le SIEM via l'input GELF existant.

Même mécanisme que oms-xdr : POST /gelf (HTTP) ou trame \\0 (TCP).
Chaque score anormal devient un événement event_source=ml_anomaly, consommable
par les pipelines / la console / les alertes (champ ml_score, ml_reason).
"""
from __future__ import annotations

import json
import logging
import socket
import time
from typing import Any

import requests

log = logging.getLogger("oms-ml.gelf")


class Gelf:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.host = cfg.get("host", "127.0.0.1")
        self.port = int(cfg.get("port", 12201))
        self.proto = cfg.get("proto", "http")

    def send(self, payload: dict[str, Any]) -> bool:
        payload.setdefault("version", "1.1")
        payload.setdefault("host", "oms-ml")
        payload.setdefault("timestamp", time.time())
        if self.proto == "http":
            try:
                r = requests.post(f"http://{self.host}:{self.port}/gelf", json=payload, timeout=10)
                r.raise_for_status()
                return True
            except requests.RequestException as exc:
                log.error("GELF HTTP %s:%s échoué — %s", self.host, self.port, exc)
                return False
        data = (json.dumps(payload) + "\0").encode("utf-8")
        try:
            with socket.create_connection((self.host, self.port), 10) as s:
                s.sendall(data)
            return True
        except OSError as exc:
            log.error("GELF TCP %s:%s échoué — %s", self.host, self.port, exc)
            return False

    def push_anomaly(self, entity_type: str, item: dict[str, Any], threshold: float) -> bool:
        """Réinjecte une entité anormale. alert_tag posé si score >= seuil."""
        msg = (f"ML anomalie {entity_type} {item['entity']} "
               f"(score {item['ml_score']}) — {item['ml_reason']}")
        payload: dict[str, Any] = {
            "short_message": msg,
            "event_source": "ml_anomaly",
            "_entity": item["entity"],
            "_entity_type": entity_type,
            "_ml_score": item["ml_score"],
            "_ml_reason": item["ml_reason"],
            "_ml_model": "isolation_forest",
        }
        for k, v in item.get("features", {}).items():
            payload[f"_feat_{k}"] = v
        if item["ml_score"] >= threshold:
            payload["_alert_tag"] = "ml_anomaly"
        return self.send(payload)
