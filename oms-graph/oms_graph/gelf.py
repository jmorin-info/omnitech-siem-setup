"""Réinjection des chemins d'exposition dans le SIEM via l'input GELF existant.

Même mécanisme que oms-ml / oms-xdr : POST /gelf. Chaque chemin court pied-à-terre
-> joyau devient un événement event_source=attack_path (champ exposure_hops,
exposure_jewel...), consommable par les pipelines / la console / les alertes.
DEFENSIF : signale une exposition à durcir, ne déclenche aucune action.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

log = logging.getLogger("oms-graph.gelf")


class Gelf:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.host = cfg.get("host", "127.0.0.1")
        self.port = int(cfg.get("port", 12201))

    def send(self, payload: dict[str, Any]) -> bool:
        payload.setdefault("version", "1.1")
        payload.setdefault("host", "oms-graph")
        payload.setdefault("timestamp", time.time())
        try:
            r = requests.post(f"http://{self.host}:{self.port}/gelf", json=payload, timeout=10)
            r.raise_for_status()
            return True
        except requests.RequestException as exc:
            log.error("GELF HTTP %s:%s échoué — %s", self.host, self.port, exc)
            return False

    def push_path(self, path: dict[str, Any], threshold_hops: int) -> bool:
        msg = (f"Exposition : {path['from']} -> {path['to']} ({path['label']}) "
               f"en {path['hops']} saut(s)")
        payload: dict[str, Any] = {
            "short_message": msg,
            "event_source": "attack_path",
            "_exposure_from": path["from"],
            "_exposure_jewel": path["to"],
            "_exposure_label": path["label"],
            "_exposure_hops": path["hops"],
            "_exposure_chain": " -> ".join(path["path"]),
        }
        # Signal de POSTURE (l'exposition persiste d'un run à l'autre) -> PAS d'alert_tag
        # (sinon alerte récurrente sur un fait structurel). Champ informationnel : un
        # chemin court = exposition aiguë, surfacé dans la console/dashboard, à durcir.
        payload["_exposure_acute"] = path["hops"] <= threshold_hops
        return self.send(payload)
