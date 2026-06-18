"""Enrichissement par LLM local (Ollama / Mistral 7B).

Transforme un incident corrélé brut en narration analyste concise en français
(« que s'est-il passé, pourquoi, quoi vérifier en priorité »).
Optionnel : si Ollama est indisponible, on retombe sur une narration déterministe.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

log = logging.getLogger("oms-xdr.enrich")

_SYSTEM = (
    "Tu es analyste SOC senior chez OMNITECH Security. À partir d'un incident "
    "corrélé (signaux, entités, techniques MITRE), produis une synthèse en "
    "français, registre expert, 4 phrases maximum : nature probable de l'attaque, "
    "niveau de confiance, et l'élément à vérifier EN PRIORITÉ. Pas de remplissage."
)


def _fallback(incident: Any) -> str:
    return (
        f"{incident.title}. Entités concernées : {', '.join(incident.entities) or 'n/a'}. "
        f"Signaux : {', '.join(incident.signals)}. Techniques : {', '.join(incident.mitre)}. "
        "Vérifier en priorité la légitimité des entités et l'absence d'accès abouti."
    )


def enrich(incident: Any, cfg: dict) -> str:
    oc = cfg.get("ollama", {})
    if not oc.get("enabled"):
        return _fallback(incident)

    prompt = {
        "regle": incident.rule_id,
        "titre": incident.title,
        "severite": incident.severity,
        "entites": incident.entities,
        "signaux": incident.signals,
        "mitre": incident.mitre,
        "tactiques": incident.tactic,
        "comptages": incident.evidence.get("counts", {}),
    }
    body = {
        "model": oc.get("model", "mistral:7b"),
        "stream": False,
        "system": _SYSTEM,
        "prompt": "Incident :\n" + json.dumps(prompt, ensure_ascii=False, indent=2),
        "options": {"temperature": 0.2},
    }
    try:
        # connexion courte (5s) pour ne pas bloquer le démon si Ollama est injoignable ;
        # lecture longue (génération du modèle)
        r = requests.post(f"{oc['url'].rstrip('/')}/api/generate",
                          json=body, timeout=(5, oc.get("timeout", 120)))
        r.raise_for_status()
        text = r.json().get("response", "").strip()
        return text or _fallback(incident)
    except (requests.RequestException, ValueError) as exc:
        log.warning("Ollama indisponible (%s) — narration déterministe.", exc)
        return _fallback(incident)
