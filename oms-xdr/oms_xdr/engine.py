"""Orchestrateur OMS-XDR.

Boucle : corréler -> enrichir (LLM) -> remédiation -> réponse (dry-run) ->
réinjecter l'incident dans Graylog (GELF) + notifier Teams.
Déduplication sur fenêtre glissante via état local.

Usage :
    python -m oms_xdr.engine --once         # un cycle (idéal via systemd timer)
    python -m oms_xdr.engine                # démon (loop_seconds)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path

import requests

from .config import load_config
from .correlation import Correlator, Incident, _SEV_ORDER
from .enrich import enrich
from .graylog_client import GraylogClient
from .remediation import build_remediation
from .responder import Responder

log = logging.getLogger("oms-xdr.engine")


def _load_state(path: str) -> dict[str, float]:
    p = Path(path) / "incident_state.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_state(path: str, state: dict[str, float]) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
    (Path(path) / "incident_state.json").write_text(json.dumps(state))


def _notify_teams(cfg: dict, inc: Incident) -> None:
    tc = cfg.get("teams", {})
    if not tc.get("enabled"):
        return
    url = os.environ.get(tc.get("webhook_env", ""), "")
    if not url:
        return
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": f"[{inc.severity.upper()}] {inc.title}"},
                    {"type": "FactSet", "facts": [
                        {"title": "Règle", "value": inc.rule_id},
                        {"title": "Entités", "value": ", ".join(inc.entities) or "n/a"},
                        {"title": "MITRE", "value": ", ".join(inc.mitre)},
                        {"title": "Signaux", "value": ", ".join(inc.signals)},
                    ]},
                    {"type": "TextBlock", "wrap": True,
                     "text": inc.evidence.get("narrative", "")},
                ],
            },
        }],
    }
    try:
        requests.post(url, json=card, timeout=20)
    except requests.RequestException as exc:
        log.warning("Notification Teams échouée: %s", exc)


def run_cycle(cfg: dict, gl: GraylogClient, corr: Correlator, resp: Responder) -> int:
    state = _load_state(cfg["engine"]["state_dir"])
    now = time.time()
    dedup = cfg["engine"].get("dedup_minutes", 60) * 60
    min_sev = _SEV_ORDER[cfg["engine"].get("min_severity_notify", "medium")]

    incidents = corr.evaluate()
    processed = 0
    for inc in incidents:
        # remédiation
        rem = build_remediation(inc.rule_id, inc.mitre)
        inc.evidence["remediation_text"] = rem["text"]
        # narration LLM
        inc.evidence["narrative"] = enrich(inc, cfg)
        # réponse (dry-run par défaut)
        action_log: list[str] = []
        for action in dict.fromkeys(rem["actions"]):
            action_log += resp.execute(action, inc.entities)
        inc.evidence["actions"] = action_log

        # déduplication + seuil de notification
        key = inc.key()
        if now - state.get(key, 0) < dedup:
            log.info("Incident %s déjà notifié récemment — ignoré.", key)
            continue
        if _SEV_ORDER[inc.severity] < min_sev:
            continue

        # réinjection SIEM + Teams
        gl.send_gelf(inc.to_gelf())
        _notify_teams(cfg, inc)
        state[key] = now
        processed += 1
        log.warning("INCIDENT [%s] %s | entités=%s | actions=%s",
                    inc.severity.upper(), inc.title, inc.entities, action_log)

    _save_state(cfg["engine"]["state_dir"], state)
    log.info("Cycle terminé : %d incident(s) traité(s) sur %d détecté(s).",
             processed, len(incidents))
    return processed


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(description="OMS-XDR — moteur de corrélation")
    ap.add_argument("--config", default="/etc/oms-xdr/config.yaml")
    ap.add_argument("--once", action="store_true", help="un seul cycle puis sortie")
    ap.add_argument("--rules", default=None, help="chemin rules.yaml (défaut: paquet)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    # Lecture via OpenSearch local : aucun token Graylog requis.
    gl = GraylogClient(cfg["graylog"])
    rules_path = args.rules or str(Path(__file__).parent / "rules.yaml")
    corr = Correlator(rules_path, gl, cfg["engine"]["window_minutes"])
    resp = Responder(cfg)

    if args.once:
        run_cycle(cfg, gl, corr, resp)
        return
    interval = cfg["engine"].get("loop_seconds", 300)
    log.info("Démon OMS-XDR démarré (cycle %ds).", interval)
    while True:
        try:
            run_cycle(cfg, gl, corr, resp)
        except Exception as exc:  # le démon ne doit jamais mourir sur une erreur de cycle
            log.exception("Erreur de cycle: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
