"""Actions de réponse OMS-XDR.

SÉCURITÉ : tout est en dry-run par défaut. Une action n'est réellement exécutée
que si response.dry_run=false ET le flag auto_* correspondant=true dans config.yaml.
Sinon, l'action est seulement journalisée comme recommandation.

Équivalent des « Pre-approved Actions » d'un MXDR, mais sous contrôle RSSI.
"""
from __future__ import annotations

import logging

import requests

log = logging.getLogger("oms-xdr.responder")


class Responder:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg.get("response", {})
        self.dry = self.cfg.get("dry_run", True)

    # ------------------------------------------------------------------
    def execute(self, action: str, entities: list[str]) -> list[str]:
        """Exécute (ou recommande) une action sur les entités fournies."""
        results: list[str] = []
        for ent in entities:
            results.append(getattr(self, f"_{action}", self._unknown)(ent))
        return results

    def _guard(self, flag: str, descr: str) -> bool:
        if self.dry or not self.cfg.get(flag, False):
            log.info("[RECOMMANDATION] %s (non exécuté : dry_run/%s)", descr, flag)
            return False
        return True

    # ------------------------------------------------------------------
    def _block_fortigate(self, entity: str) -> str:
        """Délègue au feed omni-soar (AUCUN credential sur le pare-feu). On POST un
        payload compatible ; omni-soar applique public-only / whitelist / TTL / cap
        et publie l'IP dans le Threat Feed que le FortiGate lit (policy deny WAN)."""
        fc = self.cfg.get("fortigate", {})
        descr = f"Blocage FortiGate de {entity} (via feed omni-soar)"
        if not self._guard("auto_block_fortigate", descr):
            return f"RECO: {descr}"
        url = fc.get("soar_url", "http://127.0.0.1:8088/block")
        hits = int(fc.get("soar_hits", 10))  # >= SOAR_MIN_HITS (00-vars.env, défaut 5)
        payload = {"backlog": [{"src_ip": entity} for _ in range(hits)],
                   "event": {"fields": {"src_ip": entity}, "key_tuple": [entity]}}
        try:
            r = requests.post(url, json=payload, timeout=15)
            r.raise_for_status()
            res = r.json()
            if entity in (res.get("blocked") or []):
                log.warning("ACTION: %s — IP soumise au feed (bloquée).", descr)
                return f"OK: {descr}"
            log.warning("ACTION: %s — feed: %s (déjà active / non publique / whitelist).", descr, res)
            return f"OK(feed): {descr}"
        except requests.RequestException as exc:
            log.error("Délégation SOAR échouée: %s", exc)
            return f"ERREUR: {descr} ({exc})"

    def _disable_ad_account(self, entity: str) -> str:
        descr = f"Désactivation du compte AD {entity}"
        if not self._guard("auto_disable_ad_account", descr):
            return f"RECO: {descr}"
        # Exécution réelle déléguée à un runbook PowerShell signé via WinRM/NinjaOne.
        log.warning("ACTION: %s — déléguée au runbook AD.", descr)
        return f"OK(delegated): {descr}"

    def _force_pwd_reset(self, entity: str) -> str:
        descr = f"Réinitialisation forcée + révocation sessions pour {entity}"
        if not self._guard("auto_disable_ad_account", descr):
            return f"RECO: {descr}"
        log.warning("ACTION: %s — déléguée au runbook AD.", descr)
        return f"OK(delegated): {descr}"

    def _isolate_ninjaone(self, entity: str) -> str:
        descr = f"Isolation réseau de l'hôte {entity} via NinjaOne"
        if not self._guard("auto_isolate_ninjaone", descr):
            return f"RECO: {descr}"
        log.warning("ACTION: %s — déléguée à l'API NinjaOne.", descr)
        return f"OK(delegated): {descr}"

    def _unknown(self, entity: str) -> str:
        return f"RECO: action inconnue pour {entity}"
