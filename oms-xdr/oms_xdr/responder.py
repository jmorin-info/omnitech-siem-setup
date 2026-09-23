"""Actions de réponse OMS-XDR.

SÉCURITÉ : tout est en dry-run par défaut. Une action n'est réellement exécutée
que si response.dry_run=false ET le flag auto_* correspondant=true dans config.yaml.
Sinon, l'action est seulement journalisée comme recommandation.

ÉTAT RÉEL D'IMPLÉMENTATION (à tenir à jour — un écart ici se paie en incident) :
  - block_fortigate    : RÉEL, délégué au feed omni-soar (seule action câblée).
  - isolate_ninjaone   : NON IMPLÉMENTÉ — aucun runbook, aucun appel sortant.
  - disable_ad_account : NON IMPLÉMENTÉ — aucun runbook, aucun appel sortant.
  - force_pwd_reset    : NON IMPLÉMENTÉ — aucun runbook, aucun appel sortant.
Les trois actions non implémentées retournent « NON-IMPLEMENTE: … » (jamais « OK »)
lorsque le double verrou est levé : le produit doit dire la vérité, faute de quoi le
SOC croit un hôte isolé pendant qu'une attaque se propage.

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

    # ------------------------------------------------------------------
    # ACTIONS SANS RUNBOOK — elles ne s'executent PAS et ne doivent JAMAIS le laisser croire.
    #
    # Contrairement a _block_fortigate (reel, via le feed omni-soar), les trois actions
    # ci-dessous n'ont AUCUN appel sortant : ni API NinjaOne, ni WinRM, ni AD, ni runbook.
    # Elles retournaient "OK(delegated)" et journalisaient "ACTION: ... deleguee a ...",
    # ce qui est un mensonge : le SOC croyait l'hote isole ou le compte desactive alors
    # que rien ne s'etait produit. isolate_ninjaone est cite par 11 playbooks de
    # remediation.py, dont l'etape 1 de CR_RANSOMWARE.
    #
    # Regle : tant qu'aucun runbook n'est raccorde, le retour est NON-IMPLEMENTE et le
    # journal est en ERROR, MEME quand le double verrou (dry_run=false + auto_*=true)
    # est leve. Un verrou leve n'implemente rien : il ne peut donc pas produire un "OK".
    #
    # NE PAS implementer ici l'appel NinjaOne/AD reel sans autorisation RSSI explicite :
    # ce serait armer une capacite de reponse non autorisee, et le tenant invissys.com
    # est co-gere (enrichissement/etiquetage seulement, aucune action de reponse).
    def _no_runbook(self, flag: str, descr: str) -> str:
        """Retour honnete pour une action dont le runbook n'existe pas.

        Le double verrou reste evalue (pour distinguer la recommandation du cas ou
        l'operateur croyait vraiment declencher l'action), mais aucune branche ne
        renvoie un succes : ce code n'execute rien.
        """
        if not self._guard(flag, descr):
            return f"RECO: {descr}"
        log.error("NON-IMPLEMENTE: %s — le double verrou est levé (dry_run=false, %s=true) "
                  "mais AUCUN runbook n'est raccordé : rien n'a été exécuté. "
                  "Traitement MANUEL requis immédiatement.", descr, flag)
        return f"NON-IMPLEMENTE: {descr} — aucun runbook raccordé, traitement manuel requis"

    def _disable_ad_account(self, entity: str) -> str:
        return self._no_runbook("auto_disable_ad_account",
                                f"Désactivation du compte AD {entity}")

    def _force_pwd_reset(self, entity: str) -> str:
        return self._no_runbook("auto_disable_ad_account",
                                f"Réinitialisation forcée + révocation sessions pour {entity}")

    def _isolate_ninjaone(self, entity: str) -> str:
        return self._no_runbook("auto_isolate_ninjaone",
                                f"Isolation réseau de l'hôte {entity} via NinjaOne")

    def _unknown(self, entity: str) -> str:
        return f"RECO: action inconnue pour {entity}"
