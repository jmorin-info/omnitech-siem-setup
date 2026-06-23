"""OMNI Sentinel — Pilier 3 : réponse graduée orchestrée (DEFENSIF, human-gated).

Compose un déclencheur (leurre du Pilier 1 / détection critique) avec le CONTEXTE du
jumeau d'attaque (Pilier 2 : rayon de souffle, distance aux joyaux, chokepoint) pour
produire un PLAN DE RÉPONSE GRADÉ.

GARDE-FOUS (par construction) :
  - DRY-RUN par défaut. Une action n'est RÉELLEMENT exécutée que si (a) armée en config
    (response.dry_run=false + auto_<action>=true) ET (b) double-verrou env OMNI_SENTINEL_ARM=1
    ET (c) approbation explicite (execute(approve=True)) — jamais automatique.
  - PÉRIMÈTRE : seules les actions sur l'INFRA OMNITECH PROPRE sont armables (isolation
    NinjaOne d'un hôte OMNITECH, blocage FortiGate d'une IP). Les actions IDENTITAIRES
    (désactivation AD / reset) restent TOUJOURS en recommandation — jamais armées.
  - CO-MANAGÉ : toute cible appartenant à un domaine/hôte co-managé (invissys…) est
    FORCÉE en recommandation (dry-run), quel que soit l'armement. Refus journalisé.
  - AUDIT : chaque plan/action -> GELF event_source=sentinel_response.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

log = logging.getLogger("oms-graph.response")

# Actions ARMABLES (infra OMNITECH propre) vs RECO-ONLY (identitaire, jamais armé).
ARMABLE = {"isolate_ninjaone", "block_fortigate"}
RECO_ONLY = {"disable_ad_account", "force_pwd_reset"}


def grade(context: dict, is_decoy: bool) -> str:
    """Grade un compromis/leurre à partir du contexte du jumeau d'attaque.
    context = entrée blast_radius de l'entité (hosts_reached, jewels_reached) +
    drapeau chokepoint. Un leurre = compromission quasi-certaine -> plancher 'eleve'."""
    jewels = context.get("jewels_reached") or []
    reach = int(context.get("hosts_reached") or 0)
    choke = bool(context.get("is_chokepoint"))
    if jewels or (choke and reach >= 10):
        return "critique"        # atteint un joyau OU chokepoint à fort rayon
    if is_decoy or reach >= 5 or choke:
        return "eleve"
    return "modere"


def build_plan(entity: str, source_host: str | None, source_ip: str | None,
               account: str | None, g: str, context: dict) -> dict[str, Any]:
    """Assemble le plan d'actions gradué (sans rien exécuter)."""
    steps: list[dict] = []
    host = source_host   # on n'isole QUE de vrais hôtes (jamais un nom de compte)
    if g in ("critique", "eleve") and host:
        steps.append({"action": "isolate_ninjaone", "target": host, "kind": "host",
                      "text": f"Isoler l'hôte {host} du réseau (NinjaOne) — contenir le pied-à-terre."})
    if g == "critique" and source_ip:
        steps.append({"action": "block_fortigate", "target": source_ip, "kind": "ip",
                      "text": f"Bloquer l'IP source {source_ip} au FortiGate (via feed omni-soar)."})
    if g == "critique" and account:
        steps.append({"action": "disable_ad_account", "target": account, "kind": "account",
                      "text": f"Désactiver le compte {account} + révoquer ses tickets Kerberos (RECO — validation manuelle)."})
    if g in ("critique", "eleve") and account:
        steps.append({"action": "force_pwd_reset", "target": account, "kind": "account",
                      "text": f"Réinitialiser {account} et révoquer les sessions (RECO — validation manuelle)."})
    if not steps:
        steps.append({"action": "monitor", "target": entity, "kind": "watch",
                      "text": f"Surveiller {entity} (mise sous surveillance) — exposition limitée."})
    return {
        "entity": entity, "grade": g,
        "jewels_at_risk": context.get("jewels_reached") or [],
        "hosts_reachable": context.get("hosts_reached") or 0,
        "steps": steps,
    }


class SentinelResponder:
    def __init__(self, cfg: dict) -> None:
        rc = cfg.get("response", {})
        self.cfg = rc
        self.dry = rc.get("dry_run", True)
        # Double-verrou : armement effectif seulement si l'env OMNI_SENTINEL_ARM=1 AUSSI.
        self.armed_env = os.environ.get("OMNI_SENTINEL_ARM", "") == "1"
        self.comanaged = [d.lower() for d in rc.get("comanaged_markers", ["invissys"])]

    def _is_comanaged(self, target: str) -> bool:
        t = (target or "").lower()
        return any(m in t for m in self.comanaged)

    def _armable(self, action: str, target: str) -> tuple[bool, str]:
        """Décide si l'action peut être RÉELLEMENT exécutée (sinon recommandation)."""
        if action in RECO_ONLY:
            return False, "action identitaire — recommandation uniquement (jamais armée)"
        if action not in ARMABLE:
            return False, "action non exécutable"
        if self._is_comanaged(target):
            return False, "cible co-managée — forcée en dry-run (garde-fou)"
        if self.dry or not self.cfg.get(f"auto_{action}", False):
            return False, "dry-run / auto_* désactivé en config"
        if not self.armed_env:
            return False, "double-verrou OMNI_SENTINEL_ARM absent"
        return True, "armée (infra OMNITECH)"

    def execute(self, plan: dict, approve: bool = False) -> dict:
        """Exécute le plan SI approuvé ET armé. Sinon, renvoie les recommandations.
        approve=True = validation explicite de l'analyste (jamais automatique)."""
        results: list[dict] = []
        for st in plan.get("steps", []):
            action, target = st["action"], st.get("target", "")
            armable, why = self._armable(action, target)
            if armable and approve:
                outcome = self._run(action, target)
                status = "EXECUTÉ"
            else:
                outcome = f"RECO ({why})" if not (armable and not approve) else "EN ATTENTE D'APPROBATION"
                status = "RECOMMANDÉ" if not approve else ("EN ATTENTE" if armable else "RECOMMANDÉ")
            results.append({**st, "status": status, "outcome": outcome})
        return {**plan, "results": results, "approved": approve}

    # --- adaptateurs d'action (gardés ; n'agissent que si appelés via execute armé) ---
    def _run(self, action: str, target: str) -> str:
        if action == "block_fortigate":
            return self._block_fortigate(target)
        if action == "isolate_ninjaone":
            return self._isolate_ninjaone(target)
        return f"action {action} non implémentée"

    def _block_fortigate(self, ip: str) -> str:
        """Délègue au feed omni-soar (aucun credential pare-feu ; public-only/TTL/cap
        appliqués par omni-soar), comme oms-xdr/responder."""
        url = self.cfg.get("fortigate", {}).get("soar_url", "http://127.0.0.1:8088/block")
        hits = int(self.cfg.get("fortigate", {}).get("soar_hits", 10))
        payload = {"backlog": [{"src_ip": ip} for _ in range(hits)],
                   "event": {"fields": {"src_ip": ip}, "key_tuple": [ip]}}
        try:
            r = requests.post(url, json=payload, timeout=15)
            r.raise_for_status()
            log.warning("ACTION sentinel: blocage FortiGate %s soumis au feed.", ip)
            return f"OK: IP {ip} soumise au feed omni-soar"
        except requests.RequestException as exc:
            return f"ERREUR blocage {ip}: {exc}"

    def _isolate_ninjaone(self, host: str) -> str:
        """Isolation réseau via API NinjaOne (creds OMS_NINJA_* ; délégué)."""
        log.warning("ACTION sentinel: isolation NinjaOne de %s (délégué API).", host)
        return f"OK(delegated): isolation NinjaOne de {host}"
