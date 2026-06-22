"""Moteur de corrélation OMS-XDR.

1. Évalue chaque SIGNAL (requête Graylog) -> ensemble d'entités déclenchantes
2. Évalue chaque RÈGLE (combinaison de signaux) -> incidents corrélés
3. Chaque incident porte : sévérité, techniques MITRE, entités, signaux sources
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .graylog_client import GraylogClient

log = logging.getLogger("oms-xdr.correlation")

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Incident:
    rule_id: str
    title: str
    severity: str
    entities: list[str]
    signals: list[str]
    mitre: list[str]
    tactic: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        return f"{self.rule_id}:{','.join(sorted(self.entities)) or 'global'}"

    def to_gelf(self) -> dict[str, Any]:
        return {
            "host": self.entities[0] if self.entities else "oms-xdr",
            "short_message": f"[{self.severity.upper()}] {self.title}",
            "full_message": self.evidence.get("narrative", self.title),
            "level": {"low": 6, "medium": 4, "high": 3, "critical": 2}.get(self.severity, 5),
            "_event_source": "xdr_incident",
            "_oms_event": "xdr_incident",
            "_rule_id": self.rule_id,
            "_severity": self.severity,
            "_mitre": ",".join(self.mitre),
            "_tactic": ",".join(self.tactic),
            "_entities": ",".join(self.entities),
            "_signals": ",".join(self.signals),
            "_remediation": self.evidence.get("remediation_text", ""),
        }


class Correlator:
    def __init__(self, rules_path: str, gl: GraylogClient, window_minutes: int) -> None:
        with Path(rules_path).open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        self.signals: dict[str, dict] = data.get("signals", {})
        self.rules: dict[str, dict] = data.get("rules", {})
        self.gl = gl
        self.window = window_minutes

    # ------------------------------------------------------------------
    def _eval_signal(self, sid: str) -> dict[str, int]:
        """Retourne {entite: count} pour un signal.

        Fenêtre : `window` du signal si présent, sinon la fenêtre globale
        (rétro-compatible ; requis pour S_LSASS_6H -> corrélation latérale lente).
        """
        sig = self.signals[sid]
        stream = sig.get("stream", "")
        query = sig["query"]
        ef = sig["entity_field"]
        window = int(sig.get("window", self.window))
        agg = self.gl.aggregate(query, stream, ef, window)
        if sig["type"] == "count_by":
            thr = int(sig.get("threshold", 1))
            return {k: v for k, v in agg.items() if v >= thr}
        return {k: v for k, v in agg.items() if v > 0}

    def _emit_health(self, failed: list[str]) -> None:
        """Réinjecte un événement de santé quand des signaux échouent.

        Sans cela, un signal en panne (timeout OpenSearch, mapping cassé) devient un
        ensemble VIDE indistinguable d'un signal qui n'a légitimement rien déclenché :
        toute règle `require_all` qui en dépend est alors SILENCIEUSEMENT supprimée.
        On émet `xdr_health` pour que le SIEM alerte sur la perte de couverture.
        """
        if not getattr(self, "gl", None):
            return
        try:
            self.gl.send_gelf({
                "host": "oms-xdr",
                "short_message": f"[XDR] {len(failed)} signal(aux) de corrélation en échec",
                "full_message": ("Signaux en échec : " + ", ".join(failed)
                                 + ". Les règles de corrélation qui en dépendent peuvent "
                                   "ne pas se déclencher (perte de couverture)."),
                "level": 4,
                "_event_source": "xdr_health",
                "_oms_event": "xdr_health",
                "_signals_failed": ",".join(failed),
                "_signals_failed_count": len(failed),
            })
        except Exception as exc:  # l'émission de santé ne doit jamais casser le cycle
            log.error("Émission xdr_health échouée : %s", exc)

    def evaluate(self) -> list[Incident]:
        # cache des signaux (évite de réinterroger Graylog plusieurs fois)
        fired: dict[str, dict[str, int]] = {}
        failed: list[str] = []
        for sid in self.signals:
            try:
                fired[sid] = self._eval_signal(sid)
            except Exception as exc:  # robustesse : un signal cassé ne bloque pas le reste
                log.warning("Signal %s en échec: %s", sid, exc)
                fired[sid] = {}
                failed.append(sid)
        if failed:  # ne pas masquer la dégradation : la rendre visible dans le SIEM
            self._emit_health(failed)

        incidents: list[Incident] = []
        for rid, rule in self.rules.items():
            inc = self._eval_rule(rid, rule, fired)
            incidents.extend(inc)
        # tri par sévérité décroissante (sévérité inconnue -> -1, jamais de KeyError)
        incidents.sort(key=lambda i: _SEV_ORDER.get(i.severity, -1), reverse=True)
        return incidents

    def _eval_rule(self, rid: str, rule: dict,
                   fired: dict[str, dict[str, int]]) -> list[Incident]:
        require_all = rule.get("require_all", [])
        any_of = rule.get("any_of", [])
        join = rule.get("join_entity", False)

        # les signaux "require_all" doivent tous avoir déclenché
        if any(not fired.get(s) for s in require_all):
            return []
        # au moins un "any_of" si la liste est non vide
        if any_of and not any(fired.get(s) for s in any_of):
            return []

        active_signals = [s for s in (require_all + any_of) if fired.get(s)]

        if join:
            # intersection des entités sur les signaux obligatoires,
            # puis exiger présence d'au moins un any_of sur la même entité
            sets = [set(fired[s]) for s in require_all if fired.get(s)]
            common = set.intersection(*sets) if sets else set()
            if any_of:
                any_entities: set[str] = set()
                for s in any_of:
                    any_entities |= set(fired.get(s, {}))
                common = common & any_entities if common else (any_entities if not require_all else common)
            if not common:
                return []
            entities = sorted(common)
        else:
            entities = sorted({
                e for s in active_signals for e in fired.get(s, {})
            })

        ev = {
            s: {e: fired[s][e] for e in (entities if join else fired[s]) if e in fired[s]}
            for s in active_signals
        }
        return [Incident(
            rule_id=rid,
            title=rule["title"],
            severity=rule["severity"],
            entities=entities,
            signals=active_signals,
            mitre=rule.get("mitre", []),
            tactic=rule.get("tactic", []),
            evidence={"counts": ev},
        )]
