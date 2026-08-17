"""Tests de l'orchestrateur : ordre dedup/seuil AVANT enrichissement et reponse.

Verrou F.5 (audit 17/07/2026). Les tests de dedup et de seuil de severite etaient
evalues APRES enrich() et resp.execute() : un incident deja notifie payait la
narration LLM (Ollama, CPU) et rejouait toutes les actions de reponse a chaque
cycle de 5 min. Un incident ecarte ne doit RIEN declencher.
"""
import json
import time
from pathlib import Path

import pytest

from oms_xdr import engine
from oms_xdr.correlation import Incident


class ResponderCompteur:
    """Ne fait rien, compte les appels. Aucune action reelle, aucun reseau."""

    def __init__(self):
        self.appels = []

    def execute(self, action, entities):
        self.appels.append((action, tuple(entities)))
        return [f"RECO: {action}"]


class GraylogFactice:
    def __init__(self):
        self.sent = []

    def send_gelf(self, payload):
        self.sent.append(payload)
        return True


class CorrelateurFactice:
    def __init__(self, incidents):
        self._incidents = incidents

    def evaluate(self):
        return list(self._incidents)


def _incident(rule_id="CR_RANSOMWARE", severity="critical"):
    return Incident(rule_id=rule_id, title="Rancongiciel detecte", severity=severity,
                    entities=["BX-AD-01-IT-VM"], signals=["s_vss"], mitre=["T1486"],
                    tactic="impact", evidence={})


@pytest.fixture
def enrich_compteur(monkeypatch):
    """Neutralise l'appel LLM et compte les invocations (aucun Ollama en test)."""
    appels = []

    def _fake(inc, cfg):
        appels.append(inc.key())
        return "narration"

    monkeypatch.setattr(engine, "enrich", _fake)
    return appels


def _cfg(state_dir):
    return {"engine": {"state_dir": str(state_dir), "dedup_minutes": 60,
                       "min_severity_notify": "medium"},
            "teams": {"enabled": False}}


def test_incident_deduplique_ne_declenche_aucune_action(tmp_path, enrich_compteur):
    """Incident deja notifie => resp.execute JAMAIS appele, et pas de LLM."""
    inc = _incident()
    # Deja notifie il y a 60 s : largement dans la fenetre de dedup (60 min).
    (tmp_path / "incident_state.json").write_text(
        json.dumps({inc.key(): time.time() - 60}))

    resp = ResponderCompteur()
    gl = GraylogFactice()
    traites = engine.run_cycle(_cfg(tmp_path), gl, CorrelateurFactice([inc]), resp)

    assert traites == 0
    assert gl.sent == []
    assert resp.appels == [], (
        f"actions declenchees sur un incident deduplique : {resp.appels}")
    assert enrich_compteur == [], "appel LLM sur un incident deduplique"


def test_incident_sous_le_seuil_ne_declenche_aucune_action(tmp_path, enrich_compteur):
    """Severite < min_severity_notify => aucune action, aucun LLM."""
    inc = _incident(rule_id="CR_LOW", severity="low")
    resp = ResponderCompteur()
    gl = GraylogFactice()
    traites = engine.run_cycle(_cfg(tmp_path), gl, CorrelateurFactice([inc]), resp)

    assert traites == 0
    assert gl.sent == []
    assert resp.appels == []
    assert enrich_compteur == []


def test_chemin_nominal_intact(tmp_path, enrich_compteur):
    """NON-REGRESSION : un incident neuf est bien enrichi, traite et notifie."""
    inc = _incident()
    resp = ResponderCompteur()
    gl = GraylogFactice()
    traites = engine.run_cycle(_cfg(tmp_path), gl, CorrelateurFactice([inc]), resp)

    assert traites == 1
    assert len(gl.sent) == 1
    assert resp.appels, "aucune action sur un incident neuf : le nominal est casse"
    assert enrich_compteur == [inc.key()]
    assert inc.evidence["narrative"] == "narration"
    assert inc.evidence["actions"]
    # L'etat est persiste pour que le cycle suivant deduplique.
    etat = json.loads((tmp_path / "incident_state.json").read_text())
    assert inc.key() in etat


def test_deuxieme_cycle_deduplique_le_premier(tmp_path, enrich_compteur):
    """Bout en bout : 2 cycles consecutifs => 1 seul traitement, 1 seule action."""
    inc = _incident()
    gl = GraylogFactice()
    cfg = _cfg(tmp_path)

    resp1 = ResponderCompteur()
    assert engine.run_cycle(cfg, gl, CorrelateurFactice([inc]), resp1) == 1

    resp2 = ResponderCompteur()
    assert engine.run_cycle(cfg, gl, CorrelateurFactice([inc]), resp2) == 0

    assert resp1.appels and resp2.appels == []
    assert len(gl.sent) == 1
    assert len(enrich_compteur) == 1, "le LLM a ete rappele au 2e cycle"
    assert Path(tmp_path, "incident_state.json").exists()
