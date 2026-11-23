"""Outil de mise à jour des détections (tools/maj-detections-2026-11.py), sans réseau.

L'API Graylog et OpenSearch sont remplacées par des faux en mémoire ; on vérifie que le
mode plan n'écrit rien, que --apply sauvegarde puis applique une définition à la fois,
qu'il est idempotent, qu'une dérive bloque, que la désactivation passe par unschedule
et que --rollback restaure l'état sauvegardé.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("maj_detections_2026_11", ROOT / "tools/maj-detections-2026-11.py")
maj = importlib.util.module_from_spec(_spec)
sys.modules["maj_detections_2026_11"] = maj
_spec.loader.exec_module(maj)

S_SYS, S_AUD = "a" * 24, "b" * 24


def _defn(i, titre, query, streams=(S_SYS,), state="ENABLED"):
    return {"_scope": "DEFAULT", "id": i, "title": titre, "priority": 2, "alert": True, "state": state,
            "updated_at": "x", "matched_at": "y", "scheduler": None,
            "config": {"type": "aggregation-v1", "query": query, "streams": list(streams), "group_by": [],
                       "series": [{"type": "count", "id": "count()", "field": None}],
                       "conditions": {"expression": None}, "search_within_ms": 60000, "execute_every_ms": 60000},
            "field_spec": {}, "key_spec": [], "notifications": [], "storage": []}


class FauxGraylog:
    def __init__(self, defs):
        self.defs = {d["id"]: copy.deepcopy(d) for d in defs}
        self.ecritures = []

    def get(self, chemin):
        if chemin == "/streams":
            return {"streams": [{"id": S_SYS, "title": "OMNI - Sysmon", "index_set_id": "i1"},
                                {"id": S_AUD, "title": "OMNI - SEAL Audit", "index_set_id": "i1"}]}
        if chemin.startswith("/system/indices/index_sets"):
            return {"index_sets": [{"id": "i1", "index_prefix": "omni-x"}]}
        i = chemin.rsplit("/", 1)[-1]
        if i not in self.defs:
            import urllib.error
            raise urllib.error.HTTPError(chemin, 404, "absent", {}, None)
        return copy.deepcopy(self.defs[i])

    def put(self, chemin, corps=None):
        self.ecritures.append((chemin, copy.deepcopy(corps)))
        base, _, qs = chemin.partition("?")
        if base.endswith("/unschedule"):
            self.defs[base.split("/")[-2]]["state"] = "DISABLED"
            return {}
        i = base.rsplit("/", 1)[-1]
        nouveau = copy.deepcopy(corps)
        nouveau["state"] = "ENABLED" if qs == "schedule=true" else "DISABLED"
        self.defs[i] = nouveau
        return {"id": i}


class FauxOpenSearch:
    def __init__(self):
        self.appels = []

    def appel(self, methode, chemin, corps=None, **_):
        assert methode == "POST" and "/_count" in chemin
        self.appels.append(corps)
        q = corps["query"]["bool"]["must"][0].get("query_string", {}).get("query", "*")
        return {"count": 7 if "[aA]" in q else 3}


def _cibles(tmp_path, cibles):
    p = tmp_path / "cibles.json"
    p.write_text(json.dumps({"cibles": cibles}), encoding="utf-8")
    return p


CIBLE_Q = {"id": "d1", "titre": "OMNI - RAT", "chantier": "1-casse", "motif": "casse",
           "attendu_avant": {"query": "img:*anydesk*"}, "cible": {"query": "img:/.*[aA][nN][yY].*/"}}
CIBLE_OFF = {"id": "d2", "titre": "OMNI - ZON", "chantier": "4-zon001", "motif": "table vide",
             "attendu_avant": {"state": "ENABLED"}, "cible": {"state": "DISABLED"}}
CIBLE_FLUX = {"id": "d3", "titre": "OMNI - Fuite", "chantier": "7-flux", "motif": "flux",
              "attendu_avant": {"streams_titres": []}, "cible": {"streams_titres": ["OMNI - SEAL Audit"]}}


def _gl():
    return FauxGraylog([_defn("d1", "OMNI - RAT", "img:*anydesk*"), _defn("d2", "OMNI - ZON", "zone:*"),
                        _defn("d3", "OMNI - Fuite", "alert_tag:github_leak", streams=())])


def test_plan_lecture_seule_diff_et_comptages(tmp_path):
    gl, os_ = _gl(), FauxOpenSearch()
    lignes = []
    code = maj.main(["--cibles", str(_cibles(tmp_path, [CIBLE_Q, CIBLE_OFF, CIBLE_FLUX]))], gl=gl, os_client=os_,
                    journal=lignes.append)
    texte = "\n".join(lignes)
    assert code == 0 and gl.ecritures == []
    assert "_count : production 3 -> cible 7 (écart +4)" in texte
    assert '+ "etat": "DISABLED"' in texte and "OMNI - SEAL Audit" in texte
    assert "Aucune écriture effectuée" in texte


def test_apply_exige_un_repertoire_de_sauvegarde(tmp_path):
    assert maj.main(["--apply", "--cibles", str(_cibles(tmp_path, [CIBLE_Q]))], gl=_gl(),
                    os_client=FauxOpenSearch(), journal=lambda *_: None) == 3


def test_apply_sauvegarde_applique_puis_idempotent(tmp_path):
    gl, sauv = _gl(), tmp_path / "sauv"
    args = ["--apply", "--sauvegardes", str(sauv), "--cibles", str(_cibles(tmp_path, [CIBLE_Q, CIBLE_OFF, CIBLE_FLUX]))]
    assert maj.main(args, gl=gl, os_client=FauxOpenSearch(), journal=lambda *_: None) == 0
    assert gl.defs["d1"]["config"]["query"] == "img:/.*[aA][nN][yY].*/"
    assert gl.defs["d1"]["state"] == "ENABLED"
    assert gl.defs["d2"]["state"] == "DISABLED"
    assert gl.defs["d3"]["config"]["streams"] == [S_AUD]
    assert ("/events/definitions/d2/unschedule", None) in gl.ecritures
    corps_d1 = next(c for ch, c in gl.ecritures if ch.startswith("/events/definitions/d1?"))
    assert not set(corps_d1) & {"_scope", "matched_at", "updated_at", "scheduler", "state"}
    assert json.loads((sauv / "d1.json").read_text())["config"]["query"] == "img:*anydesk*"
    n = len(gl.ecritures)
    lignes = []
    assert maj.main(args, gl=gl, os_client=FauxOpenSearch(), journal=lignes.append) == 0
    assert len(gl.ecritures) == n                                  # rien à réécrire
    assert "CONFORME 3" in lignes[-1]
    assert json.loads((sauv / "d1.json").read_text())["config"]["query"] == "img:*anydesk*"   # original conservé


def test_derive_bloque_sauf_forcer(tmp_path):
    gl = _gl()
    gl.defs["d1"]["config"]["query"] = "img:*anydesk* AND NOT host:x"
    args = ["--apply", "--sans-comptage", "--sauvegardes", str(tmp_path / "s"),
            "--cibles", str(_cibles(tmp_path, [CIBLE_Q]))]
    assert maj.main(args, gl=gl, journal=lambda *_: None) == 1
    assert gl.ecritures == []
    assert maj.main(args + ["--forcer"], gl=gl, journal=lambda *_: None) == 0
    assert gl.defs["d1"]["config"]["query"] == "img:/.*[aA][nN][yY].*/"


def test_definition_introuvable_signalee(tmp_path):
    c = dict(CIBLE_Q, id="zz")
    lignes = []
    assert maj.main(["--sans-comptage", "--cibles", str(_cibles(tmp_path, [c]))], gl=_gl(),
                    journal=lignes.append) == 1
    assert any("INTROUVABLE" in ligne for ligne in lignes)


def test_rollback_restaure_etat_et_planification(tmp_path):
    gl, sauv = _gl(), tmp_path / "sauv"
    args = ["--sans-comptage", "--sauvegardes", str(sauv), "--cibles", str(_cibles(tmp_path, [CIBLE_Q, CIBLE_OFF]))]
    maj.main(["--apply"] + args, gl=gl, journal=lambda *_: None)
    assert gl.defs["d2"]["state"] == "DISABLED"
    assert maj.main(["--rollback"] + args, gl=gl, journal=lambda *_: None) == 0
    assert gl.defs["d1"]["config"]["query"] == "img:*anydesk*"
    assert gl.defs["d2"]["state"] == "ENABLED"


def test_fichier_de_cibles_livre_coherent():
    doc = json.loads(maj.CIBLES_PAR_DEFAUT.read_text(encoding="utf-8"))
    ids = [c["id"] for c in doc["cibles"]]
    assert len(ids) == len(set(ids))
    for c in doc["cibles"]:
        assert c["motif"] and c["cible"]
        assert set(c["attendu_avant"]) == set(c["cible"])
        if "query" in c["cible"]:
            maj.dv.analyser(c["cible"]["query"])
        if "state" in c["cible"]:
            assert c["cible"]["state"] == "DISABLED"           # seule écriture d'état permise
    desactivees = [c["titre"] for c in doc["cibles"] if c["cible"].get("state") == "DISABLED"]
    assert desactivees == ["OMNI - SEAL ZON-001 - Rafale de refus d'acces dans une zone"]
