"""Validation des détections : analyseur, évaluateur, fixtures, contrôles statiques et vivacité.

Aucun accès réseau : l'API Graylog et OpenSearch sont remplacés par des faux en mémoire
(le faux OpenSearch réutilise l'évaluateur de l'outil pour répondre aux _count).
"""
from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("omni_detection_validate", ROOT / "tools/omni-detection-validate.py")
dv = importlib.util.module_from_spec(_spec)
sys.modules["omni_detection_validate"] = dv
_spec.loader.exec_module(dv)

FIXTURES = dv.charger_fixtures(dv.FIXTURES_PAR_DEFAUT)
MAINTENANT = 1_800_000_000.0


# ----------------------------------------------------------------- analyseur
@pytest.mark.parametrize("requete,doc,attendu", [
    ("alert_tag:canary", {"alert_tag": "canary"}, True),
    ("alert_tag:canary", {"alert_tag": "Canary"}, False),                      # keyword sensible à la casse
    ("a:1 AND b:2 OR c:3", {"a": "1", "b": "2"}, True),
    ("a:1 AND b:2 OR c:3", {"c": "3"}, False),                                 # sémantique Lucene, pas booléenne
    ("a:1 OR b:2", {"b": "2"}, True),
    ("NOT a:1", {"a": "2"}, True),                                             # négatif pur : match_all implicite
    ("NOT a:1", {"a": "1"}, False),
    ("a:1 AND NOT user:*$", {"a": "1", "user": "PC01$"}, False),
    ("a:1 AND NOT user:*$", {"a": "1", "user": "jdupont"}, True),
    ("user:(ninjaone OR ADSyncMSA_*)", {"user": "ADSyncMSA_42"}, True),
    (r"action:tunnel\-up", {"action": "tunnel-up"}, True),
    (r"user:*\\adm\-*", {"user": "OMNI\\adm-x"}, True),
    (r"user:*\\adm\-*", {"user": "adm-x"}, False),
    ('client_app:("Other clients" OR "IMAP4")', {"client_app": "Other clients"}, True),
    ("_exists_:src_ip", {"src_ip": "10.0.0.1"}, True),
    ("_exists_:src_ip", {"src_ip": ""}, False),
    ("age_days:>=7", {"age_days": 9}, True),
    ("age_days:>=7", {"age_days": 3}, False),
    ("http_status:[400 TO 499]", {"http_status": 404}, True),
    ("http_status:{400 TO 404}", {"http_status": 404}, False),
    ("event_id:4625", {"event_id": 4625}, True),
    ("src_ip_reserved_ip:true", {"src_ip_reserved_ip": True}, True),
    ('message:"is now off-line"', {"message": "Port 12 is now OFF-LINE"}, True),
    ("message:offline", {"message": "Port is now off-line"}, False),
    ("+a:1 b:2", {"a": "1"}, True),
    ("-a:1 b:2", {"b": "2", "a": "1"}, False),
    ("", {"x": 1}, True),
    ("*", {"x": 1}, True),
])
def test_semantique_requete(requete, doc, attendu):
    assert dv.correspond(dv.analyser(requete), doc) is attendu


@pytest.mark.parametrize("requete", ["(a:1", "a:1)", 'a:"x', "a:[1 TO", "a:1 AND", "a:"])
def test_requete_invalide(requete):
    with pytest.raises(dv.ErreurRequete):
        dv.analyser(requete)


def test_toutes_les_requetes_des_fixtures_sont_analysables():
    for fx in FIXTURES:
        dv.analyser(fx["definition"]["query"])


def test_champs_et_polarite():
    champs = dv.champs_requete(dv.analyser("a:1 AND NOT b:2 AND _exists_:c"))
    assert champs["a"] == {"positif": True, "negatif": False}
    assert champs["b"] == {"positif": False, "negatif": True}
    assert champs["c"]["positif"]


@pytest.mark.parametrize("requete,absents,attendu", [
    ("a:1 AND b:2", {"b"}, "non"),
    ("a:1 OR b:2", {"b"}, "peut-etre"),
    ("a:1 OR b:2", {"a", "b"}, "non"),
    ("a:1 AND NOT b:2", {"b"}, "peut-etre"),
])
def test_satisfiable(requete, absents, attendu):
    assert dv.satisfiable(dv.analyser(requete), absents) == attendu


# --------------------------------------------------------------- évaluateur
def _defn(**kw):
    base = {"query": "x:1", "streams": ["F"], "group_by": [],
            "series": [{"type": "count", "id": "count()", "field": None}],
            "conditions": {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"},
                                          "right": {"expr": "number", "value": 2.0}}},
            "search_within_ms": 600000, "execute_every_ms": 600000}
    base.update(kw)
    return base


def _docs(*champs, flux="F", age=10):
    return [dict(c, _flux=flux, _ts=MAINTENANT - age) for c in champs]


def test_seuil_regroupement_et_fenetre():
    d = _defn(group_by=["u"])
    docs = _docs({"x": "1", "u": "a"}, {"x": "1", "u": "a"}, {"x": "1", "u": "b"}, {"x": "1"})
    docs += [dict(x="1", u="b", _flux="F", _ts=MAINTENANT - 3600)]           # hors fenêtre
    res = dv.evaluer_definition(d, docs, MAINTENANT)
    assert [e["cle"] for e in res["evenements"]] == [["a"]]


def test_series_card_sum_et_condition_composee():
    d = _defn(group_by=["ip"], series=[{"type": "card", "id": "card(u)", "field": "u"},
                                       {"type": "sum", "id": "sum(n)", "field": "n"}],
              conditions={"expression": {"expr": "&&",
                                         "left": {"expr": ">=", "left": {"expr": "number-ref", "ref": "card(u)"},
                                                  "right": {"expr": "number", "value": 2}},
                                         "right": {"expr": ">", "left": {"expr": "number-ref", "ref": "sum(n)"},
                                                   "right": {"expr": "number", "value": 4}}}})
    docs = _docs({"x": "1", "ip": "1.1.1.1", "u": "a", "n": 2}, {"x": "1", "ip": "1.1.1.1", "u": "b", "n": 3},
                 {"x": "1", "ip": "2.2.2.2", "u": "a", "n": 9})
    res = dv.evaluer_definition(d, docs, MAINTENANT)
    assert [e["cle"] for e in res["evenements"]] == [["1.1.1.1"]]
    assert res["evenements"][0]["series"] == {"card(u)": 2.0, "sum(n)": 5.0}


def test_absence_sans_regroupement_declenche_sur_fenetre_vide():
    d = _defn(conditions={"expression": {"expr": "<", "left": {"expr": "number-ref", "ref": "count()"},
                                         "right": {"expr": "number", "value": 1}}})
    assert len(dv.evaluer_definition(d, [], MAINTENANT)["evenements"]) == 1
    assert dv.evaluer_definition(d, _docs({"x": "1"}), MAINTENANT)["evenements"] == []


def test_definition_sans_agregation_un_evenement_par_message():
    d = _defn(series=[], conditions={"expression": None})
    assert len(dv.evaluer_definition(d, _docs({"x": "1"}, {"x": "1"}, {"x": "2"}), MAINTENANT)["evenements"]) == 2


def test_flux_vide_vise_tous_les_flux():
    d = _defn(streams=[], series=[], conditions={"expression": None})
    assert len(dv.evaluer_definition(d, _docs({"x": "1"}, flux="Autre"), MAINTENANT)["evenements"]) == 1


# ----------------------------------------------------------------- fixtures
def test_bibliotheque_de_fixtures_complete():
    assert len(FIXTURES) >= 15
    for fx in FIXTURES:
        assert fx["titre"].startswith("OMNI")
        assert fx["justification"] and fx["mitre"]
        noms = [c["attendu"]["evenements"] > 0 for c in fx["cas"]]
        assert any(noms) and not all(noms), f"{fx['_fichier']} : il faut au moins un cas positif et un négatif"


@pytest.mark.parametrize("fx", FIXTURES, ids=[f["_fichier"] for f in FIXTURES])
def test_fixture_passe_hors_ligne(fx):
    res = dv.executer_fixtures([fx], None, MAINTENANT)[0]
    assert all(c["ok"] for c in res["cas"]), res["cas"]


@pytest.mark.parametrize("fx", FIXTURES, ids=[f["_fichier"] for f in FIXTURES])
def test_fixture_detecte_une_requete_cassee(fx):
    """Sensibilité : une requête qui ne peut plus correspondre doit faire échouer un cas
    (cas positif muet, ou, pour une détection d'absence, alerte permanente sur le cas négatif)."""
    casse = copy.deepcopy(fx)
    casse["definition"]["query"] = "alert_tag:__detection_cassee__"
    res = dv.executer_fixtures([casse], None, MAINTENANT)[0]
    assert not all(c["ok"] for c in res["cas"])


def _fx(debut):
    return next(f for f in FIXTURES if f["titre"].startswith(debut))


def test_fixture_detecte_la_perte_d_une_exclusion():
    fx = copy.deepcopy(_fx("OMNI - Accès mémoire LSASS"))
    fx["definition"]["query"] = "alert_tag:lsass_access"
    res = dv.executer_fixtures([fx], None, MAINTENANT)[0]
    assert [c["cas"] for c in res["cas"] if not c["ok"]] == [
        "accès légitime de l'agent NinjaOne (exclusion)", "WerFaultSecure (exclusion)"]


def test_fixture_detecte_un_seuil_modifie():
    fx = copy.deepcopy(_fx("OMNI - Force brute (>=10"))
    fx["definition"]["conditions"]["expression"]["right"]["value"] = 11.0
    res = dv.executer_fixtures([fx], None, MAINTENANT)[0]
    assert not res["cas"][0]["ok"]


def test_fixture_rejouee_sur_definition_de_production_et_ecart_signale():
    fx = _fx("OMNI - COMPTE CANARI")
    live = copy.deepcopy(fx["definition"])
    live["search_within_ms"] = 900000
    res = dv.executer_fixtures([fx], {fx["titre"]: live}, MAINTENANT)[0]
    assert res["source_definition"] == "production"
    assert res["ecarts_instantane"] == ["search_within_ms"]
    assert dv.executer_fixtures([fx], {}, MAINTENANT)[0]["absente"]


# ------------------------------------------------- faux Graylog / OpenSearch
class FauxOpenSearch:
    """Index en mémoire {préfixe: [docs]} ; docs avec `streams` (ids) et `_age_j`."""

    def __init__(self, index, refus=None, jetable=False, nom="test", url="http://opensearch-jetable:9200"):
        self.index, self.refus, self.appels = index, refus or {}, []
        self.url, self.jetable, self.nom, self.crees = url, jetable, nom, {}

    def _docs(self, motif):
        prefixes = [p[:-2] for p in motif.split(",")]
        return [d for p in prefixes for d in self.index.get(p, [])]

    def appel(self, methode, chemin, corps=None, ndjson=None, timeout=120):
        self.appels.append((methode, chemin))
        nu = chemin.split("?", 1)[0]
        if methode not in ("GET",) and not nu.endswith(("/_count", "/_search")) and not self.jetable:
            raise AssertionError(f"écriture interdite : {methode} {chemin}")
        if nu == "/":
            return {"cluster_name": self.nom}
        if nu == "/_cat/indices":
            return [{"index": p + "_0"} for p in self.index]
        motif = nu.split("/")[1]
        if "/_mapping/field/" in nu:
            demandes = set(nu.split("/_mapping/field/")[1].split(","))
            res = {}
            for p in [m[:-2] for m in motif.split(",")]:
                champs = {k for d in self.index.get(p, []) for k in d if not k.startswith("_")}
                res[p + "_0"] = {"mappings": {c: {} for c in champs & demandes}}
            return res
        if nu.endswith("/_validate/query"):
            q = corps["query"]["bool"]["must"][0].get("query_string", {}).get("query", "")
            if q in self.refus:
                return {"valid": False, "explanations": [{"error": self.refus[q]}]}
            return {"valid": True}
        if nu.endswith("/_count"):
            return {"count": len(self._filtrer(self._docs(motif), corps))}
        if nu.endswith("/_search") and "aggs" in corps:
            return {"aggregations": {"d": {"buckets": [{"key": "def-vivante", "doc_count": 4}]}}}
        raise AssertionError(f"appel inattendu {methode} {chemin}")

    @staticmethod
    def _filtrer(docs, corps):
        b = corps["query"].get("bool")
        if b is None:
            return docs
        q = b["must"][0].get("query_string", {}).get("query", "")
        arbre = dv.analyser(q)
        jours = None
        flux = None
        for f in b.get("filter", []):
            if "range" in f:
                jours = int(re.match(r"now-(\d+)d", f["range"]["timestamp"]["gte"]).group(1))
            if "terms" in f:
                flux = set(f["terms"]["streams"])
        return [d for d in docs if (jours is None or d.get("_age_j", 0) <= jours)
                and (flux is None or flux & set(d.get("streams", []))) and dv.correspond(arbre, d)]


S_WIN, S_OFF, S_VIDE = "a" * 24, "b" * 24, "c" * 24


def _definition(id_, titre, query, streams=(S_WIN,), prio=3, notifs=("n1",), **cfg):
    config = {"type": "aggregation-v1", "query": query, "query_parameters": [], "filters": [],
              "streams": list(streams), "group_by": [], "series": [{"type": "count", "id": "count()", "field": None}],
              "conditions": {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"},
                                            "right": {"expr": "number", "value": 1.0}}},
              "search_within_ms": 300000, "execute_every_ms": 300000, "use_cron_scheduling": False}
    config.update(cfg)
    return {"id": id_, "title": titre, "priority": prio, "state": "ENABLED", "config": config,
            "notifications": [{"notification_id": n} for n in notifs]}


def _inventaire(definitions, planif=None):
    maintenant = dt_iso(time.time() - 60)
    return {
        "definitions": definitions,
        "planificateur": planif if planif is not None else
        {d["id"]: {"status": "runnable", "is_scheduled": True, "triggered_at": maintenant} for d in definitions},
        "flux": [{"id": S_WIN, "title": "OMNI - Windows Security", "disabled": False, "index_set_id": "i1"},
                 {"id": S_OFF, "title": "OMNI - Off", "disabled": True, "index_set_id": "i1"},
                 {"id": S_VIDE, "title": "OMNI - Vide", "disabled": False, "index_set_id": "i3"}],
        "index_sets": [{"id": "i1", "index_prefix": "omni-winsec"}, {"id": "i3", "index_prefix": "omni-vide"},
                       {"id": "ev", "index_prefix": "gl-events", "index_template_type": "events"}],
        "notifications": [{"id": "n1", "title": "Mail"}],
        "regles": [{"title": "r-canary", "source": 'rule "r" when true then set_field("alert_tag", "canary"); end'},
                   {"title": "r-orpheline", "source": 'then set_field("alert_tag", "orpheline"); end'},
                   {"title": "r-zone", "source": 'then set_field("zone", lookup_value("t", "k")); end'}],
        "pipelines": [{"id": "p1", "stages": [{"rules": ["r-canary", "r-zone"]}]}],
        "connexions": [{"stream_id": S_WIN, "pipeline_ids": ["p1"]}],
    }


def dt_iso(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _index_win():
    return {"omni-winsec": [
        {"streams": [S_WIN], "alert_tag": "canary", "user": "u", "_age_j": 2},
        {"streams": [S_WIN], "event_id": "4625", "user": "u", "_age_j": 20},
        {"streams": [S_WIN], "event_action": "battement", "_age_j": 15},
        {"streams": [S_WIN], "event_id": "1", "_age_j": 1},
    ], "omni-vide": []}


def _valider(defs, index=None, planif=None, **kw):
    inv = _inventaire(defs, planif)
    kw.setdefault("exceptions", {})
    return dv.valider(inv, FauxOpenSearch(index if index is not None else _index_win()),
                      controles={"statique", "vivacite", "fixtures"}, fixtures=kw.pop("fixtures", []),
                      depot=None, **kw)


def _par_titre(res):
    return {r.titre: r for r in res["resultats"]}


def _defauts(r):
    return {(d.controle, d.gravite) for d in r.defauts}


def test_definition_saine_ok_et_vivante():
    res = _valider([_definition("def-vivante", "OMNI - Canari", "alert_tag:canary")])
    r = _par_titre(res)["OMNI - Canari"]
    assert r.statut == "OK", r.defauts
    assert r.vivacite["etat"] == "vivante"
    assert r.vivacite["evenements_fenetre"] == 4


def test_vivacite_rare_muette_source_absente_et_battement():
    absence = {"expression": {"expr": "<", "left": {"expr": "number-ref", "ref": "count()"},
                              "right": {"expr": "number", "value": 1.0}}}
    res = _valider([
        _definition("d1", "OMNI - Rare", "event_id:4625"),
        _definition("d2", "OMNI - Muette", "event_id:4625 AND user:personne"),
        _definition("d3", "OMNI - Battement", "event_action:battement", conditions=absence,
                    search_within_ms=93600000, execute_every_ms=93600000),
        _definition("d4", "OMNI - Aveugle", "event_id:1", streams=(S_VIDE,)),
    ])
    p = _par_titre(res)
    assert p["OMNI - Rare"].vivacite["etat"] == "rare"
    assert p["OMNI - Muette"].vivacite["etat"] == "muette"
    assert p["OMNI - Muette"].statut == "OK"                          # une attaque rare peut ne rien voir
    assert p["OMNI - Battement"].vivacite["etat"] == "battement_absent"
    assert ("vivacite", "elevee") in _defauts(p["OMNI - Battement"])
    assert p["OMNI - Aveugle"].vivacite["etat"] == "source_absente"
    assert ("flux", "elevee") in _defauts(p["OMNI - Aveugle"])
    assert res["resume"]["mortes"] == 3


def test_flux_inexistant_desactive_et_notification_manquante():
    res = _valider([
        _definition("d1", "OMNI - Flux inexistant", "alert_tag:canary", streams=("f" * 24,)),
        _definition("d2", "OMNI - Flux off", "alert_tag:canary", streams=(S_OFF,)),
        _definition("d3", "OMNI - Notif fantome", "alert_tag:canary", notifs=("zzz",)),
        _definition("d4", "OMNI - Sans notif", "alert_tag:canary", notifs=()),
        _definition("d5", "OMNI - Sans notif P1", "alert_tag:canary", notifs=(), prio=1),
    ])
    p = _par_titre(res)
    assert p["OMNI - Flux inexistant"].statut == "CASSEE"
    assert p["OMNI - Flux inexistant"].vivacite["etat"] == "non_mesuree"
    assert p["OMNI - Flux off"].statut == "CASSEE"
    assert ("notifications", "critique") in _defauts(p["OMNI - Notif fantome"])
    assert ("notifications", "elevee") in _defauts(p["OMNI - Sans notif"])
    assert ("notifications", "moyenne") in _defauts(p["OMNI - Sans notif P1"])


def test_planification_incoherente_et_planificateur_bloque():
    defs = [_definition("d1", "OMNI - Trou", "alert_tag:canary", search_within_ms=60000, execute_every_ms=300000),
            _definition("d2", "OMNI - Bloquee", "alert_tag:canary"),
            _definition("d3", "OMNI - En retard", "alert_tag:canary"),
            _definition("d4", "OMNI - Non planifiee", "alert_tag:canary")]
    planif = {"d1": {"status": "runnable", "triggered_at": dt_iso(time.time())},
              "d2": {"status": "error", "triggered_at": dt_iso(time.time())},
              "d3": {"status": "runnable", "triggered_at": dt_iso(time.time() - 86400)}}
    p = _par_titre(_valider(defs, planif=planif))
    assert ("planification", "elevee") in _defauts(p["OMNI - Trou"])
    assert p["OMNI - Bloquee"].statut == "CASSEE"
    assert any("dernière exécution" in d.constat for d in p["OMNI - En retard"].defauts)
    assert any("aucune tâche planifiée" in d.constat for d in p["OMNI - Non planifiee"].defauts)


def test_champs_absents_critique_sans_producteur_elevee_avec_regle():
    res = _valider([
        _definition("d1", "OMNI - Champ inconnu", "alert_tag:canary AND champ_fantome:x"),
        _definition("d2", "OMNI - Champ de lookup", "alert_tag:canary AND zone:*", group_by=["zone"]),
        _definition("d3", "OMNI - Branche morte", "alert_tag:canary OR champ_fantome:x"),
        _definition("d4", "OMNI - Exclusion", "alert_tag:canary AND NOT champ_fantome:x"),
        _definition("d5", "OMNI - Serie", "alert_tag:canary",
                    series=[{"type": "sum", "id": "sum(fantome)", "field": "fantome"}],
                    conditions={"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "sum(fantome)"},
                                               "right": {"expr": "number", "value": 1.0}}}),
    ])
    p = _par_titre(res)
    assert p["OMNI - Champ inconnu"].statut == "CASSEE"
    assert ("champs", "elevee") in _defauts(p["OMNI - Champ de lookup"])
    assert p["OMNI - Champ de lookup"].statut == "DEFAUT"
    assert any("r-zone" in d.constat for d in p["OMNI - Champ de lookup"].defauts)
    assert ("champs", "elevee") in _defauts(p["OMNI - Branche morte"])
    assert ("champs", "faible") in _defauts(p["OMNI - Exclusion"])
    assert p["OMNI - Exclusion"].statut == "OK"
    assert p["OMNI - Serie"].statut == "CASSEE"


def test_requete_refusee_par_opensearch_et_non_analysable():
    inv = _inventaire([_definition("d1", "OMNI - Refusee", "alert_tag:canary AND user:/[/"),
                       _definition("d2", "OMNI - Syntaxe", "alert_tag:(canary")])
    faux = FauxOpenSearch(_index_win(), refus={"alert_tag:canary AND user:/[/": "regex invalide"})
    faux._filtrer = lambda docs, corps: []
    res = dv.valider(inv, faux, controles={"statique"}, fixtures=[], exceptions={}, depot=None)
    p = _par_titre(res)
    assert any("refusée par OpenSearch" in d.constat for d in p["OMNI - Refusee"].defauts)
    assert p["OMNI - Syntaxe"].statut == "CASSEE"


def test_producteur_absent_ou_regle_non_connectee():
    p = _par_titre(_valider([
        _definition("d1", "OMNI - Orpheline", "alert_tag:orpheline"),
        _definition("d2", "OMNI - Introuvable", "alert_tag:inconnue"),
    ], index={"omni-winsec": [{"streams": [S_WIN], "alert_tag": "x", "_age_j": 1}]}))
    assert ("producteur", "elevee") in _defauts(p["OMNI - Orpheline"])
    assert ("producteur", "moyenne") in _defauts(p["OMNI - Introuvable"])


def test_doublon_de_titre_et_exception_documentee():
    defs = [_definition("d1", "OMNI - Double", "alert_tag:canary"),
            _definition("d2", "OMNI - Double", "alert_tag:canary"),
            _definition("d3", "OMNI - Chasse", "alert_tag:canary", notifs=())]
    res = _valider(defs, exceptions={"OMNI - Chasse": {"ignorer": ["notifications"], "motif": "base de chasse"}})
    lots = [r for r in res["resultats"] if r.titre == "OMNI - Double"]
    assert all(("inventaire", "moyenne") in _defauts(r) for r in lots)
    chasse = _par_titre(res)["OMNI - Chasse"]
    assert chasse.statut == "OK"
    assert any(d.controle == "exception" for d in chasse.defauts)


def test_fixture_en_echec_sur_la_production_rend_la_definition_cassee():
    fx = copy.deepcopy(_fx("OMNI - COMPTE CANARI"))
    fx["definition"]["streams"] = ["OMNI - Windows Security"]
    live = _definition("d1", fx["titre"], "alert_tag:canari_renomme", prio=2)
    res = _valider([live], fixtures=[fx])
    r = _par_titre(res)[fx["titre"]]
    assert r.critique and r.statut == "CASSEE"
    assert res["resume"]["cassees_critiques"] == 1
    assert res["resume"]["fixtures"]["echec"] == 1


def test_definitions_hors_perimetre_et_inactives():
    inactive = _definition("d2", "OMNI - Inactive", "alert_tag:canary")
    inactive["state"] = "DISABLED"
    systeme = {"id": "s", "title": "System notification events", "state": "ENABLED",
               "config": {"type": "system-notifications-v1"}}
    res = _valider([_definition("d1", "OMNI - Canari", "alert_tag:canary"), inactive, systeme])
    assert res["resume"]["definitions_actives_controlees"] == 1
    assert [h["titre"] for h in res["hors_perimetre"]] == ["System notification events"]


def test_tri_les_plus_graves_en_tete():
    res = _valider([_definition("d1", "OMNI - A saine", "alert_tag:canary"),
                    _definition("d2", "OMNI - B cassee", "alert_tag:canary", streams=("f" * 24,), prio=1),
                    _definition("d3", "OMNI - C defaut", "alert_tag:canary", notifs=())])
    assert [r.statut for r in res["resultats"]] == ["CASSEE", "DEFAUT", "OK"]


# --------------------------------------------------------- traduction / sorties
def test_traduction_query_string():
    corps = dv.corps_requete("alert_tag:canary", [S_WIN], "now-30d")
    qs = corps["query"]["bool"]["must"][0]["query_string"]
    assert qs == {"query": "alert_tag:canary", "allow_leading_wildcard": True, "analyze_wildcard": True}
    assert {"terms": {"streams": [S_WIN]}} in corps["query"]["bool"]["filter"]
    assert dv.corps_requete("", [], "now-1d")["query"]["bool"]["must"] == [{"match_all": {}}]


def test_main_ecrit_les_rapports_dates_et_code_retour(tmp_path, capsys):
    inv = _inventaire([_definition("d1", "OMNI - Cassee", "alert_tag:canary", streams=("f" * 24,))])
    reponses = {"/events/definitions?per_page=100&page=1": {"event_definitions": inv["definitions"], "total": 1,
                                                            "context": {"scheduler": inv["planificateur"]}},
                "/events/notifications?per_page=500&page=1": {"notifications": inv["notifications"]},
                "/streams": {"streams": inv["flux"]},
                "/system/indices/index_sets?skip=0&limit=500": {"index_sets": inv["index_sets"]},
                "/system/pipelines/rule": inv["regles"], "/system/pipelines/pipeline": inv["pipelines"],
                "/system/pipelines/connections": inv["connexions"]}
    code = dv.main(["--sortie", str(tmp_path / "rapports"), "--fixtures", str(tmp_path / "aucune"),
                    "--depot", str(tmp_path)], gl_get=reponses.__getitem__, os_client=FauxOpenSearch(_index_win()))
    assert code == 2
    fichiers = sorted(p.name for p in (tmp_path / "rapports").iterdir())
    assert any(re.fullmatch(r"validation-detections-\d{8}-\d{4}\.json", f) for f in fichiers)
    assert "dernier.md" in fichiers
    doc = json.loads((tmp_path / "rapports" / "dernier.json").read_text())
    assert doc["resume"]["cassees_critiques"] == 1
    assert "Les 15 plus graves" in capsys.readouterr().out


def test_main_api_injoignable_code_3(tmp_path):
    def panne(_):
        raise OSError("connexion refusée")
    assert dv.main(["--fixtures", str(tmp_path)], gl_get=panne, os_client=FauxOpenSearch({})) == 3


def test_main_hors_ligne_sans_reseau(capsys):
    assert dv.main(["--hors-ligne"]) == 0
    assert "0 échec(s)" in capsys.readouterr().out


# ------------------------------------------------------------ garde-fous
@pytest.mark.parametrize("methode,chemin", [("PUT", "/x"), ("DELETE", "/omni-winsec_1"), ("POST", "/_bulk"),
                                            ("POST", "/x/_delete_by_query")])
def test_client_opensearch_refuse_les_ecritures(methode, chemin):
    with pytest.raises(PermissionError):
        dv.ClientOpenSearch("http://127.0.0.1:1").appel(methode, chemin, {})


@pytest.mark.parametrize("url,nom,index,motif", [
    ("http://127.0.0.1:9200", "test", {}, "boucle locale"),
    ("http://localhost:9200", "test", {}, "boucle locale"),
    ("http://os-jetable:9200", "graylog", {}, "graylog"),
    ("http://os-jetable:9200", "test", {"omni-winsec": []}, "index Graylog"),
])
def test_replay_refuse_la_production(url, nom, index, motif):
    faux = FauxOpenSearch(index, jetable=True, nom=nom, url=url)
    with pytest.raises(PermissionError, match=motif):
        dv.replay(FIXTURES[:1], faux)


def test_main_replay_exige_la_confirmation(capsys):
    assert dv.main(["--replay", "http://os-jetable:9200"]) == 3


def test_replay_compare_evaluateur_et_opensearch():
    """Le faux OpenSearch jetable répond avec l'évaluateur : aucun écart attendu, index supprimé."""
    class Jetable(FauxOpenSearch):
        def appel(self, methode, chemin, corps=None, ndjson=None, timeout=120):
            nu = chemin.split("?", 1)[0]
            if methode == "PUT":
                self.crees[nu.strip("/")] = []
                return {"acknowledged": True}
            if nu == "/_bulk":
                lignes = [json.loads(x) for x in ndjson.splitlines() if x]
                for meta, doc in zip(lignes[::2], lignes[1::2]):
                    self.crees[meta["index"]["_index"]].append((meta["index"]["_id"], doc))
                return {"errors": False}
            if methode == "DELETE":
                self.crees.pop(nu.strip("/"))
                return {"acknowledged": True}
            if nu.endswith("/_search"):
                index = nu.split("/")[1]
                b = corps["query"]["bool"]
                q = b["must"][0].get("query_string", {}).get("query", "")
                flux = next((set(f["terms"]["streams"]) for f in b["filter"] if "terms" in f), None)
                depuis = next(f["range"]["timestamp"]["gte"] for f in b["filter"] if "range" in f)
                hits = [{"_id": i} for i, d in self.crees[index]
                        if d["timestamp"] >= depuis and (flux is None or flux & set(d["streams"]))
                        and dv.correspond(dv.analyser(q), d)]
                return {"hits": {"hits": hits}}
            return super().appel(methode, chemin, corps, ndjson, timeout)

    faux = Jetable({}, jetable=True)
    res = dv.replay(FIXTURES, faux, maintenant=MAINTENANT, journal=lambda *_: None)
    assert res and all(x["ok"] for x in res), [x for x in res if not x["ok"]]
    assert faux.crees == {}
