"""Indicateurs SOC (tools/omni-soc-kpi.py et GET /m/api/soc-kpi), hors ligne, données simulées.

Aucun test ne joint OpenSearch, Graylog ni /var/lib : la recherche est simulée en mémoire ou
par un serveur HTTP local éphémère, et les fichiers d'état sont créés dans tmp_path.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import re
import threading
import urllib.error
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "omni-soc-kpi.py"
SOC = ROOT / "mobile" / "soc"
NOW = dt.datetime(2026, 11, 22, 12, 0, tzinfo=dt.timezone.utc)


def _load_tool():
    spec = importlib.util.spec_from_file_location("omni_soc_kpi_test", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kpi = _load_tool()


def gts(d):
    """Horodatage au format Graylog/OpenSearch (UTC, sans décalage)."""
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.") + f"{d.microsecond // 1000:03d}"


T0 = NOW - dt.timedelta(days=2)
EVENTS = [
    # unitaire : source 10:00:00, alerte créée 10:05:00 -> 300 s
    {"id": "e1", "timestamp": gts(T0), "timestamp_processing": gts(T0 + dt.timedelta(seconds=300)),
     "timerange_start": None, "timerange_end": None, "priority": 3, "event_definition_id": "d1"},
    # unitaire : 60 s
    {"id": "e2", "timestamp": gts(T0), "timestamp_processing": gts(T0 + dt.timedelta(seconds=60)),
     "timerange_start": None, "timerange_end": None, "priority": 2, "event_definition_id": "d1"},
    # agrégation : fenêtre de 600 s, traitement 10 s après la fin -> bornes 10 s et 610 s
    {"id": "e3", "timestamp": gts(T0 + dt.timedelta(seconds=600)),
     "timestamp_processing": gts(T0 + dt.timedelta(seconds=610)), "timerange_start": gts(T0),
     "timerange_end": gts(T0 + dt.timedelta(seconds=600)), "priority": 2, "event_definition_id": "d2"},
    # dérive d'horloge : délai négatif, exclu
    {"id": "e4", "timestamp": gts(T0 + dt.timedelta(seconds=100)), "timestamp_processing": gts(T0),
     "timerange_start": None, "timerange_end": None, "priority": 1, "event_definition_id": "d2"},
]
INC_TS = NOW - dt.timedelta(days=1)
BLOCK_TS = NOW - dt.timedelta(hours=5)
DEFINITIONS = [
    {"id": "d1", "title": "OMNI - LSASS", "state": "ENABLED", "description": "",
     "config": {"query": "alert_tag:lsass_access"}},
    {"id": "d2", "title": "OMNI - Kerberoast (T1558.003)", "state": "ENABLED", "description": "",
     "config": {"query": "alert_tag:(kerberoasting OR \"dcsync\") AND NOT alert_tag:ignored"}},
    {"id": "d3", "title": "OMNI - Sauvegarde", "state": "ENABLED", "config": {"query": "health_job:backup"}},
    {"id": "d4", "title": "OMNI - Ancienne", "state": "DISABLED", "config": {"query": "alert_tag:sysmon_injection"}},
]
MITRE_CSV = ("alert_tag,technique,technique_name,tactic,severity,score\n"
             "lsass_access,T1003.001,LSASS Memory,Credential Access,critique,10\n"
             "dcsync,T1003.006,DCSync,Credential Access,critique,10\n"
             "kerberoasting,T1558.003,Kerberoasting,Credential Access,eleve,8\n"
             "sysmon_injection,T1055,Process Injection,Defense Evasion,moyen,5\n")


class FakeSearch:
    """Simule les réponses _search utilisées par l'outil ; mémorise les appels."""

    def __init__(self):
        self.calls = []

    @staticmethod
    def _filters(body):
        return (body.get("query") or {}).get("bool", {}).get("filter", [])

    def _term(self, body, field):
        for f in self._filters(body):
            if "term" in f and field in f["term"]:
                return f["term"][field]
        return None

    def __call__(self, index, body):
        self.calls.append((index, json.loads(json.dumps(body))))
        res = self._answer(index, body)
        if body.get("track_total_hits") is False:      # comme OpenSearch : pas de total demandé
            res["hits"].pop("total", None)
        return res

    def _answer(self, index, body):
        ok = {"timed_out": False, "_shards": {"failed": 0}}
        if index.startswith("gl-system-events"):
            return {**ok, "hits": {"total": {"value": 2}, "hits": [
                {"_source": {"message": "SEARCH_ERROR: Aggregation search failed"}},
                {"_source": {"message": "SEARCH_ERROR: autre"}}]}}
        if index.startswith("gl-events"):
            if "aggs" in body:
                return {**ok, "hits": {"total": {"value": 4}, "hits": []}, "aggregations": {
                    "sev": {"buckets": [{"key": 2, "doc_count": 2}, {"key": 3, "doc_count": 1}, {"key": 1, "doc_count": 1}]},
                    "src": {"buckets": [{"key": "s1", "doc_count": 4}]},
                    "det": {"buckets": [
                        {"key": "d1", "doc_count": 2, "ex": {"hits": {"hits": [{"_source": {"message": "x"}}]}}},
                        {"key": "d9", "doc_count": 2, "ex": {"hits": {"hits": [
                            {"_source": {"message": "OMNI - Inconnue: alice - count()=3.0", "key": "alice"}}]}}}]},
                    "tech": {"buckets": [{"key": "T1003.001", "doc_count": 2}]},
                    "jour": {"buckets": [{"key": 1795219200000, "doc_count": 4}]}}}
            if self._term(body, "alert") is False:
                return {**ok, "hits": {"total": {"value": 7}, "hits": []}}
            if any("terms" in f and "key" in f["terms"] for f in self._filters(body)):
                hits = [{"_source": {"key": "203.0.113.9", "timestamp_processing": gts(BLOCK_TS - dt.timedelta(seconds=40))},
                         "sort": [1]},
                        {"_source": {"key": "203.0.113.9", "timestamp_processing": gts(BLOCK_TS + dt.timedelta(seconds=40))},
                         "sort": [2]}]
                return {**ok, "hits": {"total": {"value": 2}, "hits": hits}}
            # pagination MTTD : une page de 2 puis le reste
            start = 0 if "search_after" not in body else body["search_after"][0]
            page = EVENTS[start:start + body["size"]]
            return {**ok, "hits": {"total": {"value": len(EVENTS)}, "hits": [
                {"_source": e, "sort": [start + i + 1]} for i, e in enumerate(page)]}}
        src = self._term(body, "event_source")
        if src == "xdr_incident":
            if body.get("size"):
                return {**ok, "hits": {"total": {"value": 3}, "hits": [
                    {"_id": "case-a", "_source": {"timestamp": gts(INC_TS), "severity": "high"}},
                    {"_id": "case-b", "_source": {"timestamp": gts(INC_TS), "severity": "low"}},
                    {"_id": "sans-dossier", "_source": {"timestamp": gts(INC_TS)}}]}}
            return {**ok, "hits": {"total": {"value": 3}, "hits": []}}
        if src == "siem_soar":
            if "aggs" in body:
                return {**ok, "hits": {"total": {"value": 3}, "hits": []}, "aggregations": {"act": {"buckets": [
                    {"key": "ip_bloquee", "doc_count": 2}, {"key": "simulation", "doc_count": 1}]}}}
            return {**ok, "hits": {"total": {"value": 2}, "hits": [
                {"_source": {"timestamp": gts(BLOCK_TS), "soar_ip": "203.0.113.9"}},
                {"_source": {"timestamp": gts(BLOCK_TS), "soar_ip": "198.51.100.7"}}]}}
        if src == "alert_triage":
            return {**ok, "hits": {"total": {"value": 10}, "hits": []}, "aggregations": {
                "dec": {"buckets": [
                    {"key": "drop", "doc_count": 7, "r": {"buckets": [
                        {"key": "noise(score=20)", "doc_count": 4}, {"key": "fp_soc(analyste)", "doc_count": 1},
                        {"key": "fp_connu", "doc_count": 1}, {"key": "llm:pas pertinent", "doc_count": 1}]}},
                    {"key": "mail", "doc_count": 2, "r": {"buckets": [
                        {"key": "critical", "doc_count": 1}, {"key": "llm_erreur:HTTPError|gray_default=mail", "doc_count": 1}]}},
                    {"key": "fp_add", "doc_count": 1, "r": {"buckets": [{"key": "soc_fp par x", "doc_count": 1}]}}]},
                "tier": {"buckets": [{"key": "NOISE", "doc_count": 4}]}}}
        raise AssertionError(f"requête inattendue : {index} {body}")


@pytest.fixture
def state(tmp_path):
    mitre = tmp_path / "mitre.csv"
    mitre.write_text(MITRE_CSV, encoding="utf-8")
    cases = tmp_path / "cases.json"
    local = (INC_TS + dt.timedelta(minutes=30)).astimezone(kpi._tz("Europe/Paris")).replace(tzinfo=None)
    cases.write_text(json.dumps({
        # dossier ancien : note en heure locale sans décalage, clos sans horodatage
        "case-a": {"status": "closed", "disposition": "false_positive",
                   "notes": [{"by": "agent SOC v3", "ts": local.isoformat(timespec="seconds"), "text": "lot"}]},
        # dossier récent : historique daté avec décalage, clôture 2 h après l'incident
        "case-b": {"status": "closed", "disposition": "true_positive", "notes": [],
                   "history": [{"ts": (INC_TS + dt.timedelta(minutes=10)).isoformat(), "by": "jdupont",
                                "action": "status", "value": "in_progress"},
                               {"ts": (INC_TS + dt.timedelta(hours=2)).isoformat(), "by": "jdupont",
                                "action": "disposition", "value": "true_positive"}],
                   "closed_ts": (INC_TS + dt.timedelta(hours=2)).isoformat()},
        "hors-periode": {"status": "new", "notes": []}}), encoding="utf-8")
    admin = tmp_path / "admin"
    admin.mkdir()
    (admin / "audit.jsonl").write_text(
        json.dumps({"ts": (NOW - dt.timedelta(days=1)).isoformat(), "event": "execution", "action": "fp_add"}) + "\n"
        + json.dumps({"ts": (NOW - dt.timedelta(days=90)).isoformat(), "event": "execution", "action": "fp_add"}) + "\n"
        + "ligne illisible\n", encoding="utf-8")
    return {"mitre": str(mitre), "cases": str(cases), "admin": str(admin)}


def run(state, **kw):
    fake = FakeSearch()
    args = dict(days=30, now=NOW, cases_file=state["cases"], admin_dir=state["admin"], mitre_csv=state["mitre"],
                definitions={"event_definitions": DEFINITIONS}, streams={"streams": [{"id": "s1", "title": "OMNI - Sysmon"}]})
    args.update(kw)
    return kpi.compute(fake, **args), fake


# ------------------------------------------------------------------ fonctions pures
def test_stats_median_p90_and_empty():
    s = kpi.stats(range(1, 11))
    assert s == {"n": 10, "moyenne": 5.5, "mediane": 5.5, "p90": 9.1, "min": 1.0, "max": 10.0}
    assert kpi.stats([])["mediane"] is None and kpi.stats([])["n"] == 0
    assert kpi.stats([42])["p90"] == 42.0


def test_parse_ts_formats_and_naive_local_time():
    paris = kpi._tz("Europe/Paris")
    assert kpi.parse_ts("2026-11-22 16:55:16.105").isoformat() == "2026-11-22T16:55:16.105000+00:00"
    assert kpi.parse_ts("2026-11-22T12:55:07+0100").hour == 11
    assert kpi.parse_ts("2026-11-22T12:00:00Z").hour == 12
    assert kpi.parse_ts("2026-11-11T21:04:12", paris).hour == 20      # CET = UTC+1
    assert kpi.parse_ts("2026-07-11T21:04:12", paris).hour == 19      # CEST = UTC+2
    assert kpi.parse_ts(1795219200000).year == 2026
    assert kpi.parse_ts("illisible") is None and kpi.parse_ts(None) is None


def test_title_tags_and_triage_classes():
    assert kpi.title_from_message("OMNI - Force brute: jmorin - count()=32.0", "jmorin") == "OMNI - Force brute"
    assert kpi.title_from_message("OMNI - Tentative sur compte désactivé") == "OMNI - Tentative sur compte désactivé"
    assert kpi.extract_alert_tags('alert_tag:(a OR "b") AND NOT alert_tag:c OR alert_tag:d AND alert_tag:*') == {"a", "b", "d"}
    assert kpi.classify_triage("drop", "fp_soc(x)") == "faux_positif_regle"
    assert kpi.classify_triage("drop", "fp_connu") == "faux_positif_regle"
    assert kpi.classify_triage("drop", "llm:non") == "rejet_juge_llm"
    assert kpi.classify_triage("drop", "noise(score=20)") == "bruit_sous_seuil"
    assert kpi.classify_triage("mail", "critical") == "transmis_ou_regroupe"


def test_mttd_unit_exact_aggregation_bounded_negative_excluded():
    unit, lo, hi, neg, per_sev, _ = kpi.mttd_from_events(EVENTS)
    assert sorted(unit) == [60.0, 300.0] and lo == [10.0] and hi == [610.0] and neg == 1
    assert per_sev[2] == ([60.0, 10.0], [60.0, 610.0])


def test_window_bounds_and_validation():
    w = kpi.make_window(days=7, now=NOW)
    assert (w.until - w.since).days == 7
    assert kpi.make_window(since="2026-11-01T00:00:00Z", until="2026-11-02T00:00:00Z").as_dict()["jours"] == 1.0
    with pytest.raises(kpi.KpiError):
        kpi.make_window(days=0, now=NOW)
    with pytest.raises(kpi.KpiError):
        kpi.make_window(since="2026-11-03T00:00:00Z", until="2026-11-02T00:00:00Z")


# ------------------------------------------------------------------ calcul complet
def test_compute_full_report_on_simulated_data(state):
    r, fake = run(state)
    a = r["alertes"]
    assert a["total"] == 4 and a["evenements_non_alertes"] == 7
    assert [x["libelle"] for x in a["par_severite"]] == ["élevée", "moyenne", "faible"]
    assert a["par_source"][0]["titre"] == "OMNI - Sysmon"
    titles = {d["id"]: d["titre"] for d in a["par_detection"]}
    assert titles == {"d1": "OMNI - LSASS", "d9": "OMNI - Inconnue"}     # API puis repli sur le message
    m = r["mttd"]
    assert m["alertes_analysees"] == 4 and m["delais_negatifs_exclus"] == 1 and not m["tronque"]
    assert m["unitaires"]["mediane"] == 180.0 and m["agregations_borne_haute"]["mediane"] == 610.0
    assert m["global_borne_basse"]["n"] == 3 and m["evenements_systeme"]["par_type_echantillon"] == {"SEARCH_ERROR": 2}
    d = r["mttr"]["dossiers"]
    assert d["incidents_xdr_periode"] == 3 and d["dossiers_periode"] == 2 and d["dossiers_fichier"] == 3
    assert d["prise_en_charge"]["n"] == 2 and d["prise_en_charge"]["min"] == 600.0 and d["prise_en_charge"]["max"] == 1800.0
    assert d["prise_en_charge_humaine"] == kpi.stats([600.0])                 # auteur « agent ... » exclu
    assert d["cloture"] == kpi.stats([7200.0]) and d["clotures_sans_horodatage"] == 1
    assert d["par_qualification"] == {"false_positive": 1, "true_positive": 1}
    assert d["part_faux_positifs_analyste"] == 50.0
    s = r["mttr"]["soar"]
    assert s["actions"] == {"ip_bloquee": 2, "simulation": 1}
    assert s["delai_alerte_blocage"] == kpi.stats([40.0]) and s["blocages_sans_alerte_associee"] == 1
    au = r["mttr"]["journal_audit"]
    assert au["disponible"] and au["entrees_periode"] == 1 and au["par_action"] == {"execution:fp_add": 1}
    t = r["triage"]
    assert t["decisions_total"] == 9 and t["faux_positifs"] == 2 and t["part_faux_positifs"] == 22.2
    assert t["rejets_juge_llm"] == 1 and t["regles_fp_creees"] == 1 and t["juge_llm_indisponible"] == 1
    c = r["couverture"]
    assert c["disponible"] and c["definitions_actives"] == 3 and c["definitions_desactivees"] == 1
    assert {x["technique"] for x in c["techniques"]} == {"T1003.001", "T1003.006", "T1558.003"}
    assert c["declarees_sans_definition_active"] == ["T1055"]
    assert c["techniques_actives_avec_alerte"] == 1 and c["definitions_actives_sans_alerte_periode"] == 2
    assert c["techniques_observees_alertes"] == ["T1003.001"]
    assert any("Acquittement" in g for g in r["lacunes"]) and any("Clôture" in g for g in r["lacunes"])
    # lecture seule : uniquement des requêtes de recherche, jamais d'index système de Graylog hors gl-*
    assert {i for i, _ in fake.calls} <= {"gl-events*", "gl-system-events*", "omni-*"}


def test_missing_state_and_graylog_are_reported_not_invented(state, tmp_path):
    r, _ = run(state, cases_file=str(tmp_path / "absent.json"), admin_dir=str(tmp_path / "absent"),
               definitions=None, streams=None)
    assert r["mttr"]["dossiers"]["fichier_lu"] is False and r["mttr"]["dossiers"]["dossiers_periode"] == 0
    assert r["mttr"]["journal_audit"]["disponible"] is False
    assert r["couverture"]["disponible"] is False and "définitions" in r["couverture"]["raison"]
    assert any("Journal d'audit" in g for g in r["lacunes"])
    assert any("Couverture ATT&CK active" in g for g in r["lacunes"])


def test_graylog_api_failure_is_a_warning_and_api_is_get_only(state):
    seen = []

    def boom(path):
        seen.append(path)
        raise OSError("panne simulée")
    r, _ = run(state, definitions=None, streams=None, graylog_get=boom)
    assert seen == ["/events/definitions?per_page=100&page=1"]
    assert r["couverture"]["disponible"] is False and r["avertissements"]

    pages = {1: {"total": 3, "event_definitions": DEFINITIONS[:2]}, 2: {"total": 3, "event_definitions": DEFINITIONS[2:3]}}

    def ok(path):
        if path.startswith("/events/definitions"):
            return pages[int(path.rsplit("=", 1)[1])]
        return {"streams": [{"id": "s1", "title": "Flux"}]}
    r, _ = run(state, definitions=None, streams=None, graylog_get=ok)
    assert r["couverture"]["definitions_actives"] == 3 and r["sources"]["graylog"] == "api"
    assert r["alertes"]["par_source"][0]["titre"] == "Flux"


def test_search_failure_is_never_reported_as_zero(state):
    def failing(index, body):
        return {"hits": {"total": {"value": 0}, "hits": []}, "timed_out": True}
    with pytest.raises(kpi.KpiError):
        kpi.compute(failing, days=30, now=NOW, cases_file=state["cases"], admin_dir=state["admin"],
                    mitre_csv=state["mitre"])

    def no_aggs(index, body):
        return {"hits": {"total": {"value": 0}, "hits": []}}
    with pytest.raises(kpi.KpiError):
        kpi.compute(no_aggs, days=30, now=NOW, cases_file=None, admin_dir=None, mitre_csv=state["mitre"])


def test_markdown_rendering_has_all_sections_and_no_emoji(state):
    r, _ = run(state)
    md = kpi.to_markdown(r)
    for title in ("## Volume d'alertes", "## MTTD", "## MTTR", "## Faux positifs", "## Couverture ATT&CK",
                  "## Lacunes de données", "Médiane", "p90"):
        assert title in md
    assert "3,0 min" in md                      # médiane des unitaires (180 s)
    assert not re.search("[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]", md)
    json.dumps(r)                               # sérialisable tel quel


# ------------------------------------------------------------------ ligne de commande
@contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        th.join()


def test_cli_uses_only_search_posts_and_writes_requested_outputs(state, tmp_path, monkeypatch, capsys):
    fake = FakeSearch()
    seen = []

    class OS(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            seen.append(("POST", self.path))
            index = urllib.request.unquote(self.path.split("/")[1])
            out = json.dumps(fake(index, body)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

        def do_GET(self):
            seen.append(("GET", self.path))
            self.send_response(405)
            self.end_headers()

        def log_message(self, *a):
            pass
    defs = tmp_path / "defs.json"
    defs.write_text(json.dumps({"event_definitions": DEFINITIONS}), encoding="utf-8")
    with serve(OS) as base:
        rc = kpi.main(["--opensearch", base, "--days", "30", "--cases-file", state["cases"],
                       "--admin-dir", state["admin"], "--mitre-csv", state["mitre"],
                       "--graylog-definitions", str(defs), "--format", "json",
                       "--json-out", str(tmp_path / "k.json"), "--md-out", str(tmp_path / "k.md")])
    assert rc == 0
    assert seen and all(m == "POST" and p.endswith("/_search") for m, p in seen)
    out = json.loads(capsys.readouterr().out)
    assert out["couverture"]["definitions_actives"] == 3
    assert json.loads((tmp_path / "k.json").read_text())["alertes"]["total"] == out["alertes"]["total"]
    assert (tmp_path / "k.md").read_text().startswith("# Indicateurs SOC")


def test_cli_refuses_production_paths_in_test_mode(capsys):
    assert kpi.main(["--opensearch", "http://127.0.0.1:9", "--cases-file", "/var/lib/omni-mobile/cases.json"]) == 2
    assert "chemin de production refusé" in capsys.readouterr().err


def test_cli_reports_unreachable_search_with_error_code(state, capsys):
    rc = kpi.main(["--opensearch", "http://127.0.0.1:9", "--cases-file", state["cases"],
                   "--admin-dir", state["admin"], "--mitre-csv", state["mitre"]])
    assert rc == 2 and "OpenSearch injoignable" in capsys.readouterr().err


# ------------------------------------------------------------------ backend de la console
def _get(base, path, user):
    req = urllib.request.Request(base + path, headers={"Cookie": "oms_session=" + user})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def _prepare_api(api, state, monkeypatch, tmp_path, patch_search=True):
    fake = FakeSearch()
    if patch_search:
        monkeypatch.setattr(api, "os_search", fake)
    monkeypatch.setattr(api, "SOC_KPI_TOOL", str(TOOL))
    monkeypatch.setattr(api, "CASES_FILE", state["cases"])
    monkeypatch.setenv("MITRE_LOOKUP", state["mitre"])
    monkeypatch.setattr(api, "_graylog_token", lambda: "")
    api._CACHE.clear()
    admin = Path(api.SOC_ADMIN_DIR)
    admin.mkdir(parents=True, exist_ok=True)
    (admin / "roles.json").write_text(json.dumps({"users": {"lab-reader": {"role": "lecteur"}}}), encoding="utf-8")
    assert not str(api.SOC_ADMIN_DIR).startswith("/var/lib") and str(tmp_path) in str(api.SOC_ADMIN_DIR)
    return fake


def test_endpoint_requires_analyst_role_and_returns_report(api, state, monkeypatch, tmp_path):
    fake = _prepare_api(api, state, monkeypatch, tmp_path)
    with serve(api.H) as base:
        code, body = _get(base, "/m/api/soc-kpi?days=7", "")
        assert code == 401
        code, body = _get(base, "/m/api/soc-kpi", api.sign_session("lab-reader"))
        assert code == 403 and "analyste" in body["error"]
        assert not fake.calls                                  # aucun calcul pour un lecteur
        code, body = _get(base, "/m/api/soc-kpi?days=7", api.sign_session("lab-analyst"))
        assert code == 200
        assert body["periode"]["jours"] == 7.0 and body["alertes"]["total"] == 4
        assert body["mttr"]["dossiers"]["dossiers_periode"] >= 1
        assert body["couverture"]["disponible"] is False       # pas de jeton Graylog : signalé
        assert {i for i, _ in fake.calls} <= {"gl-events*", "gl-system-events*", "omni-*"}
        n = len(fake.calls)
        code, _ = _get(base, "/m/api/soc-kpi?days=7", api.sign_session("lab-analyst"))
        assert code == 200 and len(fake.calls) == n            # mis en cache
        code, body = _get(base, "/m/api/soc-kpi?days=9999", api.sign_session("lab-analyst"))
        assert code == 200 and body["periode"]["jours"] == 90.0   # borné à 90 jours


def test_endpoint_unavailable_tool_and_search_errors(api, state, monkeypatch, tmp_path):
    _prepare_api(api, state, monkeypatch, tmp_path)
    monkeypatch.setattr(api, "SOC_KPI_TOOL", str(tmp_path / "absent.py"))
    with serve(api.H) as base:
        code, body = _get(base, "/m/api/soc-kpi", api.sign_session("lab-analyst"))
        assert code == 503 and body["available"] is False
    monkeypatch.setattr(api, "SOC_KPI_TOOL", str(TOOL))
    api._CACHE.clear()

    def unavailable(*a, **k):
        raise api.SearchBackendError(503)
    monkeypatch.setattr(api, "os_search", unavailable)
    with serve(api.H) as base:
        code, body = _get(base, "/m/api/soc-kpi", api.sign_session("lab-analyst"))
        assert code == 503 and body["error"] == "search_unavailable"
    monkeypatch.setattr(api, "os_search", lambda index, body: {"hits": {"total": {"value": 0}, "hits": []},
                                                               "timed_out": True})
    api._CACHE.clear()
    with serve(api.H) as base:
        code, body = _get(base, "/m/api/soc-kpi", api.sign_session("lab-analyst"))
        assert code == 502 and "total" not in body


def test_case_updates_record_dated_history_and_closure(api):
    assert api.update_case({"id": "c1", "action": "status", "value": "in_progress"}, "jdupont")["ok"]
    api.update_case({"id": "c1", "action": "note", "value": "analyse"}, "jdupont")
    api.update_case({"id": "c1", "action": "disposition", "value": "false_positive"}, "jdupont")
    c = api.load_cases()["c1"]
    assert [h["action"] for h in c["history"]] == ["status", "disposition"]
    assert c["history"][1]["value"] == "false_positive" and c["status"] == "closed"
    closed = kpi.parse_ts(c["closed_ts"])
    assert closed is not None and re.search(r"[+-]\d{2}:\d{2}$", c["closed_ts"])    # décalage explicite
    api.update_case({"id": "c1", "action": "status", "value": "in_progress"}, "jdupont")
    c = api.load_cases()["c1"]
    assert "closed_ts" not in c and len(c["history"]) == 3
    for _ in range(60):
        api.update_case({"id": "c1", "action": "assign", "value": "x"}, "jdupont")
    assert len(api.load_cases()["c1"]["history"]) == 50
    assert str(api.CASES_FILE).startswith("/var/lib") is False


# ------------------------------------------------------------------ front (statique)
def test_kpi_page_is_wired_csp_compatible_and_cached():
    html = (SOC / "index.html").read_text(encoding="utf-8")
    sw = (SOC / "sw.js").read_text(encoding="utf-8")
    js = (SOC / "app-kpi.js").read_text(encoding="utf-8")
    scripts = re.findall(r'<script src="(/soc/[^"]+)"', html)
    assert "/soc/app-kpi.js?v=2026112201" in scripts and '"/soc/app-kpi.js?v=2026112201"' in sw
    assert scripts.index("/soc/app-kpi.js?v=2026112201") > scripts.index("/soc/app.js?v=2026112401")
    assert 'data-p="kpi"' in html and 'id="p-kpi"' in html and 'id="kpiRoot"' in html
    assert not re.search(r"\son(click|input|change|keydown|submit)\s*=", js)
    assert "innerHTML" not in js and "eval(" not in js and "new Function" not in js
    assert "/m/api/soc-kpi" in js
    data_ok = re.search(r"DATA_OK = new Set\(\[(.*?)\]\)", sw, re.S).group(1)
    assert "soc-kpi" not in data_ok                                   # jamais gardé hors ligne
    emoji = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")
    for f in (SOC / "app-kpi.js", TOOL, Path(__file__)):
        assert not emoji.search(f.read_text(encoding="utf-8")), f



def test_endpoint_through_backend_search_client_validation(api, state, monkeypatch, tmp_path):
    """Chemin réel : os_search du backend (validation stricte des réponses) vers un OpenSearch simulé."""
    fake = _prepare_api(api, state, monkeypatch, tmp_path, patch_search=False)
    seen = []

    class OS(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            seen.append(self.path)
            index = urllib.request.unquote(self.path.split("/")[1])
            index = "omni-*" if index.startswith(("omni-", "graylog_")) else index
            out = json.dumps(fake(index, body)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass
    with serve(OS) as osb:
        monkeypatch.setattr(api, "OS_URL", osb)
        with serve(api.H) as base:
            code, body = _get(base, "/m/api/soc-kpi", api.sign_session("lab-analyst"))
    assert code == 200, body
    assert body["alertes"]["total"] == 4 and body["mttd"]["alertes_analysees"] == 4
    assert seen and all(path.endswith("/_search") for path in seen)
