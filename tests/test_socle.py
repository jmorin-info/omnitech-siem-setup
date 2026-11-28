"""Socle SOC : dashboards et console pilotés par les sources que le site active."""
import copy
import json
from pathlib import Path
import re

import pytest

from omni_integrations import socle

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "mobile" / "soc"
# Site type : Windows (Sécurité, Sysmon, autres, inventaire) + pare-feu WatchGuard, rien d'autre.
SITE = {"schema_version": 1, "integrations": {"watchguard": {"source_input": "a" * 24, "dashboards": {}}},
        "site": {"sources": ["windows_security", "sysmon", "windows", "inventory"], "features": ["deploy_kit"],
                 "inputs": {"b" * 24: "Winlogbeat"}}}
STREAMS = {"OMNI - Windows Security": "1" * 24, "OMNI - Sysmon": "2" * 24, "OMNI - Windows autres": "3" * 24,
           "OMNI integration - WatchGuard Firebox": "4" * 24, "OMNI - FortiGate": "5" * 24}


def profile(tmp_path, data=SITE):
    path = tmp_path / "integrations.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return socle.load_site_profile(path)


def build(prof):
    caps, cat = socle.load_capabilities(), socle.load_socle()
    return socle.build_socle_dashboard(caps, cat, cat["dashboards"][0], prof["enabled"], STREAMS)


def test_catalog_contract_is_valid():
    result = socle.validate_socle()
    assert result["widgets"] > 40 and result["console_pages"] >= 19


@pytest.mark.parametrize("change,message", [
    (lambda w: w.update(field="m365_type"), "never produced"),
    (lambda w: w.update(requires=["unknown_source"]), "unknown capability"),
    (lambda w: w.update(type="script"), "unknown widget type"),
    (lambda w: (w.pop("requires"), w.pop("scope", None)), "must declare requires"),
    (lambda w: w.update(series=["count()", "eval(x)"]), "Unsupported widget series"),
])
def test_contract_refuses_widgets_that_depend_on_absent_data(change, message):
    caps, cat = socle.load_capabilities(), copy.deepcopy(socle.load_socle())
    page = next(p for p in cat["dashboards"][0]["pages"] if p["title"] == "Vue d'ensemble")
    change(page["widgets"][1])
    problems = socle.check_socle(caps, cat)
    assert any(message in " ".join(p) for p in problems), problems


def test_site_without_source_list_keeps_legacy_behaviour(tmp_path):
    prof = profile(tmp_path, {"schema_version": 1})
    assert prof["legacy"] and "m365" in prof["enabled"] and "soar" in prof["enabled"]


@pytest.mark.parametrize("site", [{"sources": ["unknown"]}, {"features": ["teleport"]}, {"dashboards": {"soc": "bad"}},
                                  {"inputs": {"x": "y"}}, {"location": {"lat": 120, "lng": 0}}])
def test_invalid_site_configuration_is_refused(tmp_path, site):
    with pytest.raises(ValueError):
        profile(tmp_path, {"schema_version": 1, "site": site})


def test_only_pages_and_widgets_of_enabled_sources_are_published(tmp_path):
    prof = profile(tmp_path)
    assert "watchguard" in prof["enabled"]          # activée par son module d'intégration
    built = build(prof)
    tabs = [s["titles"]["tab"]["title"] for s in built["view"]["state"].values()]
    assert tabs == ["Vue d'ensemble", "Collecte et santé", "Authentifications et AD", "Postes et serveurs Windows",
                    "Détections et tri"]
    titles = {w["title"] for _, w, _, _ in built["widgets"]}
    assert "Blocages du pare-feu (24 h)" in titles and "Blocages du pare-feu FortiGate (24 h)" not in titles
    assert not any(w.get("requires") and set(w["requires"]) <= {"detections", "m365", "fortigate"} for _, w, _, _ in built["widgets"])
    allowed = {STREAMS[t] for t in ("OMNI - Windows Security", "OMNI - Sysmon", "OMNI - Windows autres",
                                    "OMNI integration - WatchGuard Firebox")}
    for state in built["view"]["state"].values():
        cells = set()
        for widget in state["widgets"]:
            title = state["titles"]["widget"][widget["id"]]
            spec = next(w for _, w, _, _ in built["widgets"] if w["title"] == title)
            # Jamais d'élargissement silencieux à tous les streams : seuls les widgets « all » le sont.
            assert widget["streams"] or spec.get("scope") == "all", title
            assert set(widget["streams"]) <= allowed
            pos = state["positions"][widget["id"]]
            for col in range(pos["col"], pos["col"] + pos["width"]):
                for row in range(pos["row"], pos["row"] + pos["height"]):
                    assert (col, row) not in cells, "chevauchement : " + title
                    cells.add((col, row))
            assert pos["col"] + pos["width"] - 1 <= 12


def test_every_received_input_has_a_collection_view(tmp_path):
    built = build(profile(tmp_path))
    collecte = [w for page, w, _, _ in built["widgets"] if page == "Collecte et santé"]
    assert any(w.get("field") == "gl2_source_input" and w.get("scope") == "all" for w in collecte)
    assert any(w["type"] == "messages" and w.get("scope") == "all" for w in collecte)


def test_source_without_its_stream_is_narrowed_by_event_source(tmp_path):
    caps, cat = socle.load_capabilities(), socle.load_socle()
    streams = {k: v for k, v in STREAMS.items() if k != "OMNI integration - WatchGuard Firebox"}
    built = socle.build_socle_dashboard(caps, cat, cat["dashboards"][0], profile(tmp_path)["enabled"], streams)
    state = next(iter(built["view"]["state"].values()))
    wg = [w for w in state["widgets"] if state["titles"]["widget"][w["id"]] == "Blocages du pare-feu (24 h)"][0]
    assert wg["streams"] == [] and "event_source:(watchguard)" in wg["query"]["query_string"]


def test_console_pages_cover_the_navigation_and_new_assets_are_published():
    caps = socle.load_capabilities()
    html = (SOC / "index.html").read_text(encoding="utf-8")
    nav = set(re.findall(r'<a[^>]*data-p="([a-z0-9-]+)"', html))
    assert nav and nav <= set(caps["console_pages"]), nav - set(caps["console_pages"])
    assert '/soc/app-site.js?v=' in html and "/soc/app-site.js?v=" in (SOC / "sw.js").read_text(encoding="utf-8")
    script = (SOC / "app-site.js").read_text(encoding="utf-8")
    assert "innerHTML" not in script and " on" not in re.sub(r"[^<]*", "", script)


@pytest.fixture
def site_api(api, tmp_path, monkeypatch):
    path = tmp_path / "integrations.json"
    path.write_text(json.dumps(SITE), encoding="utf-8")
    monkeypatch.setattr(api, "SITE_CONFIG_FILE", str(path))
    api._SITE_CACHE.update(key=None, data=None)
    return api


def test_console_hides_pages_of_absent_sources_and_flags_missing_detections(site_api, monkeypatch):
    monkeypatch.setattr(site_api, "_alerts_seen", lambda days=30: False)
    site = site_api.get_site()
    assert not site["legacy"]
    hidden = {k for k, v in site["pages"].items() if not v["visible"]}
    assert hidden == {"graph", "twin", "ems", "network", "leaks", "soar"}
    assert site["pages"]["deploy"]["visible"] and site["pages"]["globe"]["visible"]
    assert site["pages"]["detections"]["notice"] and site["detections"]["configured"] is False
    assert set(site["kpis_unavailable"]) == {"incidents_critiques_7j", "hotes_risque_ueba", "kev_exposees"}


def test_alerts_produced_without_site_update_clear_the_detection_notice(site_api, monkeypatch):
    monkeypatch.setattr(site_api, "_alerts_seen", lambda days=30: True)
    assert site_api.get_site()["pages"]["detections"]["notice"] is None


def test_unconfigured_kpis_are_null_not_zero(site_api, monkeypatch):
    monkeypatch.setattr(site_api, "_kpis_raw", lambda: {"alertes_24h": 5, "incidents_critiques_7j": 0,
                                                        "hotes_risque_ueba": 0, "kev_exposees": 0})
    kpis = site_api.get_kpis()
    assert kpis == {"alertes_24h": 5, "incidents_critiques_7j": None, "hotes_risque_ueba": None, "kev_exposees": None}


def test_health_expects_site_sources_and_lists_every_input(site_api, monkeypatch):
    assert site_api._site_expected_sources()["watchguard"] == 15
    def search(index, body):
        bucket = {"key": "b" * 24, "doc_count": 7, "last": {"value_as_string": "2026-11-28T09:00:00Z"},
                  "d1": {"doc_count": 3}, "raw": {"doc_count": 1},
                  "src": {"buckets": [{"key": "host1", "doc_count": 7}]}, "es": {"buckets": [{"key": "sysmon", "doc_count": 6}]},
                  "doc": {"hits": {"hits": [{"_source": {"message": "x", "gl2_source_input": "b" * 24, "user": "u", "host": "h"}}]}}}
        return {"hits": {"total": {"value": 7}, "hits": []}, "aggregations": {"inp": {"buckets": [bucket]}}}
    monkeypatch.setattr(site_api, "os_search", search)
    row = site_api.get_inputs_collect()[0]
    assert row["label"] == "Winlogbeat" and row["n_24h"] == 3 and row["unnormalized_7d"] == 1
    assert row["fields"] == ["host", "user"]


def test_broken_site_configuration_keeps_everything_visible(api, tmp_path, monkeypatch):
    path = tmp_path / "integrations.json"
    path.write_text('{"schema_version": 1, "site": {"sources": ["nope"]}}', encoding="utf-8")
    monkeypatch.setattr(api, "SITE_CONFIG_FILE", str(path))
    api._SITE_CACHE.update(key=None, data=None)
    site = api.get_site()
    assert site["legacy"] and site["error"] and all(v["visible"] for v in site["pages"].values())


def test_discovery_maps_decorated_input_titles_and_counts_raw_messages(monkeypatch):
    class Client:
        def call(self, method, path, body=None):
            if path == "/system/inputs":
                return {"inputs": [{"id": "c" * 24, "title": "Pare-feu"}]}
            field = body["group_by"][0]["field"]
            rows = {"event_source": [["watchguard", 9], ["(Empty Value)", 4]],
                    "gl2_source_input": [["Pare-feu", 9], ["d" * 24, 4]]}[field]
            return {"datarows": rows}
    result = socle.discover_sources(Client())
    assert result["proposed_sources"] == ["watchguard"] and result["unnormalized_messages"] == 4
    assert result["inputs"] == [{"id": "c" * 24, "title": "Pare-feu", "messages": 9},
                                {"id": "d" * 24, "title": "(entrée supprimée)", "messages": 4}]


def test_console_check_reports_hidden_pages_and_fails_on_visible_errors(site_api, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("console_check", ROOT / "tools" / "omni-console-check.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    monkeypatch.setattr(site_api, "_alerts_seen", lambda days=30: False)
    for page, readers in tool.PAGES.items():
        for name in readers:
            monkeypatch.setattr(site_api, name, lambda *a, **k: {"total": 1})
    result = tool.check(site_api)
    states = {p["page"]: p["status"] for p in result["pages"]}
    assert result["failures"] == 0 and states["ems"] == "hidden" and states["health"] == "ok"
    def broken(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(site_api, "get_health", broken)
    assert tool.check(site_api)["failures"] == 1
