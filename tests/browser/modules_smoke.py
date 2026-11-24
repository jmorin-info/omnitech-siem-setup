"""Exercise the real modules editor and widgets against intercepted fixture APIs only.

Run: python tests/browser/modules_smoke.py [--screenshots DIRECTORY]
"""
import argparse
import copy
import json
import mimetypes
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2] / "mobile/soc"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--screenshots", type=Path)
args = parser.parse_args()
out = args.screenshots or Path(tempfile.mkdtemp(prefix="soc-modules-browser-"))
out.mkdir(parents=True, exist_ok=True)
base_page = {"id": "watchguard", "title": "WatchGuard", "description": "Pare-feu du laboratoire",
    "enabled": True, "min_role": "analyste", "stream_ids": ["a" * 24], "event_sources": [],
    "integration_ids": ["watchguard"], "query": "", "days": 1, "graylog_dashboard_id": "b" * 24,
    "widgets": [{"id": "volume", "title": "Événements", "type": "count", "field": "", "size": 10}]}
checks = []
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    for width in (1440, 390):
        for theme in ("dark", "light"):
            context = browser.new_context(viewport={"width": width, "height": 950}, service_workers="block")
            page = context.new_page()
            state = {"admin": True, "failure": False, "posts": [], "config": {"schema_version": 1, "revision": 2, "pages": [copy.deepcopy(base_page)]}}
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            def route(r):
                path = urlsplit(r.request.url).path
                if path == "/soc/test-modules":
                    return r.fulfill(content_type="text/html", body=(
                        '<html lang="fr" data-theme="' + theme + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                        '<link rel="stylesheet" href="/soc/app-professional.css"><link rel="stylesheet" href="/soc/app-modules.css"></head>'
                        '<body style="margin:0;padding:18px"><nav id="nav"><a data-p="modules" href="#">Modules</a></nav>'
                        '<main><div id="modulesRoot"></div></main><script src="/soc/app-modules.js"></script></body></html>'))
                if path.startswith("/m/api/"):
                    status, result = 200, {}
                    if path == "/m/api/admin/me":
                        result = {"is_admin": state["admin"], "csrf": "fixture-csrf", "writes_allowed": True}
                    elif path == "/m/api/modules":
                        result = {"revision": state["config"]["revision"], "pages": [v for v in state["config"]["pages"] if v["enabled"]]}
                    elif path == "/m/api/modules/page":
                        if state["failure"]:
                            status, result = 503, {"error": "Recherche momentanément indisponible"}
                        else:
                            result = {"page": base_page, "generated": "2026-11-24T10:00:00Z", "widgets": [
                                {"id": "volume", "title": "Événements", "type": "count", "status": "ok", "data": {"value": 42}},
                                {"id": "sources", "title": "Sources", "type": "terms", "status": "ok", "data": {"buckets": [{"key": "lab-fw", "count": 42}]}},
                                {"id": "activity", "title": "Activité", "type": "timeseries", "status": "ok", "data": {"buckets": [{"key": "2026-11-24T10:00:00Z", "count": 42}]}},
                                {"id": "logs", "title": "Journaux", "type": "messages", "status": "ok", "data": {"messages": [{"timestamp": "2026-11-24", "source": "lab-fw", "message": '<img src=x onerror="window.injected=true">'}]}},
                                {"id": "broken", "title": "Source indisponible", "type": "count", "status": "error", "data": None},
                            ]}
                    elif path == "/m/api/admin/modules" and r.request.method == "GET":
                        result = {"config": state["config"], "catalog": {"streams": [{"id": "a" * 24, "title": "WatchGuard lab"}],
                            "dashboards": [{"id": "b" * 24, "title": "WatchGuard", "widgets": 6}],
                            "fields": [{"name": "source", "aggregatable": True}], "errors": []}}
                    elif path == "/m/api/admin/modules" and r.request.method == "POST":
                        data = r.request.post_data_json
                        assert r.request.headers["x-soc-csrf"] == "fixture-csrf"
                        state["posts"].append(data)
                        if data["simulate"]:
                            result = {"ok": True, "simulation": True, "preview": {"after": data["params"]}}
                        else:
                            state["config"] = copy.deepcopy(data["params"])
                            state["config"]["revision"] += 1
                            result = {"ok": True}
                    return r.fulfill(status=status, content_type="application/json", body=json.dumps(result))
                target = ROOT / path.removeprefix("/soc/")
                if path.startswith("/soc/") and target.is_file():
                    return r.fulfill(content_type=mimetypes.guess_type(target.name)[0] or "application/octet-stream", body=target.read_bytes())
                return r.fulfill(status=404, body="not found")
            page.route("**/*", route)
            page.goto("http://127.0.0.1/soc/test-modules")
            page.locator("#nav a").click()
            page.get_by_text("Données indisponibles. Ce résultat ne vaut pas zéro.", exact=True).wait_for()
            assert page.locator(".modules-value").inner_text() == "42"
            assert page.locator(".modules-table td").last.inner_text().startswith("<img")
            assert page.locator("#modulesRoot img").count() == 0 and not page.evaluate("window.injected === true")
            assert page.locator("main").evaluate("e=>e.scrollWidth <= e.clientWidth+1")
            page.screenshot(path=str(out / f"modules-{width}-{theme}.png"), full_page=True)
            page.get_by_role("button", name="Configurer les pages et widgets", exact=True).click()
            page.get_by_role("heading", name="Pages et widgets de cet environnement").wait_for()
            page.get_by_label("Titre", exact=True).first.fill("Pare-feu du site")
            page.get_by_label("Motif du changement", exact=True).fill("Ajuster la page du site")
            page.get_by_role("button", name="Simuler le changement", exact=True).click()
            page.get_by_text("Simulation terminée.", exact=False).wait_for()
            assert len(state["posts"]) == 1 and state["posts"][0]["simulate"]
            page.get_by_role("button", name="Publier ces réglages", exact=True).click()
            page.get_by_text("Réglages enregistrés.", exact=True).wait_for()
            assert len(state["posts"]) == 2 and not state["posts"][1]["simulate"]
            assert state["config"]["pages"][0]["title"] == "Pare-feu du site"
            page.get_by_role("button", name="Retour aux pages publiées", exact=True).click()
            page.get_by_role("button", name="Configurer les pages et widgets", exact=True).wait_for()
            state["failure"] = True
            page.get_by_role("button", name="Actualiser", exact=True).click()
            page.get_by_text("Recherche momentanément indisponible", exact=True).wait_for()
            assert page.locator(".modules-value").count() == 0
            state["admin"] = False
            state["failure"] = False
            page.get_by_role("button", name="Actualiser", exact=True).click()
            page.locator(".modules-value").wait_for()
            assert page.get_by_role("button", name="Configurer les pages et widgets", exact=True).count() == 0
            assert not errors, errors
            checks.append({"width": width, "theme": theme, "passed": True})
            context.close()
    browser.close()
print(json.dumps(checks, indent=2))
