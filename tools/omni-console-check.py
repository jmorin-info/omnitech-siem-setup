#!/usr/bin/env python3
"""Post-deployment control of the /soc/ console, page by page, in read-only mode.

Loads the installed backend (no HTTP session, no write) and calls every page reader.
Each page is reported as ok (data), empty, hidden (source not enabled by the site),
notice (feature not configured, shown as such) or error. Exit code 1 when a visible
page fails or when a page depends on a capability the site does not enable.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

# page -> lectures appelées par la console pour l'afficher
PAGES = {
    "overview": ["get_kpis", "get_timeseries", "get_risk", "get_geo_threats"],
    "incidents": ["get_incidents", "get_cases"],
    "detections": ["get_detections"],
    "kpi": ["get_soc_kpi"],
    "entities": ["get_entities_browse"],
    "attack": ["get_attack_matrix"],
    "graph": ["get_attack_graph"],
    "twin": ["get_attack_graph"],
    "ems": ["get_fortiems"],
    "network": ["get_network"],
    "deploy": ["get_deploy"],
    "globe": ["get_geo_flows"],
    "leaks": ["get_leaks_v2"],
    "health": ["get_health"],
    "soar": ["get_soar"],
    "ops": ["get_siem_ops"],
    "report": ["get_report"],
    "playbooks": ["get_guidance"],
}
ARGS = {"get_geo_flows": (3,), "get_soc_kpi": (30,), "get_detections": ("", "", "", "")}


def has_data(value):
    if isinstance(value, dict):
        return any(has_data(v) for k, v in value.items() if k not in ("days", "hours", "window", "oms", "coverage", "error"))
    if isinstance(value, (list, tuple)):
        return any(has_data(v) for v in value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return value not in (None, "", "?")


def load_backend(path):
    spec = importlib.util.spec_from_file_location("omni_mobile_api_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(api):
    site = api.get_site()
    report, failures = [], 0
    for page, readers in PAGES.items():
        state = site["pages"].get(page, {"visible": True, "notice": None})
        entry = {"page": page, "visible": state["visible"], "notice": bool(state.get("notice")), "readers": {}}
        if not state["visible"]:
            entry["status"] = "hidden"
            report.append(entry)
            continue
        statuses = []
        for name in readers:
            try:
                value = getattr(api, name)(*ARGS.get(name, ()))
                status = "ok" if has_data(value) else "empty"
            except Exception as exc:   # une page visible ne doit jamais échouer
                status = "error:" + type(exc).__name__
            entry["readers"][name] = status
            statuses.append(status)
        if any(s.startswith("error") for s in statuses):
            entry["status"] = "error"
            failures += 1
        elif "ok" in statuses:
            entry["status"] = "ok"
        else:
            entry["status"] = "notice" if entry["notice"] else "empty"
        report.append(entry)
    caps = (api.site_profile()["caps"] or {}).get("console_pages", {})
    unknown = sorted(set(PAGES) - set(caps))
    if unknown:
        failures += 1
    return {"legacy": site["legacy"], "sources": [s["id"] for s in site["sources"]], "features": site["features"],
            "detections_configured": site["detections"]["configured"], "kpis_unavailable": site["kpis_unavailable"],
            "unknown_pages": unknown, "failures": failures, "pages": report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, default=Path("/opt/omni-siem/repository/mobile/omni-mobile-api.py"))
    parser.add_argument("--config", default=os.environ.get("MOBILE_CONFIG", "/etc/default/omni-mobile"))
    args = parser.parse_args(argv)
    os.environ["MOBILE_CONFIG"] = args.config
    result = check(load_backend(args.backend))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
