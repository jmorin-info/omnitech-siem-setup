"""Site-aware SOC dashboards: catalog of sources, offline contract, filtering and deployment.

The catalog (integrations/sources.json and integrations/socle/dashboards.json) declares
which source or SOC feature every page and widget depends on. A site enables sources in
the ``site`` key of /etc/omni-siem/integrations.json; nothing that depends on a disabled
source is published, so a dashboard never shows an empty widget for data the site does
not collect, nor a widget silently widened to every stream.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import time

from .core import CATALOG, GRAYLOG_FIELDS, WIDGET_TYPES, _pivot, load_module, produced_fields, query_fields, stable_id

SOURCES_FILE = CATALOG / "sources.json"
SOCLE_FILE = CATALOG / "socle" / "dashboards.json"
EVENTS_STREAM = "000000000000000000000002"   # Graylog "All events" stream (fixed identifier)
SOCLE_TYPES = WIDGET_TYPES - {"map"}
SERIES = re.compile(r"(count)\(\)|(card|latest|max|min|avg|sum)\(([A-Za-z_][A-Za-z0-9_.]*)\)")
SCOPES = {"sources", "all", "events"}
OBJECT_ID = re.compile(r"[a-f0-9]{24}")
IDENT = re.compile(r"[a-z][a-z0-9_]{0,63}")


def load_capabilities(path=SOURCES_FILE):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported sources catalog schema")
    if set(data["sources"]) & set(data["features"]):
        raise ValueError("A capability cannot be both a source and a feature")
    for key in list(data["sources"]) + list(data["features"]):
        if not IDENT.fullmatch(key):
            raise ValueError("Invalid capability identifier: " + key)
    known = set(data["sources"]) | set(data["features"])
    for page, spec in data["console_pages"].items():
        if set(spec.get("requires_any", [])) - known or set(spec.get("notice_unless_any", [])) - known:
            raise ValueError("Console page requires an unknown capability: " + page)
        if spec.get("notice_unless_any") and not spec.get("notice"):
            raise ValueError("Console page notice text missing: " + page)
    for kpi, needs in data.get("kpis", {}).items():
        if set(needs) - known:
            raise ValueError("KPI requires an unknown capability: " + kpi)
    return data


def load_socle(path=SOCLE_FILE):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or data.get("id") != "socle" or type(data.get("revision")) is not int:
        raise ValueError("Unsupported socle dashboards catalog")
    keys = [spec["key"] for spec in data["dashboards"]]
    if len(keys) != len(set(keys)) or any(not re.fullmatch(r"[a-z][a-z0-9-]*", key) for key in keys):
        raise ValueError("Socle dashboards need unique lowercase keys")
    return data


def source_fields(capabilities, capability):
    """Fields a source (or SOC feature) can write, used by the offline contract."""
    spec = capabilities["sources"].get(capability) or capabilities["features"].get(capability)
    fields = set(capabilities.get("common_fields", [])) | set(spec.get("fields", []))
    if spec.get("integration"):
        fields |= produced_fields(load_module(spec["integration"]))
    return fields, tuple(spec.get("field_prefixes", []))


def widget_series(widget):
    series = widget.get("series", ["count()"])
    parsed = []
    for item in series:
        match = SERIES.fullmatch(item)
        if not match:
            raise ValueError("Unsupported widget series: " + str(item))
        parsed.append((item, match.group(1) or match.group(2), match.group(3)))
    return parsed


def widget_used_fields(widget):
    fields = query_fields(widget.get("query", ""))
    fields |= {widget[key] for key in ("field", "split") if widget.get(key)}
    fields |= set(widget.get("fields", []))
    fields |= {field for _, _, field in widget_series(widget) if field}
    return fields - {"timestamp"}


def _requires(page, widget):
    return widget.get("requires", page.get("requires", []))


def check_socle(capabilities, socle):
    """Offline contract: known capabilities, known types, fields produced by the required sources."""
    known = set(capabilities["sources"]) | set(capabilities["features"])
    problems = []
    for spec in socle["dashboards"]:
        for page in spec["pages"]:
            if set(page.get("requires", [])) - known:
                problems.append((spec["title"], page["title"], "page requires unknown capability"))
            for widget in page["widgets"]:
                where = (spec["title"], page["title"] + " / " + widget["title"])
                needs = _requires(page, widget)
                scope = widget.get("scope", "sources")
                if widget["type"] not in SOCLE_TYPES:
                    problems.append(where + ("unknown widget type " + str(widget["type"]),))
                    continue
                if scope not in SCOPES:
                    problems.append(where + ("unknown scope " + scope,))
                if set(needs) - known:
                    problems.append(where + ("unknown capability " + ", ".join(sorted(set(needs) - known)),))
                    continue
                if scope != "all" and not needs:
                    problems.append(where + ("widget scoped to sources must declare requires",))
                if widget["type"] in ("terms",) and not widget.get("field"):
                    problems.append(where + ("terms widget without field",))
                if len(widget.get("pos", [])) != 4:
                    problems.append(where + ("pos must be [col, row, width, height]",))
                try:
                    used = widget_used_fields(widget)
                except ValueError as exc:
                    problems.append(where + (str(exc),))
                    continue
                allowed, prefixes = set(GRAYLOG_FIELDS) | {"event_source"}, ()
                if scope == "all" and not needs:
                    allowed |= {"host"}
                for capability in needs:
                    fields, more = source_fields(capabilities, capability)
                    allowed |= fields
                    prefixes += more
                for field in sorted(used - allowed):
                    if not (prefixes and field.startswith(prefixes)):
                        problems.append(where + ("field never produced by its required sources: " + field,))
    return problems


def validate_socle():
    capabilities, socle = load_capabilities(), load_socle()
    problems = check_socle(capabilities, socle)
    if problems:
        raise ValueError("socle dashboards: " + "; ".join(" / ".join(item) for item in problems))
    widgets = sum(len(page["widgets"]) for spec in socle["dashboards"] for page in spec["pages"])
    return {"id": "socle", "revision": socle["revision"], "dashboards": len(socle["dashboards"]), "widgets": widgets,
            "sources": len(capabilities["sources"]), "features": len(capabilities["features"]),
            "console_pages": len(capabilities["console_pages"])}


# ----------------------------------------------------------------- site profile
def load_site_profile(path, capabilities=None):
    """Enabled capabilities of a site. Without a ``site`` key every capability stays enabled (legacy)."""
    capabilities = capabilities or load_capabilities()
    data = json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {"schema_version": 1}
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported site configuration schema")
    site = data.get("site")
    every = set(capabilities["sources"]) | set(capabilities["features"])
    if site is None:
        return {"legacy": True, "enabled": every, "sources": sorted(capabilities["sources"]),
                "features": sorted(capabilities["features"]), "dashboards": {}, "inputs": {}, "location": None}
    if not isinstance(site, dict):
        raise ValueError("site must be an object")
    sources, features = site.get("sources", []), site.get("features", [])
    if not isinstance(sources, list) or set(sources) - set(capabilities["sources"]):
        raise ValueError("site.sources lists unknown sources: " + ", ".join(sorted(set(sources) - set(capabilities["sources"]))))
    if not isinstance(features, list) or set(features) - set(capabilities["features"]):
        raise ValueError("site.features lists unknown features: " + ", ".join(sorted(set(features) - set(capabilities["features"]))))
    bindings = site.get("dashboards", {})
    if not isinstance(bindings, dict) or any(not OBJECT_ID.fullmatch(str(v)) for v in bindings.values()):
        raise ValueError("site.dashboards must map socle keys to Graylog view IDs")
    inputs = site.get("inputs", {})
    if not isinstance(inputs, dict) or any(not OBJECT_ID.fullmatch(str(k)) or not isinstance(v, str) or len(v) > 80
                                           for k, v in inputs.items()):
        raise ValueError("site.inputs must map Graylog input IDs to short labels")
    location = site.get("location")
    if location is not None and (not isinstance(location, dict)
                                 or not all(isinstance(location.get(k), (int, float)) and not isinstance(location.get(k), bool)
                                            for k in ("lat", "lng"))
                                 or not -90 <= location["lat"] <= 90 or not -180 <= location["lng"] <= 180
                                 or not isinstance(location.get("label", ""), str) or len(location.get("label", "")) > 80):
        raise ValueError("site.location must be {lat, lng, label}")
    # A source normalized by an integration module is enabled with it.
    enabled = set(sources) | set(features)
    for key, spec in capabilities["sources"].items():
        if spec.get("integration") and spec["integration"] in data.get("integrations", {}):
            enabled.add(key)
    return {"legacy": False, "enabled": enabled, "sources": sorted(enabled & set(capabilities["sources"])),
            "features": sorted(enabled & set(capabilities["features"])), "dashboards": bindings, "inputs": inputs,
            "location": location}


def select_pages(spec, enabled):
    """Pages and widgets kept for a site (input order preserved)."""
    pages = []
    for page in spec["pages"]:
        if page.get("requires") and not set(page["requires"]) & enabled:
            continue
        widgets = [w for w in page["widgets"] if not _requires(page, w) or set(_requires(page, w)) & enabled]
        if widgets:
            pages.append(dict(page, widgets=widgets))
    return pages


def _layout(widgets):
    """Shelf packing on a 12-column grid: removed widgets leave no hole."""
    col, row, height, out = 1, 1, 0, []
    for widget in widgets:
        width, wheight = widget["pos"][2], widget["pos"][3]
        if col + width - 1 > 12:
            col, row, height = 1, row + height, 0
        out.append((col, row, width, wheight))
        col += width
        height = max(height, wheight)
    return out


def resolve_scope(capabilities, page, widget, enabled, stream_ids):
    """(streams, extra query) of a widget on a site; None when nothing on the site can feed it."""
    scope = widget.get("scope", "sources")
    if scope == "all":
        return [], ""
    if scope == "events":
        return [EVENTS_STREAM], ""
    needs = [c for c in _requires(page, widget) if c in enabled and c in capabilities["sources"]]
    streams, values = [], []
    for capability in needs:
        spec = capabilities["sources"][capability]
        found = [stream_ids[t] for t in spec.get("streams", []) if t in stream_ids]
        if found:
            streams += [s for s in found if s not in streams]
        else:
            values += spec.get("event_source", [])
    if values:
        # A source without its own stream on this site: every stream, narrowed by event_source.
        return [], "event_source:(" + " OR ".join(sorted(set(values))) + ")"
    if not streams:
        return None
    return streams, ""


def build_socle_dashboard(capabilities, socle, spec, enabled, stream_ids):
    """Native Graylog 7.2 search and view (API format) for one socle dashboard on one site."""
    slug, key = "socle", spec["key"]
    queries, states, kept = [], {}, []
    for page in select_pages(spec, enabled):
        page_number = next(i for i, original in enumerate(spec["pages"]) if original["title"] == page["title"])
        query_id = stable_id(slug, f"catalog:{key}:{page_number}:query")
        widgets, searches, positions, mapping, titles, placed = [], [], {}, {}, {}, []
        for item in page["widgets"]:
            scope = resolve_scope(capabilities, page, item, enabled, stream_ids)
            if scope is None:
                continue
            placed.append((item, scope))
        for (item, (streams, extra)), (col, row, width, height) in zip(placed, _layout([p[0] for p in placed])):
            number = next(i for i, original in enumerate(spec["pages"][page_number]["widgets"]) if original["title"] == item["title"])
            wid = stable_id(slug, f"catalog:{key}:{page_number}:{number}:widget")
            sid = stable_id(slug, f"catalog:{key}:{page_number}:{number}:search")
            text = " AND ".join(f"({q})" for q in (extra, item.get("query", "")) if q)
            query = {"type": "elasticsearch", "query_string": text}
            timerange = {"type": "relative", "range": item["range"]} if item.get("range") else None
            common = {"query": query, "streams": streams, "filter": None, "filters": [], "timerange": timerange}
            if item["type"] == "messages":
                widgets.append({"id": wid, "type": "messages", **common,
                                "config": {"fields": item.get("fields", ["timestamp", "source", "message"]),
                                           "show_message_row": "message" not in item.get("fields", []), "decorators": [], "sort": []}})
                searches.append({"id": sid, "type": "messages", "name": "messages", **common, "limit": 50, "offset": 0,
                                 "sort": [{"field": "timestamp", "order": "DESC"}], "decorators": []})
            else:
                rows, row_groups, cols, col_groups = [], [], [], []
                visualization = {"count": "numeric", "terms": "table", "timeline": "bar"}[item["type"]]
                if item["type"] == "timeline":
                    rows = [{"type": "time", "fields": ["timestamp"], "config": {"interval": {"type": "auto", "scaling": 1}}}]
                    row_groups = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}]
                    if item.get("split"):
                        pivot, group = _pivot(item["split"], 8)
                        cols, col_groups = [pivot], [group]
                elif item["type"] == "terms":
                    pivot, group = _pivot(item["field"], item.get("limit", 15))
                    rows, row_groups = [pivot], [group]
                series = widget_series(item)
                st_series = [{"type": kind, "id": name, **({"field": field} if field else {})} for name, kind, field in series]
                sort = ([{"type": "series", "field": series[0][0], "direction": "Descending"}] if item["type"] == "terms" else [])
                widgets.append({"id": wid, "type": "aggregation", **common, "stream_categories": [],
                                "config": {"visualization": visualization, "row_pivots": rows, "column_pivots": cols,
                                           "series": [{"config": {}, "function": name} for name, _, _ in series],
                                           "sort": [{"type": "series", "field": series[0][0], "direction": "Descending"}] if sort else [],
                                           "rollup": True, "event_annotation": False}})
                searches.append({"id": sid, "type": "pivot", "name": "chart", **common, "series": st_series,
                                 "row_groups": row_groups, "column_groups": col_groups, "sort": sort, "rollup": True})
            positions[wid] = {"col": col, "row": row, "width": width, "height": height}
            mapping[wid], titles[wid] = [sid], item["title"]
            kept.append((page["title"], item, query_id, sid))
        if not widgets:
            continue
        queries.append({"id": query_id, "timerange": {"type": "relative", "range": page.get("range", 86400)},
                        "filter": None, "filters": [], "query": {"type": "elasticsearch", "query_string": ""},
                        "search_types": searches})
        states[query_id] = {"selected_fields": None, "static_message_list_id": None,
                            "titles": {"tab": {"title": page["title"]}, "widget": titles},
                            "widgets": widgets, "widget_mapping": mapping, "positions": positions,
                            "formatting": {"highlighting": []}, "display_mode_settings": {"positions": {}}}
    view = {"type": "DASHBOARD", "title": spec["title"], "summary": spec.get("summary", ""),
            "description": spec.get("description", "") + " Sources du site : " + ", ".join(sorted(enabled)) +
            ". Généré par le catalogue socle révision " + str(socle["revision"]) + " ; ne pas modifier à la main.",
            "properties": [], "requires": {}, "state": states}
    return {"search": {"queries": queries, "parameters": []}, "view": view, "widgets": kept}


# ----------------------------------------------------------------- Graylog (API)
def _streams_by_title(client):
    found = {}
    for item in client.call("GET", "/streams")["streams"]:
        found.setdefault(item["title"], item["id"])
    return found


def plan_socle(client, profile):
    """GET only: socle dashboards to create, or to replace in place when the site binds a view."""
    capabilities, socle = load_capabilities(), load_socle()
    response = client.call("GET", "/views?per_page=1000")
    views = {item["id"]: item for item in response.get("views", response.get("elements", []))}
    unknown = set(profile["dashboards"]) - {spec["key"] for spec in socle["dashboards"]}
    if unknown:
        raise ValueError("Unknown socle dashboard keys in site configuration: " + ", ".join(sorted(unknown)))
    stream_ids = _streams_by_title(client)
    items = []
    for spec in socle["dashboards"]:
        target = profile["dashboards"].get(spec["key"])
        if target and target not in views:
            raise ValueError("View bound in the site configuration not found: " + target)
        if not target:
            same = [item["id"] for item in views.values() if item.get("title") == spec["title"]]
            if len(same) > 1:
                raise ValueError("Several views are titled " + spec["title"])
            target = same[0] if same else None
        if target and views[target].get("type") != "DASHBOARD":
            raise ValueError("Bound view is not a dashboard: " + target)
        built = build_socle_dashboard(capabilities, socle, spec, profile["enabled"], stream_ids)
        dropped = [(page["title"], w["title"]) for page in spec["pages"] for w in page["widgets"]
                   if (page["title"], w["title"]) not in {(p, i["title"]) for p, i, _, _ in built["widgets"]}]
        items.append({"key": spec["key"], "title": spec["title"], "action": "update" if target else "create",
                      "view_id": target, "current_title": views[target].get("title") if target else None,
                      "pages": [s["titles"]["tab"]["title"] for s in built["view"]["state"].values()],
                      "widgets": len(built["widgets"]), "omitted": len(dropped)})
    return {"catalog": "socle", "revision": socle["revision"], "legacy_site": profile["legacy"],
            "sources": profile["sources"], "features": profile["features"], "dashboards": items}


def deploy_socle(client, profile, *, apply=False, backup_dir=None):
    from .client import _new_object_id   # local import: avoid a cycle with client -> core
    plan = plan_socle(client, profile)
    if not apply:
        return plan
    if profile["legacy"]:
        raise ValueError("Declare the site sources (key 'site' of the site configuration) before publishing the socle")
    if not backup_dir:
        raise ValueError("--backup-dir is required with --apply")
    backup = Path(backup_dir)
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = dict(plan, module="socle", items=[], backup_dir=str(backup))

    def save():
        (backup / "state.json").write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    capabilities, socle = load_capabilities(), load_socle()
    stream_ids = _streams_by_title(client)
    originals = {}
    for item in plan["dashboards"]:
        if item["view_id"]:
            original = client.call("GET", "/views/" + item["view_id"])
            search = client.call("GET", "/views/search/" + original["search_id"])
            originals[item["view_id"]] = original
            (backup / ("view-" + item["view_id"] + ".json")).write_text(
                json.dumps({"view": original, "search": search}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    save()
    specs = {spec["key"]: spec for spec in socle["dashboards"]}
    for item in plan["dashboards"]:
        built = build_socle_dashboard(capabilities, socle, specs[item["key"]], profile["enabled"], stream_ids)
        search_id = _new_object_id()
        client.call("POST", "/views/search", dict(built["search"], id=search_id))
        view = dict(built["view"], search_id=search_id)
        if item["view_id"]:
            if originals[item["view_id"]].get("owner"):
                view["owner"] = originals[item["view_id"]]["owner"]
            client.call("PUT", "/views/" + item["view_id"], {"entity": dict(view, id=item["view_id"])})
            state["items"].append({"key": item["key"], "view_id": item["view_id"], "action": "updated",
                                   "search_id": search_id, "backup": "view-" + item["view_id"] + ".json"})
        else:
            created = client.call("POST", "/views", {"entity": view})
            state["items"].append({"key": item["key"], "view_id": created["id"], "action": "created", "search_id": search_id})
        save()
    return state


def check_socle_site(client, profile, *, wait_seconds=120):
    """Post-deployment control: every published widget runs, empty widgets and hidden capabilities reported."""
    plan = plan_socle(client, profile)
    capabilities, socle = load_capabilities(), load_socle()
    stream_ids = _streams_by_title(client)
    specs = {spec["key"]: spec for spec in socle["dashboards"]}
    report, failures = [], 0
    for item in plan["dashboards"]:
        if not item["view_id"]:
            report.append({"dashboard": item["title"], "status": "not-deployed"})
            failures += 1
            continue
        built = build_socle_dashboard(capabilities, socle, specs[item["key"]], profile["enabled"], stream_ids)
        view = client.call("GET", "/views/" + item["view_id"])
        published = {w["id"] for state in view.get("state", {}).values() for w in state.get("widgets", [])}
        expected = {w["id"] for state in built["view"]["state"].values() for w in state["widgets"]}
        if published != expected:
            report.append({"dashboard": item["title"], "status": "drift",
                           "detail": f"{len(expected - published)} widget(s) attendus absents, {len(published - expected)} widget(s) en trop "
                                     "(dashboard modifié à la main ou sources du site changées : relancer soc-dashboards)"})
            failures += 1
        job = client.call("POST", "/views/search/" + view["search_id"] + "/execute", {})
        for _ in range(wait_seconds):
            if (job.get("execution") or {}).get("done"):
                break
            time.sleep(1)
            job = client.call("GET", "/views/search/status/" + job["id"])
        errors = {error.get("search_type_id") for error in job.get("errors", [])}
        for page, widget, query_id, search_type in built["widgets"]:
            result = (job.get("results", {}).get(query_id) or {}).get("search_types", {}).get(search_type)
            total = None if result is None else result.get("total_results", result.get("total"))
            if result is not None and widget["type"] == "terms" and isinstance(result.get("rows"), list):
                total = sum(1 for row in result["rows"] if row.get("key"))
            if search_type in errors or result is None:
                status = "error"
            elif total:
                status = "ok"
            else:
                status = "expected-empty" if widget.get("may_be_empty") else "empty"
            entry = {"dashboard": item["title"], "page": page, "widget": widget["title"], "status": status, "total": total}
            if status == "expected-empty":
                entry["reason"] = widget["may_be_empty"]
            if status in ("error", "empty"):
                failures += 1
            report.append(entry)
    return {"catalog": "socle", "sources": profile["sources"], "features": profile["features"],
            "failures": failures, "widgets": report}


def discover_sources(client, *, days=7):
    """GET only: capabilities observed on the site (proposal for site.sources), and inputs with data."""
    capabilities = load_capabilities()
    inputs = {item["id"]: item.get("title", item["id"]) for item in client.call("GET", "/system/inputs").get("inputs", [])}

    def counts(field):
        # Graylog scripting API (read-only aggregation); errors propagate instead of guessing.
        result = client.call("POST", "/search/aggregate", {
            "query": "*", "timerange": {"type": "relative", "range": days * 86400},
            "group_by": [{"field": field, "limit": 50}], "metrics": [{"function": "count"}]})
        return {str(row[0]): row[-1] for row in result.get("datarows", [])}
    observed, per_input = counts("event_source"), counts("gl2_source_input")
    unnormalized = observed.pop("(Empty Value)", 0)
    proposal = sorted(key for key, spec in capabilities["sources"].items()
                      if any(observed.get(value) for value in spec.get("event_source", [])))
    by_title = {title: key for key, title in inputs.items()}
    rows = []
    for key, count in sorted(per_input.items(), key=lambda kv: -kv[1]):
        # The scripting API decorates input IDs with their titles; deleted inputs keep their ID.
        identifier = key if key in inputs or OBJECT_ID.fullmatch(key) else by_title.get(key, key)
        rows.append({"id": identifier, "title": inputs.get(identifier, "(entrée supprimée)"), "messages": count})
    return {"days": days, "event_sources": observed, "unnormalized_messages": unnormalized,
            "proposed_sources": proposal, "inputs": rows}
