"""Build native Graylog packs from declarative manifests; no network side effects."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import uuid

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "integrations"
NAMESPACE = uuid.UUID("7a7acf1c-15bc-43fa-b650-0f10909f8a56")
SUPPORTED = {"regex", "cef", "csv"}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Fields every Graylog input provides; dashboards may always reference them.
GRAYLOG_FIELDS = {"timestamp", "source", "message", "full_message", "streams", "gl2_source_input",
                  "gl2_source_node", "gl2_remote_ip"}
LOWERCASE = ("event_action", "network_protocol", "event_category", "event_outcome")
WIDGET_TYPES = {"count", "terms", "timeline", "map", "messages"}


def catalog():
    data = json.loads((CATALOG / "catalog.json").read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported catalog schema")
    identifiers = [item["id"] for item in data["modules"]]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Duplicate catalog module identifier")
    if any(item["manifest"] != item["id"] + "/manifest.json" for item in data["modules"]):
        raise ValueError("Catalog manifest paths must match their module identifier")
    return [load_module(item["id"]) for item in data["modules"]]


def load_module(module_id):
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", module_id):
        raise ValueError("Invalid integration identifier")
    data = json.loads((CATALOG / module_id / "manifest.json").read_text(encoding="utf-8"))
    if data.get("id") != module_id or data.get("schema_version") != 1:
        raise ValueError("Manifest identifier/schema mismatch")
    if data["parser"]["type"] not in SUPPORTED or type(data["revision"]) is not int or data["revision"] < 1:
        raise ValueError("Unsupported parser or revision")
    parser = data["parser"]
    field_names = list(parser["mapping"]) + list(parser["mapping"].values())
    field_names += parser.get("fields", [])
    field_names += list(parser.get("existing_fields", {}))
    field_names += [field for pattern in parser.get("patterns", []) for field in pattern["fields"]]
    field_names += list(parser.get("kv_fields", {})) + list(parser.get("kv_fields", {}).values())
    field_names += parser.get("success_fields", []) + list(data.get("derived_fields", {}))
    if any(not IDENTIFIER.fullmatch(field) for field in field_names):
        raise ValueError("Mapping/parse fields must be valid pipeline identifiers")
    for pattern in parser.get("patterns", []):
        if re.compile(pattern["expression"]).groups != len(pattern["fields"]):
            raise ValueError("Regex capture count does not match fields")
    if not 1024 <= data["default_port"] <= 65535:
        raise ValueError("Invalid nonprivileged input port")
    keys = [spec.get("key") for spec in data.get("dashboards", [])]
    if any(not re.fullmatch(r"[a-z][a-z0-9-]*", str(key)) for key in keys) or len(keys) != len(set(keys)):
        raise ValueError("Catalog dashboards need unique lowercase keys")
    return data


def stable_id(module_id, role):
    return str(uuid.uuid5(NAMESPACE, module_id + ":" + role))


def value(item):
    kind = "boolean" if isinstance(item, bool) else "integer" if isinstance(item, int) else "string"
    return {"@type": kind, "@value": item}


def parameter(name):
    return {"@type": "parameter", "@value": name}


def _rule(name, condition, statements):
    # Bean/map property expressions are dynamically typed by the Graylog DSL.
    # An explicit comparison makes a regex condition evaluate as Boolean.
    if condition.endswith(".matches"):
        condition += " == true"
    return {"title": name, "source": f'rule {json.dumps(name)}\nwhen\n  {condition}\nthen\n  ' + "\n  ".join(statements) + "\nend\n"}


def kv_expression(key):
    """Quoted Fireware-style key="value" pair; the key is a literal identifier."""
    return r'(?:^|\s)' + key + r'="([^"]*)"'


def _typed(canonical, field, lowercase=LOWERCASE):
    """Condition suffix and expression that validate/normalize one common-model value."""
    expression, condition = f"to_string($message.{field})", ""
    if canonical in ("src_ip", "dest_ip") or canonical.endswith("_ip"):
        condition = f" AND is_ip(to_ip({expression}))"
        expression = f"to_ip({expression})"
    elif canonical.endswith("_port"):
        condition = f' AND regex("^[0-9]+$", to_string($message.{field})).matches == true'
        condition += f" AND to_long($message.{field}) >= 0 AND to_long($message.{field}) <= 65535"
        expression = f"to_long($message.{field})"
    elif canonical.startswith("bytes_"):
        condition = f' AND regex("^[0-9]{{1,15}}$", to_string($message.{field})).matches == true'
        expression = f"to_long($message.{field})"
    elif canonical in lowercase:
        expression = f'lowercase(regex_replace(" +", {expression}, "_", true))'
    return condition, expression


def pipeline_rules(module):
    """Only documented core functions; raw vendor fields are always namespaced."""
    slug, parser = module["id"], module["parser"]
    prefix = slug.replace("-", "_") + "_"
    stem = f"omni-integration-{slug}-r{module['revision']}"
    stages = [[], [], [], []]
    # Graylog only continues to the next stage when one rule of a "match either"
    # stage matched: fields already extracted by a collector must still reach mapping.
    pass_through = bool(parser.get("existing_fields") or parser.get("kv_fields"))
    stages[0].append(_rule(stem + "-initialize", "true", [
        f'set_field("event_source", {json.dumps(slug)});',
        'set_field("omni_parse_status", "unparsed");',
        'set_field("host", to_string($message.source));',
    ]))
    if parser["type"] == "regex":
        for index, pattern in enumerate(parser["patterns"]):
            call = f'regex({json.dumps(pattern["expression"])}, to_string($message.message), {json.dumps(pattern["fields"])})'
            stages[1].append(_rule(stem + f"-parse-{index}", call + ".matches", [
                f"let parsed = {call};",
                *[f'set_field({json.dumps(prefix + field)}, parsed[{json.dumps(field)}]);' for field in pattern["fields"]],
            ]))
        for key, raw in parser.get("kv_fields", {}).items():
            call = f'regex({json.dumps(kv_expression(key))}, to_string($message.message), ["value"])'
            stages[1].append(_rule(stem + "-kv-" + key.lower(), call + ".matches", [
                f"let parsed = {call};", f'set_field({json.dumps(prefix + raw)}, parsed["value"]);']))
        if parser.get("success_fields"):
            success = " AND ".join(f'has_field("{prefix}{field}")' for field in parser["success_fields"])
        else:
            success = f'has_field("{prefix}event_id") AND has_field("{prefix}action")'
        if parser.get("existing_fields"):
            event_id_field = next((field for field, target in parser["existing_fields"].items() if target == "event_id"), None)
            action_field = next((field for field, target in parser["existing_fields"].items() if target == "event_action"), None)
            if event_id_field and action_field:
                success = f'({success}) OR (has_field("{event_id_field}") AND has_field("{action_field}"))'
    elif parser["type"] == "cef":
        expression = r"(?s)(CEF:[0-9]+\|Ubiquiti\|UniFi Network\|.*)"
        call = f'regex({json.dumps(expression)}, to_string($message.message))'
        stages[1].append(_rule(stem + "-parse-cef", call + ".matches", [
            f"let cef = {call};", 'let parsed = parse_cef(to_string(cef["0"]), false);',
            f'set_fields(fields: parsed, prefix: {json.dumps(prefix)});',
        ]))
        success = f'has_field("{prefix}device_event_class_id") AND has_field("{prefix}device_vendor")'
    else:
        # The first CSV cell may contain a syslog envelope; PAN-OS ignores that cell.
        expression = r"^[^,]*,[^,]*,[^,]*,TRAFFIC,"
        stages[1].append(_rule(stem + "-parse-csv", f'regex({json.dumps(expression)}, to_string($message.message)).matches', [
            f'let parsed = csv_to_map(value: to_string($message.message), fieldNames: {json.dumps(",".join(parser["fields"]))}, ignoreExtraCsvValues: true);',
            f'set_fields(fields: parsed, prefix: {json.dumps(prefix)});',
        ]))
        success = f'has_field("{prefix}log_type") AND has_field("{prefix}action")'
    if pass_through:
        stages[1].append(_rule(stem + "-continue-1", "true", ['set_field("event_source", ' + json.dumps(slug) + ');']))
        stages[2].append(_rule(stem + "-continue-2", "true", ['set_field("event_source", ' + json.dumps(slug) + ');']))
    stages[2].append(_rule(stem + "-parsed", success, ['set_field("omni_parse_status", "parsed");']))
    for raw, canonical in parser["mapping"].items():
        field = prefix + raw
        condition = f'has_field("{field}") AND to_string($message.{field}) != ""'
        extra, expression = _typed(canonical, field)
        stages[3].append(_rule(stem + "-map-" + raw.lower(), condition + extra, [f'set_field("{canonical}", {expression});']))
    # Some collectors or vendor extractors already populate raw Graylog fields.
    # Preserve those fields and fill the common model only when it is absent.
    for raw, canonical in parser.get("existing_fields", {}).items():
        condition = f'has_field("{raw}") AND to_string($message.{raw}) != "" AND !has_field("{canonical}")'
        extra, expression = _typed(canonical, raw, ("event_action", "network_protocol"))
        stages[3].append(_rule(stem + "-existing-" + raw.lower(), condition + extra,
                               [f'set_field("{canonical}", {expression});']))
    return stages


def dashboard(module, stream_id):
    slug = module["id"]
    query_id = stable_id(slug, "dashboard-query")
    widgets, searches, positions, mapping, titles = [], [], {}, {}, {}
    specifications = [
        ("Messages reçus", "*", "numeric", None, 1, 1, 4, 2),
        ("Format non reconnu", "omni_parse_status:unparsed", "numeric", None, 5, 1, 4, 2),
        ("Équipements émetteurs", "*", "table", "source", 9, 1, 4, 4),
        ("Actions normalisées", "*", "table", "event_action", 1, 3, 4, 4),
        ("Adresses sources", "*", "table", "src_ip", 5, 3, 4, 4),
    ]
    for number, (title, query_string, visualization, field, col, row, width, height) in enumerate(specifications):
        wid, sid = stable_id(slug, f"widget-{number}"), stable_id(slug, f"search-{number}")
        query = {"type": "elasticsearch", "query_string": query_string}
        pivots = [] if field is None else [{"type": "values", "fields": [field], "config": {"limit": 15, "skip_empty_values": True}}]
        groups = [] if field is None else [{"type": "values", "fields": [field], "limit": 15, "skip_empty_values": True}]
        # Native WidgetConfigDTO names are lowercase. The web interface uses
        # uppercase constants internally, then lowercases them in Widget.toJSON().
        widgets.append({"id": wid, "type": "aggregation", "filter": None, "filters": [], "timerange": None,
                        "query": query, "streams": [stream_id], "stream_categories": [],
                        "config": {"visualization": visualization, "row_pivots": pivots, "column_pivots": [],
                                   "series": [{"config": {}, "function": "count()"}], "sort": [], "rollup": True,
                                   "event_annotation": False}})
        searches.append({"id": sid, "type": "pivot", "query": query, "streams": [stream_id], "filter": None,
                         "filters": [], "timerange": None, "name": "chart", "series": [{"type": "count", "id": "count()"}],
                         "row_groups": groups, "column_groups": [], "sort": [], "rollup": True})
        positions[wid] = {"col": col, "row": row, "width": width, "height": height}
        mapping[wid], titles[wid] = [sid], title
    wid, sid = stable_id(slug, "widget-logs"), stable_id(slug, "search-logs")
    fields = ["timestamp", "source", "event_action", "src_ip", "dest_ip", "user", "omni_parse_status", "message"]
    widgets.append({"id": wid, "type": "messages", "filter": None, "filters": [], "timerange": None,
                    "query": {"type": "elasticsearch", "query_string": "*"}, "streams": [stream_id],
                    "config": {"fields": fields, "show_message_row": False, "decorators": [], "sort": []}})
    searches.append({"id": sid, "type": "messages", "name": "messages", "query": {"type": "elasticsearch", "query_string": "*"},
                     "streams": [stream_id], "filter": None, "filters": [], "timerange": None,
                     "limit": 50, "offset": 0, "sort": [{"field": "timestamp", "order": "DESC"}], "decorators": []})
    positions[wid] = {"col": 1, "row": 7, "width": 12, "height": 5}
    mapping[wid], titles[wid] = [sid], "Journaux et investigation"
    state = {"selected_fields": None, "static_message_list_id": None, "titles": {"tab": {"title": module["name"]}, "widget": titles},
             "widgets": widgets, "widget_mapping": mapping, "positions": positions,
             "formatting": {"highlighting": []}, "display_mode_settings": {"positions": {}}}
    return {"type": "DASHBOARD", "title": value("OMNI - " + module["name"]), "summary": value("Collecte, qualité du parsing et investigation"),
            "description": value("Module en préversion. Les formats non reconnus restent consultables et comptabilisés."),
            "properties": [], "requires": {}, "created_at": "2026-11-19T00:00:00.000Z",
            "search": {"queries": [{"id": query_id, "timerange": {"type": "relative", "range": 86400},
                                     "filter": None, "filters": [], "query": {"type": "elasticsearch", "query_string": "*"},
                                     "search_types": searches}], "parameters": [], "requires": {}, "created_at": "2026-11-19T00:00:00.000Z"},
            "state": {query_id: state}}


def _pipeline_entities(module, entity, stream):
    stages = pipeline_rules(module)
    for rules in stages:
        for rule in rules:
            entity("rule:" + rule["title"], "pipeline_rule", {"title": value(rule["title"]),
                "description": value("OMNI modular integration"), "source": value(rule["source"])})
    source = 'pipeline ' + json.dumps("OMNI integration - " + module["name"]) + "\n"
    for index, rules in enumerate(stages):
        source += f"stage {index} match either\n" + "".join("  rule " + json.dumps(rule["title"]) + ";\n" for rule in rules)
    source += "end\n"
    entity("pipeline", "pipeline", {"title": value("OMNI integration - " + module["name"]),
        "description": value(module["supported_format"]), "source": value(source), "connected_streams": [value(stream)]})


def build_pack(module):
    slug = module["id"]
    entities = []
    def entity(role, kind, data, version="1"):
        item = {"v": "1", "id": stable_id(slug, role), "type": {"name": kind, "version": version},
                "data": data, "constraints": [{"type": "server-version", "version": ">=7.2.0"}]}
        entities.append(item)
        return item["id"]
    entity("input", "input", {"title": value("OMNI integration - " + module["name"] + " UDP"),
        "type": value("org.graylog2.inputs.raw.udp.RawUDPInput"), "global": value(True), "extractors": [],
        # Graylog InputFacade resolves every static field through asString().
        "static_fields": {"omni_integration_id": value(slug), "omni_module_revision": value(str(module["revision"]))},
        "configuration": {"bind_address": parameter("bind_address"), "port": parameter("port"),
                          "recv_buffer_size": value(1048576), "number_worker_threads": value(2), "charset_name": value("UTF-8")}})
    stream = entity("stream", "stream", {"title": value("OMNI integration - " + module["name"]),
        "description": value(module["supported_format"]), "disabled": value(False), "matching_type": value("AND"),
        "remove_matches": value(True), "default_stream": value(False), "alert_conditions": [], "alarm_callbacks": [], "outputs": [],
        "stream_rules": [{"type": value("EXACT"), "field": value("omni_integration_id"), "value": value(slug),
                          "inverted": value(False), "description": value("Dedicated integration input static field")} ]})
    _pipeline_entities(module, entity, stream)
    entity("dashboard", "dashboard", dashboard(module, stream), "2")
    return {"v": "1", "id": stable_id(slug, "pack"), "rev": module["revision"], "name": "OMNI integration - " + module["name"],
            "summary": "Input, normalization pipeline, stream and dashboard", "description": module["supported_format"] + "; preview, hardware qualification pending",
            "vendor": "OMNI SIEM community", "url": "https://github.com/jmorin-info/omnitech-siem-setup",
            "parameters": [
                {"name": "port", "title": "UDP input port", "description": "Dedicated nonprivileged UDP port", "type": "integer", "default_value": module["default_port"]},
                {"name": "bind_address", "title": "Input bind address", "description": "Use the collection interface address to receive remote devices", "type": "string", "default_value": "127.0.0.1"}],
            "entities": entities}


def build_existing_input_pack(module):
    """Same normalization for a site that already receives the source on its own input.

    No input is created and the site's storage is unchanged: the stream only
    selects the existing input (parameter) and keeps messages in the default stream.
    """
    slug = module["id"]
    entities = []
    def entity(role, kind, data, version="1"):
        item = {"v": "1", "id": stable_id(slug, "existing-input:" + role), "type": {"name": kind, "version": version},
                "data": data, "constraints": [{"type": "server-version", "version": ">=7.2.0"}]}
        entities.append(item)
        return item["id"]
    stream = entity("stream", "stream", {"title": value("OMNI integration - " + module["name"]),
        "description": value(module["supported_format"] + " (existing site input)"), "disabled": value(False),
        "matching_type": value("AND"), "remove_matches": value(False), "default_stream": value(False),
        "alert_conditions": [], "alarm_callbacks": [], "outputs": [],
        "stream_rules": [{"type": value("EXACT"), "field": value("gl2_source_input"), "value": parameter("source_input"),
                          "inverted": value(False), "description": value("Existing site input selected by the site configuration")}]})
    _pipeline_entities(module, entity, stream)
    return {"v": "1", "id": stable_id(slug, "existing-input-pack"), "rev": module["revision"],
            "name": "OMNI integration - " + module["name"] + " (existing input)",
            "summary": "Normalization pipeline and stream for an existing input",
            "description": module["supported_format"] + "; existing input, storage unchanged",
            "vendor": "OMNI SIEM community", "url": "https://github.com/jmorin-info/omnitech-siem-setup",
            "parameters": [{"name": "source_input", "title": "Existing Graylog input ID",
                            "description": "Input that already receives this source (site configuration)",
                            "type": "string", "default_value": "unset"}],
            "entities": entities}


def canonical_pack(pack):
    data = {key: pack[key] for key in ("v", "id", "rev", "name", "summary", "description", "vendor", "url", "parameters", "entities")}
    data["v"] = str(data["v"])
    data["parameters"] = sorted(data["parameters"], key=lambda p: p["name"])
    data["entities"] = sorted(data["entities"], key=lambda e: e["id"])
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(pack):
    return hashlib.sha256(canonical_pack(pack)).hexdigest()


def _normalize(target, item, lowercase=LOWERCASE):
    if target in ("src_ip", "dest_ip") or target.endswith("_ip"):
        try:
            return str(ipaddress.ip_address(str(item)))
        except ValueError:
            return None
    if target.endswith("_port"):
        if not re.fullmatch(r"[0-9]+", str(item)) or not 0 <= int(item) <= 65535:
            return None
        return int(item)
    if target.startswith("bytes_"):
        return int(item) if re.fullmatch(r"[0-9]{1,15}", str(item)) else None
    if target in lowercase:
        return re.sub(" +", "_", str(item)).lower()
    return item


def parse_sample(module, message, existing_fields=None):
    """Offline format contract, not an emulation of the Graylog runtime."""
    parser, raw = module["parser"], {}
    result = {"event_source": module["id"], "omni_parse_status": "unparsed"}
    if parser["type"] == "regex":
        # Every stage-1 rule whose expression matches runs in Graylog.
        for pattern in parser["patterns"]:
            match = re.search(pattern["expression"], message)
            if match:
                for field, item in zip(pattern["fields"], match.groups()):
                    if item not in (None, "") and field not in raw:
                        raw[field] = item
                if not parser.get("kv_fields") and not parser.get("success_fields"):
                    break
        for key, field in parser.get("kv_fields", {}).items():
            match = re.search(kv_expression(key), message)
            if match and match.group(1) != "" and field not in raw:
                raw[field] = match.group(1)
    elif parser["type"] == "csv":
        try:
            cells = next(csv.reader([message], escapechar="\\", strict=True))
        except (csv.Error, StopIteration):
            return result
        if len(cells) >= len(parser["fields"]) and cells[3] == "TRAFFIC":
            raw = dict(zip(parser["fields"], cells))
    else:
        match = re.search(r"CEF:[0-9]+\|Ubiquiti\|UniFi Network\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$", message)
        if match:
            version, event_id, name, severity, extension = match.groups()
            raw = {"device_event_class_id": event_id, "name": name}
            for item in re.finditer(r"(?:^| )([A-Za-z][A-Za-z0-9_]*)=(.*?)(?= [A-Za-z][A-Za-z0-9_]*=|$)", extension):
                raw[item[1]] = item[2]
    if not raw and not existing_fields:
        return result
    for source, target in parser["mapping"].items():
        item = raw.get(source)
        if not item or result.get(target) not in (None, ""):
            continue
        item = _normalize(target, item)
        if item is not None:
            result[target] = item
    for source, target in parser.get("existing_fields", {}).items():
        item = (existing_fields or {}).get(source)
        if item in (None, "") or result.get(target) not in (None, ""):
            continue
        item = _normalize(target, item, ("event_action", "network_protocol"))
        if item is not None:
            result[target] = item
    existing = parser.get("existing_fields", {})
    collector = (any(target == "event_id" and (existing_fields or {}).get(field) for field, target in existing.items())
                 and any(target == "event_action" and (existing_fields or {}).get(field) for field, target in existing.items()))
    if parser.get("success_fields"):
        parsed = all(raw.get(field) for field in parser["success_fields"]) or collector
    else:
        parsed = any(key in result for key in parser["mapping"].values()) or any(
            target in result for target in existing.values())
    if parsed:
        result["omni_parse_status"] = "parsed"
    return result


def produced_fields(module):
    """Fields a module can write; dashboards must reference nothing else."""
    parser = module["parser"]
    fields = {"event_source", "omni_parse_status", "host"} | set(parser["mapping"].values())
    fields |= set(parser.get("existing_fields", {}).values()) | set(module.get("derived_fields", {}))
    return fields | GRAYLOG_FIELDS


def query_fields(query_string):
    """Field names referenced by a Lucene query string (quoted values ignored)."""
    text = re.sub(r'"(?:[^"\\]|\\.)*"', '""', query_string or "")
    fields = set(re.findall(r"_exists_:([A-Za-z_][A-Za-z0-9_]*)", text))
    fields |= {name for name in re.findall(r"(?<![\w.\\])([A-Za-z_][A-Za-z0-9_]*):", text) if name != "_exists_"}
    return fields


def widget_fields(widget):
    fields = query_fields(widget.get("query", ""))
    fields |= {widget[key] for key in ("field", "split") if widget.get(key)}
    return fields | set(widget.get("fields", []))


def check_dashboard_fields(module):
    """Offline contract: every widget of every dashboard uses produced fields only."""
    allowed, problems = produced_fields(module), []
    view = dashboard(module, "stream")
    for state in view["state"].values():
        for widget in state["widgets"]:
            used = query_fields(widget["query"]["query_string"]) | set(widget["config"].get("fields", []))
            used |= {field for pivot in widget["config"].get("row_pivots", []) for field in pivot["fields"]}
            problems += [("OMNI - " + module["name"], state["titles"]["widget"][widget["id"]], field)
                         for field in sorted(used - allowed - {"timestamp"})]
    for spec in module.get("dashboards", []):
        for page in spec["pages"]:
            for widget in page["widgets"]:
                if widget["type"] not in WIDGET_TYPES:
                    raise ValueError("Unknown catalog widget type: " + str(widget["type"]))
                problems += [(spec["title"], widget["title"], field) for field in sorted(widget_fields(widget) - allowed)]
    return problems


def _pivot(field, limit):
    return ({"type": "values", "fields": [field], "config": {"limit": limit, "skip_empty_values": True}},
            {"type": "values", "fields": [field], "limit": limit, "skip_empty_values": True})


def catalog_dashboard(module, spec, stream_id):
    """Native Graylog 7.2 search and view bodies (API format) for one catalog dashboard."""
    slug, key = module["id"], spec["key"]
    queries, states = [], {}
    for page_number, page in enumerate(spec["pages"]):
        query_id = stable_id(slug, f"catalog:{key}:{page_number}:query")
        widgets, searches, positions, mapping, titles = [], [], {}, {}, {}
        for number, item in enumerate(page["widgets"]):
            wid = stable_id(slug, f"catalog:{key}:{page_number}:{number}:widget")
            sid = stable_id(slug, f"catalog:{key}:{page_number}:{number}:search")
            query = {"type": "elasticsearch", "query_string": item.get("query", "")}
            timerange = {"type": "relative", "range": item["range"]} if item.get("range") else None
            common = {"query": query, "streams": [stream_id], "filter": None, "filters": [], "timerange": timerange}
            if item["type"] == "messages":
                widgets.append({"id": wid, "type": "messages", **common,
                                "config": {"fields": item.get("fields", ["timestamp", "source", "message"]),
                                           "show_message_row": True, "decorators": [], "sort": []}})
                searches.append({"id": sid, "type": "messages", "name": "messages", **common, "limit": 50, "offset": 0,
                                 "sort": [{"field": "timestamp", "order": "DESC"}], "decorators": []})
            else:
                rows, row_groups, cols, col_groups = [], [], [], []
                visualization = {"count": "numeric", "terms": "table", "timeline": "bar", "map": "map"}[item["type"]]
                if item["type"] == "timeline":
                    rows = [{"type": "time", "fields": ["timestamp"], "config": {"interval": {"type": "auto", "scaling": 1}}}]
                    row_groups = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}]
                    if item.get("split"):
                        pivot, group = _pivot(item["split"], 8)
                        cols, col_groups = [pivot], [group]
                elif item["type"] in ("terms", "map"):
                    pivot, group = _pivot(item["field"], item.get("limit", 100 if item["type"] == "map" else 15))
                    rows, row_groups = [pivot], [group]
                widgets.append({"id": wid, "type": "aggregation", **common, "stream_categories": [],
                                "config": {"visualization": visualization, "row_pivots": rows, "column_pivots": cols,
                                           "series": [{"config": {}, "function": "count()"}], "sort": [], "rollup": True,
                                           "event_annotation": False}})
                searches.append({"id": sid, "type": "pivot", "name": "chart", **common,
                                 "series": [{"type": "count", "id": "count()"}], "row_groups": row_groups,
                                 "column_groups": col_groups, "sort": [], "rollup": True})
            col, row, width, height = item["pos"]
            positions[wid] = {"col": col, "row": row, "width": width, "height": height}
            mapping[wid], titles[wid] = [sid], item["title"]
        queries.append({"id": query_id, "timerange": {"type": "relative", "range": page.get("range", 86400)},
                        "filter": None, "filters": [], "query": {"type": "elasticsearch", "query_string": ""},
                        "search_types": searches})
        states[query_id] = {"selected_fields": None, "static_message_list_id": None,
                            "titles": {"tab": {"title": page["title"]}, "widget": titles},
                            "widgets": widgets, "widget_mapping": mapping, "positions": positions,
                            "formatting": {"highlighting": []}, "display_mode_settings": {"positions": {}}}
    search = {"queries": queries, "parameters": []}
    view = {"type": "DASHBOARD", "title": spec["title"], "summary": spec.get("summary", ""),
            "description": spec.get("description", "") + " Généré par le catalogue " + slug + " révision "
            + str(module["revision"]) + " ; ne pas modifier à la main.", "properties": [], "requires": {}, "state": states}
    return {"search": search, "view": view}


def catalog_search_types(module, spec):
    """(page, widget, search type id, expected-empty reason) for post-deployment checks."""
    for page_number, page in enumerate(spec["pages"]):
        for number, item in enumerate(page["widgets"]):
            yield (page["title"], item, stable_id(module["id"], f"catalog:{spec['key']}:{page_number}:query"),
                   stable_id(module["id"], f"catalog:{spec['key']}:{page_number}:{number}:search"))


def validate_module(module):
    fixtures = json.loads((CATALOG / module["id"] / "fixtures.json").read_text(encoding="utf-8"))
    for fixture in fixtures:
        result = parse_sample(module, fixture["message"], fixture.get("fields"))
        for key, expected in fixture["expected"].items():
            if result.get(key) != expected:
                raise ValueError(f"{module['id']} fixture mismatch for {key}: {result.get(key)!r} != {expected!r}")
    problems = check_dashboard_fields(module)
    if problems:
        raise ValueError(module["id"] + " dashboards reference fields never produced: "
                         + "; ".join(f"{d} / {w} / {f}" for d, w, f in problems))
    pack = build_pack(module)
    ids = [entity["id"] for entity in pack["entities"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate native pack entity identifiers")
    stream = stable_id(module["id"], "stream")
    view = next(e["data"] for e in pack["entities"] if e["type"]["name"] == "dashboard")
    for state in view["state"].values():
        for widget in state["widgets"]:
            if widget["streams"] != [stream]:
                raise ValueError("Dashboard widget is not scoped to its module stream")
    for spec in module.get("dashboards", []):
        built = catalog_dashboard(module, spec, stream)
        for state in built["view"]["state"].values():
            if set(state["positions"]) != {w["id"] for w in state["widgets"]}:
                raise ValueError("Catalog widget positions do not match widgets")
    return {"id": module["id"], "status": module["status"], "fixtures": len(fixtures), "entities": len(ids),
            "dashboards": len(module.get("dashboards", [])), "sha256": digest(pack)}
