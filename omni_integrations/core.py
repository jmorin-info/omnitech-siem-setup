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
    field_names = list(data["parser"]["mapping"]) + list(data["parser"]["mapping"].values())
    field_names += data["parser"].get("fields", [])
    field_names += list(data["parser"].get("existing_fields", {}))
    field_names += [field for pattern in data["parser"].get("patterns", []) for field in pattern["fields"]]
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field) for field in field_names):
        raise ValueError("Mapping/parse fields must be valid pipeline identifiers")
    for pattern in data["parser"].get("patterns", []):
        if re.compile(pattern["expression"]).groups != len(pattern["fields"]):
            raise ValueError("Regex capture count does not match fields")
    if not 1024 <= data["default_port"] <= 65535:
        raise ValueError("Invalid nonprivileged input port")
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


def pipeline_rules(module):
    """Only documented core functions; raw vendor fields are always namespaced."""
    slug, parser = module["id"], module["parser"]
    prefix = slug.replace("-", "_") + "_"
    stem = f"omni-integration-{slug}-r{module['revision']}"
    stages = [[], [], [], []]
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
    stages[2].append(_rule(stem + "-parsed", success, ['set_field("omni_parse_status", "parsed");']))
    for raw, canonical in parser["mapping"].items():
        field = prefix + raw
        condition = f'has_field("{field}") AND to_string($message.{field}) != ""'
        expression = f"to_string($message.{field})"
        if canonical in ("src_ip", "dest_ip"):
            condition += f" AND is_ip(to_ip({expression}))"
            expression = f"to_ip({expression})"
        elif canonical in ("src_port", "dest_port"):
            condition += f' AND regex("^[0-9]+$", to_string($message.{field})).matches == true'
            condition += f" AND to_long($message.{field}) >= 0 AND to_long($message.{field}) <= 65535"
            expression = f"to_long($message.{field})"
        elif canonical in ("event_action", "network_protocol", "event_category"):
            expression = f'lowercase(regex_replace(" +", {expression}, "_", true))'
        stages[3].append(_rule(stem + "-map-" + raw.lower(), condition, [f'set_field("{canonical}", {expression});']))
    # Some collectors or vendor extractors already populate raw Graylog fields.
    # Preserve those fields and fill the common model only when it is absent.
    for raw, canonical in parser.get("existing_fields", {}).items():
        field = prefix + "existing-" + raw
        condition = f'has_field("{raw}") AND to_string($message.{raw}) != "" AND !has_field("{canonical}")'
        expression = f"to_string($message.{raw})"
        if canonical in ("src_ip", "dest_ip"):
            condition += f" AND is_ip(to_ip({expression}))"
            expression = f"to_ip({expression})"
        elif canonical in ("src_port", "dest_port"):
            condition += f' AND regex("^[0-9]+$", to_string($message.{raw})).matches == true'
            condition += f" AND to_long($message.{raw}) >= 0 AND to_long($message.{raw}) <= 65535"
            expression = f"to_long($message.{raw})"
        elif canonical in ("event_action", "network_protocol"):
            expression = f'lowercase(regex_replace(" +", {expression}, "_", true))'
        stages[3].append(_rule(stem + "-existing-" + raw.lower(), condition,
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
    entity("dashboard", "dashboard", dashboard(module, stream), "2")
    return {"v": "1", "id": stable_id(slug, "pack"), "rev": module["revision"], "name": "OMNI integration - " + module["name"],
            "summary": "Input, normalization pipeline, stream and dashboard", "description": module["supported_format"] + "; preview, hardware qualification pending",
            "vendor": "OMNI SIEM community", "url": "https://github.com/jmorin-info/omnitech-siem-setup",
            "parameters": [
                {"name": "port", "title": "UDP input port", "description": "Dedicated nonprivileged UDP port", "type": "integer", "default_value": module["default_port"]},
                {"name": "bind_address", "title": "Input bind address", "description": "Use the collection interface address to receive remote devices", "type": "string", "default_value": "127.0.0.1"}],
            "entities": entities}


def canonical_pack(pack):
    data = {key: pack[key] for key in ("v", "id", "rev", "name", "summary", "description", "vendor", "url", "parameters", "entities")}
    data["v"] = str(data["v"])
    data["parameters"] = sorted(data["parameters"], key=lambda p: p["name"])
    data["entities"] = sorted(data["entities"], key=lambda e: e["id"])
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(pack):
    return hashlib.sha256(canonical_pack(pack)).hexdigest()


def parse_sample(module, message, existing_fields=None):
    """Offline format contract, not an emulation of the Graylog runtime."""
    parser, raw = module["parser"], {}
    result = {"event_source": module["id"], "omni_parse_status": "unparsed"}
    if parser["type"] == "regex":
        for pattern in parser["patterns"]:
            match = re.search(pattern["expression"], message)
            if match:
                raw = dict(zip(pattern["fields"], match.groups()))
                break
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
        if not item:
            continue
        if target in ("src_ip", "dest_ip"):
            try:
                item = str(ipaddress.ip_address(item))
            except ValueError:
                continue
        elif target in ("src_port", "dest_port"):
            try:
                item = int(item)
            except ValueError:
                continue
            if not 0 <= item <= 65535:
                continue
        elif target in ("event_action", "event_category", "network_protocol"):
            item = re.sub(" +", "_", item).lower()
        result[target] = item
    for source, target in parser.get("existing_fields", {}).items():
        item = (existing_fields or {}).get(source)
        if item in (None, "") or result.get(target) not in (None, ""):
            continue
        if target in ("src_ip", "dest_ip"):
            try:
                item = str(ipaddress.ip_address(str(item)))
            except ValueError:
                continue
        elif target in ("src_port", "dest_port"):
            try:
                item = int(item)
            except (ValueError, TypeError):
                continue
            if not 0 <= item <= 65535:
                continue
        elif target in ("event_action", "network_protocol"):
            item = re.sub(" +", "_", str(item)).lower()
        result[target] = item
    if any(key in result for key in parser["mapping"].values()) or any(
            target in result for target in parser.get("existing_fields", {}).values()):
        result["omni_parse_status"] = "parsed"
    return result


def validate_module(module):
    fixtures = json.loads((CATALOG / module["id"] / "fixtures.json").read_text(encoding="utf-8"))
    for fixture in fixtures:
        result = parse_sample(module, fixture["message"], fixture.get("fields"))
        for key, expected in fixture["expected"].items():
            if result.get(key) != expected:
                raise ValueError(f"{module['id']} fixture mismatch for {key}: {result.get(key)!r} != {expected!r}")
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
    return {"id": module["id"], "status": module["status"], "fixtures": len(fixtures), "entities": len(ids), "sha256": digest(pack)}
