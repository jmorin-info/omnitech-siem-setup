"""Explicit Graylog lifecycle operations with verified TLS and read-only planning."""
from __future__ import annotations
import base64
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import os
from pathlib import Path

from .core import (build_existing_input_pack, build_pack, catalog_dashboard, catalog_search_types, digest,
                   stable_id, value, widget_fields)


class ApiError(RuntimeError):
    def __init__(self, status, operation):
        self.status = status
        super().__init__(f"Graylog {operation}: HTTP {status}; inspect server logs (response body omitted)")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ApiError(code, "redirect refused")


class Graylog:
    def __init__(self, api, token, ca=None, username=None):
        parsed = urllib.parse.urlsplit(api)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
            raise ValueError("API URL must not contain credentials, query or fragment")
        if parsed.scheme != "https":
            if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("Use HTTPS with verified TLS, or an explicit loopback SSH tunnel")
        if not token or any(c in token for c in "\r\n"):
            raise ValueError("A nonempty API token environment variable is required")
        if not parsed.path.rstrip("/").endswith("/api"):
            raise ValueError("Graylog API URL must end in /api")
        self.api = api.rstrip("/")
        # With a username, the secret variable holds that account's password
        # (local loopback administration); otherwise it is an API access token.
        if username is not None and not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
            raise ValueError("Invalid Graylog username")
        credentials = (username + ":" + token) if username else (token + ":token")
        self.authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        context = ssl.create_default_context(cafile=ca)
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def call(self, method, path, body=None):
        if not path.startswith("/") or ".." in path:
            raise ValueError("Invalid API path")
        request = urllib.request.Request(self.api + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": self.authorization, "Accept": "application/json",
                     "Content-Type": "application/json", "X-Requested-By": "omni-integrations"})
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(16 * 1024 * 1024 + 1)
                if len(data) > 16 * 1024 * 1024:
                    raise ValueError("Graylog response exceeds size limit")
                return json.loads(data) if data else None
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, method + " " + path) from None
        except urllib.error.URLError:
            raise RuntimeError("Graylog connection or TLS verification failed") from None


def parameters(module, port=None, bind="127.0.0.1"):
    port = module["default_port"] if port is None else port
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("Input port must be an integer between 1024 and 65535")
    ipaddress.ip_address(bind)
    return {"port": value(port), "bind_address": value(bind)}


def _existing_pack(client, pack):
    try:
        remote = client.call("GET", f"/system/content_packs/{pack['id']}/{pack['rev']}/download")
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise
    if digest(remote) != digest(pack):
        raise ValueError("A content pack with this ID/revision has different content; publish a new revision, never overwrite")
    return remote


def _installations(client, pack):
    response = client.call("GET", f"/system/content_packs/{pack['id']}/installations")
    if not isinstance(response, dict) or not isinstance(response.get("installations"), list):
        raise ValueError("Unexpected content pack installations response")
    return response["installations"]


def plan_install(client, module, params):
    """GET only. No upload, stream activation, database writes or log injection."""
    pack = build_pack(module)
    version = client.call("GET", "/system").get("version", "")
    if not re.match(r"^7\.2\.", version):
        raise ValueError("This manager targets Graylog 7.2.x; review compatibility for " + version)
    remote = _existing_pack(client, pack)
    installed = _installations(client, pack)
    if installed:
        if len(installed) != 1:
            raise ValueError("Multiple module installations already exist; reconcile manually")
        installation = installed[0]
        if installation.get("content_pack_revision") != pack["rev"] or installation.get("parameters") != params:
            raise ValueError("Module is installed with another revision/parameters; no automatic destructive upgrade")
        if remote is None:
            raise ValueError("Installation references a missing pack revision")
        return {"action": "already-installed", "module": module["id"], "revision": pack["rev"], "sha256": digest(pack),
                "installation_id": installation.get("_id"), "parameters": params}
    _check_processors(client)
    inputs = client.call("GET", "/system/inputs")["inputs"]
    for source in inputs:
        if source.get("title") == "OMNI integration - " + module["name"] + " UDP":
            raise ValueError("A module input already exists without its tracked installation; inspect partial deployment")
        attributes = source.get("attributes", source.get("configuration", {}))
        if "udp" in source.get("type", "").lower() and attributes.get("port") == params["port"]["@value"]:
            raise ValueError("A Graylog UDP input already uses this port; select a dedicated port")
    _check_titles(client, module, pack)
    return {"action": "install", "module": module["id"], "revision": pack["rev"], "sha256": digest(pack),
            "upload_required": remote is None, "parameters": params, "qualification": "preview; hardware validation pending",
            "storage": "default Graylog index set and its retention policy",
            "network": "dedicated raw UDP input; firewall and Docker port publication are managed separately"}


def _check_processors(client):
    order = client.call("GET", "/system/messageprocessors/config")
    names = [entry["name"] for entry in order.get("processor_order", [])]
    disabled = order.get("disabled_processors", [])
    pipeline_entries = [entry for entry in order.get("processor_order", []) if entry.get("name") == "Pipeline Processor"]
    if not pipeline_entries or "Pipeline Processor" in disabled or pipeline_entries[0].get("class_name") in disabled:
        raise ValueError("Pipeline Processor must be enabled")
    routing = [entry for entry in order.get("processor_order", []) if entry.get("name") == "Stream Rule Processor"]
    if not routing or routing[0].get("class_name") in disabled or "Stream Rule Processor" in disabled:
        raise ValueError("Stream Rule Processor must be enabled before Pipeline Processor")
    if names.index("Stream Rule Processor") > names.index("Pipeline Processor"):
        raise ValueError("Stream routing must run before Pipeline Processor; configuration will not be changed automatically")
    filters = [entry for entry in order.get("processor_order", []) if entry.get("name") == "Message Filter Chain"]
    if (not filters or filters[0].get("class_name") in disabled or "Message Filter Chain" in disabled
            or names.index("Message Filter Chain") > names.index("Stream Rule Processor")):
        raise ValueError("Message Filter Chain must be enabled before stream routing to attach input static fields; configuration will not be changed automatically")


def _check_titles(client, module, pack):
    streams = client.call("GET", "/streams")["streams"]
    if any(item.get("title") == "OMNI integration - " + module["name"] for item in streams):
        raise ValueError("A stream with the module title already exists without its tracked installation")
    for path, kind in (("/system/pipelines/rule", "pipeline_rule"), ("/system/pipelines/pipeline", "pipeline")):
        existing = client.call("GET", path)
        if not isinstance(existing, list):
            raise ValueError("Unexpected pipeline inventory response")
        expected = {item["data"]["title"]["@value"] for item in pack["entities"] if item["type"]["name"] == kind}
        if any(item.get("title") in expected for item in existing):
            raise ValueError("A module pipeline/rule already exists without its tracked installation; inspect partial deployment")


def _start_new_input(client, input_id):
    """Clean up only this newly owned input, with bounded metric-race recovery.

    Static-field updates can leave metrics from a competing native launch. A
    failed launch registers those names in its local registry, so stopping that
    failed instance removes them. Retry only this exact worker-metric collision;
    bind, authentication and configuration errors remain failures.
    """
    path = "/system/inputstates/" + input_id
    def state():
        try:
            response = client.call("GET", path)
            if not isinstance(response, dict) or response.get("id") != input_id:
                raise ValueError("Unexpected native input state response")
            return response.get("state"), response.get("detailed_message", "")
        except ApiError as exc:
            if exc.status != 404:
                raise
            return "NOT_FOUND", ""

    # Metrics 4.2.39 registers seven worker gauges; allow their cleanup and a start.
    for attempt in range(8):
        # This endpoint stops the runtime; it never deletes the saved input.
        client.call("DELETE", path)
        absent = 0
        for _ in range(60):
            current, _ = state()
            absent = absent + 1 if current == "NOT_FOUND" else 0
            if absent >= 6:
                break
            time.sleep(1)
        else:
            raise RuntimeError("New module input did not stop cleanly; inspect System > Inputs before retrying")

        client.call("PUT", path)
        previous, stable = None, 0
        for _ in range(60):
            current, detail = state()
            stable = stable + 1 if current == previous else 1
            previous = current
            if current == "RUNNING" and stable >= 6:
                return
            if current in ("FAILED", "STOPPED", "TERMINATED", "NOT_FOUND") and stable >= 3:
                own_metric_collision = (current == "FAILED" and isinstance(detail, str)
                    and "metric named " in detail and "already exists" in detail
                    and "." + input_id + ".workers.executor-service." in detail)
                if own_metric_collision and attempt < 7:
                    break
                raise RuntimeError("New module input failed to start; inspect System > Inputs before retrying")
            time.sleep(1)
        else:
            raise RuntimeError("New module input did not become RUNNING; inspect System > Inputs before retrying")


def install(client, module, params, *, apply=False):
    plan = plan_install(client, module, params)
    if not apply or plan["action"] == "already-installed":
        return plan
    pack = build_pack(module)
    if plan["upload_required"]:
        client.call("POST", "/system/content_packs", pack)
    # The native content pack service tracks ownership for a later uninstall.
    installation = client.call("POST", f"/system/content_packs/{pack['id']}/{pack['rev']}/installations", {
        "entity": {"parameters": params, "comment": "OMNI integration " + digest(pack)},
        "share_request": {"selected_grantee_capabilities": {}}})
    # Graylog 7.2 StreamFacade creates streams paused regardless of disabled=false.
    # Activate only the newly installed, owned stream; an existing paused stream is preserved.
    owned = {}
    for kind in ("stream", "input"):
        entities = [entity for entity in installation.get("entities", [])
                    if entity.get("content_pack_entity_id") == stable_id(module["id"], kind)
                    and entity.get("type", {}).get("name") == kind and entity.get("found_on_system") is False]
        if len(entities) != 1 or not re.fullmatch(r"[a-f0-9]{24}", entities[0].get("id", "")):
            raise RuntimeError("Pack installed but owned " + kind + " could not be identified; inspect Content Packs before retrying")
        owned[kind] = entities[0]["id"]
    client.call("POST", "/streams/" + owned["stream"] + "/resume")
    _start_new_input(client, owned["input"])
    plan["action"], plan["installation_id"] = "installed", installation.get("_id")
    return plan


def uninstall(client, module, installation_id, *, apply=False, existing_input=False):
    if not re.fullmatch(r"[a-f0-9]{24}", installation_id):
        raise ValueError("Use the exact Graylog installation ID")
    pack = build_existing_input_pack(module) if existing_input else build_pack(module)
    installed = _installations(client, pack)
    matches = [item for item in installed if item.get("_id") == installation_id]
    if len(matches) != 1:
        raise ValueError("Installation does not belong to this module")
    path = f"/system/content_packs/{pack['id']}/installations/{installation_id}"
    details = client.call("GET", path + "/uninstall_details")
    plan = {"action": "uninstall", "module": module["id"], "installation_id": installation_id,
            "details": details, "logs": "Indexed messages are retained under the existing index retention policy"}
    if apply:
        client.call("DELETE", path)
        plan["action"] = "uninstalled"
    return plan


OBJECT_ID = re.compile(r"[a-f0-9]{24}")


def load_site_config(path, module_id):
    """Site-owned settings kept outside Git: existing input and dashboards replaced in place."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported site configuration schema")
    site = data.get("integrations", {}).get(module_id)
    if not isinstance(site, dict):
        raise ValueError("Module absent from the site configuration")
    if site.get("source_input") is not None and not OBJECT_ID.fullmatch(str(site["source_input"])):
        raise ValueError("source_input must be a Graylog input ID")
    bindings = site.get("dashboards", {})
    if not isinstance(bindings, dict) or any(not OBJECT_ID.fullmatch(str(item)) for item in bindings.values()):
        raise ValueError("dashboards must map catalog keys to Graylog view IDs")
    return site


def plan_existing_input(client, module, site):
    """GET only: normalize a source that a site input already receives (no input, storage unchanged)."""
    if not site.get("source_input"):
        raise ValueError("source_input is required in the site configuration")
    pack = build_existing_input_pack(module)
    params = {"source_input": value(site["source_input"])}
    version = client.call("GET", "/system").get("version", "")
    if not re.match(r"^7\.2\.", version):
        raise ValueError("This manager targets Graylog 7.2.x; review compatibility for " + version)
    remote = _existing_pack(client, pack)
    installed = _installations(client, pack)
    if installed:
        if len(installed) != 1:
            raise ValueError("Multiple module installations already exist; reconcile manually")
        installation = installed[0]
        if installation.get("content_pack_revision") != pack["rev"] or installation.get("parameters") != params:
            raise ValueError("Module is installed with another revision/parameters; no automatic destructive upgrade")
        return {"action": "already-installed", "mode": "existing-input", "module": module["id"], "revision": pack["rev"],
                "sha256": digest(pack), "installation_id": installation.get("_id"), "parameters": params}
    _check_processors(client)
    source = client.call("GET", "/system/inputs/" + site["source_input"])
    _check_titles(client, module, pack)
    return {"action": "install", "mode": "existing-input", "module": module["id"], "revision": pack["rev"],
            "sha256": digest(pack), "upload_required": remote is None, "parameters": params,
            "input": source.get("title"), "storage": "unchanged: messages stay in their index set and default stream"}


def install_existing_input(client, module, site, *, apply=False):
    plan = plan_existing_input(client, module, site)
    if not apply or plan["action"] == "already-installed":
        return plan
    pack = build_existing_input_pack(module)
    if plan["upload_required"]:
        client.call("POST", "/system/content_packs", pack)
    installation = client.call("POST", f"/system/content_packs/{pack['id']}/{pack['rev']}/installations", {
        "entity": {"parameters": plan["parameters"], "comment": "OMNI integration existing input " + digest(pack)},
        "share_request": {"selected_grantee_capabilities": {}}})
    streams = [entity for entity in installation.get("entities", [])
               if entity.get("content_pack_entity_id") == stable_id(module["id"], "existing-input:stream")
               and entity.get("type", {}).get("name") == "stream" and entity.get("found_on_system") is False]
    if len(streams) != 1 or not OBJECT_ID.fullmatch(streams[0].get("id", "")):
        raise RuntimeError("Pack installed but owned stream could not be identified; inspect Content Packs before retrying")
    client.call("POST", "/streams/" + streams[0]["id"] + "/resume")
    plan.update(action="installed", installation_id=installation.get("_id"), stream_id=streams[0]["id"])
    return plan


def _module_stream(client, module):
    title = "OMNI integration - " + module["name"]
    found = [item for item in client.call("GET", "/streams")["streams"] if item.get("title") == title]
    if len(found) != 1:
        raise ValueError("Install the module first: stream '" + title + "' must exist exactly once")
    return found[0]["id"]


def _new_object_id():
    return "%08x" % int(time.time()) + os.urandom(8).hex()


def plan_dashboards(client, module, site):
    """GET only: catalog dashboards to create, or to replace in place when the site binds a view."""
    stream = _module_stream(client, module)
    response = client.call("GET", "/views?per_page=1000")
    views = {item["id"]: item for item in response.get("views", response.get("elements", []))}
    bindings = site.get("dashboards", {})
    unknown = set(bindings) - {spec["key"] for spec in module.get("dashboards", [])}
    if unknown:
        raise ValueError("Unknown catalog dashboard keys in site configuration: " + ", ".join(sorted(unknown)))
    items = []
    for spec in module.get("dashboards", []):
        target = bindings.get(spec["key"])
        if target and target not in views:
            raise ValueError("View bound in the site configuration not found: " + target)
        if not target:
            same = [item["id"] for item in views.values() if item.get("title") == spec["title"]]
            if len(same) > 1:
                raise ValueError("Several views are titled " + spec["title"])
            target = same[0] if same else None
        if target and views[target].get("type") != "DASHBOARD":
            raise ValueError("Bound view is not a dashboard: " + target)
        items.append({"key": spec["key"], "title": spec["title"], "action": "update" if target else "create",
                      "view_id": target, "current_title": views[target].get("title") if target else None})
    return {"module": module["id"], "revision": module["revision"], "stream_id": stream, "dashboards": items}


def deploy_dashboards(client, module, site, *, apply=False, backup_dir=None):
    plan = plan_dashboards(client, module, site)
    if not apply:
        return plan
    if not backup_dir:
        raise ValueError("--backup-dir is required with --apply")
    backup = Path(backup_dir)
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = dict(plan, items=[], backup_dir=str(backup))
    def save():
        (backup / "state.json").write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    originals = {}
    for item in plan["dashboards"]:
        if item["view_id"]:
            original = client.call("GET", "/views/" + item["view_id"])
            search = client.call("GET", "/views/search/" + original["search_id"])
            originals[item["view_id"]] = original
            (backup / ("view-" + item["view_id"] + ".json")).write_text(
                json.dumps({"view": original, "search": search}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    save()
    specs = {spec["key"]: spec for spec in module["dashboards"]}
    for item in plan["dashboards"]:
        built = catalog_dashboard(module, specs[item["key"]], plan["stream_id"])
        # Graylog searches are immutable: publish a new one, then point the view at it.
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


def restore_dashboards(client, backup_dir, *, apply=False):
    """Undo one deployment by ID: restore replaced views, delete created ones."""
    backup = Path(backup_dir)
    state = json.loads((backup / "state.json").read_text(encoding="utf-8"))
    actions = []
    for item in reversed(state["items"]):
        if item["action"] == "updated":
            saved = json.loads((backup / item["backup"]).read_text(encoding="utf-8"))
            actions.append({"view_id": item["view_id"], "action": "restore", "title": saved["view"].get("title")})
            if apply:
                # The original search may have been purged once unreferenced: republish it.
                search_id = _new_object_id()
                client.call("POST", "/views/search", dict(saved["search"], id=search_id))
                view = {key: item_value for key, item_value in saved["view"].items() if key != "favorite"}
                client.call("PUT", "/views/" + item["view_id"], {"entity": dict(view, search_id=search_id)})
        elif item["action"] == "created":
            actions.append({"view_id": item["view_id"], "action": "delete"})
            if apply:
                client.call("DELETE", "/views/" + item["view_id"])
    return {"backup_dir": str(backup), "applied": apply, "actions": actions}


def check_dashboards(client, module, site, *, days=1, wait_seconds=120):
    """Post-deployment control: run every catalog widget, report empty widgets and absent fields."""
    plan = plan_dashboards(client, module, site)
    try:
        response = client.call("POST", "/views/fields", {"streams": [plan["stream_id"]],
                                                         "timerange": {"type": "relative", "range": days * 86400}})
        present = {item.get("name") for item in response} if isinstance(response, list) else None
    except ApiError:
        present = None
    specs = {spec["key"]: spec for spec in module["dashboards"]}
    report, failures = [], 0
    for item in plan["dashboards"]:
        if not item["view_id"]:
            report.append({"dashboard": item["title"], "status": "not-deployed"})
            failures += 1
            continue
        view = client.call("GET", "/views/" + item["view_id"])
        job = client.call("POST", "/views/search/" + view["search_id"] + "/execute", {})
        for _ in range(wait_seconds):
            if (job.get("execution") or {}).get("done"):
                break
            time.sleep(1)
            job = client.call("GET", "/views/search/status/" + job["id"])
        errors = {error.get("search_type_id") for error in job.get("errors", [])}
        for page, widget, query_id, search_type in catalog_search_types(module, specs[item["key"]]):
            result = (job.get("results", {}).get(query_id) or {}).get("search_types", {}).get(search_type)
            total = None if result is None else result.get("total_results", result.get("total"))
            if result is not None and widget["type"] in ("terms", "map") and isinstance(result.get("rows"), list):
                # A breakdown is only useful with values: count non-empty buckets, not matching documents.
                total = sum(1 for row in result["rows"] if row.get("key"))
            missing = sorted(widget_fields(widget) - present) if present is not None else []
            if search_type in errors or result is None:
                status = "error"
            elif total:
                status = "ok"
            else:
                status = "expected-empty" if widget.get("may_be_empty") else "empty"
            entry = {"dashboard": item["title"], "page": page, "widget": widget["title"], "status": status, "total": total}
            if missing:
                entry["fields_absent"] = missing
            if widget.get("may_be_empty") and status == "expected-empty":
                entry["reason"] = widget["may_be_empty"]
            if status in ("error", "empty"):
                failures += 1
            report.append(entry)
    return {"module": module["id"], "stream_id": plan["stream_id"], "days": days, "failures": failures, "widgets": report}
