"""Explicit Graylog lifecycle operations with verified TLS and read-only planning."""
from __future__ import annotations
import base64
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .core import build_pack, digest, stable_id, value


class ApiError(RuntimeError):
    def __init__(self, status, operation):
        self.status = status
        super().__init__(f"Graylog {operation}: HTTP {status}; inspect server logs (response body omitted)")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ApiError(code, "redirect refused")


class Graylog:
    def __init__(self, api, token, ca=None):
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
        self.authorization = "Basic " + base64.b64encode((token + ":token").encode()).decode()
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
    inputs = client.call("GET", "/system/inputs")["inputs"]
    for source in inputs:
        if source.get("title") == "OMNI integration - " + module["name"] + " UDP":
            raise ValueError("A module input already exists without its tracked installation; inspect partial deployment")
        attributes = source.get("attributes", source.get("configuration", {}))
        if "udp" in source.get("type", "").lower() and attributes.get("port") == params["port"]["@value"]:
            raise ValueError("A Graylog UDP input already uses this port; select a dedicated port")
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
    return {"action": "install", "module": module["id"], "revision": pack["rev"], "sha256": digest(pack),
            "upload_required": remote is None, "parameters": params, "qualification": "preview; hardware validation pending",
            "storage": "default Graylog index set and its retention policy",
            "network": "dedicated raw UDP input; firewall and Docker port publication are managed separately"}


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
    owned = [entity for entity in installation.get("entities", [])
             if entity.get("content_pack_entity_id") == stable_id(module["id"], "stream")
             and entity.get("type", {}).get("name") == "stream" and entity.get("found_on_system") is False]
    if len(owned) != 1 or not re.fullmatch(r"[a-f0-9]{24}", owned[0].get("id", "")):
        raise RuntimeError("Pack installed but owned stream could not be identified; inspect Content Packs before retrying")
    client.call("POST", "/streams/" + owned[0]["id"] + "/resume")
    plan["action"], plan["installation_id"] = "installed", installation.get("_id")
    return plan


def uninstall(client, module, installation_id, *, apply=False):
    if not re.fullmatch(r"[a-f0-9]{24}", installation_id):
        raise ValueError("Use the exact Graylog installation ID")
    pack = build_pack(module)
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
