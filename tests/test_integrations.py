"""Portable pack contracts and lifecycle safety; no Graylog/network required."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_integrations.core import catalog, load_module, build_pack, validate_module, pipeline_rules, digest, stable_id, parse_sample
from omni_integrations.client import Graylog, ApiError, parameters, install, uninstall


@pytest.mark.parametrize("module", catalog(), ids=lambda item: item["id"])
def test_fixtures_and_native_dependency_contract(module):
    report = validate_module(module)
    assert report["fixtures"] >= 3
    pack = build_pack(module)
    assert pack == build_pack(module)  # stable identities and reproducible artifacts
    assert pack["v"] == "1" and pack["rev"] == module["revision"]
    entities = pack["entities"]
    kinds = {e["type"]["name"] for e in entities}
    assert kinds == {"input", "stream", "pipeline", "pipeline_rule", "dashboard"}
    input_data = next(e["data"] for e in entities if e["type"]["name"] == "input")
    # InputFacade.addStaticFields resolves values using ValueReference.asString.
    assert all(item["@type"] == "string" and isinstance(item["@value"], str)
               for item in input_data["static_fields"].values())
    stream_id = stable_id(module["id"], "stream")
    pipeline = next(e["data"] for e in entities if e["type"]["name"] == "pipeline")
    assert pipeline["connected_streams"] == [{"@type": "string", "@value": stream_id}]
    rules = [e["data"] for e in entities if e["type"]["name"] == "pipeline_rule"]
    for rule in rules:
        assert 'rule "' + rule["title"]["@value"] + '";' in pipeline["source"]["@value"]
    assert all(pipeline_rules(module))  # no empty stage can stop normalization
    generated_source = "\n".join(rule["source"] for stage in pipeline_rules(module) for rule in stage)
    assert "set_fields(parsed" not in generated_source  # Graylog forbids mixing positional/named arguments
    assert "csv_to_map(to_string" not in generated_source
    view = next(e for e in entities if e["type"]["name"] == "dashboard")
    assert view["type"]["version"] == "2"
    # Content Pack MessageListEntity has no fields property; columns belong to
    # the message-list widget config, unlike a native saved-search request.
    for query in view["data"]["search"]["queries"]:
        for search_type in query["search_types"]:
            if search_type["type"] == "messages":
                assert "fields" not in search_type
    query_ids = {q["id"] for q in view["data"]["search"]["queries"]}
    assert set(view["data"]["state"]) == query_ids
    for state in view["data"]["state"].values():
        assert len(state["widgets"]) == 6
        # Graylog 7.2 WidgetEntity uses the outer type as its WidgetConfigDTO
        # discriminator: native names are lowercase, unlike UI class constants.
        assert [w["type"] for w in state["widgets"]] == ["aggregation"] * 5 + ["messages"]
        assert {w["id"] for w in state["widgets"]} == set(state["positions"])
        assert all(w["streams"] == [stream_id] for w in state["widgets"])
    encoded = json.dumps(pack)
    assert "10.33." not in encoded and "bx-it-graylog" not in encoded
    assert "000000000000000000000001" not in encoded
    assert "notification" not in kinds  # installation cannot begin mailing or SOAR


def test_digest_ignores_native_set_order_but_detects_code_changes():
    pack = build_pack(load_module("watchguard"))
    shuffled = copy.deepcopy(pack)
    shuffled["entities"].reverse()
    shuffled["parameters"].reverse()
    assert digest(pack) == digest(shuffled)
    shuffled["entities"][0]["data"]["title"]["@value"] += " modified"
    assert digest(pack) != digest(shuffled)


def test_invalid_ip_and_port_never_become_normalized_values():
    module = load_module("unifi")
    line = "CEF:0|Ubiquiti|UniFi Network|1|201|Example|7|src=999.1.1.1 spt=invalid dpt=70000"
    parsed = parse_sample(module, line)
    assert "src_ip" not in parsed and "src_port" not in parsed and "dest_port" not in parsed


@pytest.mark.parametrize("api", ["http://example.test/api", "https://user:secret@example.test/api", "https://example.test/api?secret=x", "https://example.test"])
def test_api_rejects_unsafe_connection(api):
    with pytest.raises(ValueError):
        Graylog(api, "dummy-token")


class FakeGraylog:
    def __init__(self, *, installed=None, remote=None, conflict=False):
        self.calls = []
        self.installed = installed or []
        self.remote = remote
        self.conflict = conflict

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/system":
            return {"version": "7.2.2+test"}
        if method == "GET" and path.endswith("/download"):
            if self.remote is None:
                raise ApiError(404, "GET")
            return self.remote
        if method == "GET" and path.endswith("/installations"):
            return {"total": len(self.installed), "installations": self.installed}
        if path == "/system/messageprocessors/config":
            return {"processor_order": [{"name": "Message Filter Chain", "class_name": "chain"},
                                         {"name": "Stream Rule Processor", "class_name": "stream"},
                                         {"name": "Pipeline Processor", "class_name": "pipeline"}], "disabled_processors": []}
        if path == "/system/inputs":
            return {"inputs": [{"type": "RawUDPInput", "attributes": {"port": 1521}}] if self.conflict else []}
        if path == "/streams":
            return {"streams": []}
        if path in ("/system/pipelines/rule", "/system/pipelines/pipeline"):
            return []
        if method == "POST" and path.endswith("/installations"):
            return {"_id": "a" * 24, "entities": [{"content_pack_entity_id": stable_id("watchguard", "stream"),
                "id": "b" * 24, "type": {"name": "stream", "version": "1"}, "found_on_system": False}]}
        if method == "POST" and (path == "/system/content_packs" or path.endswith("/resume")):
            return {}
        if method == "GET" and path.endswith("/uninstall_details"):
            return {"entities": []}
        if method == "DELETE":
            return {}
        raise AssertionError((method, path))


def test_install_defaults_to_read_only_plan():
    client = FakeGraylog()
    module = load_module("watchguard")
    plan = install(client, module, parameters(module))
    assert plan["action"] == "install"
    assert plan["upload_required"] is True
    assert {method for method, _, _ in client.calls} == {"GET"}


def test_apply_uploads_then_installs_then_only_activates_owned_stream():
    client, module = FakeGraylog(), load_module("watchguard")
    plan = install(client, module, parameters(module), apply=True)
    assert plan["action"] == "installed"
    writes = [(method, path) for method, path, _ in client.calls if method != "GET"]
    pack = build_pack(module)
    assert writes == [("POST", "/system/content_packs"),
                      ("POST", f"/system/content_packs/{pack['id']}/1/installations"),
                      ("POST", "/streams/" + "b" * 24 + "/resume")]
    request = [body for method, path, body in client.calls if method == "POST" and path.endswith("/installations")][0]
    assert request["entity"]["parameters"] == parameters(module)
    assert request["share_request"] == {"selected_grantee_capabilities": {}}


def test_identical_installed_module_is_idempotent_even_with_apply():
    module = load_module("watchguard")
    client = FakeGraylog(remote=build_pack(module), installed=[{"_id": "a" * 24, "content_pack_revision": 1, "parameters": parameters(module)}])
    assert install(client, module, parameters(module), apply=True)["action"] == "already-installed"
    assert {method for method, _, _ in client.calls} == {"GET"}


@pytest.mark.parametrize("scenario", ["changed-pack", "port-conflict", "other-revision", "other-parameters"])
def test_conflicts_abort_before_any_write(scenario):
    module = load_module("watchguard")
    client = FakeGraylog(conflict=scenario == "port-conflict")
    if scenario == "changed-pack":
        client.remote = build_pack(module)
        client.remote["summary"] += " altered"
    elif scenario in ("other-revision", "other-parameters"):
        client.remote = build_pack(module)
        client.installed = [{"content_pack_revision": 2 if scenario == "other-revision" else 1,
                             "parameters": parameters(module, port=1524 if scenario == "other-parameters" else 1521)}]
    with pytest.raises(ValueError):
        install(client, module, parameters(module), apply=True)
    assert {method for method, _, _ in client.calls} == {"GET"}


def test_server_errors_are_not_treated_as_missing_pack():
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def failing(method, path, body=None):
        if path.endswith("/download"):
            raise ApiError(403, "GET")
        return original(method, path, body)
    client.call = failing
    with pytest.raises(ApiError):
        install(client, module, parameters(module), apply=True)
    assert all(item[0] == "GET" for item in client.calls)


@pytest.mark.parametrize("configuration", [
    {"processor_order": [{"name": "Message Filter Chain", "class_name": "chain"},
                         {"name": "Pipeline Processor", "class_name": "pipeline"},
                         {"name": "Stream Rule Processor", "class_name": "stream"}], "disabled_processors": []},
    {"processor_order": [{"name": "Message Filter Chain", "class_name": "chain"},
                         {"name": "Stream Rule Processor", "class_name": "stream"},
                         {"name": "Pipeline Processor", "class_name": "pipeline"}], "disabled_processors": ["stream"]},
    {"processor_order": [{"name": "Message Filter Chain", "class_name": "chain"},
                         {"name": "Pipeline Processor", "class_name": "pipeline"}], "disabled_processors": []},
])
def test_stream_routing_must_be_enabled_before_pipeline(configuration):
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def configured(method, path, body=None):
        if path == "/system/messageprocessors/config":
            return configuration
        return original(method, path, body)
    client.call = configured
    with pytest.raises(ValueError, match="[Ss]tream"):
        install(client, module, parameters(module), apply=True)
    assert all(method == "GET" for method, _, _ in client.calls)


def test_uninstall_requires_tracked_exact_installation_and_explicit_apply():
    module = load_module("watchguard")
    client = FakeGraylog(installed=[{"_id": "a" * 24}])
    assert uninstall(client, module, "a" * 24)["action"] == "uninstall"
    assert all(method == "GET" for method, _, _ in client.calls)
    assert uninstall(client, module, "a" * 24, apply=True)["action"] == "uninstalled"
    assert client.calls[-1][0] == "DELETE"


def test_export_does_not_require_credentials_or_network(tmp_path):
    output = tmp_path / "watchguard.json"
    command = [sys.executable, str(ROOT / "tools/omni-integrations.py"), "export", "watchguard", "--output", str(output)]
    assert subprocess.run(command, capture_output=True).returncode == 0
    assert json.loads(output.read_text())["rev"] == 1
    assert subprocess.run(command, capture_output=True).returncode != 0  # preserves local export


def test_regex_conditions_are_explicit_boolean_comparisons():
    from omni_integrations.core import catalog, pipeline_rules
    for module in catalog():
        for rule in pipeline_rules(module)[1]:
            condition = rule["source"].split("when\n", 1)[1].split("\nthen", 1)[0]
            assert condition.rstrip().endswith(".matches == true")
