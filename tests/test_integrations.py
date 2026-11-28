"""Portable pack contracts and lifecycle safety; no Graylog/network required."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import sys

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


def test_watchguard_maps_existing_vendor_fields_without_removing_them():
    module = load_module("watchguard")
    report = validate_module(module)
    assert report["fixtures"] >= 5
    pack = build_pack(module)
    rules = [rule["data"]["source"]["@value"] for rule in pack["entities"]
             if rule["type"]["name"] == "pipeline_rule"]
    generated = "\n".join(rules)
    for raw, common in (("srcip", "src_ip"), ("dstip", "dest_ip"), ("msg_id", "event_id"),
                        ("policy_name", "network_rule"), ("action", "event_action")):
        assert f'has_field("{raw}")' in generated
        assert f'set_field("{common}"' in generated
    fixture = json.loads((ROOT / "integrations/watchguard/fixtures.json").read_text())[-2]
    result = parse_sample(module, fixture["message"], fixture["fields"])
    assert result["omni_parse_status"] == "parsed"
    assert result["src_ip"] == "203.0.113.10" and result["event_action"] == "allow"
    assert "remove_field" not in generated


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
        self.input_state = "STOPPED"

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
                "id": "b" * 24, "type": {"name": "stream", "version": "1"}, "found_on_system": False},
                {"content_pack_entity_id": stable_id("watchguard", "input"), "id": "c" * 24,
                 "type": {"name": "input", "version": "1"}, "found_on_system": False}]}
        if method == "GET" and path == "/system/inputstates/" + "c" * 24:
            if self.input_state is None:
                raise ApiError(404, "GET")
            return {"id": "c" * 24, "state": self.input_state}
        if method == "DELETE" and path == "/system/inputstates/" + "c" * 24:
            self.input_state = None
            return {"id": "c" * 24}
        if method == "PUT" and path == "/system/inputstates/" + "c" * 24:
            self.input_state = "RUNNING"
            return {"id": "c" * 24}
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


def test_apply_uploads_then_installs_then_only_activates_owned_stream_and_input(monkeypatch):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    plan = install(client, module, parameters(module), apply=True)
    assert plan["action"] == "installed"
    writes = [(method, path) for method, path, _ in client.calls if method != "GET"]
    pack = build_pack(module)
    assert writes == [("POST", "/system/content_packs"),
                      ("POST", f"/system/content_packs/{pack['id']}/{pack['rev']}/installations"),
                      ("POST", "/streams/" + "b" * 24 + "/resume"),
                      ("DELETE", "/system/inputstates/" + "c" * 24),
                      ("PUT", "/system/inputstates/" + "c" * 24)]
    request = [body for method, path, body in client.calls if method == "POST" and path.endswith("/installations")][0]
    assert request["entity"]["parameters"] == parameters(module)
    assert request["share_request"] == {"selected_grantee_capabilities": {}}


def test_identical_installed_module_is_idempotent_even_with_apply():
    module = load_module("watchguard")
    client = FakeGraylog(remote=build_pack(module), installed=[{"_id": "a" * 24, "content_pack_revision": module["revision"], "parameters": parameters(module)}])
    assert install(client, module, parameters(module), apply=True)["action"] == "already-installed"
    assert {method for method, _, _ in client.calls} == {"GET"}


@pytest.mark.parametrize("initial", ["RUNNING", "FAILED", "STOPPED"])
def test_only_new_input_is_stopped_then_started_even_if_native_creation_already_started_it(monkeypatch, initial):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    client.input_state = initial
    assert install(client, module, parameters(module), apply=True)["action"] == "installed"
    states = [(method, path) for method, path, _ in client.calls if method in ("DELETE", "PUT")]
    assert states == [("DELETE", "/system/inputstates/" + "c" * 24), ("PUT", "/system/inputstates/" + "c" * 24)]


@pytest.mark.parametrize("ownership", [True, None, "missing", "duplicate"])
def test_reused_or_ambiguous_input_is_never_activated(monkeypatch, ownership):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def call(method, path, body=None):
        result = original(method, path, body)
        if method == "POST" and path.endswith("/installations"):
            item = result["entities"][-1]
            if ownership == "missing":
                result["entities"].pop()
            elif ownership == "duplicate":
                result["entities"].append(dict(item))
            else:
                item["found_on_system"] = ownership
        return result
    client.call = call
    with pytest.raises(RuntimeError, match="owned input"):
        install(client, module, parameters(module), apply=True)
    assert not any(method in ("PUT", "DELETE") or path.endswith("/resume") for method, path, _ in client.calls)


def test_failed_new_input_is_not_reported_installed_or_restarted_repeatedly(monkeypatch):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def call(method, path, body=None):
        result = original(method, path, body)
        if method == "GET" and path.startswith("/system/inputstates/") and client.input_state is not None:
            result["state"] = "FAILED"
        return result
    client.call = call
    with pytest.raises(RuntimeError, match="failed to start"):
        install(client, module, parameters(module), apply=True)
    assert len([1 for method, _, _ in client.calls if method == "PUT"]) == 1


def test_cleanup_that_never_finishes_cannot_start_a_second_transport(monkeypatch):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def not_removed(method, path, body=None):
        if method == "GET" and path.startswith("/system/inputstates/"):
            client.calls.append((method, path, body))
            return {"id": "c" * 24, "state": "STOPPING"}
        return original(method, path, body)
    client.call = not_removed
    with pytest.raises(RuntimeError, match="stop cleanly"):
        install(client, module, parameters(module), apply=True)
    assert not any(method == "PUT" for method, _, _ in client.calls)


@pytest.mark.parametrize("failures", [1, 7])
def test_new_input_recovers_only_its_orphaned_worker_metrics(monkeypatch, failures):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    starts = 0
    def racy(method, path, body=None):
        nonlocal starts
        result = original(method, path, body)
        if method == "PUT" and path.startswith("/system/inputstates/"):
            starts += 1
            if starts <= failures:
                client.input_state = "FAILED"
        if method == "GET" and path.startswith("/system/inputstates/") and client.input_state == "FAILED":
            result["detailed_message"] = "A metric named org.graylog2.inputs.raw.udp.RawUDPInput." + "c" * 24 + ".workers.executor-service.pool.size already exists"
        return result
    client.call = racy
    assert install(client, module, parameters(module), apply=True)["action"] == "installed"
    assert starts == failures + 1
    assert len([1 for method, path, _ in client.calls if method == "POST" and path.endswith("/installations")]) == 1


@pytest.mark.parametrize("failure", ["other-input-metric", "bind-error", "persistent-own-metric"])
def test_metric_recovery_is_scoped_and_bounded_and_never_masks_other_errors(monkeypatch, failure):
    monkeypatch.setattr("omni_integrations.client.time.sleep", lambda _: None)
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def failed(method, path, body=None):
        result = original(method, path, body)
        if method == "PUT" and path.startswith("/system/inputstates/"):
            client.input_state = "FAILED"
        if method == "GET" and path.startswith("/system/inputstates/") and client.input_state == "FAILED":
            result["state"] = "FAILED"
            result["detailed_message"] = ("Address already in use: dummy-private-value" if failure == "bind-error" else
                "A metric named org.graylog2.inputs.raw.udp.RawUDPInput." + ("d" if failure == "other-input-metric" else "c") * 24 + ".workers.executor-service.pool.size already exists")
        return result
    client.call = failed
    with pytest.raises(RuntimeError, match="failed to start") as error:
        install(client, module, parameters(module), apply=True)
    assert "dummy-private" not in str(error.value)
    starts = [path for method, path, _ in client.calls if method == "PUT"]
    assert starts == ["/system/inputstates/" + "c" * 24] * (8 if failure == "persistent-own-metric" else 1)


@pytest.mark.parametrize("scenario", ["changed-pack", "port-conflict", "other-revision", "other-parameters"])
def test_conflicts_abort_before_any_write(scenario):
    module = load_module("watchguard")
    client = FakeGraylog(conflict=scenario == "port-conflict")
    if scenario == "changed-pack":
        client.remote = build_pack(module)
        client.remote["summary"] += " altered"
    elif scenario in ("other-revision", "other-parameters"):
        client.remote = build_pack(module)
        client.installed = [{"content_pack_revision": module["revision"] + 1 if scenario == "other-revision" else module["revision"],
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


@pytest.mark.parametrize("scenario", ["absent", "disabled-class", "disabled-name", "late"])
def test_static_fields_must_be_attached_before_stream_routing(scenario):
    client, module = FakeGraylog(), load_module("watchguard")
    original = client.call
    def configured(method, path, body=None):
        result = original(method, path, body)
        if path == "/system/messageprocessors/config":
            if scenario == "absent":
                result["processor_order"].pop(0)
            elif scenario == "late":
                result["processor_order"].append(result["processor_order"].pop(0))
            else:
                result["disabled_processors"] = ["chain" if scenario == "disabled-class" else "Message Filter Chain"]
        return result
    client.call = configured
    with pytest.raises(ValueError, match="static fields"):
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
    assert json.loads(output.read_text())["rev"] == 4
    assert subprocess.run(command, capture_output=True).returncode != 0  # preserves local export


def test_regex_conditions_are_explicit_boolean_comparisons():
    from omni_integrations.core import catalog, pipeline_rules
    for module in catalog():
        for rule in pipeline_rules(module)[1]:
            condition = rule["source"].split("when\n", 1)[1].split("\nthen", 1)[0]
            if "regex(" in condition:
                assert condition.rstrip().endswith(".matches == true")
            else:
                assert condition.strip() == "true" and "-continue-" in rule["title"]


# --- Field contract, existing-input variant and catalog dashboards -------------------------

from omni_integrations.core import (build_existing_input_pack, catalog_dashboard, check_dashboard_fields,  # noqa: E402
                                    produced_fields, query_fields)
from omni_integrations.client import (deploy_dashboards, restore_dashboards, check_dashboards,  # noqa: E402
                                      install_existing_input, load_site_config)


@pytest.mark.parametrize("module", catalog(), ids=lambda item: item["id"])
def test_every_dashboard_widget_uses_only_fields_the_module_produces(module):
    assert check_dashboard_fields(module) == []


def test_dashboard_with_unproduced_field_is_rejected_offline():
    module = copy.deepcopy(load_module("watchguard"))
    module["dashboards"][0]["pages"][0]["widgets"].append(
        {"title": "Mal nommé", "type": "terms", "field": "srcip_typo", "query": "dstport:443", "pos": [1, 30, 4, 4]})
    problems = {field for _, _, field in check_dashboard_fields(module)}
    assert problems == {"srcip_typo", "dstport"}
    module["dashboards"][0]["pages"][0]["widgets"][-1]["type"] = "pie"
    with pytest.raises(ValueError, match="widget type"):
        check_dashboard_fields(module)


def test_query_field_extraction_ignores_quoted_values_and_operators():
    assert query_fields('event_id:("3000-0173" OR "a:b") OR _exists_:threat_name AND NOT x_y:1') == {
        "event_id", "threat_name", "x_y"}
    assert query_fields("") == set()


def test_watchguard_revision_four_normalizes_vpn_auth_and_proxy_fields():
    produced = produced_fields(load_module("watchguard"))
    for field in ("event_category", "user", "event_outcome", "vpn_peer_ip", "url_domain", "bytes_out", "network_rule"):
        assert field in produced
    rules = "\n".join(rule["source"] for stage in pipeline_rules(load_module("watchguard")) for rule in stage)
    assert 'set_field("watchguard_src_ip", parsed["value"]);' in rules
    assert "drop_message" not in rules and "remove_field" not in rules


def test_existing_input_variant_creates_no_input_and_keeps_storage():
    module = load_module("watchguard")
    pack = build_existing_input_pack(module)
    assert pack == build_existing_input_pack(module)
    kinds = {e["type"]["name"] for e in pack["entities"]}
    assert kinds == {"stream", "pipeline", "pipeline_rule"}
    stream = next(e["data"] for e in pack["entities"] if e["type"]["name"] == "stream")
    assert stream["remove_matches"] == {"@type": "boolean", "@value": False}
    assert stream["stream_rules"][0]["field"]["@value"] == "gl2_source_input"
    assert stream["stream_rules"][0]["value"] == {"@type": "parameter", "@value": "source_input"}
    assert pack["id"] != build_pack(module)["id"]
    assert not set(e["id"] for e in pack["entities"]) & set(e["id"] for e in build_pack(module)["entities"])


def _site(tmp_path, bindings=None):
    path = tmp_path / "integrations.json"
    path.write_text(json.dumps({"schema_version": 1, "integrations": {"watchguard": {
        "source_input": "e" * 24, "dashboards": bindings or {}}}}))
    return load_site_config(path, "watchguard")


def test_site_configuration_is_validated(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema_version": 1, "integrations": {"watchguard": {"source_input": "not-an-id"}}}))
    with pytest.raises(ValueError):
        load_site_config(path, "watchguard")
    with pytest.raises(ValueError):
        load_site_config(path, "unifi")


class FakeSiteGraylog(FakeGraylog):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.views = {"f" * 24: {"id": "f" * 24, "type": "DASHBOARD", "title": "Legacy", "search_id": "1" * 24, "owner": "admin"}}
        self.stream_title = "OMNI integration - WatchGuard Firebox"

    def call(self, method, path, body=None):
        if method == "GET" and path == "/system/inputs/" + "e" * 24:
            self.calls.append((method, path, body))
            return {"id": "e" * 24, "title": "site input"}
        if method == "GET" and path == "/streams":
            self.calls.append((method, path, body))
            return {"streams": [{"id": "9" * 24, "title": self.stream_title}] if self.stream_title else []}
        if path.startswith("/views"):
            self.calls.append((method, path, body))
            if method == "GET" and path.startswith("/views?"):
                return {"views": list(self.views.values())}
            if method == "GET" and path.startswith("/views/search/status/"):
                return self.job
            if method == "GET" and path.startswith("/views/search/"):
                return {"id": path.rsplit("/", 1)[1], "queries": []}
            if method == "GET":
                return self.views[path.rsplit("/", 1)[1]]
            if method == "POST" and path.endswith("/execute"):
                return self.job
            if method == "POST" and path == "/views/fields":
                return [{"name": name} for name in self.fields]
            if method == "POST" and path == "/views":
                return {"id": "7" * 24}
            return {}
        if method == "POST" and path.endswith("/installations"):
            self.calls.append((method, path, body))
            return {"_id": "a" * 24, "entities": [{"content_pack_entity_id": stable_id("watchguard", "existing-input:stream"),
                    "id": "b" * 24, "type": {"name": "stream", "version": "1"}, "found_on_system": False}]}
        return super().call(method, path, body)


def test_existing_input_install_plans_then_activates_only_its_stream(tmp_path):
    client = FakeSiteGraylog()
    client.stream_title = None
    module = load_module("watchguard")
    plan = install_existing_input(client, module, _site(tmp_path))
    assert plan["action"] == "install" and {m for m, _, _ in client.calls} == {"GET"}
    plan = install_existing_input(client, module, _site(tmp_path), apply=True)
    writes = [(m, p) for m, p, _ in client.calls if m != "GET"]
    pack = build_existing_input_pack(module)
    assert writes == [("POST", "/system/content_packs"),
                      ("POST", f"/system/content_packs/{pack['id']}/{pack['rev']}/installations"),
                      ("POST", "/streams/" + "b" * 24 + "/resume")]
    assert plan["stream_id"] == "b" * 24


def test_dashboards_plan_is_read_only_then_replace_in_place_and_restore_by_id(tmp_path):
    module = load_module("watchguard")
    client = FakeSiteGraylog()
    site = _site(tmp_path, {"activity": "f" * 24})
    plan = deploy_dashboards(client, module, site)
    assert [item["action"] for item in plan["dashboards"]] == ["update", "create", "create"]
    assert {m for m, _, _ in client.calls} == {"GET"}
    with pytest.raises(ValueError, match="backup"):
        deploy_dashboards(client, module, site, apply=True)
    state = deploy_dashboards(client, module, site, apply=True, backup_dir=tmp_path / "b")
    writes = [(m, p) for m, p, _ in client.calls if m in ("POST", "PUT", "DELETE")]
    assert writes.count(("PUT", "/views/" + "f" * 24)) == 1 and writes.count(("POST", "/views")) == 2
    put = next(b for m, p, b in client.calls if m == "PUT")
    assert put["entity"]["id"] == "f" * 24 and put["entity"]["owner"] == "admin"
    assert all(w["streams"] == ["9" * 24] for s in put["entity"]["state"].values() for w in s["widgets"])
    assert json.loads((tmp_path / "b" / ("view-" + "f" * 24 + ".json")).read_text())["view"]["title"] == "Legacy"
    assert [item["action"] for item in state["items"]] == ["updated", "created", "created"]
    with pytest.raises(FileExistsError):
        deploy_dashboards(client, module, site, apply=True, backup_dir=tmp_path / "b")
    client.calls.clear()
    assert restore_dashboards(client, tmp_path / "b")["actions"][0]["action"] == "delete"
    assert client.calls == []
    restore_dashboards(client, tmp_path / "b", apply=True)
    writes = [(m, p) for m, p, _ in client.calls]
    assert ("DELETE", "/views/" + "7" * 24) in writes and ("PUT", "/views/" + "f" * 24) in writes


def test_post_deployment_check_flags_empty_widgets_and_absent_fields(tmp_path):
    module = load_module("watchguard")
    client = FakeSiteGraylog()
    spec = module["dashboards"][2]
    client.views = {"f" * 24: {"id": "f" * 24, "type": "DASHBOARD", "title": spec["title"], "search_id": "2" * 24}}
    from omni_integrations.core import catalog_search_types
    results = {}
    for _, widget, query_id, search_type in catalog_search_types(module, spec):
        total = 0 if widget["title"] == "Messages non reconnus" else 5
        result = {"total": total}
        if widget["title"] == "Identifiants sans adresse source":
            result["rows"] = [{"key": [], "values": [{"value": 5}], "source": "non-leaf"}]  # documents but no value
        results.setdefault(query_id, {"search_types": {}})["search_types"][search_type] = result
    client.job = {"id": "j", "execution": {"done": True}, "errors": [], "results": results}
    client.fields = ["timestamp", "source", "message", "omni_parse_status", "event_id"]
    report = check_dashboards(client, module, _site(tmp_path, {"quality": "f" * 24}))
    statuses = {w["widget"]: w for w in report["widgets"] if w.get("page")}
    assert statuses["Messages non reconnus"]["status"] == "empty"
    assert statuses["Non reconnus par processus"]["fields_absent"] == ["event_category"]
    assert statuses["Identifiants sans adresse source"]["status"] == "empty"
    assert report["failures"] == 2 + 2  # two empty widgets, two catalog dashboards not deployed
    assert catalog_dashboard(module, spec, "9" * 24)["view"]["type"] == "DASHBOARD"
