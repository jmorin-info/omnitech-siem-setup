"""Synthetic integration writes must stay behind the isolated-VM guard."""
from importlib.util import module_from_spec, spec_from_file_location
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest
from omni_integrations.client import Graylog
from omni_integrations.core import build_pack, load_module, stable_id

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("omni_integration_vm", ROOT / "tools/test-integration-vm.py")
vm = module_from_spec(spec)
spec.loader.exec_module(vm)


def test_default_invocation_cannot_create_a_client_or_mutate_graylog(monkeypatch, capsys):
    monkeypatch.delenv("OMNI_ISOLATED_VM_TEST", raising=False)
    monkeypatch.setattr(vm, "Graylog", lambda *args: pytest.fail("a client must not be created"))
    monkeypatch.setattr(vm, "execute_dashboard", lambda *args: pytest.fail("a search job must not be created"))
    assert vm.main([]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is False and report["modules"] == []


@pytest.mark.parametrize("field,value", [("SIEM_IP", "192.0.2.10"), ("SIEM_FQDN", "production.example.test")])
def test_non_lab_site_identity_is_refused(tmp_path, field, value):
    config = {"SIEM_IP": "10.0.2.15", "SIEM_FQDN": "siem.lab.test", field: value}
    with pytest.raises(ValueError):
        vm.verify_identity(config, {"profile": "core-soc", "source_root": str(tmp_path)}, "siem.lab.test", tmp_path)


def test_vm_metadata_and_hostname_must_both_match(tmp_path):
    config = {"SIEM_IP": "10.0.2.15", "SIEM_FQDN": "siem.lab.test"}
    metadata = {"profile": "core-soc", "source_root": str(tmp_path)}
    vm.verify_identity(config, metadata, "siem.lab.test", tmp_path)
    with pytest.raises(ValueError):
        vm.verify_identity(config, metadata, "production-siem", tmp_path)
    with pytest.raises(ValueError):
        vm.verify_identity(config, {**metadata, "source_root": "/other"}, "siem.lab.test", tmp_path)


def test_fixture_evidence_requires_normalization_and_owned_stream_without_leaking_values():
    fixtures = [{"message": "synthetic fixture", "expected": {"src_port": 443}}]
    messages = [{"message": "synthetic fixture", "src_port": "443", "event_source": "watchguard",
                 "omni_parse_status": "parsed", "streams": ["other"], "password": "dummy-private-value"}]
    result = vm.fixture_results(fixtures, messages, "watchguard", "owned")
    assert result[0]["received"] is True and result[0]["normalized"] is False
    assert result[0]["mismatched_fields"] == ["src_port"]
    assert "dummy-private-value" not in json.dumps(result)
    messages[0]["src_port"] = 443
    result = vm.fixture_results(fixtures, messages, "watchguard", "owned")
    assert result[0]["normalized"] is True and result[0]["routed_to_module_stream"] is False
    messages[0]["streams"] = ["owned"]
    assert vm.fixture_results(fixtures, messages, "watchguard", "owned")[0]["routed_to_module_stream"] is True


def test_unknown_fixture_must_be_retained_unparsed():
    fixtures = [{"message": "unknown diagnostic", "expected": {"omni_parse_status": "unparsed"}}]
    messages = [{"message": "unknown diagnostic", "event_source": "unifi", "omni_parse_status": "unparsed", "streams": ["owned"]}]
    result = vm.fixture_results(fixtures, messages, "unifi", "owned")
    assert result[0]["received"] and result[0]["normalized"] and result[0]["routed_to_module_stream"]


@pytest.fixture
def dashboard_job():
    module = load_module("watchguard")
    view = next(entity["data"] for entity in build_pack(module)["entities"] if entity["type"]["name"] == "dashboard")
    view["search_id"] = "a" * 24
    fixtures = [{"message": "synthetic message " + str(i)} for i in range(3)]
    query_id, state = next(iter(view["state"].items()))
    types = {}
    for widget in state["widgets"]:
        identifier = state["widget_mapping"][widget["id"]][0]
        if widget["type"] == "aggregation":
            types[identifier] = {"id": identifier, "type": "pivot", "rows": [{"key": [], "values": [
                {"key": ["count()"], "value": len(fixtures)}]}]}
        else:
            types[identifier] = {"id": identifier, "type": "messages", "messages": [{"message": {
                "message": item["message"], "omni_integration_id": "watchguard", "secret": "dummy-private-value"}}
                for item in fixtures]}
    job = {"id": "b" * 24, "execution": {"done": True, "cancelled": False, "completed_exceptionally": False},
           "results": {query_id: {"state": "COMPLETED", "search_types": types}}}
    return view, fixtures, job


def test_dashboard_executes_the_saved_search_and_polls_real_http_without_rewriting_it(dashboard_job, monkeypatch):
    view, fixtures, job = dashboard_job
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def reply(self, payload, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
        def do_POST(self):
            calls.append(("POST", self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.reply({"id": "b" * 24}, 201)
        def do_GET(self):
            calls.append(("GET", self.path, None))
            self.reply({"execution": {"done": False}} if len(calls) == 2 else job)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(vm.time, "sleep", lambda _: None)
    before = copy.deepcopy(view)
    try:
        client = Graylog("http://127.0.0.1:" + str(server.server_port) + "/api", "dummy-lab-token")
        result = vm.execute_dashboard(client, view, "watchguard", fixtures)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert result["passed"] and result["search_type_results"] == 6
    assert "dummy-private" not in json.dumps(result)
    assert view == before
    assert calls == [("POST", "/api/views/search/" + "a" * 24 + "/execute", {}),
                     ("GET", "/api/views/search/status/" + "b" * 24, None),
                     ("GET", "/api/views/search/status/" + "b" * 24, None)]


@pytest.mark.parametrize("failure", ["cancelled", "exceptional", "missing-execution-flag", "job-error", "query-error", "query-failed",
    "missing-query", "missing-type", "extra-type", "wrong-type", "type-error", "zero-count", "boolean-count",
    "missing-fixture", "foreign-message"])
def test_dashboard_evidence_rejects_partial_failed_or_unscoped_results_without_values(dashboard_job, failure):
    view, fixtures, job = dashboard_job
    query = next(iter(job["results"].values()))
    types = query["search_types"]
    volume = types[stable_id("watchguard", "search-0")]
    logs = types[stable_id("watchguard", "search-logs")]["messages"]
    if failure == "cancelled":
        job["execution"]["cancelled"] = True
    elif failure == "exceptional":
        job["execution"]["completed_exceptionally"] = True
    elif failure == "missing-execution-flag":
        job["execution"].pop("completed_exceptionally")
    elif failure == "job-error":
        job["errors"] = [{"description": "dummy-private-value"}]
    elif failure == "query-error":
        query["errors"] = [{"description": "dummy-private-value"}]
    elif failure == "query-failed":
        query["state"] = "FAILED"
    elif failure == "missing-query":
        job["results"].clear()
    elif failure == "missing-type":
        types.pop(stable_id("watchguard", "search-1"))
    elif failure == "extra-type":
        types["unexpected"] = volume
    elif failure == "wrong-type":
        types[stable_id("watchguard", "search-1")]["type"] = "unsupported"
    elif failure == "type-error":
        volume["errors"] = [{"description": "dummy-private-value"}]
    elif failure in ("zero-count", "boolean-count"):
        volume["rows"][0]["values"][0]["value"] = 0 if failure == "zero-count" else True
    elif failure == "missing-fixture":
        logs.pop()
    else:
        logs[0]["message"]["omni_integration_id"] = "another-module"
    result = vm.dashboard_result_evidence(job, view, "watchguard", fixtures)
    assert result["passed"] is False
    assert "dummy-private" not in json.dumps(result)


def test_dashboard_job_timeout_fails_instead_of_skipping_checks(dashboard_job, monkeypatch):
    view, fixtures, _ = dashboard_job
    class Pending:
        def call(self, method, path, body=None):
            return {"id": "b" * 24} if method == "POST" else {"execution": {"done": False}}
    monkeypatch.setattr(vm.time, "sleep", lambda _: None)
    result = vm.execute_dashboard(Pending(), view, "watchguard", fixtures)
    assert result["passed"] is False and result["timed_out"] is True
