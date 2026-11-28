"""Search failures must not appear as zero incidents or a nominal posture."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request

import pytest


@contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def backend_handler(status, payload):
    class Handler(BaseHTTPRequestHandler):
        calls = 0
        paths = []
        def do_POST(self):
            type(self).calls += 1
            type(self).paths.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
        def log_message(self, *args):
            pass
    return Handler


@pytest.mark.parametrize("status,payload,expected", [
    (503, {"error": "dummy-private-upstream-content"}, 503),
    (400, {"error": "dummy-private-query-text"}, 502),
    (401, {"error": "dummy-private-upstream-password"}, 502),
    (200, b"malformed dummy-private-json", 502),
    (200, [], 502),
    (200, {"error": "dummy-private-error"}, 502),
    (200, {"hits": {}}, 502),
    (200, {"hits": {}, "timed_out": True}, 502),
    (200, {"hits": {}, "_shards": {"failed": 1}}, 502),
])
def test_real_search_errors_are_distinct_from_empty_data(api, status, payload, expected):
    with serve(backend_handler(status, payload)) as base:
        api.OS_URL = base
        with pytest.raises(api.SearchBackendError) as exc:
            api.get_kpis()
        assert exc.value.status == expected
        assert "dummy-private" not in str(exc.value)
        assert not api._CACHE


def test_real_empty_search_is_successful_zero_count(api):
    payload = {"hits": {"total": {"value": 0}, "hits": []}, "_shards": {"failed": 0}, "timed_out": False}
    with serve(backend_handler(200, payload)) as base:
        api.OS_URL = base
        assert api._count({"match_all": {}}) == 0


def test_integer_total_is_normalized_for_count_helpers(api):
    with serve(backend_handler(200, {"hits": {"total": 3, "hits": []}})) as base:
        api.OS_URL = base
        assert api._count({"match_all": {}}) == 3


def test_truncated_http_body_returns_safe_search_error(api):
    class Truncated(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b'{"dummy-private-payload":')
        def log_message(self, *args):
            pass
    with serve(Truncated) as base:
        api.OS_URL = base
        with pytest.raises(api.SearchBackendError) as exc:
            api._count({"match_all": {}})
        assert exc.value.status == 502
        assert "dummy-private" not in str(exc.value)


@pytest.mark.parametrize("aggregations", [None, [], {}, {"unexpected": {}}])
def test_missing_requested_aggregations_are_not_reported_as_empty_charts(api, aggregations):
    payload = {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": aggregations}
    with serve(backend_handler(200, payload)) as base:
        api.OS_URL = base
        with pytest.raises(api.SearchBackendError) as exc:
            api.get_terms("event_source", tagged=False)
        assert exc.value.status == 502
        assert not api._CACHE


def test_origin_defaults_use_configured_api_host_without_reference_site(api):
    assert api.SOC_ORIGINS == {"127.0.0.1"}
    assert api.origin_ok({"Origin": "http://127.0.0.1"})
    assert not api.origin_ok({"Origin": "https://unrelated.example.test"})
    assert not api.origin_ok({"Origin": "https://10.33.220.10"})


@pytest.mark.parametrize("endpoint", ["/kpis", "/risk", "/search?q=fixture", "/entity?u=fixture"])
def test_authenticated_http_routes_return_safe_unavailable_status(api, monkeypatch, endpoint):
    def unavailable(*args, **kwargs):
        raise api.SearchBackendError(503)
    monkeypatch.setattr(api, "os_search", unavailable)
    with serve(api.H) as base:
        request = urllib.request.Request(base + "/m/api" + endpoint,
            headers={"Cookie": "oms_session=" + api.sign_session("lab-admin")})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 503
        result = json.load(error.value)
        assert result["error"] == "search_unavailable" and result["available"] is False
        assert "NOMINAL" not in json.dumps(result) and "total" not in result


def test_search_error_does_not_change_authentication_or_stop_other_requests(api, monkeypatch):
    monkeypatch.setattr(api, "os_search", lambda *args: (_ for _ in ()).throw(api.SearchBackendError(502)))
    with serve(api.H) as base:
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(base + "/m/api/kpis")
        assert error.value.code == 401
        request = urllib.request.Request(base + "/m/api/kpis",
            headers={"Cookie": "oms_session=" + api.sign_session("lab-admin")})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 502
        with urllib.request.urlopen(base + "/m/api/vapid") as response:
            assert response.status == 200


def test_live_stream_reports_search_failure_without_double_http_headers(api, monkeypatch):
    monkeypatch.setattr(api, "os_search", lambda *args: (_ for _ in ()).throw(api.SearchBackendError()))
    with serve(api.H) as base:
        request = urllib.request.Request(base + "/m/api/stream",
            headers={"Cookie": "oms_session=" + api.sign_session("lab-admin")})
        with urllib.request.urlopen(request) as response:
            body = response.read().decode()
            assert response.status == 200
        assert 'event: unavailable\n' in body
        assert '"available":false' in body and "HTTP/" not in body


def test_deploy_uses_site_identity_without_reference_site_fallback(api, monkeypatch):
    monkeypatch.setattr(api, "os_search", lambda *args: {"hits": {}, "aggregations": {}})
    api.CONF.update(SIEM_FQDN="siem.customer.test", SIEM_IP="192.0.2.10")
    result = api.get_deploy()
    assert result["siem"]["fqdn"] == "siem.customer.test"
    assert result["siem"]["ip"] == "192.0.2.10"
    assert result["siem"]["identity_configured"] is True
    api._CACHE.clear()
    api.CONF.pop("SIEM_FQDN")
    api.CONF.pop("SIEM_IP")
    result = api.get_deploy()
    assert result["siem"]["fqdn"] == "" and result["siem"]["ip"] == ""
    assert result["siem"]["identity_configured"] is False
    assert "10.33.220.10" not in json.dumps(result)


def test_failed_search_is_not_cached_and_later_recovery_is_observed(api):
    handler = backend_handler(503, {"error": "dummy-private-value"})
    with serve(handler) as base:
        api.OS_URL = base
        with pytest.raises(api.SearchBackendError):
            api.get_kpis()
    handler = backend_handler(200, {"hits": {"total": {"value": 0}, "hits": []}})
    with serve(handler) as base:
        api.OS_URL = base
        assert all(value == 0 for value in api.get_kpis().values())
        assert handler.calls == 5   # un compteur par indicateur, dont les correspondances TI


def test_default_shared_log_scope_includes_native_modules_without_system_indices(api):
    handler = backend_handler(200, {"hits": {"total": {"value": 1}, "hits": []}})
    assert api.LOG_INDICES == "omni-*,graylog_*"
    with serve(handler) as base:
        api.OS_URL = base
        assert api._count({"match_all": {}}) == 1
        assert handler.paths[-1] == "/omni-*,graylog_*/_search"
        api.os_search("omni-winsec*", {"size": 0})
        assert handler.paths[-1] == "/omni-winsec*/_search"
        api.get_search("fixture")
        assert handler.paths[-1] == "/omni-*,graylog_*/_search"
    assert "gl-events" not in api.LOG_INDICES and "failures" not in api.LOG_INDICES


@pytest.mark.parametrize("pattern", ["*", "_all", "graylog_*/*", "omni-*?pretty", "graylog_*/../_all",
    "omni-*#x", "omni-*\ngraylog_*", "omni-*,", "gl-events_*", "gl-failures_*", ".security*",
    "system-*", "security-*", "failed-*", "omni*", "graylog*", "customer*", "omni-*,_all"])
def test_log_scope_rejects_global_system_and_url_injection_patterns(api, pattern):
    with pytest.raises(ValueError, match="SOC_LOG_INDICES"):
        api.log_index_patterns(pattern)


def test_explicit_site_log_scope_is_normalized_and_deduplicated(api):
    assert api.log_index_patterns("customer-*, graylog_*,customer-*") == "customer-*,graylog_*"


@pytest.mark.parametrize("value", ["watchguard:0", "watchguard:43201", "watchguard:-1", "unifi:1.5",
    "unifi:1e3", "unifi", "unifi:1:2", "unifi:1,", ",unifi:1", "unifi:1,unifi:2",
    "Unifi:120", "*:120", "private/dummy:120", "private\ndummy:120", "unifi:\n120", 42])
def test_expected_source_thresholds_reject_invalid_configuration_without_echo(api, value):
    with pytest.raises(ValueError, match="SOC_EXPECTED_SOURCES") as exc:
        api.expected_source_thresholds(value)
    assert "private" not in str(exc.value)


def test_expected_source_thresholds_accept_boundaries_and_explicit_empty_list(api):
    assert api.expected_source_thresholds("watchguard:1, unifi:43200,paloalto:120") == {
        "watchguard": 1, "unifi": 43200, "paloalto": 120}
    assert api.expected_source_thresholds("") == {}
    assert api.expected_source_thresholds("  ") == {}


def health_backend_handler():
    last_ms = int(time.time() * 1000) - 10 * 60000
    class Handler(BaseHTTPRequestHandler):
        def answer(self, data):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        def do_GET(self):
            self.answer({"status": "green", "number_of_nodes": 1, "active_shards": 2})
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            aggs = {}
            for name in body.get("aggs", {}):
                if name == "src":
                    aggs[name] = {"buckets": [{"key": source, "doc_count": 1, "last": {
                        "value": last_ms, "value_as_string": "2026-01-01T00:00:00Z"}}
                        for source in ("watchguard", "unifi")]}
                elif name == "tot":
                    aggs[name] = {"value": 2}
                else:
                    aggs[name] = {"buckets": []}
            self.answer({"hits": {"total": {"value": 0}, "hits": []}, "aggregations": aggs})
        def log_message(self, *args):
            pass
    return Handler


@pytest.mark.parametrize("setting", ["", "watchguard:5,unifi:30,paloalto:120", None])
def test_real_health_search_uses_only_configured_expectations_and_thresholds(api, setting):
    if setting is not None:
        with Path(os.environ["MOBILE_CONFIG"]).open("a") as config:
            config.write("SOC_EXPECTED_SOURCES=" + setting + "\n")
    spec = importlib.util.spec_from_file_location("expected_sources_api", api.__file__)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    with serve(health_backend_handler()) as base:
        api.OS_URL = base
        result = api.get_health()
    assert {source["k"] for source in result["sources"]} == {"watchguard", "unifi"}
    assert result["cluster"] == "green"
    expected = {item["k"]: item for item in result["integrations"]}
    if setting == "":
        assert expected == {}
    elif setting is None:
        assert {name: item["threshold_min"] for name, item in expected.items()} == {
            "fortigate": 120, "sysmon": 180, "windows_security": 180, "m365": 360,
            "aruba": 240, "linux": 1440, "dns": 1440, "fortiems": 2880,
            "fortimanager": 1440, "eset": 1440, "vsphere": 1440}
    else:
        assert set(expected) == {"watchguard", "unifi", "paloalto"}
        assert expected["watchguard"]["status"] == "stale" and expected["watchguard"]["threshold_min"] == 5
        assert expected["unifi"]["status"] == "ok" and expected["unifi"]["threshold_min"] == 30
        assert expected["paloalto"]["status"] == "missing" and expected["paloalto"]["threshold_min"] == 120


@pytest.mark.parametrize("admins,allowed", [(set(), False), ({"another-operator"}, False), ({"lab-admin"}, True)])
def test_soar_admin_must_be_explicit_even_when_configuration_is_empty(api, tmp_path, admins, allowed):
    api.SOC_ADMINS = admins
    api.SOC_REQ_DIR = str(tmp_path / "requests")
    with serve(api.H) as base:
        request = urllib.request.Request(base + "/m/api/soar/unblock", method="POST",
            data=json.dumps({"ip": "8.8.8.8", "motif": "fixture"}).encode(),
            headers={"Content-Type": "application/json", "Cookie": "oms_session=" + api.sign_session("lab-admin")})
        if allowed:
            with urllib.request.urlopen(request) as response:
                assert response.status == 200 and json.load(response)["ok"] is True
        else:
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            assert error.value.code == 403
    assert len(list((tmp_path / "requests").rglob("*.json"))) == (1 if allowed else 0)
