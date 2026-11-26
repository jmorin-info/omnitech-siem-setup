"""Map periods reach all queries; totals include locations beyond the rendered cap."""
import pytest

from test_console_admin import Console, Mock


def result(body):
    data = {"hits": {"total": {"value": 1800, "relation": "eq"}, "hits": []}}
    if "loc" in body.get("aggs", {}):
        data["aggregations"] = {"threat_total": {"doc_count": 900}, "loc": {
            "sum_other_doc_count": 1700, "buckets": [{"key": "40,-70", "doc_count": 100,
            "men": {"doc_count": 50}, "cc": {"buckets": [{"key": "US"}]},
            "src": {"buckets": [{"key": "watchguard"}]}}]}}
    elif "c" in body.get("aggs", {}):
        data["aggregations"] = {"c": {"buckets": [{"key": "US", "doc_count": 900}]}}
    return data


@pytest.mark.parametrize("hours", [3, 12, 24, 48, 72])
def test_period_and_exact_totals(api, monkeypatch, hours):
    calls = []
    def search(index, body):
        calls.append(body)
        return result(body)
    monkeypatch.setattr(api, "os_search", search)
    data = api.get_geo_flows(hours)
    assert data["hours"] == hours
    assert data["window"]["lte"] - data["window"]["gte"] == hours * 3600000
    assert len(calls) == 3
    for body in calls:
        assert {"range": {"timestamp": data["window"]}} in body["query"]["bool"]["filter"]
        assert {"exists": {"field": "src_ip_geolocation"}} in body["query"]["bool"]["filter"]
    assert data["totals"] == {"arcs": 1, "menace": 900, "flux": 1800}
    assert data["coverage"]["omitted_flows"] == 1700


def test_unsupported_period_never_queries(api, monkeypatch):
    monkeypatch.setattr(api, "os_search", lambda *a: pytest.fail("invalid period queried"))
    for value in (True, "24", 0, -1, 73, 99999):
        with pytest.raises(ValueError):
            api.get_geo_flows(value)


def test_period_http_auth_validation_and_backend_failure(tmp_path):
    backend = Mock(lambda mock, method, path, body: (503, {}) if mock.state.get("failure") else (200, result(body)))
    console = Console(tmp_path, extra_conf=f"OPENSEARCH=http://127.0.0.1:{backend.port}")
    try:
        assert console.call("GET", "/m/api/geo-flows?hours=72")[0] == 401
        for query in ("hours=73", "hours=", "hours=-1", "hours=3&hours=72", "hours=24h"):
            assert console.call("GET", "/m/api/geo-flows?" + query, "alice")[0] == 400
        assert backend.calls == []
        for hours in (3, 12, 24, 48, 72):
            code, data = console.call("GET", f"/m/api/geo-flows?hours={hours}", "alice")
            assert code == 200 and data["hours"] == hours
        code, data = console.call("GET", "/m/api/geo-flows", "alice")
        assert code == 200 and data["hours"] == 3
        backend.state["failure"] = True
        code, data = console.call("GET", "/m/api/geo-flows?hours=72", "alice")
        assert code == 503 and "totals" not in data
    finally:
        console.close()
        backend.close()
