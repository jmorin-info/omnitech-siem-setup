"""Site-owned console pages: role checks, bounded searches and persistent configuration."""
import copy
import io
import json
from pathlib import Path

import pytest

from test_console_admin import Console


def config():
    return {"schema_version": 1, "revision": 0, "pages": [{
        "id": "watchguard", "title": "WatchGuard", "description": "Pare-feu du site",
        "enabled": True, "min_role": "analyste", "stream_ids": ["a" * 24],
        "event_sources": ["watchguard"], "integration_ids": ["watchguard"], "query": "action:deny", "days": 7,
        "graylog_dashboard_id": "b" * 24, "widgets": [
            {"id": "volume", "title": "Événements", "type": "count", "field": "", "size": 10},
            {"id": "sources", "title": "Sources", "type": "terms", "field": "source", "size": 8},
            {"id": "activity", "title": "Activité", "type": "timeseries", "field": "", "size": 10},
            {"id": "logs", "title": "Journaux", "type": "messages", "field": "", "size": 40},
        ],
    }]}


@pytest.fixture
def configured(api, tmp_path, monkeypatch):
    directory = tmp_path / "modules"
    directory.mkdir()
    monkeypatch.setattr(api, "SOC_MODULES_DIR", str(directory))
    monkeypatch.setattr(api, "MODULES_CONFIG_FILE", str(directory / "config.json"))
    monkeypatch.setattr(api, "SOC_DEFAULT_ROLE", "lecteur")
    monkeypatch.setattr(api, "SOC_ADMINS", {"alice"})
    monkeypatch.setattr(api, "role_of", lambda user: {"alice": "administrateur", "bob": "analyste", "reader": "lecteur"}.get(user))
    return api


def publish(module, raw=None):
    value = raw or config()
    clean = module._a_modules(value, "alice")
    return module._x_modules(clean, "alice", "configuration du site", "fake-request")


def test_site_configuration_is_atomic_persistent_and_revision_guarded(configured):
    module = configured
    raw = config()
    before = copy.deepcopy(raw)
    assert module.load_modules_config()["pages"] == []
    clean = module._a_modules(raw, "alice")
    preview = module._p_modules(clean)
    assert preview["after"]["revision"] == 1 and not Path(module.MODULES_CONFIG_FILE).exists()
    publish(module, raw)
    assert raw == before
    saved = Path(module.MODULES_CONFIG_FILE).read_bytes()
    assert module.load_modules_config()["revision"] == 1
    assert Path(module.MODULES_CONFIG_FILE).stat().st_mode & 0o777 == 0o640
    with pytest.raises(module.AdminError) as error:
        module._x_modules(clean, "alice", "stale request", "other-request")
    assert error.value.code == 409 and Path(module.MODULES_CONFIG_FILE).read_bytes() == saved
    assert not list(Path(module.SOC_MODULES_DIR).glob("*.tmp"))


@pytest.mark.parametrize("change", [
    lambda c: c.update(schema_version=2), lambda c: c.update(revision=True),
    lambda c: c["pages"][0].update(stream_ids=[]), lambda c: c["pages"][0].update(stream_ids=["../private"]),
    lambda c: c["pages"][0].update(min_role="all"), lambda c: c["pages"][0].update(days=31),
    lambda c: c["pages"][0].update(index="*"), lambda c: c["pages"][0].update(graylog_dashboard_id="https://other.test"),
    lambda c: c["pages"][0]["widgets"][0].update(type="script"),
    lambda c: c["pages"][0]["widgets"][1].update(field="source,*"),
    lambda c: c["pages"][0]["widgets"][0].update(size=1000),
    lambda c: c["pages"].append(copy.deepcopy(c["pages"][0])),
])
def test_invalid_configurations_never_write(configured, change):
    raw = config()
    change(raw)
    with pytest.raises(configured.AdminError):
        configured._a_modules(raw, "alice")
    assert not Path(configured.MODULES_CONFIG_FILE).exists()


def test_corrupt_configuration_is_not_silently_reset(configured):
    path = Path(configured.MODULES_CONFIG_FILE)
    path.write_text('{"schema_version":99}')
    with pytest.raises(configured.AdminError) as error:
        configured.load_modules_config()
    assert error.value.code == 503 and '99' in path.read_text()


def test_catalog_reads_native_dashboard_widgets_without_changing_graylog(configured, monkeypatch):
    calls = []
    def graylog(method, path):
        calls.append((method, path))
        if path == "/streams":
            return {"streams": [{"id": "a" * 24, "title": "Veille développeurs"}]}
        if path.startswith("/views?"):
            return {"views": [{"id": "b" * 24, "title": "Vulnérabilités", "type": "DASHBOARD"},
                              {"id": "c" * 24, "type": "SEARCH"}]}
        assert path == "/views/" + "b" * 24
        return {"state": {"page1": {"widgets": [{"id": "1"}, {"id": "2"}]}, "page2": {"widgets": [{"id": "3"}]}}}
    monkeypatch.setattr(configured, "_graylog", graylog)
    streams, dashboards = configured._modules_graylog_catalog()
    assert streams[0]["title"] == "Veille développeurs"
    assert dashboards == [{"id": "b" * 24, "title": "Vulnérabilités", "widgets": 3}]
    assert all(method == "GET" for method, _ in calls)


def test_multiple_native_dashboard_links_are_validated_and_published(configured):
    raw = config()
    raw["pages"][0]["graylog_dashboard_ids"] = ["c" * 24, "d" * 24]
    clean = configured.modules_validate_config(raw)
    assert clean["pages"][0]["graylog_dashboard_ids"] == ["b" * 24, "c" * 24, "d" * 24]
    publish(configured, raw)
    page = configured.modules_public("bob")["pages"][0]
    assert page["graylog_dashboard_ids"] == ["b" * 24, "c" * 24, "d" * 24]


@pytest.mark.parametrize("ids", [["../bad"], ["a" * 24] * 2, ["a" * 24] * 11])
def test_invalid_native_dashboard_links_are_rejected(configured, ids):
    raw = config()
    raw["pages"][0]["graylog_dashboard_ids"] = ids
    with pytest.raises(configured.AdminError):
        configured._a_modules(raw, "alice")


def test_partial_catalog_failure_keeps_saved_configuration(configured, monkeypatch):
    publish(configured)
    saved = Path(configured.MODULES_CONFIG_FILE).read_bytes()
    def unavailable(*args, **kwargs):
        raise ValueError("service unavailable")
    monkeypatch.setattr(configured, "_graylog", unavailable)
    monkeypatch.setattr(configured, "_modules_field_catalog", unavailable)
    monkeypatch.setattr(configured, "os_search", unavailable)
    result = configured.admin_modules()
    assert result["config"]["revision"] == 1 and len(result["catalog"]["errors"]) == 3
    assert result["catalog"]["streams"] == [] and Path(configured.MODULES_CONFIG_FILE).read_bytes() == saved


def test_field_catalog_rejects_partial_index_results(configured, monkeypatch):
    result = {"fields": {"source": {"keyword": {"aggregatable": True}}}, "failed_indices": ["unavailable-index"]}
    monkeypatch.setattr(configured.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(result).encode()))
    with pytest.raises(ValueError, match="unavailable"):
        configured._modules_field_catalog()
    result.pop("failed_indices")
    assert configured._modules_field_catalog() == [{"name": "source", "type": "keyword", "aggregatable": True}]


def test_empty_graylog_catalog_explains_service_account_permissions(configured, monkeypatch):
    monkeypatch.setattr(configured, "_modules_graylog_catalog", lambda: ([], []))
    monkeypatch.setattr(configured, "_modules_field_catalog", lambda: [])
    monkeypatch.setattr(configured, "os_search", lambda *a: {"_shards": {"failed": 0}, "aggregations": {"sources": {"buckets": []}}})
    errors = configured.admin_modules()["catalog"]["errors"]
    assert len(errors) == 2 and all("partages du compte Graylog" in e for e in errors)


def test_pages_are_opt_in_and_filtered_by_server_role(configured, monkeypatch):
    publish(configured)
    assert configured.modules_public("reader")["pages"] == []
    assert configured.modules_public("bob")["pages"][0]["id"] == "watchguard"
    monkeypatch.setattr(configured, "os_search", lambda *_: pytest.fail("Forbidden page must not query OpenSearch"))
    with pytest.raises(configured.AdminError) as error:
        configured.modules_page("watchguard", "reader")
    assert error.value.code == 404


def test_every_widget_retains_stream_source_integration_query_and_time_scope(configured, monkeypatch):
    publish(configured)
    calls = []
    def search(index, body):
        calls.append((index, body))
        result = {"_shards": {"failed": 0}, "hits": {"total": {"value": 2, "relation": "eq"}, "hits": []}}
        if "aggs" in body:
            result["aggregations"] = {"items": {"buckets": [{"key": 1760000000000, "key_as_string": "2026-11-24T10:00:00Z", "doc_count": 2}]}}
        elif body["size"]:
            result["hits"]["hits"] = [{"_source": {"timestamp": "2026-11-24", "source": "firewall", "message": "deny"}}]
        return result
    monkeypatch.setattr(configured, "os_search", search)
    result = configured.modules_page("watchguard", "bob")
    assert all(w["status"] == "ok" for w in result["widgets"])
    assert result["page"]["stream_ids"] == ["a" * 24]
    for index, body in calls:
        assert index == configured.LOG_INDICES and body["timeout"] == "10s"
        filters = body["query"]["bool"]["filter"]
        assert {"terms": {"streams": ["a" * 24]}} in filters
        assert {"terms": {"event_source": ["watchguard"]}} in filters
        assert {"terms": {"omni_integration_id": ["watchguard"]}} in filters
        assert {"range": {"timestamp": {"gte": "now-7d", "lte": "now"}}} in filters
        assert any("query_string" in f for f in filters)
    assert calls[-1][1]["size"] == 20
    assert result["widgets"][0]["data"]["value"] == 2


@pytest.mark.parametrize("response", [
    {"_shards": {"failed": 1}}, {"hits": {"total": {"value": 0}}},
    {"_shards": {"failed": 0}, "hits": {"total": {"value": 2, "relation": "gte"}, "hits": []}},
    {"_shards": {"failed": 0}, "hits": {"total": {"value": True}, "hits": []}},
])
def test_partial_or_invalid_count_is_unavailable_instead_of_zero(configured, monkeypatch, response):
    raw = config(); raw["pages"][0]["widgets"] = raw["pages"][0]["widgets"][:1]
    publish(configured, raw)
    monkeypatch.setattr(configured, "os_search", lambda *_: response)
    widget = configured.modules_page("watchguard", "bob")["widgets"][0]
    assert widget["status"] == "error" and widget["data"] is None


def test_http_session_role_csrf_and_simulation_guards(tmp_path):
    console = Console(tmp_path)
    try:
        assert console.call("GET", "/m/api/modules")[0] == 401
        assert console.call("GET", "/m/api/admin/modules", "guest")[0] == 403
        body = {"params": config(), "simulate": True, "motif": "pages du site"}
        assert console.call("POST", "/m/api/admin/modules", "alice", body, csrf=False)[0] == 403
        code, result = console.call("POST", "/m/api/admin/modules", "alice", body)
        assert code == 200 and result["simulation"]
        assert not (console.data / "modules/config.json").exists()
        body["simulate"] = False
        code, result = console.call("POST", "/m/api/admin/modules", "alice", body)
        assert code == 200 and result["ok"]
        assert json.loads((console.data / "modules/config.json").read_text())["revision"] == 1
        assert console.call("POST", "/m/api/admin/modules", "alice", body)[0] == 409
        assert console.audit()["chain_ok"]
    finally:
        console.close()
