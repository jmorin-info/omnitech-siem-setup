"""Absence of optional product indices is not a platform-wide search failure."""
import json
import os

import pytest


pytestmark = pytest.mark.skipif(os.name == "nt", reason="SOC backend tests require Linux fcntl")


def _zero_shard_response(payload, monkeypatch, api):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(payload).encode()

    monkeypatch.setattr(api.urllib.request, "urlopen", lambda *_a, **_k: Response())


def test_empty_optional_product_index_has_empty_aggregations(api, monkeypatch):
    payload = {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
               "_shards": {"total": 0, "successful": 0, "failed": 0}}
    _zero_shard_response(payload, monkeypatch, api)
    query = {"size": 0, "aggs": {"sources": {"terms": {"field": "source"}}}}

    result = api.os_search("omni-aruba*", query)

    assert result["aggregations"]["sources"]["buckets"] == []


def test_empty_required_index_does_not_hide_missing_aggregations(api, monkeypatch):
    payload = {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
               "_shards": {"total": 0, "successful": 0, "failed": 0}}
    _zero_shard_response(payload, monkeypatch, api)
    query = {"size": 0, "aggs": {"sources": {"terms": {"field": "source"}}}}

    with pytest.raises(api.SearchBackendError):
        api.os_search("omni-required*", query)
