import json

import pytest
import requests

from oms_xdr.correlation import Correlator
from oms_xdr.graylog_client import GraylogClient


def test_unknown_stream_does_not_widen_the_search():
    client=GraylogClient({"streams":{}})
    with pytest.raises(ValueError,match="alias"):
        client._filters("event_id:4625","missing",15)


def test_query_keeps_absolute_window_and_selected_stream():
    client=GraylogClient({"streams":{"firewall":"a"*24}})
    query=client._filters("event_action:deny","firewall",15)
    filters=query["bool"]["filter"]
    window=filters[0]["range"]["timestamp"]
    assert window["format"]=="epoch_millis" and window["lte"]-window["gte"]==900000
    assert {"term":{"streams":"a"*24}} in filters
    assert client.last_window["from"]<client.last_window["to"]


def test_http_failure_is_not_a_successful_empty_result(monkeypatch):
    def unavailable(*args,**kwargs):raise requests.ConnectionError("dummy-sensitive-location")
    monkeypatch.setattr(requests,"post",unavailable)
    with pytest.raises(RuntimeError) as error:
        GraylogClient({})._os_search({})
    assert "dummy-sensitive" not in str(error.value)


def test_snapshot_keeps_only_signals_contributing_to_the_incident(tmp_path,graylog_factory):
    rules=tmp_path/"rules.yaml"
    rules.write_text('''signals:
  first: {type: count_by, query: q1, entity_field: src_ip, threshold: 1}
  second: {type: count_by, query: q2, entity_field: src_ip, threshold: 1}
  elsewhere: {type: count_by, query: q3, entity_field: src_ip, threshold: 1}
rules:
  check: {title: Check, severity: high, require_all: [first], any_of: [second, elsewhere], join_entity: true}
''')
    gl=graylog_factory({("q1","","src_ip"):{"192.0.2.1":2},("q2","","src_ip"):{"192.0.2.1":3},("q3","","src_ip"):{"192.0.2.2":4}})
    incidents=Correlator(str(rules),gl,15).evaluate()
    assert len(incidents)==1 and incidents[0].signals==["first","second"]
    serialized=incidents[0].to_gelf()
    proof=json.loads(serialized["_xdr_evidence"])
    assert proof["schema_version"]==1 and proof["mode"]=="shared_entity"
    assert proof["signals"][0]["counts"]=={"192.0.2.1":2}
    assert any("causalité" in value for value in proof["limitations"])
    assert "192.0.2.2" not in serialized["_xdr_evidence"]
