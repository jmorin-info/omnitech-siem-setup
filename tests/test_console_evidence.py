"""Read-only details retain source references without widening access or inventing proof."""
import json

import pytest

from test_console_admin import Console
from test_console_modules import config


def document(source=None):
    return {"_index":"graylog_7", "_id":"source-record", "_source":source or {
        "timestamp":"2026-11-25T08:00:00Z", "source":"lab-fw", "event_source":"watchguard",
        "event_action":"deny", "src_ip":"192.0.2.20", "dest_ip":"198.51.100.4",
        "message":"traffic api_token=dummy-sensitive-value password=another-private-value"}}


def test_reference_retrieves_exact_document_and_redacts_obvious_credentials(api, monkeypatch):
    hit=document();calls=[]
    ref=api.evidence_ref(hit)
    assert ref and "graylog_7" not in ref and "source-record" not in ref
    def search(index,body):
        calls.append((index,body));return {"hits":{"hits":[hit]}}
    monkeypatch.setattr(api,"os_search",search)
    detail=api.get_evidence(ref,"analyst")
    assert calls[0][0]=="graylog_7"
    assert {"ids":{"values":["source-record"]}} in calls[0][1]["query"]["bool"]["filter"]
    assert detail["kind"]=="message" and detail["graylog"]["message_path"]=="/messages/graylog_7/source-record"
    assert "dummy-sensitive-value" not in json.dumps(detail) and "another-private-value" not in json.dumps(detail)
    assert any(e["kind"]=="ip" and e["role"]=="destination" for e in detail["entities"])


@pytest.mark.parametrize("index",[".security","_all","private-records","graylog_7/_doc","gl-system-events_0"])
def test_reference_cannot_open_an_arbitrary_index(api,index):
    hit=document();hit["_index"]=index
    assert api.evidence_ref(hit)==""


def test_expired_or_changed_reference_never_queries_the_backend(api,monkeypatch):
    ref=api.evidence_ref(document())
    api._EVIDENCE_REFS[ref.split(".")[0]]["expires"]=0
    monkeypatch.setattr(api,"os_search",lambda *a:pytest.fail("invalid reference queried backend"))
    with pytest.raises(api.EvidenceError):api.get_evidence(ref,"analyst")
    with pytest.raises(api.EvidenceError):api.get_evidence(ref[:-1]+("0" if ref[-1]!="0" else "1"),"analyst")


def test_module_reference_rechecks_current_role_and_page_scope(api,monkeypatch):
    page=config()["pages"][0]
    page["min_role"]="administrateur"
    monkeypatch.setattr(api,"load_modules_config",lambda:{"pages":[page]})
    monkeypatch.setattr(api,"role_at_least",lambda user,role:user=="site-admin")
    ref=api.evidence_ref(document(),scope=page["id"])
    calls=[]
    monkeypatch.setattr(api,"os_search",lambda index,body:(calls.append(body) or {"hits":{"hits":[document()]}}))
    with pytest.raises(api.EvidenceError) as error:api.get_evidence(ref,"reader")
    assert error.value.status==403 and calls==[]
    api.get_evidence(ref,"site-admin")
    assert api._module_scope(page) in calls[0]["query"]["bool"]["filter"]
    page["enabled"]=False
    with pytest.raises(api.EvidenceError):api.get_evidence(ref,"site-admin")


def test_legacy_or_empty_correlation_does_not_claim_a_preserved_proof(api):
    for raw in (None,"invalid",json.dumps({"schema_version":1})):
        result=api._evidence_document({"event_source":"xdr_incident","xdr_evidence":raw},"ref")
        assert not result["correlation"]["proof_available"]
        assert any("historiques" in s for s in result["correlation"]["limitations"])
    assert api._evidence_document({"event_source":"incident"},"ref")["kind"]=="attack_group"


def test_typed_pivots_keep_hosts_ips_and_user_domains_distinct(api):
    assert api._identity_key("DOM1\\alice")!=api._identity_key("DOM2\\alice")
    assert api._identity_key("adm-alice")!=api._identity_key("alice")
    assert "source" in json.dumps(api._entity_filter("lab-fw","host"))
    assert "dest_ip" in json.dumps(api._entity_filter("192.0.2.20","ip"))
    assert "\"user\"" not in json.dumps(api._entity_filter("lab-fw","host"))


def test_evidence_http_requires_session_and_valid_reference(tmp_path):
    instance=Console(tmp_path)
    try:
        assert instance.call("GET","/m/api/evidence?ref=invalid")[0]==401
        assert instance.call("GET","/m/api/evidence?ref=invalid","alice")[0]==400
    finally:instance.close()
