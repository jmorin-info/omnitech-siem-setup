"""Context keeps roles, record boundaries and unknowns across all mail adapters."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("alert_context_test", ROOT / "triage/omni_alert_context.py")
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)


def payload(*messages):
    return {"event":{"event_definition_title":"Synthetic alert", "fields":{}, "priority":3},
            "backlog":[{"message":m} for m in messages]}


def values(record, kind):
    return [fact["value"] for fact in record["facts"].get(kind, [])]


def test_two_logs_cannot_fabricate_a_user_machine_connection():
    raw = payload({"user":"ORG1\\alice", "src_ip":"192.0.2.10"}, {"host":"server-b", "dest_ip":"198.51.100.4"})
    before = copy.deepcopy(raw)
    result = context.build_context(raw)
    first, second = result["records"][1:]
    assert values(first, "account") == ["ORG1\\alice"] and not values(first, "host")
    assert values(second, "host") == ["server-b"] and not values(second, "account")
    assert first["facts"]["source_ip"][0]["record"] != second["facts"]["destination_ip"][0]["record"]
    assert not result["causal_chain_proven"] and before == raw


def test_account_domains_and_privilege_prefixes_remain_distinct():
    result = context.build_context(payload({"user":["ORG1\\alice", "ORG2\\alice", "adm-alice", "alice@example.test"]}))
    assert len(values(result["records"][1], "account")) == 4


def test_collector_cannot_become_host_environment_or_actor():
    record = context.build_context(payload({"source":"qa-collector", "identity":"alice"}))["records"][1]
    assert values(record, "collector") == ["qa-collector"]
    assert not any(values(record, key) for key in ("host", "environment", "actor"))


def test_actor_target_and_system_account_are_not_silently_reassigned():
    result = context.build_context(payload({"user":"NT AUTHORITY\\SYSTEM", "actor_login":"operator",
        "winlogbeat_winlog_event_data_TargetUserName":"victim", "host":"endpoint"}))
    record = result["records"][1]
    assert values(record, "actor") == ["operator"]
    assert values(record, "target_account") == ["victim"]
    assert values(record, "account") == ["NT AUTHORITY\\SYSTEM"]


@pytest.mark.parametrize("fields", [
    {"event_source":"watchguard", "src_ip":"192.0.2.1", "dest_ip":"198.51.100.1", "dest_port":443},
    {"event_source":"unifi", "user":"guest", "host":"ap-lab"},
    {"event_source":"paloalto", "src_ip":"2001:db8::1", "dest_ip":"2001:db8::2", "event_action":"deny"},
    {"event_source":"m365", "upn":"alice@example.test", "event_action":"login"},
    {"event_source":"sysmon", "process_name":"powershell.exe", "parent_process":"service.exe"},
    {"event_source":"seal", "seal_site":"site-a", "door_id":"door-4", "actor_login":"operator"},
    {"event_source":"vuln", "host":"server", "risk_severity":"high"},
    {"event_source":"collecte_sla", "event_action":"host_go_dark"},
])
def test_source_types_keep_their_original_fields_and_unknowns(fields):
    result = context.build_context(payload(fields))
    record = result["records"][1]
    assert values(record, "event_source") == [fields["event_source"]]
    for facts in record["facts"].values():
        assert all(f["field"] in fields and f["record"] == "backlog:0" for f in facts)
    assert "Non renseigné" in context.render_text(result)


def test_alarm_code_object_label_and_network_port_are_not_called_a_door():
    record = context.build_context(payload({"trigger_code":"ALARM-22", "target_object_label":"Camera lobby", "dest_port":443}))["records"][1]
    assert values(record, "trigger") == ["ALARM-22"] and values(record, "object") == ["Camera lobby"]
    assert values(record, "destination_port") == ["443"] and not values(record, "door")


def test_conflicting_aliases_are_retained_instead_of_silently_overwritten():
    record = context.build_context(payload({"src_ip":"192.0.2.1", "srcip":"192.0.2.2"}))["records"][1]
    assert values(record, "source_ip") == ["192.0.2.1", "192.0.2.2"]


def test_invalid_ips_and_ports_do_not_look_like_observed_network_endpoints():
    record = context.build_context(payload({"src_ip":"999.1.1.1", "dest_ip":"hostname", "src_port":-1, "dest_port":65536}))["records"][1]
    assert not any(values(record, k) for k in ("source_ip", "destination_ip", "source_port", "destination_port"))


def test_risk_is_not_rescaled_and_notification_priority_stays_separate():
    result = context.build_context(payload({"risk_score":7, "risk_severity":"high"}))
    text = context.render_text(result)
    assert values(result["records"][1], "risk_score") == ["7"]
    assert values(result["records"][0], "priority") == ["3"]
    assert "échelle" in text and "/100" not in text


def test_timestamp_timezone_and_window_are_explicit():
    raw = payload({"timestamp":"2026-11-26T09:00:00+01:00"}, {"timestamp":"2026-11-26T09:00:00"})
    raw["event"]["replay_info"] = {"timerange_start":"2026-11-26T08:00:00Z", "timerange_end":"2026-11-26T10:00:00Z"}
    result = context.build_context(raw)
    assert result["records"][1]["timestamp"]["utc"] == "2026-11-26T08:00:00+00:00"
    assert result["records"][2]["timestamp"]["status"] == "timezone_missing"
    assert result["window"]["status"] == "known"
    assert "2026-11-26T08:00:00+00:00 → 2026-11-26T10:00:00+00:00" in context.render_text(result)
    raw["event"]["replay_info"]["timerange_end"] = "2026-11-26T07:00:00Z"
    assert context.build_context(raw)["window"]["status"] == "unknown"


def test_bounded_records_values_and_text_report_truncation():
    result = context.build_context(payload(*[{"user":["u" + str(n) for n in range(12)], "tool":"x" * 1000}] * 23))
    assert result["coverage"]["included"] == 20 and result["coverage"]["omitted"] == 3
    assert result["coverage"]["value_truncations"][0]["values_omitted"] == 4
    assert result["records"][1]["facts"]["tool"][0]["truncated"]
    assert "3 omis" in context.render_text(result)


def test_invalid_payloads_and_empty_sentinels_are_not_replaced_by_guesses():
    with pytest.raises(ValueError):
        context.build_context([])
    result = context.build_context(payload({"user":"N/A", "host":"(Empty Value)", "risk_score":float("nan"),
                                            "priority":True, "site":{"name":"not-a-scalar"}}))
    assert result["records"][1]["facts"] == {}
    assert "account" in result["missing"] and "host" in result["missing"]


def test_risk_scale_from_another_record_does_not_complete_a_score():
    result = context.build_context(payload({"risk_score":7}, {"risk_scale":100}))
    assert any("échelle" in text for text in result["limitations"])


def test_html_and_plain_share_facts_escape_active_content_and_redact_secrets():
    result = context.build_context(payload({"user":"<img src=x onerror=alert(1)>",
        "process_path":"https://operator:private-url-value@example.test/app token=private-api-value"}))
    raw = json.dumps(result)
    assert "private-url-value" not in raw and "private-api-value" not in raw
    plain, page = context.render_text(result), context.render_html(result)
    assert "<img" in plain and "<img" not in page and "&lt;img" in page
    assert "IP source" in plain and "IP source" in page
    assert not re.search(r"<(?:script|img|iframe)\b", page)


@pytest.mark.parametrize("value", ["Basic dGVzdDpwYXNz", "Bearer synthetic-value", "password='synthetic quoted value'", "api_key=synthetic-key&mode=x"])
def test_obvious_credentials_inside_allowed_values_are_masked(value):
    clean = context.clean(value)
    assert "[masqué]" in clean and value not in clean


def test_absence_of_backlog_never_becomes_zero_events_or_full_evidence():
    result = context.build_context({"event":{"fields":{"entities":"host-a,user-b", "signals":"signal-a,signal-b"}}})
    assert result["coverage"]["included"] == 0 and not result["causal_chain_proven"]
    assert any("Aucun événement" in text for text in result["limitations"])


@pytest.mark.parametrize("count", [0, 124, None, -1, True, "124", float("inf"), 10**1000])
def test_real_aggregation_count_is_distinct_from_backlog_size(count):
    raw = payload({"host":"lab"})
    raw["event"]["aggregation_conditions"] = {"count":count}
    result = context.build_context(raw)
    expected = 0 if type(count) is int and count == 0 else 124 if type(count) is int and count == 124 else None
    assert result["occurrences"]["value"] == expected
    assert result["coverage"]["attached"] == 1


@pytest.mark.skipif(os.name != "posix", reason="Unix preview permissions")
def test_preview_cli_is_private_offline_and_refuses_overwriting(tmp_path):
    source, output = tmp_path / "input.json", tmp_path / "preview"
    source.write_text(json.dumps(payload({"user":"synthetic-user", "src_ip":"192.0.2.20"})))
    args = [sys.executable, str(ROOT / "tools/preview-alert-context.py"), "--payload", str(source), "--output", str(output)]
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    assert not json.loads(result.stdout)["delivery_performed"] and "synthetic-user" not in result.stdout
    assert output.stat().st_mode & 0o777 == 0o700
    for name in ("context.json", "alert.txt", "alert.html"):
        assert (output / name).stat().st_mode & 0o777 == 0o600
    before = (output / "context.json").read_bytes()
    assert subprocess.run(args, capture_output=True).returncode != 0
    assert (output / "context.json").read_bytes() == before
