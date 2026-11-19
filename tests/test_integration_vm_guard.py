"""Synthetic integration writes must stay behind the isolated-VM guard."""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("omni_integration_vm", ROOT / "tools/test-integration-vm.py")
vm = module_from_spec(spec)
spec.loader.exec_module(vm)


def test_default_invocation_cannot_create_a_client_or_mutate_graylog(monkeypatch, capsys):
    monkeypatch.delenv("OMNI_ISOLATED_VM_TEST", raising=False)
    monkeypatch.setattr(vm, "Graylog", lambda *args: pytest.fail("a client must not be created"))
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
