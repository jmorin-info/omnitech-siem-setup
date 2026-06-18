"""Tests des playbooks de remédiation."""
from oms_xdr.remediation import build_remediation


def test_playbook_has_actions():
    rem = build_remediation("CR_EXECUTION_C2", ["T1059.001", "T1071"])
    assert "isolate_ninjaone" in rem["actions"]
    assert "block_fortigate" in rem["actions"]
    assert "Actions recommandées" in rem["text"]


def test_unknown_rule_falls_back():
    rem = build_remediation("CR_DOES_NOT_EXIST", [])
    assert rem["actions"] == []
    assert "Investigation manuelle" in rem["text"]


def test_mitre_context_rendered():
    rem = build_remediation("CR_AD_CREDENTIAL_THEFT", ["T1558.003"])
    assert "Kerberoasting" in rem["text"]
