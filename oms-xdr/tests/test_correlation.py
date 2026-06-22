"""Tests du moteur de corrélation."""
from __future__ import annotations

from oms_xdr.correlation import Correlator

# Requêtes / entités telles que définies dans rules.yaml (schéma réel OMNITECH :
# détections existantes alert_tag + champs normalisés event_id/src_ip/user).
Q_SCAN_FW = 'alert_tag:network_scan'
Q_BF_VPN = 'subtype:"vpn" AND action:"ssl-login-fail"'
Q_BF_WIN = 'event_id:4625 AND logon_fail:1 AND NOT account_class:machine AND NOT account_class:service'
Q_LOGON = 'event_id:4624 AND NOT account_class:machine AND NOT account_class:service'
Q_KERB = 'alert_tag:kerberoasting OR alert_tag:kerberos_rc4'


def _corr(rules_path, factory, data):
    return Correlator(rules_path, factory(data), 15)


def test_recon_to_access_join_on_ip(rules_path, graylog_factory):
    data = {
        (Q_SCAN_FW, "fortigate", "src_ip"): {"203.0.113.9": 1},
        (Q_BF_VPN, "fortigate", "src_ip"): {"203.0.113.9": 12},
    }
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    ids = {i.rule_id for i in inc}
    assert "CR_RECON_TO_ACCESS" in ids
    r = next(i for i in inc if i.rule_id == "CR_RECON_TO_ACCESS")
    assert r.entities == ["203.0.113.9"]
    assert "T1110" in r.mitre


def test_no_join_when_different_entities(rules_path, graylog_factory):
    # scan d'une IP, brute force d'une autre -> pas de corrélation jointe
    data = {
        (Q_SCAN_FW, "fortigate", "src_ip"): {"203.0.113.9": 1},
        (Q_BF_VPN, "fortigate", "src_ip"): {"198.51.100.5": 12},
    }
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    assert "CR_RECON_TO_ACCESS" not in {i.rule_id for i in inc}


def test_threshold_not_met(rules_path, graylog_factory):
    # 4 échecs VPN < seuil 8 -> signal non déclenché
    data = {
        (Q_SCAN_FW, "fortigate", "src_ip"): {"203.0.113.9": 1},
        (Q_BF_VPN, "fortigate", "src_ip"): {"203.0.113.9": 4},
    }
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    assert "CR_RECON_TO_ACCESS" not in {i.rule_id for i in inc}


def test_kerberoast_critical(rules_path, graylog_factory):
    data = {(Q_KERB, "windows", "user"): {"svc_sql": 22}}
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    r = next(i for i in inc if i.rule_id == "CR_AD_CREDENTIAL_THEFT")
    assert r.severity == "critical"


def test_severity_ordering(rules_path, graylog_factory):
    data = {
        (Q_KERB, "windows", "user"): {"svc_sql": 22},
        (Q_SCAN_FW, "fortigate", "src_ip"): {"203.0.113.9": 1},
        (Q_BF_VPN, "fortigate", "src_ip"): {"203.0.113.9": 12},
    }
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    # le critique doit précéder le high
    assert inc[0].severity == "critical"


Q_LSASS = 'alert_tag:lsass_access'
Q_RANSOM = 'alert_tag:ransomware_indicator'


def test_lsass_theft_critical(rules_path, graylog_factory):
    data = {(Q_LSASS, "", "host"): {"WS-042": 1}}
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    r = next(i for i in inc if i.rule_id == "CR_LSASS_THEFT")
    assert r.severity == "critical"
    assert "WS-042" in r.entities


def test_ransomware_critical(rules_path, graylog_factory):
    data = {(Q_RANSOM, "", "host"): {"SRV-01": 1}}
    inc = _corr(rules_path, graylog_factory, data).evaluate()
    assert any(i.rule_id == "CR_RANSOMWARE" and i.severity == "critical" for i in inc)


def test_signal_en_echec_emet_xdr_health(rules_path, graylog_factory):
    """Robustesse (audit P2) : un signal qui lève (OpenSearch down, mapping cassé)
    ne doit PAS casser le cycle, ET doit émettre un événement de santé `xdr_health`
    — sinon la panne supprime SILENCIEUSEMENT les règles qui dépendent du signal."""
    class FaillibleGraylog(graylog_factory):
        def aggregate(self, query, stream, group_by, minutes):
            if query == Q_RANSOM:                      # ce signal échoue
                raise RuntimeError("OpenSearch timeout simulé")
            return super().aggregate(query, stream, group_by, minutes)

    gl = FaillibleGraylog({(Q_LSASS, "", "host"): {"WS-042": 1}})
    inc = Correlator(rules_path, gl, 15).evaluate()    # ne doit PAS lever
    # les autres règles fonctionnent toujours malgré le signal en échec
    assert any(i.rule_id == "CR_LSASS_THEFT" for i in inc)
    # un xdr_health a été émis et liste au moins un signal en échec
    health = [p for p in gl.sent if p.get("_event_source") == "xdr_health"]
    assert health, "aucun xdr_health émis alors qu'un signal a échoué"
    assert health[0]["_signals_failed_count"] >= 1
    assert health[0]["_signals_failed"], "liste des signaux en échec vide"


def test_severite_inconnue_sans_keyerror(rules_path, graylog_factory):
    """Robustesse (audit P2) : une sévérité hors barème (coquille YAML) ne doit
    lever NI au tri (`_SEV_ORDER`) NI à la sérialisation GELF (`level`)."""
    from oms_xdr.correlation import Incident, _SEV_ORDER
    inc = Incident(rule_id="X", title="t", severity="bogus",
                   entities=["e1"], signals=["s1"], mitre=[], tactic=[])
    g = inc.to_gelf()                       # ne doit pas lever
    assert g["level"] == 5                  # niveau par défaut sûr
    assert _SEV_ORDER.get(inc.severity, -1) == -1
