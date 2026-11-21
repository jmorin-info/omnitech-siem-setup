"""Contrôle de santé : verdicts, niveaux et absence de fuite d'identifiants."""
from __future__ import annotations

import json
from pathlib import Path
import ssl
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy import health  # noqa: E402

SECRET = "mot-de-passe-de-test-123456"


class FakeProbes(health.Probes):
    graylog_conf = Path("/nonexistent/server.conf")

    def __init__(self, **overrides):
        self.units = {name: ("active", "enabled") for name in
                      (*health.CORE_SERVICES, "omni-alert-triage.service", "omni-soar.service")}
        self.timers_disabled = set()
        self.cluster = "green"
        self.inputs = [{"id": "a", "title": "Beats"}, {"id": "b", "title": "Syslog"}]
        self.running = {"a", "b"}
        self.ports = set(health.CORE_PORTS)
        self.failed = []
        self.legacy = []
        self.tls_error = False
        self.requests = []
        self.__dict__.update(overrides)

    def unit(self, unit):
        if unit.endswith(".timer"):
            return ("inactive", "disabled") if unit in self.timers_disabled else ("active", "enabled")
        return self.units.get(unit, ("inactive", "disabled"))

    def failed_units(self):
        return self.failed

    def listening(self):
        return self.ports

    def legacy_references(self, legacy, roots=()):
        return self.legacy

    def disk(self, path):
        return 40.0

    def http(self, url, *, headers=None, ca=None, server_name=None, verify=True, timeout=10):
        self.requests.append({"url": url, "headers": headers or {}, "verify": verify, "server_name": server_name})
        if url.endswith("/_cluster/health"):
            return 200, json.dumps({"status": self.cluster}).encode()
        if url.endswith("/system/lbstatus"):
            return 200, b"ALIVE"
        if url.endswith("/system"):
            return 200, json.dumps({"lifecycle": "running", "version": "7.2.2+abc"}).encode()
        if url.endswith("/system/inputs"):
            return 200, json.dumps({"inputs": self.inputs}).encode()
        if url.endswith("/system/inputstates"):
            return 200, json.dumps({"states": [{"id": i, "state": "RUNNING"} for i in self.running]}).encode()
        if url.endswith("/m/api/vapid"):
            return 200, b'{"publicKey": "k"}'
        if url.endswith("/soc/"):
            if self.tls_error and verify:
                raise ssl.SSLCertVerificationError("non approuvé")
            return 200, b"<html>"
        raise AssertionError("URL inattendue " + url)


CONFIG = {"SIEM_FQDN": "siem.example.test", "GRAYLOG_ADMIN_PASS": SECRET,
          "GRAYLOG_API_URL": "https://siem.example.test:9000"}


def run(probes, config=CONFIG):
    return health.summarize(health.evaluate(config, ROOT, probes))


def by_name(report):
    return {check["name"]: check for check in report["checks"]}


def test_healthy_platform_passes_without_leaking_credentials():
    probes = FakeProbes()
    report = run(probes)
    assert report["passed"] and report["failures"] == 0, report
    assert SECRET not in json.dumps(report)
    assert any(r["url"] == "https://siem.example.test:9000/api/system" for r in probes.requests)
    assert "Authorization" not in next(r for r in probes.requests if r["url"].endswith("/lbstatus"))["headers"]
    text = health.render_text(report)
    assert "plateforme opérationnelle" in text


def test_yellow_cluster_passes_red_fails():
    assert by_name(run(FakeProbes(cluster="yellow")))["opensearch:sante"]["status"] == "ok"
    report = run(FakeProbes(cluster="red"))
    assert not report["passed"] and by_name(report)["opensearch:sante"]["status"] == "echec"


def test_stopped_input_is_named():
    check = by_name(run(FakeProbes(running={"a"})))["graylog:inputs"]
    assert check["status"] == "echec" and "1/2 RUNNING" in check["detail"] and "Syslog" in check["detail"]


def test_stopped_core_service_and_missing_port_fail():
    probes = FakeProbes()
    probes.units["graylog-server"] = ("failed", "enabled")
    probes.ports = set(health.CORE_PORTS) - {9000}
    report = by_name(run(probes))
    assert report["service:graylog-server"]["status"] == "echec"
    assert "9000" in report["ports"]["detail"]


def test_disabled_units_and_timers_are_not_required():
    probes = FakeProbes(timers_disabled={"omni-leak-hibp.timer"})
    probes.units["omni-soar.service"] = ("inactive", "disabled")
    report = run(probes)
    assert report["passed"]
    assert by_name(report)["service:omni-soar.service"]["level"] == "info"


def test_failed_units_and_legacy_paths_are_warnings_only():
    report = run(FakeProbes(failed=["omni-ti-feeds.service"], legacy=["/usr/local/sbin/x"]))
    assert report["passed"] and report["warnings"] == 2
    assert "omni-ti-feeds.service" in by_name(report)["unites-en-echec"]["detail"]


def test_untrusted_console_certificate_is_reported_but_page_checked():
    report = by_name(run(FakeProbes(tls_error=True)))
    assert report["console:/soc/"]["status"] == "ok"
    assert report["console:certificat"]["status"] == "avertissement"


def test_probe_errors_never_expose_details():
    class Broken(FakeProbes):
        def http(self, url, **kwargs):
            raise ConnectionError("https://admin:" + SECRET + "@siem/api")
    report = run(Broken())
    assert not report["passed"]
    assert SECRET not in json.dumps(report)
    assert by_name(report)["graylog:systeme"]["detail"] == "sonde en erreur : ConnectionError"


def test_token_is_preferred_and_default_api_is_loopback(tmp_path):
    probes = FakeProbes()
    run(probes, {"GRAYLOG_API_TOKEN": "jeton", "SIEM_FQDN": "siem.example.test"})
    system = next(r for r in probes.requests if r["url"].endswith("/api/system"))
    assert system["url"] == "http://127.0.0.1:9000/api/system"
    assert system["headers"]["Authorization"].startswith("Basic ")


def test_missing_credentials_fail_authenticated_checks_only():
    report = by_name(run(FakeProbes(), {"SIEM_FQDN": "siem.example.test"}))
    assert report["graylog:lbstatus"]["status"] == "ok"
    assert report["graylog:systeme"]["detail"] == "sonde en erreur : PermissionError"


def test_site_config_loader_keeps_only_needed_keys(tmp_path):
    path = tmp_path / "00-vars.env"
    path.write_text(f"SIEM_FQDN=siem.example.test\nGRAYLOG_ADMIN_PASS='{SECRET}'\nMONGO_ADMIN_PASS=autre\n")
    config = health.load_site_config(path)
    assert config["GRAYLOG_ADMIN_PASS"] == SECRET and "MONGO_ADMIN_PASS" not in config
    assert health.load_site_config(tmp_path / "absent") == {}
