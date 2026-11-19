"""Acceptance must reject partial installs and never expose credential-bearing errors."""
import ast
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import threading
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("omni_verify", ROOT / "tools/verify-installation.py")
verify = module_from_spec(spec)
spec.loader.exec_module(verify)


@pytest.fixture
def installed(tmp_path):
    (tmp_path / "12-graylog-pipelines.sh").write_text('ensure_rule "rule-one" <<EOF\nensure_rule "rule-two" <<EOF\n')
    assets = tmp_path / "mobile/soc"
    assets.mkdir(parents=True)
    for name in ("index.html", "app-boot.js", "manifest.webmanifest", "sw.js"):
        (assets / name).write_bytes(b"public asset")
    config = {"SIEM_FQDN": "siem.example.test", "GRAYLOG_ADMIN_PASS": "dummy-admin-password",
              "MONGO_ADMIN_PASS": "dummy-database-admin", "MONGO_GRAYLOG_PASS": "dummy-database-graylog"}
    versions = {"MONGODB_PACKAGE_VERSION": "8.0.38", "OPENSEARCH_PACKAGE_VERSION": "2.19.7", "GRAYLOG_PACKAGE_VERSION": "7.2.2-1"}
    responses = {
        "/system": {"version": "7.2.2"},
        "/system/inputs": {"inputs": [{"id": str(i), "title": title} for i, title in enumerate([
            "Winlogbeat (Beats TLS 5044)", "FortiAnalyzer (Syslog TCP 1514)", "FortiAnalyzer (Syslog UDP 1514)"])]},
        "/system/inputstates": {"states": [{"id": str(i), "state": "RUNNING"} for i in range(3)]},
        "/streams": {"streams": [{"id": "stream-" + title, "title": title, "disabled": False} for title in (
            "OMNI - Windows Security", "OMNI - Sysmon", "OMNI - Windows autres", "OMNI - FortiGate")]},
        "/system/pipelines/rule": [{"title": "rule-one"}, {"title": "rule-two"}],
        "/system/pipelines/pipeline": [{"title": title, "id": "pipeline-" + title} for title in verify.CORE_STREAMS],
        "/events/definitions?per_page=100&page=1": {"total": 2, "event_definitions": [
            {"title": "OMNI - DCSync suspect"}, {"title": "OMNI - Force brute (>=10 échecs / compte / 10 min)"}]},
        "/views?page=1&per_page=100": {"views": [{"title": "OMNI - SOC", "type": "DASHBOARD"}]},
    }
    for title in verify.CORE_STREAMS:
        responses["/system/pipelines/connections/stream-" + title] = {"pipeline_ids": ["pipeline-" + title]}
    def fetch(url, **kwargs):
        if "/api/" in url and ":9200" not in url and "/m/api/" not in url:
            assert kwargs["auth"] == config["GRAYLOG_ADMIN_PASS"]
            return json.dumps(responses[url.split("/api", 1)[1]]).encode()
        if url.endswith("/_cluster/health"):
            return b'{"status":"yellow"}'
        if url.endswith("/m/api/vapid"):
            return b'{"publicKey":""}'
        return b"public asset"
    package_versions = dict(zip(("mongodb-org-server", "opensearch", "graylog-server"), versions.values()))
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, package_versions[argv[-1]] if argv[0] == "dpkg-query" else "", "")
    kwargs = dict(fetch=fetch, service_active=lambda _: True, database_auth=lambda *args: True,
                  run=run, source_root=tmp_path)
    return config, versions, responses, kwargs


def test_acceptance_requires_services_versions_auth_inputs_rules_dashboard_and_https(installed):
    config, versions, _, kwargs = installed
    checks = verify.evaluate(config, versions, **kwargs)
    assert len(checks) >= 20 and all(item["passed"] for item in checks)
    assert "dummy-" not in json.dumps(checks)


@pytest.mark.parametrize("missing", ["input", "rule", "dashboard", "detections", "service", "mongo", "connection", "asset"])
def test_partial_installation_fails_acceptance(installed, missing):
    config, versions, responses, kwargs = installed
    if missing == "input":
        responses["/system/inputstates"]["states"][0]["state"] = "FAILED"
    elif missing == "rule":
        responses["/system/pipelines/rule"].pop()
    elif missing == "dashboard":
        responses["/views?page=1&per_page=100"]["views"] = []
    elif missing == "detections":
        responses["/events/definitions?per_page=100&page=1"]["event_definitions"] = [{"title": "System definition"}]
    elif missing == "service":
        kwargs["service_active"] = lambda name: name != "mongod"
    elif missing == "connection":
        responses["/system/pipelines/connections/stream-OMNI - Sysmon"]["pipeline_ids"] = []
    elif missing == "asset":
        (kwargs["source_root"] / "mobile/soc/app-boot.js").write_bytes(b"expected Javascript")
    else:
        kwargs["database_auth"] = lambda *args: False
    assert any(not item["passed"] for item in verify.evaluate(config, versions, **kwargs))


def test_diagnostic_does_not_echo_exception_body_or_credential(installed):
    config, versions, _, kwargs = installed
    def failed(*args, **kw):
        raise ValueError("mongodb://admin:" + config["MONGO_ADMIN_PASS"] + "@localhost; " + config["GRAYLOG_ADMIN_PASS"])
    kwargs["fetch"] = failed
    report = verify.evaluate(config, versions, **kwargs)
    assert any(not item["passed"] for item in report)
    assert "dummy-" not in json.dumps(report)


def test_http_probe_negotiates_json_and_refuses_redirects():
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/other")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"version":"7.2.2"}' if self.headers.get("Accept") == "application/json" else b"<html>UI</html>")
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        assert json.loads(verify.request(base + "/system", auth="dummy-password"))["version"] == "7.2.2"
        with pytest.raises(ValueError):
            verify.request(base + "/redirect", auth="dummy-password")
        assert calls == ["/system", "/redirect"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("responses", [[{}], [{"id": "search-id"}, {}]])
def test_dashboard_creation_failure_cannot_mark_phase_successful(responses):
    shell = (ROOT / "14-graylog-dashboards.sh").read_text()
    source = shell.split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    tree = ast.parse(source)
    build = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "build")
    namespace = {"uuid": uuid, "PARAMS": [], "post_entity": lambda *args: responses.pop(0)}
    exec(compile(ast.Module(body=[build], type_ignores=[]), "dashboard-build", "exec"), namespace)
    with pytest.raises(RuntimeError, match="creation failed"):
        namespace["build"]("test", [])
