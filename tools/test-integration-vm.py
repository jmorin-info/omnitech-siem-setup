#!/usr/bin/env python3
"""Install integration packs and inject synthetic fixtures in an isolated lab VM only."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_integrations.client import ApiError, Graylog, NoRedirect, install, parameters
from omni_integrations.core import CATALOG, build_pack, catalog, stable_id


def verify_identity(config, metadata, hostname, root):
    if config.get("SIEM_FQDN") != "siem.lab.test" or config.get("SIEM_IP") != "10.0.2.15":
        raise ValueError("only the isolated VM fixture identity is accepted")
    if hostname not in ("siem.lab.test", "siem-lab", "siem"):
        raise ValueError("only the isolated VM hostname is accepted")
    if metadata.get("profile") != "core-soc" or metadata.get("source_root") != str(root):
        raise ValueError("the completed isolated core installation is required")


def isolated_configuration():
    if os.environ.get("OMNI_ISOLATED_VM_TEST") != "1":
        raise ValueError("OMNI_ISOLATED_VM_TEST=1 is required; this tool writes lab data")
    if os.geteuid() != 0:
        raise ValueError("run only as root in the isolated test VM")
    marker = Path("/run/omni-isolated-vm-test")
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("the isolated VM marker is required")
    mode = marker.stat()
    if mode.st_uid != 0 or mode.st_mode & 0o077:
        raise ValueError("the isolated VM marker must be root-only")
    spec = importlib.util.spec_from_file_location("omni_install", ROOT / "tools/install-platform.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    config = installer.load_config(ROOT / "00-vars.env")
    metadata = json.loads(Path("/etc/omni-siem/instance.json").read_text())
    verify_identity(config, metadata, socket.gethostname(), ROOT)
    return config


def indexed_messages(module_id, since):
    query = {"size": 100, "query": {"bool": {"filter": [
        {"term": {"omni_integration_id": module_id}}, {"range": {"timestamp": {"gte": since}}}]}}}
    request = urllib.request.Request("http://127.0.0.1:9200/_search", method="POST",
        data=json.dumps(query).encode(), headers={"Content-Type": "application/json"})
    # Loopback is fixed: neither caller configuration nor environment can select another server.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=15) as response:
        return [item["_source"] for item in json.load(response).get("hits", {}).get("hits", [])]


def input_running(client, input_id):
    states = client.call("GET", "/system/inputstates")["states"]
    return any(item.get("id") == input_id and item.get("state") == "RUNNING" for item in states)


def input_evidence(client, input_id, module_id, port, fixtures):
    """Diagnose lab delivery without publishing a log or arbitrary field value."""
    state = client.call("GET", "/system/inputstates/" + input_id)
    saved = client.call("GET", "/system/inputs/" + input_id)
    fields = saved.get("static_fields", {})
    request = urllib.request.Request("http://127.0.0.1:9200/_search", method="POST",
        data=json.dumps({"size": 100, "query": {"term": {"gl2_source_input": input_id}}}).encode(),
        headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=15) as response:
        messages = [item["_source"] for item in json.load(response).get("hits", {}).get("hits", [])]
    listening = subprocess.run(["ss", "-H", "-lun", "sport", "=", ":" + str(port)],
                               capture_output=True, text=True, timeout=10)
    allowed = {"RUNNING", "STARTING", "STOPPING", "STOPPED", "TERMINATED", "FAILED"}
    return {"input_state": state.get("state") if state.get("state") in allowed else "unknown",
            "udp_socket_present": listening.returncode == 0 and bool(listening.stdout.strip()),
            "static_tag_saved": fields.get("omni_integration_id") == module_id,
            "indexed_by_input": len(messages),
            "tag_present": sum(item.get("omni_integration_id") == module_id for item in messages),
            "exact_fixture_matches": sum(any(item.get("message") == fixture["message"] for item in messages) for fixture in fixtures),
            "processing_errors": sum(bool(item.get("gl2_processing_error")) for item in messages)}


def fixture_results(fixtures, messages, module_id, stream_id):
    results = []
    for index, fixture in enumerate(fixtures, 1):
        candidates = [message for message in messages if message.get("message") == fixture["message"]]
        expected = {"omni_parse_status": "parsed", "event_source": module_id, **fixture["expected"]}
        matching = [message for message in candidates if all(message.get(key) == value for key, value in expected.items())]
        routed = any(stream_id in message.get("streams", []) for message in matching)
        best = matching[0] if matching else candidates[0] if candidates else {}
        results.append({"fixture": index, "received": bool(candidates), "normalized": bool(matching),
                        "routed_to_module_stream": routed,
                        "mismatched_fields": sorted(key for key, value in expected.items() if best.get(key) != value)})
    return results


def dashboard_result_evidence(job, view, module_id, fixtures):
    """Retain flags/counts only, never a returned log, search error or field value."""
    evidence = {"completed": False, "error_free": False, "search_type_results": 0,
                "six_search_types": False, "volume_positive": False,
                "fixtures_visible": False, "messages_scoped": False, "passed": False}
    execution = job.get("execution", {})
    evidence["completed"] = execution.get("done") is True
    if (not evidence["completed"] or execution.get("cancelled") is not False
            or execution.get("completed_exceptionally") is not False or job.get("errors")):
        return evidence
    results = job.get("results", {})
    states = view.get("state", {})
    if len(states) != 1 or set(results) != set(states):
        return evidence
    query_id, state = next(iter(states.items()))
    result = results[query_id]
    if result.get("state") != "COMPLETED" or result.get("errors"):
        return evidence
    evidence["error_free"] = True
    types = result.get("search_types", {})
    mapping = state.get("widget_mapping", {})
    expected = {identifier for identifiers in mapping.values() for identifier in identifiers}
    widget_types = {"aggregation": "pivot", "messages": "messages"}
    expected_types = {identifier: widget_types[widget["type"]]
                      for widget in state.get("widgets", []) if widget.get("type") in widget_types
                      for identifier in mapping.get(widget["id"], [])}
    evidence["search_type_results"] = len(types)
    evidence["six_search_types"] = (len(mapping) == len(expected) == len(types) == 6
                                     and expected == set(types) == set(expected_types)
                                     and all(item.get("type") == expected_types[identifier] for identifier, item in types.items()))
    if any(item.get("errors") for item in types.values()):
        evidence["error_free"] = False
    if not evidence["six_search_types"] or not evidence["error_free"]:
        return evidence
    volume_ids = mapping.get(stable_id(module_id, "widget-0"), [])
    message_ids = mapping.get(stable_id(module_id, "widget-logs"), [])
    if len(volume_ids) != 1 or len(message_ids) != 1:
        return evidence
    volume, messages = types[volume_ids[0]], types[message_ids[0]]
    if volume.get("type") != "pivot" or messages.get("type") != "messages":
        return evidence
    counts = [value.get("value") for row in volume.get("rows", []) for value in row.get("values", [])
              if value.get("key") == ["count()"]]
    evidence["volume_positive"] = any(isinstance(count, (int, float)) and not isinstance(count, bool)
                                      and count >= len(fixtures) > 0 for count in counts)
    logs = [item.get("message", {}) for item in messages.get("messages", [])]
    evidence["fixtures_visible"] = bool(fixtures) and all(
        any(log.get("message") == fixture["message"] for log in logs) for fixture in fixtures)
    evidence["messages_scoped"] = bool(logs) and all(log.get("omni_integration_id") == module_id for log in logs)
    evidence["passed"] = all(evidence[key] for key in (
        "completed", "error_free", "six_search_types", "volume_positive", "fixtures_visible", "messages_scoped"))
    return evidence


def execute_dashboard(client, view, module_id, fixtures):
    """Execute the existing saved search in the guarded disposable VM only.

    Graylog 7.2.2 SearchResource exposes POST {id}/execute and GET status/{jobId};
    SearchJobDTO supplies execution and QueryResult supplies search_types/errors.
    No saved query, view, source stream or parameter is rewritten for this proof.
    """
    search_id = view.get("search_id", "")
    if not isinstance(search_id, str) or not re.fullmatch(r"[a-f0-9]{24}", search_id):
        raise ValueError("the installed dashboard must reference its saved search")
    job = client.call("POST", "/views/search/" + search_id + "/execute", {})
    job_id = job.get("id", "")
    # InMemorySearchJobService.create() uses new ObjectId().toHexString().
    if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{24}", job_id):
        raise ValueError("the dashboard search returned an invalid job identifier")
    for attempt in range(60):
        job = client.call("GET", "/views/search/status/" + job_id)
        if job.get("execution", {}).get("done") is True:
            return dashboard_result_evidence(job, view, module_id, fixtures)
        time.sleep(1)
    evidence = dashboard_result_evidence(job, view, module_id, fixtures)
    evidence["timed_out"] = True
    return evidence


def console_session(password):
    """Exercise browser authentication only after the lab identity guard succeeds."""
    context = ssl.create_default_context(cafile="/etc/nginx/ssl/graylog.crt")
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(cookies))
    def call(path, data=None):
        request = urllib.request.Request("https://siem.lab.test" + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://siem.lab.test"})
        with opener.open(request, timeout=30) as response:
            return json.load(response)
    if call("/m/api/login", {"username": "admin", "password": password}).get("ok") is not True:
        return False
    try:
        authenticated = call("/m/api/me").get("user") == "admin"
    finally:
        call("/m/api/logout", {})
    try:
        call("/m/api/me")
    except urllib.error.HTTPError as exc:
        return authenticated and exc.code == 401
    return False


def backup_test(config):
    """Run the installed backup job only inside the guarded disposable VM."""
    result = subprocess.run(["systemctl", "start", "siem-backup.service"], capture_output=True, timeout=420)
    directory = Path(config["BACKUP_DIR"])
    mongo = [path for path in (directory / "mongo").glob("graylog-mongo-*.archive.gz") if path.stat().st_size > 0]
    archives = sorted((directory / "configs").glob("siem-configs-*.tar.gz"), key=lambda path: path.stat().st_mtime)
    names = []
    if archives:
        with tarfile.open(archives[-1]) as archive:
            names = archive.getnames()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open("http://127.0.0.1:9200/_snapshot/graylog_fs/_all", timeout=15) as response:
        snapshots = json.load(response).get("snapshots", [])
    facts = {"job_success": result.returncode == 0, "mongo_archive": bool(mongo),
             "site_configuration": any(name.endswith("/00-vars.env") or name == "00-vars.env" for name in names),
             "console_configuration": "etc/default/omni-mobile" in names,
             "snapshot_success": any(item.get("state") == "SUCCESS" and item.get("snapshot", "").startswith("snap-") for item in snapshots)}
    facts["passed"] = all(facts.values())
    return facts


def test_module(client, module, report):
    report["stage"] = "install"
    plan = install(client, module, parameters(module), apply=True)
    report["installed"] = plan["action"] in ("installed", "already-installed")
    pack = build_pack(module)
    installations = client.call("GET", f"/system/content_packs/{pack['id']}/installations")["installations"]
    installation = next(item for item in installations if item.get("_id") == plan["installation_id"])
    owned = installation.get("entities", [])
    def entity(role, kind):
        found = [item for item in owned if item.get("content_pack_entity_id") == stable_id(module["id"], role)
                 and item.get("type", {}).get("name") == kind]
        if len(found) != 1:
            raise ValueError("owned module entity could not be identified")
        return found[0]["id"]
    input_id, stream_id = entity("input", "input"), entity("stream", "stream")
    pipeline_id, dashboard_id = entity("pipeline", "pipeline"), entity("dashboard", "dashboard")
    stream = client.call("GET", "/streams/" + stream_id)
    report["stream_running"] = stream.get("disabled") is False
    connection = client.call("GET", "/system/pipelines/connections/" + stream_id)
    report["pipeline_connected"] = pipeline_id in connection.get("pipeline_ids", [])
    view = client.call("GET", "/views/" + dashboard_id)
    widgets = [widget for state in view.get("state", {}).values() for widget in state.get("widgets", [])]
    report["dashboard_widgets"] = len(widgets)
    report["dashboard_scoped"] = len(widgets) == 6 and all(stream_id in widget.get("streams", []) for widget in widgets)
    report["stage"] = "input_start"
    for attempt in range(30):
        if input_running(client, input_id):
            break
        time.sleep(2)
    else:
        raise RuntimeError("the module input did not start")
    report["input_running"] = True
    fixtures = json.loads((CATALOG / module["id"] / "fixtures.json").read_text())
    # Graylog timestamps have millisecond precision; do not exclude a datagram
    # received in the same millisecond as this Python microsecond timestamp.
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=2)).isoformat()
    report["stage"] = "udp_fixtures"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for fixture in fixtures:
            sender.sendto(fixture["message"].encode(), ("127.0.0.1", module["default_port"]))
    report["fixtures_expected"] = len(fixtures)
    report["fixtures"] = []
    for attempt in range(60):
        report["fixtures"] = fixture_results(fixtures, indexed_messages(module["id"], since), module["id"], stream_id)
        if all(item["received"] and item["normalized"] and item["routed_to_module_stream"] for item in report["fixtures"]):
            break
        time.sleep(2)
    report["fixtures_received"] = sum(item["received"] for item in report["fixtures"])
    report["delivery_evidence"] = input_evidence(client, input_id, module["id"], module["default_port"], fixtures)
    report["stage"] = "dashboard_search"
    report["dashboard_search"] = execute_dashboard(client, view, module["id"], fixtures)
    report["passed"] = all(report.get(key) is True for key in (
        "installed", "stream_running", "pipeline_connected", "dashboard_scoped", "input_running")) and all(
        item["received"] and item["normalized"] and item["routed_to_module_stream"] for item in report["fixtures"]) and report["dashboard_search"]["passed"]
    report["stage"] = "complete"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "passed": False, "scope": "isolated VM; synthetic fixtures only", "modules": []}
    try:
        config = isolated_configuration()
        report["console_login_logout"] = console_session(config["GRAYLOG_ADMIN_PASS"])
        client = Graylog("http://127.0.0.1:9000/api", "isolated-vm-placeholder")
        client.authorization = "Basic " + base64.b64encode(("admin:" + config["GRAYLOG_ADMIN_PASS"]).encode()).decode()
        client.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        for module in catalog():
            result = {"module": module["id"], "passed": False}
            report["modules"].append(result)
            try:
                test_module(client, module, result)
            except Exception as exc:
                result["error_type"] = type(exc).__name__
                if isinstance(exc, ApiError):
                    result["http_status"] = exc.status
                    result["operation"] = str(exc)
        report["fixtures_expected"] = sum(item.get("fixtures_expected", 0) for item in report["modules"])
        report["fixtures_received"] = sum(item.get("fixtures_received", 0) for item in report["modules"])
        report["backup"] = backup_test(config)
        report["passed"] = report["backup"]["passed"] and report["console_login_logout"] and len(report["modules"]) == 3 and report["fixtures_expected"] == 10 and all(
            item["passed"] for item in report["modules"])
    except Exception as exc:
        report["error_type"] = type(exc).__name__
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        if args.output.is_symlink():
            raise ValueError("symlinked report output is refused")
        with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        os.replace(temporary, args.output)
    else:
        print(text, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
