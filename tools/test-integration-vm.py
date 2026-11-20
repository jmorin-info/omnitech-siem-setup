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
    report["passed"] = all(report.get(key) is True for key in (
        "installed", "stream_running", "pipeline_connected", "dashboard_scoped", "input_running")) and all(
        item["received"] and item["normalized"] and item["routed_to_module_stream"] for item in report["fixtures"])
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
