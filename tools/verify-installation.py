#!/usr/bin/env python3
"""Read-only acceptance checks for a native core SOC; emit facts, never credentials."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import ssl
import subprocess
import tempfile
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ("mongod", "opensearch", "graylog-server", "nginx", "omni-mobile-api")
CORE_STREAMS = {"OMNI - Windows Security", "OMNI - Sysmon", "OMNI - Windows autres", "OMNI - FortiGate"}


def request(url, auth=None, ca=None):
    target = urlsplit(url)
    if target.scheme not in ("http", "https") or target.username or target.password:
        raise ValueError("unsupported diagnostic URL")
    if target.scheme == "https":
        conn = http.client.HTTPSConnection(target.hostname, target.port, timeout=15,
                                          context=ssl.create_default_context(cafile=ca))
    else:
        conn = http.client.HTTPConnection(target.hostname, target.port, timeout=15)
    headers = {"X-Requested-By": "omni-acceptance", "Accept": "application/json"}
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(("admin:" + auth).encode()).decode()
    try:
        conn.request("GET", target.path + ("?" + target.query if target.query else ""), headers=headers)
        result = conn.getresponse()
        body = result.read(8 * 1024 * 1024)
        if result.status != 200:
            raise ValueError("HTTP check failed")
        return body
    finally:
        conn.close()


def active(service):
    process = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=15)
    return process.returncode == 0 and process.stdout.strip() == "active"


def mongo_auth(password, user, database):
    uri = f"mongodb://{user}:{quote(password, safe='')}@127.0.0.1:27017/{database}?authSource={database}&replicaSet=rs0"
    code = ('const c=new Mongo(process.env.OMNI_MONGO_URI);'
            'const a=c.getDB("admin").runCommand({connectionStatus:1});'
            'const h=c.getDB("admin").runCommand({hello:1});'
            'if(!a.authInfo.authenticatedUsers.length||!h.isWritablePrimary||h.setName!=="rs0")quit(2);'
            'print("AUTHENTICATED_PRIMARY");')
    result = subprocess.run(["mongosh", "--quiet", "--norc", "--nodb", "--eval", code],
                            env={**os.environ, "OMNI_MONGO_URI": uri}, capture_output=True, text=True, timeout=30)
    return result.returncode == 0 and "AUTHENTICATED_PRIMARY" in result.stdout


def pipeline_titles(source):
    # A referenced rule may come from an optional historical script. Requiring
    # only ensure_rule declarations would accept an unresolved base pipeline.
    return set(re.findall(r'^\s*(?:ensure_rule|rule)\s+["\']([^"\']+)["\']', source, re.M))


def evaluate(config, versions, *, fetch=request, service_active=active, database_auth=mongo_auth,
             run=subprocess.run, source_root=ROOT):
    checks = []

    def check(name, operation):
        try:
            value = operation()
            passed = value is not False and value is not None
            checks.append({"name": name, "passed": passed, "evidence": value})
        except Exception as exc:
            # HTTP/command exceptions can contain URLs, credentials or response bodies.
            checks.append({"name": name, "passed": False, "error_type": type(exc).__name__})

    api = config.get("GRAYLOG_API_URL") or "http://127.0.0.1:9000/api"
    api = api.rstrip("/")
    ca = (config.get("GRAYLOG_API_CA") or None) if api.startswith("https:") else None
    def get(path):
        return json.loads(fetch(api + path, auth=config["GRAYLOG_ADMIN_PASS"], ca=ca))

    def version(key):
        package = {"MONGODB_PACKAGE_VERSION": "mongodb-org-server", "OPENSEARCH_PACKAGE_VERSION": "opensearch",
                   "GRAYLOG_PACKAGE_VERSION": "graylog-server"}[key]
        result = run(["dpkg-query", "-W", "-f=${Version}", package], capture_output=True, text=True, timeout=15)
        if result.returncode or result.stdout.strip() != versions[key]:
            return False
        return {"package": package, "version": versions[key]}

    for service in SERVICES:
        check("service:" + service, lambda name=service: service_active(name))
    for key in ("MONGODB_PACKAGE_VERSION", "OPENSEARCH_PACKAGE_VERSION", "GRAYLOG_PACKAGE_VERSION"):
        check("version:" + key, lambda key=key: version(key))
    for user, database, key in (("admin", "admin", "MONGO_ADMIN_PASS"), ("graylog", "graylog", "MONGO_GRAYLOG_PASS")):
        check("mongodb:authenticated-primary:" + user, lambda u=user, d=database, k=key: database_auth(config[k], u, d))
    check("opensearch:health", lambda: json.loads(fetch("http://127.0.0.1:9200/_cluster/health")).get("status") in ("green", "yellow"))
    expected_graylog = versions["GRAYLOG_PACKAGE_VERSION"].split("-", 1)[0]
    check("graylog:authenticated-api", lambda: get("/system").get("version", "").split("+", 1)[0] == expected_graylog)

    def inputs():
        configured = get("/system/inputs")["inputs"]
        required = {"Winlogbeat (Beats TLS 5044)", "FortiAnalyzer (Syslog TCP 1514)", "FortiAnalyzer (Syslog UDP 1514)"}
        ids = {item["id"] for item in configured if item.get("title") in required}
        if len(ids) != len(required):
            return False
        states = get("/system/inputstates")["states"]
        running = {item["id"] for item in states if item.get("state") == "RUNNING"}
        return {"running_required": len(ids)} if ids <= running else False
    check("graylog:inputs-running", inputs)

    def streams():
        current = get("/streams")["streams"]
        required = CORE_STREAMS
        live = {item["title"] for item in current if not item.get("disabled", True)}
        return {"running_required": len(required)} if required <= live else False
    check("graylog:streams-running", streams)

    def rules():
        expected = pipeline_titles((source_root / "12-graylog-pipelines.sh").read_text())
        installed = {item["title"] for item in get("/system/pipelines/rule")}
        return {"required": len(expected), "present": len(expected & installed)} if expected and expected <= installed else False
    check("graylog:pipeline-rules", rules)
    def pipelines():
        streams_by_title = {item["title"]: item["id"] for item in get("/streams")["streams"]}
        pipelines_by_title = {item["title"]: item["id"] for item in get("/system/pipelines/pipeline")}
        if not CORE_STREAMS <= streams_by_title.keys() or not CORE_STREAMS <= pipelines_by_title.keys():
            return False
        for title in CORE_STREAMS:
            connected = get("/system/pipelines/connections/" + streams_by_title[title]).get("pipeline_ids", [])
            if pipelines_by_title[title] not in connected:
                return False
        return {"connected_required": len(CORE_STREAMS)}
    check("graylog:pipelines", pipelines)

    def detections():
        names = set()
        for page in range(1, 101):
            data = get(f"/events/definitions?per_page=100&page={page}")
            items = data.get("event_definitions", data.get("elements", []))
            names.update(item["title"] for item in items)
            if not items or page * 100 >= data.get("total", len(items)):
                break
        required = {"OMNI - DCSync suspect", "OMNI - Force brute (>=10 échecs / compte / 10 min)"}
        return {"omni_definitions": sum(name.startswith("OMNI - ") for name in names)} if required <= names else False
    check("graylog:detections", detections)

    def dashboard():
        data = get("/views?page=1&per_page=100")
        views = data.get("views", data.get("elements", []))
        return any(view.get("title") == "OMNI - SOC" and view.get("type") == "DASHBOARD" for view in views)
    check("graylog:soc-dashboard", dashboard)
    check("nginx:configuration", lambda: run(["nginx", "-t"], capture_output=True, timeout=15).returncode == 0)
    web = "https://" + config["SIEM_FQDN"]
    cert = "/etc/nginx/ssl/graylog.crt"
    for path, local in (("/soc/", "index.html"), ("/soc/app-boot.js", "app-boot.js"),
                        ("/soc/manifest.webmanifest", "manifest.webmanifest"), ("/soc/sw.js", "sw.js")):
        def asset(path=path, local=local):
            served = fetch(web + path, ca=cert)
            expected = (source_root / "mobile/soc" / local).read_bytes()
            return bool(expected) and hashlib.sha256(served).digest() == hashlib.sha256(expected).digest()
        check("https:" + path, asset)
    check("https:/m/api/vapid", lambda: isinstance(json.loads(fetch(web + "/m/api/vapid", ca=cert)).get("publicKey"), str))
    check("backups:timer", lambda: service_active("siem-backup.timer"))
    return checks


def write_report(path, report):
    if path.is_symlink():
        raise ValueError("symlinked report destination is refused")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, indent=2)
            stream.write("\n")
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="also save the sanitized JSON report")
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "kernel": platform.release(), "python": platform.python_version(), "passed": False, "checks": []}
    signature = Path("/proc/version_signature")
    if signature.is_file():
        report["kernel_signature"] = signature.read_text().strip()
    try:
        spec = importlib.util.spec_from_file_location("omni_installer", ROOT / "tools/install-platform.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        os_id, os_version = module.read_os()
        report["platform"] = f"{os_id}:{os_version}"
        report["source_revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        state_path = Path("/var/lib/omni-siem/install-state.json")
        if state_path.is_file():
            state = json.loads(state_path.read_text())
            phase = state.get("current_phase")
            allowed = {name for name, _ in module.PHASES} | {"triage"}
            report["installation"] = {"last_phase": phase if phase in allowed else "unknown",
                                      "completed_phases": len(state.get("completed_phases", []))}
        config_path = ROOT / "00-vars.env"
        if config_path.is_symlink():
            raise ValueError("symlinked configuration")
        config = module.load_config(config_path)
        graylog_config = Path("/etc/graylog/server/server.conf")
        if not config.get("GRAYLOG_API_URL") and graylog_config.is_file():
            if re.search(r"(?m)^http_enable_tls\s*=\s*true\s*$", graylog_config.read_text()):
                config["GRAYLOG_API_URL"] = "https://" + config["SIEM_FQDN"] + ":9000/api"
        versions = dict(line.split("=", 1) for line in (ROOT / "stack-versions.env").read_text().splitlines()
                        if line and not line.startswith("#"))
        report["checks"] = evaluate(config, versions)
        report["passed"] = bool(report["checks"]) and all(item["passed"] for item in report["checks"])
    except Exception as exc:
        report["checks"].append({"name": "configuration-or-platform", "passed": False, "error_type": type(exc).__name__})
    if args.output:
        write_report(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
