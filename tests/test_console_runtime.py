"""Exercise the Docker entrypoint and real nginx routing on Linux, without Graylog."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("console_deploy_runtime", ROOT / "tools/deploy-console.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def test_packaged_backend_uses_configured_lookup_directory(tmp_path, monkeypatch):
    packaged = tmp_path / "application"
    packaged.mkdir()
    backend = packaged / "omni-mobile-api.py"
    shutil.copyfile(ROOT / "mobile/omni-mobile-api.py", backend)
    lookups = tmp_path / "site-lookups"
    lookups.mkdir()
    (lookups / "site-techniques.csv").write_text("alert_tag,technique,technique_name,tactic,severity\nfixture,T1110,Brute Force,Credential Access,high\n")
    (lookups / "alert-guidance.json").write_text(json.dumps({"fixture": {"ce_que_cest": "Guide du site"}}))
    config = tmp_path / "mobile.conf"
    config.write_text("MOBILE_SECRET=fixture-session-secret\nMOBILE_PUSH_SECRET=fixture-push-secret\n"
                      f"MOBILE_SUBS_FILE={tmp_path}/state/subs.json\nMITRE_LOOKUP={lookups}/site-techniques.csv\n"
                      f"MOBILE_CASES_FILE={tmp_path}/state/cases.json\nMOBILE_WATCH_FILE={tmp_path}/state/watchlist.json\n"
                      f"SOC_REQ_DIR={tmp_path}/state/requests\n")
    monkeypatch.setenv("MOBILE_CONFIG", str(config))
    module_spec = importlib.util.spec_from_file_location("packaged_mobile_api", backend)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    assert module.get_guidance()["fixture"] == {"ce_que_cest": "Guide du site", "technique": "T1110",
                                             "name": "Brute Force", "tactic": "Credential Access", "severity": "high"}


@pytest.mark.skipif(os.name != "posix", reason="native Linux shell wrapper")
def test_native_wrapper_exports_site_identity_and_log_scope(tmp_path):
    shutil.copyfile(ROOT / "71-soc-console.sh", tmp_path / "71-soc-console.sh")
    (tmp_path / "tools").mkdir()
    (tmp_path / "00-vars.env").write_text(
        'SIEM_FQDN=siem.customer.test\nSIEM_IP=192.0.2.10\n'
        'SOC_LOG_INDICES="customer-*,graylog_*"\nGRAYLOG_API_CA=/etc/site/ca.crt\n'
        'SOC_ORIGINS=siem.customer.test,192.0.2.10\nSOC_EXPECTED_SOURCES=watchguard:120\n')
    (tmp_path / "tools/install-console.sh").write_text(
        '#!/bin/bash\npython3 -c \'import json,os; print(json.dumps({k:os.environ.get(k) '
        'for k in ("SIEM_FQDN","SIEM_IP","SOC_LOG_INDICES","GRAYLOG_API_CA","SOC_ORIGINS","SOC_EXPECTED_SOURCES")}))\'\n')
    result = subprocess.run(["bash", str(tmp_path / "71-soc-console.sh")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "SIEM_FQDN": "siem.customer.test", "SIEM_IP": "192.0.2.10",
        "SOC_LOG_INDICES": "customer-*,graylog_*", "GRAYLOG_API_CA": "/etc/site/ca.crt",
        "SOC_ORIGINS": "siem.customer.test,192.0.2.10", "SOC_EXPECTED_SOURCES": "watchguard:120"}


@pytest.mark.skipif(os.name != "posix", reason="Linux container entrypoint")
@pytest.mark.parametrize("file_secret", [False, True])
@pytest.mark.parametrize("expected_sources", ["", "watchguard:120,unifi:240"])
def test_container_entrypoint_runs_with_env_or_file_secrets(tmp_path, file_secret, expected_sources):
    binary = tmp_path / "python"
    binary.write_text("#!/bin/sh\nprintf ready > \"$MOBILE_DATA_DIR/started\"\n")
    binary.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MOBILE_", "GRAYLOG_"))}
    env.update(PATH=str(tmp_path) + os.pathsep + env.get("PATH", ""),
               MOBILE_DATA_DIR=str(tmp_path / "data"), MOBILE_SECRET="test-session", MOBILE_PUSH_SECRET="test-push",
               SIEM_FQDN="siem.customer.test", SIEM_IP="192.0.2.10", SOC_LOG_INDICES="customer-*,graylog_*",
               SOC_EXPECTED_SOURCES=expected_sources)
    if file_secret:
        secret = tmp_path / "secret"
        # A secret is data: shell substitution must never run.
        secret.write_text("test-$(touch " + str(tmp_path / "injected") + ")")
        env["MOBILE_SECRET_FILE"] = str(secret)
    result = subprocess.run(["bash", str(ROOT / "docker/console-entrypoint.sh")], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "data/started").read_text() == "ready"
    config = (tmp_path / "data/omni-mobile.conf").read_text()
    assert "MOBILE_ALLOW_HTTP_DOCKER=1" in config
    assert "SIEM_FQDN=siem.customer.test\n" in config
    assert "SIEM_IP=192.0.2.10\n" in config
    assert "SOC_LOG_INDICES=customer-*,graylog_*\n" in config
    assert "SOC_EXPECTED_SOURCES=" + expected_sources + "\n" in config
    assert "OMNI_REPO_DIR=/app\n" in config
    assert "SOC_KPI_TOOL=/app/tools/omni-soc-kpi.py\n" in config
    assert not (tmp_path / "injected").exists()
    assert ((tmp_path / "data/omni-mobile.conf").stat().st_mode & 0o077) == 0


@pytest.mark.skipif(os.name != "posix" or not shutil.which("nginx"), reason="requires Linux nginx")
def test_real_nginx_serves_complete_console_and_missing_assets_return_404(tmp_path):
    soc, mobile = tmp_path / "soc", tmp_path / "mobile"
    deploy.publish(ROOT / "mobile/soc", soc)
    deploy.publish(ROOT / "mobile/www", mobile)
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        port = candidate.getsockname()[1]
    user = "user root;" if os.geteuid() == 0 else ""
    site = f"server {{\n listen 127.0.0.1:{port};\n location / {{ return 418; }}\n}}\n"
    site = deploy.add_routes(site, soc, mobile)
    config = tmp_path / "nginx.conf"
    config.write_text(f"{user}\npid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\nevents {{}}\nhttp {{ access_log off; {site} }}\n")
    command = [shutil.which("nginx"), "-p", str(tmp_path), "-c", str(config)]
    subprocess.run(command + ["-t"], check=True, capture_output=True)
    process = subprocess.Popen(command + ["-g", "daemon off; master_process off;"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                with urllib.request.urlopen(base + "/soc/", timeout=1) as response:
                    assert b"OMNI SOC" in response.read()
                    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
                break
            except urllib.error.URLError:
                if process.poll() is not None:
                    pytest.fail(process.stderr.read().decode())
                time.sleep(0.1)
        else:
            pytest.fail("nginx did not start")
        for path in ("app-boot.js", "app-loader.js", "app-v3.js", "icons/icon-192.png", "sw.js"):
            with urllib.request.urlopen(base + "/soc/" + path) as response:
                assert response.status == 200
                assert response.read()
        with urllib.request.urlopen(base + "/soc/manifest.webmanifest") as response:
            assert json.load(response)["start_url"].startswith("/soc/")
        for path in ("/soc/missing.js", "/m/api/push"):
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(base + path)
            assert error.value.code == 404
    finally:
        process.terminate()
        process.communicate(timeout=5)
