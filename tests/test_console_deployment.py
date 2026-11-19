"""Regression tests for fresh installs, missing assets and nginx rollback."""
import importlib.util
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("console_deploy", ROOT / "tools/deploy-console.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

SITE = "server {\n    listen 443 ssl;\n    location / { proxy_pass http://127.0.0.1:9000; }\n}\n"


def routes(text=SITE):
    return deploy.add_routes(text, Path("/var/www/siem-soc"), Path("/var/www/siem-mobile"))


def test_fresh_routes_are_complete_and_idempotent():
    result = routes()
    assert "location /soc/" in result
    assert "location /m/api/" in result
    assert "location = /m/api/push { return 404; }" in result
    assert "proxy_set_header X-Real-IP $remote_addr" in result
    assert routes(result) == result


def test_existing_acl_is_preserved():
    existing = SITE.replace("    location / {", "    location /soc/ { allow 10.0.0.0/8; deny all; alias /var/www/siem-soc/; }\n    location / {")
    result = routes(existing)
    assert result.count("location /soc/") == 1
    assert "allow 10.0.0.0/8; deny all;" in result


def test_ambiguous_site_is_rejected():
    with pytest.raises(ValueError, match="one 'location"):
        routes(SITE + SITE)


def test_complete_assets_are_published_without_backend_or_secrets(tmp_path):
    deploy.check_assets(ROOT / "mobile/soc")
    deploy.publish(ROOT / "mobile/soc", tmp_path)
    for name in ("app-boot.js", "app-loader.js", "app-v3.js", "manifest.webmanifest", "icons/icon-192.png", "sw.js"):
        assert (tmp_path / name).is_file()
    assert not list(tmp_path.rglob("*.py"))
    assert not list(tmp_path.rglob("*.env"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX nginx worker permissions")
def test_public_assets_remain_readable_with_private_installer_umask(tmp_path):
    old_umask = os.umask(0o027)
    try:
        deploy.publish(ROOT / "mobile/soc", tmp_path / "public")
    finally:
        os.umask(old_umask)
    assert ((tmp_path / "public/icons").stat().st_mode & 0o777) == 0o755
    assert ((tmp_path / "public/icons/icon-192.png").stat().st_mode & 0o777) == 0o644


@pytest.mark.parametrize("fail_at", [1, 2])
def test_nginx_failure_restores_original(tmp_path, fail_at):
    directory = tmp_path / "sites-available"
    directory.mkdir()
    site = directory / "graylog"
    site.write_text(SITE)
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if len(calls) == fail_at:
            raise subprocess.CalledProcessError(1, command)

    with patch.object(deploy.subprocess, "run", side_effect=execute):
        with pytest.raises(subprocess.CalledProcessError):
            deploy.apply_site(site, routes())
    assert site.read_text() == SITE
    assert len(list((tmp_path / "omni-console-backups").iterdir())) == 1
