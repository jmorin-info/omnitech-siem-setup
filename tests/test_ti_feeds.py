"""omni-ti-feeds (deploye/sbin, recopié par 66-threatintel.sh) : flux URLhaus, hors ligne."""
from __future__ import annotations

import io
import json
from pathlib import Path
import runpy
import urllib.error
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploye" / "sbin" / "omni-ti-feeds"

FEODO = "# comment\nfirst_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n2026-11-01,192.0.2.10,443,online,2026-11-21,Emotet\n"
URLHAUS = {"query_status": "ok", "urls": [
    {"url": "http://malware.example.net/a.exe", "host": "malware.example.net"},
    {"url": "https://drive.google.com/uc?id=x", "host": "drive.google.com"},
    {"url": "http://198.51.100.7/x", "host": "198.51.100.7"}]}


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    requests = []

    def urlopen(request, timeout=0):
        url = request.full_url
        requests.append((url, dict(request.header_items())))
        if "feodotracker" in url:
            return Response(FEODO.encode())
        if url.startswith("https://urlhaus-api.abuse.ch/v1/urls/recent/"):
            if request.get_header("Auth-key") != "cle-de-test":
                raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)
            return Response(json.dumps(URLHAUS).encode())
        if "urlhaus.abuse.ch/downloads" in url:
            raise urllib.error.HTTPError(url, 410, "Gone", {}, None)
        if "threatfox" in url:
            return Response(b'{"query_status": "no_result", "data": []}')
        raise AssertionError("URL inattendue " + url)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setenv("OMNI_TI_LOOKUP_DIR", str(tmp_path))
    for name in ("ABUSECH_AUTH_KEY", "THREATFOX_AUTH_KEY"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "ti-mal-domain.csv").write_text("domain,source\nancien.example.org,urlhaus\n")

    def run():
        module = runpy.run_path(str(SCRIPT), run_name="omni_ti_feeds")
        module["main"]()
        return requests

    return tmp_path, run


def test_urlhaus_uses_authenticated_api_and_skips_shared_infrastructure(feeds, monkeypatch, capsys):
    lookup, run = feeds
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "cle-de-test")
    requests = run()
    assert not any("urlhaus.abuse.ch/downloads" in url for url, _ in requests)
    assert (lookup / "ti-mal-domain.csv").read_text().splitlines() == ["domain,source", "malware.example.net,urlhaus"]
    assert "192.0.2.10" in (lookup / "ti-c2-ip.csv").read_text()
    assert "cle-de-test" not in capsys.readouterr().out


def test_threatfox_key_is_accepted_for_urlhaus(feeds, monkeypatch):
    lookup, run = feeds
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "cle-de-test")
    run()
    assert "malware.example.net" in (lookup / "ti-mal-domain.csv").read_text()


def test_missing_key_keeps_previous_domains_and_says_why(feeds, capsys):
    lookup, run = feeds
    requests = run()
    assert not any("urlhaus" in url for url, _ in requests)
    assert "ancien.example.org" in (lookup / "ti-mal-domain.csv").read_text()
    assert "urlhaus: pas de cle abuse.ch" in capsys.readouterr().out


def test_rejected_key_keeps_previous_domains(feeds, monkeypatch, capsys):
    lookup, run = feeds
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "mauvaise-cle")
    run()
    assert "ancien.example.org" in (lookup / "ti-mal-domain.csv").read_text()
    assert "urlhaus KO: HTTP Error 401" in capsys.readouterr().out


def test_provisioning_script_embeds_the_deployed_collector():
    text = (ROOT / "66-threatintel.sh").read_text()
    embedded = text.split("cat > /usr/local/sbin/omni-ti-feeds <<'PYEOF'\n", 1)[1].split("\nPYEOF\n", 1)[0] + "\n"
    assert embedded == SCRIPT.read_text()
    assert "ABUSECH_AUTH_KEY=" in text
