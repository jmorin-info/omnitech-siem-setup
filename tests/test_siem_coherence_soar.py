"""Sentinelle omni-siem-coherence : contrôles SOAR (hors ligne, sans réseau ni GELF)."""
import importlib.machinery
import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploye" / "sbin" / "omni-siem-coherence"


@pytest.fixture
def sentinelle(tmp_path, monkeypatch):
    loader = importlib.machinery.SourceFileLoader("omni_siem_coherence_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    alerts = []
    monkeypatch.setattr(mod, "alert", lambda key, tag, msg, **kw: alerts.append((key, tag, msg)))
    state, feed, log = tmp_path / "blocklist.json", tmp_path / "blocklist.txt", tmp_path / "access.log"
    monkeypatch.setattr(mod, "SOAR_STATE", str(state))
    monkeypatch.setattr(mod, "SOAR_FEED", str(feed))
    monkeypatch.setattr(mod, "NGINX_LOG", str(log))
    now = time.time()
    monkeypatch.setattr(mod, "NOW", now)
    state.write_text(json.dumps({"198.51.100.7": now + 3600}))
    feed.write_text("# en-tete\n198.51.100.7\n")
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(now - 60))
    log.write_text(f'192.0.2.254 - - [{stamp}] "GET /kit/soar/blocklist.txt HTTP/1.1" 304 0\n')
    return mod, alerts, state, feed


def test_no_site_firewall_list_by_default():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'c("SOAR_FG_ATTENDUS", "")' in text
    assert not any(net in text for net in ("10.33.", "10.94.", "10.13."))


def test_healthy_publication_raises_nothing(sentinelle):
    mod, alerts, _, _ = sentinelle
    mod.check_soar()
    assert alerts == []


def test_state_newer_than_published_file_is_reported(sentinelle):
    """28/11/2026 : omni-soar enregistrait son état mais ne pouvait plus réécrire le fichier publié."""
    mod, alerts, state, feed = sentinelle
    old = mod.NOW - 1200
    os.utime(feed, (old, old))
    mod.check_soar()
    assert [a[1] for a in alerts] == ["soar_publication_en_echec"]


def test_site_firewall_that_stops_reading_is_reported(sentinelle, monkeypatch):
    mod, alerts, _, _ = sentinelle
    monkeypatch.setattr(mod, "SOAR_FG_ATTENDUS", {"FW-A": "192.0.2.254", "FW-B": "192.0.2.253"})
    monkeypatch.setattr(mod, "NOW", mod.NOW + 1000)
    mod.check_soar()
    keys = {a[0] for a in alerts}
    assert "soar_fetch_FW-A" in keys and "soar_fetch_FW-B" in keys
