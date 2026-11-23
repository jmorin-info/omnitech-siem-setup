"""Apparence de la console SOC (Administration > Apparence) : validation des couleurs et du
contraste, signatures et dimensions des logos, droits, journalisation, fichier corrompu.

Le backend est lancé en sous-processus avec des dossiers temporaires (même banc que
test_console_admin.py) : aucun chemin d'état de production n'est utilisé.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import stat
import struct
import urllib.error
import urllib.request
import zlib

import pytest

from test_console_admin import Console

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "mobile" / "soc"

pytestmark = pytest.mark.skipif(os.name != "posix", reason="backend Linux (fcntl)")


# --------------------------------------------------------------- images de test (en-têtes réels)
def png(w=64, h=32):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    raw = b"".join(b"\x00" + b"\x00\x00\x00" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def jpeg(w=100, h=50):
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, h, w, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xd9"


def webp_vp8x(w=200, h=100):
    body = b"VP8X" + struct.pack("<I", 10) + b"\x00\x00\x00\x00" + (w - 1).to_bytes(3, "little") + (h - 1).to_bytes(3, "little")
    return b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WEBP" + body


def webp_vp8l(w=48, h=48):
    bits = (w - 1) | ((h - 1) << 14)
    payload = b"\x2f" + struct.pack("<I", bits) + b"\x00" * 8
    body = b"VP8L" + struct.pack("<I", len(payload)) + payload
    return b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WEBP" + body


def webp_vp8(w=40, h=30):
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", w, h)
    body = b"VP8 " + struct.pack("<I", len(frame)) + frame
    return b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WEBP" + body


SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


# --------------------------------------------------------------- validation (module importé)
def test_contrast_ratio_matches_wcag_reference_values(api):
    assert round(api.contrast_ratio("#000000", "#ffffff"), 2) == 21.0
    assert round(api.contrast_ratio("#ffffff", "#ffffff"), 2) == 1.0
    assert round(api.contrast_ratio("#767676", "#ffffff"), 2) == 4.54     # gris AA de référence


@pytest.mark.parametrize("raw", [
    {"dark": {"bg": "red"}}, {"dark": {"bg": "#12345"}}, {"dark": {"bg": "#1234567"}},
    {"dark": {"bg": "#12345g"}}, {"dark": {"bg": "#fff"}}, {"dark": {"bg": "url(x)"}},
    {"dark": {"position": "#000000"}}, {"sepia": {"bg": "#000000"}}, {"dark": ["#000000"]}, "#000000",
])
def test_invalid_colors_are_rejected(api, raw):
    with pytest.raises(api.AdminError):
        api.appearance_colors(raw)


def test_colors_are_normalized_and_original_values_are_not_overrides(api):
    c = api.appearance_colors({"dark": {"bg": "#0A0B0C", "fg": api.APPEARANCE_DEFAULTS["dark"]["fg"]}})
    assert c == {"dark": {"bg": "#0a0b0c"}, "light": {}}


def test_default_values_follow_the_stylesheet(api):
    css = (SOC / "app-professional.css").read_text(encoding="utf-8")
    dark = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    light = re.search(r"html\[data-theme=light\]\s*\{(.*?)\}", css, re.S).group(1)
    for block, mode in ((dark, "dark"), (light, "light")):
        for key, value in api.APPEARANCE_DEFAULTS[mode].items():
            assert re.search(rf"--{re.escape(key)}:{value}\b", block.replace(" ", "").replace("#fff;", "#ffffff;")), (mode, key)


def test_low_contrast_is_refused_only_for_modified_pairs(api):
    assert api.appearance_contrast_issues({"dark": {}, "light": {}}) == []      # origine : jamais bloquante
    issues = api.appearance_contrast_issues({"dark": {"fg": "#151f30"}, "light": {}})
    assert issues and all(i["mode"] == "dark" and "fg" in i["pair"] for i in issues)
    assert api.appearance_contrast_issues({"dark": {"pro-accent": "#1d4ed8"}, "light": {}}) == []
    bad = api.appearance_contrast_issues({"dark": {}, "light": {"pro-accent": "#7aa2f7"}})
    assert bad and bad[0]["ratio"] < 4.5
    with pytest.raises(api.AdminError, match="contraste"):
        api._a_appearance({"colors": {"light": {"mut": "#c0c0c0"}}}, "alice")


@pytest.mark.parametrize("data, expected", [
    (png(64, 32), ("image/png", 64, 32)), (jpeg(100, 50), ("image/jpeg", 100, 50)),
    (webp_vp8x(200, 100), ("image/webp", 200, 100)), (webp_vp8l(48, 48), ("image/webp", 48, 48)),
    (webp_vp8(40, 30), ("image/webp", 40, 30)),
])
def test_image_signatures_and_dimensions(api, data, expected):
    assert api.image_info(data) == expected


@pytest.mark.parametrize("data", [
    SVG, b"GIF89a" + b"\x00" * 40, b"BM" + b"\x00" * 60, b"", b"\x89PNG\r\n\x1a\n",
    b"<html><script>alert(1)</script></html>", b"\xff\xd8\xff\xe0\x00\x02", b"RIFF\x00\x00\x00\x00WEBPXXXX" + b"\x00" * 20,
    b"%PDF-1.7" + b"\x00" * 40,
])
def test_non_image_or_unsupported_formats_are_refused(api, data):
    with pytest.raises(api.AdminError):
        api.appearance_logo(data)


def test_logo_size_and_dimension_limits(api):
    big = png(64, 64) + b"\x00" * (api.APPEARANCE_LOGO_MAX)
    with pytest.raises(api.AdminError, match="volumineux"):
        api.appearance_logo(big)
    for w, h in ((8, 64), (64, 8), (4096, 64), (64, 2000)):
        with pytest.raises(api.AdminError, match="dimensions"):
            api.appearance_logo(png(w, h) if max(w, h) <= 64 else webp_vp8x(w, h))
    meta = api.appearance_logo(png(64, 64))
    assert meta["type"] == "image/png" and len(meta["sha256"]) == 64


@pytest.mark.parametrize("params", [
    {"name": "a" * 41}, {"subtitle": "b" * 61}, {"name": "OMNI\u202eCOS"}, {"name": "x\u200by"},
    {"theme_default": "sepia"}, {"logo": {"data": "pas du base64 !"}}, {"logo": "autre"},
    {"logo": {"data": base64.b64encode(SVG).decode()}},
])
def test_invalid_appearance_params_are_rejected(api, params):
    with pytest.raises(api.AdminError):
        api._a_appearance(params, "alice")


def test_corrupted_or_partial_file_falls_back_to_original(api):
    os.makedirs(api.SOC_APPEARANCE_DIR, exist_ok=True)
    path = Path(api.APPEARANCE_FILE)
    assert str(path).startswith(str(Path(api.SUBS_FILE).parent))           # jamais la production
    path.write_text("{ ceci n'est pas du JSON", encoding="utf-8")
    assert api.appearance_public() == {"name": "", "subtitle": "", "theme_default": "system",
                                       "colors": {"dark": {}, "light": {}}, "logo": None}
    assert api.admin_appearance()["file_ok"] is False
    path.write_text(json.dumps({"name": "Console\nX", "subtitle": 12, "theme_default": "rose",
                                "colors": {"dark": {"bg": "javascript:1"}},
                                "logo": {"type": "image/svg+xml", "sha256": "0" * 64}}), encoding="utf-8")
    pub = api.appearance_public()
    assert pub["theme_default"] == "system" and pub["colors"] == {"dark": {}, "light": {}} and pub["logo"] is None
    # couleurs enregistrées puis devenues illisibles par contraste : origine
    path.write_text(json.dumps({"name": "SOC Bordeaux", "colors": {"dark": {"fg": "#0c1220"}}}), encoding="utf-8")
    pub = api.appearance_public()
    assert pub["name"] == "SOC Bordeaux" and pub["colors"] == {"dark": {}, "light": {}}
    # logo déclaré mais fichier absent : non annoncé
    path.write_text(json.dumps({"logo": {"type": "image/png", "sha256": "a" * 64, "width": 64, "height": 64}}), encoding="utf-8")
    assert api.appearance_public()["logo"] is None and api.appearance_logo_bytes() is None


def test_state_path_is_configurable_and_guarded_in_test_mode(api):
    assert "SOC_APPEARANCE_DIR" in api.state_paths()
    assert not api.SOC_APPEARANCE_DIR.startswith("/var/lib")


# --------------------------------------------------------------- bout en bout (backend lancé)
@pytest.fixture
def console(tmp_path):
    c = Console(tmp_path, extra_conf=f"SOC_APPEARANCE_DIR={tmp_path}/data/apparence")
    yield c
    c.close()


def raw_get(console, path, user=None):
    h = {"X-Real-IP": "10.1.2.3"}
    if user:
        h["Cookie"] = "oms_session=" + console.session(user)
    req = urllib.request.Request(f"http://127.0.0.1:{console.port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def save(console, user, params, motif="charte graphique du site", **kw):
    body = {"params": params, "motif": motif}
    return console.call("POST", "/m/api/admin/appearance", user, body, **kw)


def test_reads_require_authentication(console):
    assert console.call("GET", "/m/api/appearance")[0] == 401
    assert raw_get(console, "/m/api/appearance/logo")[0] == 401


def test_any_authenticated_user_reads_but_only_admins_write(console):
    code, pub = console.call("GET", "/m/api/appearance", "carol")
    assert code == 200 and pub["name"] == "" and pub["logo"] is None
    assert console.call("GET", "/m/api/admin/appearance", "carol")[0] == 403
    code, r = save(console, "carol", {"name": "Pirate"})
    assert code == 403
    assert not (console.tmp / "data" / "apparence" / "appearance.json").exists()
    refus = [e for e in console.audit()["entries"] if e["event"] == "refus" and e["actor"] == "carol"]
    assert refus and refus[0]["action"] == "appearance"


def test_admin_guards_are_reused(console):
    assert save(console, "alice", {"name": "X"}, csrf=False)[0] == 403
    assert save(console, "alice", {"name": "X"}, origin="https://evil.example")[0] == 403
    code, r = save(console, "alice", {"name": "X"}, ip="203.0.113.7")
    assert code == 403 and "internes" in r["error"]
    assert save(console, "alice", {"name": "X"}, motif="")[0] == 400          # motif obligatoire


def test_save_logo_serve_and_reset(console):
    logo = base64.b64encode(png(64, 64)).decode()
    params = {"name": "SOC Bordeaux", "subtitle": "Site principal", "theme_default": "light",
              "colors": {"dark": {"pro-accent": "#1d4ed8"}, "light": {}}, "logo": {"data": logo}}
    code, sim = console.call("POST", "/m/api/admin/appearance", "alice", {"params": params, "simulate": True})
    assert code == 200 and sim["simulation"] and sim["preview"]["after"]["nom"] == "SOC Bordeaux"
    assert not (console.tmp / "data" / "apparence" / "appearance.json").exists()     # simulation sans effet
    code, r = save(console, "alice", params)
    assert code == 200 and r["ok"] and r["status"] == "faite", r
    d = console.tmp / "data" / "apparence"
    assert stat.S_IMODE((d / "appearance.json").stat().st_mode) == 0o640
    assert stat.S_IMODE((d / "logo.png").stat().st_mode) == 0o640
    code, pub = console.call("GET", "/m/api/appearance", "carol")
    assert pub["name"] == "SOC Bordeaux" and pub["theme_default"] == "light"
    assert pub["colors"]["dark"] == {"pro-accent": "#1d4ed8"} and pub["logo"]["url"].startswith("/m/api/appearance/logo?v=")
    code, headers, body = raw_get(console, pub["logo"]["url"], "carol")
    assert code == 200 and body == png(64, 64)
    assert headers["Content-Type"] == "image/png" and headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in headers["Content-Security-Policy"]
    entry = [e for e in console.audit()["entries"] if e["action"] == "appearance_set" and e["event"] == "execution"][0]
    assert entry["actor"] == "alice" and entry["after"]["nom"] == "SOC Bordeaux" and entry["target"] == "apparence"
    assert logo[:40] not in json.dumps(console.audit())                      # jamais le contenu du logo dans l'audit
    # même configuration : refusée comme « aucun changement »
    assert save(console, "alice", dict(params, logo="conserver"))[0] == 409
    # remplacement par un WebP : l'ancien fichier PNG disparaît
    assert save(console, "alice", dict(params, logo={"data": base64.b64encode(webp_vp8x(128, 64)).decode()}))[0] == 200
    assert (d / "logo.webp").exists() and not (d / "logo.png").exists()
    # retour aux valeurs d'origine
    code, r = save(console, "alice", {"reset": True})
    assert code == 200 and r["ok"]
    pub = console.call("GET", "/m/api/appearance", "carol")[1]
    assert pub == {"name": "", "subtitle": "", "theme_default": "system", "colors": {"dark": {}, "light": {}}, "logo": None}
    assert raw_get(console, "/m/api/appearance/logo", "carol")[0] == 404 and not (d / "logo.webp").exists()


def test_tampered_logo_is_never_served(console):
    assert save(console, "alice", {"name": "SOC", "logo": {"data": base64.b64encode(png(32, 32)).decode()}})[0] == 200
    f = console.tmp / "data" / "apparence" / "logo.png"
    f.write_bytes(SVG)
    assert raw_get(console, "/m/api/appearance/logo", "carol")[0] == 404
    assert console.call("GET", "/m/api/appearance", "carol")[1]["logo"] is None


def test_svg_disguised_and_oversized_uploads_are_refused(console):
    code, r = save(console, "alice", {"logo": {"data": base64.b64encode(SVG).decode()}})
    assert code == 400 and "PNG, JPEG ou WebP" in r["error"]
    big = base64.b64encode(png(64, 64) + b"\x00" * (520 * 1024)).decode()
    code, r = save(console, "alice", {"logo": {"data": big}})
    assert code == 400 and "volumineux" in r["error"]
    # la route générique garde sa limite de 16 Ko : un logo ne passe que par la route dédiée
    small = base64.b64encode(png(64, 64) + b"\x00" * 20000).decode()
    code, _ = console.act("alice", "appearance_set", {"logo": {"data": small}})
    assert code == 413
    assert not (console.tmp / "data" / "apparence" / "logo.png").exists()


def test_low_contrast_is_refused_by_server(console):
    code, r = save(console, "alice", {"colors": {"dark": {"fg": "#151f30"}}})
    assert code == 400 and "contraste" in r["error"]
    code, r = save(console, "alice", {"colors": {"dark": {"bg": "#zzzzzz"}}})
    assert code == 400 and "hexadécimale" in r["error"]


def test_global_dry_run_does_not_write(tmp_path):
    c = Console(tmp_path, extra_conf=f"SOC_ADMIN_DRY_RUN=1\nSOC_APPEARANCE_DIR={tmp_path}/data/apparence")
    try:
        code, r = save(c, "alice", {"name": "Essai"})
        assert code == 200 and r.get("simulation") is True
        assert not (tmp_path / "data" / "apparence" / "appearance.json").exists()
    finally:
        c.close()


def test_corrupted_file_on_disk_keeps_console_working(console):
    d = console.tmp / "data" / "apparence"
    d.mkdir(parents=True)
    (d / "appearance.json").write_bytes(b"\x00\xff garbage")
    code, pub = console.call("GET", "/m/api/appearance", "carol")
    assert code == 200 and pub["name"] == "" and pub["colors"] == {"dark": {}, "light": {}}
    code, adm = console.call("GET", "/m/api/admin/appearance", "alice")
    assert code == 200 and adm["file_ok"] is False and adm["defaults"]["name"] == "OMNI SOC"
    assert save(console, "alice", {"name": "Reprise"})[0] == 200                # réécriture propre
    assert json.loads((d / "appearance.json").read_text())["name"] == "Reprise"


# --------------------------------------------------------------- front (statique)
def test_theme_module_is_loaded_early_and_cached():
    html = (SOC / "index.html").read_text(encoding="utf-8")
    sw = (SOC / "sw.js").read_text(encoding="utf-8")
    scripts = re.findall(r'<script src="(/soc/[^"]+)"', html)
    theme = "/soc/app-theme.js?v=2026112301"
    assert scripts.index(theme) == scripts.index("/soc/app-boot.js?v=2026112101") + 1
    assert f'"{theme}"' in sw and 'VERSION = "soc-v9-2026112302"' in sw
    assert "<script>" not in html


def test_theme_module_respects_csp_and_validates_values():
    js = (SOC / "app-theme.js").read_text(encoding="utf-8")
    assert "style.setProperty" in js
    assert not re.search(r"setAttribute\(\s*[\"']style|\.style\.cssText|innerHTML|eval\(|new Function|insertAdjacentHTML", js)
    assert "/^#[0-9a-f]{6}$/" in js                         # aucune valeur non hexadécimale appliquée
    keys = re.search(r"var KEYS = \[(.*?)\];", js).group(1)
    css = (SOC / "app-professional.css").read_text(encoding="utf-8")
    for key in re.findall(r'"([a-z-]+)"', keys):
        assert f"--{key}:" in css, key                       # uniquement des variables existantes
    admin = (SOC / "app-admin.js").read_text(encoding="utf-8")
    assert '["appearance", "Apparence"]' in admin and '"/admin/appearance"' in admin


def test_no_emoji_in_appearance_deliverables():
    emoji = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")
    for f in (SOC / "app-theme.js", Path(__file__)):
        text = f.read_text(encoding="utf-8")
        assert not emoji.search(text), f
