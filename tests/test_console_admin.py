"""Espace Administration de la console SOC : autorisations, CSRF, validation,
approbation à deux temps, simulation, audit chaîné et exécuteur privilégié.

Le backend est lancé en sous-processus sur un port libre, avec une configuration
de test et des dossiers temporaires. Le triage, le SOAR et l'API Graylog sont des
serveurs factices locaux : aucun appel n'atteint les services de production.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "mobile" / "omni-mobile-api.py"
EXEC = ROOT / "mobile" / "omni-soc-admin-exec"
SECRET = "test-session-secret"
ORIGIN = "https://soc.test"
GL_ID_1 = "a" * 24
GL_ID_2 = "b" * 24
SENSITIVE = "valeur-secrete-ne-doit-pas-fuiter"

pytestmark = pytest.mark.skipif(os.name != "posix", reason="backend Linux (fcntl, systemd)")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Mock:
    """Serveur HTTP factice qui enregistre chaque appel."""

    def __init__(self, handler):
        self.calls = []
        self.state = {}
        mock = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(n) if n else b""
                body = json.loads(raw) if raw else None
                mock.calls.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
                code, out = handler(mock, self.command, self.path, body)
                data = b"" if out is None else json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _do

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def triage_handler(mock, method, path, body):
    rules = mock.state.setdefault("rules", [])
    if method == "GET" and path.startswith("/fp"):
        return 200, rules
    if method == "POST" and path.startswith("/fp"):
        rules.append({"entity": body["entity"], "tag": body.get("tag", ""), "title_sub": body.get("title_sub", ""),
                      "until": time.time() + body["ttl_days"] * 86400, "by": body.get("by", "")})
        return 200, {"ok": True, "actifs": len(rules)}
    if method == "DELETE" and path.startswith("/fp"):
        ent = urllib.parse.unquote(path.split("entity=", 1)[1])
        mock.state["rules"] = [r for r in rules if r["entity"] != ent]
        return 200, {"ok": True}
    return 404, {"error": "nf"}


def soar_handler(mock, method, path, body):
    if method == "POST" and path == "/block":
        return 200, {"ok": True, "blocked": body["ip"], "ttl_h": 24}
    return 404, {"error": "nf"}


def graylog_handler(mock, method, path, body):
    defs = mock.state.setdefault("defs", {GL_ID_1: "ENABLED", GL_ID_2: "DISABLED"})
    if method == "GET" and path.startswith("/api/events/definitions?"):
        return 200, {"total": 2, "event_definitions": [
            {"id": i, "title": f"OMNI - détection {i[:1]}", "priority": 2, "state": s} for i, s in defs.items()]}
    if method == "GET" and path.startswith("/api/events/definitions/"):
        i = path.rsplit("/", 1)[1]
        return (200, {"id": i, "title": f"OMNI - détection {i[:1]}", "state": defs[i]}) if i in defs else (404, {})
    if method == "PUT" and path.endswith("/schedule"):
        defs[path.split("/")[-2]] = "ENABLED"
        return 204, None
    if method == "PUT" and path.endswith("/unschedule"):
        defs[path.split("/")[-2]] = "DISABLED"
        return 204, None
    return 404, {}


FAKE_SYSTEMCTL = r'''#!/usr/bin/env python3
import sys, os
a = sys.argv[1:]
log = os.environ.get("FAKE_SYSTEMCTL_LOG") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "systemctl.log")
open(log, "a").write(" ".join(a) + "\n")
if a and a[0] == "list-units":
    print("omni-alert-triage.service loaded active running OMNI triage")
    print("omni-soar.service loaded failed failed OMNI SOAR")
    print("omni-m365-fetch.timer loaded active waiting OMNI M365")
elif a and a[0] == "show" and "--value" in a:
    print("active")
elif a and a[0] == "show":
    print("Id=omni-alert-triage.service\nDescription=OMNI triage\nActiveState=active\nSubState=running\nUnitFileState=enabled\nResult=success\n")
    print("Id=omni-soar.service\nDescription=OMNI SOAR\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\nResult=exit-code\n")
    print("Id=omni-m365-fetch.timer\nDescription=OMNI M365\nActiveState=active\nSubState=waiting\nUnitFileState=enabled\nResult=success\nLastTriggerUSec=Sat 2026-11-21 15:01:10 CET\n")
'''


class Console:
    def __init__(self, tmp: Path, extra_conf: str = ""):
        self.tmp = tmp
        self.data = tmp / "data"
        self.data.mkdir()
        self.etc = tmp / "etc"
        self.etc.mkdir()
        self.triage = Mock(triage_handler)
        self.soar = Mock(soar_handler)
        self.graylog = Mock(graylog_handler)
        self.triage_env = self.etc / "omni-alert-triage.env"
        self.triage_env.write_text(
            "SMTP_HOST=smtp.test\nMAIL_RECIPIENTS=soc@exemple.test\nMAIL_SCORE_THRESHOLD=80\n"
            f"GRAY_SCORE_THRESHOLD=70\nTRIAGE_TOKEN=tok-triage\nANTHROPIC_API_KEY={SENSITIVE}\n")
        self.soar_env = self.etc / "soar.env"
        self.soar_env.write_text("SOAR_MODE=actif\nSOAR_MIN_HITS_PAYS_NORMAL=10\n")
        self.soar_fix = self.etc / "exclusions-statiques.txt"
        self.soar_fix.write_text("# liste fixe\n93.184.216.34     # site partenaire\n")
        self.soar_state = self.data / "blocklist.json"
        self.soar_state.write_text(json.dumps({"9.9.9.9": time.time() + 3600}))
        (self.etc / "graylog.token").write_text("tok-graylog\n")
        self.systemctl = tmp / "systemctl"
        self.systemctl.write_text(FAKE_SYSTEMCTL)
        self.systemctl.chmod(0o755)
        self.port = free_port()
        conf = tmp / "mobile.conf"
        conf.write_text("\n".join([
            "MOBILE_BIND=127.0.0.1", f"MOBILE_PORT={self.port}",
            f"MOBILE_SECRET={SECRET}", "MOBILE_PUSH_SECRET=test-push-secret",
            f"GRAYLOG_API=http://127.0.0.1:{self.graylog.port}/api", "OPENSEARCH=http://127.0.0.1:9",
            f"MOBILE_SUBS_FILE={self.data}/subscriptions.json", f"MOBILE_CASES_FILE={self.data}/cases.json",
            f"MOBILE_WATCH_FILE={self.data}/watchlist.json",
            "SOC_ADMINS=alice,bob", "SOC_ORIGINS=soc.test", "SOC_ADMIN_GELF_URL=",
            f"SOC_REQ_DIR={self.data}/soc-requests",
            f"SOC_TRIAGE_URL=http://127.0.0.1:{self.triage.port}", f"SOC_TRIAGE_ENV={self.triage_env}",
            f"SOC_SOAR_URL=http://127.0.0.1:{self.soar.port}", f"SOC_SOAR_ENV={self.soar_env}",
            f"SOC_SOAR_STATE={self.soar_state}", f"SOC_SOAR_META={self.data}/blocklist-meta.json",
            f"SOC_SOAR_EXCL={self.data}/exclusions.json", f"SOC_SOAR_FIX={self.soar_fix}",
            f"SOC_SOAR_DEC={self.data}/decisions.log",
            f"SOC_GRAYLOG_TOKEN_FILE={self.etc}/graylog.token", f"SOC_SYSTEMCTL={self.systemctl}",
            "SOC_ADMIN_RESTARTABLE=omni-alert-triage.service", extra_conf]) + "\n")
        self.exec_conf = tmp / "exec.conf"
        self.exec_conf.write_text("\n".join([
            f"SOC_ADMIN_DIR={self.data}/admin", f"SOC_TRIAGE_ENV={self.triage_env}",
            f"SOC_SOAR_ENV={self.soar_env}", f"SOC_SOAR_FIX={self.soar_fix}",
            f"SOC_SYSTEMCTL={self.systemctl}", "SOC_EXEC_RESTARTABLE=omni-alert-triage.service"]) + "\n")
        env = dict(os.environ, MOBILE_CONFIG=str(conf), FAKE_SYSTEMCTL_LOG=str(tmp / "systemctl.log"), OMNI_TEST_MODE="1")
        self.proc = subprocess.Popen([sys.executable, str(API)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/m/api/vapid", timeout=1).read()
                break
            except Exception:
                if self.proc.poll() is not None:
                    raise RuntimeError(self.proc.stderr.read().decode())
                time.sleep(0.1)
        else:
            raise RuntimeError("backend non démarré")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for m in (self.triage, self.soar, self.graylog):
            m.close()

    @staticmethod
    def session(user):
        exp = int(time.time()) + 3600
        payload = f"{user}|{exp}"
        sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()

    def call(self, method, path, user=None, body=None, ip="10.1.2.3", origin=ORIGIN, csrf=True,
             ctype="application/json", headers=None):
        h = {"X-Real-IP": ip}
        tok = ""
        if user:
            tok = self.session(user)
            h["Cookie"] = f"oms_session={tok}"
        if origin:
            h["Origin"] = origin
        if csrf and user:
            h["X-SOC-CSRF"] = hmac.new(SECRET.encode(), b"csrf|" + tok.encode(), hashlib.sha256).hexdigest()[:40]
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = ctype
        h.update(headers or {})
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def act(self, user, action, params, motif="motif de test", simulate=False, **kw):
        body = {"action": action, "params": params, "motif": motif}
        if simulate:
            body["simulate"] = True
        return self.call("POST", "/m/api/admin/action", user, body, **kw)

    def decide(self, user, rid, decision="approuver", motif="validé", **kw):
        return self.call("POST", "/m/api/admin/decide", user, {"id": rid, "decision": decision, "motif": motif}, **kw)

    def audit(self):
        return self.call("GET", "/m/api/admin/audit?limit=500", "alice")[1]

    def run_executor(self):
        env = dict(os.environ, OMNI_SOC_EXEC_CONFIG=str(self.exec_conf), FAKE_SYSTEMCTL_LOG=str(self.tmp / "systemctl.log"),
                   OMNI_TEST_MODE="1")
        return subprocess.run([sys.executable, str(EXEC)], env=env, capture_output=True, text=True, timeout=30)


@pytest.fixture
def console(tmp_path):
    c = Console(tmp_path)
    yield c
    c.close()


# --------------------------------------------------------------- autorisation
def test_unauthenticated_requests_are_rejected(console):
    assert console.call("GET", "/m/api/admin/users")[0] == 401
    assert console.call("POST", "/m/api/admin/action", body={"action": "fp_add"})[0] == 401


def test_non_admin_cannot_read_or_write_and_refusal_is_audited(console):
    code, me = console.call("GET", "/m/api/admin/me", "carol")
    assert code == 200 and me["role"] == "analyste" and me["is_admin"] is False and "csrf" not in me
    for path in ("/m/api/admin/users", "/m/api/admin/audit", "/m/api/admin/settings", "/m/api/admin/services"):
        assert console.call("GET", path, "carol")[0] == 403
    code, r = console.act("carol", "soar_block", {"ip": "8.8.8.8"})
    assert code == 403
    assert not console.soar.calls
    refus = [e for e in console.audit()["entries"] if e["event"] == "refus"]
    assert refus and refus[0]["actor"] == "carol"


def test_me_exposes_role(console):
    assert console.call("GET", "/m/api/me", "alice")[1] == {"user": "alice", "role": "administrateur"}


# --------------------------------------------------------------- CSRF / transport
@pytest.mark.parametrize("kwargs, code", [
    ({"csrf": False}, 403),
    ({"origin": "https://evil.example"}, 403),
    ({"origin": None}, 403),
    ({"ctype": "text/plain"}, 415),
    ({"headers": {"X-SOC-CSRF": "0" * 40}}, 403),
])
def test_csrf_and_content_type_guards(console, kwargs, code):
    status, r = console.act("alice", "fp_add", {"entity": "src_ip=203.0.113.9", "ttl_days": 7,
                                                "justification": "scanner autorisé du prestataire"}, **kwargs)
    assert status == code, r
    assert not [c for c in console.triage.calls if c["method"] == "POST"]


def test_admin_writes_restricted_to_internal_networks(console):
    status, r = console.act("alice", "soar_unblock", {"ip": "9.9.9.9"}, ip="203.0.113.77")
    assert status == 403 and "internes" in r["error"]
    me = console.call("GET", "/m/api/admin/me", "alice", ip="203.0.113.77")[1]
    assert me["client_internal"] is False and me["writes_allowed"] is False
    status, r = console.act("alice", "soar_unblock", {"ip": "9.9.9.9"}, ip="192.168.10.4")
    assert status == 200 and r["status"] == "transmise"
    queued = list((console.data / "soc-requests" / "pending").glob("*.json"))
    assert len(queued) == 1 and json.loads(queued[0].read_text())["action"] == "debloquer"


def test_oversized_body_is_rejected(console):
    status, _ = console.call("POST", "/m/api/admin/action", "alice", {"action": "fp_add", "motif": "x" * 20000})
    assert status == 413


# --------------------------------------------------------------- validation
@pytest.mark.parametrize("action, params, motif", [
    ("fp_add", {"entity": "src_ip=203.0.113.9", "ttl_days": 7, "justification": "court"}, "motif"),
    ("fp_add", {"entity": "src_ip=203.0.113.9", "ttl_days": 0, "justification": "justification suffisante"}, "motif"),
    ("fp_add", {"entity": "src_ip=203.0.113.9", "justification": "justification suffisante"}, "motif"),
    ("fp_add", {"entity": "a", "ttl_days": 7, "justification": "justification suffisante"}, "motif"),
    ("fp_add", {"entity": "pwd=abc", "ttl_days": 7, "justification": "justification suffisante"}, "motif"),
    ("soar_block", {"ip": "10.0.0.1"}, "motif"),
    ("soar_block", {"ip": "8.8.8.8; rm -rf /"}, "motif"),
    ("soar_exclusion_add", {"value": "8.0.0.0/8"}, "motif"),
    ("triage_param", {"key": "MAIL_SCORE_THRESHOLD", "value": "5"}, "motif"),
    ("triage_param", {"key": "ANTHROPIC_API_KEY", "value": "x"}, "motif"),
    ("triage_param", {"key": "MAIL_RECIPIENTS", "value": "pas-une-adresse"}, "motif"),
    ("soar_param", {"key": "SOAR_MODE", "value": "agressif"}, "motif"),
    ("detection_toggle", {"id": "../../system", "enabled": False}, "motif"),
    ("service_restart", {"unit": "sshd.service"}, "motif"),
    ("service_restart", {"unit": "omni-soar.service"}, "motif"),
    ("role_set", {"user": "alice", "role": "lecteur"}, "motif"),
    ("role_set", {"user": "carol", "role": "root"}, "motif"),
    ("role_set", {"user": "carol", "role": "lecteur"}, ""),
    ("inconnue", {}, "motif"),
])
def test_invalid_inputs_are_rejected_without_side_effect(console, action, params, motif):
    status, r = console.act("alice", action, params, motif=motif)
    assert status in (400, 403), r
    assert r["ok"] is False
    assert not console.soar.calls
    assert not [c for c in console.triage.calls if c["method"] != "GET"]
    assert not [c for c in console.graylog.calls if c["method"] != "GET"]


def test_admin_cannot_change_own_role(console):
    status, r = console.act("dave_inconnu", "role_set", {"user": "carol", "role": "lecteur"})
    assert status == 403
    console.act("alice", "role_set", {"user": "eve", "role": "administrateur"})
    assert console.act("alice", "role_set", {"user": "alice", "role": "lecteur"})[0] == 400


# --------------------------------------------------------------- simulation
def test_soar_simulation_has_no_side_effect_and_is_audited(console):
    status, r = console.act("alice", "soar_block", {"ip": "8.8.8.8"}, simulate=True, motif="")
    assert status == 200 and r["simulation"] is True
    assert r["preview"]["impact"] == "fort" and r["preview"]["refus"] == ""
    assert not console.soar.calls
    assert not list((console.data / "admin").glob("requests/*.json"))
    assert console.audit()["entries"][0]["event"] == "simulation"


def test_excluded_ip_is_refused_in_preview(console):
    status, r = console.act("alice", "soar_block", {"ip": "93.184.216.34"}, simulate=True)
    assert "exclue" in r["preview"]["refus"]
    status, r = console.act("alice", "soar_block", {"ip": "93.184.216.34"})
    assert status == 409 and not console.soar.calls


def test_global_dry_run_never_executes(tmp_path):
    c = Console(tmp_path, "SOC_ADMIN_DRY_RUN=1")
    try:
        status, r = c.act("alice", "fp_add", {"entity": "src_ip=203.0.113.9", "ttl_days": 7,
                                              "justification": "scanner autorisé du prestataire"})
        assert status == 200 and r["simulation"] is True
        assert not [x for x in c.triage.calls if x["method"] == "POST"]
        assert c.call("GET", "/m/api/admin/me", "alice")[1]["dry_run"] is True
    finally:
        c.close()


# --------------------------------------------------------------- approbation à deux temps
def test_high_impact_action_requires_second_admin(console):
    status, r = console.act("alice", "soar_block", {"ip": "8.8.8.8"}, motif="scan agressif confirmé")
    assert status == 200 and r["pending"] is True
    rid = r["id"]
    assert not console.soar.calls
    status, r = console.decide("alice", rid)
    assert status == 403 and "second administrateur" in r["error"]
    assert not console.soar.calls
    assert console.decide("carol", rid)[0] == 403          # non administrateur
    status, r = console.decide("bob", rid)
    assert status == 200 and r["ok"] is True and r["status"] == "faite", r
    assert console.soar.calls[-1]["body"] == {"ip": "8.8.8.8", "manual": True, "by": "soc:bob"}
    assert r["rollback"] == {"action": "soar_unblock", "params": {"ip": "8.8.8.8"}}
    assert console.decide("bob", rid)[0] == 409             # rejeu impossible
    reqs = console.call("GET", "/m/api/admin/requests", "bob")[1]["requests"]
    assert reqs[0]["status"] == "faite" and reqs[0]["decided_by"] == "bob"
    audit = console.audit()
    assert audit["chain_ok"] is True
    events = [e["event"] for e in audit["entries"] if e["request_id"] == rid]
    assert events[::-1] == ["demande", "refus", "approbation", "execution"]


def test_rejection_requires_motif_and_blocks_execution(console):
    rid = console.act("alice", "soar_block", {"ip": "8.8.4.4"})[1]["id"]
    assert console.decide("bob", rid, "rejeter", motif="")[0] == 400
    status, r = console.decide("bob", rid, "rejeter", motif="pas de preuve suffisante")
    assert status == 200 and r["status"] == "rejetee"
    assert not console.soar.calls


def test_expired_request_cannot_be_approved(console):
    rid = console.act("alice", "soar_block", {"ip": "8.8.4.4"})[1]["id"]
    path = console.data / "admin" / "requests" / f"{rid}.json"
    req = json.loads(path.read_text())
    req["expires_ts"] = int(time.time()) - 1
    path.write_text(json.dumps(req))
    assert console.decide("bob", rid)[0] == 409
    assert not console.soar.calls


# --------------------------------------------------------------- faux positifs
def test_false_positive_add_list_remove(console):
    status, r = console.act("alice", "fp_add", {"entity": "src_ip=203.0.113.9", "tag": "waf_scan", "ttl_days": 14,
                                               "justification": "scanner de vulnérabilités du prestataire"})
    assert status == 200 and r["status"] == "faite", r
    post = [c for c in console.triage.calls if c["method"] == "POST"][0]
    assert post["headers"]["X-Triage-Token"] == "tok-triage"
    assert post["body"]["ttl_days"] == 14 and post["body"]["by"] == "soc-admin:alice"
    rules = console.call("GET", "/m/api/admin/fp", "alice")[1]["rules"]
    assert rules[0]["justification"] == "scanner de vulnérabilités du prestataire"
    status, r = console.act("alice", "fp_remove", {"entity": "src_ip=203.0.113.9"})
    assert status == 200 and r["status"] == "faite"
    assert console.call("GET", "/m/api/admin/fp", "alice")[1]["rules"] == []


# --------------------------------------------------------------- rôles
def test_roles_reader_loses_analyst_writes_and_admin_grant_needs_approval(console):
    status, r = console.act("alice", "role_set", {"user": "carol", "role": "lecteur"})
    assert status == 200 and r["status"] == "faite"
    assert console.call("POST", "/m/api/case", "carol", {"id": "x", "action": "note", "value": "n"})[0] == 403
    status, r = console.act("alice", "role_set", {"user": "dave", "role": "administrateur"})
    assert r["pending"] is True
    assert console.call("GET", "/m/api/admin/me", "dave")[1]["is_admin"] is False
    assert console.decide("bob", r["id"])[1]["status"] == "faite"
    assert console.call("GET", "/m/api/admin/me", "dave")[1]["is_admin"] is True
    users = console.call("GET", "/m/api/admin/users", "dave")[1]
    assert {u["user"]: u["source"] for u in users["users"]}["alice"] == "configuration"
    assert users["admins"] == 3


# --------------------------------------------------------------- détections (Graylog factice)
def test_detection_toggle_uses_token_and_disable_needs_approval(console):
    d = console.call("GET", "/m/api/admin/detections", "alice")[1]
    assert d["available"] is True and d["enabled"] == 1 and d["disabled"] == 1
    status, r = console.act("alice", "detection_toggle", {"id": GL_ID_2, "enabled": True})
    assert status == 200 and r["status"] == "faite"
    put = [c for c in console.graylog.calls if c["method"] == "PUT"][-1]
    assert put["path"] == f"/api/events/definitions/{GL_ID_2}/schedule"
    assert put["headers"]["Authorization"] == "Basic " + base64.b64encode(b"tok-graylog:token").decode()
    assert put["headers"]["X-Requested-By"]
    r = console.act("alice", "detection_toggle", {"id": GL_ID_1, "enabled": False}, motif="bruit pendant migration")[1]
    assert r["pending"] is True
    assert console.decide("bob", r["id"])[1]["status"] == "faite"
    assert console.graylog.calls[-1]["path"] == f"/api/events/definitions/{GL_ID_1}/unschedule"


# --------------------------------------------------------------- paramètres + exécuteur
def test_settings_never_expose_secrets(console):
    for path in ("/m/api/admin/settings", "/m/api/admin/soar"):
        status, r = console.call("GET", path, "alice")
        assert status == 200
        raw = json.dumps(r)
        assert SENSITIVE not in raw and "tok-triage" not in raw
    s = console.call("GET", "/m/api/admin/settings", "alice")[1]
    assert s["triage"]["MAIL_SCORE_THRESHOLD"] == "80"


def test_threshold_order_is_enforced(console):
    status, r = console.act("alice", "triage_param", {"key": "GRAY_SCORE_THRESHOLD", "value": "85"})
    assert status == 409 and "inférieur" in r["error"]


def test_param_change_goes_through_executor_with_backup_and_audit(console):
    r = console.act("alice", "triage_param", {"key": "MAIL_SCORE_THRESHOLD", "value": "85"}, motif="moins de mails")[1]
    rid = r["id"]
    assert r["pending"] is True
    r = console.decide("bob", rid)[1]
    assert r["status"] == "transmise" and r["rollback"]["params"] == {"key": "MAIL_SCORE_THRESHOLD", "value": "80"}
    assert "MAIL_SCORE_THRESHOLD=80" in console.triage_env.read_text()     # rien avant l'exécuteur
    out = console.run_executor()
    assert out.returncode == 0, out.stderr
    text = console.triage_env.read_text()
    assert "MAIL_SCORE_THRESHOLD=85\n" in text and f"ANTHROPIC_API_KEY={SENSITIVE}\n" in text
    backups = list(console.etc.glob("omni-alert-triage.env.bak-soc-*"))
    assert len(backups) == 1 and "MAIL_SCORE_THRESHOLD=80" in backups[0].read_text()
    req = [x for x in console.call("GET", "/m/api/admin/requests", "bob")[1]["requests"] if x["id"] == rid][0]
    assert req["execution"]["status"] == "faite" and req["execution"]["before"] == "80"
    audit = console.audit()
    assert audit["chain_ok"] is True
    assert audit["entries"][0]["event"] == "execution_privilegiee" and audit["entries"][0]["request_id"] == rid


def test_soar_exclusion_add_and_remove_via_executor(console):
    rid = console.act("alice", "soar_exclusion_add", {"value": "192.0.2.0/24"}, motif="test")[1]
    # 192.0.2.0/24 (TEST-NET-1) n'est pas globale : refusée dès la validation
    assert rid.get("ok") is False
    r = console.act("alice", "soar_exclusion_add", {"value": "8.8.8.8"}, motif="résolveur public")[1]
    console.decide("bob", r["id"])
    assert console.run_executor().returncode == 0
    assert "8.8.8.8  # résolveur public" in console.soar_fix.read_text()
    r = console.act("alice", "soar_exclusion_remove", {"value": "8.8.8.8"}, motif="retour arrière")[1]
    console.decide("bob", r["id"])
    console.run_executor()
    assert "8.8.8.8" not in console.soar_fix.read_text()
    assert "93.184.216.34" in console.soar_fix.read_text()


def test_executor_refuses_unapproved_tampered_or_replayed_jobs(console):
    pend = console.data / "admin" / "exec" / "pending"
    done_dir = console.data / "admin" / "exec" / "done"
    req_dir = console.data / "admin" / "requests"
    pend.mkdir(parents=True)
    req_dir.mkdir(parents=True, exist_ok=True)
    params = {"key": "MAIL_SCORE_THRESHOLD", "value": "99", "file": "triage"}

    def run(rid, request=None):
        if request is not None:
            (req_dir / f"{rid}.json").write_text(json.dumps(dict({"id": rid, "action": "triage_param"}, **request)))
        (pend / f"{rid}.json").write_text(json.dumps({"id": rid, "kind": "triage_param", "params": params,
                                                      "actor": "mallory"}))
        console.run_executor()
        return json.loads((done_dir / f"{rid}.json").read_text())

    assert "introuvable" in run("20261121-120000-0000000a")["resultat"]
    d = run("20261121-120000-0000000b", {"status": "en_attente", "requested_by": "alice", "params": params})
    assert d["status"] == "refusee" and "non approuvée" in d["resultat"]
    d = run("20261121-120000-0000000c", {"status": "approuvee", "requested_by": "alice", "decided_by": "alice",
                                         "params": params})
    assert d["status"] == "refusee" and "identique" in d["resultat"]
    d = run("20261121-120000-0000000d", {"status": "approuvee", "requested_by": "alice", "decided_by": "bob",
                                         "params": dict(params, value="90")})
    assert d["status"] == "refusee" and "différents" in d["resultat"]
    assert "MAIL_SCORE_THRESHOLD=80" in console.triage_env.read_text()
    # exécution légitime puis rejeu du même identifiant : refusé, résultat d'origine conservé
    rid = "20261121-120000-0000000e"
    d = run(rid, {"status": "approuvee", "requested_by": "alice", "decided_by": "bob", "params": params})
    assert d["status"] == "faite" and "MAIL_SCORE_THRESHOLD=99" in console.triage_env.read_text()
    assert run(rid)["status"] == "faite"
    replay = json.loads(next(done_dir.glob(f"{rid}.rejeu-*.json")).read_text())
    assert replay["status"] == "refusee" and "rejeu" in replay["resultat"]


def test_service_restart_whitelists(console):
    services = console.call("GET", "/m/api/admin/services", "alice")[1]
    units = {u["unit"]: u for u in services["units"]}
    assert units["omni-soar.service"]["level"] == "crit" and services["failed"] == 1
    assert units["omni-alert-triage.service"]["restartable"] is True
    assert units["omni-soar.service"]["restartable"] is False
    r = console.act("alice", "service_restart", {"unit": "omni-alert-triage.service"}, motif="file bloquée")[1]
    console.decide("bob", r["id"])
    out = console.run_executor()
    assert out.returncode == 0
    assert "restart -- omni-alert-triage.service" in (console.tmp / "systemctl.log").read_text()


# --------------------------------------------------------------- audit
def test_audit_chain_detects_tampering(console):
    console.act("alice", "fp_add", {"entity": "src_ip=203.0.113.9", "ttl_days": 7,
                                    "justification": "scanner autorisé du prestataire"})
    console.act("alice", "soar_block", {"ip": "8.8.8.8"}, simulate=True)
    assert console.audit()["chain_ok"] is True
    path = console.data / "admin" / "audit.jsonl"
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["actor"] = "quelqu-un-d-autre"
    lines[0] = json.dumps(first, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n")
    a = console.audit()
    assert a["chain_ok"] is False and a["broken_at_line"] == 1


# --------------------------------------------------------------- cohérence backend / exécuteur
def test_backend_and_executor_whitelists_match(api, tmp_path, monkeypatch):
    fake = tmp_path / "systemctl"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("OMNI_SOC_EXEC_CONFIG", str(tmp_path / "absent.conf"))
    for k, v in (("SOC_ADMIN_DIR", tmp_path / "a"), ("SOC_TRIAGE_ENV", tmp_path / "t.env"),
                 ("SOC_SOAR_ENV", tmp_path / "s.env"), ("SOC_SOAR_FIX", tmp_path / "f.txt"), ("SOC_SYSTEMCTL", fake)):
        monkeypatch.setenv(k, str(v))
    loader = importlib.machinery.SourceFileLoader("omni_soc_admin_exec", str(EXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    ex = importlib.util.module_from_spec(spec)
    loader.exec_module(ex)
    strip = lambda t: {k: {kk: vv for kk, vv in v.items() if kk != "label"} for k, v in t.items()}
    assert strip(api.TRIAGE_PARAMS) == ex.TRIAGE_PARAMS
    assert strip(api.SOAR_PARAMS) == ex.SOAR_PARAMS


# --------------------------------------------------------------- front (statique)
SOC = ROOT / "mobile" / "soc"


def test_admin_assets_are_published_and_cached_by_service_worker():
    html = (SOC / "index.html").read_text(encoding="utf-8")
    sw = (SOC / "sw.js").read_text(encoding="utf-8")
    import re
    scripts = re.findall(r'<script src="(/soc/[^"]+)"', html)
    assert "/soc/app-admin.js?v=2026112101" in scripts
    assert scripts.index("/soc/app-admin.js?v=2026112101") > scripts.index("/soc/app-csp.js?v=2026112101")
    for src in scripts:
        if "?v=" in src:
            assert f'"{src}"' in sw, src
    assert 'id="p-admin"' in html and 'id="admRoot"' in html
    assert "<script>" not in html                       # CSP : aucun script en ligne
    # les lectures d'administration ne sont jamais conservées hors ligne
    data_ok = re.search(r"DATA_OK = new Set\(\[(.*?)\]\)", sw, re.S).group(1)
    assert "admin" not in data_ok


def test_admin_front_is_csp_compatible_and_handlers_exist():
    import re
    js = (SOC / "app-admin.js").read_text(encoding="utf-8")
    assert not re.search(r"\son(click|input|change|keydown|submit)\s*=", js)
    assert "eval(" not in js and "new Function" not in js
    handlers = set(re.findall(r'"(adm[A-Za-z]+)\(', js))
    defined = set(re.findall(r"window\.(adm[A-Za-z]+)\s*=", js))
    assert handlers and handlers <= defined, handlers - defined
    # les gestionnaires ne reçoivent que des indices entiers ou des littéraux fixes
    for call in re.findall(r'data-onclick="([^"]*)"', js):
        assert re.fullmatch(r'"?\s*\+?\s*"?[A-Za-z(),\' +"0-9i]*', call), call
    assert "X-SOC-CSRF" in js and '"Content-Type": "application/json"' in js


def test_no_emoji_in_admin_deliverables():
    import re
    emoji = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")
    files = [SOC / "app-admin.js", ROOT / "mobile" / "omni-soc-admin-exec", Path(__file__),
             ROOT / "docs" / "CONSOLE-SOC.md", ROOT / "docs" / "CONSOLE-SOC.en.md", ROOT / "docs" / "CONSOLE-DEPLOIEMENT.md"]
    files += sorted((ROOT / "mobile" / "systemd").glob("omni-soc-admin-exec*"))
    for f in files:
        assert not emoji.search(f.read_text(encoding="utf-8")), f


def test_repository_paths_default_to_reference_clone_and_are_configurable(api, tmp_path, monkeypatch):
    assert api.OMNI_REPO_DIR == "/opt/omni-siem/repository"
    assert api.OMS_GRAPH_DIR == "/opt/omni-siem/repository/oms-graph"
    assert "/root/omnitech-siem-setup" not in (api.OMS_GRAPH_DIR + api.OMS_GRAPH_PY)
    conf = tmp_path / "c.conf"
    conf.write_text("MOBILE_SECRET=a\nMOBILE_PUSH_SECRET=b\nGRAYLOG_API=http://127.0.0.1:9000/api\n")
    monkeypatch.setenv("MOBILE_CONFIG", str(conf))
    for k in ("MOBILE_SUBS_FILE", "MOBILE_CASES_FILE", "MOBILE_WATCH_FILE", "SOC_REQ_DIR", "SOC_ADMIN_DIR"):
        monkeypatch.setenv(k, str(tmp_path / k.lower()))      # chemins d'état aussi par l'environnement
    monkeypatch.setenv("OMNI_REPO_DIR", "/srv/depot/")
    spec = importlib.util.spec_from_file_location("omni_mobile_api_paths", str(API))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.OMS_GRAPH_DIR == "/srv/depot/oms-graph" and mod.OMS_GRAPH_PY == "/srv/depot/oms-graph/.venv/bin/python"
    assert mod.SOC_ADMIN_DIR == str(tmp_path / "soc_admin_dir") and mod.SOC_ADMIN_GELF_URL == ""


def test_shared_fixture_never_targets_production_paths(api, tmp_path):
    for path in (api.SOC_ADMIN_DIR, api.ADMIN_AUDIT_FILE, api.SOC_REQ_DIR, api.SUBS_FILE, api.CASES_FILE, api.WATCH_FILE):
        assert str(path).startswith(str(tmp_path)), path
    assert api.SOC_ADMIN_GELF_URL == ""


@pytest.mark.parametrize("variable", ["SOC_ADMIN_DIR", "MOBILE_SUBS_FILE", "SOC_REQ_DIR", "MOBILE_CASES_FILE"])
def test_backend_refuses_production_state_paths_in_test_mode(tmp_path, variable):
    conf = tmp_path / "c.conf"
    conf.write_text("MOBILE_SECRET=a\nMOBILE_PUSH_SECRET=b\nGRAYLOG_API=http://127.0.0.1:9000/api\n"
                    f"MOBILE_SUBS_FILE={tmp_path}/s.json\nMOBILE_CASES_FILE={tmp_path}/c.json\n"
                    f"MOBILE_WATCH_FILE={tmp_path}/w.json\nSOC_REQ_DIR={tmp_path}/r\nSOC_ADMIN_DIR={tmp_path}/a\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SOC_", "MOBILE_"))}
    minimal = tmp_path / "minimal.conf"
    minimal.write_text("MOBILE_SECRET=a\nMOBILE_PUSH_SECRET=b\nGRAYLOG_API=http://127.0.0.1:9000/api\n")
    env.update(MOBILE_CONFIG=str(minimal), OMNI_TEST_MODE="1")
    # configuration sans chemins : les défauts de production (/var/lib/omni-mobile) sont refusés
    r = subprocess.run([sys.executable, str(API)], env=env, capture_output=True, text=True, timeout=20)
    assert r.returncode != 0 and "production refusé" in r.stderr
    # un seul chemin de production dans une configuration par ailleurs isolée : refusé aussi
    env["MOBILE_CONFIG"] = str(conf)
    target = "/var/lib/omni-mobile/admin" if variable == "SOC_ADMIN_DIR" else "/var/lib/omni-mobile/x"
    conf.write_text(conf.read_text().replace(f"{variable}=", f"#{variable}=") + f"{variable}={target}\n")
    r = subprocess.run([sys.executable, str(API)], env=env, capture_output=True, text=True, timeout=20)
    assert r.returncode != 0 and variable in r.stderr


def test_executor_refuses_production_paths_in_test_mode(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}
    env.update(OMNI_SOC_EXEC_CONFIG=str(tmp_path / "absent.conf"), OMNI_TEST_MODE="1")
    r = subprocess.run([sys.executable, str(EXEC)], env=env, capture_output=True, text=True, timeout=20)
    assert r.returncode != 0 and "production refusé" in r.stderr
    assert not (tmp_path / "admin").exists()
