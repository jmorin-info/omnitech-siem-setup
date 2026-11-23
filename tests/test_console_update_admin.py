"""Mise à jour depuis la console : backend (droits, confirmation, libre-service limité à cette
action, garde-fous) et exécuteur privilégié (revalidation, transmission à la file root).

Réutilise le backend factice de tests/test_console_admin.py (sous-processus, dossiers
temporaires, OMNI_TEST_MODE=1) : aucun chemin de production n'est lu ni écrit.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import time

import pytest

_SPEC = importlib.util.spec_from_file_location("console_admin_fixture", Path(__file__).with_name("test_console_admin.py"))
fixture_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fixture_mod)
Console = fixture_mod.Console

TARGET = "c" * 40
PREV = "a" * 40
pytestmark = pytest.mark.skipif(os.name != "posix", reason="backend Linux")


def publish_status(c, **over):
    d = c.data / "admin" / "update"
    d.mkdir(parents=True, exist_ok=True)
    st = {"schema_version": 1, "generated_ts": time.time(), "generated_at": "2026-11-23T10:00:00+01:00",
          "update_available": True, "can_apply": True, "blocking": [], "installed": {"rev": PREV, "short": PREV[:12]},
          "available": {"rev": TARGET, "short": TARGET[:12]}, "restarts": ["omni-mobile-api.service"],
          "checks": [{"id": "ecarts", "label": "Écarts", "status": "avertissement", "detail": "1 fichier"}],
          "options": {"console": {"available": True}, "restart": {"available": True},
                      "modules": [{"id": "watchguard", "installable": False}, {"id": "unifi", "installable": True}]}}
    st.update(over)
    (d / "status.json").write_text(json.dumps(st))
    return st


def apply_params(**over):
    p = {"target": TARGET, "confirm": TARGET[:12], "console": True, "restart": True, "modules": [], "plan_read": True}
    p.update(over)
    return p


@pytest.fixture
def console(tmp_path):
    c = Console(tmp_path)
    yield c
    c.close()


def queue(c):
    return sorted((c.tmp / "update-queue").glob("*.json"))


def test_update_runs_without_second_admin_while_other_high_impact_actions_still_need_one(console):
    publish_status(console)
    status, r = console.act("alice", "update_apply", apply_params(), motif="mise à jour mensuelle")
    assert status == 200 and r["ok"] is True and r["status"] == "transmise" and not r.get("pending"), r
    req = json.loads((console.data / "admin" / "requests" / (r["id"] + ".json")).read_text())
    assert req["self_service"] is True and req["requested_by"] == req["decided_by"] == "alice"
    out = console.run_executor()
    assert out.returncode == 0, out.stderr
    jobs = queue(console)
    assert len(jobs) == 1 and json.loads(jobs[0].read_text())["params"]["target"] == TARGET
    assert oct(jobs[0].parent.stat().st_mode & 0o777) == "0o700"
    done = json.loads((console.data / "admin" / "exec" / "done" / (r["id"] + ".json")).read_text())
    assert done["status"] == "faite"
    # une autre action à fort impact reste soumise à la double validation
    status, r2 = console.act("alice", "soar_block", {"ip": "8.8.8.8"}, motif="scan agressif")
    assert r2["pending"] is True
    assert console.decide("alice", r2["id"])[0] == 403
    assert not console.soar.calls
    events = [(e["event"], e["action"]) for e in console.audit()["entries"]]
    assert ("demande", "update_apply") in events and ("execution_privilegiee", "update_apply") in events


@pytest.mark.parametrize("params,needle", [
    (apply_params(confirm=""), "confirmation"),
    (apply_params(confirm="0" * 12), "confirmation"),
    (apply_params(plan_read=False), "lu le plan"),
    (apply_params(target="d" * 40, confirm="d" * 12), "pas la mise à jour disponible"),
    (apply_params(modules=["watchguard"]), "non installable"),
    (apply_params(target="HEAD"), "révision cible invalide"),
])
def test_update_apply_refusals_have_no_side_effect(console, params, needle):
    publish_status(console)
    status, r = console.act("alice", "update_apply", params, motif="essai")
    assert status in (400, 409) and needle in r["error"], r
    assert not (console.data / "admin" / "exec" / "pending").exists() or \
        not list((console.data / "admin" / "exec" / "pending").glob("*.json"))


def test_blocking_checks_or_stale_plan_refuse_update(console):
    publish_status(console, can_apply=False, blocking=["Arbre de travail propre : 1 fichier"])
    status, r = console.act("alice", "update_apply", apply_params(), motif="essai")
    assert status == 409 and "Arbre" in r["error"]
    publish_status(console, generated_ts=time.time() - 30 * 3600)
    status, r = console.act("alice", "update_apply", apply_params(), motif="essai")
    assert status == 409 and "24 h" in r["error"]


def test_simulation_shows_plan_and_requires_nothing(console):
    publish_status(console)
    status, r = console.act("alice", "update_apply", apply_params(confirm="", plan_read=False), simulate=True)
    assert status == 200 and r["impact"] == "eleve"
    assert r["preview"]["confirmation"]["expected"] == TARGET[:12]
    assert any("Écarts" in w for w in r["preview"]["warnings"])


def test_update_is_reserved_to_admins_and_internal_networks(console):
    publish_status(console)
    assert console.call("GET", "/m/api/admin/update", "carol")[0] == 403
    assert console.act("carol", "update_apply", apply_params())[0] == 403
    assert console.act("alice", "update_apply", apply_params(), ip="203.0.113.7")[0] == 403
    assert console.act("alice", "update_apply", apply_params(), csrf=False)[0] == 403
    assert console.act("alice", "update_apply", apply_params(), origin="https://evil.test")[0] == 403
    status, d = console.call("GET", "/m/api/admin/update", "alice")
    assert status == 200 and d["status"]["available"]["rev"] == TARGET and d["in_progress"] is False
    me = console.call("GET", "/m/api/admin/me", "alice")[1]
    assert me["update_available"] is True and me["update_short"] == TARGET[:12]


def test_global_dry_run_never_queues(tmp_path):
    c = Console(tmp_path, "SOC_ADMIN_DRY_RUN=1")
    try:
        publish_status(c)
        status, r = c.act("alice", "update_apply", apply_params(), motif="essai")
        assert status == 200 and r["simulation"] is True
        assert not (c.data / "admin" / "exec" / "pending").exists() or not list((c.data / "admin" / "exec" / "pending").glob("*.json"))
    finally:
        c.close()


def test_second_update_while_one_is_in_progress_is_refused(console):
    publish_status(console)
    assert console.act("alice", "update_apply", apply_params(), motif="première")[1]["status"] == "transmise"
    status, r = console.act("bob", "update_apply", apply_params(), motif="seconde")
    assert status == 409 and "en cours" in r["error"]


def test_check_request_is_written_then_rate_limited(console):
    publish_status(console, generated_ts=time.time() - 3600)
    status, r = console.act("alice", "update_check", {}, motif="vérifier GitHub")
    assert status == 200 and r["ok"] is True
    assert (console.data / "admin" / "update" / "check-request").exists()
    status, r = console.act("alice", "update_check", {}, motif="encore")
    assert status == 409 and "déjà demandée" in r["error"]


def test_rollback_needs_confirmation_of_previous_revision(console):
    publish_status(console)
    run = {"id": "20261123-100000-0000000a", "kind": "apply", "status": "terminee", "target": TARGET, "prev_rev": PREV}
    (console.data / "admin" / "update" / "run.json").write_text(json.dumps(dict(run, id="20261123-110000-0000000f",
                                                                             status="refusee")))
    (console.data / "admin" / "update" / "last_apply.json").write_text(json.dumps(run))
    status, r = console.act("alice", "update_rollback", {"run_id": run["id"], "confirm": TARGET[:12]}, motif="régression")
    assert status == 400 and "confirmation" in r["error"]
    status, r = console.act("alice", "update_rollback", {"run_id": run["id"], "confirm": PREV[:12]}, motif="régression")
    assert status == 200 and r["status"] == "transmise"
    assert console.run_executor().returncode == 0
    assert json.loads(queue(console)[0].read_text())["kind"] == "update_rollback"


def test_executor_refuses_self_service_for_other_actions_and_tampered_update_requests(console):
    pend = console.data / "admin" / "exec" / "pending"
    req_dir = console.data / "admin" / "requests"
    done = console.data / "admin" / "exec" / "done"
    pend.mkdir(parents=True)
    req_dir.mkdir(parents=True, exist_ok=True)

    def run(rid, kind, params, request):
        (req_dir / f"{rid}.json").write_text(json.dumps(dict({"id": rid, "action": kind, "params": params}, **request)))
        (pend / f"{rid}.json").write_text(json.dumps({"id": rid, "kind": kind, "params": params, "actor": "alice"}))
        console.run_executor()
        return json.loads((done / f"{rid}.json").read_text())

    triage = {"key": "MAIL_SCORE_THRESHOLD", "value": "99"}
    d = run("20261123-120000-0000000a", "triage_param", triage,
            {"status": "transmise", "self_service": True, "requested_by": "alice", "decided_by": "alice"})
    assert d["status"] == "refusee" and "libre-service" in d["resultat"]
    assert "MAIL_SCORE_THRESHOLD=80" in console.triage_env.read_text()
    d = run("20261123-120000-0000000b", "update_apply", apply_params(),
            {"status": "approuvee", "requested_by": "alice", "decided_by": "bob"})
    assert d["status"] == "refusee"
    d = run("20261123-120000-0000000c", "update_apply", apply_params(confirm="0" * 12),
            {"status": "transmise", "self_service": True, "requested_by": "alice", "decided_by": "alice"})
    assert d["status"] == "refusee" and "confirmation" in d["resultat"]
    d = run("20261123-120000-0000000d", "update_apply", dict(apply_params(), extra="x"),
            {"status": "transmise", "self_service": True, "requested_by": "alice", "decided_by": "alice"})
    assert d["status"] == "refusee"
    assert not queue(console)


def test_front_has_update_tab_banner_and_confirmation():
    js = (fixture_mod.SOC / "app-admin.js").read_text(encoding="utf-8")
    assert '["updates", "Mises à jour"]' in js and 'updates: "/admin/update"' in js
    assert "admUpdBanner" in js and "J\\'ai lu le plan" in js and "admConfRev" in js
    assert "setTimeout" in js and "updPoll" in js
