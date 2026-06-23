"""Tests du Pilier 3 — réponse graduée (grade, garde-fous, scope, armement)."""
import os

from oms_graph import response


def test_grade():
    assert response.grade({"jewels_reached": ["DC1"], "hosts_reached": 5}, False) == "critique"
    assert response.grade({"jewels_reached": [], "hosts_reached": 0}, True) == "eleve"   # leurre = plancher
    assert response.grade({"jewels_reached": [], "hosts_reached": 0}, False) == "modere"
    assert response.grade({"is_chokepoint": True, "hosts_reached": 12}, False) == "critique"


def test_build_plan_critique_has_contain_and_reco():
    ctx = {"jewels_reached": ["DC1"], "hosts_reached": 9}
    p = response.build_plan("bx-dev-pc1", "bx-dev-pc1", "10.33.1.5", "bob", "critique", ctx)
    acts = {s["action"] for s in p["steps"]}
    assert "isolate_ninjaone" in acts and "block_fortigate" in acts
    assert "disable_ad_account" in acts  # présent mais reco-only


def test_dry_run_recommends_only():
    resp = response.SentinelResponder({"response": {"dry_run": True}})
    p = response.build_plan("h1", "h1", "1.2.3.4", "bob", "critique",
                            {"jewels_reached": ["DC1"], "hosts_reached": 9})
    out = resp.execute(p, approve=True)
    assert all(r["status"] == "RECOMMANDÉ" for r in out["results"])


def test_identity_action_never_armable():
    cfg = {"response": {"dry_run": False, "auto_disable_ad_account": True}}
    os.environ["OMNI_SENTINEL_ARM"] = "1"
    resp = response.SentinelResponder(cfg)
    armable, _ = resp._armable("disable_ad_account", "bob")
    assert armable is False   # identitaire = jamais armé
    del os.environ["OMNI_SENTINEL_ARM"]


def test_comanaged_forced_dry_run():
    cfg = {"response": {"dry_run": False, "auto_isolate_ninjaone": True, "comanaged_markers": ["invissys"]}}
    os.environ["OMNI_SENTINEL_ARM"] = "1"
    resp = response.SentinelResponder(cfg)
    a_own, _ = resp._armable("isolate_ninjaone", "bx-dev-pc1")
    a_co, why = resp._armable("isolate_ninjaone", "host.invissys.com")
    assert a_own is True            # infra OMNITECH -> armable
    assert a_co is False and "co-managée" in why   # co-managé -> forcé dry-run
    del os.environ["OMNI_SENTINEL_ARM"]


def test_double_lock_env_required():
    cfg = {"response": {"dry_run": False, "auto_isolate_ninjaone": True}}
    os.environ.pop("OMNI_SENTINEL_ARM", None)
    resp = response.SentinelResponder(cfg)
    armable, why = resp._armable("isolate_ninjaone", "bx-dev-pc1")
    assert armable is False and "OMNI_SENTINEL_ARM" in why   # double-verrou manquant
