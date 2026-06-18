"""Tests du responder : dry-run garantit l'absence d'exécution."""
from oms_xdr.responder import Responder


def test_dry_run_only_recommends():
    r = Responder({"response": {"dry_run": True, "auto_block_fortigate": True}})
    out = r.execute("block_fortigate", ["203.0.113.9"])
    assert out and out[0].startswith("RECO:")


def test_double_lock_required():
    # dry_run=false mais flag auto absent -> reste en recommandation
    r = Responder({"response": {"dry_run": False, "auto_isolate_ninjaone": False}})
    out = r.execute("isolate_ninjaone", ["WS-001"])
    assert out[0].startswith("RECO:")
