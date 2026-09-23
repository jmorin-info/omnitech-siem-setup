"""Tests du responder : dry-run garantit l'absence d'exécution."""
import logging

import pytest

from oms_xdr.responder import Responder

# Actions sans runbook : aucun appel sortant n'existe derriere elles.
# (block_fortigate est exclu : lui est REEL, via le feed omni-soar.)
SANS_RUNBOOK = [
    ("isolate_ninjaone", "auto_isolate_ninjaone", "BX-AD-01-IT-VM"),
    ("disable_ad_account", "auto_disable_ad_account", "adm-jmorin"),
    ("force_pwd_reset", "auto_disable_ad_account", "adm-jmorin"),
]


def test_dry_run_only_recommends():
    r = Responder({"response": {"dry_run": True, "auto_block_fortigate": True}})
    out = r.execute("block_fortigate", ["203.0.113.9"])
    assert out and out[0].startswith("RECO:")


def test_double_lock_required():
    # dry_run=false mais flag auto absent -> reste en recommandation
    r = Responder({"response": {"dry_run": False, "auto_isolate_ninjaone": False}})
    out = r.execute("isolate_ninjaone", ["WS-001"])
    assert out[0].startswith("RECO:")


# ----------------------------------------------------------------------
# Verrou d'HONNETETE (audit 17/07/2026).
# Ces actions n'ont AUCUN runbook raccorde. Le jour ou un operateur leve le double
# verrou en croyant armer la reponse, le produit doit dire qu'il n'a RIEN fait.
# Un "OK" ici ferait croire au SOC qu'un hote est isole pendant qu'un rancongiciel
# se propage (isolate_ninjaone = etape 1 de CR_RANSOMWARE, cite par 11 playbooks).
# Si un vrai runbook est un jour implemente, ces tests DOIVENT etre revus en meme
# temps -- et pas avant : les faire passer en trichant reintroduit le mensonge.
@pytest.mark.parametrize("action,flag,entity", SANS_RUNBOOK)
def test_action_sans_runbook_ne_ment_jamais(action, flag, entity):
    """Double verrou LEVE => le retour ne commence PAS par OK."""
    r = Responder({"response": {"dry_run": False, flag: True}})
    out = r.execute(action, [entity])
    assert out, "aucun retour"
    assert not out[0].startswith("OK"), (
        f"{action} annonce un succes ({out[0]!r}) alors qu'aucun appel sortant "
        f"n'existe : le SOC croirait l'action effectuee."
    )
    assert out[0].startswith("NON-IMPLEMENTE:"), out[0]


@pytest.mark.parametrize("action,flag,entity", SANS_RUNBOOK)
def test_action_sans_runbook_ne_journalise_pas_action(action, flag, entity, caplog):
    """Double verrou leve => journal en ERROR, jamais une ligne 'ACTION:' de succes."""
    r = Responder({"response": {"dry_run": False, flag: True}})
    with caplog.at_level(logging.INFO, logger="oms-xdr.responder"):
        r.execute(action, [entity])
    assert not any(rec.getMessage().startswith("ACTION:") for rec in caplog.records), (
        "journalise 'ACTION:' pour une action qui n'a pas eu lieu"
    )
    assert any(rec.levelno >= logging.ERROR for rec in caplog.records), (
        "un verrou leve sans runbook doit remonter en ERROR"
    )


def test_aucun_appel_sortant_dans_les_actions_sans_runbook():
    """Verrou structurel : prouve par l'AST qu'aucune de ces methodes n'appelle le
    reseau. Si quelqu'un implemente un vrai runbook, ce test casse volontairement :
    l'action devra alors etre re-autorisee (RSSI) et sortir de SANS_RUNBOOK.
    Rappel : le tenant invissys.com est co-gere, aucune action de reponse permise.
    """
    import ast
    import inspect

    import oms_xdr.responder as mod

    src = inspect.getsource(mod)
    tree = ast.parse(src)
    cls = next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "Responder")
    sortants = {"requests", "urllib", "http", "socket", "subprocess",
                "paramiko", "winrm", "ldap3", "smtplib"}
    # _no_runbook porte l'implementation partagee des trois actions.
    for meth in [a for a, _, _ in SANS_RUNBOOK] + ["no_runbook"]:
        fn = next((n for n in cls.body
                   if isinstance(n, ast.FunctionDef) and n.name == f"_{meth}"), None)
        assert fn is not None, f"_{meth} introuvable"
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                racine = node.func
                while isinstance(racine, ast.Attribute):
                    racine = racine.value
                if isinstance(racine, ast.Name):
                    assert racine.id not in sortants, (
                        f"_{meth} contient un appel sortant ({racine.id}) : "
                        f"si le runbook est reellement implemente, revoir ce test "
                        f"ET l'autorisation RSSI."
                    )
