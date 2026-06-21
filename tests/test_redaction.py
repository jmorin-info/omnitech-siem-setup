"""Rédaction du backend mobile (mode démo / captures) — sans OpenSearch ni serveur.

Vérifie les invariants attendus par la console SOC en mode rédigé :
  - _rd pseudonymise de façon STABLE (même entrée -> même sortie) et RÉVERSIBLE
    (_RD_REV pseudo -> réel, pour que l'Entité-360 fonctionne) ;
  - _scrub masque IP / SID / e-mail dans le texte libre + les entités déjà vues ;
  - _walk_redact applique _scrub récursivement sans toucher aux non-chaînes ;
  - tout est NO-OP quand REDACT est faux (mode production).
"""
from __future__ import annotations

import re


def test_rd_stable_et_reversible(api):
    a = api._rd("OMNITECH\\jmorin")
    b = api._rd("OMNITECH\\jmorin")
    assert a == b, "pseudonyme instable pour la même entrée"
    assert a != "OMNITECH\\jmorin", "valeur réelle non masquée"
    assert api._RD_REV[a] == "OMNITECH\\jmorin", "réversibilité _RD_REV cassée"
    # un autre compte -> un autre pseudo (pas de collision triviale)
    assert api._rd("OMNITECH\\autre") != a


def test_rd_formes_specifiques(api):
    # DOMAINE\compte : le domaine est préservé (utile à l'analyste), le compte masqué
    out = api._rd("OMNITECH\\jmorin")
    assert out.startswith("OMNITECH\\ent-")
    # compte machine AD (suffixe $) -> HOST-…$
    m = api._rd("BX-IT-DC01$")
    assert m.startswith("HOST-") and m.endswith("$")
    # entité simple -> préfixe neutre ent-
    assert api._rd("svc-backup").startswith("ent-")


def test_rd_ip_pseudonymisee_et_privee(api):
    out = api._rd("203.0.113.42")
    assert out != "203.0.113.42"
    assert api._IP_RE.fullmatch(out), "la sortie doit rester une IPv4 valide"
    assert out.startswith("10."), "IP pseudonymisée attendue en plage privée 10/8"
    # stable
    assert api._rd("203.0.113.42") == out


def test_rd_noop_quand_desactive(api):
    api.REDACT = False
    assert api._rd("OMNITECH\\jmorin") == "OMNITECH\\jmorin"
    assert api._rd("203.0.113.42") == "203.0.113.42"
    # valeurs vides : renvoyées telles quelles, pas d'entrée créée
    assert api._rd("") == ""
    assert api._rd(None) is None


def test_scrub_masque_ip_sid_email(api):
    txt = "login 203.0.113.9 sid S-1-5-21-111-222-333-1001 mail a.b@omnitech-security.fr"
    out = api._scrub(txt)
    assert "203.0.113.9" not in out
    assert "S-1-5-21-111-222-333-1001" not in out
    assert "S-1-5-21-x-x-x" in out
    assert "a.b@omnitech-security.fr" not in out
    assert "user@redacted.local" in out
    # aucune IPv4 réelle (hors plage 10) ne doit subsister
    for ip in re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", out):
        assert ip.startswith("10."), f"IP non masquée : {ip}"


def test_scrub_reutilise_entites_connues(api):
    pseudo = api._rd("OMNITECH\\jmorin")           # mémorise la correspondance
    out = api._scrub("alerte sur OMNITECH\\jmorin depuis 198.51.100.7")
    assert "OMNITECH\\jmorin" not in out, "entité connue non substituée dans le texte"
    assert pseudo in out
    assert "198.51.100.7" not in out


def test_scrub_noop_quand_desactive_ou_non_str(api):
    api.REDACT = False
    assert api._scrub("ip 203.0.113.9") == "ip 203.0.113.9"
    api.REDACT = True
    assert api._scrub(None) is None          # non-chaîne : inchangé
    assert api._scrub(1234) == 1234


def test_walk_redact_recursif_preserve_types(api):
    api._rd("OMNITECH\\jmorin")
    payload = {
        "msg": "depuis 203.0.113.9",
        "count": 5,                          # int préservé
        "ratio": 1.5,                        # float préservé
        "flag": True,                        # bool préservé
        "items": ["mail x@omnitech-security.fr", "OMNITECH\\jmorin"],
        "nested": {"ip": "198.51.100.2"},
    }
    out = api._walk_redact(payload)
    assert out["count"] == 5 and out["ratio"] == 1.5 and out["flag"] is True
    assert "203.0.113.9" not in out["msg"]
    assert "x@omnitech-security.fr" not in out["items"][0]
    assert "OMNITECH\\jmorin" not in out["items"][1]
    assert "198.51.100.2" not in out["nested"]["ip"]


def test_walk_redact_noop_quand_desactive(api):
    api.REDACT = False
    obj = {"ip": "203.0.113.9", "n": 1}
    assert api._walk_redact(obj) == obj
