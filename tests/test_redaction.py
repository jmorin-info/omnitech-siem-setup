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


def test_entites_jointes_virgule_masquees_dans_narrative(api):
    """Régression P0 (fuite rédaction des incidents).

    Le champ `entities` des incidents oms-xdr est une CHAÎNE jointe par virgules
    (`",".join(...)`). S'il est pseudonymisé EN BLOC, chaque nom d'hôte/compte
    n'entre pas dans _RD_MAP et reste EN CLAIR dans la narrative (texte libre) au
    passage _walk_redact. Le correctif scinde la chaîne et pseudonymise chaque
    entité — ce test verrouille l'invariant.
    """
    blob = "VM-BDX-NAV2018$,ninjaone"
    narrative = "Vol d'identifiants LSASS sur VM-BDX-NAV2018$, pivot vers ninjaone."

    # Comportement fautif (bloc entier) : la narrative N'est PAS masquée.
    api._rd(blob)
    assert "VM-BDX-NAV2018$" in api._scrub(narrative), \
        "pré-condition : pseudonymiser le bloc entier ne masque pas les noms individuels"

    # Correctif : on scinde puis _rd par entité (logique de get_incidents).
    api._RD_MAP.clear()
    api._RD_REV.clear()
    ents = [api._rd(e) for e in blob.split(",") if e]
    out = api._scrub(narrative)
    assert "VM-BDX-NAV2018$" not in out, "hostname machine ($) toujours en clair"
    assert "ninjaone" not in out, "compte de service toujours en clair"
    # forme attendue + présence des pseudonymes dans la narrative masquée
    assert ents[0].startswith("HOST-") and ents[0].endswith("$")
    assert all(p in out for p in ents)
