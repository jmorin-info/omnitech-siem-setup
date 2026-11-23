"""26-graylog-objets-manuels.sh : syntaxe, plan en lecture seule et idempotence.

Depuis le 22/11/2026, 26 ne crée plus que les définitions d'événements ; les
règles versionnées et leur raccordement sont seulement contrôlés (ils sont posés
par les scripts propriétaires des pipelines, voir tests/test_pipelines_versionnes.py).

Le script réel est exécuté contre une API Graylog simulée : un faux `curl` placé
en tête du PATH lit et écrit un état JSON (règles, pipelines, flux,
notifications, définitions paginées). Aucun accès réseau.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "26-graylog-objets-manuels.sh"
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("jq") or not shutil.which("bash"),
                                reason="Bash et jq requis")

FAUX_CURL = r'''#!/usr/bin/env python3
import json, os, sys, urllib.parse
etat_f = os.environ["FAUX_GRAYLOG_ETAT"]
etat = json.load(open(etat_f, encoding="utf-8"))
args = sys.argv[1:]
methode, corps, write_out, fail, url = "GET", None, None, "--fail" in args, None
i = 0
while i < len(args):
    a = args[i]
    if a == "-X": methode = args[i + 1]; i += 1
    elif a == "-d": corps = sys.stdin.read() if args[i + 1] == "@-" else args[i + 1]; i += 1
    elif a == "--write-out": write_out = args[i + 1]; i += 1
    elif a in ("-u", "-H", "--cacert", "--connect-timeout", "--max-time"): i += 1
    elif a.startswith("http"): url = a
    i += 1
if corps is not None and methode == "GET": methode = "POST"
u = urllib.parse.urlsplit(url); chemin = u.path.removeprefix("/api"); q = dict(urllib.parse.parse_qsl(u.query))
etat.setdefault("appels", []).append([methode, chemin])
def nid():
    etat["seq"] = etat.get("seq", 0) + 1
    return "%024x" % (0xabc000 + etat["seq"])
code, rep = 200, None
if methode != "GET":
    etat.setdefault("ecritures", []).append([methode, chemin])
if methode == "GET" and chemin == "/system":
    rep = {"version": "7.2.2"}
elif methode == "GET" and chemin == "/system/pipelines/rule":
    rep = etat["regles"]
elif methode == "POST" and chemin == "/system/pipelines/rule":
    b = json.loads(corps); b["id"] = nid(); etat["regles"].append(b); rep = b
elif methode == "GET" and chemin == "/system/pipelines/pipeline":
    rep = etat["pipelines"]
elif methode == "PUT" and chemin.startswith("/system/pipelines/pipeline/"):
    b = json.loads(corps)
    for p in etat["pipelines"]:
        if p["id"] == chemin.rsplit("/", 1)[1]: p["source"] = b["source"]; rep = p
elif methode == "GET" and chemin == "/system/pipelines/connections":
    rep = etat["connexions"]
elif methode == "GET" and chemin == "/streams":
    rep = {"streams": etat["flux"]}
elif methode == "GET" and chemin == "/events/notifications":
    rep = {"notifications": etat["notifications"], "total": len(etat["notifications"])}
elif methode == "GET" and chemin == "/events/definitions":
    pp, page = int(q.get("per_page", 50)), int(q.get("page", 1))
    rep = {"event_definitions": etat["definitions"][(page - 1) * pp: page * pp], "total": len(etat["definitions"])}
elif methode == "POST" and chemin == "/events/definitions":
    b = json.loads(corps)
    if "entity" not in b:
        code, rep = 400, {"message": "entity cannot be null"}
    else:
        d = b["entity"]; d["id"] = nid(); d["state"] = "ENABLED"; etat["definitions"].append(d); rep = d
else:
    code, rep = 404, {"message": "inconnu"}
json.dump(etat, open(etat_f, "w", encoding="utf-8"), ensure_ascii=False)
sortie = json.dumps(rep)
if code >= 400 and fail:
    sys.exit(22)
sys.stdout.write(sortie + ("\n%d" % code if write_out else ""))
'''

FLUX = {"OMNI - FortiGate": "f0000000000000000000000a", "OMNI - BunkerWeb": "f0000000000000000000000b",
        "OMNI - Windows Security": "f0000000000000000000000c", "OMNI - Sysmon": "f0000000000000000000000d"}
NOTIFS = {"OMNI - SOAR auto-block": "n0000000000000000000000a", "OMNI - Teams SOC": "n0000000000000000000000b",
          "OMNI - Triage (mail critique)": "n0000000000000000000000c"}
PIPES = {"OMNI - Exposition reseau": ("p0000000000000000000000a", 'pipeline "OMNI - Exposition reseau"\nstage 14 match either\nrule "omni-forti-14-privflags"\nstage 16 match either\nrule "omni-forti-16-expo-internet"\nend'),
         "OMNI - Allowlist FP": ("p0000000000000000000000b", 'pipeline "OMNI - Allowlist FP"\nstage 25 match either\nrule "omni-fp-25-service-install"\nend'),
         "OMNI v3 - Detections et correlation": ("p0000000000000000000000c", 'pipeline "OMNI v3 - Detections et correlation"\nstage 40 match either\nrule "omni-v3-logon-admin"\nend')}


def inventaire():
    """(titre, fichier, pipeline, étape) de l'inventaire unique ; définitions lues dans le script."""
    texte = SCRIPT.read_text(encoding="utf-8")
    lignes = (ROOT / "objets-graylog/raccordements.txt").read_text(encoding="utf-8").splitlines()
    regles = [tuple(l.split("|")) for l in lignes if l.strip() and not l.startswith("#")]
    defs = [l.strip() for l in texte.split("DEFINITIONS=(", 1)[1].split(")", 1)[0].splitlines() if l.strip()]
    return [(t, f, p, e) for t, f, _d, p, e, _pos in regles], defs


def definition_resolue(fichier):
    d = json.loads((ROOT / fichier).read_text(encoding="utf-8"))
    d["config"]["streams"] = [FLUX[t] for t in d.pop("flux_par_titre")]
    d["notifications"] = [{"notification_id": NOTIFS[t], "notification_parameters": None}
                          for t in d.pop("notifications_par_titre")]
    return d


def etat_vide():
    """Instance reconstruite : prérequis présents, objets versionnés absents, 130 définitions (pagination)."""
    return {
        "regles": [{"id": "r-existante", "title": "omni-fp-25-service-install", "description": "", "source": "rule \"omni-fp-25-service-install\"\nwhen true then end"}],
        "pipelines": [{"id": i, "title": t, "description": "provisionne", "source": s} for t, (i, s) in PIPES.items()],
        "connexions": [{"id": "c1", "stream_id": FLUX["OMNI - FortiGate"], "pipeline_ids": [PIPES["OMNI - Exposition reseau"][0]]}],
        "flux": [{"id": i, "title": t} for t, i in FLUX.items()],
        "notifications": [{"id": i, "title": t} for t, i in NOTIFS.items()],
        "definitions": [{"id": "d%023d" % n, "title": f"OMNI - remplissage {n}", "config": {}} for n in range(130)],
    }


def etat_pipelines_ok():
    """Règles versionnées créées et raccordées par les scripts propriétaires ; définitions absentes."""
    etat = etat_vide()
    regles, _defs = inventaire()
    for n, (titre, fichier, pipe, etape) in enumerate(regles):
        source = (ROOT / fichier).read_text(encoding="utf-8").rstrip("\n")   # production : sans saut final
        etat["regles"].append({"id": f"r{n}", "title": titre, "description": "", "source": source})
    for p in etat["pipelines"]:
        lignes = {}
        for titre, _f, pipe, etape in regles:
            if pipe == p["title"]:
                lignes.setdefault(etape, []).append(f'rule "{titre}"')
        corps = p["source"].rsplit("\nend", 1)[0]
        for etape, rs in sorted(lignes.items()):
            if f"stage {etape} " in corps:
                corps = corps.replace(f"stage {etape} match either", f"stage {etape} match either\n" + "\n".join(rs))
            else:
                corps += f"\nstage {etape} match either\n" + "\n".join(rs)
        p["source"] = corps + "\nend"
    return etat


def etat_production():
    """Tous les objets en service, définitions versionnées placées au-delà du rang 100."""
    etat = etat_pipelines_ok()
    _regles, defs = inventaire()
    for n, f in enumerate(defs):
        d = definition_resolue(f)
        d["id"], d["state"] = f"e{n:023d}", "ENABLED"
        # forme rendue par l'API : seuils flottants, champs posés par le serveur
        d["config"]["conditions"]["expression"]["right"]["value"] = float(d["config"]["conditions"]["expression"]["right"]["value"])
        d.update({"_scope": "DEFAULT", "updated_at": "2026-11-11T00:00:00Z", "scheduler": None})
        etat["definitions"].insert(110 + n, d)
    return etat


@pytest.fixture
def api(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(FAUX_CURL, encoding="utf-8")
    (bin_dir / "curl").chmod(0o755)
    vars_f = tmp_path / "vars.env"
    vars_f.write_text("GRAYLOG_API_URL=http://127.0.0.1:9000/api\nGRAYLOG_ADMIN_PASS=dummy-test-only\n", encoding="utf-8")
    etat_f = tmp_path / "etat.json"

    class Api:
        def charger(self, etat):
            etat_f.write_text(json.dumps(etat), encoding="utf-8")

        @property
        def etat(self):
            return json.loads(etat_f.read_text(encoding="utf-8"))

        def lancer(self, *opts):
            env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAUX_GRAYLOG_ETAT": str(etat_f)}
            return subprocess.run(["bash", str(SCRIPT), "--vars", str(vars_f), *opts],
                                  env=env, capture_output=True, text=True, timeout=120)
    return Api()


def test_syntaxe_bash():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-S", "error", "-x", str(SCRIPT)], check=True, cwd=ROOT)


def test_sources_versionnees_coherentes():
    regles, defs = inventaire()
    assert len(regles) == 17 and len(defs) == 3
    titres = [t for t, *_ in regles]
    assert len(set(titres)) == len(titres)
    assert sum(t.startswith("omni-fp-26-") for t in titres) == 15
    for titre, fichier, _p, etape in regles:
        source = (ROOT / fichier).read_text(encoding="utf-8")
        assert source.startswith(f'rule "{titre}"'), fichier
        assert etape.isdigit()
        assert " ? " not in source, "ternaire non supporté par les règles de pipeline Graylog"
    for f in defs:
        d = json.loads((ROOT / f).read_text(encoding="utf-8"))
        assert d["config"]["streams"] == [] and d["flux_par_titre"], "flux désignés par titre uniquement"
        assert "notifications" not in d and d["notifications_par_titre"]
        assert "id" not in d and not any(k.startswith("_") for k in d)


def test_plan_sur_production_tout_deja_present(api):
    api.charger(etat_production())
    r = api.lancer()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "37 déjà présent(s), 0 à créer, 0 écart(s)" in r.stdout
    assert "à créer :" not in r.stdout
    assert "ecritures" not in api.etat
    assert "dummy-test-only" not in r.stdout + r.stderr


def test_plan_puis_apply_puis_idempotence(api):
    api.charger(etat_pipelines_ok())
    plan = api.lancer()
    assert plan.returncode == 0, plan.stdout + plan.stderr
    assert "34 déjà présent(s), 3 à créer" in plan.stdout
    assert "ecritures" not in api.etat, "le mode plan ne doit rien écrire"

    app = api.lancer("--apply")
    assert app.returncode == 0, app.stdout + app.stderr
    etat = api.etat
    _regles, defs = inventaire()
    # seules écritures : les 3 définitions (règles et pipelines appartiennent à leurs scripts)
    # (post_entity retente avec l'enveloppe Graylog 7 : 2 POST par définition)
    assert {tuple(e) for e in etat["ecritures"]} == {("POST", "/events/definitions")}
    # définitions : enveloppe Graylog 7, identifiants résolus par titre, aucun doublon malgré la pagination
    crees = [d for d in etat["definitions"] if not d["title"].startswith("OMNI - remplissage")]
    assert sorted(d["title"] for d in crees) == sorted(json.loads((ROOT / f).read_text(encoding="utf-8"))["title"] for f in defs)
    ike = next(d for d in crees if "IKE" in d["title"])
    assert ike["config"]["streams"] == [FLUX["OMNI - FortiGate"]]
    assert ike["notifications"] == [{"notification_id": NOTIFS["OMNI - SOAR auto-block"], "notification_parameters": None}]
    assert "flux_par_titre" not in ike

    n_ecritures = len(etat["ecritures"])
    second = api.lancer()
    assert second.returncode == 0 and "37 déjà présent(s), 0 à créer, 0 écart(s)" in second.stdout, second.stdout
    troisieme = api.lancer("--apply")
    assert troisieme.returncode == 0
    assert len(api.etat["ecritures"]) == n_ecritures, "second --apply : aucune écriture"


def test_regles_absentes_controle_sans_ecriture(api):
    """Instance reconstruite sans les scripts propriétaires : 26 signale, n'écrit ni règle ni pipeline."""
    api.charger(etat_vide())
    r = api.lancer("--apply")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "absent (relancer 81-fp-allowlist.sh) : règle omni-fp-26-outlook-liens" in r.stdout
    assert "absent (relancer tools/omni-v3/v3_build.py --appliquer) : raccordement omni-v3-laps-lecture" in r.stdout
    assert "absent (relancer 49-expo-port-class.sh" in r.stdout
    ecritures = api.etat.get("ecritures", [])
    assert all(chemin == "/events/definitions" for _m, chemin in ecritures), ecritures


def test_ecart_signale_jamais_ecrase(api):
    etat = etat_production()
    next(r for r in etat["regles"] if r["title"] == "omni-v3-laps-lecture")["source"] += "\n// modifiee a la main"
    next(d for d in etat["definitions"] if "WAF" in d["title"])["priority"] = 1
    api.charger(etat)
    r = api.lancer("--apply")
    assert r.returncode == 0
    assert "écart (non modifié) : règle omni-v3-laps-lecture" in r.stdout
    assert "scan applicatif" in r.stdout and "priority" in r.stdout
    assert "ecritures" not in api.etat


def test_prerequis_manquants(api):
    etat = etat_vide()
    etat["pipelines"] = [p for p in etat["pipelines"] if p["title"] != "OMNI - Allowlist FP"]
    etat["flux"] = [f for f in etat["flux"] if f["title"] != "OMNI - BunkerWeb"]
    api.charger(etat)
    r = api.lancer("--apply")
    assert r.returncode == 1
    assert "absent (relancer 81-fp-allowlist.sh) : pipeline « OMNI - Allowlist FP »" in r.stdout
    assert "OMNI - BunkerWeb" in r.stdout
    assert not any("WAF" in d["title"] for d in api.etat["definitions"])


def test_coherence_check_ne_signale_plus_ces_objets():
    spec = importlib.util.spec_from_file_location("occ_versionnage", ROOT / "tools/omni-coherence-check.py")
    occ = importlib.util.module_from_spec(spec)
    sys.modules["occ_versionnage"] = occ
    spec.loader.exec_module(occ)
    regles, defs = inventaire()
    titres = [t for t, *_ in regles] + [json.loads((ROOT / f).read_text(encoding="utf-8"))["title"] for f in defs]
    corpus = occ.corpus_depot(occ.Contexte(ROOT))
    assert occ.titres_introuvables(titres, corpus, occ.plier(corpus)) == []
