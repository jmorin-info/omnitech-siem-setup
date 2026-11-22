"""Règles versionnées incluses par les scripts propriétaires de pipeline (hors ligne).

49-expo-port-class.sh, 49-enrich-lots.sh, 81-fp-allowlist.sh et
tools/omni-v3/v3_build.py réécrivent la source complète de leur pipeline : ils
doivent y inclure eux-mêmes les règles d'objets-graylog/raccordements.txt, lues
dans les fichiers .rule (source unique). Aucun accès réseau : les modes
--source-pipeline n'appellent pas l'API, l'API de ensure_regles_versionnees est
simulée par le faux curl de test_graylog_objets_manuels.py.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "lib-regles-versionnees.sh"
INVENTAIRE = ROOT / "objets-graylog/raccordements.txt"
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("bash") or not shutil.which("jq"),
                                reason="Bash et jq requis")

# Sources en service au 22/11/2026 (GET /system/pipelines/pipeline), ordre compris.
PRODUCTION = {
    "OMNI - Exposition reseau": """pipeline "OMNI - Exposition reseau"
stage 14 match either
rule "omni-forti-14-privflags"
stage 15 match either
rule "omni-forti-15-port-class"
rule "omni-forti-15-dir-interne"
rule "omni-forti-15-dir-sortant"
rule "omni-forti-15-dir-entrant"
rule "omni-forti-15-dir-transit"
stage 16 match either
rule "omni-forti-16-expo-internet"
stage 17 match either
rule "omni-fp-26-expo-ztna-vaultwarden"
end""",
    "OMNI - Allowlist FP": "\n".join(
        ['pipeline "OMNI - Allowlist FP"', "stage 25 match either"]
        + [f'rule "omni-fp-26-{n}"' for n in ("service-veeam-vss", "lsass-ninjaone-metering", "adexplorer-dev-seal")]
        + [f'rule "omni-fp-25-{n}"' for n in ("service-install", "scheduled-task", "autorun", "sysmon-injection",
                                               "adminshare-loopback", "ps-claude", "proctamper")]
        + [f'rule "omni-fp-26-{n}"' for n in ("adminshare-veeam-dc", "explicit-cred-admin", "injection-outils",
                                               "lsass-defender", "ntds-surebackup-mh", "outlook-liens", "schtask-oms",
                                               "wbadmin-retention-dc", "webshell-proactive", "zerologon-mdp-machine",
                                               "webshell-dev-central6")]
        + ["end"]),
    "OMNI v3 - Detections et correlation": "\n".join(
        ['pipeline "OMNI v3 - Detections et correlation"', "stage 40 match either", 'rule "omni-v3-laps-lecture"']
        + [f'rule "omni-v3-{n}"' for n in ("gmsa-lecture-utilisateur", "kerberos-chiffrement-faible", "logon-admin",
                                            "eset-menace", "eset-non-remediee", "fg-admin-local", "fg-admin-ip-publique",
                                            "fg-admin-echec", "veeam-restauration-inattendue", "veeam-suppression",
                                            "cert-template", "veeam-resultat", "veeam-job")]
        + ["stage 41 match either", 'rule "omni-v3-laps-lecture-it"', 'rule "omni-v3-actif-critique"', "end"]),
}


def inventaire():
    lignes = [l for l in INVENTAIRE.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return [tuple(l.split("|")) for l in lignes]


def env_hors_ligne():
    """Environnement sans aucune variable Graylog : prouve que --source-pipeline n'en a pas besoin."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GRAYLOG", "OMNI"))}
    env["PATH"] = os.environ["PATH"]
    return env


def source_script(script):
    r = subprocess.run(["bash", str(ROOT / script), "--source-pipeline"], capture_output=True, text=True,
                       timeout=60, env=env_hors_ligne(), cwd="/")
    assert r.returncode == 0, r.stderr
    return r.stdout.rstrip("\n")


def source_v3():
    env = {**env_hors_ligne(), "OMNI_REPO": str(ROOT), "OMNI_V3_VARS": "/nonexistent"}
    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools/omni-v3/v3_build.py"), "--source-pipeline"],
                       capture_output=True, text=True, timeout=60, env=env, cwd="/")
    assert r.returncode == 0, r.stderr
    return r.stdout.rstrip("\n")


def etape_de(source, titre):
    etape = None
    for l in source.splitlines():
        if m := re.match(r"\s*stage\s+(-?\d+)", l):
            etape = m.group(1)
        if l.strip() == f'rule "{titre}"':
            return etape
    return None


def bash_inclure(pipeline, base, inventaire_f=None):
    env = dict(os.environ)
    if inventaire_f:
        env["RACCORDEMENTS_FICHIER"] = str(inventaire_f)
    r = subprocess.run(["bash", "-c", 'source "$1" && inclure_regles_versionnees "$2"', "_", str(LIB), pipeline],
                       input=base, capture_output=True, text=True, timeout=30, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.rstrip("\n")


def module_v3(depot):
    """v3_build importé en mode --source-pipeline (aucune lecture de 00-vars.env, aucun appel API)."""
    ancien_argv, ancien_env = sys.argv, os.environ.get("OMNI_REPO")
    sys.argv, os.environ["OMNI_REPO"] = ["v3_build.py", "--source-pipeline"], str(depot)
    try:
        spec = importlib.util.spec_from_file_location("v3_build_test", ROOT / "tools/omni-v3/v3_build.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.argv = ancien_argv
    return mod, ancien_env


# ----------------------------------------------------------------------------- inventaire
def test_inventaire_coherent():
    r = subprocess.run(["bash", "-c", 'source "$1" && verifier_raccordements', "_", str(LIB)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    entrees = inventaire()
    assert len(entrees) == 17
    for titre, fichier, desc, pipe, etape, pos in entrees:
        assert (ROOT / fichier).read_text(encoding="utf-8").startswith(f'rule "{titre}"')
        assert pipe in PRODUCTION and pos in ("debut", "fin") and etape.isdigit() and desc


def test_inventaire_defectueux_detecte(tmp_path):
    f = tmp_path / "raccordements.txt"
    f.write_text("omni-x|objets-graylog/regles/absente.rule|d|OMNI - Allowlist FP|25|milieu\n"
                 "omni-v3-laps-lecture|objets-graylog/regles/omni-v3-laps-lecture-it.rule|d|P|x|fin\n", encoding="utf-8")
    r = subprocess.run(["bash", "-c", 'source "$1" && verifier_raccordements', "_", str(LIB)],
                       capture_output=True, text=True, timeout=30, env={**os.environ, "RACCORDEMENTS_FICHIER": str(f)})
    assert r.returncode == 1
    assert "position 'milieu'" in r.stderr and "source absente" in r.stderr
    assert "etape 'x' non numerique" in r.stderr and "ne declare pas" in r.stderr


# ------------------------------------------------------------- sources générées par les scripts
@pytest.mark.parametrize("script,pipeline", [
    ("49-expo-port-class.sh", "OMNI - Exposition reseau"),
    ("49-enrich-lots.sh", "OMNI - Exposition reseau"),
    ("81-fp-allowlist.sh", "OMNI - Allowlist FP"),
])
def test_script_inclut_les_regles_versionnees(script, pipeline):
    src = source_script(script)
    assert src == PRODUCTION[pipeline], "source différente de la production du 22/11/2026"
    for titre, _f, _d, pipe, etape, _pos in inventaire():
        if pipe == pipeline:
            assert etape_de(src, titre) == etape, titre
    regles = [l for l in src.splitlines() if l.startswith("rule ")]
    assert len(regles) == len(set(regles))


def test_les_deux_scripts_49_ecrivent_la_meme_source():
    assert source_script("49-expo-port-class.sh") == source_script("49-enrich-lots.sh")


def test_v3_build_inclut_les_regles_versionnees():
    src = source_v3()
    assert src == PRODUCTION["OMNI v3 - Detections et correlation"]
    assert etape_de(src, "omni-v3-laps-lecture") == "40" and etape_de(src, "omni-v3-laps-lecture-it") == "41"


def test_source_pipeline_sans_effet_de_bord(tmp_path):
    """--source-pipeline s'arrête avant 00-vars.env, la vérification root et toute écriture."""
    for script in ("49-expo-port-class.sh", "49-enrich-lots.sh", "81-fp-allowlist.sh"):
        texte = (ROOT / script).read_text(encoding="utf-8")
        option = texte.index('"--source-pipeline" ]]')
        assert option < texte.index("source ./00-vars.env") < texte.index("require_api")
        assert option < texte.index("EUID")
        assert "ensure_regles_versionnees" in texte and "inclure_regles_versionnees" in texte
    avant = sorted(p.name for p in (ROOT / "lookups").iterdir())
    source_script("49-expo-port-class.sh")
    assert sorted(p.name for p in (ROOT / "lookups").iterdir()) == avant


def test_aucun_contenu_de_regle_versionnee_recopie():
    """Source unique : les scripts ne recopient pas le corps des règles .rule."""
    for titre, *_ in inventaire():
        for script in ("49-expo-port-class.sh", "49-enrich-lots.sh", "81-fp-allowlist.sh",
                       "26-graylog-objets-manuels.sh", "tools/omni-v3/v3_build.py"):
            assert f'rule "{titre}"\nwhen' not in (ROOT / script).read_text(encoding="utf-8"), (script, titre)


# --------------------------------------------------------- algorithme : bash et Python identiques
CAS = {
    "etapes nouvelles avant, entre et après": (
        'pipeline "P"\nstage 10 match either\nrule "a"\nstage 20 match all\nrule "b"\nend',
        ["n5|5|fin", "n15|15|debut", "n30|30|fin", "d10|10|debut", "f20|20|fin", "d20|20|debut"]),
    "regle deja presente non dupliquee": (
        'pipeline "P"\nstage 10 match either\nrule "x"\nrule "a"\nend', ["x|10|debut", "y|10|fin"]),
    "etape negative et indentation conservee": (
        'pipeline "P"\n  stage 0 match either\n    rule "a"\nend', ["neg|-1|fin", "z|0|fin"]),
    "aucune regle pour ce pipeline": ('pipeline "P"\nstage 1 match either\nrule "a"\nend', []),
}


@pytest.mark.parametrize("nom", sorted(CAS))
def test_bash_et_python_identiques_et_idempotents(nom, tmp_path):
    base, entrees = CAS[nom]
    (tmp_path / "objets-graylog").mkdir()
    inv = tmp_path / "objets-graylog/raccordements.txt"
    inv.write_text("# test\n" + "".join(f"{t}|f.rule|d|P|{e}|{p}\n" for t, e, p in (x.split("|") for x in entrees))
                   + "autre|f.rule|d|Q|10|debut\n", encoding="utf-8")
    sortie_bash = bash_inclure("P", base, inv)
    mod, ancien = module_v3(tmp_path)
    try:
        sortie_py = mod.inclure_regles_versionnees(base, "P")
    finally:
        if ancien is None:
            os.environ.pop("OMNI_REPO", None)
        else:
            os.environ["OMNI_REPO"] = ancien
    assert sortie_bash == sortie_py
    assert bash_inclure("P", sortie_bash, inv) == sortie_bash, "idempotence"
    for l in base.splitlines():
        assert l in sortie_bash.splitlines(), "aucune ligne retirée"
    assert 'rule "autre"' not in sortie_bash
    for t, e, _p in (x.split("|") for x in entrees):
        assert etape_de(sortie_bash, t) == e
    etapes = [int(m.group(1)) for l in sortie_bash.splitlines() if (m := re.match(r"\s*stage\s+(-?\d+)", l))]
    assert etapes == sorted(etapes)
    if nom.startswith("etapes nouvelles"):
        assert sortie_bash.splitlines() == ['pipeline "P"', "stage 5 match either", 'rule "n5"',
                                            "stage 10 match either", 'rule "d10"', 'rule "a"',
                                            "stage 15 match either", 'rule "n15"',
                                            "stage 20 match all", 'rule "d20"', 'rule "b"', 'rule "f20"',
                                            "stage 30 match either", 'rule "n30"', "end"]


# --------------------------------------------- ensure_regles_versionnees contre une API simulée
@pytest.fixture
def faux_graylog(tmp_path):
    spec = importlib.util.spec_from_file_location("tgom", ROOT / "tests/test_graylog_objets_manuels.py")
    tgom = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tgom)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(tgom.FAUX_CURL, encoding="utf-8")
    (bin_dir / "curl").chmod(0o755)
    vars_f = tmp_path / "vars.env"
    vars_f.write_text("GRAYLOG_API_URL=http://127.0.0.1:9000/api\nGRAYLOG_ADMIN_PASS=dummy-test-only\n", encoding="utf-8")
    etat_f = tmp_path / "etat.json"

    def lancer(etat, pipeline):
        etat_f.write_text(json.dumps(etat), encoding="utf-8")
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAUX_GRAYLOG_ETAT": str(etat_f)}
        r = subprocess.run(["bash", "-c", 'source "$1"; source "$2"; source "$3"; ensure_regles_versionnees "$4"',
                            "_", str(vars_f), str(ROOT / "lib-graylog.sh"), str(LIB), pipeline],
                           capture_output=True, text=True, timeout=60, env=env)
        return r, json.loads(etat_f.read_text(encoding="utf-8"))
    return lancer


def test_ensure_regles_versionnees_cree_signale_ne_modifie_jamais(faux_graylog):
    entrees = [e for e in inventaire() if e[3] == "OMNI - Allowlist FP"]
    present = entrees[0]
    modifiee = entrees[1]
    etat = {"regles": [
        {"id": "r1", "title": present[0], "description": "x",
         "source": (ROOT / present[1]).read_text(encoding="utf-8").rstrip("\n")},
        {"id": "r2", "title": modifiee[0], "description": "x", "source": f'rule "{modifiee[0]}"\nwhen true then end'},
    ], "pipelines": [], "connexions": [], "flux": [], "notifications": [], "definitions": []}
    r, apres = faux_graylog(etat, "OMNI - Allowlist FP")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"regle versionnee '{present[0]}' inchangee" in r.stdout
    assert f"regle versionnee '{modifiee[0]}' : source en service differente" in r.stdout
    assert {tuple(e) for e in apres["ecritures"]} == {("POST", "/system/pipelines/rule")}
    assert len(apres["ecritures"]) == len(entrees) - 2, "seules les absentes sont créées"
    crees = {x["title"]: x for x in apres["regles"]}
    assert crees[modifiee[0]]["source"].endswith("when true then end"), "jamais modifiée"
    dernier = entrees[-1]
    assert crees[dernier[0]]["source"] == (ROOT / dernier[1]).read_text(encoding="utf-8")
    assert crees[dernier[0]]["description"] == dernier[2]
    assert "dummy-test-only" not in r.stdout + r.stderr
    # second passage : plus aucune écriture
    r2, apres2 = faux_graylog({k: v for k, v in apres.items() if k not in ("ecritures", "appels")}, "OMNI - Allowlist FP")
    assert r2.returncode == 0 and "ecritures" not in apres2


# ------------------------------------------------------------------- comparaison à un export
def test_verif_pipelines_versionnees_hors_ligne(tmp_path):
    export = tmp_path / "pipelines.json"
    export.write_text(json.dumps([{"id": str(n), "title": t, "source": s + "\n"}
                                  for n, (t, s) in enumerate(PRODUCTION.items())]), encoding="utf-8")
    outil = ROOT / "tools/verif-pipelines-versionnees.sh"
    env = {**env_hors_ligne(), "PYTHON": sys.executable}
    r = subprocess.run(["bash", str(outil), "--hors-ligne", str(export)], capture_output=True, text=True,
                       timeout=120, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.count("[IDENTIQUE]") == 4
    modifie = {t: s.replace('rule "omni-fp-26-outlook-liens"\n', "") for t, s in PRODUCTION.items()}
    export.write_text(json.dumps([{"id": t, "title": t, "source": s} for t, s in modifie.items()]), encoding="utf-8")
    r = subprocess.run(["bash", str(outil), "--hors-ligne", str(export)], capture_output=True, text=True,
                       timeout=120, env=env)
    assert r.returncode == 1
    assert '+rule "omni-fp-26-outlook-liens"' in r.stdout and "[ECART] 81-fp-allowlist.sh" in r.stdout


# ------------------------------------------------------------------------- défaut corrigé
def test_49_enrich_lots_explicit_cred_heredoc_cite():
    texte = (ROOT / "49-enrich-lots.sh").read_text(encoding="utf-8")
    assert "ensure_rule \"omni-extra-10-explicit-cred\" <<'EOF'\n" in texte
    # Rendu réel du heredoc par bash (ensure_rule remplacé par cat) : $message et \\ intacts.
    bloc = texte.split('ensure_rule "omni-extra-10-explicit-cred" <<', 1)[1].split("\nEOF\n", 1)[0]
    r = subprocess.run(["bash", "-c", "message=PIEGE; ensure_rule() { cat; }; eval \"$1\"",
                        "_", 'ensure_rule "omni-extra-10-explicit-cred" <<' + bloc + "\nEOF\n"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "to_string($message.event_source)" in r.stdout and "PIEGE" not in r.stdout
    assert '"\\\\lsass.exe"' in r.stdout


@pytest.mark.parametrize("script", ["49-expo-port-class.sh", "49-enrich-lots.sh", "81-fp-allowlist.sh",
                                    "26-graylog-objets-manuels.sh", "lib-regles-versionnees.sh",
                                    "tools/verif-pipelines-versionnees.sh"])
def test_syntaxe_et_shellcheck(script):
    subprocess.run(["bash", "-n", str(ROOT / script)], check=True)
    sc = shutil.which("shellcheck")
    if sc:
        r = subprocess.run([sc, "-S", "warning", "-x", script], cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout
