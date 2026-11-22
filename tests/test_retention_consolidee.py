"""83-retention-consolidee.sh : calcul du plan et garde-fous, hors ligne.

Le script est copié dans un répertoire temporaire avec un faux 00-vars.env, une
fausse lib-graylog.sh (API simulée, chaque appel journalisé) et un faux curl
(OpenSearch simulé). Aucun accès à Graylog, à OpenSearch ni au système réel.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "83-retention-consolidee.sh"
TB = "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"
SO = "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategy"
DEL = "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"

pytestmark = pytest.mark.skipif(not shutil.which("jq"), reason="jq requis")

FAUSSE_LIB = r'''
api_get() {
  echo "GET $1" >> "$CALLS_LOG"
  case "$1" in
    /system/indices/index_sets\?*) cat "$FIX_DIR/sets.json" ;;
    /system/indices/index_sets/*)
      [[ ! -f "$FIX_DIR/get-fails" ]] || return 22
      jq -c --arg id "${1##*/}" '.index_sets[]|select(.id==$id)' "$FIX_DIR/sets.json" \
        | if [[ -f "$FIX_DIR/concurrent-change" ]]; then jq '.retention_strategy.max_number_of_indices += 1'; else cat; fi
      ;;
    /system/inputstates) echo '{"states":[]}' ;;
    *) echo '{}' ;;
  esac
}
api_put() {
  echo "PUT $1 $(jq -c . )" >> "$CALLS_LOG"
  [[ ! -f "$FIX_DIR/put-fails" ]] || return 22
  if [[ -f "$FIX_DIR/put-invalid" ]]; then
    echo '{"error":"private-response-body"}'
  else
    jq -cn --arg id "${1##*/}" '{id:$id}'
  fi
}
api_post() { echo "POST $1" >> "$CALLS_LOG"; cat >/dev/null; echo '{}'; }
api_del()  { echo "DELETE $1" >> "$CALLS_LOG"; echo '{}'; }
require_api() { :; }
get_stream_id() { echo ""; }
die()  { echo "ERREUR: $*" >&2; exit 1; }
ok()   { echo "    [+] $*"; }
skip() { echo "    [=] $*"; }
warn() { echo "    [!] $*"; }
'''

FAUX_CURL = r'''#!/usr/bin/env bash
echo "curl $*" >> "$CALLS_LOG"
for a in "$@"; do [[ "$a" == -X* || "$a" == --request* ]] && { echo "curl-ecriture $*" >> "$CALLS_LOG"; exit 9; }; done
[[ -f "$FIX_DIR/os-down" ]] && exit 7
url="${@: -1}"
p="${url#*/_cat/indices/}"; p="${p%%_\**}"
n=0; [[ -f "$FIX_DIR/counts/$p" ]] && n=$(cat "$FIX_DIR/counts/$p")
for ((i=0; i<n; i++)); do echo "${p}_$i"; done
'''


def index_set(prefix, keep=None, period=None, so_max=None):
    s = {"id": f"id-{prefix}", "title": prefix, "index_prefix": prefix, "shards": 1}
    if so_max:
        s.update(use_legacy_rotation=False, rotation_strategy_class=SO,
                 rotation_strategy={"type": SO + "Config", "index_lifetime_min": "P30D", "index_lifetime_max": so_max},
                 retention_strategy_class=DEL, retention_strategy={"type": DEL + "Config", "max_number_of_indices": 20},
                 data_tiering={"type": "hot_only", "index_lifetime_min": "P30D", "index_lifetime_max": so_max})
    else:
        s.update(use_legacy_rotation=True, rotation_strategy_class=TB,
                 rotation_strategy={"type": TB + "Config", "rotation_period": period,
                                    "max_rotation_period": None, "rotate_empty_index_set": False},
                 retention_strategy_class=DEL, retention_strategy={"type": DEL + "Config", "max_number_of_indices": keep},
                 data_tiering=None)
    return s


# prefixe -> (index set, nombre d'index existants)
SCENARIO = {
    "omni-winsec": (index_set("omni-winsec", 180, "P1D"), 80),          # conforme
    "omni-m365": (index_set("omni-m365", 4, "P1M"), 1),                 # 120 j -> 390 j : appliquer
    "omni-sysmon": (index_set("omni-sysmon", 60, "P1D"), 79),           # 60 j -> 90 j : appliquer
    "omni-aruba": (index_set("omni-aruba", 4, "P1M"), 1),               # 120 j demandés 90 : plus court
    "omni-eset": (index_set("omni-eset", 100, "P1D"), 100),             # P1D -> P1M : 6 conservés < 100 index
    "omni-fortigate": (index_set("omni-fortigate", so_max="P180D"), 200),  # 200 index > 180 conservés
}


@pytest.fixture
def banc(tmp_path):
    work = tmp_path / "depot"
    fix = tmp_path / "fix"
    (fix / "counts").mkdir(parents=True)
    work.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(SCRIPT, work / SCRIPT.name)
    (work / "00-vars.env").write_text("# factice\n", encoding="utf-8")
    (work / "lib-graylog.sh").write_text(FAUSSE_LIB, encoding="utf-8")
    (bin_dir / "curl").write_text(FAUX_CURL, encoding="utf-8")
    (bin_dir / "curl").chmod(0o755)
    (fix / "sets.json").write_text(json.dumps({"index_sets": [s for s, _ in SCENARIO.values()]}), encoding="utf-8")
    for prefix, (_, n) in SCENARIO.items():
        (fix / "counts" / prefix).write_text(str(n), encoding="utf-8")
    calls = tmp_path / "calls.log"
    calls.write_text("", encoding="utf-8")
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "FIX_DIR": str(fix), "CALLS_LOG": str(calls),
           "OMNI_TEST_MODE": "1", "OS_URL": "http://opensearch.invalid:9200", "HOME": str(tmp_path)}

    def lancer(*args, extra=None):
        e = dict(env, **(extra or {}))
        r = subprocess.run(["bash", str(work / SCRIPT.name), *args], env=e, capture_output=True,
                           text=True, timeout=60, cwd=tmp_path)
        return r, calls.read_text(encoding="utf-8").splitlines()

    lancer.fix = fix
    return lancer


def bash_fn(expr):
    r = subprocess.run(["bash", "-c", f'source "{SCRIPT}"; {expr}'], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_period_days():
    assert bash_fn("period_days P1D") == "1"
    assert bash_fn("period_days P1W") == "7"
    assert bash_fn("period_days P1M") == "30"
    assert bash_fn("period_days P2M") == "60"
    assert bash_fn("period_days P1Y") == "365"
    assert bash_fn("period_days PT6H || echo non") == "non"


@pytest.mark.parametrize("args,decision,keep", [
    ("180 P1D P1D 180 180 80", "CONFORME", "180"),
    ("365 P1M P1M 4 120 1", "APPLIQUER", "13"),        # arrondi au supérieur : 390 j >= 365 j
    ("90 P1D P1D 60 60 79", "APPLIQUER", "90"),
    ("90 P1M P1M 4 120 1", "PLUS_COURT", "3"),
    ("180 P1M P1D 100 100 100", "REFUS", "6"),         # changement de rotation : 6 < 100 index existants
    ("180 P1D '' '' 180 200", "REFUS", "180"),          # stratégie différente : pas de migration
    ("180 P1M P1D 180 180 6", "REFUS", "6"),          # future rotation ne doit pas purger les index quotidiens
    ("180 P1D P1D 90 90 '?'", "REFUS", "180"),          # OpenSearch illisible
    ("180 P1D '' '' '?' 3", "REFUS", "180"),            # rétention actuelle inconnue
    ("180 PT1H P1D 90 90 3", "REFUS", "-"),
])
def test_decide(args, decision, keep):
    dec, k, _jours, _motif = bash_fn(f"decide {args}").split("|", 3)
    assert (dec, k) == (decision, keep)


def test_decide_ne_reduit_jamais():
    # quelle que soit la durée demandée inférieure à l'existant, aucune décision d'écriture
    for cible in (1, 30, 60, 89):   # 91 à 120 j donnent 4 index : conforme
        dec = bash_fn(f"decide {cible} P1M P1M 4 120 1").split("|")[0]
        assert dec == "PLUS_COURT"


def test_plan_par_defaut_n_ecrit_rien(banc):
    r, calls = banc()
    assert r.returncode == 3, r.stdout + r.stderr
    assert not [c for c in calls if c.startswith(("PUT", "POST", "DELETE", "curl-ecriture"))]
    assert "PLAN (lecture seule)" in r.stdout
    assert "ATTENTION omni-aruba" in r.stdout and "plus courte que l'existant" in r.stdout
    assert "REFUS omni-eset" in r.stdout and "REFUS omni-fortigate" in r.stdout
    assert "--apply" in r.stdout


def test_variable_apply_ignoree(banc):
    r, calls = banc(extra={"APPLY": "1"})
    assert not [c for c in calls if c.startswith(("PUT", "POST", "DELETE"))]
    assert "n'est plus reconnue" in r.stdout


def test_apply_ne_touche_que_les_changements_surs(banc):
    r, calls = banc("--apply")
    assert r.returncode == 3, r.stdout + r.stderr
    assert not [c for c in calls if c.startswith(("POST", "DELETE", "curl-ecriture"))]
    puts = [c for c in calls if c.startswith("PUT")]
    cibles = sorted(c.split()[1] for c in puts)
    assert cibles == ["/system/indices/index_sets/id-omni-m365", "/system/indices/index_sets/id-omni-sysmon"]
    for c in puts:
        corps = json.loads(c.split(" ", 2)[2])
        assert corps["use_legacy_rotation"] is True and corps["data_tiering"] is None
        assert corps["rotation_strategy_class"] == TB and corps["retention_strategy_class"] == DEL
    m365 = json.loads(next(c for c in puts if "m365" in c).split(" ", 2)[2])
    assert m365["rotation_strategy"]["rotation_period"] == "P1M"
    assert m365["retention_strategy"]["max_number_of_indices"] == 13
    sysmon = json.loads(next(c for c in puts if "sysmon" in c).split(" ", 2)[2])
    assert sysmon["retention_strategy"]["max_number_of_indices"] == 90


def test_daily_to_monthly_with_few_indices_is_refused_before_first_new_rotation(banc):
    # Le garde précédent acceptait ce cas car 6 conservés == 6 présents.
    # Au prochain index mensuel, Graylog supprimait un index quotidien récent.
    entry = index_set("omni-eset", 180, "P1D")
    (banc.fix / "sets.json").write_text(json.dumps({"index_sets": [entry]}))
    (banc.fix / "counts/omni-eset").write_text("6")
    result, calls = banc("--apply")
    assert result.returncode == 3
    assert "changement de periode ou de strategie" in result.stdout
    assert not any(c.startswith("PUT") for c in calls)


@pytest.mark.parametrize("field,value", [("use_legacy_rotation", False), ("data_tiering", {"type": "hot_only"})])
def test_strategy_flags_are_not_migrated(banc, field, value):
    entry = index_set("omni-sysmon", 60, "P1D")
    entry[field] = value
    (banc.fix / "sets.json").write_text(json.dumps({"index_sets": [entry]}))
    result, calls = banc("--apply")
    assert result.returncode == 3
    assert not any(c.startswith("PUT") for c in calls)


def test_increase_preserves_every_setting_except_retention_count(banc):
    entry = index_set("omni-sysmon", 60, "P1D")
    entry["rotation_strategy"].update(rotate_empty_index_set=True, max_rotation_period="P2D")
    entry["description"] = "local setting"
    (banc.fix / "sets.json").write_text(json.dumps({"index_sets": [entry]}))
    result, calls = banc("--apply")
    assert result.returncode == 0
    body = json.loads(next(c for c in calls if c.startswith("PUT")).split(" ", 2)[2])
    entry["retention_strategy"]["max_number_of_indices"] = 90
    assert body == entry


@pytest.mark.parametrize("failure", ["put-fails", "put-invalid", "get-fails", "concurrent-change"])
def test_failed_or_stale_update_returns_error_and_stops(banc, failure):
    entries = [index_set("omni-m365", 4, "P1M"), index_set("omni-sysmon", 60, "P1D")]
    (banc.fix / "sets.json").write_text(json.dumps({"index_sets": entries}))
    (banc.fix / failure).write_text("1")
    result, calls = banc("--apply")
    assert result.returncode == 1
    assert "arret" in result.stdout
    puts = [c for c in calls if c.startswith("PUT")]
    assert len(puts) == (1 if failure.startswith("put-") else 0)
    assert "private-response-body" not in result.stdout + result.stderr


def test_opensearch_injoignable_aucune_ecriture(banc):
    (banc.fix / "os-down").write_text("", encoding="utf-8")
    r, calls = banc("--apply")
    assert r.returncode == 3
    assert not [c for c in calls if c.startswith(("PUT", "POST", "DELETE"))]
    assert "nombre d'index existants inconnu" in r.stdout


def test_option_inconnue_refusee(banc):
    r, calls = banc("--force")
    assert r.returncode == 1 and not calls


def test_aucun_appel_de_suppression_dans_le_script():
    texte = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(l for l in texte.splitlines() if not l.lstrip().startswith("#"))
    assert "api_del" not in code and "api_post" not in code
    assert not re.search(r"-X\s*(DELETE|POST|PUT)|--request|_delete_by_query|_reindex|XDELETE", code)
    assert "SizeOptimizing" not in code and "hot_only\"" not in code
