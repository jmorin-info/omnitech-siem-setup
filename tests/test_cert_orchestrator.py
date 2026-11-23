"""Source Cert Orchestrator : renommage cert_orchestrator et alignement de production, hors ligne.

tools/maj-cert-orchestrator-prod.sh est copié avec 99-cert-orchestrator.sh dans un
répertoire temporaire, avec une fausse lib-graylog.sh (API simulée, appels journalisés)
et un faux curl (OpenSearch simulé). Aucun accès à Graylog ni à OpenSearch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
TB = "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"
DEL = "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"
RULES = ["omni-cert-00-tag", "omni-cert-05-sev-eleve", "omni-cert-05-sev-moyen", "omni-cert-05-sev-info",
         "omni-cert-10-error"]
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("jq"), reason="Bash/jq requis")

FAKE_LIB = r'''
api_get() {
  echo "GET $1" >> "$CALLS_LOG"
  case "$1" in
    /system/pipelines/rule) cat "$FIX/rules.json" ;;
    /system/pipelines/rule/*) jq -c --arg id "${1##*/}" '.[]|select(.id==$id)' "$FIX/rules.json" ;;
    /system/indices/index_sets\?*) jq -c '{index_sets:[.]}' "$FIX/set.json" ;;
    /system/indices/index_sets/*) cat "$FIX/set.json" ;;
    *) echo '{}' ;;
  esac
}
api_put() {
  local body; body="$(cat)"
  echo "PUT $1 $body" >> "$CALLS_LOG"
  case "$1" in
    /system/pipelines/rule/*)
      jq --argjson b "$body" 'map(if .id == $b.id then $b else . end)' "$FIX/rules.json" > "$FIX/r.tmp" && mv "$FIX/r.tmp" "$FIX/rules.json"
      echo "$body" ;;
    /system/indices/index_sets/*) echo "$body" > "$FIX/set.json"; echo "$body" ;;
  esac
}
api_post() { echo "POST $1" >> "$CALLS_LOG"; cat >/dev/null; echo '{}'; }
api_del()  { echo "DELETE $1" >> "$CALLS_LOG"; echo '{}'; }
require_api() { :; }
die()  { echo "ERREUR: $*" >&2; exit 1; }
ok()   { echo "    [+] $*"; }
skip() { echo "    [=] $*"; }
warn() { echo "    [!] $*"; }
'''

FAKE_CURL = r'''#!/usr/bin/env bash
echo "curl $*" >> "$CALLS_LOG"
for a in "$@"; do [[ "$a" == -X* ]] && exit 9; done
[[ -f "$FIX/os-down" ]] && exit 7
n=$(cat "$FIX/nb-index")
for ((i=0; i<n; i++)); do echo "omni-cert_$i 0"; done
'''


def rule_source(title, source_name):
    text = (ROOT / "99-cert-orchestrator.sh").read_text()
    body = text.split(f"ensure_rule \"{title}\" <<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0]
    return body.replace('"cert_orchestrator"', f'"{source_name}"')


@pytest.fixture
def prod(tmp_path):
    (tmp_path / "tools").mkdir()
    shutil.copy(ROOT / "tools" / "maj-cert-orchestrator-prod.sh", tmp_path / "tools")
    shutil.copy(ROOT / "99-cert-orchestrator.sh", tmp_path)
    (tmp_path / "lib-graylog.sh").write_text(FAKE_LIB)
    (tmp_path / "00-vars.env").write_text("SIEM_HOSTNAME=fixture\n")
    fix = tmp_path / "fix"
    fix.mkdir()
    rules = [{"id": f"id{i}", "title": t, "description": "provisionne par 12-graylog-pipelines.sh",
              "source": rule_source(t, "cert_parc")} for i, t in enumerate(RULES)]
    rules.append({"id": "pki", "title": "omni-winother-10-cert-parc", "description": "12",
                  "source": 'rule "omni-winother-10-cert-parc"\nwhen true\nthen\n  set_field("event_source", "cert_parc");\nend'})
    (fix / "rules.json").write_text(json.dumps(rules))
    (fix / "set.json").write_text(json.dumps({
        "id": "set-cert", "title": "OMNI - Cert Orchestrator", "index_prefix": "omni-cert",
        "use_legacy_rotation": True, "data_tiering": None, "rotation_strategy_class": TB,
        "rotation_strategy": {"type": TB + "Config", "rotation_period": "P1D", "max_rotation_period": None},
        "retention_strategy_class": DEL, "retention_strategy": {"type": DEL + "Config", "max_number_of_indices": 90}}))
    (fix / "nb-index").write_text("1")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "curl").write_text(FAKE_CURL)
    (bindir / "curl").chmod(0o755)
    log = tmp_path / "calls.log"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "FIX": str(fix), "CALLS_LOG": str(log),
           "OMNI_TEST_MODE": "1"}

    def run(*args):
        return subprocess.run(["bash", str(tmp_path / "tools" / "maj-cert-orchestrator-prod.sh"), *args],
                              env=env, capture_output=True, text=True, timeout=60)

    def calls():
        return log.read_text().splitlines() if log.exists() else []

    return {"run": run, "calls": calls, "fix": fix}


def test_repository_uses_cert_orchestrator_and_keeps_pki_source():
    script = (ROOT / "99-cert-orchestrator.sh").read_text()
    assert 'set_field("event_source", "cert_orchestrator");' in script
    assert '== "cert_parc"' not in script and 'set_field("event_source", "cert_parc")' not in script
    assert "ensure_index_set 'omni-cert' 'OMNI - Cert Orchestrator' P1M 3" in script
    assert 'set_field("event_source", "cert_parc");' in (ROOT / "12-graylog-pipelines.sh").read_text()
    watchdog = re.search(r"^WATCHDOG_SOURCES=(.*)$", (ROOT / "74-source-watchdog.sh").read_text(), re.M).group(1)
    sources = dict(item.split(":") for item in watchdog.split(","))
    assert sources["cert_parc"] == "2880" and sources["cert_orchestrator"] == "2880"
    retention = (ROOT / "83-retention-consolidee.sh").read_text()
    assert "[omni-cert]=90" in retention and "[omni-cert]=P1M" in retention


def test_plan_is_read_only_and_lists_every_gap(prod):
    result = prod["run"]()
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stdout.count("à mettre à jour") == 5
    assert "P1D x 90 -> P1M x 3" in result.stdout
    assert not [c for c in prod["calls"]() if not c.startswith(("GET ", "curl "))]


def test_apply_updates_rules_and_index_set_idempotently(prod):
    result = prod["run"]("--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    rules = {r["title"]: r for r in json.loads((prod["fix"] / "rules.json").read_text())}
    for title in RULES:
        assert rules[title]["source"] == rule_source(title, "cert_orchestrator")
        assert rules[title]["description"] == "provisionne par 12-graylog-pipelines.sh"
    assert '"cert_parc"' in rules["omni-winother-10-cert-parc"]["source"]
    current = json.loads((prod["fix"] / "set.json").read_text())
    assert current["rotation_strategy"]["rotation_period"] == "P1M"
    assert current["retention_strategy"]["max_number_of_indices"] == 3
    assert current["rotation_strategy_class"] == TB and current["index_prefix"] == "omni-cert"
    assert not [c for c in prod["calls"]() if c.startswith(("POST", "DELETE"))]
    puts = len([c for c in prod["calls"]() if c.startswith("PUT")])
    assert puts == 6
    again = prod["run"]("--apply")
    assert again.returncode == 0, again.stdout
    assert len([c for c in prod["calls"]() if c.startswith("PUT")]) == puts


@pytest.mark.parametrize("condition", ["too-many-indices", "os-down"])
def test_index_set_is_never_changed_when_indices_could_be_deleted(prod, condition):
    if condition == "too-many-indices":
        (prod["fix"] / "nb-index").write_text("4")
    else:
        (prod["fix"] / "os-down").write_text("")
    result = prod["run"]("--apply")
    assert result.returncode == 2
    assert not [c for c in prod["calls"]() if c.startswith("PUT /system/indices")]
    assert json.loads((prod["fix"] / "set.json").read_text())["retention_strategy"]["max_number_of_indices"] == 90
