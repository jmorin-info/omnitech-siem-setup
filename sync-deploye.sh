#!/bin/bash
# =============================================================================
# sync-deploye.sh : recopie dans le depot ce qui est DEPLOYE sur le SIEM mais hors depot,
# scanne les secrets (gitleaks + motifs maison) et commite par theme si rien n'est detecte.
# OMNITECH 2026-11-11. A lancer en root depuis le worktree /root/omnitech-siem-merge.
#   ./sync-deploye.sh            -> copie + scan + commits (pas de push)
#   ./sync-deploye.sh --simuler  -> copie + scan, puis annule les changements (git checkout/clean)
# Le push reste manuel : git push origin main (cle de deploiement ou jeton fourni par jmorin).
# Les fichiers en production ne sont JAMAIS modifies : seule la copie du depot l'est.
# =============================================================================
set -u
export LANG=C.UTF-8 GIT_PAGER=cat
cd "$(dirname "$(readlink -f "$0")")" || exit 1
MODE="${1:-}"
D=deploye
CO_AUTH=$'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_01Ab8DjTQ7dmNksGd6Si2iCD'

# 1. scripts /usr/local/sbin : ceux deja suivis ailleurs dans le depot sont mis a jour a leur place
declare -A SUIVIS=( [omni-alert-triage]=triage/omni-alert-triage [omni-alert-digest]=triage/omni-alert-digest
                    [omni-fp]=tools/omni-fp [omni-version-watch]=tools/omni-version-watch )
mkdir -p $D/sbin $D/systemd $D/apt $D/logstash $D/opt/oms-seal-sla
for f in /usr/local/sbin/*; do
  b=$(basename "$f"); [ -f "$f" ] || continue
  case "$b" in __pycache__|*.pyc) continue;; esac
  if [ -n "${SUIVIS[$b]:-}" ]; then cp -p "$f" "${SUIVIS[$b]}"; else cp -p "$f" "$D/sbin/$b"; fi
done
# 2. unites systemd maison + drop-ins
for f in /etc/systemd/system/omni-* /etc/systemd/system/oms-* /etc/systemd/system/siem-*; do
  [ -e "$f" ] || continue
  if [ -d "$f" ]; then mkdir -p "$D/systemd/$(basename "$f")"; cp -p "$f"/*.conf "$D/systemd/$(basename "$f")/" 2>/dev/null
  else cp -p "$f" "$D/systemd/"; fi
done
# 3. APT (series epinglees, liste noire unattended), logstash (sans keystore), SEAL SLA (sans venv)
cp -p /etc/apt/preferences.d/oms-siem-series $D/apt/ 2>/dev/null
cp -p /etc/apt/apt.conf.d/52omni-siem.conf $D/apt/ 2>/dev/null
cp -p /etc/logstash/conf.d/*.conf $D/logstash/ 2>/dev/null
mkdir -p $D/logstash/sql; cp -p /etc/logstash/sql/*.sql $D/logstash/sql/ 2>/dev/null
cp -p /etc/logstash/log4j2.properties /etc/logstash/jvm.options $D/logstash/ 2>/dev/null
for f in /opt/oms-seal-sla/*; do case "$(basename "$f")" in .venv|__pycache__|*.env|*.json) ;; *) [ -f "$f" ] && cp -p "$f" $D/opt/oms-seal-sla/;; esac; done
[ -f /opt/oms-seal-sla/seal_sla_poller.py ] && cp -p /opt/oms-seal-sla/seal_sla_poller.py seal/sla/seal_sla_poller.py
find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null

# 3 bis. NEUTRALISATION dans la copie du depot (jamais en production) :
#   - URL avec identifiants (ex. mongodb://user:${MOT_DE_PASSE_LU_HORS_DEPOT}@hote) -> mot de passe remplace par une variable
#     (en production, l'URI reelle est lue dans /etc/graylog/server/server.conf)
for f in $( { git diff --name-only; git ls-files --others --exclude-standard; } | sort -u ); do
  [ -f "$f" ] || continue
  sed -i -E 's#([a-z][a-z0-9+.-]*://[^/[:space:]:@"'"'"'$]+):[^/[:space:]@"'"'"'$]{4,}@#\1:${MOT_DE_PASSE_LU_HORS_DEPOT}@#g' "$f"
done

# 4. SCAN DE SECRETS sur les changements (nouveaux + modifies)
git add -A --dry-run . >/dev/null
CHANGES=$( { git diff --name-only; git ls-files --others --exclude-standard; } | sort -u )
[ -z "$CHANGES" ] && { echo "Rien a synchroniser."; exit 0; }
echo "$CHANGES" | sed 's/^/  ~ /'
TMP=$(mktemp -d); printf '%s\n' $CHANGES | while read -r f; do [ -f "$f" ] && { mkdir -p "$TMP/$(dirname "$f")"; cp -p "$f" "$TMP/$f"; }; done
FUITE=0
if command -v gitleaks >/dev/null; then
  gitleaks dir "$TMP" --no-banner --redact --exit-code 3 >/tmp/oms-gitleaks.txt 2>&1; rc=$?
  [ $rc = 3 ] && { FUITE=1; echo "GITLEAKS : fuite detectee"; grep -E "File:|RuleID:|Line:" /tmp/oms-gitleaks.txt | head -40; }
fi
MOTIFS='(password|passwd|pwd|secret|token|api[_-]?key|apikey|bearer|client_secret|webhook)["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9/+_.~-]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-ant-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|webhook\.office\.com/webhookb2/[A-Za-z0-9@/-]{20,}|https://[a-z0-9-]+\.logic\.azure\.com[^ "]*sig=[A-Za-z0-9%]{10,}|[a-z][a-z0-9+.-]*://[^/[:space:]:@"$]+:[^/[:space:]@"$]{4,}@'
EXCL='example|changeme|change_me|xxxx|<[A-Z_]+>|\$\{|\$[A-Z_]{3,}|REPLACE|dummy|fake|placeholder|\.\.\.|os\.environ|getenv|read -r'
if grep -rnIE "$MOTIFS" "$TMP" | grep -viE "$EXCL" | sed -E "s#$TMP/##" > /tmp/oms-motifs.txt && [ -s /tmp/oms-motifs.txt ]; then
  FUITE=1; echo "MOTIFS : valeurs suspectes (masquees) :"; sed -E 's/([:=]["'"'"' ]*)([A-Za-z0-9/+_.~-]{3})[A-Za-z0-9/+_.~-]{6,}/\1\2*****/' /tmp/oms-motifs.txt | cut -c1-160 | head -30
fi
rm -rf "$TMP" /tmp/oms-gitleaks.txt /tmp/oms-motifs.txt
if [ "$FUITE" = 1 ] || [ "$MODE" = --simuler ]; then
  echo "Annulation des copies (fuite=$FUITE, mode=$MODE)."; git checkout -q -- . ; git clean -fdq -- $D; exit $FUITE
fi

# 5. commits par theme
commit(){ local msg="$1"; shift; git add -A -- "$@" 2>/dev/null; git diff --cached --quiet && return; git commit -q -m "$msg" -m "$CO_AUTH"; echo "commit $(git rev-parse --short HEAD) : $msg"; }
commit "Scripts deployes : tri des alertes, faux positifs, veille de versions (etat du $(date +%d/%m/%Y))" triage tools/omni-fp tools/omni-version-watch
commit "Scripts deployes /usr/local/sbin (robots omni-*, SOAR, sauvegardes, mises a jour) - etat du $(date +%d/%m/%Y)" $D/sbin
commit "Unites systemd omni-*/oms-* et drop-ins deployes - etat du $(date +%d/%m/%Y)" $D/systemd
commit "Configuration deployee : APT (series epinglees), Logstash SEAL, poller SLA SEAL - etat du $(date +%d/%m/%Y)" $D/apt $D/logstash $D/opt seal/sla
git status --porcelain | head
