#!/usr/bin/env bash
# =============================================================================
# ci-lint.sh : contrôles statiques de la CI, rejouables sur un poste.
#   ShellCheck : niveau « warning », exclusions globales dans .shellcheckrc,
#                constats acceptés dans tools/shellcheck-baseline.txt.
#   Ruff       : erreurs bloquantes (syntaxe, noms indéfinis) selon ruff.toml ;
#                le rapport pyflakes complet est affiché à titre indicatif.
# Les scripts sans extension sont retenus d'après leur shebang.
# Variables : SHELLCHECK, RUFF (binaires à utiliser).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
SHELLCHECK="${SHELLCHECK:-shellcheck}"
RUFF="${RUFF:-ruff}"
SH=(); PY=()
while IFS= read -r -d '' f; do
  [[ -f "$f" && ! -L "$f" ]] || continue
  case "$f" in
    *.sh) SH+=("$f") ;;
    *.py) PY+=("$f") ;;
    *.*) ;;
    *) first=$(head -n1 "$f" 2>/dev/null | tr -d '\0' || true)
       if [[ "$first" =~ ^#!.*(bash|/sh)([[:space:]]|$) ]]; then SH+=("$f")
       elif [[ "$first" =~ ^#!.*python ]]; then PY+=("$f"); fi ;;
  esac
done < <(git ls-files -z)
rc=0

echo "ShellCheck $("$SHELLCHECK" --version | sed -n 's/^version: //p') sur ${#SH[@]} scripts"
report=$("$SHELLCHECK" -S warning -f gcc "${SH[@]}" || true)
new=$(printf '%s\n' "$report" | while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  file=${line%%:*}; code=$(sed -nE 's/.*\[(SC[0-9]+)\]$/\1/p' <<<"$line")
  grep -qE "^${file//./\\.} ${code}( |$)" tools/shellcheck-baseline.txt || printf '%s\n' "$line"
done)
known=$(printf '%s\n' "$report" | grep -c . || true)
if [[ -n "$new" ]]; then
  echo "Nouveaux constats ShellCheck :"; printf '%s\n' "$new"; rc=1
else
  echo "ShellCheck : aucun nouveau constat ($known constat(s) connu(s), voir tools/shellcheck-baseline.txt)."
fi

echo "Ruff $("$RUFF" --version | awk '{print $2}') sur ${#PY[@]} fichiers Python"
if "$RUFF" check --config ruff.toml --output-format concise "${PY[@]}"; then
  echo "Ruff : aucune erreur bloquante."
else
  rc=1
fi
echo "Rapport pyflakes indicatif (non bloquant) :"
"$RUFF" check --isolated --select F --statistics "${PY[@]}" || true
exit "$rc"
