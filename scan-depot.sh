#!/bin/bash
# =============================================================================
# scan-depot.sh : refuse les secrets et les mentions d'outillage dans ce qui va être commité.
#   ./scan-depot.sh --index          -> lignes ajoutées de l'index (git diff --cached)
#   ./scan-depot.sh --message FICHIER -> message de commit (crochet commit-msg)
#   ./scan-depot.sh --installer      -> pose les crochets pre-commit et commit-msg du dépôt
# Code de sortie 1 = alerte (le commit est bloqué par les crochets).
# =============================================================================
set -u
export LANG=C.UTF-8 GIT_PAGER=cat
SECRETS='(password|passwd|pwd|secret|token|api[_-]?key|apikey|bearer|client_secret|webhook)["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9/+_.~-]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-ant-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|webhook\.office\.com/webhookb2/[A-Za-z0-9@/-]{20,}|logic\.azure\.com[^ "]*sig=[A-Za-z0-9%]{10,}|[?&]secret=[0-9a-f]{20,}|[a-z][a-z0-9+.-]*://[^/[:space:]:@"$]+:[^/[:space:]@"$]{4,}@'
EXCL='example|changeme|change_me|xxxx|<[A-Z_]+>|\$\{|\$[A-Z_]{3,}|REPLACE|dummy|fake|placeholder|os\.environ|getenv|read -r|CONF\.get'
OUTILS='claude|anthropic|co-authored-by|generated with|chatgpt|openai|copilot|codex'
masque(){ sed -E 's/([:=]["'"'"' ]*)([A-Za-z0-9/+_.~-]{3})[A-Za-z0-9/+_.~-]{6,}/\1\2*****/' | cut -c1-180; }
case "${1:-}" in
  --index)
    AJOUTS=$(git diff --cached -U0 --no-color | grep -E '^(\+\+\+ |\+)' | grep -vE '^\+\+\+ /dev/null')
    ALERTE=0
    S=$(printf '%s\n' "$AJOUTS" | awk '/^\+\+\+ /{f=substr($0,7);next}{print f": "substr($0,2)}' | grep -E "$SECRETS" | grep -viE "$EXCL")
    [ -n "$S" ] && { ALERTE=1; echo "SECRETS possibles (valeurs masquées) :"; printf '%s\n' "$S" | masque | head -30; }
    # (scan-depot.sh lui-même contient la liste des motifs : il est écarté de ce contrôle)
    O=$(printf '%s\n' "$AJOUTS" | awk '/^\+\+\+ /{f=substr($0,7);next}{print f": "substr($0,2)}' | grep -v '^scan-depot\.sh: ' | grep -iE "$OUTILS")
    [ -n "$O" ] && { ALERTE=1; echo "MENTIONS D'OUTILLAGE :"; printf '%s\n' "$O" | cut -c1-180 | head -30; }
    [ $ALERTE = 0 ] && echo "scan : aucun secret ni mention d'outillage dans l'index."
    exit $ALERTE ;;
  --message)
    if grep -v '^#' "$2" | grep -qiE "$OUTILS"; then echo "Message de commit refusé : mention d'outillage."; exit 1; fi
    exit 0 ;;
  --installer)
    H="$(git rev-parse --git-common-dir)/hooks"; R="$(git rev-parse --show-toplevel)"
    printf '#!/bin/sh\n# scan des secrets et mentions d outillage (scan-depot.sh)\nexec "%s/scan-depot.sh" --index\n' "$R" > "$H/pre-commit"
    printf '#!/bin/sh\nexec "%s/scan-depot.sh" --message "$1"\n' "$R" > "$H/commit-msg"
    chmod 755 "$H/pre-commit" "$H/commit-msg"; echo "crochets posés dans $H" ;;
  *) echo "usage : $0 --index | --message FICHIER | --installer"; exit 2 ;;
esac
