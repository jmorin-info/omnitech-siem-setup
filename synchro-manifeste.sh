#!/bin/bash
# =============================================================================
# synchro-manifeste.sh : recopie dans le dépôt les fichiers EN SERVICE listés dans
# manifeste-deploye.txt (et seulement eux), après comparaison SHA-256.
# Remplace sync-deploye.sh (son étape « 2 bis » recopiait des versions anciennes).
#   ./synchro-manifeste.sh            -> état : IDENTIQUE / DIFFERENT / NOUVEAU / ABSENT (rien n'est modifié)
#   ./synchro-manifeste.sh --copier   -> copie les DIFFERENT et NOUVEAU, les ajoute à l'index,
#                                        puis lance scan-depot.sh ; en cas d'alerte, tout est annulé.
# Ne fait JAMAIS de commit ni de push. Les fichiers en production ne sont jamais modifiés.
# Format du manifeste : <chemin en service><TAB><chemin dans le dépôt>, « # » = commentaire.
# =============================================================================
set -u
export LANG=C.UTF-8 GIT_PAGER=cat
cd "$(dirname "$(readlink -f "$0")")" || exit 1
MAN=manifeste-deploye.txt; MODE="${1:-}"
[ -f "$MAN" ] || { echo "manifeste absent : $MAN"; exit 1; }
copies=(); n_id=0; n_diff=0; n_new=0; n_abs=0
while IFS=$'\t' read -r prod depot; do
  case "$prod" in ''|\#*) continue;; esac
  [ -n "${depot:-}" ] || { echo "ligne invalide : $prod"; continue; }
  if [ ! -f "$prod" ]; then echo "ABSENT     $prod"; n_abs=$((n_abs+1)); continue; fi
  if [ ! -f "$depot" ]; then etat=NOUVEAU; n_new=$((n_new+1))
  elif [ "$(sha256sum < "$prod")" = "$(sha256sum < "$depot")" ]; then n_id=$((n_id+1)); continue
  else etat=DIFFERENT; n_diff=$((n_diff+1)); fi
  echo "$etat  $depot  <-  $prod"
  if [ "$MODE" = --copier ]; then
    mkdir -p "$(dirname "$depot")"; cp -p "$prod" "$depot"
    # URL avec identifiants : mot de passe remplacé par une variable dans la copie du dépôt
    sed -i -E 's#([a-z][a-z0-9+.-]*://[^/[:space:]:@"'"'"'$]+):[^/[:space:]@"'"'"'$]{4,}@#\1:${MOT_DE_PASSE_LU_HORS_DEPOT}@#g' "$depot"
    git add -- "$depot"; copies+=("$depot")
  fi
done < "$MAN"
echo "identiques : $n_id ; différents : $n_diff ; nouveaux : $n_new ; absents en service : $n_abs"
[ "$MODE" = --copier ] || exit 0
[ ${#copies[@]} -eq 0 ] && { echo "Rien à copier."; exit 0; }
if ! ./scan-depot.sh --index; then
  echo "Alerte du scan : copies annulées."
  git reset -q -- "${copies[@]}"
  for f in "${copies[@]}"; do if git cat-file -e "HEAD:$f" 2>/dev/null; then git checkout -q -- "$f"; else rm -f -- "$f"; fi; done
  exit 2
fi
echo "Copies indexées (${#copies[@]}). Vérifier : git diff --cached --stat ; puis commit à la main."
