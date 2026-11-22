#!/usr/bin/env bash
# =============================================================================
# migrer-chemin-canonique.sh : bascule des services de l'ancienne copie
# /root/omnitech-siem-setup vers le dépôt canonique (OMNI_SIEM_HOME,
# /opt/omni-siem/repository par défaut).
#
#   bash tools/migrer-chemin-canonique.sh            plan seul (lecture seule)
#   sudo bash tools/migrer-chemin-canonique.sh --apply
#
# Aligné sur le plan de cohérence du 21/11/2026 (docs/AUDIT-COHERENCE-2026-11-21.md, § 5) :
#   étape 0 : archives (ancienne copie, /etc/systemd/system, /etc/nginx) ;
#   étape 2 : venvs dans le dépôt canonique (omni-deploy deploy venvs) ;
#   étape 3 : drop-ins 50-depot-reference.conf, UNE transaction par service, du moins
#             critique au plus critique ; arrêt au premier échec (celui-ci est annulé
#             automatiquement, les précédents restent annulables un par un) ;
#   puis robots (lecture de 00-vars.env dans le dépôt canonique) et droits 0644 des unités.
# Les étapes 4 (lien de transition) et 5 (retrait des copies) sont affichées, jamais exécutées.
# L'ancienne copie n'est ni déplacée ni supprimée : elle reste le filet de sécurité.
# Variables : OMNI_SIEM_HOME, MIGRATION_ANCIEN (ancienne copie),
#             MIGRATION_ARCHIVES (répertoire des archives, défaut /var/backups/omni-siem).
# =============================================================================
set -euo pipefail
export LANG=C.UTF-8 GIT_OPTIONAL_LOCKS=0
CANON="${OMNI_SIEM_HOME:-/opt/omni-siem/repository}"
ANCIEN="${MIGRATION_ANCIEN:-/root/omnitech-siem-setup}"
ARCHIVES="${MIGRATION_ARCHIVES:-/var/backups/omni-siem}"
MODE="${1:-}"
case "$MODE" in ""|--plan|--apply) ;; *) echo "usage : $0 [--plan|--apply]" >&2; exit 2 ;; esac
BLOCAGES=0
ok()   { echo "  OK      $*"; }
info() { echo "  INFO    $*"; }
bloc() { echo "  BLOCAGE $*"; BLOCAGES=$((BLOCAGES + 1)); }

echo "Migration vers le dépôt canonique"
echo "  dépôt canonique : $CANON"
echo "  ancienne copie  : $ANCIEN"
echo
echo "[1] Dépôt canonique"
if git -C "$CANON" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  ok "clone Git présent, révision $(git -C "$CANON" rev-parse --short HEAD)"
  [[ -f "$CANON/omni_deploy/engine.py" ]] && ok "outil de déploiement présent" \
    || bloc "omni_deploy absent : mettre à jour le dépôt canonique sur une révision qui contient tools/omni-deploy.py"
  if [[ -n "$(git -C "$CANON" status --porcelain --untracked-files=no)" ]]; then
    bloc "fichiers suivis modifiés dans $CANON : examiner git -C $CANON diff avant de migrer"
  else
    ok "aucun fichier suivi modifié"
  fi
else
  bloc "$CANON n'est pas un clone Git"
fi

echo "[2] Configuration du site (00-vars.env, jamais affichée)"
COPIER_ENV=0
if [[ -f "$CANON/00-vars.env" ]]; then
  if [[ -f "$ANCIEN/00-vars.env" ]] && ! cmp -s "$CANON/00-vars.env" "$ANCIEN/00-vars.env"; then
    bloc "00-vars.env diffère entre les deux copies : réconcilier à la main (diff hors écran partagé)"
  else
    ok "00-vars.env présent dans le dépôt canonique"
  fi
  [[ "$(stat -c %a "$CANON/00-vars.env")" == 600 ]] && ok "droits 600" || bloc "00-vars.env doit être en 600"
elif [[ -f "$ANCIEN/00-vars.env" ]]; then
  info "00-vars.env sera copié de l'ancienne copie (droits 600)"
  COPIER_ENV=1
else
  bloc "aucun 00-vars.env trouvé"
fi

echo "[3] Ancienne copie (conservée telle quelle)"
if [[ -d "$ANCIEN" ]]; then
  if git -C "$ANCIEN" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    MODIFIES=$(git -C "$ANCIEN" status --porcelain --untracked-files=no | wc -l)
    info "$MODIFIES fichier(s) suivi(s) modifié(s) non commités : ils seront archivés, pas recopiés"
  fi
  info "archive prévue : $ARCHIVES/ancienne-copie-<date>.tar.gz (venvs et caches exclus)"
else
  info "ancienne copie absente : rien à archiver"
fi

echo "[4] Prérequis du dépôt (plan de cohérence, étape 1)"
if grep -q '\[\[ "\$API" == \*/api \]\]' "$CANON/lib-platform.sh" 2>/dev/null; then
  ok "lib-platform.sh normalise le suffixe /api de GRAYLOG_API_URL"
else
  bloc "lib-platform.sh ne normalise pas /api : omni-disk-guard ne doit pas être repointé (purge d'urgence inopérante)"
fi
[[ -f "$CANON/mobile/requirements.txt" ]] && ok "mobile/requirements.txt présent" || bloc "mobile/requirements.txt absent"
if [[ -d "$CANON/docs/archives/preuves-iso" ]]; then
  ok "dossier de preuves ISO présent (seule écriture d'omni-iso-evidence dans le dépôt)"
else
  bloc "docs/archives/preuves-iso absent de $CANON : omni-iso-evidence échouerait (ReadWritePaths)"
fi

echo "[5] Références restantes hors outil de déploiement"
if grep -q "$ANCIEN" "$CANON/mobile/omni-mobile-api.py" 2>/dev/null; then
  info "mobile/omni-mobile-api.py référence encore $ANCIEN (OMS_GRAPH_DIR, défaut MITRE_LOOKUP) :"
  info "  le backend lira oms-graph et le lookup MITRE dans l'ancienne copie tant que ce code n'est pas corrigé ;"
  info "  ne pas retirer l'ancienne copie avant cette correction. --apply ajoute MITRE_LOOKUP à /etc/default/omni-mobile s'il manque."
fi

echo "[6] Plan de déploiement délégué à omni-deploy"
if [[ -f "$CANON/tools/omni-deploy.py" ]]; then
  if ! OMNI_SIEM_HOME="$CANON" python3 "$CANON/tools/omni-deploy.py" --home "$CANON" deploy all | sed 's/^/    /'; then
    bloc "le plan de déploiement a échoué : corriger ses blocages avant toute migration"
  fi
fi

echo
if [[ "$MODE" != --apply ]]; then
  echo "Plan seul ($BLOCAGES blocage(s)). Appliquer : sudo bash $0 --apply"
  exit $(( BLOCAGES > 0 ? 2 : 0 ))
fi
[[ $BLOCAGES -eq 0 ]] || { echo "Migration refusée : $BLOCAGES blocage(s)." >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "--apply exige root." >&2; exit 1; }

if [[ -d "$ANCIEN" ]]; then
  install -d -m 700 "$ARCHIVES"
  ARCHIVE="$ARCHIVES/ancienne-copie-$(date +%Y%m%d-%H%M%S).tar.gz"
  ( umask 077; tar czf "$ARCHIVE" --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' \
      --exclude='.ruff_cache' -C "$(dirname "$ANCIEN")" "$(basename "$ANCIEN")" )
  echo "Archive de l'ancienne copie : $ARCHIVE"
fi
if [[ $COPIER_ENV -eq 1 ]]; then
  install -m 600 -o root -g root "$ANCIEN/00-vars.env" "$CANON/00-vars.env"
  echo "00-vars.env copié dans $CANON (600)."
fi
STAMP=$(date +%Y%m%d-%H%M%S)
install -d -m 700 "$ARCHIVES"
( umask 077; tar czf "$ARCHIVES/systemd-$STAMP.tar.gz" -C /etc/systemd system; tar czf "$ARCHIVES/nginx-$STAMP.tar.gz" -C /etc nginx )
if [[ -f /etc/default/omni-mobile ]] && ! grep -q '^MITRE_LOOKUP=' /etc/default/omni-mobile; then
  cp -p /etc/default/omni-mobile "$ARCHIVES/omni-mobile-$STAMP.default"
  echo "MITRE_LOOKUP=$CANON/lookups/mitre-attack.csv" >> /etc/default/omni-mobile
  echo "MITRE_LOOKUP ajouté à /etc/default/omni-mobile (copie : $ARCHIVES/omni-mobile-$STAMP.default)."
fi
DEPLOY=(env OMNI_SIEM_HOME="$CANON" python3 "$CANON/tools/omni-deploy.py" --home "$CANON")
"${DEPLOY[@]}" deploy venvs --apply --no-verify
for service in omni-iso-evidence oms-graph oms-graph-respond oms-ml-anomaly oms-ml-fp oms-xdr omni-backup-config omni-disk-guard omni-mobile-api; do
  echo "== Repointage de $service"
  "${DEPLOY[@]}" deploy systemd --filtre "/etc/systemd/system/$service.service.d/50-depot-reference.conf" --apply --no-verify
done
"${DEPLOY[@]}" deploy robots --apply --no-verify
"${DEPLOY[@]}" deploy systemd --apply
cat <<EOF
Migration appliquée. Transactions : ${DEPLOY[*]} history
L'ancienne copie $ANCIEN est conservée pour le retour arrière.
Étape 4, après un cycle complet de timers (24 h) sans incident, NON exécutée ici :
  mv $ANCIEN $ANCIEN.retire-\$(date +%Y%m%d) && ln -s $CANON $ANCIEN
Étape 5, après 7 jours sans incident : retrait des copies obsolètes (voir docs/DEPLOYMENT.md).
EOF
