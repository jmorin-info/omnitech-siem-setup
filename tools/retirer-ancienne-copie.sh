#!/usr/bin/env bash
# =============================================================================
# retirer-ancienne-copie.sh : étape 4 du plan de cohérence (docs/DEPLOYMENT.md, § 6) :
# l'ancienne copie /root/omnitech-siem-setup est renommée et remplacée par un lien
# symbolique vers le dépôt canonique. Rien n'est supprimé.
#
#   bash tools/retirer-ancienne-copie.sh               plan (défaut, lecture seule)
#   sudo bash tools/retirer-ancienne-copie.sh --apply  contrôles puis mv + ln -s
#   sudo bash tools/retirer-ancienne-copie.sh --rollback
#
# Contrôles (tous bloquants sauf mention) :
#   - pas avant le 23/11/2026 10:00 (RETRAIT_PAS_AVANT) ;
#   - dépôt canonique : clone Git présent ; ancienne copie : répertoire réel (pas déjà un lien) ;
#     nom de retrait libre ;
#   - aucune unité systemd n'utilise l'ancienne copie dans sa configuration EFFECTIVE
#     (ExecStart*, WorkingDirectory, EnvironmentFiles, ReadWritePaths... lus par
#     systemctl show, drop-ins compris) : une unité de base qui la cite encore mais
#     qu'un drop-in 50-depot-reference.conf repointe n'est pas bloquante ;
#   - aucune tâche cron ne la cite ;
#   - aucun processus ne l'utilise (répertoire courant, exécutable, ligne de commande,
#     fichiers ouverts, bibliothèques chargées) ;
#   - 00-vars.env identique dans les deux copies (comparaison sans affichage du contenu) ;
#   - information : fichiers de secrets en clair de l'ancienne copie, listés (chemin,
#     taille, droits ; jamais le contenu) pour leur suppression à l'étape 5 (7 jours) ;
#     archive de l'ancienne copie présente dans /var/backups/omni-siem.
# --rollback : retire le lien (seulement s'il pointe sur le dépôt canonique) et remet le
#   répertoire retiré à sa place.
# Variables (tests hors ligne) : OMNI_SIEM_HOME, MIGRATION_ANCIEN, MIGRATION_ARCHIVES,
#   RETRAIT_ETAT (/var/lib/omni-retrait-ancienne-copie), RETRAIT_PAS_AVANT
#   ("2026-11-23 10:00"), RETRAIT_MAINTENANT (epoch), RETRAIT_SYSTEMD_DIRS,
#   RETRAIT_CRON, RETRAIT_PROC (/proc), RETRAIT_TEST_MODE.
# =============================================================================
set -uo pipefail
export LANG=C.UTF-8
CANON="${OMNI_SIEM_HOME:-/opt/omni-siem/repository}"
ANCIEN="${MIGRATION_ANCIEN:-/root/omnitech-siem-setup}"
ARCHIVES="${MIGRATION_ARCHIVES:-/var/backups/omni-siem}"
ETAT="${RETRAIT_ETAT:-/var/lib/omni-retrait-ancienne-copie}"
PAS_AVANT="${RETRAIT_PAS_AVANT:-2026-11-23 10:00}"
MAINTENANT="${RETRAIT_MAINTENANT:-$(date +%s)}"
read -r -a SYSTEMD_DIRS <<<"${RETRAIT_SYSTEMD_DIRS:-/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system}"
read -r -a CRON <<<"${RETRAIT_CRON:-/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs}"
PROC="${RETRAIT_PROC:-/proc}"
MODE=plan
for arg in "$@"; do
  case "$arg" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --rollback) MODE=rollback ;;
    -h|--help) sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "option inconnue : $arg (voir --help)" >&2; exit 2 ;;
  esac
done
BLOCAGES=0
ok()   { echo "  OK      $*"; }
info() { echo "  INFO    $*"; }
bloc() { echo "  BLOCAGE $*"; BLOCAGES=$((BLOCAGES + 1)); }
die()  { echo "ERREUR : $*" >&2; exit 1; }
racine_ou_test() { [[ $EUID -eq 0 || "${RETRAIT_TEST_MODE:-}" == 1 ]] || die "$MODE exige root"; }
RETIRE="$ANCIEN.retire-$(date -d "@$MAINTENANT" +%Y%m%d)"

# Propriétés systemd qui désignent un chemin utilisé par l'unité.
PROPRIETES="ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecReload,ExecCondition,WorkingDirectory,RootDirectory,EnvironmentFiles,ReadWritePaths,ReadOnlyPaths,BindPaths,BindReadOnlyPaths,StateDirectory,LogsDirectory,ConfigurationDirectory,What,Where"

controle_unites() {
  local fichiers unites u effectif n=0
  fichiers="$(grep -rlsF -- "$ANCIEN" "${SYSTEMD_DIRS[@]}" 2>/dev/null)"
  unites="$(sed -E 's#.*/([^/]+\.(service|timer|socket|path|mount))(\.d/.*)?$#\1#' <<<"$fichiers" | grep -E '\.(service|timer|socket|path|mount)$' | sort -u)"
  if [[ -z "$unites" ]]; then ok "aucune unité systemd ne cite $ANCIEN"; return; fi
  for u in $unites; do
    effectif="$(systemctl show "$u" -p "$PROPRIETES" 2>/dev/null)"
    if grep -qF -- "$ANCIEN" <<<"$effectif"; then
      bloc "unité $u : configuration effective utilisant $ANCIEN ($(grep -F -- "$ANCIEN" <<<"$effectif" | cut -d= -f1 | sort -u | tr '\n' ' '))"
      n=$((n + 1))
    else
      info "unité $u : cite $ANCIEN dans un fichier, configuration effective repointée"
    fi
  done
  [[ $n == 0 ]] && ok "aucune configuration effective d'unité n'utilise $ANCIEN"
}

controle_cron() {
  local trouve; trouve="$(grep -rlsF -- "$ANCIEN" "${CRON[@]}" 2>/dev/null)"
  if [[ -n "$trouve" ]]; then
    while read -r f; do bloc "tâche cron citant $ANCIEN : $f"; done <<<"$trouve"
  else
    ok "aucune tâche cron ne cite $ANCIEN"
  fi
}

controle_processus() {
  local d pid n=0 raison cmd
  for d in "$PROC"/[0-9]*; do
    pid="${d##*/}"
    [[ "$pid" == "$$" || "$pid" == "$BASHPID" ]] && continue
    raison=""
    [[ "$(readlink "$d/cwd" 2>/dev/null)" == "$ANCIEN"* ]] && raison+="répertoire courant "
    [[ "$(readlink "$d/exe" 2>/dev/null)" == "$ANCIEN"* ]] && raison+="exécutable "
    cmd="$({ tr '\0' ' ' < "$d/cmdline"; } 2>/dev/null)"
    [[ "$cmd" == *"$ANCIEN"* ]] && raison+="ligne de commande "
    if find "$d/fd" -maxdepth 1 -type l -lname "$ANCIEN*" 2>/dev/null | grep -q .; then raison+="fichier ouvert "; fi
    grep -qsF -- "$ANCIEN" "$d/maps" && raison+="bibliothèque chargée "
    if [[ -n "$raison" ]]; then
      bloc "processus $pid ($(cut -c1-80 <<<"$cmd")) : $raison"
      n=$((n + 1))
    fi
  done
  [[ $n == 0 ]] && ok "aucun processus n'utilise $ANCIEN"
}

# Fichiers de secrets en clair : motifs de .gitignore (section SECRETS) et fichiers
# d'environnement. Chemin, taille et droits seulement.
lister_secrets() {
  find "$ANCIEN" \( -name .git -o -name .venv -o -name node_modules -o -name __pycache__ \) -prune -o -type f \( \
       -name '00-vars.env' -o -name '00-vars.autodetect.env' -o -name '*.env' -o -name 'SECRETS.md' \
       -o -name '.graylog_password_secret' -o -name '*.cred' -o -name '*.key' -o -name '*.pem' -o -name '*.pfx' \
       -o -name '*.p12' -o -name '*.jks' -o -name '*_secret*' -o -name '*password*' -o -name '*.kdbx' \) \
       ! -name '*.example' ! -name '*.example.*' -print 2>/dev/null | sort
}

constat() {
  echo "Retrait de l'ancienne copie (mode : $MODE)"
  echo "  ancienne copie  : $ANCIEN"
  echo "  dépôt canonique : $CANON"
  echo "  nom de retrait  : $RETIRE"
  echo
  echo "[1] Date"
  local limite; limite="$(date -d "$PAS_AVANT" +%s 2>/dev/null)" || { bloc "RETRAIT_PAS_AVANT illisible : $PAS_AVANT"; limite=0; }
  if (( MAINTENANT >= limite )); then ok "après le $PAS_AVANT"; else bloc "pas avant le $PAS_AVANT"; fi
  echo "[2] Copies"
  git -C "$CANON" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    && ok "dépôt canonique : clone Git, révision $(git -C "$CANON" rev-parse --short HEAD)" || bloc "$CANON n'est pas un clone Git"
  if [[ -L "$ANCIEN" ]]; then bloc "$ANCIEN est déjà un lien symbolique (vers $(readlink "$ANCIEN")) : retrait déjà fait ?"
  elif [[ -d "$ANCIEN" ]]; then ok "$ANCIEN est un répertoire"
  else bloc "$ANCIEN absent"; fi
  [[ -e "$RETIRE" ]] && bloc "$RETIRE existe déjà" || ok "$RETIRE libre"
  echo "[3] Unités systemd (configuration effective)"
  controle_unites
  echo "[4] Tâches cron"
  controle_cron
  echo "[5] Processus"
  controle_processus
  echo "[6] Configuration du site (00-vars.env, jamais affichée)"
  if [[ -f "$CANON/00-vars.env" && -f "$ANCIEN/00-vars.env" ]]; then
    cmp -s "$CANON/00-vars.env" "$ANCIEN/00-vars.env" && ok "00-vars.env identique dans les deux copies" \
      || bloc "00-vars.env diffère : réconcilier à la main (diff hors écran partagé) avant le retrait"
  elif [[ -f "$ANCIEN/00-vars.env" ]]; then bloc "00-vars.env absent du dépôt canonique"
  else info "pas de 00-vars.env dans l'ancienne copie"; fi
  echo "[7] Secrets en clair de l'ancienne copie (pour l'étape 5, à 7 jours)"
  local s n=0
  while read -r s; do
    [[ -n "$s" ]] || continue
    info "secret en clair : ${s#"$ANCIEN"/} ($(stat -c '%s octets, %a' "$s"))"; n=$((n + 1))
  done < <([[ -d "$ANCIEN" && ! -L "$ANCIEN" ]] && lister_secrets)
  (( n > 0 )) && info "$n fichier(s) de secrets : à supprimer (shred) avec la copie retirée à l'étape 5, après rotation éventuelle des secrets exposés"
  echo "[8] Archive"
  local a; a="$(ls -1t "$ARCHIVES"/ancienne-copie-*.tar.gz 2>/dev/null | head -1)"
  [[ -n "$a" ]] && info "archive la plus récente : $a" || info "aucune archive ancienne-copie-* dans $ARCHIVES (le renommage ne supprime rien)"
}

mode_plan() {
  constat
  echo
  echo "Plan ($BLOCAGES blocage(s)). Appliquer : sudo bash $0 --apply"
  exit $(( BLOCAGES > 0 ? 2 : 0 ))
}

mode_apply() {
  racine_ou_test
  constat
  echo
  [[ $BLOCAGES -eq 0 ]] || die "retrait refusé : $BLOCAGES blocage(s)"
  install -d -m 700 "$ETAT"
  lister_secrets > "$ETAT/secrets-a-supprimer.txt"
  sed -i "s|^$ANCIEN|$RETIRE|" "$ETAT/secrets-a-supprimer.txt"
  mv -- "$ANCIEN" "$RETIRE" || die "mv a échoué : rien n'a changé"
  if ! ln -s -- "$CANON" "$ANCIEN"; then
    mv -- "$RETIRE" "$ANCIEN"; die "ln -s a échoué : ancienne copie remise en place"
  fi
  printf 'RETIRE=%s\nDATE=%s\n' "$RETIRE" "$(date -d "@$MAINTENANT" '+%F %T')" > "$ETAT/retrait.env"
  ok "$ANCIEN -> $(readlink "$ANCIEN") ; copie retirée : $RETIRE"
  cat <<EOF

Retrait appliqué (rien n'a été supprimé).
Contrôles :
  systemctl --failed
  ls -la $ANCIEN
  journalctl --since '-1h' -p err --no-pager | tail -50
Étape 5, au plus tôt 7 jours après, NON exécutée ici : supprimer $RETIRE, dont les
secrets en clair listés dans $ETAT/secrets-a-supprimer.txt (shred -u sur ces fichiers d'abord).
Retour arrière : sudo bash $0 --rollback
EOF
}

mode_rollback() {
  racine_ou_test
  local retire
  retire="$(sed -n 's/^RETIRE=//p' "$ETAT/retrait.env" 2>/dev/null | head -1)"
  [[ -n "$retire" ]] || retire="$(ls -1dt "$ANCIEN".retire-* 2>/dev/null | head -1)"
  [[ -n "$retire" && -d "$retire" && ! -L "$retire" ]] || die "aucune copie retirée trouvée ($ANCIEN.retire-*)"
  [[ -L "$ANCIEN" ]] || die "$ANCIEN n'est pas un lien symbolique : rien à annuler"
  [[ "$(readlink "$ANCIEN")" == "$CANON" ]] || die "$ANCIEN pointe sur $(readlink "$ANCIEN"), pas sur $CANON : intervention manuelle"
  rm -- "$ANCIEN" && mv -- "$retire" "$ANCIEN" || die "retour arrière incomplet : vérifier $ANCIEN et $retire"
  rm -f "$ETAT/retrait.env"
  ok "$ANCIEN remis en place depuis $retire"
}

case "$MODE" in
  plan) mode_plan ;;
  apply) mode_apply ;;
  rollback) mode_rollback ;;
esac
