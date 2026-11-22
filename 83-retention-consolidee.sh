#!/usr/bin/env bash
# =============================================================================
# 83-retention-consolidee.sh - Source unique des retentions des index sets omni-*
#
#   Valeurs alignees sur docs/securite-conformite/POLITIQUE-RETENTION.md.
#   Remplace 31-retention-iso.sh (archive sous tools/ponctuel/) et le volet 2
#   de 41-retention-iso.sh, qui se contredisaient.
#
#   REVISION 22/11/2026 (decision de l'administrateur) :
#   La version precedente migrait les index sets vers TimeBasedSizeOptimizing +
#   data_tiering hot_only. Sur la version de Graylog alors en service, cette
#   migration a supprime des index a ~30 jours au lieu de la retention demandee
#   (incident 09/2026, retour arriere : tools/ponctuel/revert-index-rotation-legacy.sh).
#   Ce script ne fait plus cette migration. Desormais :
#     - il ne modifie QUE les reglages des index sets (rotation temporelle
#       heritee et nombre d'index conserves), qui s'appliquent aux index futurs ;
#     - il ne supprime jamais d'index, n'appelle jamais DELETE, ne reindexe pas ;
#     - il ne reduit jamais une retention : si la retention demandee est plus
#       courte que l'existant, il le signale explicitement et laisse le reglage
#       en place (une reduction se decide et s'applique a la main) ;
#     - il refuse tout reglage dont le nombre d'index conserves serait inferieur
#       au nombre d'index deja presents (Graylog supprimerait les plus anciens
#       au passage suivant de la retention) ;
#     - il refuse d'agir sur un index set dont l'etat ne peut pas etre lu
#       (OpenSearch injoignable, rotation non temporelle sans duree connue).
#
#   Retention effective = nombre d'index conserves x periode de rotation
#   (P1D = 1 jour, P1W = 7 jours, P1M = 30 jours, P1Y = 365 jours). Le nombre
#   d'index cible est arrondi au superieur : la retention obtenue est toujours
#   superieure ou egale a la duree demandee.
#
#   Le routage des streams et la sante des inputs sont CONTROLES en lecture
#   seule : un ecart est signale, jamais corrige ici.
#
#   Usage :
#     ./83-retention-consolidee.sh            plan (lecture seule, defaut)
#     ./83-retention-consolidee.sh --apply    applique les seuls changements surs
#   Code retour : 0 plan sans reserve ; 3 au moins un index set ecarte (retention
#   plus courte que l'existant ou refus), rien d'ecrit pour ceux-la ; 1 erreur.
#   Idempotent.
# =============================================================================
set -uo pipefail

# --- SOURCE UNIQUE DE VERITE (alignee POLITIQUE-RETENTION.md) -----------------
# prefixe -> retention demandee en JOURS
declare -A PLAN=(
  [omni-winsec]=180      [omni-winother]=90     [omni-sysmon]=90
  [omni-m365]=365        [omni-vsphere]=180     [omni-eset]=180
  [omni-fortigate]=180   [omni-bunkerweb]=90    [omni-vaultwarden]=90
  [omni-fortimanager]=90 [omni-interne]=90      [omni-aruba]=90
  [omni-linux]=90        [omni-cert]=90         [omni-fortidhcp]=90
  [omni-fortiems]=90     [omni-seal-access]=365 [omni-seal-alarm]=365
  [omni-seal-audit]=730
)
# prefixe -> periode de rotation temporelle (rotation heritee, sans hierarchisation).
# Relevee en production le 22/11/2026 (API Graylog, GET) : quotidienne pour les
# sources a fort volume, mensuelle pour les sources peu volumineuses. Un prefixe
# absent de cette table conserve la periode en place.
declare -A ROTATION=(
  [omni-winsec]=P1D       [omni-winother]=P1D    [omni-sysmon]=P1D
  [omni-vsphere]=P1D      [omni-fortigate]=P1D   [omni-bunkerweb]=P1D
  [omni-m365]=P1M         [omni-eset]=P1M        [omni-vaultwarden]=P1M
  [omni-fortimanager]=P1M [omni-interne]=P1M     [omni-aruba]=P1M
  [omni-linux]=P1M        [omni-cert]=P1M        [omni-fortidhcp]=P1M
  [omni-fortiems]=P1M     [omni-seal-access]=P1M [omni-seal-alarm]=P1M
  [omni-seal-audit]=P1M
)
# Affectation stream -> prefixe d'index set attendu (controle de routage)
declare -A STREAM_IS=(
  ["OMNI - Windows Security"]=omni-winsec
  ["OMNI - Windows autres"]=omni-winother
  ["OMNI - Sysmon"]=omni-sysmon
  ["OMNI - M365"]=omni-m365
  ["OMNI - vSphere"]=omni-vsphere
  ["OMNI - ESET"]=omni-eset
  ["OMNI - FortiGate"]=omni-fortigate
  ["OMNI - BunkerWeb"]=omni-bunkerweb
  ["OMNI - Vaultwarden"]=omni-vaultwarden
  ["OMNI - FortiManager"]=omni-fortimanager
  ["OMNI - Interne SIEM"]=omni-interne
)

TIMEBASED="org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"
DELETION="org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"

# --- Logique de calcul (fonctions pures, testees hors ligne) ------------------
# period_days PERIODE -> nombre de jours ; code 1 si la periode n'est pas geree.
period_days() {
  local p="$1" n u
  [[ "$p" =~ ^P([1-9][0-9]*)([DWMY])$ ]] || return 1
  n="${BASH_REMATCH[1]}"; u="${BASH_REMATCH[2]}"
  case "$u" in
    D) echo "$n" ;;
    W) echo $(( n * 7 )) ;;
    M) echo $(( n * 30 )) ;;
    Y) echo $(( n * 365 )) ;;
  esac
}

# decide CIBLE_JOURS PERIODE_CIBLE PERIODE_ACTUELLE CONSERVES_ACTUELS JOURS_ACTUELS NB_INDEX
#   PERIODE_ACTUELLE et CONSERVES_ACTUELS sont vides si la rotation n'est pas temporelle.
#   JOURS_ACTUELS : retention effective actuelle en jours, ou « ? » si inconnue.
#   NB_INDEX : nombre d'index existants du prefixe, ou « ? » si inconnu.
# Sortie (une ligne) : DECISION|CONSERVES_CIBLE|JOURS_CIBLE|MOTIF
#   DECISION = CONFORME | APPLIQUER | PLUS_COURT | REFUS
decide() {
  local cible="$1" pcible="$2" pcur="$3" kcur="$4" jcur="$5" nb="$6" pd keep jours
  if ! pd="$(period_days "$pcible")"; then
    echo "REFUS|-|-|periode de rotation cible non geree (${pcible})"; return
  fi
  keep=$(( (cible + pd - 1) / pd ))
  jours=$(( keep * pd ))
  if [[ "$pcur" == "$pcible" && "$kcur" == "$keep" ]]; then
    echo "CONFORME|${keep}|${jours}|deja conforme"; return
  fi
  if [[ "$jcur" == "?" ]]; then
    echo "REFUS|${keep}|${jours}|retention actuelle inconnue : aucune modification"; return
  fi
  if (( jours < jcur )); then
    echo "PLUS_COURT|${keep}|${jours}|retention demandee (${jours} j) plus courte que l'existant (${jcur} j) : reglage conserve, aucune reduction"; return
  fi
  if [[ "$nb" == "?" ]]; then
    echo "REFUS|${keep}|${jours}|nombre d'index existants inconnu (OpenSearch) : aucune modification"; return
  fi
  if (( keep < nb )); then
    echo "REFUS|${keep}|${jours}|${nb} index existants pour ${keep} conserves : Graylog supprimerait des index existants"; return
  fi
  echo "APPLIQUER|${keep}|${jours}|retention ${jcur} j -> ${jours} j"
}

# set_body JSON_INDEX_SET PERIODE CONSERVES -> corps du PUT (rotation heritee).
# Seules la rotation et la retention changent ; data_tiering est desactive car le
# mode hot_only est celui qui a supprime des index prematurement (09/2026).
set_body() {
  jq --arg period "$2" --argjson keep "$3" --arg rot "$TIMEBASED" --arg ret "$DELETION" '
    .use_legacy_rotation = true
    | .rotation_strategy_class = $rot
    | .rotation_strategy = {type: ($rot + "Config"), rotation_period: $period,
                            max_rotation_period: (.rotation_strategy.max_rotation_period // null),
                            rotate_empty_index_set: (.rotation_strategy.rotate_empty_index_set // false)}
    | .retention_strategy_class = $ret
    | .retention_strategy = {type: ($ret + "Config"), max_number_of_indices: $keep}
    | .data_tiering = null' <<<"$1"
}

usage() { sed -n '3,41p' "$0" | sed 's/^# \{0,1\}//'; }

main() {
  local ENV_APPLY="${APPLY:-}" APPLY=0 arg
  for arg in "$@"; do
    case "$arg" in
      --apply) APPLY=1 ;;
      -h|--help) usage; return 0 ;;
      *) echo "option inconnue : $arg (voir --help)" >&2; return 1 ;;
    esac
  done
  cd "$(dirname "$0")" || return 1
  [[ -r ./00-vars.env ]] || { echo "ERREUR: 00-vars.env illisible (lancer en root)" >&2; return 1; }
  # shellcheck disable=SC1091
  source ./00-vars.env
  # shellcheck disable=SC1091
  source ./lib-graylog.sh
  if [[ $APPLY == 1 && $EUID -ne 0 && "${OMNI_TEST_MODE:-}" != 1 ]]; then
    die "root requis pour --apply"
  fi
  [[ -n "$ENV_APPLY" && $APPLY != 1 ]] && warn "la variable APPLY n'est plus reconnue : seule l'option --apply ecrit"
  require_api
  local OS="${OS_URL:-http://127.0.0.1:9200}"

  echo "=============================================================================="
  echo " 83-retention-consolidee.sh  (mode : $([[ $APPLY == 1 ]] && echo 'APPLICATION (--apply)' || echo 'PLAN (lecture seule)'))"
  echo "=============================================================================="

  local SETS
  SETS="$(api_get '/system/indices/index_sets?skip=0&limit=200')"
  jq -e '.index_sets' >/dev/null 2>&1 <<<"$SETS" || die "liste des index sets illisible"

  echo "==> [1/4] Retention et rotation des index sets (s'appliquent aux index futurs)"
  printf "    %-18s %-6s %-14s %-14s %-6s %s\n" PREFIXE CIBLE ACTUEL "CIBLE REGLEE" INDEX DECISION
  local PREFIX ID JSET PCUR KCUR JCUR NB PCIBLE LMAX LIST RES DEC KEEP JOURS MOTIF REP pd P
  local N_APPLY=0 N_REFUS=0 N_COURT=0
  local -a A_APPLY=()
  for PREFIX in $(printf '%s\n' "${!PLAN[@]}" | sort); do
    JSET="$(jq -c --arg p "$PREFIX" '[.index_sets[]|select(.index_prefix==$p)][0] // empty' <<<"$SETS")"
    if [[ -z "$JSET" ]]; then
      printf "    %-18s %-6s %-14s %-14s %-6s %s\n" "$PREFIX" "${PLAN[$PREFIX]}j" - - - "index set absent (ignore)"
      continue
    fi
    ID="$(jq -r '.id' <<<"$JSET")"
    PCUR=""; KCUR=""; JCUR="?"
    if [[ "$(jq -r '.rotation_strategy_class // ""' <<<"$JSET")" == "$TIMEBASED" \
       && "$(jq -r '.retention_strategy_class // ""' <<<"$JSET")" == "$DELETION" ]]; then
      PCUR="$(jq -r '.rotation_strategy.rotation_period // ""' <<<"$JSET")"
      KCUR="$(jq -r '.retention_strategy.max_number_of_indices // ""' <<<"$JSET")"
      if pd="$(period_days "$PCUR")" && [[ "$KCUR" =~ ^[0-9]+$ ]]; then JCUR=$(( KCUR * pd )); fi
    else
      # rotation non temporelle : duree connue seulement si index_lifetime_max = PnD
      LMAX="$(jq -r '(.data_tiering.index_lifetime_max // .rotation_strategy.index_lifetime_max // "")' <<<"$JSET")"
      if [[ "$LMAX" =~ ^P([0-9]+)D$ ]]; then JCUR="${BASH_REMATCH[1]}"; fi
    fi
    PCIBLE="${ROTATION[$PREFIX]:-${PCUR:-P1D}}"
    if LIST="$(curl -sf "${OS}/_cat/indices/${PREFIX}_*?h=index" 2>/dev/null)"; then
      NB="$(grep -c . <<<"$LIST")"
    else
      NB="?"
    fi
    RES="$(decide "${PLAN[$PREFIX]}" "$PCIBLE" "$PCUR" "$KCUR" "$JCUR" "$NB")"
    IFS='|' read -r DEC KEEP JOURS MOTIF <<<"$RES"
    printf "    %-18s %-6s %-14s %-14s %-6s %s\n" "$PREFIX" "${PLAN[$PREFIX]}j" \
      "${PCUR:-?}x${KCUR:-?}=${JCUR}j" "${PCIBLE}x${KEEP}=${JOURS}j" "$NB" "$DEC"
    case "$DEC" in
      APPLIQUER)  N_APPLY=$((N_APPLY+1)); A_APPLY+=("${PREFIX}|${ID}|${PCIBLE}|${KEEP}") ;;
      PLUS_COURT) N_COURT=$((N_COURT+1)); warn "ATTENTION ${PREFIX} : ${MOTIF}" ;;
      REFUS)      N_REFUS=$((N_REFUS+1)); warn "REFUS ${PREFIX} : ${MOTIF}" ;;
    esac
  done
  echo "    ------------------------------------------------------------------"
  echo "    A appliquer : ${N_APPLY} ; plus courte que l'existant (non reduite) : ${N_COURT} ; refus : ${N_REFUS}"
  echo "    Aucun index existant n'est supprime, reduit ou reindexe par ce script."

  if (( N_APPLY > 0 )); then
    if [[ $APPLY != 1 ]]; then
      echo; warn "PLAN : aucune ecriture. Pour appliquer : ./83-retention-consolidee.sh --apply"
    else
      echo; echo "    --apply : mise a jour des seuls index sets marques APPLIQUER"
      local ITEM I PER K
      for ITEM in "${A_APPLY[@]}"; do
        IFS='|' read -r P I PER K <<<"$ITEM"
        JSET="$(jq -c --arg p "$P" '[.index_sets[]|select(.index_prefix==$p)][0]' <<<"$SETS")"
        REP="$(set_body "$JSET" "$PER" "$K" | api_put "/system/indices/index_sets/${I}")"
        if jq -e '.id' >/dev/null 2>&1 <<<"$REP"; then
          ok "${P} -> rotation ${PER}, ${K} index conserves"
        else
          warn "${P} : echec de la mise a jour -> $(head -c 200 <<<"$REP")"
        fi
      done
    fi
  fi

  # --- [2/4] Routage des streams (controle seul) ------------------------------
  echo
  echo "==> [2/4] Routage des streams OMNI-* (controle, aucune modification)"
  local TITLE SID WANT_ID CURIS
  for TITLE in "${!STREAM_IS[@]}"; do
    SID="$(get_stream_id "$TITLE")"
    [[ -n "$SID" ]] || { skip "stream absent : ${TITLE}"; continue; }
    WANT_ID="$(jq -r --arg p "${STREAM_IS[$TITLE]}" '.index_sets[]|select(.index_prefix==$p)|.id' <<<"$SETS")"
    [[ -n "$WANT_ID" ]] || { warn "index set ${STREAM_IS[$TITLE]} absent"; continue; }
    CURIS="$(api_get "/streams/${SID}" | jq -r '.index_set_id')"
    if [[ "$CURIS" == "$WANT_ID" ]]; then
      skip "${TITLE} -> ${STREAM_IS[$TITLE]} (OK)"
    else
      warn "${TITLE} route sur l'index set ${CURIS} au lieu de ${STREAM_IS[$TITLE]} (${WANT_ID}) : a corriger a la main"
    fi
  done

  # --- [3/4] Sante des inputs (lecture seule) ---------------------------------
  echo
  echo "==> [3/4] Sante des inputs"
  local STATES NB_OK NB_TOT
  STATES="$(api_get '/system/inputstates')"
  NB_OK="$(jq '[.states[]?|select(.state=="RUNNING")]|length' <<<"$STATES" 2>/dev/null)"
  NB_TOT="$(jq '[.states[]?]|length' <<<"$STATES" 2>/dev/null)"
  echo "    inputs RUNNING : ${NB_OK}/${NB_TOT}"
  jq -r '.states[]?|select(.state!="RUNNING")|"    [!] NON RUNNING : \(.message_input.title) (\(.state))"' <<<"$STATES" 2>/dev/null
  if [[ -n "$NB_OK" && "$NB_OK" == "$NB_TOT" ]]; then ok "tous les inputs sont RUNNING"; else warn "verifier les inputs ci-dessus"; fi

  # --- [4/4] Index sets omni-* hors plan ---------------------------------------
  echo
  echo "==> [4/4] Index sets omni-* hors source de verite"
  for P in $(jq -r '.index_sets[]|select(.index_prefix|startswith("omni-"))|.index_prefix' <<<"$SETS"); do
    [[ -v "PLAN[$P]" ]] || warn "index set '${P}' absent du PLAN : l'ajouter ici et dans POLITIQUE-RETENTION.md"
  done

  echo
  echo "=== 83-retention-consolidee.sh termine (mode $([[ $APPLY == 1 ]] && echo APPLICATION || echo PLAN)). ==="
  (( N_REFUS + N_COURT > 0 )) && return 3
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
