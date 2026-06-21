#!/usr/bin/env bash
# =============================================================================
# 81-retention-consolidee.sh - SOURCE UNIQUE DE VERITE de la retention omni-*
#   Remplace 31-retention-iso.sh ET 41-retention-iso.sh (volet 2), qui se
#   CONTREDISAIENT (sysmon/vsphere 180 vs 365, fortigate 180 vs 90 -> derniere
#   execution gagne). Valeurs alignees sur docs/POLITIQUE-RETENTION.md (la
#   reference d'audit ISO 27001 A.8.15), couvrant TOUS les index sets omni-*,
#   y compris omni-fortimanager (cree par 63) et omni-interne (cree par 79) qui
#   n'etaient dans AUCUN script de retention.
#
#   Constats d'audit traites :
#     (a) eset/bunkerweb/vaultwarden documentes mais absents de 31/41 -> ajoutes.
#     (b) 31 vs 41 contradictoires -> ce script devient l'unique reference.
#
#   *** APPLIQUER UNE RETENTION SUPPRIME LES INDEX AU-DELA DU SEUIL. ***
#   Ce script est en DRY-RUN par defaut : il imprime, par prefixe, le nombre
#   EXACT d'index qui seraient supprimes (et leurs noms) et N'ECRIT RIEN.
#   Pour appliquer reellement : APPLY=1 ./81-retention-consolidee.sh
#   Garde-fou : refuse de supprimer > MAX_DELETE index d'un coup sans FORCE=1.
#
#   Mesure terrain 2026-06-22 : chaque prefixe a <= 8 index (~36 j), plus petit
#   seuil = 90 -> 0 index supprime aujourd'hui. Effet de suppression purement
#   FUTUR (quand les donnees depasseront le seuil) ; le disk-guard (32) reste le
#   backstop a 88 %.
#
#   Volet 1 de 41 (regles drop_message stage 30 de reduction de bruit) N'EST PAS
#   repris ici : il reste gere par 41. Ce script ne touche QUE la retention, le
#   routage des streams et la sante des inputs.
#
#   Idempotent. Lecture seule tant que APPLY!=1. Relancer apres 10/52/55/63/79.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

OS="${OS_URL:-http://127.0.0.1:9200}"
APPLY="${APPLY:-0}"          # 0 = dry-run (defaut), 1 = ecrit la retention
FORCE="${FORCE:-0}"          # 1 = autorise une suppression > MAX_DELETE
MAX_DELETE="${MAX_DELETE:-5}"  # garde-fou : refus si un seuil supprime plus que ca

# --- SOURCE UNIQUE DE VERITE (alignee docs/POLITIQUE-RETENTION.md) ------------
# prefixe -> retention en NOMBRE D'INDEX (rotation P1D => 1 index = 1 jour)
declare -A PLAN=(
  [omni-winsec]=365      [omni-winother]=365   [omni-sysmon]=365
  [omni-m365]=365        [omni-vsphere]=365     [omni-eset]=365
  [omni-fortigate]=180   [omni-bunkerweb]=90    [omni-vaultwarden]=90
  [omni-fortimanager]=365 [omni-interne]=90
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

SETS="$(api_get '/system/indices/index_sets?skip=0&limit=200')"
is_id()     { echo "$SETS" | jq -r --arg p "$1" '.index_sets[]|select(.index_prefix==$p)|.id'; }
is_curret() { echo "$SETS" | jq -r --arg p "$1" '.index_sets[]|select(.index_prefix==$p)|.retention_strategy.max_number_of_indices'; }
# index d'un prefixe tries du PLUS ANCIEN au plus recent (par date de creation)
idx_list()  { curl -s "${OS}/_cat/indices/${1}_*?h=index,creation.date&s=creation.date" 2>/dev/null | awk '{print $1}'; }

echo "=============================================================================="
echo " 81-retention-consolidee.sh  (mode : $([[ $APPLY == 1 ]] && echo 'APPLY (ecriture)' || echo 'DRY-RUN (lecture seule)'))"
echo "=============================================================================="

# --- [1/4] Impact de suppression + (option) application -----------------------
echo "==> [1/4] Retention POLITIQUE.md + impact de suppression (par prefixe)"
printf "    %-20s %-7s %-7s %-9s %s\n" PREFIXE ACTUEL CIBLE SUPPRIMES ETAT
TOTAL_SUPPR=0; ABORT=0
declare -a TO_DELETE_ALL=()
for PREFIX in $(printf '%s\n' "${!PLAN[@]}" | sort); do
  TARGET="${PLAN[$PREFIX]}"
  ID="$(is_id "$PREFIX")"
  if [[ -z "$ID" || "$ID" == null ]]; then
    printf "    %-20s %-7s %-7s %-9s %s\n" "$PREFIX" "-" "$TARGET" "-" "index set ABSENT (ignore)"
    continue
  fi
  CUR="$(is_curret "$PREFIX")"
  mapfile -t IDX < <(idx_list "$PREFIX")
  NB="${#IDX[@]}"
  SUPPR=$(( NB > TARGET ? NB - TARGET : 0 ))
  TOTAL_SUPPR=$(( TOTAL_SUPPR + SUPPR ))
  ETAT="ret=${CUR}"
  [[ "$CUR" == "$TARGET" ]] && ETAT="${ETAT} (deja conforme)" || ETAT="${ETAT} -> ${TARGET}"
  printf "    %-20s %-7s %-7s %-9s %s\n" "$PREFIX" "$NB" "$TARGET" "$SUPPR" "$ETAT"
  if (( SUPPR > 0 )); then
    # les SUPPR plus ANCIENS seraient supprimes (la liste est triee asc.)
    for ((i=0; i<SUPPR; i++)); do
      echo "         -> serait supprime : ${IDX[$i]}"
      TO_DELETE_ALL+=("${IDX[$i]}")
    done
    (( SUPPR > MAX_DELETE )) && ABORT=1
  fi
done
echo "    ------------------------------------------------------------------"
echo "    TOTAL index omni-* qui seraient supprimes a l'application : ${TOTAL_SUPPR}"

if (( ABORT == 1 && FORCE != 1 )); then
  warn "Au moins un prefixe supprimerait > ${MAX_DELETE} index. ARRET (securite)."
  warn "Verifier la liste ci-dessus. Pour passer outre : FORCE=1 APPLY=1 ./81-retention-consolidee.sh"
  exit 2
fi

if [[ "$APPLY" != "1" ]]; then
  echo
  warn "DRY-RUN : aucune ecriture effectuee. Pour appliquer : APPLY=1 ./81-retention-consolidee.sh"
else
  echo
  echo "    APPLY=1 -> ecriture de la retention (idempotent)"
  for PREFIX in $(printf '%s\n' "${!PLAN[@]}" | sort); do
    TARGET="${PLAN[$PREFIX]}"; ID="$(is_id "$PREFIX")"
    [[ -z "$ID" || "$ID" == null ]] && continue
    CUR="$(is_curret "$PREFIX")"
    if [[ "$CUR" == "$TARGET" ]]; then skip "${PREFIX} deja a ${TARGET}"; continue; fi
    REP="$(echo "$SETS" | jq --arg p "$PREFIX" --argjson j "$TARGET" \
            '.index_sets[]|select(.index_prefix==$p)|.retention_strategy.max_number_of_indices=$j' \
          | api_put "/system/indices/index_sets/${ID}")"
    echo "$REP" | jq -e '.id' >/dev/null 2>&1 \
      && ok "${PREFIX} -> retention ${TARGET} (etait ${CUR})" \
      || warn "${PREFIX} : echec maj -> $(echo "$REP" | head -c 200)"
  done
fi

# --- [2/4] Coherence du routage des streams (index_set_id) --------------------
# Constat live : 'OMNI - FortiManager' route sur l'index set Default 'graylog'
# au lieu de omni-fortimanager -> events dans graylog_0. Fix style 79 (PUT
# UpdateStreamRequest complet : preserve title/desc/matching_type/rules).
echo
echo "==> [2/4] Coherence du routage des streams OMNI-*"
fix_stream_routing() {
  local TITLE="$1" WANT_PFX="$2" SID WANT_ID CUR CURIS BODY
  SID="$(get_stream_id "$TITLE")"
  [[ -n "$SID" ]] || { skip "stream absent: ${TITLE}"; return 0; }
  WANT_ID="$(is_id "$WANT_PFX")"
  [[ -n "$WANT_ID" && "$WANT_ID" != null ]] || { warn "index set ${WANT_PFX} absent (cf. script createur)"; return 0; }
  CUR="$(api_get "/streams/${SID}")"
  CURIS="$(jq -r '.index_set_id' <<<"$CUR")"
  if [[ "$CURIS" == "$WANT_ID" ]]; then skip "${TITLE} -> ${WANT_PFX} (OK)"; return 0; fi
  warn "${TITLE} route sur index_set ${CURIS} au lieu de ${WANT_PFX} (${WANT_ID})"
  if [[ "$APPLY" != "1" ]]; then
    echo "         (DRY-RUN) ré-affectation prévue : ${TITLE} -> ${WANT_PFX}"
    return 0
  fi
  BODY="$(jq -c --arg is "$WANT_ID" '{title:.title,
            description:(.description//.title),
            matching_type:(.matching_type//"AND"),
            remove_matches_from_default_stream:(.remove_matches_from_default_stream//true),
            index_set_id:$is}' <<<"$CUR")"
  echo "$BODY" | api_put "/streams/${SID}" >/dev/null \
    && ok "${TITLE} ré-affecté à ${WANT_PFX} (etait ${CURIS})" \
    || warn "${TITLE} : echec ré-affectation"
}
for TITLE in "${!STREAM_IS[@]}"; do
  fix_stream_routing "$TITLE" "${STREAM_IS[$TITLE]}"
done

# --- [3/4] Sante des inputs ---------------------------------------------------
echo
echo "==> [3/4] Sante des inputs (api_get /system/inputstates)"
STATES="$(api_get '/system/inputstates')"
NB_OK="$(echo "$STATES" | jq '[.states[]?|select(.state=="RUNNING")]|length' 2>/dev/null)"
NB_TOT="$(echo "$STATES" | jq '[.states[]?]|length' 2>/dev/null)"
echo "    inputs RUNNING : ${NB_OK}/${NB_TOT}"
echo "$STATES" | jq -r '.states[]?|select(.state!="RUNNING")|"    [!] NON RUNNING : \(.message_input.title) (\(.state))"' 2>/dev/null
[[ "$NB_OK" == "$NB_TOT" && -n "$NB_OK" ]] && ok "tous les inputs sont RUNNING" || warn "verifier les inputs ci-dessus"

# --- [4/4] Index sets omni-* SANS plan de retention (alerte de derive) --------
echo
echo "==> [4/4] Index sets omni-* hors source de verite (a documenter / planifier)"
for P in $(echo "$SETS" | jq -r '.index_sets[]|select(.index_prefix|startswith("omni-"))|.index_prefix'); do
  [[ -v "PLAN[$P]" ]] || warn "index set '${P}' present mais ABSENT du PLAN -> l'ajouter a 81 + POLITIQUE.md"
done

echo
echo "=== 81-retention-consolidee.sh termine (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)). ==="
echo "    Source de verite : ce script. Penser a deprecier 31 et 41 (volet 2) et a"
echo "    aligner docs/POLITIQUE-RETENTION.md (ajouter omni-fortimanager=365, omni-interne=90)."