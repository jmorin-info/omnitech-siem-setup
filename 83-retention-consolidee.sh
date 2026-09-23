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
#   MISE A JOUR 09/2026 (incident "max shards 1000") : ce script migre desormais
#   la ROTATION des index sets omni-* de "quotidienne (P1D)" vers
#   TimeBasedSizeOptimizing + suppression par AGE (data_tiering, index_lifetime_max
#   = retention). La DUREE de retention est INCHANGEE ; seul le mecanisme change
#   (age, plus "nombre d'index"), ce qui divise par ~30 le nombre de shards.
#
#   *** LA SUPPRESSION SE FAIT PAR AGE : un index n'est supprime que si sa date
#       de creation depasse la retention. Aucune suppression anticipee. ***
#   DRY-RUN par defaut : imprime, par prefixe, la rotation cible et le nombre
#   d'index deja plus vieux que la retention (donc supprimes a l'application).
#   Appliquer : APPLY=1 ./83-retention-consolidee.sh
#   Garde-fou : refuse si un prefixe supprimerait > MAX_DELETE index sans FORCE=1.
#   La recuperation IMMEDIATE des index quotidiens deja crees (sources muettes)
#   est traitee separement par reclaim-shards-reindex.sh (reindexation, 0 perte).
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
# RECALIBRE 14/08/2026 (arbitrage risque x CAPACITE) : 365j partout = ~9 To >
# disque 7,3 To -> irrealiste. Paliers : 180j sources securite volume moyen
# (winsec/eset/vsphere/fortigate = 6 mois forensic), 90j sources gros volume
# ou faible valeur (sysmon/winother/bunkerweb/vaultwarden/fortimanager/interne),
# 365j haute-valeur faible-volume (m365). Projection ~5,3 To = 72%. NB : 31- et
# 41-retention-iso.sh sont OBSOLETES (contradictoires) -> ce script fait foi.
declare -A PLAN=(
  [omni-winsec]=180      [omni-winother]=90     [omni-sysmon]=90
  [omni-m365]=365        [omni-vsphere]=180     [omni-eset]=180
  [omni-fortigate]=180   [omni-bunkerweb]=90    [omni-vaultwarden]=90
  [omni-fortimanager]=90 [omni-interne]=90      [omni-aruba]=90
  [omni-linux]=90        [omni-cert]=90         [omni-fortidhcp]=90
  [omni-fortiems]=90     [omni-seal-access]=365 [omni-seal-alarm]=365
  [omni-seal-audit]=730
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

# --- [1/4] Migration rotation -> SizeOptimizing (suppression par AGE) ----------
# CAUSE RACINE de l'explosion de shards (incident 09/2026) : rotation P1D =>
# 1 index (= 1 shard) par JOUR et par source, y compris sources quasi muettes
# (aruba/linux/cert/fortiems ~1 Mo pour 50+ index). En regime permanent ce design
# reclamait ~3500 shards pour un plafond de 1000 -> mur atteint a ~54 j, UI lente.
# CORRECTIF : TimeBasedSizeOptimizingStrategy (comme les index sets natifs) +
# suppression par AGE via data_tiering hot_only (index_lifetime_max = RETENTION).
# La DUREE de retention est PRESERVEE a l'identique (PLAN, aligne POLITIQUE.md) ;
# seul le MECANISME change (age, pas nombre d'index) -> 1 a quelques index par
# source au lieu de 90/180/365/730. Aucune suppression anticipee : un index n'est
# supprime que lorsque sa date de creation depasse la retention.
echo "==> [1/4] Rotation SizeOptimizing (age-based) + impact suppression par age"
printf "    %-20s %-8s %-11s %-9s %s\n" PREFIXE "CIBLE(j)" ROTATION "AGE>CIBLE" ETAT
NOW_MS=$(( $(date +%s) * 1000 ))
SET_MIN="P30D"
TOTAL_SUPPR=0; ABORT=0
for PREFIX in $(printf '%s\n' "${!PLAN[@]}" | sort); do
  TARGET="${PLAN[$PREFIX]}"; MAXP="P${TARGET}D"
  ID="$(is_id "$PREFIX")"
  if [[ -z "$ID" || "$ID" == null ]]; then
    printf "    %-20s %-8s %-11s %-9s %s\n" "$PREFIX" "$TARGET" "-" "-" "index set ABSENT (ignore)"
    continue
  fi
  ROTCLASS="$(echo "$SETS" | jq -r --arg p "$PREFIX" '.index_sets[]|select(.index_prefix==$p)|.rotation_strategy_class|sub(".*\\.";"")')"
  CURMAX="$(echo "$SETS" | jq -r --arg p "$PREFIX" '.index_sets[]|select(.index_prefix==$p)|(.data_tiering.index_lifetime_max // .rotation_strategy.index_lifetime_max // "-")')"
  # index plus vieux que TARGET jours -> supprimes par l'age au prochain passage
  CUT_MS=$(( NOW_MS - TARGET*86400000 ))
  OLD=$(curl -s "${OS}/_cat/indices/${PREFIX}_*?h=index,creation.date" 2>/dev/null | awk -v c="$CUT_MS" '$2<c{n++} END{print n+0}')
  TOTAL_SUPPR=$(( TOTAL_SUPPR + OLD ))
  if [[ "$ROTCLASS" == "TimeBasedSizeOptimizingStrategy" && "$CURMAX" == "$MAXP" ]]; then
    ETAT="deja conforme"
  else
    ETAT="${ROTCLASS:-?} -> SizeOptimizing(max ${MAXP})"
  fi
  printf "    %-20s %-8s %-11s %-9s %s\n" "$PREFIX" "$TARGET" "${ROTCLASS:0:11}" "$OLD" "$ETAT"
  (( OLD > MAX_DELETE )) && ABORT=1
done
echo "    ------------------------------------------------------------------"
echo "    Index deja plus vieux que leur retention (supprimes par age a l'apply) : ${TOTAL_SUPPR}"

if (( ABORT == 1 && FORCE != 1 )); then
  warn "Au moins un prefixe supprimerait > ${MAX_DELETE} index par age. ARRET (securite)."
  warn "Verifier ci-dessus. Passer outre : FORCE=1 APPLY=1 ./83-retention-consolidee.sh"
  exit 2
fi

if [[ "$APPLY" != "1" ]]; then
  echo
  warn "DRY-RUN : aucune ecriture. Pour appliquer : APPLY=1 ./83-retention-consolidee.sh"
else
  echo
  echo "    APPLY=1 -> migration rotation + retention (idempotent)"
  for PREFIX in $(printf '%s\n' "${!PLAN[@]}" | sort); do
    TARGET="${PLAN[$PREFIX]}"; MAXP="P${TARGET}D"; ID="$(is_id "$PREFIX")"
    [[ -z "$ID" || "$ID" == null ]] && continue
    ROTCLASS="$(echo "$SETS" | jq -r --arg p "$PREFIX" '.index_sets[]|select(.index_prefix==$p)|.rotation_strategy_class|sub(".*\\.";"")')"
    CURMAX="$(echo "$SETS" | jq -r --arg p "$PREFIX" '.index_sets[]|select(.index_prefix==$p)|(.data_tiering.index_lifetime_max // .rotation_strategy.index_lifetime_max // "-")')"
    if [[ "$ROTCLASS" == "TimeBasedSizeOptimizingStrategy" && "$CURMAX" == "$MAXP" ]]; then
      skip "${PREFIX} deja SizeOptimizing(max ${MAXP})"; continue
    fi
    REP="$(echo "$SETS" | jq --arg p "$PREFIX" --arg min "$SET_MIN" --arg max "$MAXP" --argjson keep "$TARGET" '
      .index_sets[]|select(.index_prefix==$p)
      | .use_legacy_rotation=false
      | .rotation_strategy_class="org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategy"
      | .rotation_strategy={type:"org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategyConfig",index_lifetime_min:$min,index_lifetime_max:$max}
      | .retention_strategy_class="org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"
      | .retention_strategy={type:"org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",max_number_of_indices:$keep}
      | .data_tiering={type:"hot_only",index_lifetime_min:$min,index_lifetime_max:$max}
    ' | api_put "/system/indices/index_sets/${ID}")"
    echo "$REP" | jq -e '.id' >/dev/null 2>&1 \
      && ok "${PREFIX} -> SizeOptimizing(min ${SET_MIN}/max ${MAXP}), age-based" \
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