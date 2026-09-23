#!/usr/bin/env bash
# =============================================================================
# reclaim-shards-reindex.sh - Recuperation IMMEDIATE de shards (incident 09/2026)
#
#   Contexte : la rotation quotidienne (P1D) a cree des dizaines d'index (=shards)
#   par source, y compris pour des sources quasi muettes (aruba/linux/cert/
#   fortiems/fortimanager/fortidhcp/interne : ~1-300 Mo pour 50+ index). 83-
#   retention-consolidee.sh corrige la ROTATION (SizeOptimizing, age-based) pour
#   l'avenir, mais les index quotidiens DEJA crees ne s'effaceraient que par age
#   (semaines). Ce script les CONSOLIDE tout de suite, SANS PERTE :
#     1. reindexe tous les index en lecture seule d'un prefixe -> son index
#        d'ecriture courant (deflector), en preservant l'_id des messages ;
#     2. supprime les anciens index (shards liberes immediatement) ;
#     3. demande a Graylog de recalculer les plages d'index (ranges).
#
#   PERIMETRE : uniquement les sets NON-REGLEMENTAIRES quasi vides listes dans
#   PREFIXES. Ne touche PAS winsec/m365/seal/fortigate/vsphere/eset (forensic).
#
#   PREREQUIS : lancer d'abord `APPLY=1 ./83-retention-consolidee.sh` (bascule la
#   rotation en SizeOptimizing, min P30D) pour eviter toute rotation pendant la
#   reindexation.
#
#   DRY-RUN par defaut (n'ecrit RIEN). Appliquer : APPLY=1 ./reclaim-shards-reindex.sh
#   Garde-fou : refuse de supprimer > MAX_DELETE index par prefixe sans FORCE=1.
#   Idempotent : relance sans effet si un prefixe est deja consolide (1 index).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

OS="${OS_URL:-http://127.0.0.1:9200}"
APPLY="${APPLY:-0}"
FORCE="${FORCE:-0}"
MAX_DELETE="${MAX_DELETE:-80}"   # ces sets ont ~50-65 index -> plafond large

# Sets NON-REGLEMENTAIRES quasi muets, valides par le RSSI (14/09/2026).
PREFIXES=(omni-aruba omni-linux omni-cert omni-fortiems omni-fortimanager omni-fortidhcp omni-interne)

echo "=============================================================================="
echo " reclaim-shards-reindex.sh  (mode : $([[ $APPLY == 1 ]] && echo 'APPLY (ecriture)' || echo 'DRY-RUN (lecture seule)'))"
echo "=============================================================================="

# index d'ecriture courant (cible du deflector) d'un prefixe
write_index() { curl -s "${OS}/_cat/aliases/${1}_deflector?h=index" 2>/dev/null | awk 'NF{print $1; exit}'; }
docs_of()     { curl -s "${OS}/${1}/_count" 2>/dev/null | jq -r '.count // 0'; }

TOTAL_RECLAIM=0; ABORT=0
declare -A PLAN_DEL=()

for P in "${PREFIXES[@]}"; do
  WI="$(write_index "$P")"
  if [[ -z "$WI" ]]; then
    warn "${P} : pas d'alias d'ecriture (index set absent ?) -> ignore"; continue
  fi
  # tous les index du prefixe SAUF l'index d'ecriture
  mapfile -t OLD < <(curl -s "${OS}/_cat/indices/${P}_*?h=index,docs.count&s=index" 2>/dev/null | awk -v w="$WI" '$1!=w{print $1}')
  NBOLD="${#OLD[@]}"
  SUM_DOCS=0; for i in "${OLD[@]}"; do d="$(curl -s "${OS}/${i}/_count" 2>/dev/null | jq -r '.count // 0')"; SUM_DOCS=$(( SUM_DOCS + d )); done
  WI_DOCS="$(docs_of "$WI")"
  printf "  %-20s ecriture=%-16s a_consolider=%-3s docs_anciens=%-8s docs_ecriture=%s\n" "$P" "$WI" "$NBOLD" "$SUM_DOCS" "$WI_DOCS"
  if (( NBOLD == 0 )); then skip "${P} deja consolide (1 seul index)"; continue; fi
  (( NBOLD > MAX_DELETE )) && ABORT=1
  TOTAL_RECLAIM=$(( TOTAL_RECLAIM + NBOLD ))
  PLAN_DEL["$P"]="$WI"
done
echo "  ------------------------------------------------------------------"
echo "  Shards recuperables immediatement (index anciens a supprimer) : ${TOTAL_RECLAIM}"

if (( ABORT == 1 && FORCE != 1 )); then
  warn "Un prefixe depasse MAX_DELETE=${MAX_DELETE}. ARRET. Passer outre : FORCE=1 APPLY=1 ./reclaim-shards-reindex.sh"
  exit 2
fi

if [[ "$APPLY" != "1" ]]; then
  echo; warn "DRY-RUN : aucune ecriture. Appliquer : APPLY=1 ./reclaim-shards-reindex.sh"
  exit 0
fi

echo; echo "  APPLY=1 -> reindexation + suppression + recalcul des ranges"
RANGES_TODO=0
for P in "${!PLAN_DEL[@]}"; do
  WI="${PLAN_DEL[$P]}"
  mapfile -t OLD < <(curl -s "${OS}/_cat/indices/${P}_*?h=index&s=index" 2>/dev/null | awk -v w="$WI" '$1!=w{print $1}')
  (( ${#OLD[@]} == 0 )) && { skip "${P} rien a faire"; continue; }
  SRC_JSON="$(printf '%s\n' "${OLD[@]}" | jq -R . | jq -sc .)"
  BEFORE="$(docs_of "$WI")"
  SUM_DOCS=0; for i in "${OLD[@]}"; do d="$(docs_of "$i")"; SUM_DOCS=$(( SUM_DOCS + d )); done
  # 1) reindexation ASYNCHRONE (robuste gros volumes) + suivi de tache jusqu'a fin.
  #    preserve l'_id ; op_type index = idempotent (relance sans doublon).
  #    reprend une tache deja en cours vers la meme cible (evite un double lancement).
  TASK="$(curl -s "${OS}/_tasks?actions=*reindex&detailed=true" 2>/dev/null \
          | jq -r --arg d "$WI" '[.nodes[]?.tasks|to_entries[]?|select(.value.description|contains($d))|.key][0] // empty' 2>/dev/null)"
  if [[ -n "$TASK" ]]; then
    warn "${P} : reindexation deja en cours (task ${TASK}) -> attente de sa fin"
  else
    TASK="$(curl -s -X POST "${OS}/_reindex?wait_for_completion=false&slices=auto" \
            -H 'Content-Type: application/json' \
            -d "{\"conflicts\":\"proceed\",\"source\":{\"index\":${SRC_JSON},\"size\":5000},\"dest\":{\"index\":\"${WI}\",\"op_type\":\"index\"}}" 2>/dev/null | jq -r '.task // empty')"
  fi
  [[ -n "$TASK" ]] || { warn "${P} : lancement reindex KO"; continue; }
  RES=""
  for _ in $(seq 1 720); do   # jusqu'a ~1h (720 x 5s)
    TJSON="$(curl -s "${OS}/_tasks/${TASK}" 2>/dev/null)"
    [[ "$(echo "$TJSON" | jq -r '.completed // false' 2>/dev/null)" == "true" ]] && { RES="$(echo "$TJSON" | jq -c '.response' 2>/dev/null)"; break; }
    sleep 5
  done
  [[ -n "$RES" && "$RES" != "null" ]] || { warn "${P} : reindex non terminee (suivre: curl ${OS}/_tasks/${TASK})"; continue; }
  curl -s -X POST "${OS}/${WI}/_refresh" >/dev/null 2>&1
  FAIL="$(echo "$RES" | jq -r '(.failures|length) // 0' 2>/dev/null)"
  CREATED="$(echo "$RES" | jq -r '.created // 0' 2>/dev/null)"
  UPDATED="$(echo "$RES" | jq -r '.updated // 0' 2>/dev/null)"
  AFTER="$(docs_of "$WI")"
  if [[ "$FAIL" != "0" || -z "$CREATED" ]]; then
    warn "${P} : reindexation en echec (failures=${FAIL}) -> AUCUNE suppression. Detail: $(echo "$RES" | head -c 200)"
    continue
  fi
  ok "${P} : reindexe -> ${WI} (created=${CREATED} updated=${UPDATED}) docs ${BEFORE} -> ${AFTER} (attendu +${SUM_DOCS})"
  # 2) securite : ne supprimer que si l'index d'ecriture a bien absorbe les docs
  if (( AFTER + 0 < BEFORE + 0 )); then
    warn "${P} : docs cible en baisse (anormal) -> suppression annulee"
    continue
  fi
  # 3) suppression des anciens index
  DELN=0
  for i in "${OLD[@]}"; do
    if curl -s -X DELETE "${OS}/${i}" 2>/dev/null | jq -e '.acknowledged==true' >/dev/null 2>&1; then
      DELN=$(( DELN + 1 ))
    else
      warn "${P} : echec suppression ${i}"
    fi
  done
  ok "${P} : ${DELN}/${#OLD[@]} anciens index supprimes (shards liberes)"
  RANGES_TODO=1
done

# 4) recalcul des plages d'index cote Graylog (une seule fois, global)
if (( RANGES_TODO == 1 )); then
  echo; echo "  Recalcul des plages d'index Graylog (ranges rebuild)..."
  if echo '{}' | api_post "/system/indices/ranges/rebuild" >/dev/null 2>&1; then
    ok "recalcul des ranges declenche"
  else
    warn "recalcul des ranges : echec API (a relancer depuis System > Indices > Maintenance)"
  fi
fi

echo; echo "=== reclaim-shards-reindex.sh termine (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)). ==="
echo "    Verifier : curl -s ${OS}/_cluster/health | jq .active_shards"
