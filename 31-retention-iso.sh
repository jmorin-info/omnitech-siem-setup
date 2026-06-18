#!/usr/bin/env bash
# =============================================================================
# 31-retention-iso.sh - Retentions des index sets alignees ISO 27001 (12/06/2026)
# -----------------------------------------------------------------------------
# Base : volumetrie MESUREE le 12/06 (apres activation UTM FortiGate), disque
# /data de 7,3 To dedie. Rotation quotidienne -> retention = nb d'indices.
#   winsec    365 j (~5,5 Go/j -> ~2,0 To)   auth/AD : 1 an (ANSSI/CNIL)
#   winother  365 j (~2,7 Go/j -> ~1,0 To)   comptes, Veeam, Defender
#   m365      365 j (<0,1 Go/j -> negligeable)
#   sysmon    180 j (~1,8 Go/j -> ~0,33 To)  telemetrie endpoint
#   vsphere   180 j (~1,7 Go/j -> ~0,31 To)
#   fortigate 180 j (~11 Go/j  -> ~2,0 To)   le plus volumineux (traffic+UTM)
# TOTAL projete a saturation : ~5,6 To (~77 % de /data). Revue MENSUELLE :
# si fortigate gonfle, options = 120 j OU split traffic/UTM en 2 index sets.
# Idempotent. Relancer apres tout re-run de 10-graylog-model.sh.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh
require_api

declare -A PLAN=(
  [omni-winsec]=365  [omni-winother]=365 [omni-m365]=365
  [omni-sysmon]=180  [omni-vsphere]=180  [omni-fortigate]=180
)

SETS="$(api_get "/system/indices/index_sets?skip=0&limit=100")"
for PREFIX in "${!PLAN[@]}"; do
  J="${PLAN[$PREFIX]}"
  ID="$(echo "${SETS}" | jq -r --arg p "${PREFIX}" '.index_sets[] | select(.index_prefix==$p) | .id')"
  if [[ -z "${ID}" || "${ID}" == "null" ]]; then warn "index set '${PREFIX}' introuvable"; continue; fi
  REP="$(echo "${SETS}" \
    | jq --arg p "${PREFIX}" --argjson j "${J}" \
        '.index_sets[] | select(.index_prefix==$p)
         | .retention_strategy.max_number_of_indices = $j' \
    | api_put "/system/indices/index_sets/${ID}")"
  if echo "${REP}" | jq -e '.id' >/dev/null 2>&1; then
    ok "${PREFIX} -> retention ${J} jours"
  else
    warn "${PREFIX} : echec -> $(echo "${REP}" | head -c 200)"
  fi
done
echo "=== 31-retention-iso.sh termine ==="
