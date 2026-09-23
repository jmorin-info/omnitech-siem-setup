#!/usr/bin/env bash
# =============================================================================
# revert-index-rotation-legacy.sh - RETOUR ARRIERE d'urgence (incident 09/2026).
#
#   La migration 83 vers TimeBasedSizeOptimizing + data_tiering hot_only a
#   provoque une SUPPRESSION PREMATUREE : sur cette version de Graylog, le
#   data_tiering HotOnly a supprime des index a ~30 j au lieu de la retention
#   demandee (index_lifetime_max 90/180/365/730 NON honore). Pertes constatees :
#   vsphere/m365/seal (anterieur a mi-aout). winsec/sysmon/winother preserves.
#
#   Ce script REVIENT a la configuration LEGACY qui a tourne 3 mois sans jamais
#   supprimer prematurement :
#     - use_legacy_rotation = true
#     - rotation TimeBasedRotationStrategy, rotation_period = P1D
#     - retention DeletionRetentionStrategy, max_number_of_indices = <jours>
#     - data_tiering = null  (desactive le HotOnly fautif)
#   Aucune suppression a l'application (les compteurs d'index courants << seuil).
#   La croissance quotidienne de shards redevient effective mais le plafond est
#   a 3000 (on est a ~157) : des mois de marge. L'optimisation shards sera
#   retravaillee proprement plus tard (rotation hebdo testee set par set).
#
#   DRY-RUN par defaut. Appliquer : APPLY=1 ./revert-index-rotation-legacy.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
APPLY="${APPLY:-0}"

# prefixe -> retention en JOURS (= config legacy d'origine, rotation P1D)
declare -A DAYS=(
  [omni-winsec]=180 [omni-winother]=90 [omni-sysmon]=90 [omni-m365]=365
  [omni-vsphere]=180 [omni-eset]=180 [omni-fortigate]=180 [omni-bunkerweb]=90
  [omni-vaultwarden]=90 [omni-fortimanager]=90 [omni-interne]=90 [omni-aruba]=90
  [omni-linux]=90 [omni-cert]=90 [omni-fortidhcp]=90 [omni-fortiems]=90
  [omni-seal-access]=365 [omni-seal-alarm]=365 [omni-seal-audit]=730
)

SETS="$(api_get '/system/indices/index_sets?skip=0&limit=200')"
is_id() { echo "$SETS" | jq -r --arg p "$1" '.index_sets[]|select(.index_prefix==$p)|.id'; }

echo "=== revert-index-rotation-legacy.sh (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)) ==="
for PREFIX in $(printf '%s\n' "${!DAYS[@]}" | sort); do
  KEEP="${DAYS[$PREFIX]}"; ID="$(is_id "$PREFIX")"
  [[ -z "$ID" || "$ID" == null ]] && { warn "${PREFIX} absent"; continue; }
  CURROT="$(echo "$SETS" | jq -r --arg p "$PREFIX" '.index_sets[]|select(.index_prefix==$p)|.rotation_strategy_class|sub(".*\\.";"")')"
  NEW="$(echo "$SETS" | jq --arg p "$PREFIX" --argjson keep "$KEEP" '
    .index_sets[]|select(.index_prefix==$p)
    | .use_legacy_rotation=true
    | .rotation_strategy_class="org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"
    | .rotation_strategy={type:"org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",rotation_period:"P1D",rotate_empty_index_set:false,max_rotation_period:null}
    | .retention_strategy_class="org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"
    | .retention_strategy={type:"org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",max_number_of_indices:$keep}
    | .data_tiering=null
  ')"
  if [[ "$APPLY" != "1" ]]; then
    echo "  [DRY] ${PREFIX}: ${CURROT} -> TimeBasedRotation(P1D)+Deletion(keep=${KEEP}), data_tiering=null"
    continue
  fi
  REP="$(echo "$NEW" | api_put "/system/indices/index_sets/${ID}")"
  echo "$REP" | jq -e '.id' >/dev/null 2>&1 \
    && ok "${PREFIX}: revert legacy P1D + keep=${KEEP} (data_tiering off)" \
    || warn "${PREFIX}: echec -> $(echo "$REP" | head -c 200)"
done
echo "=== termine. Verifier: aucune suppression ne doit se declencher (compteurs << seuil). ==="
