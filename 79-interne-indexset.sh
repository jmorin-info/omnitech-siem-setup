#!/usr/bin/env bash
# =============================================================================
# 79-interne-indexset.sh - Donne un index set DEDIE au stream "OMNI - Interne SIEM".
#   BUG corrige : ce stream pointait sur le Default index set (prefixe 'graylog')
#   -> tous les evenements internes reinjectes (ueba_score ~74k, collecte_sla,
#   siem_health, xdr_incident, ml_anomaly) atterrissaient dans graylog_0, INVISIBLES
#   a la console/PWA qui lit 'omni-*'. La console se rabattait donc sur un risque
#   heuristique au lieu du vrai score UEBA.
#   Fix : index set 'omni-interne' (90 j) + rattachement du stream. Les NOUVEAUX
#   evenements internes deviennent visibles via 'omni-*'. L'historique reste dans
#   graylog_0 (pas de migration).
# Idempotent. Prerequis : 21 (stream interne).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

ensure_index_set() {  # $1 titre  $2 prefixe  $3 retention_jours -> echo id
  local ID; ID="$(get_index_set_id "$2")"
  if [[ -n "${ID}" ]]; then echo "${ID}"; return; fi
  ID="$(api_post "/system/indices/index_sets" <<EOF | jqr '.id'
{
  "title": "$1",
  "description": "Provisionne par 79-interne-indexset.sh (analytics internes)",
  "index_prefix": "$2",
  "shards": 1,
  "replicas": 0,
  "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
  "rotation_strategy": {
    "type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",
    "rotation_period": "P1D",
    "rotate_empty_index_set": false
  },
  "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
  "retention_strategy": {
    "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
    "max_number_of_indices": $3
  },
  "index_analyzer": "standard",
  "index_optimization_max_num_segments": 1,
  "index_optimization_disabled": false,
  "field_type_refresh_interval": 5000,
  "writable": true,
  "creation_date": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
}
EOF
)"
  [[ -n "${ID}" && "${ID}" != "null" ]] || die "creation index set $1"
  echo "${ID}"
}

echo "==> [1/3] Index set 'omni-interne' (retention 90 j)"
ISID="$(ensure_index_set 'OMNI - Interne SIEM' 'omni-interne' 90)"
ok "index set omni-interne = ${ISID}"

echo "==> [2/3] Rattachement du stream 'OMNI - Interne SIEM'"
ST="$(get_stream_id 'OMNI - Interne SIEM')"; [[ -n "$ST" ]] || die "stream interne introuvable (lancer 21)"
CUR="$(api_get "/streams/${ST}")"
CURIS="$(jq -r '.index_set_id' <<<"$CUR")"
if [[ "$CURIS" == "$ISID" ]]; then
  skip "stream deja sur omni-interne"
else
  # UpdateStreamRequest : title/description/matching_type/remove_matches.../index_set_id
  # (les regles du stream sont une sous-ressource, preservees.)
  BODY="$(jq -c --arg is "$ISID" '{title:.title, description:(.description//"OMNI - Interne SIEM"),
            matching_type:(.matching_type//"AND"),
            remove_matches_from_default_stream:(.remove_matches_from_default_stream//true),
            index_set_id:$is}' <<<"$CUR")"
  echo "$BODY" | api_put "/streams/${ST}" >/dev/null && ok "stream rattache a omni-interne (etait: ${CURIS})" || die "echec rattachement"
fi

echo "==> [3/3] Verification"
NEWIS="$(api_get "/streams/${ST}" | jq -r '.index_set_id')"
echo "    index_set_id du stream : ${NEWIS} (attendu ${ISID})"
echo
echo "=== 79 termine. Les NOUVEAUX evenements internes (ueba/health/sla/xdr/ml)"
echo "    iront dans omni-interne_* -> visibles via omni-* (console). Ajouter"
echo "    omni-interne=90j au document de politique de retention."
