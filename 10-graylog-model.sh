#!/usr/bin/env bash
# ==============================================================================
# 10-graylog-model.sh - Modele de donnees Graylog (remplace 10-graylog-provision)
#   1. Index sets   : omni-winsec / omni-sysmon / omni-winother / omni-fortigate
#                     (rotation 1 jour, retention differenciee, replicas=0)
#   2. Profil de types de champs "omni-ip-fields" : src_ip / dest_ip en type
#      OpenSearch "ip" -> recherches CIDR possibles (src_ip:"10.33.0.0/16")
#   3. Streams      : routage par input + canal Windows, retires du flux default
#
# Compatible Graylog 7.x : POST /streams exige l'enveloppe CreateEntityRequest
# (entity + share_request) - cf. lib-graylog.sh::wrap_entity.
# Idempotent. Prerequis : 04 (API up) + 07 (inputs crees).
# Suite : 11-graylog-enrichment.sh
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

# ----------------------------------------------------------------- Index sets
ensure_index_set() {  # $1 titre  $2 prefixe  $3 retention_jours  -> echo id
  local ID; ID="$(get_index_set_id "$2")"
  if [[ -n "${ID}" ]]; then echo "${ID}"; return; fi
  ID="$(api_post "/system/indices/index_sets" <<EOF | jqr '.id'
{
  "title": "$1",
  "description": "Provisionne par 10-graylog-model.sh",
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

echo "==> [1/3] Index sets (1 index/jour, replicas=0 - mono-noeud)"
IS_WINSEC="$(ensure_index_set 'OMNI - Windows Security' 'omni-winsec'     90)"
IS_SYSMON="$(ensure_index_set 'OMNI - Sysmon'           'omni-sysmon'    60)"
IS_WINOTH="$(ensure_index_set 'OMNI - Windows autres'   'omni-winother'  60)"
IS_FORTI="$(ensure_index_set  'OMNI - FortiGate'        'omni-fortigate' 180)"  # 180j (~1.8To) : compromis forensique/disque (audit 2026-06-14)
echo "    winsec=${IS_WINSEC} sysmon=${IS_SYSMON} winother=${IS_WINOTH} forti=${IS_FORTI}"
echo "    (retention en ligne 60-90 j ; long terme = snapshots, cf. 08-backup)"

# -------------------------------------------- Profil de types de champs (ip)
# Champs normalises par les pipelines -> type "ip" pour les recherches CIDR.
echo "==> [2/3] Profil de types de champs 'omni-ip-fields' (src_ip/dest_ip -> ip)"
PROFILE_ID="$(api_get "/system/indices/index_sets/profiles/all" \
              | jq -r 'if type=="array" then . else (.elements // []) end
                       | .[]? | select(.name=="omni-ip-fields") | .id' | head -1)"
if [[ -z "${PROFILE_ID}" || "${PROFILE_ID}" == "null" ]]; then
  PROFILE_ID="$(api_post "/system/indices/index_sets/profiles" <<'EOF' | jqr '.id'
{
  "name": "omni-ip-fields",
  "description": "Champs IP normalises OMNI (recherches CIDR)",
  "custom_field_mappings": [
    { "field": "src_ip",  "type": "ip" },
    { "field": "dest_ip", "type": "ip" }
  ]
}
EOF
)"
fi
if [[ -n "${PROFILE_ID}" && "${PROFILE_ID}" != "null" ]]; then
  ok "profil ${PROFILE_ID}"
  # Profil applique a TOUS les index sets OMNI sources (recupere dynamiquement) :
  # couvre vsphere/eset/m365/bunkerweb/vaultwarden crees par 19/52/55 (sur re-run de 10).
  # src_ip/dest_ip sont normalises en IP valide par les pipelines (regex stricte).
  for ISID in $(api_get "/system/indices/index_sets?limit=200" | jq -r '.index_sets[]? | select(.index_prefix|startswith("omni-")) | .id'); do
    CUR="$(api_get "/system/indices/index_sets/${ISID}")"
    if [[ "$(echo "${CUR}" | jq -r '.field_type_profile // empty')" == "${PROFILE_ID}" ]]; then
      skip "profil deja applique a ${ISID}"
    else
      echo "${CUR}" | jq --arg p "${PROFILE_ID}" '.field_type_profile = $p' \
        | api_put "/system/indices/index_sets/${ISID}" >/dev/null \
        && ok "profil applique a ${ISID}" || warn "profil non applique a ${ISID}"
    fi
  done
else
  warn "profil refuse par l'API -> recherches CIDR indisponibles (non bloquant)"
fi

# ----------------------------------------------------------------- Inputs ids
echo "==> [3/3] Streams + regles de routage"
INPUTS_JSON="$(api_get "/system/inputs")"
IN_BEATS="$(jq -r '.inputs[] | select(.title|startswith("Winlogbeat")) | .id' <<<"${INPUTS_JSON}")"
IN_SYSTCP="$(jq -r '.inputs[] | select(.title|contains("Syslog TCP")) | .id' <<<"${INPUTS_JSON}")"
IN_SYSUDP="$(jq -r '.inputs[] | select(.title|contains("Syslog UDP")) | .id' <<<"${INPUTS_JSON}")"
[[ -n "${IN_BEATS}" ]] || die "input Beats introuvable (lancer 07-inputs.sh)"
echo "    inputs: beats=${IN_BEATS} syslog_tcp=${IN_SYSTCP} syslog_udp=${IN_SYSUDP}"

# ensure_stream <titre> <index_set_id> <matching> <rules_json> -> echo id
# type 1 = correspondance exacte ; inverted=true => "different de"
ensure_stream() {
  local ID; ID="$(get_stream_id "$1")"
  if [[ -z "${ID}" ]]; then
    ID="$(jq -n --arg t "$1" --arg is "$2" --arg m "$3" --argjson r "$4" '{
            title: $t,
            description: "Provisionne par 10-graylog-model.sh",
            index_set_id: $is,
            remove_matches_from_default_stream: true,
            matching_type: $m,
            rules: $r
          }' | wrap_entity | api_post "/streams" | jqr '.stream_id')"
    [[ -n "${ID}" && "${ID}" != "null" ]] || die "creation stream $1"
    api_post "/streams/${ID}/resume" </dev/null >/dev/null
    ok "stream '$1' (${ID})" >&2
  else
    skip "stream '$1' existe (${ID})" >&2
  fi
  echo "${ID}"
}

ST_WINSEC="$(ensure_stream 'OMNI - Windows Security' "${IS_WINSEC}" "AND" "[
  {\"type\":1,\"field\":\"gl2_source_input\",\"value\":\"${IN_BEATS}\",\"inverted\":false,\"description\":\"input Beats\"},
  {\"type\":1,\"field\":\"winlogbeat_winlog_channel\",\"value\":\"Security\",\"inverted\":false,\"description\":\"canal Security\"}]")"

ST_SYSMON="$(ensure_stream 'OMNI - Sysmon' "${IS_SYSMON}" "AND" "[
  {\"type\":1,\"field\":\"gl2_source_input\",\"value\":\"${IN_BEATS}\",\"inverted\":false,\"description\":\"input Beats\"},
  {\"type\":1,\"field\":\"winlogbeat_winlog_channel\",\"value\":\"Microsoft-Windows-Sysmon/Operational\",\"inverted\":false,\"description\":\"canal Sysmon\"}]")"

ST_WINOTH="$(ensure_stream 'OMNI - Windows autres' "${IS_WINOTH}" "AND" "[
  {\"type\":1,\"field\":\"gl2_source_input\",\"value\":\"${IN_BEATS}\",\"inverted\":false,\"description\":\"input Beats\"},
  {\"type\":1,\"field\":\"winlogbeat_winlog_channel\",\"value\":\"Security\",\"inverted\":true,\"description\":\"hors Security\"},
  {\"type\":1,\"field\":\"winlogbeat_winlog_channel\",\"value\":\"Microsoft-Windows-Sysmon/Operational\",\"inverted\":true,\"description\":\"hors Sysmon\"}]")"

FORTI_RULES="[{\"type\":1,\"field\":\"gl2_source_input\",\"value\":\"${IN_SYSTCP}\",\"inverted\":false,\"description\":\"syslog TCP FAZ\"}"
[[ -n "${IN_SYSUDP}" ]] && FORTI_RULES+=",{\"type\":1,\"field\":\"gl2_source_input\",\"value\":\"${IN_SYSUDP}\",\"inverted\":false,\"description\":\"syslog UDP FAZ\"}"
FORTI_RULES+="]"
ST_FORTI="$(ensure_stream 'OMNI - FortiGate' "${IS_FORTI}" "OR" "${FORTI_RULES}")"

echo "    streams: winsec=${ST_WINSEC} sysmon=${ST_SYSMON} winother=${ST_WINOTH} forti=${ST_FORTI}"
echo
echo "=== 10-graylog-model.sh termine. Lancer 11-graylog-enrichment.sh ==="
