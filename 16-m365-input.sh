#!/usr/bin/env bash
# ==============================================================================
# 16-m365-input.sh - Reception Microsoft 365 / Entra ID
#   1. Input GELF HTTP 127.0.0.1:12201 (alimente par omni-m365-fetch, cf. 17)
#   2. Index set omni-m365 (rotation 1 j, retention 180 j - tracabilite cloud)
#      + profil omni-ip-fields (src_ip type ip)
#   3. Stream "OMNI - M365" (routage par input)
#   4. Pipeline de detection (les champs arrivent DEJA normalises du fetcher :
#      user, src_ip, src_country, event_action, m365_type, risk_state, app)
#   5. Alertes : connexion etrangere, compte a risque, modification de role,
#      force brute cloud
# Idempotent. Prerequis : 10-13. Suite : 17-m365-fetcher.sh puis 14 (dashboard).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

# ------------------------------------------------------------------ 1. Input
echo "==> [1/5] Input GELF HTTP 127.0.0.1:12201"
IN_GELF="$(api_get "/system/inputs" | jq -r '.inputs[] | select(.title=="M365 (GELF HTTP 12201)") | .id')"
if [[ -z "${IN_GELF}" ]]; then
  IN_GELF="$(api_post "/system/inputs" <<'EOF' | jqr '.id'
{
  "title": "M365 (GELF HTTP 12201)",
  "type": "org.graylog2.inputs.gelf.http.GELFHttpInput",
  "global": true,
  "configuration": {
    "bind_address": "127.0.0.1",
    "port": 12201,
    "recv_buffer_size": 1048576,
    "enable_bulk_receiving": true,
    "enable_cors": false,
    "max_chunk_size": 65536,
    "idle_writer_timeout": 60,
    "override_source": null,
    "decompress_size_limit": 8388608
  }
}
EOF
)"
  [[ -n "${IN_GELF}" && "${IN_GELF}" != "null" ]] && ok "input ${IN_GELF}" || die "creation input GELF"
else
  skip "input existe (${IN_GELF})"
fi

# -------------------------------------------------------------- 2. Index set
echo "==> [2/5] Index set omni-m365 (180 j)"
IS_M365="$(get_index_set_id "omni-m365")"
if [[ -z "${IS_M365}" ]]; then
  IS_M365="$(api_post "/system/indices/index_sets" <<EOF | jqr '.id'
{
  "title": "OMNI - Microsoft 365", "description": "Provisionne par 16-m365-input.sh",
  "index_prefix": "omni-m365", "shards": 1, "replicas": 0,
  "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
  "rotation_strategy": {"type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig", "rotation_period": "P1D", "rotate_empty_index_set": false},
  "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
  "retention_strategy": {"type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig", "max_number_of_indices": 180},
  "index_analyzer": "standard", "index_optimization_max_num_segments": 1,
  "index_optimization_disabled": false, "field_type_refresh_interval": 5000,
  "writable": true, "creation_date": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
}
EOF
)"
  [[ -n "${IS_M365}" && "${IS_M365}" != "null" ]] && ok "index set ${IS_M365}" || die "creation index set"
else
  skip "index set existe (${IS_M365})"
fi
PROFILE_ID="$(api_get "/system/indices/index_sets/profiles/all" | jq -r 'if type=="array" then . else (.elements // []) end | .[]? | select(.name=="omni-ip-fields") | .id' | head -1)"
if [[ -n "${PROFILE_ID}" ]]; then
  CUR="$(api_get "/system/indices/index_sets/${IS_M365}")"
  [[ "$(echo "${CUR}" | jq -r '.field_type_profile // empty')" == "${PROFILE_ID}" ]] \
    || echo "${CUR}" | jq --arg p "${PROFILE_ID}" '.field_type_profile = $p' | api_put "/system/indices/index_sets/${IS_M365}" >/dev/null
  ok "profil IP applique"
fi

# ------------------------------------------------------------------ 3. Stream
echo "==> [3/5] Stream 'OMNI - M365'"
ST_M365="$(get_stream_id 'OMNI - M365')"
if [[ -z "${ST_M365}" ]]; then
  ST_M365="$(jq -n --arg is "${IS_M365}" --arg in "${IN_GELF}" '{
      title: "OMNI - M365", description: "Provisionne par 16-m365-input.sh",
      index_set_id: $is, remove_matches_from_default_stream: true, matching_type: "AND",
      rules: [{type:1, field:"gl2_source_input", value:$in, inverted:false, description:"input GELF M365"}]
    }' | wrap_entity | api_post "/streams" | jqr '.stream_id')"
  [[ -n "${ST_M365}" && "${ST_M365}" != "null" ]] || die "creation stream"
  api_post "/streams/${ST_M365}/resume" </dev/null >/dev/null
  ok "stream ${ST_M365}"
else
  skip "stream existe (${ST_M365})"
fi

# ---------------------------------------------------------------- 4. Pipeline
echo "==> [4/5] Pipeline de detection M365"
ensure_rule "omni-m365-10-role-privilegie" <<'EOF'
rule "omni-m365-10-role-privilegie"
when
  to_string($message.m365_type) == "audit"
  AND contains(to_string($message.event_action), "member to role", true)
then
  set_field("alert_tag", "m365_role");
end
EOF

ensure_rule "omni-m365-10-compte-risque" <<'EOF'
rule "omni-m365-10-compte-risque"
when
  has_field("risk_state")
  AND to_string($message.risk_state) != "none"
  AND to_string($message.risk_state) != "dismissed"
  AND to_string($message.risk_state) != "remediated"
then
  set_field("alert_tag", "m365_risque");
end
EOF

ensure_rule "omni-m365-10-connexion-etrangere" <<'EOF'
rule "omni-m365-10-connexion-etrangere"
when
  to_string($message.m365_type) == "signin"
  AND to_string($message.event_action) == "connexion_reussie"
  AND has_field("src_country")
  AND to_string($message.src_country) != "FR"
then
  set_field("alert_tag", "m365_etranger");
  set_field("m365_foreign", 1);
end
EOF

PL_M365="$(ensure_pipeline "OMNI - M365" <<'EOF'
pipeline "OMNI - M365"
stage 10 match either
rule "omni-m365-10-role-privilegie"
rule "omni-m365-10-compte-risque"
rule "omni-m365-10-connexion-etrangere"
end
EOF
)"
connect_pipeline "${ST_M365}" "${PL_M365}"

# ----------------------------------------------------------------- 5. Alertes
echo "==> [5/5] Alertes M365"
NOTIF_ID="$(api_get "/events/notifications?per_page=100" | jq -r '(.notifications // [])[] | select(.title=="OMNI - Mail equipe IT") | .id')"
TEAMS_ID="$(api_get "/events/notifications?per_page=100" | jq -r '(.notifications // [])[] | select(.title=="OMNI - Teams SOC") | .id')"
NOTIFS="$(jq -n --arg e "${NOTIF_ID}" --arg t "${TEAMS_ID}" \
  '[{notification_id:$e, notification_parameters:null}] + (if $t != "" then [{notification_id:$t, notification_parameters:null}] else [] end)')"

ensure_event_m365() { # titre prio query group series cond within every
  local TITLE="$1" PRIO="$2" QUERY="$3" GROUPBY="$4" SERIES="$5" COND="$6" WITHIN="$7" EVERY="$8"
  local EXIST ID
  EXIST="$(api_get "/events/definitions?per_page=100" | jq -r --arg t "${TITLE}" '(.event_definitions // .elements // [])[] | select(.title==$t) | .id')"
  if [[ -n "${EXIST}" ]]; then skip "evenement '${TITLE}' existe"; return 0; fi
  ID="$(jq -n --arg t "${TITLE}" --argjson p "${PRIO}" --arg q "${QUERY}" --arg st "${ST_M365}" \
        --argjson gb "${GROUPBY}" --argjson se "${SERIES}" --argjson co "${COND}" \
        --argjson w "$(( WITHIN * 60000 ))" --argjson e "$(( EVERY * 60000 ))" --argjson n "${NOTIFS}" '{
    title: $t, description: ("P" + ($p|tostring) + " - provisionne par 16-m365-input.sh"),
    priority: $p, alert: true,
    config: { type: "aggregation-v1", query: $q, query_parameters: [], streams: [$st],
      group_by: $gb, series: $se, conditions: $co,
      search_within_ms: $w, execute_every_ms: $e, use_cron_scheduling: false, event_limit: 100 },
    field_spec: {}, key_spec: [],
    notification_settings: { grace_period_ms: 600000, backlog_size: 5 },
    notifications: $n
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  [[ -n "${ID}" && "${ID}" != "null" ]] && ok "evenement '${TITLE}'" || warn "evenement '${TITLE}' REFUSE"
}
NOCOND='{"expression":null}'
ensure_event_m365 "OMNI - M365 connexion réussie hors France" 3 \
  'alert_tag:m365_etranger' '[]' '[]' "${NOCOND}" 15 5
# Detection m365_risque : geree par 13-graylog-alerts.sh ("Compte M365 a risque
# (Entra ID Protection)") en mode AGREGE par compte (anti-spam, grace 6h) + mail.
# L'ancienne def filtre-mode ici faisait DOUBLON (1 alerte/evenement) -> retiree.
ensure_event_m365 "OMNI - M365 modification de rôle privilégié" 3 \
  'alert_tag:m365_role' '[]' '[]' "${NOCOND}" 15 5
ensure_event_m365 "OMNI - M365 force brute (>=10 échecs / compte / 30 min)" 2 \
  'm365_type:signin AND event_action:echec_connexion' '["user"]' \
  '[{"id":"count()","type":"count"}]' \
  '{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":10}}}' 30 10

echo
echo "=== 16-m365-input.sh termine. Lancer 17-m365-fetcher.sh ==="
