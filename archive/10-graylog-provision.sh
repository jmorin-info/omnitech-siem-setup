#!/usr/bin/env bash
# ==============================================================================
# 10-graylog-provision.sh - Provisioning du modele de donnees via l'API REST
#   1. Index sets  : omni-winsec / omni-sysmon / omni-winother / omni-fortigate
#                    (rotation 1 jour, retention differenciee, replicas=0)
#   2. Streams     : routage par input + canal Windows, retires du flux default
#   3. Pipeline    : normalisation -> champs communs event_id, event_source,
#                    target_user, src_ip, logon_type + parsing key=value Forti
#   4. Notification e-mail (relais interne) + 5 detections prioritaires :
#      bruteforce 4625, verrouillages 4740, Kerberoasting 4769/RC4,
#      DCSync 4662, acces LSASS (Sysmon 10)
#
# Idempotent : ne recree pas ce qui porte deja le meme titre/prefixe.
# Prerequis : scripts 04 et 07 passes (API up + inputs crees).
# NB schema API : si une detection est refusee (schema variable selon version
# mineure), le script affiche la reponse -> recette UI equivalente au README §9.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

API="http://127.0.0.1:9000/api"
CURL=(curl -s -u "admin:${GRAYLOG_ADMIN_PASS}" -H "Content-Type: application/json" -H "X-Requested-By: 10-provision")

jqr() { jq -r "$1" 2>/dev/null; }

# ----------------------------------------------------------------- Index sets
ensure_index_set() {  # $1 titre  $2 prefixe  $3 retention_jours  -> echo id
  local ID
  ID="$("${CURL[@]}" "${API}/system/indices/index_sets?skip=0&limit=200" \
        | jq -r --arg p "$2" '.index_sets[] | select(.index_prefix==$p) | .id')"
  if [[ -n "${ID}" ]]; then echo "${ID}"; return; fi
  ID="$("${CURL[@]}" -X POST "${API}/system/indices/index_sets" -d @- <<EOF | jqr '.id'
{
  "title": "$1",
  "description": "Provisionne par 10-graylog-provision.sh",
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
  [[ -n "${ID}" && "${ID}" != "null" ]] || { echo "ECHEC index set $1" >&2; exit 1; }
  echo "${ID}"
}

echo "==> [1/5] Index sets (1 index/jour, replicas=0 - mono-noeud)"
IS_WINSEC="$(ensure_index_set 'OMNI - Windows Security' 'omni-winsec'    90)"
IS_SYSMON="$(ensure_index_set 'OMNI - Sysmon'           'omni-sysmon'   60)"
IS_WINOTH="$(ensure_index_set 'OMNI - Windows autres'   'omni-winother' 60)"
IS_FORTI="$(ensure_index_set  'OMNI - FortiGate'        'omni-fortigate' 90)"
echo "    winsec=${IS_WINSEC} sysmon=${IS_SYSMON} winother=${IS_WINOTH} forti=${IS_FORTI}"
echo "    (retention en ligne 60-90 j ; le long terme = snapshots, cf. 08-backup)"

# ----------------------------------------------------------------- Inputs ids
echo "==> [2/5] Resolution des inputs (crees par 07-inputs.sh)"
INPUTS_JSON="$("${CURL[@]}" "${API}/system/inputs")"
IN_BEATS="$(jq -r '.inputs[] | select(.title|startswith("Winlogbeat")) | .id' <<<"${INPUTS_JSON}")"
IN_SYSTCP="$(jq -r '.inputs[] | select(.title|contains("Syslog TCP")) | .id' <<<"${INPUTS_JSON}")"
IN_SYSUDP="$(jq -r '.inputs[] | select(.title|contains("Syslog UDP")) | .id' <<<"${INPUTS_JSON}")"
[[ -n "${IN_BEATS}" ]] || { echo "ERREUR: input Beats introuvable (lancer 07-inputs.sh)"; exit 1; }
echo "    beats=${IN_BEATS} syslog_tcp=${IN_SYSTCP} syslog_udp=${IN_SYSUDP}"

# ----------------------------------------------------------------- Streams
ensure_stream() {  # $1 titre  $2 index_set_id  $3 matching  $4 JSON rules -> echo id
  local ID
  ID="$("${CURL[@]}" "${API}/streams" | jq -r --arg t "$1" '.streams[] | select(.title==$t) | .id')"
  if [[ -z "${ID}" ]]; then
    ID="$("${CURL[@]}" -X POST "${API}/streams" -d @- <<EOF | jqr '.stream_id'
{
  "title": "$1",
  "description": "Provisionne par 10-graylog-provision.sh",
  "index_set_id": "$2",
  "remove_matches_from_default_stream": true,
  "matching_type": "$3",
  "rules": $4
}
EOF
)"
    [[ -n "${ID}" && "${ID}" != "null" ]] || { echo "ECHEC stream $1" >&2; exit 1; }
    "${CURL[@]}" -X POST "${API}/streams/${ID}/resume" >/dev/null
  fi
  echo "${ID}"
}

echo "==> [3/5] Streams + regles de routage"
# type 1 = correspondance exacte ; inverted=true => "different de"
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
echo "    winsec=${ST_WINSEC} sysmon=${ST_SYSMON} winother=${ST_WINOTH} forti=${ST_FORTI}"

# ----------------------------------------------------------------- Pipelines
ensure_rule() {  # $1 titre ; source DSL sur stdin
  local SRC; SRC="$(cat)"
  local EXIST
  EXIST="$("${CURL[@]}" "${API}/system/pipelines/rule" | jq -r --arg t "$1" '.[] | select(.title==$t) | .id')"
  [[ -n "${EXIST}" ]] && { echo "    [=] regle '$1' existe."; return; }
  jq -n --arg t "$1" --arg s "${SRC}" '{title:$t, description:"10-provision", source:$s}' \
    | "${CURL[@]}" -X POST "${API}/system/pipelines/rule" -d @- | jq -r '"    [+] regle \(.title // "ECHEC") (\(.id // "voir reponse"))"'
}

echo "==> [4/5] Pipeline de normalisation (modele de donnees commun)"
ensure_rule "omni-win-base" <<'EOF'
rule "omni-win-base"
when
  has_field("winlogbeat_winlog_event_id")
then
  set_field("event_id", to_long($message.winlogbeat_winlog_event_id));
  set_field("event_source", "windows");
  set_field("host_name", lowercase(to_string($message.winlogbeat_host_name)));
end
EOF
ensure_rule "omni-win-auth" <<'EOF'
rule "omni-win-auth"
when
  has_field("winlogbeat_winlog_event_data_TargetUserName")
then
  set_field("target_user", lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName)));
  set_field("src_ip", to_string($message.winlogbeat_winlog_event_data_IpAddress));
  set_field("logon_type", to_string($message.winlogbeat_winlog_event_data_LogonType));
  set_field("src_workstation", to_string($message.winlogbeat_winlog_event_data_WorkstationName));
end
EOF
ensure_rule "omni-sysmon-base" <<'EOF'
rule "omni-sysmon-base"
when
  has_field("winlogbeat_winlog_channel") AND
  to_string($message.winlogbeat_winlog_channel) == "Microsoft-Windows-Sysmon/Operational"
then
  set_field("process_image", to_string($message.winlogbeat_winlog_event_data_Image));
  set_field("process_cmdline", to_string($message.winlogbeat_winlog_event_data_CommandLine));
  set_field("parent_image", to_string($message.winlogbeat_winlog_event_data_ParentImage));
  set_field("target_image", to_string($message.winlogbeat_winlog_event_data_TargetImage));
  set_field("dest_ip", to_string($message.winlogbeat_winlog_event_data_DestinationIp));
end
EOF
ensure_rule "omni-fortigate-kv" <<'EOF'
rule "omni-fortigate-kv"
when
  has_field("message") AND contains(to_string($message.message), "devname=")
then
  set_fields(
    fields: key_value(
      value: to_string($message.message),
      trim_value_chars: "\"",
      trim_key_chars: "\""
    )
  );
  set_field("event_source", "fortigate");
end
EOF

PIPE_ID="$("${CURL[@]}" "${API}/system/pipelines/pipeline" | jq -r '.[] | select(.title=="OMNI Normalisation") | .id')"
if [[ -z "${PIPE_ID}" ]]; then
  PIPE_SRC='pipeline "OMNI Normalisation"
stage 0 match either
rule "omni-win-base"
rule "omni-fortigate-kv"
stage 1 match either
rule "omni-win-auth"
rule "omni-sysmon-base"
end'
  PIPE_ID="$(jq -n --arg s "${PIPE_SRC}" '{title:"OMNI Normalisation", description:"10-provision", source:$s}' \
    | "${CURL[@]}" -X POST "${API}/system/pipelines/pipeline" -d @- | jqr '.id')"
  echo "    [+] pipeline 'OMNI Normalisation' (${PIPE_ID})"
fi
for SID in "${ST_WINSEC}" "${ST_SYSMON}" "${ST_WINOTH}" "${ST_FORTI}"; do
  jq -n --arg s "${SID}" --arg p "${PIPE_ID}" '{stream_id:$s, pipeline_ids:[$p]}' \
    | "${CURL[@]}" -X POST "${API}/system/pipelines/connections/to_stream" -d @- >/dev/null \
    && echo "    [~] pipeline connecte au stream ${SID}"
done

# ------------------------------------------------- Notification + detections
echo "==> [5/5] Notification e-mail + detections prioritaires"
NOTIF_ID="$("${CURL[@]}" "${API}/events/notifications?per_page=100" | jq -r '.notifications[]? | select(.title=="Mail RSSI") | .id')"
if [[ -z "${NOTIF_ID}" ]]; then
  NOTIF_ID="$("${CURL[@]}" -X POST "${API}/events/notifications" -d @- <<EOF | jqr '.id'
{
  "title": "Mail RSSI",
  "description": "Notification e-mail via relais interne",
  "config": {
    "type": "email-notification-v1",
    "sender": "${SMTP_FROM}",
    "subject": "[SIEM OMNITECH] \${event_definition_title}",
    "reply_to": "",
    "user_recipients": [],
    "email_recipients": ["${ALERT_EMAIL}"],
    "time_zone": "Europe/Paris",
    "body_template": "Alerte : \${event_definition_title}\nDate : \${event.timestamp}\nMessage : \${event.message}\nChamps : \${event.fields}\nConsole : https://${SIEM_FQDN}/alerts",
    "html_body_template": ""
  }
}
EOF
)"
  [[ -n "${NOTIF_ID}" && "${NOTIF_ID}" != "null" ]] && echo "    [+] notification 'Mail RSSI' (${NOTIF_ID})" \
    || echo "    [!] notification refusee -> creer via UI (Alerts > Notifications) puis relancer."
fi

ensure_eventdef() {  # $1 titre  $2 query  $3 stream  $4 group_by(json array)  $5 seuil  $6 fenetre_ms
  local EXIST
  EXIST="$("${CURL[@]}" "${API}/events/definitions?per_page=100" | jq -r --arg t "$1" '(.event_definitions // .entity // [])[] | select(.title==$t) | .id' | head -1)"
  [[ -n "${EXIST}" ]] && { echo "    [=] detection '$1' existe."; return; }
  RES="$("${CURL[@]}" -X POST "${API}/events/definitions?schedule=true" -d @- <<EOF
{
  "title": "$1",
  "description": "Provisionne par 10-graylog-provision.sh",
  "priority": 2,
  "alert": true,
  "config": {
    "type": "aggregation-v1",
    "query": "$2",
    "query_parameters": [],
    "streams": ["$3"],
    "group_by": $4,
    "series": [ { "id": "cnt", "type": "count" } ],
    "conditions": {
      "expression": {
        "expr": ">=",
        "left":  { "expr": "number-ref", "ref": "cnt" },
        "right": { "expr": "number", "value": $5 }
      }
    },
    "search_within_ms": $6,
    "execute_every_ms": 60000,
    "event_limit": 100
  },
  "field_spec": {},
  "key_spec": [],
  "notification_settings": { "grace_period_ms": 300000, "backlog_size": 10 },
  "notifications": [ { "notification_id": "${NOTIF_ID}" } ]
}
EOF
)"
  if echo "${RES}" | jq -e '.id' >/dev/null 2>&1; then
    echo "    [+] detection '$1'"
  else
    echo "    [!] detection '$1' refusee par l'API (schema) -> recette UI au README §9. Reponse :"
    echo "${RES}" | head -c 500 | sed 's/^/        /'; echo
  fi
}

ensure_eventdef "Bruteforce - echecs 4625 repetes" \
  "event_id:4625" "${ST_WINSEC}" '["target_user"]' 10 300000
ensure_eventdef "Compte verrouille (4740)" \
  "event_id:4740" "${ST_WINSEC}" '["target_user"]' 1 300000
ensure_eventdef "Kerberoasting suspect (4769 RC4)" \
  "event_id:4769 AND winlogbeat_winlog_event_data_TicketEncryptionType:0x17" \
  "${ST_WINSEC}" '["winlogbeat_winlog_event_data_ServiceName"]' 1 300000
ensure_eventdef "DCSync suspect (4662 replication)" \
  "event_id:4662 AND winlogbeat_winlog_event_data_Properties:*1131f6a*" \
  "${ST_WINSEC}" '["winlogbeat_winlog_event_data_SubjectUserName"]' 1 300000
ensure_eventdef "Acces memoire LSASS (Sysmon 10)" \
  "event_id:10 AND target_image:*lsass.exe" \
  "${ST_SYSMON}" '["winlogbeat_winlog_event_data_SourceImage"]' 1 300000

echo
echo "=== 10-graylog-provision.sh termine ==="
echo "    Verifier : System>Indices, Streams, System>Pipelines, Alerts>Event Definitions."
echo "    Dashboards : recettes pas-a-pas au README §9 (5 min chacun dans l'UI)."
