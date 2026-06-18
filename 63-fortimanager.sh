#!/usr/bin/env bash
# =============================================================================
# 63-fortimanager.sh - Integration des logs FortiManager (10.33.80.252)
#   - Input Syslog TCP+UDP dedie (port ${FMG_PORT}, defaut 1517)
#   - Stream "OMNI - FortiManager" (route par gl2_remote_ip = FMG) + index set
#     omni-fortimanager (365j : audit des changements de config = ISO A.8.32)
#   - Pipeline "OMNI - FortiManager" : parse key=value -> normalise (user,
#     event_action, src_ip depuis userfrom) -> tags (login admin echoue / reussi,
#     changement de config / install de policy)
#   - MITRE (fmg_admin_login_fail = T1110) + 1 alerte (echecs de login admin)
#   Idempotent. Prerequis : 06 (pare-feu) + 07 (inputs) + 12 + 37 (MITRE).
#   RESTE COTE JULIEN : (1) ouvrir le flux FortiGate + nftables 10.33.80.252 ->
#   SIEM ${FMG_PORT} ; (2) cote FortiManager : System Settings > Advanced >
#   Syslog Server -> 10.33.220.10 port ${FMG_PORT} (ou `config system locallog
#   syslogd setting`). Relancer 13 + 14 ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

FMG_IP="${FMG_IP:-10.33.80.252}"
FMG_PORT="${FMG_PORT:-1517}"
FMG_INPUT="FortiManager (Syslog ${FMG_PORT})"

echo "==> [1/4] Inputs Syslog TCP+UDP FortiManager (port ${FMG_PORT})"
create_input() {  # titre json
  local T="$1" J="$2"
  if api_get "/system/inputs" | jq -e --arg t "$T" '.inputs[]|select(.title==$t)' >/dev/null; then
    skip "input '${T}' existe"
  else
    echo "$J" | post_entity "/system/inputs" | jqr '.id' >/dev/null && ok "input '${T}' cree" || warn "input '${T}' refuse"
  fi
}
for PROTO in tcp udp; do
  TYPE="org.graylog2.inputs.syslog.${PROTO}.Syslog$( [[ $PROTO == tcp ]] && echo TCP || echo UDP )Input"
  create_input "${FMG_INPUT} ${PROTO^^}" "$(cat <<EOF
{ "title": "${FMG_INPUT} ${PROTO^^}",
  "type": "${TYPE}", "global": true,
  "configuration": { "bind_address": "0.0.0.0", "port": ${FMG_PORT},
    "recv_buffer_size": 1048576, "number_worker_threads": 2,
    "force_rdns": false, "allow_override_date": true, "store_full_message": true,
    "expand_structured_data": true $( [[ $PROTO == tcp ]] && echo ', "tls_enable": false' ) } }
EOF
)"
done

echo "==> [2/4] Stream 'OMNI - FortiManager' + index set (route par gl2_remote_ip)"
IDX_DEFAULT="$(api_get '/system/indices/index_sets?limit=200' | jq -r '.index_sets[]|select(.index_prefix=="graylog")|.id')"
if [[ -z "$(get_stream_id 'OMNI - FortiManager')" ]]; then
  jq -n --arg t "OMNI - FortiManager" --arg d "Logs FortiManager (admin, changements de config)" \
        --arg idx "$IDX_DEFAULT" --arg ip "$FMG_IP" \
    '{title:$t, description:$d, matching_type:"AND", remove_matches_from_default_stream:true,
      index_set_id:$idx, rules:[{field:"gl2_remote_ip",type:1,value:$ip,inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read -r SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree ($SID)"; } || warn "stream refuse"; }
else skip "stream 'OMNI - FortiManager' existe"; fi
ST_FMG="$(get_stream_id 'OMNI - FortiManager')"

# Index set dedie (clone du modele omni-fortigate, 365j pour l'audit des changements)
IDX_FMG="$(api_get '/system/indices/index_sets?limit=200' | jq -r '.index_sets[]|select(.index_prefix=="omni-fortimanager")|.id')"
if [[ -z "$IDX_FMG" ]]; then
  IDX_FMG="$(api_get '/system/indices/index_sets?limit=200' | jq -c '.index_sets[]|select(.index_prefix=="omni-fortigate")' \
    | jq 'del(.id,.creation_date,.default,.can_be_default) | .title="OMNI - FortiManager" | .index_prefix="omni-fortimanager" | .description="Logs FortiManager (audit config 365j)" | .retention_strategy.max_number_of_indices=365' \
    | api_post '/system/indices/index_sets' | jqr '.id')"
  [[ -n "$IDX_FMG" && "$IDX_FMG" != null ]] && ok "index set 'OMNI - FortiManager' cree" || warn "index set refuse"
else skip "index set omni-fortimanager existe"; fi
if [[ -n "$ST_FMG" && -n "$IDX_FMG" && "$IDX_FMG" != null ]]; then
  CUR="$(api_get "/streams/${ST_FMG}" | jq -r '.index_set_id')"
  if [[ "$CUR" != "$IDX_FMG" ]]; then
    api_get "/streams/${ST_FMG}" | jq -c '{title,description,matching_type,remove_matches_from_default_stream,index_set_id:"'"$IDX_FMG"'"}' \
      | "${CURL[@]}" -X PUT "${API}/streams/${ST_FMG}" -H 'Content-Type: application/json' -d @- >/dev/null 2>&1 \
      && ok "stream reaffecte a l'index set omni-fortimanager"
  else skip "stream deja sur omni-fortimanager"; fi
fi

echo "==> [3/4] Pipeline 'OMNI - FortiManager' (parse + normalise + tags)"
# Stage 0 : parse key=value (format FortiManager, comme FortiOS) + event_source.
# La regle matche TOUTE message -> sert aussi de garde anti-HALT du stage 0.
ensure_rule "omni-fmg-00-parse" <<'EOF'
rule "omni-fmg-00-parse"
when
  has_field("message")
then
  set_fields(key_value(
    value: to_string($message.message),
    delimiters: " ", kv_delimiters: "=",
    ignore_empty_values: true, trim_value_chars: " \""
  ));
  set_field("event_source", "fortimanager");
  set_field("event_category", "config_mgmt");
end
EOF
# Stage 5 : normalisation. event_source==fortimanager est toujours vrai ici
# (pose au stage 0) -> garde anti-HALT du stage 5.
ensure_rule "omni-fmg-05-normalise" <<'EOF'
rule "omni-fmg-05-normalise"
when
  to_string($message.event_source) == "fortimanager"
then
  set_field("event_action", lowercase(to_string($message.action, to_string($message.subtype, "event"))));
  // src_ip : extrait l'IP de 'userfrom' (ex "GUI(10.33.50.10)") ou 'remote_ip'
  let g = grok(pattern: "%{IPV4:src_ip}", value: to_string($message.userfrom, to_string($message.remote_ip, "")), only_named_captures: true);
  set_fields(g);
end
EOF
# Stage 10 : detections (login admin echoue/reussi, changement de config).
ensure_rule "omni-fmg-10-login-fail" <<'EOF'
rule "omni-fmg-10-login-fail"
when
  to_string($message.event_source) == "fortimanager"
  AND ( contains(lowercase(to_string($message.msg)), "login failed")
     OR contains(lowercase(to_string($message.logdesc)), "login fail")
     OR ( contains(lowercase(to_string($message.action)), "login")
          AND ( contains(lowercase(to_string($message.status)), "fail")
             OR contains(lowercase(to_string($message.result)), "fail") ) ) )
then
  set_field("alert_tag", "fmg_admin_login_fail");
end
EOF
ensure_rule "omni-fmg-10-login-ok" <<'EOF'
rule "omni-fmg-10-login-ok"
when
  to_string($message.event_source) == "fortimanager"
  AND contains(lowercase(to_string($message.action)), "login")
  AND ( contains(lowercase(to_string($message.status)), "success")
     OR contains(lowercase(to_string($message.result)), "success") )
then
  set_field("alert_tag", "fmg_admin_login");
end
EOF
ensure_rule "omni-fmg-10-config-change" <<'EOF'
rule "omni-fmg-10-config-change"
when
  to_string($message.event_source) == "fortimanager"
  AND ( contains(lowercase(to_string($message.action)), "edit")
     OR contains(lowercase(to_string($message.action)), "add")
     OR contains(lowercase(to_string($message.action)), "delete")
     OR contains(lowercase(to_string($message.action)), "update")
     OR contains(lowercase(to_string($message.action)), "install")
     OR contains(lowercase(to_string($message.action)), "import") )
then
  set_field("alert_tag", "fmg_config_change");
end
EOF
# Garde anti-HALT du stage 10 : matche toute source FMG, ne fait rien.
ensure_rule "omni-fmg-10-pass" <<'EOF'
rule "omni-fmg-10-pass"
when to_string($message.event_source) == "fortimanager"
then let noop = true;
end
EOF

PL="$(ensure_pipeline "OMNI - FortiManager" <<'PIPE'
pipeline "OMNI - FortiManager"
stage 0 match either
rule "omni-fmg-00-parse"
stage 5 match either
rule "omni-fmg-05-normalise"
stage 10 match either
rule "omni-fmg-10-login-fail"
rule "omni-fmg-10-login-ok"
rule "omni-fmg-10-config-change"
rule "omni-fmg-10-pass"
end
PIPE
)"
[[ -n "$ST_FMG" ]] && connect_pipeline "$ST_FMG" "$PL"

echo "==> [4/4] MITRE + alerte (echecs de login admin FortiManager)"
CSV="lookups/mitre-attack.csv"
grep -q '^fmg_admin_login_fail,' "$CSV" || echo 'fmg_admin_login_fail,T1110,Brute Force,Credential Access,eleve,6' >> "$CSV"
grep -q '^fmg_config_change,'     "$CSV" || echo 'fmg_config_change,T1565.001,Stored Data Manipulation,Impact,moyen,4' >> "$CSV"
grep -q '^fmg_admin_login,'       "$CSV" || echo 'fmg_admin_login,T1078,Valid Accounts,Defense Evasion,faible,2' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE fmg_admin_login_fail / fmg_config_change / fmg_admin_login"

# Alerte : >=5 echecs de login admin FortiManager / 10 min (P3, mail+Teams).
NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NOTIF_TEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
TITLE="OMNI - FortiManager : echecs de login admin (>=5 / 10 min)"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "$TITLE" '.event_definitions[]|select(.title==$t)' >/dev/null; then
  skip "alerte FMG login existe"
else
  NOTIFS="$(jq -n --arg m "$NOTIF_MAIL" --arg tm "$NOTIF_TEAMS" \
    '[ {notification_id:$m, notification_parameters:null} ] + (if $tm=="" or $tm=="null" then [] else [{notification_id:$tm, notification_parameters:null}] end)')"
  jq -n --arg t "$TITLE" --arg st "$ST_FMG" --argjson n "$NOTIFS" '{
    title:$t, description:"Echecs de login administrateur sur le FortiManager (brute force / acces non autorise). Provisionne par 63-fortimanager.sh",
    priority:3, alert:true,
    config:{type:"aggregation-v1", query:"alert_tag:fmg_admin_login_fail", query_parameters:[],
      streams:[$st], group_by:[], series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:5}}},
      search_within_ms:600000, execute_every_ms:300000, use_cron_scheduling:false, event_limit:50},
    field_spec:{}, key_spec:[],
    notification_settings:{grace_period_ms:3600000, backlog_size:10},
    notifications:$n
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte FMG login creee" || warn "alerte FMG login REFUSEE"
fi

echo
echo "=== 63-fortimanager.sh termine."
echo "    RESTE COTE JULIEN :"
echo "    1) Pare-feu : autoriser ${FMG_IP} -> ${SIEM_IP}:${FMG_PORT} (TCP+UDP) +"
echo "       nftables : ajouter ${FMG_PORT} a la regle d'entree du VLAN admin."
echo "    2) FortiManager (${FMG_IP}) : System Settings > Advanced > Syslog Server"
echo "       -> ${SIEM_IP} port ${FMG_PORT} (ou: config system locallog syslogd setting ;"
echo "       set status enable ; set server ${SIEM_IP} ; set port ${FMG_PORT} ; end)."
echo "    3) Relancer 14-graylog-dashboards.sh (page Reseau/Sources) + 21-alert-hygiene.sh."
echo "    Verif : tag alert_tag:fmg_* visible des que le FMG forwarde. ==="
