#!/usr/bin/env bash
# =============================================================================
# 76-detection-cmdline.sh - Detections cmdline (vol ruche SAM, effacement journaux)
#   - sam_hive_dump (T1003.002) : reg save HKLM\SAM|SYSTEM|SECURITY = vol des ruches
#     (credential dumping hors-ligne).
#   - log_cleared (T1070.001)   : wevtutil cl / Clear-EventLog = effacement de
#     journaux (anti-forensic). 'wevtutil qe' (legitime) NON tague.
#   Sysmon EID1 (command_line). Pipeline dedie, MITRE, alertes. Idempotent. Relancer 57.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/3] Regles"
ensure_rule "omni-sysmon-12-regsave-sam" <<'EOF'
rule "omni-sysmon-12-regsave-sam"
when
  to_string($message.event_source) == "sysmon"
  AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "save", true)
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "hklm\\sam", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "hklm\\system", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "hklm\\security", true) )
then
  set_field("alert_tag", "sam_hive_dump");
end
EOF
ensure_rule "omni-sysmon-12-logclear" <<'EOF'
rule "omni-sysmon-12-logclear"
when
  to_string($message.event_source) == "sysmon"
  AND ( ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "wevtutil", true)
          AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), " cl ", true) )
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "clear-eventlog", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "clear-log", true) )
then
  set_field("alert_tag", "log_cleared");
end
EOF
PL="$(ensure_pipeline "OMNI - Detection cmdline" <<'PIPE'
pipeline "OMNI - Detection cmdline"
stage 12 match either
rule "omni-sysmon-12-regsave-sam"
rule "omni-sysmon-12-logclear"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Sysmon')"; [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL"

echo "==> [2/3] MITRE"
CSV="lookups/mitre-attack.csv"
grep -q '^sam_hive_dump,' "$CSV" || echo 'sam_hive_dump,T1003.002,Security Account Manager,Credential Access,critique,9' >> "$CSV"
grep -q '^log_cleared,'   "$CSV" || echo 'log_cleared,T1070.001,Clear Windows Event Logs,Defense Evasion,eleve,8' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE sam_hive_dump / log_cleared"

echo "==> [3/3] Alertes"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
SYS="$(get_stream_id 'OMNI - Sysmon')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
mk_a() { local T="$1" Q="$2"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg st "$SYS" --argjson n "$NF" '{title:$t,description:"76-detection-cmdline.sh",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"; }
mk_a "OMNI - Vol de ruche SAM/SYSTEM (reg save)" "alert_tag:sam_hive_dump"
mk_a "OMNI - Effacement de journaux Windows (anti-forensic)" "alert_tag:log_cleared"
echo
echo "=== 76 termine. Relancer 57 (carte). ==="
