#!/usr/bin/env bash
# =============================================================================
# 67-detection-coverage.sh - Comblement de trous ATT&CK (detections ciblees)
#   Plutot que d'auto-importer 3000 regles Sigma (flood + mapping de champs),
#   ajoute des detections HAUTE-FIDELITE inspirees Sigma, MAPPEES au schema
#   OMNITECH (Sysmon EID1), sur les trous prioritaires de la carte de couverture :
#     - ad_recon  (T1087.002 Discovery)   : reco AD offensive (nltest /dclist,
#       dsquery, adfind, SharpHound/BloodHound, net group "domain admins")
#     - web_shell (T1505.003 Persistence) : process web (w3wp/httpd/php/nginx/
#       tomcat) lancant un shell -> web shell
#     - ntds_dump (T1003.006/T1003.003)   : extraction NTDS.dit (ntdsutil)
#   Pipeline dedie (stream Sysmon), MITRE, alertes agregees (count>=1, tumbling).
#   Idempotent. Prerequis : 12 (pipelines) + 37 (MITRE). Relancer 57 (carte) + 14.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Detections de comblement (Sysmon EID1, schema reel)"
ensure_rule "omni-sysmon-11-ad-recon" <<'EOF'
rule "omni-sysmon-11-ad-recon"
when
  to_string($message.event_source) == "sysmon"
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "/dclist", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "domain_trusts", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "dsquery", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "adfind", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "sharphound", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "bloodhound", true)
     OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "net group", true)
          AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "domain admins", true)
             OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "enterprise admins", true) ) ) )
then
  set_field("alert_tag", "ad_recon");
end
EOF
ensure_rule "omni-sysmon-11-webshell" <<'EOF'
rule "omni-sysmon-11-webshell"
when
  to_string($message.event_source) == "sysmon"
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\w3wp.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\httpd.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\php-cgi.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\nginx.exe", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_ParentImage), "tomcat", true) )
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\cmd.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\powershell.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\pwsh.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\cscript.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\wscript.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\bash.exe", true) )
then
  set_field("alert_tag", "web_shell");
end
EOF
ensure_rule "omni-sysmon-11-ntds" <<'EOF'
rule "omni-sysmon-11-ntds"
when
  to_string($message.event_source) == "sysmon"
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "ntds.dit", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\ntdsutil.exe", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "ntdsutil", true) )
then
  set_field("alert_tag", "ntds_dump");
end
EOF

echo "==> [2/4] Pipeline 'OMNI - Couverture ATT&CK etendue' (stream Sysmon, stage 11)"
PL="$(ensure_pipeline "OMNI - Couverture ATT&CK etendue" <<'PIPE'
pipeline "OMNI - Couverture ATT&CK etendue"
stage 11 match either
rule "omni-sysmon-11-ad-recon"
rule "omni-sysmon-11-webshell"
rule "omni-sysmon-11-ntds"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Sysmon')"; [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL"

echo "==> [3/4] MITRE + alertes (agregees, sans flood)"
CSV="lookups/mitre-attack.csv"
grep -q '^ad_recon,'  "$CSV" || echo 'ad_recon,T1087.002,Account Discovery: Domain Account,Discovery,eleve,6' >> "$CSV"
grep -q '^web_shell,' "$CSV" || echo 'web_shell,T1505.003,Web Shell,Persistence,critique,9' >> "$CSV"
grep -q '^ntds_dump,' "$CSV" || echo 'ntds_dump,T1003.003,NTDS,Credential Access,critique,10' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE ad_recon / web_shell / ntds_dump"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
SYS="$(get_stream_id 'OMNI - Sysmon')"
mk_alert() {  # titre query priorite
  local T="$1" Q="$2" P="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T' existe"; return; }
  local NF; NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
  jq -n --arg t "$T" --arg q "$Q" --arg st "$SYS" --argjson p "$P" --argjson n "$NF" '{title:$t,description:"Comblement couverture ATT&CK (67-detection-coverage.sh)",priority:$p,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"
}
mk_alert "OMNI - Reconnaissance Active Directory (nltest/dsquery/BloodHound)" "alert_tag:ad_recon" 3
mk_alert "OMNI - Web shell (process web -> shell)" "alert_tag:web_shell" 3
mk_alert "OMNI - Extraction NTDS.dit (vol base AD)" "alert_tag:ntds_dump" 3

echo "==> [4/4] Regeneration de la carte de couverture ATT&CK"
bash ./57-mitre-coverage.sh 2>&1 | grep -iE 'couvert|technique|tactique|trou|layer|navigator|termine' | tail -8 || warn "relancer 57 manuellement"

echo
echo "=== 67 termine. 3 techniques ajoutees (T1087.002 / T1505.003 / T1003.003)."
echo "    Carte : docs/mitre-navigator-layer.json (charger dans ATT&CK Navigator)."
echo "    Relancer 14-graylog-dashboards.sh (page ATT&CK). ==="
