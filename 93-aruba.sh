#!/usr/bin/env bash
# =============================================================================
# 93-aruba.sh - Integration des switches ARUBA (ArubaOS AOS-S / AOS-CX).
#   PAS de collecte aujourd'hui -> cree le RECEPTEUR (input Syslog UDP+TCP 1520) +
#   parsing + detections. Le header syslog est decoupe par l'input (source=switch) ;
#   on detecte sur le CONTENU de message (le programme ArubaOS n'est pas dans
#   application_name, comme pour Linux). Design = workflow 4-sources.
#   Detections : echec auth admin (brute force), changement de config, violation
#   port-security, flap de lien, login hors plage. Config switch = etape [4].
#   Idempotent. Prerequis : 12 (lib). Port 1520 ouvert au VLAN interne (06-firewall.sh).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Inputs Syslog 1520 (UDP+TCP) + index set + stream 'OMNI - Aruba'"
ensure_index_set() {
  local PFX="$1" TITLE="$2" RET="$3" ID
  ID="$(api_get '/system/indices/index_sets?limit=200' | jq -r --arg p "$PFX" '.index_sets[]|select(.index_prefix==$p)|.id')"
  [[ -n "$ID" ]] && { echo "$ID"; return; }
  api_get '/system/indices/index_sets?limit=200' | jq -c '.index_sets[]|select(.index_prefix=="omni-fortigate")' \
    | jq --arg t "$TITLE" --arg p "$PFX" --argjson r "$RET" 'del(.id,.creation_date,.default,.can_be_default)|.title=$t|.index_prefix=$p|.description=$t|.retention_strategy.max_number_of_indices=$r' \
    | api_post '/system/indices/index_sets' | jqr '.id'
}
mk_input() {  # type-suffix  TYPE
  local T="Aruba (Syslog $1 1520)" TYPE="$2"
  [[ -n "$(api_get '/system/inputs' | jq -r --arg t "$T" '.inputs[]|select(.title==$t)|.id')" ]] && { skip "input $T"; return; }
  jq -n --arg t "$T" --arg ty "$TYPE" '{title:$t,type:$ty,global:true,configuration:{bind_address:"0.0.0.0",port:1520,recv_buffer_size:1048576,number_worker_threads:2,force_rdns:false,allow_override_date:true,expand_structured_data:false,store_full_message:true}}' \
    | api_post "/system/inputs" >/dev/null && ok "input $T cree"
}
mk_input "UDP" "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
mk_input "TCP" "org.graylog2.inputs.syslog.tcp.SyslogTCPInput"
sleep 3
# stream route sur les 2 inputs (UDP+TCP)
IU="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Aruba (Syslog UDP 1520)")|.id')"
IT="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Aruba (Syslog TCP 1520)")|.id')"
IDX="$(ensure_index_set 'omni-aruba' 'OMNI - Aruba' 90)"
if [[ -z "$(get_stream_id 'OMNI - Aruba')" ]]; then
  jq -n --arg idx "$IDX" --arg u "$IU" --arg t "$IT" '{title:"OMNI - Aruba",description:"Switches Aruba (ArubaOS)",matching_type:"OR",remove_matches_from_default_stream:true,index_set_id:$idx,
    rules:[{field:"gl2_source_input",type:1,value:$u,inverted:false},{field:"gl2_source_input",type:1,value:$t,inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree"; }; }
else skip "stream 'OMNI - Aruba' existe"; fi
ST="$(get_stream_id 'OMNI - Aruba')"

echo "==> [2/4] Pipeline 'OMNI - Aruba' (base + detections sur le contenu message)"
# base TOUJOURS vrai (stage 0) -> le pipeline atteint toujours les detections (stage 10).
ensure_rule "omni-aruba-00-base" <<'EOF'
rule "omni-aruba-00-base"
when has_field("source")
then set_field("event_source", "aruba"); set_field("host", to_string($message.source)); end
EOF
ensure_rule "omni-aruba-10-authfail" <<'EOF'
rule "omni-aruba-10-authfail"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"Authentication failed",true)
     OR contains(to_string($message.message),"login failed",true)
     OR contains(to_string($message.message),"Invalid password",true)
     OR contains(to_string($message.message),"failed login",true) )
then set_field("alert_tag","aruba_auth_fail"); set_field("event_action","echec_auth_switch"); end
EOF
ensure_rule "omni-aruba-10-config" <<'EOF'
rule "omni-aruba-10-config"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"configuration changed",true)
     OR contains(to_string($message.message),"running configuration was changed",true)
     OR contains(to_string($message.message),"startup configuration",true)
     OR contains(to_string($message.message),"config saved",true) )
then set_field("alert_tag","aruba_config_change"); set_field("event_action","changement_config_switch"); end
EOF
ensure_rule "omni-aruba-10-portsec" <<'EOF'
rule "omni-aruba-10-portsec"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"port-security",true)
     OR contains(to_string($message.message),"security violation",true)
     OR contains(to_string($message.message),"intrusion",true)
     OR contains(to_string($message.message),"Intruder",true) )
then set_field("alert_tag","aruba_port_security"); set_field("event_action","violation_port_security"); end
EOF
ensure_rule "omni-aruba-10-adminlogin" <<'EOF'
rule "omni-aruba-10-adminlogin"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"SSH login",true)
     OR contains(to_string($message.message),"new SSH session",true)
     OR contains(to_string($message.message),"logged in",true)
     OR contains(to_string($message.message),"User logged",true) )
then set_field("alert_tag","aruba_admin_login"); set_field("event_action","login_admin_switch"); end
EOF
PL="$(ensure_pipeline "OMNI - Aruba" <<'PIPE'
pipeline "OMNI - Aruba"
stage 0 match either
rule "omni-aruba-00-base"
stage 10 match either
rule "omni-aruba-10-authfail"
rule "omni-aruba-10-config"
rule "omni-aruba-10-portsec"
rule "omni-aruba-10-adminlogin"
end
PIPE
)"
[[ -n "$ST" ]] && connect_pipeline "$ST" "$PL"

echo "==> [3/4] MITRE"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; }
add_mitre aruba_auth_fail     T1110     "Brute Force (admin switch)"             "Credential Access" moyen   5
add_mitre aruba_config_change T1601.001 "Modify System Image / config reseau"    "Defense Evasion"   eleve   7
add_mitre aruba_port_security T1200     "Hardware Additions / port-security"     "Initial Access"    eleve   7
add_mitre aruba_admin_login   T1078     "Valid Accounts (admin switch)"          "Defense Evasion"   moyen   4
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE aruba_*"

echo
echo "=== 93 termine. Recepteur Aruba pret (1520 UDP+TCP). CONFIGURER LES SWITCHES :"
echo "  AOS-CX  : conf t ; logging ${HOSTNAME_SIEM:-<IP_SIEM>} tcp 1520 ; logging severity warning"
echo "  AOS-S   : conf t ; logging <IP_SIEM> ; logging facility local7   (AOS-S emet sur 514 ->"
echo "            donne-moi les IP des switches pour ajouter un redirect 514->1520 scope, ou"
echo "            utilise AOS-CX vers 1520 directement)."
echo "  Firewall : 1520 ouvert au VLAN interne (restreindre aux IP switches en prod). ==="
