#!/usr/bin/env bash
# =============================================================================
# 93-aruba.sh - Integration des switches ARUBA (ArubaOS-Switch / AOS-S, ex 2930F).
#   Recepteur Syslog UDP+TCP 1520 + PARSING ENRICHI + detections + inventaire.
#   Format AOS-S reel (mesure 23/06) :  <PRI> date IP <event_id> <subsys>: <texte>
#     ex:  10.33.80.1 00419 auth:  ST1-CMDR: Invalid user name/password ... from 10.33.20.9
#          10.33.80.4 00076 ports:  port 8 is now on-line
#          10.33.80.1 05933 ssl:   SSL/TLS session started for WEB-UI from 10.33.20.9
#   Le programme AOS-S n'est PAS dans application_name -> on parse le CONTENU de
#   'message' (grok) : aruba_event_id, aruba_subsystem, aruba_text, aruba_client_ip
#   (IP a l'origine d'un login/echec), aruba_port (events 'ports:'). Detections
#   calees sur les chaines REELLES (piege : "Invalid user name/password", pas
#   "Invalid password"). Inventaire IP->nom via lookup (Julien edite 1 CSV).
#   Idempotent. Prerequis : 12 (lib) + 13 (notifications). Port 1520 ouvert aux
#   IP switches (06-firewall.sh : 10.33.80.1-6). Relancer 57 + 14 ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/5] Inputs Syslog 1520 (UDP+TCP) + index set + stream 'OMNI - Aruba'"
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
IU="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Aruba (Syslog UDP 1520)")|.id')"
IT="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Aruba (Syslog TCP 1520)")|.id')"
IDX="$(ensure_index_set 'omni-aruba' 'OMNI - Aruba' 90)"
if [[ -z "$(get_stream_id 'OMNI - Aruba')" ]]; then
  jq -n --arg idx "$IDX" --arg u "$IU" --arg t "$IT" '{title:"OMNI - Aruba",description:"Switches Aruba (ArubaOS-Switch)",matching_type:"OR",remove_matches_from_default_stream:true,index_set_id:$idx,
    rules:[{field:"gl2_source_input",type:1,value:$u,inverted:false},{field:"gl2_source_input",type:1,value:$t,inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree"; }; }
else skip "stream 'OMNI - Aruba' existe"; fi
ST="$(get_stream_id 'OMNI - Aruba')"

echo "==> [2/5] Inventaire switches (lookup IP -> nom/role) - Julien edite lookups/aruba-switches.csv"
# Header CSV obligatoire (key_column/value_column par NOM). Pas de commentaire/ligne vide.
if [[ ! -f lookups/aruba-switches.csv ]]; then
  cat > lookups/aruba-switches.csv <<'CSV'
ip,name,role,site
10.33.80.1,bx-aruba-01,distribution,Bourgoin
10.33.80.2,bx-aruba-02,acces,Bourgoin
10.33.80.3,bx-aruba-03,acces,Bourgoin
10.33.80.4,bx-aruba-04,acces,Bourgoin
10.33.80.5,bx-aruba-05,acces,Bourgoin
10.33.80.6,bx-aruba-06,acces,Bourgoin
CSV
  ok "lookups/aruba-switches.csv cree (a personnaliser : vrais noms/roles)"
else skip "lookups/aruba-switches.csv existe (conserve)"; fi
install -m 644 lookups/aruba-switches.csv "${LOOKUP_DIR}/aruba-switches.csv"
chown root:graylog "${LOOKUP_DIR}/aruba-switches.csv" 2>/dev/null || true
ensure_lookup "aruba-switch" "OMNI Aruba IP -> nom" "aruba-switches.csv" "ip" "name"

echo "==> [3/5] Pipeline 'OMNI - Aruba' (base + parsing enrichi + detections)"
# --- STAGE 0 : base + parsing (toutes gardes independantes des mutations du stage) -
ensure_rule "omni-aruba-00-base" <<'EOF'
rule "omni-aruba-00-base"
when has_field("source")
then
  set_field("event_source", "aruba");
  set_field("host", to_string($message.source));
  let n = lookup_value("omni-aruba-switch", to_string($message.source));
  set_field("aruba_switch_name", n);
end
EOF
# Parsing : IP (optionnelle) + event_id + subsystem + texte
ensure_rule "omni-aruba-01-parse" <<'EOF'
rule "omni-aruba-01-parse"
when has_field("source") AND has_field("message")
then
  // grok TOLERANT (3e arg=true) : ne pose que les captures qui matchent, jamais de champ vide.
  // %{NOTSPACE} (et non %{WORD}) pour capter les subsystems a tiret : port-access, port-security.
  set_fields(grok("%{DATA}%{INT:aruba_event_id}%{SPACE}%{NOTSPACE:aruba_subsystem}:%{SPACE}%{GREEDYDATA:aruba_text}", to_string($message.message), true));
end
EOF
# IP cliente (origine d'un login / echec / session) -> aruba_client_ip + src_ip (cle de correlation)
ensure_rule "omni-aruba-02-clientip" <<'EOF'
rule "omni-aruba-02-clientip"
when has_field("source") AND contains(to_string($message.message), " from ", true)
then
  set_fields(grok("from %{IP:aruba_client_ip}", to_string($message.message), true));
  set_fields(grok("from %{IP:src_ip}", to_string($message.message), true));
end
EOF
# Numero de port (events 'ports:')
ensure_rule "omni-aruba-03-port" <<'EOF'
rule "omni-aruba-03-port"
when has_field("source") AND contains(to_string($message.message), "ports:", true)
then
  set_fields(grok("port %{INT:aruba_port}", to_string($message.message), true));
end
EOF
# --- STAGE 10 : detections (chaines AOS-S REELLES) --------------------------------
ensure_rule "omni-aruba-10-authfail" <<'EOF'
rule "omni-aruba-10-authfail"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"Invalid user name/password",true)
     OR contains(to_string($message.message),"Invalid password",true)
     OR contains(to_string($message.message),"Authentication failed",true)
     OR contains(to_string($message.message),"authentication failure",true)
     OR contains(to_string($message.message),"Login incorrect",true)
     OR contains(to_string($message.message),"login failed",true)
     OR contains(to_string($message.message),"Failed login",true)
     OR contains(to_string($message.message),"unable to authenticate",true)
     OR contains(to_string($message.message),"access denied",true) )
then set_field("alert_tag","aruba_auth_fail"); set_field("event_action","echec_auth_switch"); end
EOF
ensure_rule "omni-aruba-10-config" <<'EOF'
rule "omni-aruba-10-config"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"configuration changed",true)
     OR contains(to_string($message.message),"running configuration was changed",true)
     OR contains(to_string($message.message),"Running config",true)
     OR contains(to_string($message.message),"Startup config",true)
     OR contains(to_string($message.message),"config saved",true)
     OR contains(to_string($message.message),"saved configuration",true)
     OR contains(to_string($message.message),"write memory",true) )
then set_field("alert_tag","aruba_config_change"); set_field("event_action","changement_config_switch"); end
EOF
ensure_rule "omni-aruba-10-portsec" <<'EOF'
rule "omni-aruba-10-portsec"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"security violation",true)
     OR contains(to_string($message.message),"Intrusion",true)
     OR contains(to_string($message.message),"Intruder",true)
     OR contains(to_string($message.message),"port-security",true)
     OR contains(to_string($message.message),"port-access",true)
     OR contains(to_string($message.message),"address limit",true)
     OR contains(to_string($message.message),"MAC Lockout",true) )
then set_field("alert_tag","aruba_port_security"); set_field("event_action","violation_port_security"); end
EOF
ensure_rule "omni-aruba-10-adminlogin" <<'EOF'
rule "omni-aruba-10-adminlogin"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"New SSH session",true)
     OR contains(to_string($message.message),"SSH session for",true)
     OR contains(to_string($message.message),"Console session",true)
     OR contains(to_string($message.message),"session for user",true)
     OR contains(to_string($message.message),"logged in",true)
     OR contains(to_string($message.message),"authentication accepted",true) )
then set_field("alert_tag","aruba_admin_login"); set_field("event_action","login_admin_switch"); end
EOF
# STP / boucle reseau (Blocked by STP, loop protect) = boucle ou rogue device.
ensure_rule "omni-aruba-10-stploop" <<'EOF'
rule "omni-aruba-10-stploop"
when to_string($message.event_source)=="aruba"
  AND ( contains(to_string($message.message),"Blocked by STP",true)
     OR contains(to_string($message.message),"loop protect",true)
     OR contains(to_string($message.message),"Loop detected",true)
     OR contains(to_string($message.message),"loop-protect",true) )
then set_field("alert_tag","aruba_stp_loop"); set_field("event_action","boucle_stp_switch"); end
EOF
PL="$(ensure_pipeline "OMNI - Aruba" <<'PIPE'
pipeline "OMNI - Aruba"
stage 0 match either
rule "omni-aruba-00-base"
rule "omni-aruba-01-parse"
rule "omni-aruba-02-clientip"
rule "omni-aruba-03-port"
stage 10 match either
rule "omni-aruba-10-authfail"
rule "omni-aruba-10-config"
rule "omni-aruba-10-portsec"
rule "omni-aruba-10-adminlogin"
rule "omni-aruba-10-stploop"
end
PIPE
)"
[[ -n "$ST" ]] && connect_pipeline "$ST" "$PL"

echo "==> [4/5] MITRE + alerte brute-force admin (agregation >=5 echecs / IP cliente)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; }
add_mitre aruba_auth_fail     T1110     "Brute Force (admin switch)"             "Credential Access" moyen   5
add_mitre aruba_config_change T1601.001 "Modify System Image / config reseau"    "Defense Evasion"   eleve   7
add_mitre aruba_port_security T1200     "Hardware Additions / port-security"     "Initial Access"    eleve   7
add_mitre aruba_admin_login   T1078     "Valid Accounts (admin switch)"          "Defense Evasion"   moyen   4
add_mitre aruba_stp_loop      T1498     "Network DoS (boucle / STP)"             "Impact"            moyen   5
add_mitre aruba_port_flap     T1200     "Hardware Additions (port flap)"         "Initial Access"    moyen   4
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE aruba_*"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NF="$(jq -n --arg m "$NMAIL" '[{notification_id:$m,notification_parameters:null}]')"
if [[ -n "$ST" ]] && ! api_get "/events/definitions?per_page=300" | jq -e '.event_definitions[]|select(.title=="OMNI - Brute force admin switch (Aruba)")' >/dev/null; then
  jq -n --arg st "$ST" --argjson n "$NF" '{title:"OMNI - Brute force admin switch (Aruba)",description:"93-aruba.sh",priority:2,alert:true,
    config:{type:"aggregation-v1",query:"alert_tag:aruba_auth_fail",query_parameters:[],streams:[$st],group_by:["aruba_client_ip"],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:5}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:600000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte brute-force admin switch (>5/IP)"
else skip "alerte brute-force admin switch existe"; fi

# Alertes simples (count>=1) sur tag : changement config, port-security, boucle STP.
mk_tag_alert() {  # TITRE  TAG  PRIORITE
  local T="$1" TAG="$2" PR="${3:-2}"
  [[ -z "$ST" ]] && return
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte $T existe"; return; }
  jq -n --arg st "$ST" --arg t "$T" --arg q "alert_tag:$TAG" --argjson n "$NF" --argjson pr "$PR" \
    '{title:$t,description:"93-aruba.sh",priority:$pr,alert:true,
      config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:["source"],series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
        search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
      field_spec:{},key_spec:[],notification_settings:{grace_period_ms:600000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte $T"
}
mk_tag_alert "OMNI - Changement config switch (Aruba)" "aruba_config_change" 2
mk_tag_alert "OMNI - Violation port-security (Aruba)"  "aruba_port_security" 2
mk_tag_alert "OMNI - Boucle reseau / STP (Aruba)"      "aruba_stp_loop"      2
# Port-flap agrege (pas de tag : requete sur le contenu) : >5 'off-line' / port / 10 min.
if [[ -n "$ST" ]] && ! api_get "/events/definitions?per_page=300" | jq -e '.event_definitions[]|select(.title=="OMNI - Port-flap switch (Aruba)")' >/dev/null; then
  jq -n --arg st "$ST" --argjson n "$NF" '{title:"OMNI - Port-flap switch (Aruba)",description:"93-aruba.sh : lien instable / boucle",priority:1,alert:true,
    config:{type:"aggregation-v1",query:"event_source:aruba AND message:\"is now off-line\"",query_parameters:[],streams:[$st],group_by:["source","aruba_port"],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:5}}},
      search_within_ms:600000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:1800000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte port-flap (>5/port/10min)"
else skip "alerte port-flap existe"; fi

echo
echo "==> [5/5] Termine."
echo "  Switches mesures emetteurs : .1 / .4 / .6 (les autres emettront sur evenement)."
echo "  Champs enrichis : aruba_event_id / aruba_subsystem / aruba_text / aruba_client_ip / aruba_port / aruba_switch_name."
echo "  Personnaliser l'inventaire : lookups/aruba-switches.csv (vrais noms/roles), puis relancer 93."
echo "=== 93 termine. Recepteur Aruba enrichi + detections AOS-S reelles. ==="
