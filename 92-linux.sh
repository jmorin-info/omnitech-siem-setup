#!/usr/bin/env bash
# =============================================================================
# 92-linux.sh - Integration des serveurs LINUX (Debian : BunkerWeb, Vaultwarden,
#   SIEM...). Visibilite endpoint Linux : SSH, sudo/su, creation de comptes/cles,
#   auditd (modif de fichiers sensibles). PAS de collecte aujourd'hui -> ce script
#   cree le RECEPTEUR (input Syslog TCP 1519) + parsing + detections ; le KIT CLIENT
#   (rsyslog + auditd) a deployer sur les hotes est dans kit/linux-omni.sh.
#   Design = workflow 4-sources (mesure-first). Format = syslog RFC3164/5424 ;
#   l'input remplit source(host)/application_name(programme)/facility ; on parse le
#   corps via grok() selon le programme (sshd/sudo/su/useradd).
#   Detections : echec SSH (brute force = alerte agregee), succes apres echecs,
#   sudo->root inhabituel, ajout user/cle SSH, alteration de fichier sensible (auditd).
#   Idempotent. Prerequis : 12 (lib). Relancer 14 (dashboard). Port 1519 ouvert au
#   VLAN interne (06-firewall.sh) ; restreindre aux IP des serveurs en prod.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Input Syslog TCP 1519 + index set + stream 'OMNI - Linux'"
ensure_index_set() {  # prefix titre retention -> id
  local PFX="$1" TITLE="$2" RET="$3" ID
  ID="$(api_get '/system/indices/index_sets?limit=200' | jq -r --arg p "$PFX" '.index_sets[]|select(.index_prefix==$p)|.id')"
  [[ -n "$ID" ]] && { echo "$ID"; return; }
  api_get '/system/indices/index_sets?limit=200' | jq -c '.index_sets[]|select(.index_prefix=="omni-fortigate")' \
    | jq --arg t "$TITLE" --arg p "$PFX" --argjson r "$RET" 'del(.id,.creation_date,.default,.can_be_default)|.title=$t|.index_prefix=$p|.description=$t|.retention_strategy.max_number_of_indices=$r' \
    | api_post '/system/indices/index_sets' | jqr '.id'
}
if [[ -z "$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Linux (Syslog TCP 1519)")|.id')" ]]; then
  jq -n '{title:"Linux (Syslog TCP 1519)",type:"org.graylog2.inputs.syslog.tcp.SyslogTCPInput",global:true,configuration:{bind_address:"0.0.0.0",port:1519,recv_buffer_size:1048576,number_worker_threads:2,tls_enable:false,force_rdns:false,allow_override_date:true,expand_structured_data:false,store_full_message:true}}' \
    | api_post "/system/inputs" >/dev/null && { ok "input Linux 1519 cree"; sleep 4; } || warn "input refuse"
else skip "input Linux existe"; fi
IID="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Linux (Syslog TCP 1519)")|.id')"
IDX="$(ensure_index_set 'omni-linux' 'OMNI - Linux' 90)"
if [[ -z "$(get_stream_id 'OMNI - Linux')" ]]; then
  jq -n --arg idx "$IDX" --arg in "$IID" '{title:"OMNI - Linux",description:"Serveurs Linux (SSH/sudo/auditd)",matching_type:"AND",remove_matches_from_default_stream:true,index_set_id:$idx,rules:[{field:"gl2_source_input",type:1,value:$in,inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree"; }; }
else skip "stream 'OMNI - Linux' existe"; fi
ST="$(get_stream_id 'OMNI - Linux')"

echo "==> [2/4] Pipeline 'OMNI - Linux' (parse grok + normalisation + detections)"
ensure_rule "omni-linux-00-base" <<'EOF'
rule "omni-linux-00-base"
when has_field("source") AND NOT has_field("winlogbeat_winlog_event_id")
then
  set_field("event_source", "linux");
  set_field("host", to_string($message.source));
end
EOF
# NB : Graylog ne remplit PAS application_name pour ce flux -> le programme reste
# dans 'message' (ex "host sshd[pid]: ..."). On gate donc sur le CONTENU de message
# (robuste) et on grok les champs directement dessus.
ensure_rule "omni-linux-05-sshd" <<'EOF'
rule "omni-linux-05-sshd"
when contains(to_string($message.message),"Failed password") OR contains(to_string($message.message),"Accepted ") OR contains(to_string($message.message),"Invalid user")
then
  set_fields(grok("Failed password for (invalid user )?%{USERNAME:user} from %{IP:src_ip} port %{INT:src_port}", to_string($message.message), true));
  set_fields(grok("Accepted %{WORD:ssh_method} for %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port}", to_string($message.message), true));
  set_fields(grok("Invalid user %{USERNAME:user} from %{IP:src_ip}", to_string($message.message), true));
  // segment reseau via le 3e octet de src_ip (meme correlation que Aruba/EMS)
  set_fields(grok("%{INT}.%{INT}.%{INT:net_octet}.%{INT}", to_string($message.src_ip), true));
  let lseg = lookup_value("omni-net-segment", to_string($message.net_octet));
  set_field("net_segment", lseg);
end
EOF
ensure_rule "omni-linux-05-sudo" <<'EOF'
rule "omni-linux-05-sudo"
when contains(to_string($message.message),"COMMAND=") AND contains(to_string($message.message),"USER=")
then
  set_fields(grok("%{USERNAME:user} : .*USER=%{USERNAME:target_user} ; COMMAND=%{GREEDYDATA:command_line}", to_string($message.message), true));
end
EOF
# --- Detections (gate sur le contenu de message) ---
ensure_rule "omni-linux-10-sshfail" <<'EOF'
rule "omni-linux-10-sshfail"
when contains(to_string($message.message),"Failed password")
then set_field("alert_tag","linux_ssh_fail"); set_field("event_action","ssh_login_failed"); end
EOF
ensure_rule "omni-linux-10-sshok" <<'EOF'
rule "omni-linux-10-sshok"
when contains(to_string($message.message),"Accepted ") AND contains(to_string($message.message)," ssh2")
then set_field("event_action","ssh_login_success"); end
EOF
ensure_rule "omni-linux-10-sudo-root" <<'EOF'
rule "omni-linux-10-sudo-root"
when contains(to_string($message.message),"USER=root") AND contains(to_string($message.message),"COMMAND=")
then set_field("alert_tag","linux_sudo_root"); set_field("event_action","sudo_root"); end
EOF
ensure_rule "omni-linux-10-useradd" <<'EOF'
rule "omni-linux-10-useradd"
when contains(to_string($message.message),"new user:",true) OR ( contains(to_string($message.message)," to group",true) AND contains(to_string($message.message),"add ",true) )
then
  set_fields(grok("name=%{USERNAME:new_user}", to_string($message.message), true));
  set_field("alert_tag","linux_user_added"); set_field("event_action","compte_linux_cree");
end
EOF
ensure_rule "omni-linux-10-audit-sensitive" <<'EOF'
rule "omni-linux-10-audit-sensitive"
when ( to_string($message.application_name)=="audit" OR to_string($message.application_name)=="auditd" )
     AND ( contains(to_string($message.message),"omni_passwd") OR contains(to_string($message.message),"omni_sudoers") OR contains(to_string($message.message),"omni_shadow") OR contains(to_string($message.message),"omni_sshkeys") )
then set_field("alert_tag","linux_sensitive_tamper"); set_field("event_action","modif_fichier_sensible"); end
EOF
# NB stages : un stage "match either" ne CONTINUE au suivant que si >=1 regle matche.
# On met base (toujours vrai) + parse dans le MEME stage 0 -> le pipeline atteint
# toujours le stage 10 des detections (sinon un useradd, qui ne matche aucun parse,
# serait bloque avant les detections).
PL="$(ensure_pipeline "OMNI - Linux" <<'PIPE'
pipeline "OMNI - Linux"
stage 0 match either
rule "omni-linux-00-base"
rule "omni-linux-05-sshd"
rule "omni-linux-05-sudo"
stage 10 match either
rule "omni-linux-10-sshfail"
rule "omni-linux-10-sshok"
rule "omni-linux-10-sudo-root"
rule "omni-linux-10-useradd"
rule "omni-linux-10-audit-sensitive"
end
PIPE
)"
[[ -n "$ST" ]] && connect_pipeline "$ST" "$PL"

echo "==> [3/4] MITRE + alerte brute-force SSH (agregation >=8 echecs / IP)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; }
add_mitre linux_ssh_fail        T1110     "Brute Force (SSH)"                    "Credential Access" moyen   5
add_mitre linux_sudo_root       T1548.003 "Sudo and Sudo Caching"               "Privilege Escalation" moyen 5
add_mitre linux_user_added      T1136.001 "Create Account: Local Account"        "Persistence"       eleve   7
add_mitre linux_sensitive_tamper T1098    "Account Manipulation (fichier sensible)" "Persistence"    critique 8
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NF="$(jq -n --arg m "$NMAIL" '[{notification_id:$m,notification_parameters:null}]')"
if [[ -n "$ST" ]] && ! api_get "/events/definitions?per_page=300" | jq -e '.event_definitions[]|select(.title=="OMNI - Brute force SSH (Linux)")' >/dev/null; then
  jq -n --arg st "$ST" --argjson n "$NF" '{title:"OMNI - Brute force SSH (Linux)",description:"92-linux.sh",priority:2,alert:true,
    config:{type:"aggregation-v1",query:"alert_tag:linux_ssh_fail",query_parameters:[],streams:[$st],group_by:["src_ip"],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:8}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:600000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte brute-force SSH (>8/IP)"
fi

echo "==> [4/4] Routage (deja dedie via input ; stream remove_matches_from_default=true)"
echo
echo "=== 92 termine. Recepteur Linux pret. DEPLOYER LE KIT sur chaque serveur Debian :"
echo "    kit/linux-omni.sh <IP_DU_SIEM>   (rsyslog forward 1519 + auditd fichiers sensibles)"
echo "    Firewall : 1519/tcp ouvert au VLAN interne (restreindre aux IP serveurs en prod). ==="
