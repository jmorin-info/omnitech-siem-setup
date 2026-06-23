#!/usr/bin/env bash
# =============================================================================
# 96-correlation.sh - Correlation cross-source (exploite src_ip/net_segment/user
#   normalises). Issu de la chasse ancree du 23/06 (workflow). Trois apports :
#
#   [1] FIX DATA-QUALITY : net_segment n'etait derive que sur les sources seeds
#       (Aruba/Linux/EMS, ~tens de docs). Le VOLUME de src_ip est sur
#       windows_security (1.46M) / m365 (638k) / bunkerweb (421k) / vaultwarden.
#       -> pipeline d'enrichissement PARTAGE "OMNI - Enrichissement reseau"
#       (stage 30, derive net_octet+net_segment pour TOUTE IP interne 10.33.x),
#       connecte a ces streams. Non invasif (n'altere pas leurs pipelines).
#
#   [2] Anomalie d'autorite M365 : action privilegiee (m365_ca_change /
#       m365_app_credential_add / m365_role) par un user HORS baseline. Baseline
#       mesuree 30j = 100% jmorin + 3 service principals connus. Tout autre = alerte.
#
#   [3] Login admin hors segment : aruba_admin_login / ems_admin_login depuis un
#       net_octet != 90 (VLAN Admin/VPN) = contournement de jump host (T1078).
#       Motif vrai-positif deja observe (adm-jmorin depuis 10.33.20.9).
#
#   Idempotent. Prerequis : 93 (lookup omni-net-segment) + 13 (notifications).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Pipeline d'enrichissement reseau PARTAGE (net_segment sur src_ip interne)"
# Derive net_octet (3e octet) + net_segment pour toute IP interne 10.33.x, quelle
# que soit la source. Stage 30 : s'execute APRES le parsing des pipelines source
# (Graylog ordonne les stages globalement) -> src_ip deja pose.
ensure_rule "omni-corr-30-netseg" <<'EOF'
rule "omni-corr-30-netseg"
when has_field("src_ip") OR has_field("winlogbeat_winlog_event_data_IpAddress") OR has_field("winlogbeat_winlog_event_data_SourceIp")
then
  // COALESCENCE de l'IP source selon la source : src_ip (aruba/linux/m365/forti),
  // IpAddress (logon Windows winsec), SourceIp (sysmon EID3). Premier non vide.
  let ip = to_string($message.src_ip, to_string($message.winlogbeat_winlog_event_data_IpAddress, to_string($message.winlogbeat_winlog_event_data_SourceIp, "")));
  // derive le segment (le grok ne matche que les IPv4 ; "-"/"" ignores) puis lookup VLAN
  set_fields(grok("%{INT}.%{INT}.%{INT:net_octet}.%{INT}", ip, true));
  let seg = lookup_value("omni-net-segment", to_string($message.net_octet));
  set_field("net_segment", seg);
end
EOF
PL="$(ensure_pipeline "OMNI - Enrichissement reseau" <<'PIPE'
pipeline "OMNI - Enrichissement reseau"
stage 30 match either
rule "omni-corr-30-netseg"
end
PIPE
)"
# Connecte a TOUTES les sources internes (pas seulement 5) -> net_segment cross-source.
for S in 'OMNI - Windows Security' 'OMNI - Windows autres' 'OMNI - Sysmon' 'OMNI - M365' \
         'OMNI - BunkerWeb' 'OMNI - Vaultwarden' 'OMNI - FortiGate' \
         'OMNI - Linux' 'OMNI - Aruba' 'OMNI - FortiClient EMS'; do
  SID="$(get_stream_id "$S")"
  [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream absent: $S"
done

echo "==> [2/4] MITRE des correlations"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; }
add_mitre m365_authority_drift   T1098     "Anomalie d'autorite (action privilegiee M365 hors baseline)" "Privilege Escalation" critique 9
add_mitre admin_login_off_segment T1078    "Login admin hors VLAN admin (contournement jump host)"        "Defense Evasion"      eleve    7
add_mitre ip_spray_multisource   T1110.003 "Spray d'identifiants multi-systeme (meme IP)"                 "Credential Access"    eleve    8
add_mitre impossible_travel_xsrc T1078.004 "Voyage impossible (signin etranger + presence on-prem)"       "Initial Access"       critique 9
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE correlations"

# Notifications
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
NF="$(jq -n --arg m "$NMAIL" --arg t "$NTEAMS" '[{notification_id:$m,notification_parameters:null}] + (if $t!="" and $t!=null then [{notification_id:$t,notification_parameters:null}] else [] end)')"

mk_corr_alert() {  # TITRE  QUERY  GROUP_BY  PRIORITE  DESCRIPTION
  local T="$1" Q="$2" GB="$3" PR="${4:-3}" DESC="$5"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte $T existe"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg gb "$GB" --argjson n "$NF" --argjson pr "$PR" --arg d "$DESC" \
    '{title:$t,description:$d,priority:$pr,alert:true,
      config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[],group_by:[$gb],series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
        search_within_ms:600000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
      field_spec:{},key_spec:[],notification_settings:{grace_period_ms:600000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte $T"
}

echo "==> [3/4] Anomalie d'autorite M365 (action privilegiee hors baseline)"
# Baseline mesuree 30j : ca_change 100% jmorin ; credential_add jmorin + 3 SP connus.
ALLOW='NOT user:"jmorin" AND NOT user:"microsoft azure ad internal - jit provisioning" AND NOT user:"ztna network access control plane" AND NOT user:"aad app management"'
mk_corr_alert "OMNI - Anomalie d'autorite M365 (user inattendu)" \
  "(alert_tag:m365_app_credential_add OR alert_tag:m365_ca_change OR alert_tag:m365_role) AND ${ALLOW}" \
  "user" 1 "96-correlation.sh : action privilegiee M365 (secret app / Conditional Access / role) par un compte HORS baseline (jmorin + service principals connus). T1098.001/T1556."

echo "==> [4/4] Login admin hors VLAN admin (net_octet != 90)"
mk_corr_alert "OMNI - Login admin hors segment admin (Aruba/EMS)" \
  "(alert_tag:aruba_admin_login OR alert_tag:ems_admin_login) AND _exists_:net_octet AND NOT net_octet:90" \
  "user" 2 "96-correlation.sh : login admin switch/EMS depuis un VLAN non-admin (octet != 90) = contournement de jump host. T1078."

echo
echo "=== 96 termine. Enrichissement net_segment partage + 2 correlations Graylog."
echo "    (IP multi-systeme + voyage impossible = oms-xdr, cf rules.yaml.) ==="
