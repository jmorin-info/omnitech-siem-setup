#!/usr/bin/env bash
# ==============================================================================
# 19-vsphere.sh - Collecte ESXi / vCenter (syslog) -> Graylog
#   1. Inputs syslog TCP + UDP 1516 dedies vSphere (port distinct du FAZ/1514)
#   2. Index omni-vsphere (90 j) + stream "OMNI - vSphere"
#   3. Pipeline de parsing/detection (best-effort sur le texte syslog ESXi/VCSA ;
#      a affiner avec les vrais logs - cf. VSPHERE.md) :
#        - event_source=vsphere, extraction user/src_ip
#        - tags : vsphere_auth_fail, vsphere_shell_ssh, vsphere_vm_destroy,
#                 vsphere_config (lockdown / permissions)
#   4. Alertes : brute force, acces SSH/Shell, suppression de VM
#
# Prerequis : 06 (port 1516 ouvert) + API up. Cote ESXi/vCenter : cf. VSPHERE.md.
# Idempotent. Suite : relancer 14 pour la page dashboard vSphere.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

# ------------------------------------------------------------------ 1. Inputs
echo "==> [1/4] Inputs syslog 1516 (vSphere)"
create_syslog() { # $1 titre $2 type(tcp|udp)
  local CLASS; [[ "$2" == "tcp" ]] && CLASS="org.graylog2.inputs.syslog.tcp.SyslogTCPInput" || CLASS="org.graylog2.inputs.syslog.udp.SyslogUDPInput"
  local ID; ID="$(api_get /system/inputs | jq -r --arg t "$1" '.inputs[]|select(.title==$t)|.id')"
  if [[ -n "${ID}" ]]; then skip "input '$1' existe (${ID})"; echo "${ID}"; return; fi
  ID="$(api_post /system/inputs <<EOF | jqr '.id'
{ "title":"$1", "type":"${CLASS}", "global":true,
  "configuration":{ "bind_address":"0.0.0.0", "port":1516, "recv_buffer_size":1048576,
    "allow_override_date":true, "expand_structured_data":false, "force_rdns":false,
    "store_full_message":true, "use_null_delimiter":false } }
EOF
)"
  [[ -n "${ID}" && "${ID}" != "null" ]] && ok "input '$1' (${ID})" >&2 || die "creation input $1"
  echo "${ID}"
}
IN_TCP="$(create_syslog 'vSphere (Syslog TCP 1516)' tcp)"
IN_UDP="$(create_syslog 'vSphere (Syslog UDP 1516)' udp)"

# -------------------------------------------------------------- 2. Index/stream
echo "==> [2/4] Index omni-vsphere + stream"
IS_VS="$(get_index_set_id 'omni-vsphere')"
if [[ -z "${IS_VS}" ]]; then
  IS_VS="$(api_post /system/indices/index_sets <<EOF | jqr '.id'
{ "title":"OMNI - vSphere", "description":"Provisionne par 19-vsphere.sh", "index_prefix":"omni-vsphere",
  "shards":1, "replicas":0,
  "rotation_strategy_class":"org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
  "rotation_strategy":{"type":"org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig","rotation_period":"P1D","rotate_empty_index_set":false},
  "retention_strategy_class":"org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
  "retention_strategy":{"type":"org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig","max_number_of_indices":90},
  "index_analyzer":"standard","index_optimization_max_num_segments":1,"index_optimization_disabled":false,
  "field_type_refresh_interval":5000,"writable":true,"creation_date":"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" }
EOF
)"
  [[ -n "${IS_VS}" && "${IS_VS}" != "null" ]] && ok "index set ${IS_VS}" || die "creation index set"
else skip "index set existe (${IS_VS})"; fi

ST_VS="$(get_stream_id 'OMNI - vSphere')"
if [[ -z "${ST_VS}" ]]; then
  ST_VS="$(jq -n --arg is "${IS_VS}" --arg a "${IN_TCP}" --arg b "${IN_UDP}" '{
    title:"OMNI - vSphere", description:"Provisionne par 19-vsphere.sh", index_set_id:$is,
    remove_matches_from_default_stream:true, matching_type:"OR",
    rules:[ {type:1,field:"gl2_source_input",value:$a,inverted:false,description:"syslog TCP vSphere"},
            {type:1,field:"gl2_source_input",value:$b,inverted:false,description:"syslog UDP vSphere"} ] }' \
    | wrap_entity | api_post /streams | jqr '.stream_id')"
  [[ -n "${ST_VS}" && "${ST_VS}" != "null" ]] || die "creation stream"
  api_post "/streams/${ST_VS}/resume" </dev/null >/dev/null
  ok "stream ${ST_VS}"
else skip "stream existe (${ST_VS})"; fi

# ----------------------------------------------------------------- 3. Pipeline
echo "==> [3/4] Pipeline de parsing/detection vSphere"

ensure_rule "omni-vsphere-00-drop-bruit" <<'EOF'
rule "omni-vsphere-00-drop-bruit"
when
  has_field("application_name")
  AND (
    starts_with(to_string($message.application_name), "ui-", true)
    OR ends_with(to_string($message.application_name), "-perf", true)
    OR starts_with(to_string($message.application_name), "vmon", true)
    OR starts_with(to_string($message.application_name), "sca-vmon", true)
    OR starts_with(to_string($message.application_name), "vsan-health", true)
    OR starts_with(to_string($message.application_name), "trustmanagement", true)
    OR starts_with(to_string($message.application_name), "vum-", true)
    OR starts_with(to_string($message.application_name), "lookupsvc", true)
    OR starts_with(to_string($message.application_name), "vpxd-svcs", true)
    OR starts_with(to_string($message.application_name), "vstats", true)
    OR starts_with(to_string($message.application_name), "vsphere-ui", true)
    OR starts_with(to_string($message.application_name), "vapi-endpoint", true)
    OR starts_with(to_string($message.application_name), "envoy", true)
    OR starts_with(to_string($message.application_name), "procstate", true)
    OR starts_with(to_string($message.application_name), "eam", true)
    OR starts_with(to_string($message.application_name), "sps", true)
    OR starts_with(to_string($message.application_name), "sca-", true)
    OR ends_with(to_string($message.application_name), "-access", true)
    OR ends_with(to_string($message.application_name), "-gc", true)
  )
then
  drop_message();
end
EOF

ensure_rule "omni-vsphere-00-normalisation" <<'EOF'
rule "omni-vsphere-00-normalisation"
when
  has_field("message")
then
  set_field("event_source", "vsphere");
  set_field("host", to_string($message.source));
end
EOF

# Bruit ESXi (application_name vide cote ESXi -> on filtre sur le contenu) :
# traces vSAN, storage, proxy access, warnings noyau. AUCUNE valeur securite.
# Garde hostd/vpxa/sshd/shell/vobd/sudo (auth, acces, events). Mesure 12/06 :
# vsantrace+osfsd+vsansystem+vsand+envoy-access+vmkwarning ~= 80% du volume ESXi.
ensure_rule "omni-vsphere-00-drop-esxi-bruit" <<'EOF'
rule "omni-vsphere-00-drop-esxi-bruit"
when
  has_field("message")
  AND (
    contains(to_string($message.message), " vsantrace", false)
    OR contains(to_string($message.message), " vsansystem[", false)
    OR contains(to_string($message.message), " vsand[", false)
    OR contains(to_string($message.message), " vsanmgmtsvc[", false)
    OR contains(to_string($message.message), " vsanperfsvc[", false)
    OR contains(to_string($message.message), " clomd[", false)
    OR contains(to_string($message.message), " cmmds", false)
    OR contains(to_string($message.message), " lsom", false)
    OR contains(to_string($message.message), " osfsd[", false)
    OR contains(to_string($message.message), " envoy-access[", false)
    OR contains(to_string($message.message), " vmkwarning[", false)
    OR contains(to_string($message.message), " vmkernel: ", false)
    OR contains(to_string($message.message), " sandboxd[", false)
    OR contains(to_string($message.message), " nfcd[", false)
    OR contains(to_string($message.message), " swapobjd[", false)
    OR contains(to_string($message.message), " vdfsd", false)
  )
then
  drop_message();
end
EOF

# Bruit du service cluster ESXi (vCLS/etcd) : le balancer gRPC du client etcd annule
# des dials redondants -> "authentication handshake failed: context canceled". Cluster
# sain (quorum vert, pas de "failed to find member"). ~500-700 evts/j/hote = pur bruit.
# On DROP (un vrai defaut etcd ne contient PAS "context canceled" -> conserve).
ensure_rule "omni-vsphere-00-drop-cluster-noise" <<'EOF'
rule "omni-vsphere-00-drop-cluster-noise"
when
  has_field("message")
  AND contains(to_string($message.message), "clusterAgent", true)
  AND contains(to_string($message.message), "context canceled", true)
then
  drop_message();
end
EOF

# Bruit du gestionnaire de mises a jour vSphere (vLCM) : validation des URL du
# catalogue de patches (vapp-updates / vai-catalog). Zero valeur securite, et les
# numeros de version (ex. 8.0.4.0) y etaient extraits a tort comme src_ip. -> drop.
ensure_rule "omni-vsphere-00-drop-vlcm-noise" <<'EOF'
rule "omni-vsphere-00-drop-vlcm-noise"
when
  has_field("message")
  AND ( contains(to_string($message.message), "vapp-updates", true)
        OR contains(to_string($message.message), "vai-catalog", true) )
then
  drop_message();
end
EOF

ensure_rule "omni-vsphere-05-user-ip" <<'EOF'
rule "omni-vsphere-05-user-ip"
when
  has_field("message")
then
  let m = to_string($message.message);
  let u = regex("(?:user|User)[ =']+([A-Za-z0-9._\\\\@-]+)", m);
  set_field("user", u["0"]);
  // IPv4 STRICTE (octets 0-255, rejette les "004"/versions). Sinon la regex laxiste
  // extrayait des numeros de version (ex. vLCM "8.0.3.004") dans src_ip -> mapping keyword.
  let p = regex("(\\b(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\\b)", m);
  set_field("src_ip", p["0"]);
end
EOF

ensure_rule "omni-vsphere-10-auth-fail" <<'EOF'
rule "omni-vsphere-10-auth-fail"
when
  has_field("message")
  AND (
    (contains(to_string($message.message), "authentication", true) AND contains(to_string($message.message), "fail", true))
    OR contains(to_string($message.message), "Failed password", true)
    OR contains(to_string($message.message), "Cannot login", true)
    OR contains(to_string($message.message), "Invalid login", true)
  )
  // Exclure le bruit des services cluster ESXi (vCLS/etcd) : les erreurs gRPC TLS
  // ("authentication handshake failed") et clusterAgent "failed to connect ...:2379"
  // ne sont PAS des echecs d'auth (user vide) -> sinon faux brute-force par IP.
  AND NOT contains(to_string($message.message), "clusterAgent", true)
  AND NOT contains(to_string($message.message), "handshake", true)
  AND NOT contains(to_string($message.message), "grpc", true)
  // Expiration normale de jeton SAML (cycle de vie vCenter, sans user/IP) = bruit, pas une attaque
  AND NOT contains(to_string($message.message), "token expired", true)
  AND NOT contains(to_string($message.message), "ValidatorFutureImpl", true)
  // Bruit de TELEMETRIE vpxd/ESXi (blobs multi-lignes de stats) qui matchent "authentication"
  // via des noms de classe (AuthenticationManagerMo) ET "fail" via FailoverClusterManagerMo --
  // PAS des echecs d'auth. + "SOAP ... HTTP failure" (connectivite/licences) et "ssoAdminServer"
  // (INFO gestion de domaine SSO). Mesure 7j : 6852/7556 = ce bruit ; 0 recouvrement avec les
  // 29 vrais echecs (Cannot/Invalid login, Failed password, Authentication failed). -> ~91% FP retire.
  AND NOT contains(to_string($message.message), "PropJournalStats", false)
  AND NOT contains(to_string($message.message), "InventoryStats", false)
  AND NOT contains(to_string($message.message), "ProcessStats", false)
  AND NOT contains(to_string($message.message), "SOAP request returned HTTP failure", true)
  AND NOT contains(to_string($message.message), "ssoAdminServer", true)
  // Exclure les comptes de service vCenter/ESXi (auth interne permanente = PAS du brute-force)
  // et localhost. Sinon vpxuser/dcui generent des centaines de faux positifs/jour.
  AND lowercase(to_string($message.user)) != "vpxuser"
  AND lowercase(to_string($message.user)) != "dcui"
  AND lowercase(to_string($message.user)) != "anonymous"
  AND to_string($message.src_ip) != "127.0.0.1"
then
  set_field("event_action", "auth_echec");
  set_field("alert_tag", "vsphere_auth_fail");
end
EOF

ensure_rule "omni-vsphere-10-shell-ssh" <<'EOF'
rule "omni-vsphere-10-shell-ssh"
when
  has_field("message")
  AND (
    contains(to_string($message.message), "SSH access has been enabled", true)
    OR contains(to_string($message.message), "ESXi Shell access has been enabled", true)
    OR contains(to_string($message.message), "SSH login has been enabled", true)
    OR (contains(to_string($message.message), "sshd", true) AND contains(to_string($message.message), "session opened", true))
  )
then
  set_field("event_action", "shell_ssh_active");
  set_field("alert_tag", "vsphere_shell_ssh");
end
EOF

ensure_rule "omni-vsphere-10-vm-destroy" <<'EOF'
rule "omni-vsphere-10-vm-destroy"
when
  has_field("message")
  AND (
    contains(to_string($message.message), "RemoveVm", true)
    OR contains(to_string($message.message), "Remove virtual machine", true)
    OR (contains(to_string($message.message), "has been deleted from", true) AND contains(to_string($message.message), "virtual machine", true))
  )
  AND NOT contains(to_string($message.message), "napshot", true)
  AND NOT contains(to_string($message.message), "Veeam", true)
  AND NOT contains(to_string($message.message), "Consolidate", true)
then
  set_field("event_action", "vm_supprimee");
  set_field("alert_tag", "vsphere_vm_destroy");
end
EOF

ensure_rule "omni-vsphere-10-snapshot" <<'EOF'
rule "omni-vsphere-10-snapshot"
when
  has_field("message")
  AND (contains(to_string($message.message), "RemoveSnapshot", true)
    OR contains(to_string($message.message), "CreateSnapshot", true))
then
  set_field("event_action", "snapshot_sauvegarde");
end
EOF

ensure_rule "omni-vsphere-10-config" <<'EOF'
rule "omni-vsphere-10-config"
when
  has_field("message")
  AND (
    contains(to_string($message.message), "lockdown mode", true)
    OR contains(to_string($message.message), "Permission", true)
    OR contains(to_string($message.message), "firewall", true)
  )
then
  set_field("event_action", "config_modifiee");
end
EOF

PL_VS="$(ensure_pipeline "OMNI - vSphere" <<'EOF'
pipeline "OMNI - vSphere"
stage 0 match either
rule "omni-vsphere-00-normalisation"
rule "omni-vsphere-00-drop-bruit"
rule "omni-vsphere-00-drop-esxi-bruit"
rule "omni-vsphere-00-drop-cluster-noise"
rule "omni-vsphere-00-drop-vlcm-noise"
stage 5 match either
rule "omni-vsphere-05-user-ip"
stage 10 match either
rule "omni-vsphere-10-auth-fail"
rule "omni-vsphere-10-shell-ssh"
rule "omni-vsphere-10-vm-destroy"
rule "omni-vsphere-10-snapshot"
rule "omni-vsphere-10-config"
end
EOF
)"
connect_pipeline "${ST_VS}" "${PL_VS}"

# ----------------------------------------------------------------- 4. Alertes
echo "==> [4/4] Alertes vSphere"
NOTIF_ID="$(api_get "/events/notifications?per_page=100" | jq -r '(.notifications // [])[] | select(.title=="OMNI - Mail equipe IT") | .id')"
TEAMS_ID="$(api_get "/events/notifications?per_page=100" | jq -r '(.notifications // [])[] | select(.title=="OMNI - Teams SOC") | .id')"
NOTIFS="$(jq -n --arg e "${NOTIF_ID}" --arg t "${TEAMS_ID}" '[{notification_id:$e, notification_parameters:null}] + (if $t != "" then [{notification_id:$t, notification_parameters:null}] else [] end)')"

ev_vs() { # titre prio query group series cond grace within every
  local TITLE="$1" PRIO="$2" QUERY="$3" GB="$4" SE="$5" CO="$6" GRACE="$7" WITHIN="$8" EVERY="$9"
  api_get "/events/definitions?per_page=100" | jq -e --arg t "${TITLE}" '(.event_definitions // .elements // [])[] | select(.title==$t)' >/dev/null 2>&1 \
    && { skip "evenement '${TITLE}' existe"; return 0; }
  jq -n --arg t "${TITLE}" --argjson p "${PRIO}" --arg q "${QUERY}" --arg st "${ST_VS}" \
        --argjson gb "${GB}" --argjson se "${SE}" --argjson co "${CO}" \
        --argjson w "$(( WITHIN*60000 ))" --argjson e "$(( EVERY*60000 ))" --argjson g "$(( GRACE*60000 ))" --argjson n "${NOTIFS}" '{
    title:$t, description:("P"+($p|tostring)+" - provisionne par 19-vsphere.sh"), priority:$p, alert:true,
    config:{ type:"aggregation-v1", query:$q, query_parameters:[], streams:[$st],
      group_by:$gb, series:$se, conditions:$co, search_within_ms:$w, execute_every_ms:$e, use_cron_scheduling:false, event_limit:100 },
    field_spec:{}, key_spec:[], notification_settings:{ grace_period_ms:$g, backlog_size:5 }, notifications:$n
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id' \
    | { read -r ID; [[ -n "${ID}" && "${ID}" != "null" ]] && ok "evenement '${TITLE}'" || warn "evenement '${TITLE}' REFUSE"; }
}
CGE='{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":5}}}'
CS='[{"id":"count()","type":"count"}]'
NC='{"expression":null}'
ev_vs "OMNI - vSphere brute force (>=5 échecs / source / 10 min)" 2 'alert_tag:vsphere_auth_fail' '["src_ip"]' "${CS}" "${CGE}" 30 10 5
ev_vs "OMNI - vSphere accès SSH/Shell ESXi" 2 'alert_tag:vsphere_shell_ssh' '[]' '[]' "${NC}" 60 10 5
ev_vs "OMNI - vSphere suppression de VM" 3 'alert_tag:vsphere_vm_destroy' '[]' '[]' "${NC}" 30 10 5

echo
echo "=== 19-vsphere.sh termine. Configurer ESXi/vCenter (cf. VSPHERE.md) puis 14. ==="
