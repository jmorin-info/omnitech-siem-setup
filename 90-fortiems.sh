#!/usr/bin/env bash
# =============================================================================
# 90-fortiems.sh - Integration FortiClient EMS (telemetrie endpoint).
#   FortiClient EMS (10.33.80.15) -> syslog-over-TLS -> input TLS 1518 (redirect
#   514->1518, cf 06-firewall.sh + cert /etc/graylog/fortiems-syslog.*). Format =
#   cle=valeur facon FortiGate (type=/subtype=/logid=/emsserial=/devid=/level=/msg=).
#   Cree : index set dedie omni-fortiems + stream (route gl2_source_input) + pipeline
#   (parse key_value + recup msg complet + normalisation severite/host) + detections.
#
#   MESURE-FIRST : format CONFIRME sur donnees reelles (events ems-adconnector vus).
#   Les events de SECURITE endpoint (malware AV, vulnerabilite, AV desactive) ne sont
#   pas encore apparus dans l'echantillon (sporadique) -> detections cadrees sur des
#   MARQUEURS ROBUSTES (contains insensible casse) plutot que des noms de champs non
#   encore observes. A CONFIRMER/affiner au 1er vrai event de securite.
# Idempotent. Prerequis : input EMS cree (titre "FortiClient EMS (Syslog TLS 1518)").
#   Relancer 14 (dashboard) ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [0/4] Certificat TLS + input Syslog TLS 1518 (l'EMS emet du syslog CHIFFRE)"
# FortiClient EMS envoie du syslog-over-TLS : input plain = charabia. Cert auto-signe
# accepte par l'EMS (pas de validation cote client). Redirect 514->1518 = 06-firewall.sh.
CRT=/etc/graylog/fortiems-syslog.cert.pem; KEY=/etc/graylog/fortiems-syslog.key.pem
if [[ ! -f "$CRT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CRT" -days 3650 -nodes \
    -subj "/CN=$(hostname -f 2>/dev/null || hostname)/O=OMNITECH" >/dev/null 2>&1 && ok "cert TLS genere"
fi
chown root:graylog "$CRT" "$KEY" 2>/dev/null || true; chmod 640 "$KEY" 2>/dev/null; chmod 644 "$CRT" 2>/dev/null
if [[ -z "$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title|test("FortiClient EMS";"i"))|.id' | head -1)" ]]; then
  jq -n --arg c "$CRT" --arg k "$KEY" '{title:"FortiClient EMS (Syslog TLS 1518)",type:"org.graylog2.inputs.syslog.tcp.SyslogTCPInput",global:true,configuration:{bind_address:"0.0.0.0",port:1518,recv_buffer_size:1048576,number_worker_threads:2,tls_enable:true,tls_cert_file:$c,tls_key_file:$k,tls_key_password:"",tls_client_auth:"disabled",tls_client_auth_cert_file:"",force_rdns:false,allow_override_date:true,expand_structured_data:true,store_full_message:true}}' \
    | api_post "/system/inputs" >/dev/null && { ok "input TLS 1518 cree"; sleep 4; } || warn "input refuse"
else skip "input FortiClient EMS existe"; fi

echo "==> [1/4] Index set dedie + stream 'OMNI - FortiClient EMS' (route sur l'input EMS)"
ensure_index_set() {  # prefix  titre  retention_indices -> stdout: id
  local PFX="$1" TITLE="$2" RET="$3" ID
  ID="$(api_get '/system/indices/index_sets?limit=200' | jq -r --arg p "$PFX" '.index_sets[]|select(.index_prefix==$p)|.id')"
  if [[ -n "$ID" ]]; then echo "$ID"; return; fi
  local TMPL; TMPL="$(api_get '/system/indices/index_sets?limit=200' | jq -c '.index_sets[]|select(.index_prefix=="omni-fortigate")')"
  ID="$(echo "$TMPL" | jq --arg t "$TITLE" --arg p "$PFX" --argjson r "$RET" \
        'del(.id,.creation_date,.default,.can_be_default) | .title=$t | .index_prefix=$p | .description=$t | .retention_strategy.max_number_of_indices=$r' \
        | api_post '/system/indices/index_sets' | jqr '.id')"
  [[ -n "$ID" && "$ID" != null ]] && ok "index set '$TITLE' cree" >&2 || warn "index set '$TITLE' refuse" >&2
  echo "$ID"
}
reassign_stream_idx() {  # stream_id  index_set_id
  local SID="$1" IDX="$2" CUR
  [[ -z "$SID" || -z "$IDX" ]] && return
  CUR="$(api_get "/streams/${SID}" | jq -r '.index_set_id')"
  [[ "$CUR" == "$IDX" ]] && return
  local CODE
  CODE="$(api_get "/streams/${SID}" | jq -c --arg i "$IDX" '{title,description,matching_type,remove_matches_from_default_stream,index_set_id:$i,rules:[.rules[]|{field,type,value,inverted}]}' \
    | "${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT "${API}/streams/${SID}" -H 'Content-Type: application/json' -d @-)"
  [[ "$CODE" == "200" ]] && ok "stream reaffecte a l'index set ${IDX}" >&2 || warn "reaffectation stream KO (HTTP ${CODE})" >&2
}

IID="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title|test("FortiClient EMS";"i"))|.id' | head -1)"
[[ -z "$IID" ]] && die "input 'FortiClient EMS' introuvable (le creer d'abord)"
echo "    input EMS id=${IID}"
IDX_EMS="$(ensure_index_set 'omni-fortiems' 'OMNI - FortiClient EMS' 90)"
if [[ -z "$(get_stream_id 'OMNI - FortiClient EMS')" ]]; then
  jq -n --arg idx "$IDX_EMS" --arg in "$IID" '{title:"OMNI - FortiClient EMS",description:"Telemetrie endpoint FortiClient EMS (syslog TLS)",matching_type:"AND",remove_matches_from_default_stream:true,index_set_id:$idx,
    rules:[{field:"gl2_source_input",type:1,value:$in,inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree ($SID)"; } || warn "stream refuse"; }
else skip "stream 'OMNI - FortiClient EMS' existe"; fi
ST_EMS="$(get_stream_id 'OMNI - FortiClient EMS')"
reassign_stream_idx "$ST_EMS" "$IDX_EMS"

echo "==> [2/4] Pipeline 'OMNI - FortiClient EMS' (parse KV + normalisation + detections)"
# --- Parse : key_value (eprouve FortiGate) + recup du msg="..." complet (que
#     key_value tronque au 1er espace). Gate sur le marqueur EMS 'emsserial='.
ensure_rule "omni-ems-00-parse" <<'EOF'
rule "omni-ems-00-parse"
when
  has_field("message") AND contains(to_string($message.message), "emsserial=", false)
then
  set_fields(
    key_value(
      value: to_string($message.message),
      delimiters: " ",
      kv_delimiters: "=",
      ignore_empty_values: true,
      allow_dup_keys: true,
      handle_dup_keys: "take_first",
      trim_value_chars: "\""
    )
  );
  set_field("event_source", "fortiems");
  set_field("event_category", "endpoint");
  set_fields(grok("msg=\"%{DATA:ems_msg}\"", to_string($message.message), true));
end
EOF
# --- Normalisation severite : level FortiClient (critical/warning/...) -> risk_severity FR.
ensure_rule "omni-ems-05-sev-crit" <<'EOF'
rule "omni-ems-05-sev-crit"
when to_string($message.event_source)=="fortiems" AND (lowercase(to_string($message.level))=="critical" OR lowercase(to_string($message.level))=="alert" OR lowercase(to_string($message.level))=="emergency")
then set_field("risk_severity","critique"); end
EOF
ensure_rule "omni-ems-05-sev-elev" <<'EOF'
rule "omni-ems-05-sev-elev"
when to_string($message.event_source)=="fortiems" AND (lowercase(to_string($message.level))=="error" OR lowercase(to_string($message.level))=="warning")
then set_field("risk_severity","eleve"); end
EOF
# --- Normalisation host : 1er champ d'identification de poste present (hostname/endpoint/device/devid).
ensure_rule "omni-ems-05-host" <<'EOF'
rule "omni-ems-05-host"
when to_string($message.event_source)=="fortiems"
then
  let h = to_string($message.hostname, to_string($message.endpoint, to_string($message.device, to_string($message.devid, ""))));
  set_field("host", h);
end
EOF

# --- DETECTIONS (marqueurs ROBUSTES contains() ; a CONFIRMER au 1er event securite) ---
# Malware/virus detecte par l'AV FortiClient sur un poste.
ensure_rule "omni-ems-10-malware" <<'EOF'
rule "omni-ems-10-malware"
when
  to_string($message.event_source)=="fortiems"
  AND ( contains(to_string($message.message),"malware",true)
     OR contains(to_string($message.message),"virus",true)
     OR contains(to_string($message.message),"infected",true)
     OR contains(to_string($message.message),"quarantin",true) )
then
  set_field("alert_tag","forticlient_malware");
  set_field("event_action","malware_endpoint");
end
EOF
# Vulnerabilite critique/haute detectee sur un poste.
ensure_rule "omni-ems-10-vuln" <<'EOF'
rule "omni-ems-10-vuln"
when
  to_string($message.event_source)=="fortiems"
  AND contains(to_string($message.message),"vulnerab",true)
  AND ( contains(to_string($message.message),"critical",true)
     OR contains(to_string($message.message),"high",true) )
then
  set_field("alert_tag","forticlient_vuln");
  set_field("event_action","vulnerabilite_critique_endpoint");
end
EOF
# Protection temps-reel / AV desactive(e) ou FortiClient altere (defense evasion).
ensure_rule "omni-ems-10-avoff" <<'EOF'
rule "omni-ems-10-avoff"
when
  to_string($message.event_source)=="fortiems"
  AND ( ( contains(to_string($message.message),"real-time",true) AND contains(to_string($message.message),"disabl",true) )
     OR ( contains(to_string($message.message),"protection",true) AND contains(to_string($message.message),"disabl",true) )
     OR contains(to_string($message.message),"tamper",true) )
then
  set_field("alert_tag","forticlient_av_off");
  set_field("event_action","protection_desactivee");
end
EOF
PL="$(ensure_pipeline "OMNI - FortiClient EMS" <<'PIPE'
pipeline "OMNI - FortiClient EMS"
stage 0 match either
rule "omni-ems-00-parse"
stage 5 match either
rule "omni-ems-05-sev-crit"
rule "omni-ems-05-sev-elev"
rule "omni-ems-05-host"
stage 10 match either
rule "omni-ems-10-malware"
rule "omni-ems-10-vuln"
rule "omni-ems-10-avoff"
end
PIPE
)"
[[ -n "$ST_EMS" ]] && connect_pipeline "$ST_EMS" "$PL"

echo "==> [3/4] MITRE (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || { echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; ok "MITRE +$1"; }; }
add_mitre forticlient_malware T1204     "Malware sur endpoint (FortiClient AV)"      "Execution"        critique 9
add_mitre forticlient_vuln    T1190     "Vulnerabilite exploitable (endpoint)"        "Initial Access"   eleve    7
add_mitre forticlient_av_off  T1562.001 "Impair Defenses: Disable/Modify Tools"       "Defense Evasion"  critique 8
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE forticlient_malware / forticlient_vuln / forticlient_av_off"

echo "==> [4/4] Routage event_source=fortiems hors des streams partages (deja dedie via input)"
echo
echo "=== 90 termine. Stream 'OMNI - FortiClient EMS' + parse KV + 3 detections (marqueurs)."
echo "    VERIFIER au 1er event securite reel : noms de champs (threat/endpoint/user) +"
echo "    declenchement des detections. Relancer 14 (dashboard). ==="
