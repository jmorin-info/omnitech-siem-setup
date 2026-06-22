#!/usr/bin/env bash
# =============================================================================
# 52-new-sources.sh - Integration de 3 nouvelles sources de logs :
#   - ESET PROTECT (10.33.50.20) : input Syslog TCP 1515 (514 redirige par le
#     pare-feu) -> stream "OMNI - ESET" -> event_source=eset (+ tag menace).
#   - BunkerWeb   (10.33.70.1)   : Filebeat -> Beats 5044 -> stream "OMNI -
#     BunkerWeb" (route par event_source=bunkerweb pose par Filebeat) -> tag WAF.
#   - NPS         (10.33.50.247) : RIEN ICI - deja gere (lookup win-events.csv
#     6272/6273/6274). Cote serveur : deployer Winlogbeat. (alerte ajoutee en 13.)
# Idempotent. Prerequis : 06 (pare-feu/redirect) + 07 (inputs) + 12.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
LOOKUP_DIR="/etc/graylog/lookup"

# ensure_lookup canonique (cf. piege : non centralise dans lib-graylog.sh).
ensure_lookup() {
  local NAME="$1" TITLE="$2" CSV="$3" KEY="$4" VAL="$5" AID CID
  AID="$(api_get "/system/lookup/adapters" | jq -r --arg n "omni-${NAME}-adapter" '.data_adapters[]? | select(.name==$n) | .id')"
  if [[ -z "${AID}" ]]; then
    AID="$(jq -n --arg n "omni-${NAME}-adapter" --arg t "${TITLE} (adapter)" --arg p "${LOOKUP_DIR}/${CSV}" --arg k "${KEY}" --arg v "${VAL}" '{
            name:$n,title:$t,description:"52-new-sources.sh",
            config:{type:"csvfile",path:$p,separator:",",quotechar:"\"",key_column:$k,value_column:$v,check_interval:60,case_insensitive_lookup:true,cidr_lookup:false}}' \
          | api_post "/system/lookup/adapters" | jqr '.id')"
    [[ -n "${AID}" && "${AID}" != "null" ]] || { warn "adapter ${NAME} refuse"; return 1; }
  fi
  CID="$(api_get "/system/lookup/caches" | jq -r --arg n "omni-${NAME}-cache" '.caches[]? | select(.name==$n) | .id')"
  if [[ -z "${CID}" ]]; then
    CID="$(jq -n --arg n "omni-${NAME}-cache" --arg t "${TITLE} (cache)" '{
            name:$n,title:$t,description:"52-new-sources.sh",
            config:{type:"guava_cache",max_size:1000,expire_after_access:300,expire_after_access_unit:"SECONDS",expire_after_write:300,expire_after_write_unit:"SECONDS",ignore_null:false,ttl_empty:60,ttl_empty_unit:"SECONDS"}}' \
          | api_post "/system/lookup/caches" | jqr '.id')"
    [[ -n "${CID}" && "${CID}" != "null" ]] || { warn "cache ${NAME} refuse"; return 1; }
  fi
  if [[ -z "$(api_get "/system/lookup/tables" | jq -r --arg n "omni-${NAME}" '.lookup_tables[]? | select(.name==$n) | .id')" ]]; then
    jq -n --arg n "omni-${NAME}" --arg t "${TITLE}" --arg a "${AID}" --arg c "${CID}" '{
            name:$n,title:$t,description:"52-new-sources.sh",data_adapter_id:$a,cache_id:$c,
            default_single_value:"",default_single_value_type:"NULL",default_multi_value:"",default_multi_value_type:"NULL"}' \
      | api_post "/system/lookup/tables" | jqr '.id' >/dev/null && ok "table 'omni-${NAME}'" || warn "table ${NAME} refusee"
  else skip "table 'omni-${NAME}' existe"; fi
}

echo "==> [1/4] Input Syslog TCP ESET (port ${ESET_PORT})"
create_input() {  # titre json
  local T="$1" J="$2"
  if api_get "/system/inputs" | jq -e --arg t "$T" '.inputs[]|select(.title==$t)' >/dev/null; then
    skip "input '${T}' existe"
  else
    echo "$J" | post_entity "/system/inputs" | jqr '.id' >/dev/null && ok "input '${T}' cree" || warn "input '${T}' refuse"
  fi
}
create_input "ESET (Syslog TCP ${ESET_PORT})" "$(cat <<EOF
{ "title": "ESET (Syslog TCP ${ESET_PORT})",
  "type": "org.graylog2.inputs.syslog.tcp.SyslogTCPInput", "global": true,
  "configuration": { "bind_address": "0.0.0.0", "port": ${ESET_PORT},
    "recv_buffer_size": 1048576, "number_worker_threads": 2,
    "force_rdns": false, "allow_override_date": true, "store_full_message": true,
    "expand_structured_data": true, "tls_enable": false } }
EOF
)"
ESET_INPUT_ID="$(api_get "/system/inputs" | jq -r '.inputs[]|select(.title|startswith("ESET"))|.id' | head -1)"
echo "    ESET input id = ${ESET_INPUT_ID}"

echo "==> [2/4] Streams (OMNI - ESET, OMNI - BunkerWeb)"
IDX_DEFAULT="$(api_get '/system/indices/index_sets?limit=100' | jq -r '.index_sets[]|select(.index_prefix=="graylog")|.id')"
mk_stream() {  # titre  regle_json  description  (logs vers stderr, rien sur stdout)
  local T="$1" RULE="$2" D="$3" SID
  if [[ -n "$(get_stream_id "$T")" ]]; then skip "stream '$T' existe" >&2; return; fi
  SID="$(jq -n --arg t "$T" --arg d "$D" --arg idx "$IDX_DEFAULT" --argjson r "$RULE" \
    '{title:$t, description:$d, matching_type:"AND", remove_matches_from_default_stream:true, index_set_id:$idx, rules:$r}' \
    | post_entity "/streams" | jqr '.stream_id // .id')"
  if [[ -n "$SID" && "$SID" != null ]]; then
    "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1
    ok "stream '$T' cree ($SID)" >&2
  else warn "stream '$T' refuse" >&2; fi
}
mk_stream "OMNI - ESET" "$(jq -n --arg i "$ESET_INPUT_ID" '[{field:"gl2_source_input",type:1,value:$i,inverted:false}]')" "Logs ESET PROTECT (syslog)"
mk_stream "OMNI - BunkerWeb" '[{field:"filebeat_event_source",type:1,value:"bunkerweb",inverted:false}]' "Logs WAF BunkerWeb (Filebeat)"
ST_ESET="$(get_stream_id 'OMNI - ESET')"
ST_BW="$(get_stream_id 'OMNI - BunkerWeb')"

# Index sets dedies (clone du modele omni-fortigate, retention adaptee) +
# reaffectation des streams : ESET = 365j (forensique), BunkerWeb = 90j (volume).
ensure_index_set() {  # prefix  titre  retention_indices  -> stdout: id
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
  [[ "$CUR" == "$IDX" ]] && { skip "stream deja sur son index set" >&2; return; }
  api_get "/streams/${SID}" | jq -c '{title,description,matching_type,remove_matches_from_default_stream,index_set_id:"'"$IDX"'"}' \
    | "${CURL[@]}" -X PUT "${API}/streams/${SID}" -H 'Content-Type: application/json' -d @- >/dev/null 2>&1 \
    && ok "stream reaffecte a l'index set ${IDX}" >&2
}
IDX_ESET="$(ensure_index_set 'omni-eset' 'OMNI - ESET' 365)"
IDX_BW="$(ensure_index_set 'omni-bunkerweb' 'OMNI - BunkerWeb' 90)"
reassign_stream_idx "$ST_ESET" "$IDX_ESET"
reassign_stream_idx "$ST_BW" "$IDX_BW"

# BunkerWeb arrive par l'input Beats partage -> il matche aussi 'OMNI - Windows
# autres'. On l'en exclut (sinon double routage + stockage dans l'index winother).
WO_ID="$(get_stream_id 'OMNI - Windows autres')"
if [[ -n "$WO_ID" ]]; then
  if ! "${CURL[@]}" "${API}/streams/${WO_ID}/rules" | jq -e '.stream_rules[]?|select(.field=="filebeat_event_source" and .inverted==true)' >/dev/null 2>&1; then
    "${CURL[@]}" -X POST "${API}/streams/${WO_ID}/rules" -H 'Content-Type: application/json' \
      -d '{"field":"filebeat_event_source","type":1,"value":"bunkerweb","inverted":true,"description":"Exclure BunkerWeb (route vers OMNI - BunkerWeb)"}' >/dev/null 2>&1 \
      && ok "exclusion BunkerWeb ajoutee a 'OMNI - Windows autres'"
  else skip "exclusion BunkerWeb deja sur 'OMNI - Windows autres'"; fi
fi

echo "==> [3/4] Pipeline 'OMNI - Sources externes' (normalisation + tags)"
ensure_rule "omni-eset-00-normalise" <<EOF
rule "omni-eset-00-normalise"
when
  to_string(\$message.gl2_source_input) == "${ESET_INPUT_ID}"
then
  set_field("event_source", "eset");
  set_field("event_category", "antivirus");
end
EOF
# ESET PROTECT envoie en JSON (event_type, severity, threat_name, object_uri...).
# On strip le prefixe syslog (tout avant le 1er '{') puis parse -> champs eset_*.
ensure_rule "omni-eset-05-json" <<'EOF'
rule "omni-eset-05-json"
when
  to_string($message.event_source) == "eset"
  AND contains(to_string($message.message), "{")
then
  let raw = to_string($message.message);
  let js = regex_replace("^[^{]*", raw, "");
  let parsed = parse_json(js);
  let m = to_map(parsed);
  set_fields(m, "eset_");
end
EOF
ensure_rule "omni-eset-10-menace" <<'EOF'
rule "omni-eset-10-menace"
when
  to_string($message.event_source) == "eset"
  AND ( to_string($message.eset_event_type) == "Threat_Event"
     OR to_string($message.eset_event_type) == "HipsAggregated_Event"
     OR contains(to_string($message.message), "Threat", true)
     OR contains(to_string($message.message), "ransomware", true)
     OR contains(to_string($message.message), "quarantine", true) )
then
  set_field("alert_tag", "eset_detection");
end
EOF
ensure_rule "omni-bunkerweb-00-normalise" <<'EOF'
rule "omni-bunkerweb-00-normalise"
when
  to_string($message.filebeat_event_source) == "bunkerweb"
then
  set_field("event_source", "bunkerweb");
  set_field("event_category", "waf");
end
EOF
# Parsing des logs d'acces nginx/BunkerWeb : vhost, IP source, methode, URL,
# code HTTP (int), octets, referer, user-agent. Les lignes d'erreur (sans HTTP/)
# ne matchent pas -> grok renvoie une map vide -> aucun champ pose (sans danger).
ensure_rule "omni-bunkerweb-05-parse" <<'EOF'
rule "omni-bunkerweb-05-parse"
when
  to_string($message.event_source) == "bunkerweb"
  AND contains(to_string($message.message), "HTTP/")
then
  let m = grok("%{IPORHOST:waf_vhost} %{IPORHOST:src_ip} - %{NOTSPACE:waf_reqid} - \\[%{HTTPDATE:waf_time}\\] \"%{WORD:http_method} %{NOTSPACE:http_url} HTTP/%{NOTSPACE:http_ver}\" %{INT:http_status:int} %{INT:http_bytes:int} \"%{DATA:http_referer}\" \"%{DATA:http_user_agent}\"",
                to_string($message.message), true);
  set_fields(m);
end
EOF
# Anti-HALT du stage 5 : regle pass-through qui matche TOUTE source externe.
# Sans elle, une ligne non parsable (BunkerWeb hors format access-log : blocage
# ModSecurity, erreur, demarrage ; ou ESET sans '{') ne matche aucune regle du
# stage 5 'match either' -> le pipeline STOPPE -> stages 6/7/10 sautes (perte de
# la detection waf_block, qui se base sur le texte du message, pas sur http_status).
ensure_rule "omni-ext-05-pass" <<'EOF'
rule "omni-ext-05-pass"
when
  to_string($message.event_source) == "eset"
  OR to_string($message.event_source) == "bunkerweb"
then
  let noop = true;
end
EOF
ensure_rule "omni-bunkerweb-10-block" <<'EOF'
rule "omni-bunkerweb-10-block"
when
  to_string($message.event_source) == "bunkerweb"
  AND ( to_long($message.http_status, 0) == 403
     OR contains(to_string($message.message), "ModSecurity", true)
     OR contains(to_string($message.message), "denied", true)
     OR contains(to_string($message.message), "blocked", true) )
then
  set_field("alert_tag", "waf_block");
end
EOF
echo "==> [3a] BunkerWeb : drop du bruit stderr/metrics (~97% du volume)"
# Lignes Docker stderr repetitives (lua "no memory" / timer metrics) sans valeur
# securite -> drop_message() pour ne pas saturer l'index. ModSecurity/erreurs reelles
# preservees (motifs cibles uniquement). Stage 1 : apres normalise (stage 0).
ensure_rule "omni-bunkerweb-02-drop-noise" <<'EOF'
rule "omni-bunkerweb-02-drop-noise"
when
  to_string($message.filebeat_event_source) == "bunkerweb"
  AND ( contains(to_string($message.message), "metrics:timer() call failed")
     OR contains(to_string($message.message), "[METRICS] can't update")
     OR contains(to_string($message.message), "badbehavior_table") )
then
  drop_message();
end
EOF
# WAF : tag externe + threat intel sur src_ip publiques (parite FortiGate).
ensure_rule "omni-bunkerweb-06-threatintel-src" <<'EOF'
rule "omni-bunkerweb-06-threatintel-src"
when
  to_string($message.event_source) == "bunkerweb" AND has_field("src_ip")
  AND NOT cidr_match("10.0.0.0/8",     to_ip(to_string($message.src_ip),"0.0.0.0"))
  AND NOT cidr_match("192.168.0.0/16", to_ip(to_string($message.src_ip),"0.0.0.0"))
  AND NOT cidr_match("172.16.0.0/12",  to_ip(to_string($message.src_ip),"0.0.0.0"))
  AND NOT cidr_match("127.0.0.0/8",    to_ip(to_string($message.src_ip),"0.0.0.0"))
then
  set_field("waf_src_externe", true);
  set_fields(threat_intel_lookup_ip(to_string($message.src_ip), "src_ip"));
end
EOF

echo "==> [3b] Enrichissement approfondi (score ESET, classe HTTP, outils WAF, 5xx)"
install -m 644 lookups/eset-severity.csv "${LOOKUP_DIR}/"; chown root:graylog "${LOOKUP_DIR}/eset-severity.csv" 2>/dev/null || true
ensure_lookup "eset-severity" "ESET severite -> score" "eset-severity.csv" "severity" "score"

# --- ESET : score de risque depuis la severite (lookup, defaut 3) ---
ensure_rule "omni-eset-06-score" <<'EOF'
rule "omni-eset-06-score"
when
  to_string($message.event_source) == "eset" AND has_field("eset_severity")
then
  set_field("eset_risk_score", to_long(lookup_value("omni-eset-severity", lowercase(to_string($message.eset_severity))), 3));
  // event_action generique (depuis eset_event_type) -> integre ESET dans les vues
  // cross-source / Investigation (threat_event, filteredwebsites_event, audit_event...).
  set_field("event_action", lowercase(to_string($message.eset_event_type, "eset_event")));
end
EOF
# --- ESET : triage menace remediee vs non remediee (base + override) ---
# Base : toute menace ESET porteuse d'une action (eset_action sur HIPS/FilteredWebsites,
# eset_action_taken sur Threat_Event) part "non remediee", l'override stage 7 la requalifie.
ensure_rule "omni-eset-06-outcome-base" <<'EOF'
rule "omni-eset-06-outcome-base"
when
  to_string($message.event_source) == "eset"
  AND ( has_field("eset_action") OR has_field("eset_action_taken") )
then
  set_field("eset_outcome", "non_remediee");
  set_field("eset_non_remediee", true);
end
EOF
# Override "remediee" : on lit eset_action ET eset_action_taken (Threat_Event = action_taken,
# ex EICAR "Cleaned by deleting"). Sans le 2e champ, les Threat_Event restaient non classes.
ensure_rule "omni-eset-07-outcome-ok" <<'EOF'
rule "omni-eset-07-outcome-ok"
when
  to_string($message.event_source) == "eset"
  AND ( contains(lowercase(to_string($message.eset_action)), "clean")
     OR contains(lowercase(to_string($message.eset_action)), "delet")
     OR contains(lowercase(to_string($message.eset_action)), "quarant")
     OR contains(lowercase(to_string($message.eset_action)), "block")
     OR contains(lowercase(to_string($message.eset_action_taken)), "clean")
     OR contains(lowercase(to_string($message.eset_action_taken)), "delet")
     OR contains(lowercase(to_string($message.eset_action_taken)), "quarant")
     OR contains(lowercase(to_string($message.eset_action_taken)), "block") )
then
  set_field("eset_outcome", "remediee");
  set_field("eset_non_remediee", false);
end
EOF
# Anti-HALT du stage 7 : sans ce pass-through, une menace ESET sans action remediante
# (Threat_Event non nettoye, action_taken vide/erreur) ne matche AUCUNE regle du stage 7
# 'match either' -> pipeline STOPPE -> stage 10 saute -> alert_tag jamais pose -> alerte
# "ESET : detection" muette. La regle matche toute source ESET et ne fait rien (noop).
ensure_rule "omni-eset-07-pass" <<'EOF'
rule "omni-eset-07-pass"
when
  to_string($message.event_source) == "eset"
then
  let noop = true;
end
EOF
# --- ESET : source = vrai poste (corrige source=mois syslog FR) ---
ensure_rule "omni-eset-08-source-fix" <<'EOF'
rule "omni-eset-08-source-fix"
when
  has_field("eset_hostname") AND to_string($message.eset_hostname) != ""
then
  set_field("source", to_string($message.eset_hostname));
end
EOF
# --- WAF : classe de code HTTP (2xx/3xx/4xx/5xx) ---
ensure_rule "omni-bunkerweb-06-class-2xx" <<'EOF'
rule "omni-bunkerweb-06-class-2xx"
when to_string($message.event_source)=="bunkerweb" AND to_long($message.http_status,0)>=200 AND to_long($message.http_status,0)<300
then set_field("http_status_class","2xx"); end
EOF
ensure_rule "omni-bunkerweb-06-class-3xx" <<'EOF'
rule "omni-bunkerweb-06-class-3xx"
when to_string($message.event_source)=="bunkerweb" AND to_long($message.http_status,0)>=300 AND to_long($message.http_status,0)<400
then set_field("http_status_class","3xx"); end
EOF
ensure_rule "omni-bunkerweb-06-class-4xx" <<'EOF'
rule "omni-bunkerweb-06-class-4xx"
when to_string($message.event_source)=="bunkerweb" AND to_long($message.http_status,0)>=400 AND to_long($message.http_status,0)<500
then set_field("http_status_class","4xx"); end
EOF
ensure_rule "omni-bunkerweb-06-class-5xx" <<'EOF'
rule "omni-bunkerweb-06-class-5xx"
when to_string($message.event_source)=="bunkerweb" AND to_long($message.http_status,0)>=500 AND to_long($message.http_status,0)<600
then set_field("http_status_class","5xx"); end
EOF
# --- WAF : backend en erreur (5xx) -> champs dedies (n'ecrase PAS alert_tag) ---
ensure_rule "omni-bunkerweb-12-backend-down" <<'EOF'
rule "omni-bunkerweb-12-backend-down"
when to_string($message.event_source)=="bunkerweb" AND to_long($message.http_status,0)>=500 AND to_long($message.http_status,0)<600
then
  set_field("waf_backend_down", true);
  set_field("waf_anomalie", "backend_5xx");
end
EOF
# --- WAF : user-agent d'outil offensif (flag, OR dans le when) ---
ensure_rule "omni-bunkerweb-12-ua-outil" <<'EOF'
rule "omni-bunkerweb-12-ua-outil"
when
  to_string($message.event_source)=="bunkerweb" AND has_field("http_user_agent")
  AND ( contains(lowercase(to_string($message.http_user_agent)),"sqlmap")
     OR contains(lowercase(to_string($message.http_user_agent)),"nikto")
     OR contains(lowercase(to_string($message.http_user_agent)),"nmap")
     OR contains(lowercase(to_string($message.http_user_agent)),"masscan")
     OR contains(lowercase(to_string($message.http_user_agent)),"gobuster")
     OR contains(lowercase(to_string($message.http_user_agent)),"dirbuster")
     OR contains(lowercase(to_string($message.http_user_agent)),"wpscan")
     OR contains(lowercase(to_string($message.http_user_agent)),"hydra")
     OR contains(lowercase(to_string($message.http_user_agent)),"python-requests")
     OR contains(lowercase(to_string($message.http_user_agent)),"go-http-client") )
then
  set_field("waf_ua_outil", true);
end
EOF

# [FIX waf_block] Anti-HALT stage 7 pour BunkerWeb : sans ce pass-through, un event
# bunkerweb ne matche AUCUNE regle du stage 7 (qui n'avait que des regles ESET) -> le
# pipeline 'match either' STOPPE -> le stage 10 saute -> omni-bunkerweb-10-block (et
# 12-backend-down / 12-ua-outil) ne tournent jamais. Mesure : 1103 HTTP-403 reels,
# 0 waf_block taggue. Ce pass-through laisse les events bunkerweb atteindre le stage 10.
ensure_rule "omni-bunkerweb-07-pass" <<'EOF'
rule "omni-bunkerweb-07-pass"
when
  to_string($message.event_source) == "bunkerweb"
then
  let noop = true;
end
EOF

PL="$(ensure_pipeline "OMNI - Sources externes" <<'PIPE'
pipeline "OMNI - Sources externes"
stage 0 match either
rule "omni-eset-00-normalise"
rule "omni-bunkerweb-00-normalise"
rule "omni-bunkerweb-02-drop-noise"
stage 5 match either
rule "omni-eset-05-json"
rule "omni-bunkerweb-05-parse"
rule "omni-ext-05-pass"
stage 6 match either
rule "omni-eset-06-score"
rule "omni-eset-06-outcome-base"
rule "omni-eset-08-source-fix"
rule "omni-bunkerweb-06-class-2xx"
rule "omni-bunkerweb-06-class-3xx"
rule "omni-bunkerweb-06-class-4xx"
rule "omni-bunkerweb-06-class-5xx"
rule "omni-bunkerweb-06-threatintel-src"
stage 7 match either
rule "omni-eset-07-outcome-ok"
rule "omni-eset-07-pass"
rule "omni-bunkerweb-07-pass"
stage 10 match either
rule "omni-eset-10-menace"
rule "omni-bunkerweb-10-block"
rule "omni-bunkerweb-12-backend-down"
rule "omni-bunkerweb-12-ua-outil"
end
PIPE
)"
for S in "$ST_ESET" "$ST_BW"; do [[ -n "$S" ]] && connect_pipeline "$S" "$PL"; done

echo "==> [4/4] MITRE + couleurs (relancer 14)"
CSV="lookups/mitre-attack.csv"
grep -q '^eset_detection,' "$CSV" || echo 'eset_detection,T1059,Command and Scripting Interpreter,Execution,eleve,6' >> "$CSV"
grep -q '^waf_block,' "$CSV"     || echo 'waf_block,T1190,Exploit Public-Facing Application,Initial Access,eleve,6' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE eset_detection/waf_block"
echo
echo "=== 52 termine. Cote sources : ESET=deja configure (514) ; NPS=Winlogbeat sur ${IP_NPS} ;"
echo "    BunkerWeb=Filebeat (voir docs/INTEGRATION-BUNKERWEB.md). Relancer 13 + 14. ==="
