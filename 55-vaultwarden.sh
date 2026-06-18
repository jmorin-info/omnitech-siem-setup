#!/usr/bin/env bash
# =============================================================================
# 55-vaultwarden.sh - Integration de la source Vaultwarden (coffre MDP).
#   Vaultwarden (Docker) -> Filebeat -> Beats 5044 (event_source=vaultwarden,
#   prefixe filebeat_ par l'input Beats, comme BunkerWeb). Cree le stream dedie,
#   l'exclut de 'OMNI - Windows autres', et un pipeline de normalisation +
#   detections (echecs d'auth, acces panneau admin). Kit client : /kit/vw-filebeat.sh
# Idempotent. Prerequis : 12 (lib), input Beats 5044. Relancer 14 pour le dashboard.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/3] Index set dedie + stream 'OMNI - Vaultwarden' (route sur filebeat_event_source)"
# Index set DEDIE (et NON l'index set Default 'graylog') : Vaultwarden peut emettre
# un gros volume, et Filebeat peut rejouer TOUT l'historique du conteneur au 1er
# demarrage (timestamps anciens). Sans index set dedie, ce flux remplit l'index set
# Default et finit par EVINCER les evenements internes du SIEM (vuln/ueba/ndr/
# incidents/siem_health) au fil des rotations. Retention 90 indices (comme BunkerWeb).
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
  # IMPORTANT : inclure 'rules' dans le corps PUT, sinon Graylog rejette (HTTP 400)
  # et curl sans -f ne le remonte pas -> reaffectation silencieusement perdue.
  local CODE
  CODE="$(api_get "/streams/${SID}" | jq -c --arg i "$IDX" '{title,description,matching_type,remove_matches_from_default_stream,index_set_id:$i,rules:[.rules[]|{field,type,value,inverted}]}' \
    | "${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT "${API}/streams/${SID}" -H 'Content-Type: application/json' -d @-)"
  [[ "$CODE" == "200" ]] && ok "stream reaffecte a l'index set ${IDX}" >&2 || warn "reaffectation stream KO (HTTP ${CODE})" >&2
}
IDX_VAULT="$(ensure_index_set 'omni-vaultwarden' 'OMNI - Vaultwarden' 90)"
if [[ -z "$(get_stream_id 'OMNI - Vaultwarden')" ]]; then
  jq -n --arg idx "$IDX_VAULT" '{title:"OMNI - Vaultwarden",description:"Coffre de mots de passe (Vaultwarden)",matching_type:"AND",remove_matches_from_default_stream:true,index_set_id:$idx,
    rules:[{field:"filebeat_event_source",type:1,value:"vaultwarden",inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree ($SID)"; } || warn "stream refuse"; }
else skip "stream 'OMNI - Vaultwarden' existe"; fi
ST_VW="$(get_stream_id 'OMNI - Vaultwarden')"
# Reaffecter le stream EXISTANT (cree avant sur l'index set Default) a son index set dedie.
reassign_stream_idx "$ST_VW" "$IDX_VAULT"

# exclure Vaultwarden de 'OMNI - Windows autres' (input Beats partage)
WO_ID="$(get_stream_id 'OMNI - Windows autres')"
if [[ -n "$WO_ID" ]] && ! "${CURL[@]}" "${API}/streams/${WO_ID}/rules" | jq -e '.stream_rules[]?|select(.field=="filebeat_event_source" and .value=="vaultwarden")' >/dev/null 2>&1; then
  "${CURL[@]}" -X POST "${API}/streams/${WO_ID}/rules" -H 'Content-Type: application/json' \
    -d '{"field":"filebeat_event_source","type":1,"value":"vaultwarden","inverted":true,"description":"Exclure Vaultwarden"}' >/dev/null 2>&1 \
    && ok "exclusion Vaultwarden ajoutee a 'OMNI - Windows autres'"
fi

echo "==> [2/3] Pipeline 'OMNI - Vaultwarden' (normalisation + detections)"
ensure_rule "omni-vw-00-normalise" <<'EOF'
rule "omni-vw-00-normalise"
when
  to_string($message.filebeat_event_source) == "vaultwarden"
then
  set_field("event_source", "vaultwarden");
  set_field("event_category", "vault");
end
EOF
# Drop du BRUIT de boucle : un conteneur de l'hote interroge /admin/ en boucle et
# se fait rate-limiter (reqwest::Error / 429) -> des millions de lignes inutiles
# (Filebeat capture tous les conteneurs). On les drope avant tout tag/stockage.
# Inclut "Too many admin requests" (rate-limit du conteneur en boucle, SANS src_ip
# = non actionnable, ~9k/j) : on le drope aussi. La vraie detection coffre =
# vault_auth_fail (echecs d'auth avec src_ip + compte), conservee.
ensure_rule "omni-vw-02-drop-loop" <<'EOF'
rule "omni-vw-02-drop-loop"
when
  to_string($message.filebeat_event_source) == "vaultwarden"
  AND ( contains(to_string($message.message), "reqwest::Error")
     OR contains(to_string($message.message), "too many admin requests", true)
     OR ( contains(to_string($message.message), "429 Too Many Requests")
          AND contains(to_string($message.message), "/admin") ) )
then
  drop_message();
end
EOF
# Parse du format Vaultwarden [ts][module][NIVEAU] msg + IP/Username sur echecs.
ensure_rule "omni-vw-05-parse" <<'EOF'
rule "omni-vw-05-parse"
when
  to_string($message.event_source) == "vaultwarden"
then
  set_fields(grok("\\[%{TIMESTAMP_ISO8601:vw_time}\\]\\[%{NOTSPACE:vw_module}\\]\\[%{WORD:vw_level}\\] %{GREEDYDATA:vw_msg}", to_string($message.message), true));
  set_fields(grok("IP: %{IP:src_ip}. Username: %{NOTSPACE:vault_user}", to_string($message.message), true));
end
EOF
# Fallback : les lignes de CONTINUATION d'erreur multi-lignes (stack traces type
# "Caused by:", "Error inviting users from ldap...", "0: ...") n'ont pas l'entete
# [ts][module][NIVEAU] -> non classees par le parse. On les marque vw_level=error
# si elles portent un marqueur d'erreur. Gate sur la FORME (pas sur vw_level, qui
# serait pose dans le meme stage -> course) : ligne ne commencant pas par "[".
ensure_rule "omni-vw-05-fallback" <<'EOF'
rule "omni-vw-05-fallback"
when
  to_string($message.event_source) == "vaultwarden"
  AND NOT starts_with(to_string($message.message), "[")
  AND ( contains(lowercase(to_string($message.message)), "error")
     OR contains(lowercase(to_string($message.message)), "failed")
     OR contains(lowercase(to_string($message.message)), "caused by")
     OR contains(lowercase(to_string($message.message)), "panic") )
then
  set_field("vw_level", "ERROR");
  set_field("vw_module", "multiline");
end
EOF
# Echec d'authentification au coffre (mauvais MDP / 2FA / utilisateur inconnu).
ensure_rule "omni-vw-10-authfail" <<'EOF'
rule "omni-vw-10-authfail"
when
  to_string($message.event_source) == "vaultwarden"
  AND ( contains(lowercase(to_string($message.message)), "username or password is incorrect")
     OR contains(lowercase(to_string($message.message)), "invalid totp")
     OR contains(lowercase(to_string($message.message)), "incorrect twostep")
     OR contains(lowercase(to_string($message.message)), "user not found")
     OR contains(lowercase(to_string($message.message)), "login attempt failed") )
then
  set_field("alert_tag", "vault_auth_fail");
end
EOF
# Acces / actions sur le panneau d'administration Vaultwarden.
ensure_rule "omni-vw-10-admin" <<'EOF'
rule "omni-vw-10-admin"
when
  to_string($message.event_source) == "vaultwarden"
  AND ( contains(lowercase(to_string($message.message)), "/admin")
     OR contains(lowercase(to_string($message.message)), "admin panel") )
then
  set_field("alert_tag", "vault_admin");
end
EOF
# Abus du panneau admin (rate-limit "Too many admin requests" = brute-force/sonde du coffre).
ensure_rule "omni-vw-10-adminabuse" <<'EOF'
rule "omni-vw-10-adminabuse"
when
  to_string($message.event_source) == "vaultwarden"
  AND contains(lowercase(to_string($message.message)), "too many admin requests")
then
  set_field("alert_tag", "vault_admin_abuse");
end
EOF
PL="$(ensure_pipeline "OMNI - Vaultwarden" <<'PIPE'
pipeline "OMNI - Vaultwarden"
stage 0 match either
rule "omni-vw-00-normalise"
rule "omni-vw-02-drop-loop"
stage 5 match either
rule "omni-vw-05-parse"
rule "omni-vw-05-fallback"
stage 10 match either
rule "omni-vw-10-authfail"
rule "omni-vw-10-admin"
rule "omni-vw-10-adminabuse"
end
PIPE
)"
[[ -n "$ST_VW" ]] && connect_pipeline "$ST_VW" "$PL"

echo "==> [3/3] MITRE (T1555 coffre / T1078 acces admin)"
CSV="lookups/mitre-attack.csv"
grep -q '^vault_auth_fail,' "$CSV" || echo 'vault_auth_fail,T1555.005,Password Managers,Credential Access,eleve,7' >> "$CSV"
grep -q '^vault_admin,'     "$CSV" || echo 'vault_admin,T1078,Valid Accounts,Defense Evasion,eleve,6' >> "$CSV"
grep -q '^vault_admin_abuse,' "$CSV" || echo 'vault_admin_abuse,T1110,Brute Force,Credential Access,critique,8' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE vault_auth_fail/vault_admin"
echo
echo "=== 55 termine. Cote serveur Vaultwarden : deployer /kit/vw-filebeat.sh."
echo "    Affiner le parsing des champs une fois de vraies lignes recues. Relancer 14. ==="
