# ==============================================================================
# lib-graylog.sh - Helpers communs aux scripts 10-14 (provisioning API Graylog)
# A sourcer APRES 00-vars.env. Ne s'execute pas seul.
#
# Point cle Graylog 7.x : les POST de creation d'entites "partageables"
# (streams, event definitions, notifications, views/dashboards) exigent
# l'enveloppe CreateEntityRequest :
#   { "entity": { ...objet... }, "share_request": {"selected_grantee_capabilities": {}} }
# -> wrap_entity ajoute cette enveloppe (c'etait la cause du "ECHEC stream"
#    avec l'ancien script ecrit pour le schema 6.x).
# ==============================================================================

# API en TLS de bout en bout (cert PKI, FQDN resolu en 127.0.0.1 via /etc/hosts)
API="https://${SIEM_FQDN}:9000/api"
API_CA="/etc/graylog/certs/omnitech-rootca.crt"
CURL=(curl -s --cacert "${API_CA}" -u "admin:${GRAYLOG_ADMIN_PASS}" -H "Content-Type: application/json" -H "X-Requested-By: omni-provision")

jqr()       { jq -r "$1" 2>/dev/null; }
api_get()   { "${CURL[@]}" "${API}$1"; }
api_post()  { "${CURL[@]}" -X POST "${API}$1" -d @-; }   # JSON sur stdin
api_put()   { "${CURL[@]}" -X PUT  "${API}$1" -d @-; }   # JSON sur stdin
api_del()   { "${CURL[@]}" -X DELETE "${API}$1"; }

wrap_entity() { jq '{entity: ., share_request: {selected_grantee_capabilities: {}}}'; }

die()  { echo "ERREUR: $*" >&2; exit 1; }
ok()   { echo "    [+] $*"; }
skip() { echo "    [=] $*"; }
warn() { echo "    [!] $*"; }

# Verifie que l'API repond avant d'aller plus loin
require_api() {
  api_get "/system" | jq -e '.version' >/dev/null 2>&1 \
    || die "API Graylog injoignable sur 127.0.0.1:9000 (service graylog-server ?)"
}

# ------------------------------------------------------------------ index sets
# get_index_set_id <prefixe>  -> id ou vide
get_index_set_id() {
  api_get "/system/indices/index_sets?skip=0&limit=200" \
    | jq -r --arg p "$1" '.index_sets[] | select(.index_prefix==$p) | .id'
}

# --------------------------------------------------------------------- streams
# get_stream_id <titre> -> id ou vide
get_stream_id() {
  api_get "/streams" | jq -r --arg t "$1" '.streams[] | select(.title==$t) | .id'
}

# ------------------------------------------------------------------- pipelines
# ensure_rule <titre>  (source DSL sur stdin) : cree ou MET A JOUR si different
ensure_rule() {
  local TITLE="$1" SRC; SRC="$(cat)"
  local CUR ID CURSRC
  CUR="$(api_get "/system/pipelines/rule" | jq -r --arg t "${TITLE}" '[.[] | select(.title==$t)][0] // empty | @base64')"
  if [[ -z "${CUR}" ]]; then
    ID="$(jq -n --arg t "${TITLE}" --arg s "${SRC}" '{title:$t, description:"provisionne par 12-graylog-pipelines.sh", source:$s}' \
          | api_post "/system/pipelines/rule" | jqr '.id')"
    [[ -n "${ID}" && "${ID}" != "null" ]] && ok "regle '${TITLE}'" || warn "regle '${TITLE}' REFUSEE"
  else
    ID="$(echo "${CUR}" | base64 -d | jq -r '.id')"
    CURSRC="$(echo "${CUR}" | base64 -d | jq -r '.source')"
    if [[ "${CURSRC}" != "${SRC}" ]]; then
      jq -n --arg t "${TITLE}" --arg s "${SRC}" --arg i "${ID}" \
        '{id:$i, title:$t, description:"provisionne par 12-graylog-pipelines.sh", source:$s}' \
        | api_put "/system/pipelines/rule/${ID}" >/dev/null
      ok "regle '${TITLE}' mise a jour"
    else
      skip "regle '${TITLE}' inchangee"
    fi
  fi
}

# ensure_pipeline <titre> (source DSL sur stdin) : cree ou met a jour -> echo id
ensure_pipeline() {
  local TITLE="$1" SRC; SRC="$(cat)"
  local CUR ID CURSRC
  CUR="$(api_get "/system/pipelines/pipeline" | jq -r --arg t "${TITLE}" '[.[] | select(.title==$t)][0] // empty | @base64')"
  if [[ -z "${CUR}" ]]; then
    ID="$(jq -n --arg t "${TITLE}" --arg s "${SRC}" '{title:$t, description:"provisionne par 12-graylog-pipelines.sh", source:$s}' \
          | api_post "/system/pipelines/pipeline" | jqr '.id')"
    [[ -n "${ID}" && "${ID}" != "null" ]] && ok "pipeline '${TITLE}' (${ID})" >&2 || { warn "pipeline '${TITLE}' REFUSE" >&2; return 1; }
  else
    ID="$(echo "${CUR}" | base64 -d | jq -r '.id')"
    CURSRC="$(echo "${CUR}" | base64 -d | jq -r '.source')"
    if [[ "${CURSRC}" != "${SRC}" ]]; then
      jq -n --arg t "${TITLE}" --arg s "${SRC}" --arg i "${ID}" \
        '{id:$i, title:$t, description:"provisionne par 12-graylog-pipelines.sh", source:$s}' \
        | api_put "/system/pipelines/pipeline/${ID}" >/dev/null
      ok "pipeline '${TITLE}' mis a jour" >&2
    else
      skip "pipeline '${TITLE}' inchange" >&2
    fi
  fi
  echo "${ID}"
}

# post_entity <path> : POST direct ; si l'API exige l'enveloppe CreateEntityRequest
# ("entity cannot be null"), retente enveloppe. Echo la reponse brute.
post_entity() {
  local BODY RES; BODY="$(cat)"
  RES="$(echo "${BODY}" | api_post "$1")"
  if echo "${RES}" | grep -q "entity cannot be null"; then
    RES="$(echo "${BODY}" | wrap_entity | api_post "$1")"
  fi
  echo "${RES}"
}

# connect_pipeline <stream_id> <pipeline_id> : ajoute sans ecraser les existants
connect_pipeline() {
  local SID="$1" PID="$2" CURRENT
  CURRENT="$(api_get "/system/pipelines/connections/${SID}" | jq -r '.pipeline_ids // [] | .[]' 2>/dev/null)"
  if echo "${CURRENT}" | grep -q "^${PID}$"; then skip "pipeline deja connecte au stream ${SID}"; return; fi
  jq -n --arg s "${SID}" --argjson p "$(printf '%s\n' ${CURRENT} ${PID} | grep -v '^$' | jq -R . | jq -s 'unique')" \
     '{stream_id:$s, pipeline_ids:$p}' \
    | api_post "/system/pipelines/connections/to_stream" >/dev/null \
    && ok "pipeline connecte au stream ${SID}"
}

# ensure_lookup NAME TITLE CSV KEY VAL [DESC] - cree (idempotent) adapter csvfile +
# cache guava + table de lookup 'omni-NAME'. Version CANONIQUE unique (avant : copiee
# dans 11/37/49/49-expo, ABSENTE de 48 -> lookup m365 jamais cree, echec silencieux).
# Utilise $LOOKUP_DIR (defini par le script appelant). DESC optionnel (defaut generique).
ensure_lookup() {
  local NAME="$1" TITLE="$2" CSV="$3" KEY="$4" VAL="$5" DESC="${6:-provisionne par OMNITECH (lib-graylog.sh)}"
  local AID CID TID
  AID="$(api_get "/system/lookup/adapters" | jq -r --arg n "omni-${NAME}-adapter" '.data_adapters[]? | select(.name==$n) | .id')"
  if [[ -z "${AID}" ]]; then
    AID="$(jq -n --arg n "omni-${NAME}-adapter" --arg t "${TITLE} (adapter)" --arg d "${DESC}" \
                 --arg p "${LOOKUP_DIR}/${CSV}" --arg k "${KEY}" --arg v "${VAL}" '{
            name:$n, title:$t, description:$d,
            config:{ type:"csvfile", path:$p, separator:",", quotechar:"\"",
                     key_column:$k, value_column:$v, check_interval:60,
                     case_insensitive_lookup:true, cidr_lookup:false }
          }' | api_post "/system/lookup/adapters" | jqr '.id')"
    [[ -n "${AID}" && "${AID}" != "null" ]] || { warn "adapter ${NAME} refuse"; return 1; }
  fi
  CID="$(api_get "/system/lookup/caches" | jq -r --arg n "omni-${NAME}-cache" '.caches[]? | select(.name==$n) | .id')"
  if [[ -z "${CID}" ]]; then
    CID="$(jq -n --arg n "omni-${NAME}-cache" --arg t "${TITLE} (cache)" --arg d "${DESC}" '{
            name:$n, title:$t, description:$d,
            config:{ type:"guava_cache", max_size:1000,
                     expire_after_access:300, expire_after_access_unit:"SECONDS",
                     expire_after_write:300,  expire_after_write_unit:"SECONDS",
                     ignore_null:false, ttl_empty:60, ttl_empty_unit:"SECONDS" }
          }' | api_post "/system/lookup/caches" | jqr '.id')"
    [[ -n "${CID}" && "${CID}" != "null" ]] || { warn "cache ${NAME} refuse"; return 1; }
  fi
  TID="$(api_get "/system/lookup/tables" | jq -r --arg n "omni-${NAME}" '.lookup_tables[]? | select(.name==$n) | .id')"
  if [[ -z "${TID}" ]]; then
    jq -n --arg n "omni-${NAME}" --arg t "${TITLE}" --arg a "${AID}" --arg c "${CID}" --arg d "${DESC}" '{
            name:$n, title:$t, description:$d,
            data_adapter_id:$a, cache_id:$c,
            default_single_value:"", default_single_value_type:"NULL",
            default_multi_value:"",  default_multi_value_type:"NULL"
          }' | api_post "/system/lookup/tables" | jqr '.id' >/dev/null \
      && ok "table 'omni-${NAME}'" || { warn "table ${NAME} refusee"; return 1; }
  else skip "table 'omni-${NAME}' existe"; fi
}
