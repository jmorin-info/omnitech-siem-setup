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

# Recupere TOUTES les definitions d'evenements en PAGINANT. Indispensable : le
# catalogue depasse ~170 defs, donc un simple ?per_page=100 (1ere page) rend
# invisibles au garde d'existence les defs au-dela du rang 100 -> re-creation =
# DOUBLONS (cf incident des 11 alertes en double). Sortie : {event_definitions:[...]}.
all_event_defs() {
  local page=1 resp n total tmp; tmp="$(mktemp)"; echo '[]' > "${tmp}"
  while :; do
    resp="$(api_get "/events/definitions?per_page=100&page=${page}")"
    n="$(echo "${resp}" | jq '(.event_definitions // .elements // []) | length' 2>/dev/null)"
    [[ -z "${n}" || "${n}" -eq 0 ]] && break
    # fusion via fichiers (jq -s) : evite la limite d'argv sur de gros objets
    echo "${resp}" | jq -c '(.event_definitions // .elements // [])' > "${tmp}.pg"
    jq -s -c '.[0] + .[1]' "${tmp}" "${tmp}.pg" > "${tmp}.nx" && mv "${tmp}.nx" "${tmp}"
    total="$(echo "${resp}" | jq -r '.total // 0' 2>/dev/null)"
    (( page*100 >= ${total:-0} )) && break
    (( page++ )); (( page > 100 )) && break   # garde-fou anti-boucle
  done
  jq -c '{event_definitions: .}' "${tmp}"; rm -f "${tmp}" "${tmp}.pg" "${tmp}.nx"
}
# Id d'une definition d'evenement par titre (paginee). Vide si absente.
event_def_id() { all_event_defs | jq -r --arg t "$1" '.event_definitions[] | select(.title==$t) | .id' | head -1; }
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

# ============================================================================
# CONVERGENCE DES DEFINITIONS D'EVENEMENTS (RC-7 - detecteur de derive)
# ----------------------------------------------------------------------------
# CONTEXTE : ensure_event() (defini dans 13-graylog-alerts.sh:256) est
# CREATE-ONLY ("if exists, skip"). Corriger une def au depot ne met donc JAMAIS
# a jour l'instance vivante -> le depot n'est pas source de verite (audit F.3 :
# def "kill-chain correlee" commentee au depot mais toujours ENABLED en prod).
#
# Ces fonctions sont ADDITIVES : elles NE modifient PAS ensure_event (20+ scripts
# en dependent). Elles construisent le JSON DESIRE avec le MEME gabarit que
# ensure_event, le comparent au JSON COURANT (GET, normalise) et rapportent la
# derive. Par defaut = DRY-RUN (imprime le diff, aucun PUT). Un PUT n'est tente
# que si GRAYLOG_CONVERGE=1 (jamais arme par l'audit).
#
# CE QUI EST COMPARE (champs que 13-graylog-alerts.sh possede seul) :
#   title, description, priority, alert, config.{query,streams,group_by,series,
#   conditions,search_within_ms,execute_every_ms,event_limit}, key_spec.
# CE QUI EST DELIBEREMENT EXCLU (co-gere ailleurs -> un PUT le clobbererait) :
#   - notifications / storage / scheduler : ajoutes par 21/22-alert-routing ;
#     un live typique porte 2-3 notifications, le desire n'en construit qu'1.
#   - notification_settings.grace_period_ms + field_spec : co-geres par
#     21-alert-hygiene.sh (surcouche anti-tempete). grace/key_spec sont donc
#     classes "TUNING" (rapportes a part), PAS "LOGIQUE".
# ============================================================================

# _event_desired_json <TITLE> <PRIO> <QUERY> <STREAMS> <GROUPBY> <SERIES> \
#                      <COND> <WITHIN_min> <EVERY_min> [GRACE_min]
# Reproduit A L'IDENTIQUE le gabarit de ensure_event (13-graylog-alerts.sh:262).
# NOTIF_ID (global pose par 13) est lu depuis l'environnement, comme ensure_event.
_event_desired_json() {
  local TITLE="$1" PRIO="$2" QUERY="$3" STREAMS="$4" GROUPBY="$5" SERIES="$6" COND="$7" WITHIN="$8" EVERY="$9"
  local GRACE="${10:-10}"
  jq -n --arg t "${TITLE}" --argjson p "${PRIO}" --arg q "${QUERY}" \
        --argjson st "${STREAMS}" --argjson gb "${GROUPBY}" --argjson se "${SERIES}" \
        --argjson co "${COND}" --argjson w "$(( WITHIN * 60000 ))" --argjson e "$(( (EVERY < WITHIN ? WITHIN : EVERY) * 60000 ))" \
        --argjson g "$(( GRACE * 60000 ))" \
        --arg n "${NOTIF_ID:-}" '{
    title: $t,
    description: ("P" + ($p|tostring) + " - provisionne par 13-graylog-alerts.sh"),
    priority: $p,
    alert: true,
    config: {
      type: "aggregation-v1",
      query: $q,
      query_parameters: [],
      streams: $st,
      group_by: $gb,
      series: $se,
      conditions: $co,
      search_within_ms: $w,
      execute_every_ms: $e,
      use_cron_scheduling: false,
      event_limit: 100
    },
    field_spec: ($gb | map({key: ., value: {data_type: "string",
        providers: [{type: "template-v1", template: ("${source." + . + "}"),
                     require_values: false}]}}) | from_entries),
    key_spec: $gb,
    notification_settings: { grace_period_ms: $g, backlog_size: 5 },
    notifications: [ { notification_id: $n, notification_parameters: null } ]
  }'
}

# _event_canon : projette une def (desiree OU live) sur le sous-ensemble
# "possede par 13", canonicalise (tri des cles via -S, series normalisees, champs
# poses par le serveur retires) pour un diff textuel stable. IMPORTANT : jq 1.7
# PRESERVE les litteraux numeriques (le live rend 10.0, le desire 10) -> on force
# une forme canonique sur TOUT nombre via `walk(.+0)` (10.0+0 -> 10), sinon faux
# positif sur chaque seuil. Lit un objet sur stdin.
_event_canon() {
  jq -S 'walk(if type == "number" then . + 0 else . end) | {
    title, description, priority, alert,
    config: {
      type: .config.type,
      query: .config.query,
      streams: (.config.streams // [] | sort),
      group_by: (.config.group_by // []),
      series: (.config.series // [] | map({type, id, field: (.field // null)}) | sort_by(.id)),
      conditions: .config.conditions,
      search_within_ms: .config.search_within_ms,
      execute_every_ms: .config.execute_every_ms,
      event_limit: (.config.event_limit // 100)
    },
    key_spec: (.key_spec // []),
    _tuning: {
      grace_period_ms: (.notification_settings.grace_period_ms // null)
    }
  }'
}

# ensure_event_converge : MEME SIGNATURE que ensure_event (drop-in). Detecteur de
# derive RC-7. Si la def existe : compare desire vs live et imprime le diff
# (DRY-RUN). PUT UNIQUEMENT si GRAYLOG_CONVERGE=1 (fusion preservant
# notifications/storage/scheduler ; jamais arme par l'audit). Si absente :
# n'ecrit RIEN, signale simplement qu'une creation serait requise (la creation
# reste la responsabilite de ensure_event, inchangee).
# Retour : 0 = inchangee ; 10 = derive detectee ; 20 = absente.
ensure_event_converge() {
  local TITLE="$1"
  local ID DESIRED LIVE C_DES C_LIVE
  ID="$(event_def_id "${TITLE}")"
  if [[ -z "${ID}" || "${ID}" == "null" ]]; then
    warn "converge '${TITLE}' : ABSENTE live -> creation requise (ensure_event)"
    return 20
  fi
  DESIRED="$(_event_desired_json "$@")"
  LIVE="$(api_get "/events/definitions/${ID}")"
  C_DES="$(echo "${DESIRED}" | _event_canon)"
  C_LIVE="$(echo "${LIVE}"    | _event_canon)"
  if [[ "${C_DES}" == "${C_LIVE}" ]]; then
    skip "converge '${TITLE}' : conforme (aucune derive)"
    return 0
  fi
  warn "converge '${TITLE}' : DERIVE (${ID}) - diff live(-) -> desire(+) :"
  diff <(echo "${C_LIVE}") <(echo "${C_DES}") | sed 's/^/        /'
  if [[ "${GRAYLOG_CONVERGE:-0}" != "1" ]]; then
    echo "        [DRY-RUN] GRAYLOG_CONVERGE!=1 -> aucun PUT. Diff seulement."
    return 10
  fi
  # --- PUT de convergence (DESACTIVE par defaut) ---------------------------
  # Fusion PRUDENTE : on repart du LIVE (preserve id/notifications/storage/
  # scheduler/field_spec/grace poses par 21/22) et on n'ecrase QUE les champs
  # LOGIQUE possedes par 13. On ne touche JAMAIS notifications ni storage.
  local MERGED
  MERGED="$(jq -n --argjson live "${LIVE}" --argjson des "${DESIRED}" '
    $live
    | .title = $des.title
    | .description = $des.description
    | .priority = $des.priority
    | .alert = $des.alert
    | .config.query = $des.config.query
    | .config.streams = $des.config.streams
    | .config.group_by = $des.config.group_by
    | .config.series = $des.config.series
    | .config.conditions = $des.config.conditions
    | .config.search_within_ms = $des.config.search_within_ms
    | .config.execute_every_ms = $des.config.execute_every_ms
    | .config.event_limit = $des.config.event_limit
    | .key_spec = $des.key_spec
    | del(._scope, .matched_at, .updated_at, .scheduler)')"
  echo "${MERGED}" | api_put "/events/definitions/${ID}?schedule=true" >/dev/null \
    && ok "converge '${TITLE}' : PUT applique (${ID})" \
    || warn "converge '${TITLE}' : PUT REFUSE"
  return 10
}
