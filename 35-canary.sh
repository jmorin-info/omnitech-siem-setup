#!/usr/bin/env bash
# =============================================================================
# 35-canary.sh - Compte(s) canari AD : detection d'intrusion interne
# -----------------------------------------------------------------------------
# Principe : un compte AD leurre, credible et attractif (semble privilegie),
# JAMAIS utilise legitimement. Toute authentification, tentative ou requete
# Kerberos le concernant = signal d'intrusion (enumeration AD, brute force,
# Kerberoasting, mouvement lateral). Faux positifs ~nuls par construction.
#
# Ce script (cote SIEM) : lookup table omni-canary (depuis canary-accounts.csv)
# + alerte P3 mail+Teams. La REGLE pipeline omni-winsec-10-canary est dans
# 12-graylog-pipelines.sh (source de verite). Cote AD : windows/New-OmniCanary.ps1.
#
# ORDRE : lancer 35 (cree la lookup) AVANT de rejouer 12 (la regle l'utilise).
# Pour ajouter un canari : editer lookups/canary-accounts.csv + relancer 35.
# Idempotent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh
require_api

LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/3] Deploiement du CSV des comptes canari"
install -m 644 lookups/canary-accounts.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/canary-accounts.csv" 2>/dev/null || true
ok "canary-accounts.csv deploye"

echo "==> [2/3] Lookup table omni-canary (adapter + cache + table)"
AID="$(api_get "/system/lookup/adapters" | jq -r '.data_adapters[]? | select(.name=="omni-canary-adapter") | .id')"
if [[ -z "${AID}" || "${AID}" == "null" ]]; then
  AID="$(jq -n '{title:"OMNI comptes canari", description:"Comptes leurre - detection intrusion",
      name:"omni-canary-adapter", custom_error_ttl_enabled:false,
      config:{type:"csvfile", path:"/etc/graylog/lookup/canary-accounts.csv",
        separator:",", quotechar:"\"", key_column:"account", value_column:"note",
        check_interval:60, case_insensitive_lookup:true}}' \
    | api_post "/system/lookup/adapters" | jqr '.id')"
  ok "adapter omni-canary-adapter cree"
else skip "adapter omni-canary-adapter existe"; fi

CID="$(api_get "/system/lookup/caches" | jq -r '.caches[]? | select(.name=="omni-canary-cache") | .id')"
if [[ -z "${CID}" || "${CID}" == "null" ]]; then
  CID="$(jq -n '{title:"OMNI canari cache", description:"cache comptes canari",
      name:"omni-canary-cache", config:{type:"guava_cache", max_size:100,
      expire_after_access:60, expire_after_access_unit:"SECONDS",
      expire_after_write:0, expire_after_write_unit:"SECONDS"}}' \
    | api_post "/system/lookup/caches" | jqr '.id')"
  ok "cache omni-canary-cache cree"
else skip "cache omni-canary-cache existe"; fi

TID="$(api_get "/system/lookup/tables" | jq -r '.lookup_tables[]? | select(.name=="omni-canary") | .id')"
if [[ -z "${TID}" || "${TID}" == "null" ]]; then
  jq -n --arg a "${AID}" --arg c "${CID}" '{title:"OMNI canari", description:"compte -> note",
      name:"omni-canary", cache_id:$c, data_adapter_id:$a,
      default_single_value:"", default_single_value_type:"NULL",
      default_multi_value:"", default_multi_value_type:"NULL"}' \
    | api_post "/system/lookup/tables" >/dev/null
  ok "table omni-canary creee"
else skip "table omni-canary existe"; fi

echo "==> [3/3] Alerte P3 mail+Teams"
ST_WINSEC="$(get_stream_id 'OMNI - Windows Security')"
NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[] | select(.title=="OMNI - Mail equipe IT") | .id')"
NOTIF_TEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[] | select(.title=="OMNI - Teams SOC") | .id')"
TITLE="OMNI - COMPTE CANARI touché (intrusion AD probable)"
EXIST="$(api_get "/events/definitions?per_page=300" | jq -r --arg t "${TITLE}" '.event_definitions[] | select(.title==$t) | .id')"
if [[ -n "${EXIST}" && "${EXIST}" != "null" ]]; then
  skip "alerte canari existe deja"
else
  NEWID="$(jq -n --arg t "${TITLE}" --arg st "${ST_WINSEC}" --arg n "${NOTIF_MAIL}" --arg tm "${NOTIF_TEAMS}" '{
    title:$t,
    description:"P3 INTRUSION - un compte canari (leurre, jamais utilise) a ete sollicite. Investiguer immediatement le poste/IP source. Provisionne par 35-canary.sh",
    priority:3, alert:true,
    config:{type:"aggregation-v1", query:"alert_tag:canary", query_parameters:[],
      streams:[$st], group_by:[], series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000, execute_every_ms:60000, use_cron_scheduling:false, event_limit:50},
    field_spec:{}, key_spec:[],
    notification_settings:{grace_period_ms:600000, backlog_size:10},
    notifications:[{notification_id:$n, notification_parameters:null},{notification_id:$tm, notification_parameters:null}]
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  [[ -n "${NEWID}" && "${NEWID}" != "null" ]] && ok "alerte canari creee (P3 mail+Teams)" || warn "creation alerte canari REFUSEE"
fi
echo "=== 35-canary.sh termine. Rejouer ensuite 12-graylog-pipelines.sh (regle de detection). ==="
