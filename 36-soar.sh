#!/usr/bin/env bash
# =============================================================================
# 36-soar.sh - Active le SOAR-light : service + notification Graylog + alerte
# -----------------------------------------------------------------------------
# 1. demarre omni-soar.service (recoit les webhooks) + omni-soar-expire.timer
# 2. cree la notification HTTP "OMNI - SOAR auto-block" -> 127.0.0.1:8088/block
# 3. l'attache aux alertes VPN / spraying (force brute portail, password spraying)
# 4. cree l'alerte de tracabilite "OMNI - SOAR : IP bloquee automatiquement"
# Cote FortiGate : appliquer fortigate/06-soar-threatfeed.conf.
# Idempotent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh
require_api

echo "==> [1/4] Service SOAR + timer d'expiration"
systemctl daemon-reload
systemctl enable --now omni-soar.service omni-soar-expire.timer
sleep 2
curl -s -o /dev/null -w "  service omni-soar (127.0.0.1:8088) -> HTTP %{http_code}\n" \
  -X POST http://127.0.0.1:8088/block -d '{}' || warn "service injoignable"

echo "==> [2/4] Notification HTTP vers le service SOAR"
NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]? | select(.title=="OMNI - SOAR auto-block") | .id')"
if [[ -z "${NID}" || "${NID}" == "null" ]]; then
  NID="$(jq -n '{title:"OMNI - SOAR auto-block",
      description:"Webhook vers omni-soar (blocage auto IP) - provisionne par 36-soar.sh",
      config:{type:"http-notification-v1", url:"http://127.0.0.1:8088/block",
        api_key_as_header:false, api_key:"", api_secret:null, basic_auth:null,
        skip_tls_verification:true}}' \
    | post_entity "/events/notifications" | jqr '.id')"
  [[ -n "${NID}" && "${NID}" != "null" ]] && ok "notification SOAR creee (${NID})" || die "creation notification SOAR REFUSEE"
else skip "notification SOAR existe (${NID})"; fi

echo "==> [3/4] Attachement aux alertes VPN / spraying"
attach() {  # attach <titre_definition>
  local T="$1" DEF ID CUR
  ID="$(api_get "/events/definitions?per_page=300" | jq -r --arg t "$T" '.event_definitions[] | select(.title==$t) | .id')"
  if [[ -z "${ID}" || "${ID}" == "null" ]]; then warn "definition '$T' introuvable"; return; fi
  DEF="$(api_get "/events/definitions/${ID}")"
  if echo "${DEF}" | jq -e --arg n "${NID}" '.notifications[]? | select(.notification_id==$n)' >/dev/null; then
    skip "'$T' deja relie au SOAR"; return
  fi
  echo "${DEF}" | jq --arg n "${NID}" \
    'del(._scope,.matched_at,.updated_at,.scheduler) | .notifications += [{notification_id:$n, notification_parameters:null}] | .notification_settings.backlog_size = (.notification_settings.backlog_size // 10 | if . < 10 then 10 else . end)' \
    | api_put "/events/definitions/${ID}?schedule=true" >/dev/null \
    && ok "'$T' -> SOAR" || warn "'$T' : echec attachement"
}
attach "OMNI - Force brute portail VPN (>=30 echecs / IP / h)"
attach "OMNI - Password spraying (>=8 comptes / IP / 10 min)"

echo "==> [4/4] Alerte de tracabilite (mail)"
ST_INTERNE="$(get_stream_id 'OMNI - Interne SIEM')"
# s'assurer que le stream interne route siem_soar
SID="${ST_INTERNE}"
if [[ -n "${SID}" ]] && ! api_get "/streams/${SID}" | jq -e '.rules[]? | select(.value=="siem_soar")' >/dev/null; then
  echo '{"field":"event_source","type":1,"value":"siem_soar","inverted":false,"description":"evenements SOAR"}' \
    | api_post "/streams/${SID}/rules" >/dev/null && ok "stream interne route desormais siem_soar"
fi
NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[] | select(.title=="OMNI - Mail equipe IT") | .id')"
TITLE="OMNI - SOAR : IP bloquee automatiquement"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "${TITLE}" '.event_definitions[] | select(.title==$t)' >/dev/null; then
  skip "alerte SOAR existe"
else
  jq -n --arg t "${TITLE}" --arg st "${SID}" --arg n "${NOTIF_MAIL}" '{
    title:$t, description:"P3 SOAR - une IP a ete bloquee automatiquement sur le FortiGate (feed). Verifier la legitimite. Provisionne par 36-soar.sh",
    priority:3, alert:true,
    config:{type:"aggregation-v1", query:"event_action:ip_bloquee", query_parameters:[],
      streams:[$st], group_by:[], series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:600000, execute_every_ms:300000, use_cron_scheduling:false, event_limit:50},
    field_spec:{}, key_spec:[],
    notification_settings:{grace_period_ms:1800000, backlog_size:10},
    notifications:[{notification_id:$n, notification_parameters:null}]
  }' | post_entity "/events/definitions?schedule=true" >/dev/null && ok "alerte SOAR creee" || warn "alerte SOAR REFUSEE"
fi
echo "=== 36-soar.sh termine. Cote FortiGate : appliquer fortigate/06-soar-threatfeed.conf ==="
