#!/usr/bin/env bash
# =============================================================================
# 97-multisite-soar.sh - Deux apports (idempotents) :
#
#  [A] MULTI-SITE FortiGate : les 3 FortiGate (BDX 10.33, IV 10.94, LC 10.13)
#      forwardent deja via le meme FortiAnalyzer -> leurs logs sont DEJA dans le
#      SIEM (input syslog 1514), mais indistincts. On ajoute la dimension SITE :
#        - lookup omni-fortigate-site : devid -> site (BDX/IV/LC ; "autre" sinon)
#        - regle pipeline omni-forti-04-site (stage 6 du pipeline OMNI - FortiGate)
#          -> pose le champ fortigate_site sur chaque log Forti.
#      Aucun flux reseau a ouvrir (transit FAZ existant). Pour mapper un nouveau
#      boitier : ajouter sa ligne devid,site dans lookups/fortigate-sites.csv.
#
#  [B] ELARGISSEMENT SOAR : alimente la blocklist (jusque-la nourrie seulement
#      par spray AD + brute VPN, qui ne declenchaient jamais) avec les attaquants
#      WAF. Alerte "IP attaquante WAF" (>=20 blocages waf_block / src_ip / 6h)
#      -> notification SOAR auto-block (+ Teams). Garde-fous cote service omni-soar
#      inchanges (jamais RFC1918/whitelist, min-hits, cap, TTL 24h).
#      NB : l'IPS FortiGate (alert_tag:fortigate_utm) a ete ECARTE comme feeder :
#      ce sont surtout des anomalies/flood internes sans srcip externe propre.
#
#  Idempotent. Prerequis : 36-soar.sh (service + notif SOAR), 12 (pipeline Forti),
#  11 (LOOKUP_DIR). Convention : helpers lib-graylog.sh.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

LOOKUP_DIR="${LOOKUP_DIR:-/etc/graylog/lookup}"

echo "==> [A.1] Lookup omni-fortigate-site (devid -> site)"
install -m 644 lookups/fortigate-sites.csv "${LOOKUP_DIR}/fortigate-sites.csv"
chown root:graylog "${LOOKUP_DIR}/fortigate-sites.csv" 2>/dev/null || true
# default a "autre" pour qu'un nouveau boitier non mappe soit visible (pas null)
ensure_lookup "fortigate-site" "FortiGate devid -> site" "fortigate-sites.csv" "devid" "site" \
  "97-multisite-soar.sh : identification du site par numero de serie FortiGate"
# force le defaut "autre" sur la table (ensure_lookup pose NULL par defaut)
FSID="$(api_get "/system/lookup/tables" | jq -r '.lookup_tables[]?|select(.name=="omni-fortigate-site")|.id')"
if [[ -n "${FSID}" ]]; then
  api_get "/system/lookup/tables" | jq -c --arg id "$FSID" '.lookup_tables[]|select(.id==$id)
      | {id,title,description,name,cache_id,data_adapter_id,
         default_single_value:"autre",default_single_value_type:"STRING",
         default_multi_value:"",default_multi_value_type:"NULL"}' \
    | api_put "/system/lookup/tables" >/dev/null 2>&1 || true
fi
# recharge le cache CSV (cf piege cache csvfile, voir 93-aruba.sh)
"${CURL[@]}" -X POST "${API}/system/lookup/tables/omni-fortigate-site/purge" >/dev/null 2>&1 || true
ok "lookup omni-fortigate-site"

echo "==> [A.2] Regle pipeline omni-forti-04-site (pose fortigate_site)"
ensure_rule "omni-forti-04-site" <<'EOF'
rule "omni-forti-04-site"
when
  to_string($message.event_source) == "fortigate" AND has_field("devid")
then
  set_field("fortigate_site", lookup_value("omni-fortigate-site", to_string($message.devid)));
end
EOF
# Injection dans le pipeline OMNI - FortiGate (stage 6), sans ecraser les autres regles
PID="$(api_get "/system/pipelines/pipeline" | jq -r '.[]|select(.title=="OMNI - FortiGate")|.id')"
if [[ -n "${PID}" ]]; then
  PIPE="$(api_get "/system/pipelines/pipeline/${PID}")"
  if echo "${PIPE}" | jq -r '.source' | grep -q 'omni-forti-04-site'; then
    skip "regle deja dans le pipeline"
  else
    NEWSRC="$(echo "${PIPE}" | jq -r '.source' \
      | sed 's/^rule "omni-forti-06-source-host"$/rule "omni-forti-06-source-host"\nrule "omni-forti-04-site"/')"
    echo "${PIPE}" | jq -c --arg s "${NEWSRC}" 'del(._scope)|.source=$s' \
      | api_put "/system/pipelines/pipeline/${PID}" >/dev/null && ok "regle injectee stage 6" || warn "injection KO"
  fi
else
  warn "pipeline OMNI - FortiGate introuvable"
fi

echo "==> [B] Alerte WAF -> SOAR (>=20 blocages / src_ip / 6h)"
SOAR_NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - SOAR auto-block")|.id')"
TEAMS_NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
BW_STREAM="$(get_stream_id 'OMNI - BunkerWeb')"
TITLE="OMNI - WAF : IP attaquante (>=20 blocages / IP / 6h) -> SOAR"
[[ -n "${SOAR_NID}" ]] || die "notification SOAR absente (lancer 36-soar.sh d'abord)"
[[ -n "${BW_STREAM}" ]] || die "stream BunkerWeb absent"
EXIST="$(api_get "/events/definitions?per_page=300" | jq -r --arg t "$TITLE" '.event_definitions[]?|select(.title==$t)|.id')"
if [[ -n "${EXIST}" ]]; then
  skip "alerte WAF->SOAR existe (${EXIST})"
else
  NOTIFS="$(jq -nc --arg s "$SOAR_NID" --arg t "$TEAMS_NID" \
    '[{notification_id:$s,notification_parameters:null}] + (if $t!="" then [{notification_id:$t,notification_parameters:null}] else [] end)')"
  NEWID="$(jq -n --arg t "$TITLE" --arg q 'alert_tag:waf_block AND _exists_:src_ip' --arg s "$BW_STREAM" --argjson n "$NOTIFS" \
    '{title:$t,
      description:"97-multisite-soar.sh : IP externe repetant des blocages WAF BunkerWeb -> blocklist FortiGate via SOAR. Garde-fous omni-soar (jamais RFC1918/whitelist, min-hits, TTL 24h).",
      priority:2,alert:true,
      config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$s],group_by:["src_ip"],
        series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:20}}},
        search_within_ms:21600000,execute_every_ms:600000,use_cron_scheduling:false,event_limit:100},
      field_spec:{},key_spec:[],
      notification_settings:{grace_period_ms:600000,backlog_size:20},
      notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  if [[ -n "${NEWID}" && "${NEWID}" != "null" ]]; then
    "${CURL[@]}" -X PUT "${API}/events/definitions/${NEWID}/schedule" >/dev/null 2>&1 || true
    ok "alerte WAF->SOAR creee + activee (${NEWID})"
  else
    warn "creation alerte WAF->SOAR KO"
  fi
fi

echo "==> [C] Alerte WAF scanner 404 RECIDIVISTE -> SOAR (>=150 erreurs 404 / src_ip / 6h)"
# Complement de l'alerte 404 informative (>=25/10min, mail) : ici on BLOQUE l'IP
# qui SOUTIENT le scan (>=150 erreurs 404 sur 6h) = recidiviste. SOAR uniquement,
# PAS de mail/Teams : l'alerte 404 a 10 min previent deja l'humain (anti-doublon).
# TTL 24h cote omni-soar, renouvele tant que le scan continue -> blocage de fait
# permanent pour un scanner persistant, auto-nettoye des qu'il s'arrete.
TITLE_R="OMNI - WAF : scanner 404 récidiviste (>=150 / IP / 6h) -> SOAR"
EXIST_R="$(api_get "/events/definitions?per_page=300" | jq -r --arg t "$TITLE_R" '.event_definitions[]?|select(.title==$t)|.id')"
if [[ -n "${EXIST_R}" ]]; then
  skip "alerte 404-recidiviste->SOAR existe (${EXIST_R})"
elif [[ -n "${SOAR_NID}" && -n "${BW_STREAM}" ]]; then
  NEWID_R="$(jq -n --arg t "$TITLE_R" --arg q 'event_source:bunkerweb AND http_status:404' --arg s "$BW_STREAM" --arg soar "$SOAR_NID" \
    '{title:$t,
      description:"97-multisite-soar.sh : IP externe >=150 erreurs 404 sur 6h (scan recidiviste) -> blocklist FortiGate via SOAR. SOAR seul (pas de mail, anti-doublon avec l|alerte 404 a 10 min). Garde-fous omni-soar (jamais RFC1918/whitelist, TTL 24h).",
      priority:3,alert:true,
      config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$s],group_by:["src_ip"],
        series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:150}}},
        search_within_ms:21600000,execute_every_ms:1800000,use_cron_scheduling:false,event_limit:100},
      field_spec:{},key_spec:[],
      notification_settings:{grace_period_ms:1800000,backlog_size:20},
      notifications:[{notification_id:$soar,notification_parameters:null}]}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  if [[ -n "${NEWID_R}" && "${NEWID_R}" != "null" ]]; then
    "${CURL[@]}" -X PUT "${API}/events/definitions/${NEWID_R}/schedule" >/dev/null 2>&1 || true
    ok "alerte 404-recidiviste->SOAR creee + activee (${NEWID_R})"
  else
    warn "creation alerte 404-recidiviste->SOAR KO"
  fi
fi

echo
echo "=== 97 termine. Multi-site Forti (fortigate_site BDX/IV/LC) + feeder SOAR WAF. ==="
echo "    Pour mapper un nouveau FortiGate : lookups/fortigate-sites.csv + relancer 97."
