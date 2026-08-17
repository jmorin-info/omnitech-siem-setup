#!/usr/bin/env bash
# =============================================================================
# 28-vpn-remip-ti.sh - T1133 External Remote Services : login SSL-VPN FortiGate
#   depuis une IP a mauvaise reputation (Tor / Spamhaus DROP / C2 Feodo).
#
#   Le champ remip (IP distante du client VPN) n'etait PAS enrichi par la
#   threat-intel (seuls src_ip/dest_ip l'etaient). On ajoute 3 regles de pipeline
#   (stage 12, apres l'enrichissement TI src/dest) qui, sur le SSL-VPN uniquement
#   (tunneltype ssl* -> exclut l'IPsec site-a-site et son flood d'IP partenaires),
#   testent remip contre les 3 feeds et posent remip_threat_indicated +
#   alert_tag=vpn_malicious_ip. Puis alerte + mapping MITRE.
#
#   PIEGE (verifie en live, analyse multi-agents 02/07/2026) : les feeds n'ont pas
#   la meme semantique d'absence -> tor/c2 = null si absent (test ! is_null) ;
#   spamhaus = BOOLEEN false si absent (test to_bool(...) == true, JAMAIS is_null,
#   sinon flood sur 100% des logins). Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

PLID="$(api_get '/system/pipelines/pipeline' | jq -r '.[]|select(.title=="OMNI - FortiGate")|.id')"
[[ -n "${PLID}" ]] || die "pipeline OMNI - FortiGate absent"
ST_FORTI="$(get_stream_id 'OMNI - FortiGate')"; [[ -n "${ST_FORTI}" ]] || die "stream FortiGate absent"

echo "==> [1/4] Regles d'enrichissement remip (3 feeds)"
ensure_rule "omni-forti-12-remip-tor" <<'EOF'
rule "omni-forti-12-remip-tor"
when
  to_string($message.event_source) == "fortigate"
  AND to_string($message.subtype) == "vpn"
  AND starts_with(to_string($message.tunneltype), "ssl")
  AND has_field("remip")
  AND ! is_null(lookup_value("tor-exit-node-list", to_string($message.remip)))
then
  set_field("remip_threat_indicated", true);
  set_field("remip_threat", to_string($message.remip));
  set_field("ti_reputation", "tor_exit");
  set_field("alert_tag", "vpn_malicious_ip");
  set_field("mitre_technique", "T1133");
end
EOF

ensure_rule "omni-forti-12-remip-spamhaus" <<'EOF'
rule "omni-forti-12-remip-spamhaus"
when
  to_string($message.event_source) == "fortigate"
  AND to_string($message.subtype) == "vpn"
  AND starts_with(to_string($message.tunneltype), "ssl")
  AND has_field("remip")
  AND to_bool(lookup_value("spamhaus-drop", to_string($message.remip))) == true
then
  set_field("remip_threat_indicated", true);
  set_field("remip_threat", to_string($message.remip));
  set_field("ti_reputation", "spamhaus_drop");
  set_field("alert_tag", "vpn_malicious_ip");
  set_field("mitre_technique", "T1133");
end
EOF

ensure_rule "omni-forti-12-remip-c2" <<'EOF'
rule "omni-forti-12-remip-c2"
when
  to_string($message.event_source) == "fortigate"
  AND to_string($message.subtype) == "vpn"
  AND starts_with(to_string($message.tunneltype), "ssl")
  AND has_field("remip")
  AND ! is_null(lookup_value("omni-ti-c2-ip", to_string($message.remip)))
then
  set_field("remip_threat_indicated", true);
  set_field("remip_threat", to_string($message.remip));
  set_field("ti_c2_malware", to_string(lookup_value("omni-ti-c2-ip", to_string($message.remip))));
  set_field("ti_reputation", "c2");
  set_field("alert_tag", "vpn_malicious_ip");
  set_field("mitre_technique", "T1133");
end
EOF

echo "==> [2/4] Ajout du stage 12 au pipeline OMNI - FortiGate"
SRC="$(api_get "/system/pipelines/pipeline/${PLID}" | jq -r '.source')"
if grep -q 'omni-forti-12-remip-tor' <<<"${SRC}"; then
  skip "stage 12 remip deja present"
else
  NEWSRC="$(printf '%s\n' "${SRC}" | sed 's/^end$//' )"
  NEWSRC="${NEWSRC%$'\n'}"$'\nstage 12 match either\n  rule "omni-forti-12-remip-tor"\n  rule "omni-forti-12-remip-spamhaus"\n  rule "omni-forti-12-remip-c2"\nend'
  api_get "/system/pipelines/pipeline/${PLID}" \
    | jq --arg s "${NEWSRC}" '{id, title, description, source:$s}' \
    | api_put "/system/pipelines/pipeline/${PLID}" | jq -e '.id' >/dev/null \
    && ok "stage 12 ajoute (3 regles remip)" || warn "mise a jour pipeline KO"
fi

echo "==> [3/4] Mapping MITRE vpn_malicious_ip -> T1133"
CSV="lookups/mitre-attack.csv"
if ! grep -q '^vpn_malicious_ip,' "${CSV}"; then
  echo 'vpn_malicious_ip,T1133,External Remote Services,Initial Access,critique,9' >> "${CSV}"
  install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
  # purge du cache des tables lookup MITRE (sinon l'ancien CSV reste servi)
  for t in omni-mitre-score omni-mitre-severity omni-mitre-technique omni-mitre-tactic; do
    "${CURL[@]}" -X POST "${API}/system/lookup/tables/${t}/purge" >/dev/null 2>&1 || true
  done
  ok "MITRE vpn_malicious_ip ajoute + cache purge"
else
  skip "MITRE vpn_malicious_ip existe"
fi

echo "==> [4/4] Alerte SSL-VPN depuis IP malveillante"
TITLE="OMNI - Login SSL-VPN depuis IP malveillante ou Tor (T1133)"
if [[ -n "$(event_def_id "${TITLE}")" ]]; then
  skip "alerte existe"
else
  TEAMS_ID="$(api_get '/events/notifications?per_page=100' | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
  TRIAGE_ID="$(api_get '/events/notifications?per_page=100' | jq -r '.notifications[]?|select(.title=="OMNI - Triage (mail critique)")|.id')"
  NOTIFS="$(jq -nc --arg t "$TEAMS_ID" --arg tr "$TRIAGE_ID" \
    '[{notification_id:$t,notification_parameters:null}] + (if $tr!="" then [{notification_id:$tr,notification_parameters:null}] else [] end)')"
  ID="$(jq -n --arg t "$TITLE" --arg s "$ST_FORTI" --argjson n "$NOTIFS" \
    '{title:$t, description:"28/T1133 : ouverture de session SSL-VPN reussie ou tentee depuis une IP a mauvaise reputation (Tor/Spamhaus DROP/C2). remip enrichi au stage 12 du pipeline FortiGate.",
      priority:2, alert:true,
      config:{type:"aggregation-v1", query:"alert_tag:vpn_malicious_ip", query_parameters:[], streams:[$s],
        group_by:["user","remip","ti_reputation"], series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
        search_within_ms:300000, execute_every_ms:300000, use_cron_scheduling:false, event_limit:50},
      field_spec:{}, key_spec:[],
      notification_settings:{grace_period_ms:3600000, backlog_size:10}, notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  [[ -n "${ID}" && "${ID}" != "null" ]] && { "${CURL[@]}" -X PUT "${API}/events/definitions/${ID}/schedule" >/dev/null 2>&1 || true; ok "alerte creee (${ID})"; } || warn "alerte KO"
fi

echo
echo "=== 28-vpn-remip-ti.sh termine. Verifier : la regle tire quand un remip Tor/Spamhaus se presente"
echo "    (dormance legitime si parc VPN sain). Relancer 57 (carte ATT&CK) pour afficher T1133."
