#!/usr/bin/env bash
# =============================================================================
# 73-detection-ad.sh - Detection AD : Kerberoasting (T1558.003)
#   Trou de couverture comble : l'environnement utilise AES (0x12) ; une requete
#   de ticket de service Kerberos en RC4 (0x17) pour un compte de SERVICE (non
#   machine $) = downgrade pour crackage hors-ligne = kerberoasting. Tripwire
#   propre (zero FP attendu vu la posture AES). EventID 4769.
#   Idempotent. Prerequis : 37 (MITRE). Relancer 57 (carte) ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/3] Regle de detection kerberoasting (4769 + RC4)"
ensure_rule "omni-winsec-kerberoast" <<'EOF'
rule "omni-winsec-kerberoast"
when
  to_string($message.event_id) == "4769"
  AND to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x17"
  AND ! ends_with(to_string($message.winlogbeat_winlog_event_data_ServiceName), "$", true)
  AND to_string($message.winlogbeat_winlog_event_data_ServiceName) != "krbtgt"
then
  set_field("ad_service", to_string($message.winlogbeat_winlog_event_data_ServiceName));
  set_field("alert_tag", "kerberoasting");
end
EOF
PL="$(ensure_pipeline "OMNI - Detection AD" <<'PIPE'
pipeline "OMNI - Detection AD"
stage 12 match either
rule "omni-winsec-kerberoast"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Windows Security')"; [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL"

echo "==> [2/3] MITRE"
CSV="lookups/mitre-attack.csv"
grep -q '^kerberoasting,' "$CSV" || echo 'kerberoasting,T1558.003,Kerberoasting,Credential Access,critique,9' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE kerberoasting (T1558.003)"

echo "==> [3/3] Alerte"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
SYS="$(get_stream_id 'OMNI - Windows Security')"
T="OMNI - Kerberoasting (ticket Kerberos RC4 demande)"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null; then
  skip "alerte kerberoasting existe"
else
  NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
  jq -n --arg t "$T" --arg st "$SYS" --argjson n "$NF" '{title:$t,description:"Requete de ticket Kerberos en RC4 pour un compte de service = kerberoasting (73-detection-ad.sh). Posture AES -> RC4 anormal.",priority:3,alert:true,
    config:{type:"aggregation-v1",query:"alert_tag:kerberoasting",query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte kerberoasting creee" || warn "alerte KO"
fi
echo
echo "=== 73 termine. Tripwire kerberoasting actif (silencieux tant que pas de RC4). Relancer 57. ==="
