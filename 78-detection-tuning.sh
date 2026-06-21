#!/usr/bin/env bash
# =============================================================================
# 78-detection-tuning.sh - Ajustement detections (suite audit) :
#   ALERTE service_stop_securite (T1489) : la regle existe (47) mais AUCUNE event
#   definition ne la declenchait -> precurseur ransomware muet. On cable l'alerte
#   (arret EDR/backup = signal fiable juste avant chiffrement).
#
#   NB : la detection Pass-the-Hash "textbook" (LogonType 9 + seclogo + NTLM) a ete
#   ECARTEE apres verification sur les donnees reelles : sur ce parc, LogonType 9 =
#   100% Systeme/Advapi (benin) et le package NTLM est massif (4776 DC/ninjaone) ->
#   la regle serait soit morte, soit un deluge de FP. Idem RDP lateral (T1021.001) :
#   42 sessions/7j mais distinguer admin legitime du lateral exige la liste des
#   jump-hosts -> a concevoir proprement (backlog), pas a bacler ici.
#
#   Idempotent. Prerequis : 47 (regle), 13 (notifications).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/1] Alerte service_stop_securite (T1489) -> tier mail + Teams"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
SYS="$(get_stream_id 'OMNI - Sysmon')"
[[ -n "$SYS" ]] || die "stream 'OMNI - Sysmon' introuvable"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
mk_a() { local T="$1" Q="$2" ST="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg st "$ST" --argjson n "$NF" '{title:$t,description:"78-detection-tuning.sh",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"; }
mk_a "OMNI - Arret service de securite (precurseur ransomware)" "alert_tag:service_stop_securite" "$SYS"

echo
echo "=== 78 termine. (Detections laterales PtH/RDP : backlog, besoin liste jump-hosts.) ==="
