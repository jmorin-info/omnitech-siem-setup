#!/usr/bin/env bash
# =============================================================================
# fp-tuning2-2026-09-23.sh - Reduction des FP, deuxieme passe (couche suivante).
#   Mesures du 23/09/2026, apres la 1re passe (Tor/LSASS/TeamViewer/SEAL QA) :
#
#   1. M365 T1098.005 : le compte de SYNCHRONISATION Entra Connect
#      (ConnectSyncProvisioning_<serveur>_<guid>) enregistre des appareils -- c'est
#      sa fonction. 8 evenements/30 j. Exclu, comme l'est deja "Device Registration
#      Service". Les inscriptions par de VRAIS comptes restent detectees.
#   2. SEAL EVT-001 : son titre le dit, c'est une BASE DE CORRELATION/CHASSE
#      (chaque badge accorde, count>=1). Elle etait pourtant alert=true avec une
#      notification -> ~500 alertes/jour pour des acces normaux. Passee en
#      evenement non-alertant : la donnee reste pour la chasse et la correlation.
#   3. vCenter mot de passe expire : le compte de service "logging" rejouait son
#      authentification en boucle (80 543 evenements/7 j) ; la regle de pipeline
#      ne le compte plus comme brute-force (19-vsphere.sh). On cree ici UNE
#      detection agregee (>=50 / 6 h) pour le signaler une fois, pas 11 500 fois.
#
#   DRY-RUN par defaut. Appliquer : APPLY=1 ./fp-tuning2-2026-09-23.sh
#   Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api
APPLY="${APPLY:-0}"

DEFS="$(api_get '/events/definitions?per_page=400')"
id_by_title(){ echo "$DEFS" | jq -r --arg t "$1" '.event_definitions[]?|select(.title|test($t))|.id' | head -1; }

set_query(){ # $1=motif titre  $2=nouvelle requete
  local id t cur
  id="$(id_by_title "$1")"; [[ -z "$id" ]] && { warn "absente: $1"; return; }
  t="$(echo "$DEFS" | jq -r --arg i "$id" '.event_definitions[]?|select(.id==$i)|.title')"
  cur="$(echo "$DEFS" | jq -r --arg i "$id" '.event_definitions[]?|select(.id==$i)|.config.query')"
  [[ "$cur" == "$2" ]] && { skip "[$t] deja a jour"; return; }
  echo "  ~ [$t]"; echo "     APRES: ${2:0:150}..."
  [[ "$APPLY" != "1" ]] && return
  api_get "/events/definitions/$id" | jq --arg q "$2" '.config.query=$q' \
    | api_put "/events/definitions/$id?schedule=true" | jq -e '.id' >/dev/null 2>&1 \
    && ok "[$t] requete mise a jour" || warn "[$t] echec"
}

echo "=== fp-tuning2 (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)) ==="

echo "[1/3] M365 T1098.005 : exclure le connecteur de synchronisation Entra"
Q='event_source:m365 AND m365_type:audit AND event_action:("Register device" OR "Add device" OR "Add registered owner to device" OR "Add registered users to device" OR "Add Windows Hello for Business credential" OR "User registered security info" OR "User registered all required security info" OR "User started security info registration") AND NOT upn:"Device Registration Service" AND NOT upn:ConnectSyncProvisioning_* AND NOT upn:Sync_*'
set_query "M365 enregistrement appareil / m.thode MFA" "$Q"

echo "[2/3] SEAL EVT-001 : base de chasse -> evenement non-alertant"
EID="$(id_by_title "SEAL EVT-001")"
if [[ -z "$EID" ]]; then warn "SEAL EVT-001 absente"
else
  CURA="$(echo "$DEFS" | jq -r --arg i "$EID" '.event_definitions[]?|select(.id==$i)|.alert')"
  if [[ "$CURA" == "false" ]]; then skip "SEAL EVT-001 deja non-alertante"
  else
    echo "  ~ [SEAL EVT-001] alert=true -> false (notifications retirees)"
    if [[ "$APPLY" == "1" ]]; then
      api_get "/events/definitions/$EID" | jq '.alert=false | .notifications=[]' \
        | api_put "/events/definitions/$EID?schedule=true" | jq -e '.id' >/dev/null 2>&1 \
        && ok "SEAL EVT-001 passee en evenement non-alertant" || warn "SEAL EVT-001 echec"
    fi
  fi
fi

echo "[3/3] Detection agregee : compte de service vCenter a mot de passe expire"
TITLE="OMNI - vCenter : compte de service a mot de passe expire (boucle d'authentification)"
if [[ -n "$(id_by_title "vCenter : compte de service a mot de passe expire")" ]]; then
  skip "detection deja presente"
elif [[ "$APPLY" != "1" ]]; then
  echo "  + creation prevue : \"$TITLE\" (>=50 / 6 h, stream vSphere)"
else
  ST="$(get_stream_id 'OMNI - vSphere')"
  TR="$(api_get '/events/notifications?per_page=100' | jq -r '.notifications[]?|select(.title=="OMNI - Triage (mail critique)")|.id')"
  NOTIF="$(jq -nc --arg tr "$TR" 'if $tr!="" then [{notification_id:$tr,notification_parameters:null}] else [] end')"
  ID="$(jq -n --arg t "$TITLE" --arg s "$ST" --argjson n "$NOTIF" \
    '{title:$t,
      description:"Un compte de service vCenter a son mot de passe expire et son integration rejoue l authentification en boucle. Panne d exploitation : elle sature les journaux et masque les vrais echecs d authentification.",
      priority:2, alert:true,
      config:{type:"aggregation-v1", query:"event_source:vsphere AND message:PasswordExpired",
              query_parameters:[], streams:(if $s=="" then [] else [$s] end),
              group_by:["user"], series:[{id:"count()",type:"count"}],
              conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:50}}},
              search_within_ms:21600000, execute_every_ms:21600000,
              use_cron_scheduling:false, event_limit:10},
      field_spec:{}, key_spec:[],
      notification_settings:{grace_period_ms:21600000, backlog_size:3}, notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  [[ -n "$ID" && "$ID" != "null" ]] && ok "detection creee ($ID)" || warn "creation refusee"
fi
echo "=== termine ($([[ $APPLY == 1 ]] && echo APPLIQUE || echo DRY-RUN)). ==="
