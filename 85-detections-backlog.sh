#!/usr/bin/env bash
# =============================================================================
# 85-detections-backlog.sh - Detections issues du backlog MITRE (workflow
#   couverture, cf DETECTION-BACKLOG.md). Chaque requete VALIDEE sur donnees
#   reelles (champs existants + allowlist) avant ajout. Notifs : Teams (firehose)
#   + Triage (mail si critique/pertinent). Idempotent (garde event_def_id paginee).
#
#   [#4]  T1219 Remote Access Software (RAT/RMM hors NinjaRMM, hotliners exclus)
#   [#6]  T1572 Protocol Tunneling (ngrok / cloudflared / serveo / localtunnel)
#   [#3]  T1621 MFA fatigue / push bombing (M365 fail_code 500121, >=5/user/10min)
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

ST_SYSMON="$(get_stream_id 'OMNI - Sysmon')"; [[ -n "${ST_SYSMON}" ]] || die "stream Sysmon absent"
ST_M365="$(get_stream_id 'OMNI - M365')";     [[ -n "${ST_M365}" ]]   || die "stream M365 absent"
ST_FORTI="$(get_stream_id 'OMNI - FortiGate')"; [[ -n "${ST_FORTI}" ]] || die "stream FortiGate absent"
TEAMS_ID="$(api_get '/events/notifications?per_page=100' | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
TRIAGE_ID="$(api_get '/events/notifications?per_page=100' | jq -r '.notifications[]?|select(.title=="OMNI - Triage (mail critique)")|.id')"
NOTIFS="$(jq -nc --arg t "$TEAMS_ID" --arg tr "$TRIAGE_ID" \
  '[{notification_id:$t,notification_parameters:null}] + (if $tr!="" then [{notification_id:$tr,notification_parameters:null}] else [] end)')"

# mk_detect <titre> <prio> <query> <stream> <group_by_json> <seuil> <within_ms> <every_ms> <grace_ms> <desc>
mk_detect() {
  local T="$1" P="$2" Q="$3" S="$4" GB="$5" TH="$6" W="$7" E="$8" G="$9" D="${10}"
  if [[ -n "$(event_def_id "${T}")" ]]; then skip "detection '${T}' existe"; return; fi
  local ID
  ID="$(jq -n --arg t "$T" --argjson p "$P" --arg q "$Q" --arg s "$S" --argjson gb "$GB" \
        --argjson th "$TH" --argjson w "$W" --argjson e "$E" --argjson g "$G" --arg d "$D" --argjson n "$NOTIFS" \
    '{title:$t, description:$d, priority:$p, alert:true,
      config:{type:"aggregation-v1", query:$q, query_parameters:[], streams:[$s],
        group_by:$gb, series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:$th}}},
        search_within_ms:$w, execute_every_ms:$e, use_cron_scheduling:false, event_limit:50},
      field_spec:{}, key_spec:[],
      notification_settings:{grace_period_ms:$g, backlog_size:10}, notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  if [[ -n "${ID}" && "${ID}" != "null" ]]; then
    "${CURL[@]}" -X PUT "${API}/events/definitions/${ID}/schedule" >/dev/null 2>&1 || true
    ok "cree + active : ${T} (${ID})"
  else warn "creation KO : ${T}"; fi
}

# [#4] T1219 — RAT/RMM hors RMM officiel (NinjaRMM) et hors PC hotline (bx-hl-*)
mk_detect "OMNI - Logiciel d'acces distant non autorise (RAT/RMM) - T1219" 2 \
  'event_source:sysmon AND winlogbeat_winlog_event_id:1 AND (winlogbeat_winlog_event_data_OriginalFileName:("AnyDesk.exe" OR "TeamViewer.exe" OR "RustDesk.exe" OR "ngrok.exe") OR winlogbeat_winlog_event_data_Image:(*anydesk* OR *teamviewer* OR *screenconnect* OR *splashtop* OR *atera* OR *rustdesk* OR *gotoassist* OR *remoteutilities* OR *zohoassist* OR *action1* OR *pulseway* OR *quickassist*)) AND NOT winlogbeat_winlog_event_data_Image:*ninjarmm* AND NOT source:bx\-hl\-*' \
  "$ST_SYSMON" '["source"]' 1 600000 300000 3600000 \
  "85/T1219 : outil de controle a distance hors RMM officiel (NinjaRMM) et hors hotline (bx-hl-*) = vecteur ransomware/intrusion. Sysmon EID1."

# [#6] T1572 — tunneling sortant (ngrok/cloudflared/serveo/localtunnel)
mk_detect "OMNI - Tunnel sortant ngrok/cloudflared (Protocol Tunneling) - T1572" 2 \
  'event_source:sysmon AND ((winlogbeat_winlog_event_id:1 AND winlogbeat_winlog_event_data_OriginalFileName:("cloudflared.exe" OR "ngrok.exe")) OR (winlogbeat_winlog_event_id:22 AND dns_query:(*.ngrok.io OR *.ngrok\-free.app OR *.ngrok.app OR *.trycloudflare.com OR *.loca.lt OR *.serveo.net OR *.lhr.life OR *.localhost.run)))' \
  "$ST_SYSMON" '["source"]' 1 600000 300000 3600000 \
  "85/T1572 : tunnel sortant (ngrok/cloudflared/serveo/localtunnel) = exfiltration / C2 / acces distant cache. Sysmon EID1+EID22(dns_query)."

# [#3] T1621 — MFA fatigue / push bombing (M365 sign-in 500121 = MFA refusee, rafale)
mk_detect "OMNI - MFA fatigue / push bombing M365 (>=5 refus / compte / 10 min) - T1621" 2 \
  'event_source:m365 AND m365_type:signin AND m365_fail_code:500121' \
  "$ST_M365" '["user"]' 5 600000 300000 1800000 \
  "85/T1621 : >=5 demandes MFA refusees (code 500121) sur un compte en 10 min = creds DEJA valides + spam de push (MFA fatigue). Entra sign-in."

# [#7] T1203 — exploitation client (navigateur/PDF -> interpreteur de script).
#   cmd.exe EXCLU : 9641 evts/7j = pattern legitime ici ; ps/wscript/mshta = 0 FP.
mk_detect "OMNI - Exploitation client : navigateur/PDF lance un interpreteur - T1203" 3 \
  'event_source:sysmon AND winlogbeat_winlog_event_id:1 AND winlogbeat_winlog_event_data_ParentImage:(*chrome.exe OR *msedge.exe OR *firefox.exe OR *AcroRd32.exe OR *Acrobat.exe OR *iexplore.exe) AND winlogbeat_winlog_event_data_Image:(*powershell.exe OR *wscript.exe OR *cscript.exe OR *mshta.exe)' \
  "$ST_SYSMON" '["source"]' 1 600000 300000 1800000 \
  "85/T1203 : un navigateur ou lecteur PDF engendre un interpreteur de script (powershell/wscript/mshta) = exploitation/RCE cote client. cmd.exe exclu (bruit legitime du parc)."

# [#11] T1078.004 — legacy auth M365 (bypass MFA), hors 'Authenticated SMTP' (MFP).
mk_detect "OMNI - Authentification legacy M365 (bypass MFA) - T1078.004" 3 \
  'event_source:m365 AND m365_type:signin AND event_action:connexion_reussie AND client_app:("Other clients" OR "IMAP4" OR "POP3")' \
  "$ST_M365" '["user"]' 1 3600000 600000 3600000 \
  "85/T1078.004 : connexion M365 reussie via protocole legacy (Other clients/IMAP/POP) = contournement MFA. 'Authenticated SMTP' (MFP) exclu."

# [#10] T1555.004 — vol de credentials Windows Credential Manager (cmdkey/vaultcmd /list).
mk_detect "OMNI - Vol Credential Manager Windows (cmdkey/vaultcmd) - T1555.004" 3 \
  'event_source:sysmon AND winlogbeat_winlog_event_id:1 AND (command_line:*cmdkey* OR command_line:*vaultcmd*) AND command_line:*list*' \
  "$ST_SYSMON" '["source"]' 1 600000 300000 3600000 \
  "85/T1555.004 : enumeration du gestionnaire d'identifiants Windows (cmdkey /list, vaultcmd /list) = vol de credentials stockes. Rare en legitime (IT/provisioning a allowlister si besoin)."

# [#23] T1518.001 Security Software Discovery — l'attaquant enumere l'AV/EDR avant de frapper.
mk_detect "OMNI - Reconnaissance de l'antivirus/EDR (Security Software Discovery) - T1518.001" 2 \
  'event_source:sysmon AND winlogbeat_winlog_event_id:1 AND (command_line:*MpComputerStatus* OR command_line:*MpPreference* OR command_line:*securitycenter2* OR (command_line:*tasklist* AND (command_line:*defender* OR command_line:*sentinel* OR command_line:*crowdstrike* OR command_line:*eset*)))' \
  "$ST_SYSMON" '["source"]' 1 600000 300000 3600000 \
  "85/T1518.001 : enumeration du produit de securite (Get-MpComputerStatus/MpPreference, securitycenter2, tasklist|findstr AV) = repérage avant desactivation/contournement. Rare en legitime."

# [#extra] T1547.001 Boot/Logon Autostart — Run-key avec charge malveillante (persistance).
#   Valeurs legitimes (OneDrive/Apidog/installeurs) EXCLUES ; on cible le payload franc.
mk_detect "OMNI - Persistance autorun malveillant (Run key) - T1547.001" 3 \
  'event_source:sysmon AND winlogbeat_winlog_event_id:13 AND winlogbeat_winlog_event_data_TargetObject:*CurrentVersion*Run* AND winlogbeat_winlog_event_data_Details:(*EncodedCommand* OR *FromBase64* OR *DownloadString* OR *DownloadFile* OR *IEX* OR *hidden* OR *bitsadmin* OR *certutil*)' \
  "$ST_SYSMON" '["source"]' 1 600000 300000 3600000 \
  "85/T1547.001 : cle Run/RunOnce ecrite avec une charge malveillante (powershell encode, DownloadString, certutil/bitsadmin, fenetre cachee) = persistance de malware. 0 FP valide."

# [ops] HA FortiGate out-of-sync / flapping — sante operationnelle (Teams/console).
#   logid 0108037903 = "Synchronization status with primary". Un membre stable ~0/h ;
#   en flapping ~7/h (vu : secondaire BDX FG120GTK23000193, 162/24h par paires). grace 6h.
mk_detect "OMNI - HA FortiGate instable / out-of-sync (>=5 / membre / h) - ops" 2 \
  'event_source:fortigate AND subtype:ha AND logid:0108037903' \
  "$ST_FORTI" '["devid"]' 5 3600000 600000 21600000 \
  "85/ops : un membre HA FortiGate change de statut de synchro >=5x/h = flapping (sort puis rentre en sync) = paire HA instable, protection de bascule degradee. PAS un evt securite -> Teams/console, pas de mail."

# MITRE mapping
CSV="lookups/mitre-attack.csv"
add_m(){ grep -q "^$1," "$CSV" 2>/dev/null || echo "$1,$2,\"$3\",\"$4\",$5,$6" >> "$CSV"; }
[[ -f "$CSV" ]] && { add_m remote_access_software T1219 "Logiciel acces distant non autorise" "Command and Control" eleve 7
                     add_m protocol_tunneling T1572 "Tunnel sortant ngrok/cloudflared" "Command and Control" eleve 7
                     add_m mfa_fatigue T1621 "MFA fatigue / push bombing" "Credential Access" eleve 8
                     add_m client_exploitation T1203 "Exploitation client (navigateur lance interpreteur)" "Execution" critique 9
                     add_m legacy_auth_m365 T1078.004 "Auth legacy M365 (bypass MFA)" "Initial Access" eleve 8
                     add_m cred_manager_theft T1555.004 "Vol Credential Manager Windows" "Credential Access" eleve 7
                     add_m secsoft_discovery T1518.001 "Reconnaissance antivirus/EDR" "Discovery" moyen 5
                     add_m autorun_persist T1547.001 "Persistance autorun malveillant" "Persistence" eleve 8; }

echo
echo "=== 85 termine. 7 detections (T1219/T1572/T1621/T1203/T1078.004/T1555.004/T1518.001) + HA ops. Cf DETECTION-BACKLOG.md (42). ==="
