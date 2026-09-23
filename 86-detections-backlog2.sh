#!/usr/bin/env bash
# =============================================================================
# 86-detections-backlog2.sh - 2e lot de detections du backlog MITRE (analyse
#   multi-agents 02/07/2026). Chaque requete VALIDEE en live avant ajout (champ
#   present, syntaxe OK, dormance legitime ou activite reelle mesuree). Modele
#   mk_detect (requete directe, pas de regle pipeline a attacher). Notifs Teams
#   + Triage (mail si critique/pertinent). Idempotent.
#
#   NOUVELLES (les 6 deja couvertes par 85 - T1219/T1572/T1621/T1203/T1078.004/
#   T1555.004 - ne sont PAS reprises ici) :
#     T1606.002 Golden SAML / detournement de federation (M365 audit)   [dormant]
#     T1098.005 Enregistrement appareil / methode MFA (M365 audit)      [actif 19]
#     T1114.002 Exfiltration email eDiscovery/export (M365 Exchange)    [dormant]
#     T1562.008 Alteration des journaux d'audit cloud M365             [dormant]
#     T1204.002 Execution binaire depose via archiveur/Outlook (Sysmon) [dormant]
#     T1505.005 VIB rogue / script de demarrage ESXi (vSphere)          [dormant]
#   T1133 (login VPN depuis IP malveillante) = enrichissement remip requis,
#   traite separement (voir 12-graylog-pipelines.sh / regle omni-forti-*-remip-ti).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

ST_SYSMON="$(get_stream_id 'OMNI - Sysmon')"; [[ -n "${ST_SYSMON}" ]] || die "stream Sysmon absent"
ST_M365="$(get_stream_id 'OMNI - M365')";     [[ -n "${ST_M365}" ]]   || die "stream M365 absent"
ST_VS="$(get_stream_id 'OMNI - vSphere')";     [[ -n "${ST_VS}" ]]     || die "stream vSphere absent"
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

# --- T1606.002 Golden SAML / detournement de federation (M365 directoryAudits) --
# Chaque modif de federation/domaine = compromission tenant potentielle -> P2, filtre.
mk_detect "OMNI - M365 Golden SAML / détournement de fédération (T1606.002)" 2 \
  'event_source:m365 AND m365_type:audit AND event_action:("Set federation settings on domain" OR "Set domain authentication" OR "Set DirSync feature" OR "Add unverified domain" OR "Add domain to company" OR "Add partner to company")' \
  "$ST_M365" '["user"]' 1 900000 300000 3600000 \
  "86/T1606.002 : modification des parametres de federation/domaine Entra (base d'un Golden SAML / detournement d'annuaire). Dormance legitime (PME sans ADFS) : chaque occurrence = a investiguer."

# --- T1098.005 Enregistrement appareil / methode MFA (M365 directoryAudits) -----
# Actif (19 evts) : onboarding MFA legitime + ajout de methode par un attaquant.
# Exclut le service systeme d'enregistrement d'appareils. P3 (bruyant) -> Teams+triage.
mk_detect "OMNI - M365 enregistrement appareil / méthode MFA (T1098.005)" 3 \
  'event_source:m365 AND m365_type:audit AND event_action:("Register device" OR "Add device" OR "Add registered owner to device" OR "Add registered users to device" OR "Add Windows Hello for Business credential" OR "User registered security info" OR "User registered all required security info" OR "User started security info registration") AND NOT upn:"Device Registration Service"' \
  "$ST_M365" '["upn"]' 1 3600000 600000 3600000 \
  "86/T1098.005 : enregistrement d'un appareil ou d'une methode MFA (Entra). Legitime a l'onboarding, mais un ajout de methode MFA sur un compte compromis = persistance identitaire. Correler avec un login inhabituel."

# --- T1114.002 Exfiltration email via eDiscovery / export (M365 Exchange/SCC) ----
mk_detect "OMNI - Exfiltration email via eDiscovery/export M365 (T1114.002)" 2 \
  'event_source:m365 AND m365_workload:(Exchange OR SecurityComplianceCenter) AND event_action:("New-ComplianceSearch" OR "New-ComplianceSearchAction" OR "New-MailboxExportRequest")' \
  "$ST_M365" '["user"]' 1 3600000 600000 3600000 \
  "86/T1114.002 : recherche eDiscovery / export d'action de recherche / export de boite (PST) = collecte massive d'emails. Rare (equipe conformite) -> a confirmer legitime."

# --- T1562.008 Alteration des journaux d'audit cloud M365 (Exchange) ------------
# Allowlist du principal de service Microsoft (bruit de config EXO interne).
mk_detect "OMNI - Altération des journaux d'audit cloud M365 (T1562.008)" 2 \
  'event_source:m365 AND m365_workload:Exchange AND event_action:("Set-AdminAuditLogConfig" OR "Set-MailboxAuditBypassAssociation" OR "New-MailboxAuditBypassAssociation" OR "Disable-MailboxAuditLog" OR "Remove-MailboxAuditBypassAssociation") AND NOT upn:*MSExchange*' \
  "$ST_M365" '["upn"]' 1 900000 300000 3600000 \
  "86/T1562.008 : cmdlet Exchange desactivant/contournant l'audit mailbox ou l'admin audit log = l'attaquant efface ses traces cloud. Principal de service Microsoft exclu."

# --- T1204.002 Execution d'un binaire depose via archiveur ou Outlook (Sysmon) --
# Parent archiveur interactif / Outlook -> enfant PE en zone inscriptible = loader.
mk_detect "OMNI - Exécution d'un binaire déposé via archiveur ou Outlook (T1204.002)" 2 \
  'event_source:sysmon AND winlogbeat_winlog_event_id:1 AND winlogbeat_winlog_event_data_ParentImage:(*WinRAR.exe OR *Rar.exe OR *7zFM.exe OR *7zG.exe OR *Bandizip.exe OR *PeaZip.exe OR *OUTLOOK.EXE) AND winlogbeat_winlog_event_data_Image:(*Downloads* OR *AppData* OR *Windows*Temp* OR *Users*Public* OR *ProgramData*)' \
  "$ST_SYSMON" '["host"]' 1 900000 300000 1800000 \
  "86/T1204.002 : un archiveur interactif (WinRAR/7-Zip/Bandizip/PeaZip) ou Outlook lance un binaire depose en zone inscriptible = execution d'une piece jointe malveillante (loader QakBot/IcedID). 7z.exe CLI et Explorer exclus."

# --- T1505.005 VIB rogue / script de demarrage ESXi (vSphere) -------------------
mk_detect "OMNI - VIB rogue / script de démarrage ESXi (T1505.005)" 2 \
  'event_source:vsphere AND message:("vib install" OR "vib remove" OR "acceptance set" OR "CommunitySupported" OR "PartnerSupported" OR "no-sig-check" OR "nosigcheck" OR "rc.local.d" OR "VisorFSTar" OR "vmkload_mod") AND NOT message:("ha-cli-handler" OR "CreateDynMoType" OR "dynamicMethodValidator" OR "does not belong to vib")' \
  "$ST_VS" '["source"]' 1 900000 300000 3600000 \
  "86/T1505.005 : installation/suppression de VIB, abaissement du niveau d'acceptation, contournement de signature ou script rc.local.d sur un hote ESXi = backdoor hyperviseur. Handlers/validateurs benins exclus."

echo
echo "=== 86-detections-backlog2.sh termine. 6 detections (5 dormantes + 1 active)."
echo "    T1133 (VPN IP malveillante) = enrichissement remip a part. Relancer 57 (carte ATT&CK)."
