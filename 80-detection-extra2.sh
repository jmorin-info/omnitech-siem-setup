#!/usr/bin/env bash
# =============================================================================
# 80-detection-extra2.sh - Nouveaux detecteurs ATT&CK haute-fidelite / faible FP
#   Trois tripwires valides sur les donnees REELLES du parc (sonde OpenSearch
#   omni-*, fenetre 30 j) : baseline observee = 0 evenement pour chaque signature
#   -> alerte count>=1 justifiee (et non un seuil comportemental bruyant).
#
#   1) defender_tamper (T1562.001) : neutralisation de Microsoft Defender.
#      - Sysmon EID1 (CommandLine) : Set-MpPreference -Disable*, Add-MpPreference
#        -Exclusion*, MpCmdRun -RemoveDefinitions, sc config/delete WinDefend|
#        Sense|WdNisSvc. (0 hit / 30 j)
#      - Sysmon EID13 (TargetObject) : ecriture des cles de POLITIQUE Defender
#        (DisableAntiSpyware, Real-Time Protection\Disable*, Features\
#        TamperProtection, \Exclusions\). (0 hit / 30 j ; le bruit BAM sous
#        Services\bam\... ne matche PAS ces sous-cles de politique).
#      NB complementaire de 47 (service_stop_securite = 'sc stop windefend') et de
#      la regle Defender EID5001 (winother) : ici on cible la DESACTIVATION/
#      affaiblissement persistant, pas un simple stop ni une detection AV.
#
#   2) schtask_payload (T1053.005) : tache planifiee (4698) dont le CONTENU embarque
#      une charge offensive (PowerShell encode/-enc, cradle de telechargement,
#      LOLBin, fenetre cachee, chemin temp/appdata). Se declenche MEME si la tache
#      est creee par SYSTEM / un compte machine $ -> comble l'angle mort de la regle
#      'scheduled_task' (47) qui ne filtre que sur le compte createur. Sur le parc,
#      les seules taches a charge PowerShell sont \OMNI-SIEM-Deploy/\OMNI-Inventory
#      (-nop, script de deploiement) : aucune ne matche ces signatures offensives.
#      (0 hit / 30 j).
#
#   3) amsi_bypass (T1562.001) : contournement AMSI en memoire (patch amsiScanBuffer
#      / amsiInitFailed, reflexion sur ...Management.Automation.AmsiUtils,
#      unverifiableLoadTable) vu dans le ScriptBlock PowerShell (4104, stream
#      'OMNI - Windows autres') ou la CommandLine Sysmon. La regle scriptblock
#      existante (12) couvre frombase64/downloadstring/mimikatz/reflectivePE mais
#      PAS la famille AMSI. (0 hit / 30 j sur ~7,4 M de ScriptBlock).
#
#   Pipeline dedie (stage 13), regles posees AVANT l'enrichissement MITRE (stage 20),
#   connecte aux streams Sysmon / Windows Security / Windows autres. MITRE csv append,
#   alertes via le pattern mk_a (tier mail + Teams). Idempotent.
#   Prerequis : 12 (streams/pipelines) + 37 (lookup MITRE) + 13 (notifications).
#   Relancer ensuite 57 (carte de couverture) puis 14 (couleurs/dashboards).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Regles de detection"

# --- 1) Defender tamper -------------------------------------------------------
# Voie A : ligne de commande (Sysmon EID1). On exige le verbe d'affaiblissement
# pour eviter tout faux positif sur un simple 'Get-MpPreference'/'Get-MpComputerStatus'.
ensure_rule "omni-x2-13-defender-tamper-cmd" <<'EOF'
rule "omni-x2-13-defender-tamper-cmd"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND (
    ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "set-mppreference", true)
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "disablerealtimemonitoring", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "disableioavprotection", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "disablebehaviormonitoring", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "disablescriptscanning", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "disableblockatfirstseen", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "disableantispyware", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "-mapsreporting 0", true) ) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "add-mppreference", true)
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "exclusionpath", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "exclusionprocess", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "exclusionextension", true) ) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "mpcmdrun", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "removedefinitions", true) )
    OR ( ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "sc ", true)
        OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "sc.exe", true) )
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "config", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "delete", true) )
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "windefend", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "wdnissvc", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "sense", true) ) )
  )
then
  set_field("alert_tag", "defender_tamper");
  set_field("event_action", "defender_affaibli");
end
EOF

# Voie B : ecriture registre des cles de politique Defender (Sysmon EID13).
# Cible les sous-cles de POLITIQUE/configuration uniquement -> le bruit BAM
# (HKLM\System\CurrentControlSet\Services\bam\... referencant MsMpEng.exe) est
# exclu de fait car il ne contient aucune de ces sous-cles.
ensure_rule "omni-x2-13-defender-tamper-reg" <<'EOF'
rule "omni-x2-13-defender-tamper-reg"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "13"
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "windows defender\\disableantispyware", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "windows defender\\real-time protection\\disable", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "windows defender\\features\\tamperprotection", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "windows defender\\exclusions\\", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "windows advanced threat protection\\forcedefenderpassivemode", true) )
then
  set_field("alert_tag", "defender_tamper");
  set_field("event_action", "defender_politique_modifiee");
end
EOF

# --- 2) Scheduled task a charge offensive (4698, contenu de la tache) ---------
ensure_rule "omni-x2-13-schtask-payload" <<'EOF'
rule "omni-x2-13-schtask-payload"
when
  to_string($message.event_source) == "windows_security"
  AND to_string($message.winlogbeat_winlog_event_id) == "4698"
  AND has_field("winlogbeat_winlog_event_data_TaskContent")
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "-encodedcommand", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), " -enc ", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "frombase64string", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "downloadstring", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "downloadfile", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "invoke-expression", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "invoke-webrequest", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "iwr ", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "-windowstyle hidden", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "-w hidden", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "bitsadmin", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "certutil", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "regsvr32", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "mshta", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "rundll32", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "\\appdata\\", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "\\users\\public\\", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_TaskContent), "\\windows\\temp\\", true) )
then
  set_field("alert_tag", "schtask_payload");
  set_field("event_action", "tache_planifiee_charge_suspecte");
end
EOF

# --- 3) AMSI bypass (ScriptBlock 4104 ou CommandLine Sysmon) -----------------
ensure_rule "omni-x2-13-amsi-bypass" <<'EOF'
rule "omni-x2-13-amsi-bypass"
when
  ( ( to_string($message.winlogbeat_winlog_event_id) == "4104"
      AND has_field("winlogbeat_winlog_event_data_ScriptBlockText")
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "amsiinitfailed", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "amsiscanbuffer", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "amsicontext", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "amsiutils", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "system.management.automation.amsi", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "unverifiableloadtable", true) ) )
    OR ( to_string($message.event_source) == "sysmon"
      AND to_string($message.winlogbeat_winlog_event_id) == "1"
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "amsiinitfailed", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "amsiscanbuffer", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "amsiutils", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "unverifiableloadtable", true) ) )
  )
then
  set_field("alert_tag", "amsi_bypass");
  set_field("event_action", "amsi_contourne");
end
EOF

echo "==> [2/4] Pipeline 'OMNI - Detections extra2' (stage 13) + connexion streams"
PL="$(ensure_pipeline "OMNI - Detections extra2" <<'PIPE'
pipeline "OMNI - Detections extra2"
stage 13 match either
rule "omni-x2-13-defender-tamper-cmd"
rule "omni-x2-13-defender-tamper-reg"
rule "omni-x2-13-schtask-payload"
rule "omni-x2-13-amsi-bypass"
end
PIPE
)"
for ST in "OMNI - Sysmon" "OMNI - Windows Security" "OMNI - Windows autres"; do
  SID="$(get_stream_id "$ST")"
  [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream absent: $ST"
done

echo "==> [3/4] MITRE (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || { echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; ok "MITRE +$1"; }; }
add_mitre defender_tamper  T1562.001 "Impair Defenses: Disable or Modify Tools" "Defense Evasion" critique 9
add_mitre schtask_payload  T1053.005 "Scheduled Task"                           "Execution"       eleve    8
add_mitre amsi_bypass      T1562.001 "Impair Defenses: Disable or Modify Tools" "Defense Evasion" eleve    8
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE defender_tamper / schtask_payload / amsi_bypass"

echo "==> [4/4] Alertes (tier mail + Teams ; tripwire count>=1, baseline reelle = 0)"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
mk_a() { local T="$1" Q="$2" ST="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg st "$ST" --argjson n "$NF" '{title:$t,description:"80-detection-extra2.sh",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"; }
SYS="$(get_stream_id 'OMNI - Sysmon')"
WSEC="$(get_stream_id 'OMNI - Windows Security')"
WOTH="$(get_stream_id 'OMNI - Windows autres')"
# defender_tamper peut tomber sur Sysmon (cmd+reg) -> alerte sur le stream Sysmon.
mk_a "OMNI - Neutralisation de Defender (tamper/exclusion)" "alert_tag:defender_tamper" "$SYS"
mk_a "OMNI - Tache planifiee a charge offensive (4698)"     "alert_tag:schtask_payload" "$WSEC"
# amsi_bypass arrive surtout via 4104 (stream Windows autres).
mk_a "OMNI - Contournement AMSI (patch memoire PowerShell)"  "alert_tag:amsi_bypass"     "$WOTH"
echo
echo "=== 80 termine. 3 techniques : T1562.001 (defender_tamper, amsi_bypass) + T1053.005"
echo "    (schtask_payload). Relancer 57 (carte ATT&CK) puis 14 (couleurs/dashboards). ==="
