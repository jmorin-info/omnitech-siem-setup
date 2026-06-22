#!/usr/bin/env bash
# =============================================================================
# 85-detection-extra3.sh - Detecteurs ATT&CK haute-fidelite / FP mesure nul
#   Neuf tripwires valides sur les donnees REELLES du parc (sonde OpenSearch
#   omni-sysmon_*). FENETRE REELLE MESUREE : ~11 j (2026-06-11 -> 2026-06-22),
#   ~10,6 M d'EID1 Sysmon, 85 hotes (l'index Sysmon ne couvre PAS 90 j). Pour
#   chaque signature OFFENSIVE precise : baseline observee = 0 -> alerte count>=1.
#   Le piege commun (mesure) : la RACINE LARGE est bruyante mais legitime, alors
#   que la signature offensive cadree = 0.
#
#   1) inhibit_recovery (T1490) : destruction des sauvegardes pre-ransomware.
#      vssadmin delete/resize shadows, wmic shadowcopy delete, wbadmin delete
#      catalog, bcdedit recoveryenabled no / ignoreallfailures.
#      Mesure : vssadmin=306 hits (TOUS 'list shadows/writers', 0 'delete') ;
#      wbadmin=10 (tous 'start backup' / 'delete systemstatebackup -keepVersions'
#      = rotation legitime, jamais 'delete catalog') ; bcdedit=4 (lecture seule).
#      Signatures destructrices = 0. (Impact : protege la capacite de restauration.)
#
#   2) lsass_dump_comsvcs (T1003.001) : dump LSASS via rundll32 comsvcs.dll MiniDump.
#      Complete lsass_access (Sysmon EID10, angle handle) par l'angle LIGNE DE
#      COMMANDE. Piege mesure : 'minidump' brut = 1792 hits, 100% BENIN
#      (crashpad_handler.exe : Palo Alto PrismaAccess 1634, TeamViewer 104,
#      Spotify 26 ; argument --type=crashpad-handler). On cadre sur comsvcs.dll
#      OU 'minidump'+'lsass' -> 0 hit, FP nul.
#
#   3) ntds_ifm_dump (T1003.003) : extraction NTDS.dit via 'ntdsutil ... ifm
#      create full'. Mesure : ntdsutil=0, 'create full'=0 sur 11 j. ntdsutil IFM
#      n'est pas execute en regime normal (promotions DC rares/planifiees). Leve
#      l'angle mort de 67 (ntdsutil y est range dans ad_recon, sans tag dump dedie).
#
#   4) installutil_proxy (T1218.004) : execution proxy via InstallUtil.exe (gate
#      sur /logfile= , /u , /logtoconsole=false). Mesure : installutil(Image)=0.
#      msbuild ECARTE volontairement (9183 hits = postes dev, builds .NET = NON
#      zero-FP) malgre T1127.001. Complete lolbin_suspect (47) qui ne couvre PAS
#      installutil. (Confiance moyenne : fenetre 11 j ; gate d'execution = robuste.)
#
#   Pipeline dedie "OMNI - Detections extra3" (stage 13, avant enrichissement MITRE
#   stage 20), connecte au stream Sysmon. MITRE csv append, alertes mk_a (mail +
#   Teams, count>=1). Idempotent.
#   Prerequis : 12 (streams/pipelines) + 37 (lookup MITRE) + 13 (notifications).
#   Relancer ensuite 57 (carte de couverture) puis 14 (couleurs/dashboards).
#   NON DEPLOYE par defaut dans le flux 00-run-all : a deployer apres revue (comme 80).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Regles de detection (stream Sysmon, EID1)"

# --- 1) Inhibition de la restauration (T1490) --------------------------------
ensure_rule "omni-x3-13-inhibit-recovery" <<'EOF'
rule "omni-x3-13-inhibit-recovery"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND (
    ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "vssadmin", true)
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "delete shadows", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "resize shadowstorage", true) ) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "shadowcopy", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "delete", true) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "wbadmin", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "delete catalog", true) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "bcdedit", true)
      AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "recoveryenabled no", true)
         OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "ignoreallfailures", true) ) )
  )
then
  set_field("alert_tag", "inhibit_recovery");
  set_field("event_action", "destruction_sauvegardes");
end
EOF

# --- 2) Dump LSASS via comsvcs.dll MiniDump (T1003.001) ----------------------
ensure_rule "omni-x3-13-comsvcs-lsass" <<'EOF'
rule "omni-x3-13-comsvcs-lsass"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND (
    ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "comsvcs", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "minidump", true) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "minidump", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "lsass", true) )
  )
then
  set_field("alert_tag", "lsass_dump_comsvcs");
  set_field("event_action", "dump_lsass_comsvcs");
end
EOF

# --- 3) Extraction NTDS.dit via ntdsutil IFM (T1003.003) ---------------------
ensure_rule "omni-x3-13-ntdsutil-ifm" <<'EOF'
rule "omni-x3-13-ntdsutil-ifm"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "ntdsutil", true)
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "create full", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "ifm", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "ac i ntds", true) )
then
  set_field("alert_tag", "ntds_ifm_dump");
  set_field("event_action", "extraction_ntds_ifm");
end
EOF

# --- 4) Execution proxy via InstallUtil (T1218.004) --------------------------
# Gate sur un declencheur d'execution (/logfile= , /u , /logtoconsole=false) pour
# rester robuste si un installeur .NET legitime apparait sur le parc.
ensure_rule "omni-x3-13-installutil-proxy" <<'EOF'
rule "omni-x3-13-installutil-proxy"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND contains(to_string($message.winlogbeat_winlog_event_data_Image), "installutil.exe", true)
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "/logfile=", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "/u ", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "/logtoconsole=false", true) )
then
  set_field("alert_tag", "installutil_proxy");
  set_field("event_action", "execution_proxy_installutil");
end
EOF

# --- 5) Application Office lance un interpreteur (T1204.002) ------------------
# Macro/document malveillant : une appli Office (winword/excel/powerpnt/outlook/
# mspub/onenote) lance un shell/script/LOLBin. Mesure 7j : 0 occurrence (Office ne
# lance JAMAIS cmd/powershell/wscript/cscript/mshta/regsvr32/rundll32/certutil/
# bitsadmin/schtasks en regime normal) -> tout hit = execution de macro = incident.
ensure_rule "omni-x3-13-office-shell" <<'EOF'
rule "omni-x3-13-office-shell"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\winword.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\excel.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\powerpnt.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\outlook.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\mspub.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\onenote.exe", true) )
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\cmd.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\powershell.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\pwsh.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\wscript.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\cscript.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\mshta.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\regsvr32.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\rundll32.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\certutil.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\bitsadmin.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\schtasks.exe", true) )
then
  set_field("alert_tag", "office_spawn_shell");
  set_field("event_action", "execution_macro_office");
end
EOF

# --- 6) Telechargement via certutil : variantes -split / -verifyctl (T1105) ---
# COMPLEMENT de lolbin_suspect (47) qui couvre deja certutil + urlcache/-decode/-encode.
# Ici on cible les methodes de telechargement que 47 NE couvre PAS : -split (recombinaison
# de fichier) et -verifyctl (recuperation de CTL via URL). Pas d'urlcache (anti-doublon).
# Mesure 7j : 0.
ensure_rule "omni-x3-13-certutil-download" <<'EOF'
rule "omni-x3-13-certutil-download"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "certutil", true)
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "-split", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "verifyctl", true) )
then
  set_field("alert_tag", "certutil_download");
  set_field("event_action", "download_lolbin_certutil");
end
EOF

# --- 7) Effacement de journal via wevtutil (T1070.001) -----------------------
# wevtutil cl / clear-log : effacement d'un journal d'evenements (couverture de traces).
# Mesure 7j : 0 -> tout hit = effacement delibere (incident d'evasion).
ensure_rule "omni-x3-13-wevtutil-clear" <<'EOF'
rule "omni-x3-13-wevtutil-clear"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "wevtutil", true)
  AND ( contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), " cl ", true)
     OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "clear-log", true) )
then
  set_field("alert_tag", "wevtutil_clear");
  set_field("event_action", "effacement_journal");
end
EOF

# --- 8) Suppression du journal USN via fsutil (anti-forensique, T1070) -------
# fsutil usn deletejournal : detruit le journal des modifications NTFS (cache les
# operations fichier, frequent pre-ransomware). Mesure 7j : 0.
ensure_rule "omni-x3-13-fsutil-usn" <<'EOF'
rule "omni-x3-13-fsutil-usn"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "deletejournal", true)
then
  set_field("alert_tag", "fsutil_usn");
  set_field("event_action", "suppression_journal_usn");
end
EOF

# --- 9) Execution via WMI : wmic process call create (T1047) -----------------
# Lancement de processus a distance/local via WMI. Mesure 7j : 0 'process call create'.
ensure_rule "omni-x3-13-wmic-exec" <<'EOF'
rule "omni-x3-13-wmic-exec"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "process call create", true)
then
  set_field("alert_tag", "wmic_exec");
  set_field("event_action", "execution_wmi");
end
EOF

echo "==> [2/4] Pipeline 'OMNI - Detections extra3' (stage 13) + connexion stream Sysmon"
PL="$(ensure_pipeline "OMNI - Detections extra3" <<'PIPE'
pipeline "OMNI - Detections extra3"
stage 13 match either
rule "omni-x3-13-inhibit-recovery"
rule "omni-x3-13-comsvcs-lsass"
rule "omni-x3-13-ntdsutil-ifm"
rule "omni-x3-13-installutil-proxy"
rule "omni-x3-13-office-shell"
rule "omni-x3-13-certutil-download"
rule "omni-x3-13-wevtutil-clear"
rule "omni-x3-13-fsutil-usn"
rule "omni-x3-13-wmic-exec"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Sysmon')"
[[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream absent: OMNI - Sysmon"

echo "==> [3/4] MITRE (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || { echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; ok "MITRE +$1"; }; }
add_mitre inhibit_recovery   T1490     "Inhibit System Recovery"                    "Impact"            critique 9
add_mitre lsass_dump_comsvcs T1003.001 "OS Credential Dumping: LSASS Memory"        "Credential Access" critique 9
add_mitre ntds_ifm_dump      T1003.003 "OS Credential Dumping: NTDS"                "Credential Access" critique 9
add_mitre installutil_proxy  T1218.004 "System Binary Proxy Execution: InstallUtil" "Defense Evasion"   eleve    7
add_mitre office_spawn_shell  T1204.002 "User Execution: Malicious File"             "Execution"         critique 9
add_mitre certutil_download   T1105     "Ingress Tool Transfer"                       "Command and Control" eleve  7
add_mitre wevtutil_clear      T1070.001 "Indicator Removal: Clear Windows Event Logs" "Defense Evasion"   critique 9
add_mitre fsutil_usn          T1070     "Indicator Removal"                           "Defense Evasion"   eleve    8
add_mitre wmic_exec           T1047     "Windows Management Instrumentation"          "Execution"         eleve    7
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE inhibit_recovery / lsass_dump_comsvcs / ntds_ifm_dump / installutil_proxy"

echo "==> [4/4] Alertes (tier mail + Teams ; tripwire count>=1, baseline reelle = 0)"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
mk_a() { local T="$1" Q="$2" ST="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg st "$ST" --argjson n "$NF" '{title:$t,description:"85-detection-extra3.sh",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"; }
SYS="$(get_stream_id 'OMNI - Sysmon')"
mk_a "OMNI - Destruction des sauvegardes (vssadmin/wbadmin/bcdedit)" "alert_tag:inhibit_recovery"   "$SYS"
mk_a "OMNI - Dump LSASS via comsvcs.dll MiniDump"                    "alert_tag:lsass_dump_comsvcs" "$SYS"
mk_a "OMNI - Extraction NTDS.dit via ntdsutil IFM"                   "alert_tag:ntds_ifm_dump"      "$SYS"
mk_a "OMNI - Execution proxy via InstallUtil"                        "alert_tag:installutil_proxy"  "$SYS"
mk_a "OMNI - Application Office lance un interpreteur (macro)"        "alert_tag:office_spawn_shell" "$SYS"
mk_a "OMNI - Telechargement via certutil (LOLBin)"                   "alert_tag:certutil_download" "$SYS"
mk_a "OMNI - Effacement de journal d'evenements (wevtutil)"          "alert_tag:wevtutil_clear"    "$SYS"
mk_a "OMNI - Suppression du journal USN (fsutil, anti-forensique)"   "alert_tag:fsutil_usn"        "$SYS"
mk_a "OMNI - Execution via WMI (process call create)"               "alert_tag:wmic_exec"         "$SYS"
echo
echo "=== 85 termine. 9 techniques (+office_spawn_shell/certutil_download/wevtutil_clear/fsutil_usn/wmic_exec) : T1490 (inhibit_recovery), T1003.001 (lsass_dump_comsvcs),"
echo "    T1003.003 (ntds_ifm_dump), T1218.004 (installutil_proxy). Baseline 0 mesuree sur ~11 j."
echo "    Relancer 57 (carte ATT&CK) puis 14 (couleurs/dashboards). ==="
