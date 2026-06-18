#!/usr/bin/env bash
# =============================================================================
# 47-detections-extra.sh - Detections complementaires (lacunes identifiees par
#   la revue multi-agent). 5 nouvelles regles, posees dans un pipeline DEDIE
#   (stage 10, donc avant l'enrichissement MITRE stage 20) connecte aux streams
#   concernes. Chaque regle pose un alert_tag mappe MITRE (CSV 37) :
#     - gpo_modification   (T1484.001) : edition de GPO par un HUMAIN (5136)
#     - asrep_roasting     (T1558.004) : 4768 sans pre-auth (PreAuthType=0)
#     - lolbin_suspect     (T1218)     : binaires systeme detournes (Sysmon 1)
#     - persistence_autorun(T1547.001) : cles Run/RunOnce (Sysmon 13)
#     - m365_oauth_consent (T1528)     : consentement applicatif OAuth (Entra)
# Idempotent. Prerequis : 12 (streams/pipelines) + 37 (lookup MITRE). Relance 13/14.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

echo "==> [1/4] Ajout des techniques MITRE manquantes (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }
add_mitre gpo_modification    T1484.001 "Domain Policy Modification"          "Defense Evasion"   eleve 7
add_mitre asrep_roasting      T1558.004 "AS-REP Roasting"                     "Credential Access" eleve 7
add_mitre lolbin_suspect      T1218     "System Binary Proxy Execution"       "Defense Evasion"   eleve 6
add_mitre persistence_autorun T1547.001 "Registry Run Keys / Startup Folder"  "Persistence"       eleve 6
add_mitre m365_oauth_consent  T1528     "Steal Application Access Token"       "Credential Access" eleve 7
# --- Comble la tactique Privilege Escalation (0 detection avant, cf. 57-mitre-coverage) :
add_mitre scheduled_task      T1053.005 "Scheduled Task"                       "Privilege Escalation" eleve 6
add_mitre service_install     T1543.003 "Windows Service"                      "Privilege Escalation" eleve 6
add_mitre uac_bypass          T1548.002 "Bypass User Account Control"          "Privilege Escalation" critique 8
# --- Enrichissements 2026-06-14 (suite) : menace M365 reelle + tactiques fines :
add_mitre m365_brute_externe  T1110     "Brute Force"                          "Credential Access" eleve 6
add_mitre remote_discovery    T1018     "Remote System Discovery"              "Discovery"         moyen 5
add_mitre service_stop_securite T1489   "Service Stop"                         "Impact"            eleve 7
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/4] Regles de detection"
WD="winlogbeat_winlog_event_data"

ensure_rule "omni-extra-10-gpo" <<EOF
rule "omni-extra-10-gpo"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 5136
  AND to_string(\$message.${WD}_ObjectClass) == "groupPolicyContainer"
  AND to_string(\$message.${WD}_SubjectUserSid) != "S-1-5-18"
  AND NOT ends_with(to_string(\$message.${WD}_SubjectUserName), "\$")
then
  set_field("alert_tag", "gpo_modification");
  set_field("event_action", "gpo_modifie");
end
EOF

ensure_rule "omni-extra-10-asrep" <<EOF
rule "omni-extra-10-asrep"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4768
  AND to_string(\$message.${WD}_PreAuthType) == "0"
  AND NOT ends_with(to_string(\$message.${WD}_TargetUserName), "\$")
then
  set_field("alert_tag", "asrep_roasting");
end
EOF

ensure_rule "omni-extra-10-lolbin" <<EOF
rule "omni-extra-10-lolbin"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 1
  AND (
    (contains(to_string(\$message.process_name), "certutil", true)
       AND (contains(to_string(\$message.command_line), "urlcache", true)
         OR contains(to_string(\$message.command_line), "-decode", true)
         OR contains(to_string(\$message.command_line), "-encode", true)))
    OR (contains(to_string(\$message.process_name), "regsvr32", true)
       AND (contains(to_string(\$message.command_line), "scrobj", true)
         OR contains(to_string(\$message.command_line), "/i:http", true)))
    OR (contains(to_string(\$message.process_name), "rundll32", true)
       AND contains(to_string(\$message.command_line), "javascript:", true))
    OR (contains(to_string(\$message.process_name), "mshta", true)
       AND (contains(to_string(\$message.command_line), "http", true)
         OR contains(to_string(\$message.command_line), "vbscript:", true)
         OR contains(to_string(\$message.command_line), "javascript:", true)))
    OR (contains(to_string(\$message.process_name), "bitsadmin", true)
       AND contains(to_string(\$message.command_line), "/transfer", true))
  )
then
  set_field("alert_tag", "lolbin_suspect");
end
EOF

ensure_rule "omni-extra-10-autorun" <<EOF
rule "omni-extra-10-autorun"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 13
  AND (contains(to_string(\$message.${WD}_TargetObject), "CurrentVersion\\\\Run", true)
    OR contains(to_string(\$message.${WD}_TargetObject), "StartupApproved", true))
then
  set_field("alert_tag", "persistence_autorun");
end
EOF

# Tache planifiee creee par un HUMAIN (4698 ; exclut les comptes machine $).
# Vecteur classique d'execution/persistance/elevation (T1053.005).
ensure_rule "omni-extra-10-schtask" <<EOF
rule "omni-extra-10-schtask"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4698
  AND NOT ends_with(to_string(\$message.user), "\$")
then
  set_field("alert_tag", "scheduled_task");
  set_field("event_action", "tache_planifiee_creee");
end
EOF

# Service installe (4697) hors svchost legitime = persistance/elevation (T1543.003).
ensure_rule "omni-extra-10-service" <<EOF
rule "omni-extra-10-service"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4697
  AND NOT contains(to_string(\$message.${WD}_ServiceFileName), "svchost.exe", true)
then
  set_field("alert_tag", "service_install");
  set_field("event_action", "service_installe");
end
EOF

# Contournement UAC (T1548.002) : binaire auto-elevant connu (fodhelper, eventvwr,
# sdclt, computerdefaults, wsreset, slui) qui lance un interpreteur = elevation.
ensure_rule "omni-extra-10-uacbypass" <<EOF
rule "omni-extra-10-uacbypass"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 1
  AND ( contains(to_string(\$message.${WD}_ParentImage), "fodhelper.exe", true)
     OR contains(to_string(\$message.${WD}_ParentImage), "eventvwr.exe", true)
     OR contains(to_string(\$message.${WD}_ParentImage), "sdclt.exe", true)
     OR contains(to_string(\$message.${WD}_ParentImage), "computerdefaults.exe", true)
     OR contains(to_string(\$message.${WD}_ParentImage), "wsreset.exe", true)
     OR contains(to_string(\$message.${WD}_ParentImage), "slui.exe", true) )
  AND ( contains(to_string(\$message.process_name), "cmd.exe", true)
     OR contains(to_string(\$message.process_name), "powershell", true)
     OR contains(to_string(\$message.process_name), "rundll32", true)
     OR contains(to_string(\$message.process_name), "wscript", true)
     OR contains(to_string(\$message.process_name), "cscript", true)
     OR contains(to_string(\$message.process_name), "mshta", true) )
then
  set_field("alert_tag", "uac_bypass");
end
EOF

# Brute-force / spraying M365 depuis l'etranger : echecs de connexion hors FR.
# Donnee REELLE (95 echecs depuis des IP etrangeres ciblant des comptes precis).
ensure_rule "omni-extra-10-m365brute" <<EOF
rule "omni-extra-10-m365brute"
when
  to_string(\$message.m365_type) == "signin"
  AND to_string(\$message.event_action) == "echec_connexion"
  AND has_field("src_country")
  AND to_string(\$message.src_country) != "FR"
then
  set_field("alert_tag", "m365_brute_externe");
end
EOF

# Reconnaissance AD/reseau (T1018) : net view/group, nltest, dsquery (Sysmon 1).
ensure_rule "omni-extra-10-discovery" <<EOF
rule "omni-extra-10-discovery"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 1
  AND ( contains(to_string(\$message.process_name), "nltest", true)
     OR contains(to_string(\$message.process_name), "dsquery", true)
     OR ( (contains(to_string(\$message.process_name), "net.exe", true)
            OR contains(to_string(\$message.process_name), "net1.exe", true))
          AND ( contains(to_string(\$message.command_line), " view", true)
             OR contains(to_string(\$message.command_line), " group ", true)
             OR contains(to_string(\$message.command_line), "domain admins", true) ) ) )
then
  set_field("alert_tag", "remote_discovery");
end
EOF

# Arret de services de SECURITE (T1489) : prelude classique au ransomware/sabotage.
ensure_rule "omni-extra-10-svcstop" <<EOF
rule "omni-extra-10-svcstop"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 1
  AND contains(to_string(\$message.command_line), "stop", true)
  AND ( contains(to_string(\$message.command_line), "windefend", true)
     OR contains(to_string(\$message.command_line), "wuauserv", true)
     OR contains(to_string(\$message.command_line), "eventlog", true)
     OR contains(to_string(\$message.command_line), "mpssvc", true)
     OR contains(to_string(\$message.command_line), "sense", true)
     OR contains(to_string(\$message.command_line), "wscsvc", true)
     OR contains(to_string(\$message.command_line), "sophos", true)
     OR contains(to_string(\$message.command_line), "veeam", true) )
then
  set_field("alert_tag", "service_stop_securite");
end
EOF

# Risque Entra ID Protection (detection ML native Microsoft) : compte atRisk.
# Haute confiance (c'est le moteur de risque de Microsoft sur TON tenant).
ensure_rule "omni-extra-10-m365risk" <<EOF
rule "omni-extra-10-m365risk"
when
  to_string(\$message.m365_type) == "risk"
  AND to_string(\$message.risk_state) == "atRisk"
then
  set_field("alert_tag", "m365_risque");
end
EOF

ensure_rule "omni-extra-10-oauth" <<EOF
rule "omni-extra-10-oauth"
when
  to_string(\$message.m365_type) == "audit"
  AND (to_string(\$message.event_action) == "Consent to application"
    OR to_string(\$message.event_action) == "Add delegated permission grant"
    OR to_string(\$message.event_action) == "Add OAuth2PermissionGrant"
    OR to_string(\$message.event_action) == "Add app role assignment to service principal")
then
  set_field("alert_tag", "m365_oauth_consent");
end
EOF

echo "==> [3/4] Pipeline 'OMNI - Detections complementaires' (stage 10) + connexion"
PL="$(ensure_pipeline "OMNI - Detections complementaires" <<'EOF'
pipeline "OMNI - Detections complementaires"
stage 10 match either
rule "omni-extra-10-gpo"
rule "omni-extra-10-asrep"
rule "omni-extra-10-lolbin"
rule "omni-extra-10-autorun"
rule "omni-extra-10-schtask"
rule "omni-extra-10-service"
rule "omni-extra-10-uacbypass"
rule "omni-extra-10-m365brute"
rule "omni-extra-10-discovery"
rule "omni-extra-10-svcstop"
rule "omni-extra-10-m365risk"
rule "omni-extra-10-oauth"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon" "OMNI - M365"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done

echo "==> [4/4] Couleur (COMMON_HL via 14) - relancer 14 ensuite"
echo
echo "=== 47-detections-extra.sh termine. Relancer 13 (alertes) + 14 (couleurs). ==="
