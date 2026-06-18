#!/usr/bin/env bash
# ==============================================================================
# 12-graylog-pipelines.sh - Pipelines de traitement (normalisation + detection)
#
#   Schema de champs normalises OMNI (commun a toutes les sources) :
#     event_id, event_source, event_action, event_category,
#     user, host, src_ip, src_port, dest_ip, dest_port,
#     process_name, process_path, command_line, parent_process,
#     dns_query, logon_type_label, failure_reason, priv_group_label,
#     alert_tag  <- pose par les regles de detection, consomme par 13 (alertes)
#
#   4 pipelines, 1 par stream :
#     OMNI - Windows Security : normalisation, lookups (action/categorie,
#       logon type, raisons d'echec 4625/4776, echecs Kerberos, RID groupes
#       privilegies), detections (sabotage audit, DCSync, Kerberoasting)
#     OMNI - Sysmon           : process/reseau/DNS + injection, PowerShell suspect
#     OMNI - Windows autres   : action par canal:event_id + Defender, ScriptBlock
#     OMNI - FortiGate        : parsing key=value + renommage + tag UTM
#
#   + ordre des processeurs force : Message Filter Chain -> Pipeline Processor
#     -> GeoIP Resolver en dernier (geolocalise les src_ip/dest_ip normalises).
#
# Idempotent (les regles/pipelines sont mis a jour si la source change).
# Prerequis : 10 (streams) + 11 (lookups). Suite : 13-graylog-alerts.sh
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

# ==========================================================================
echo "==> [1/6] Regles - Windows Security"
# ==========================================================================

ensure_rule "omni-winsec-00-normalisation" <<'EOF'
rule "omni-winsec-00-normalisation"
when
  has_field("winlogbeat_winlog_event_id")
then
  set_field("event_id", to_string($message.winlogbeat_winlog_event_id));
  set_field("event_source", "windows_security");
  set_field("host", to_string($message.winlogbeat_winlog_computer_name));
end
EOF

ensure_rule "omni-winsec-00-user" <<'EOF'
rule "omni-winsec-00-user"
when
  has_field("winlogbeat_winlog_event_data_TargetUserName")
then
  set_field("user", to_string($message.winlogbeat_winlog_event_data_TargetUserName));
end
EOF

ensure_rule "omni-winsec-00-user-fallback" <<'EOF'
rule "omni-winsec-00-user-fallback"
when
  NOT has_field("winlogbeat_winlog_event_data_TargetUserName")
  AND has_field("winlogbeat_winlog_event_data_SubjectUserName")
then
  set_field("user", to_string($message.winlogbeat_winlog_event_data_SubjectUserName));
end
EOF

ensure_rule "omni-winsec-00-srcip" <<'EOF'
rule "omni-winsec-00-srcip"
when
  has_field("winlogbeat_winlog_event_data_IpAddress")
  AND to_string($message.winlogbeat_winlog_event_data_IpAddress) != "-"
then
  let ip = replace(to_string($message.winlogbeat_winlog_event_data_IpAddress), "::ffff:", "");
  set_field("src_ip", ip);
  set_field("src_host", to_string($message.winlogbeat_winlog_event_data_WorkstationName));
end
EOF

ensure_rule "omni-winsec-05-action" <<'EOF'
rule "omni-winsec-05-action"
when
  has_field("event_id")
then
  set_field("event_action",   lookup_value("omni-win-event-action",   to_string($message.event_id)));
  set_field("event_category", lookup_value("omni-win-event-category", to_string($message.event_id)));
end
EOF

ensure_rule "omni-winsec-05-logontype" <<'EOF'
rule "omni-winsec-05-logontype"
when
  has_field("winlogbeat_winlog_event_data_LogonType")
then
  set_field("logon_type_label", lookup_value("omni-logon-type", to_string($message.winlogbeat_winlog_event_data_LogonType)));
end
EOF

ensure_rule "omni-winsec-05-echec-logon" <<'EOF'
rule "omni-winsec-05-echec-logon"
when
  has_field("winlogbeat_winlog_event_data_SubStatus")
then
  // SubStatus vaut souvent 0x0 (ex: refus d'un droit de logon) : la vraie
  // cause est alors dans Status. 0x0 n'est plus mappe dans le CSV, le
  // parametre par defaut (lookup sur Status) prend donc le relais.
  set_field("failure_reason",
    lookup_value("omni-logon-failure",
      to_string($message.winlogbeat_winlog_event_data_SubStatus),
      lookup_value("omni-logon-failure", to_string($message.winlogbeat_winlog_event_data_Status))));
end
EOF

ensure_rule "omni-winsec-05-echec-ntlm" <<'EOF'
rule "omni-winsec-05-echec-ntlm"
when
  to_string($message.winlogbeat_winlog_event_id) == "4776"
  AND has_field("winlogbeat_winlog_event_data_Status")
  AND to_string($message.winlogbeat_winlog_event_data_Status) != "0x0"
then
  set_field("failure_reason", lookup_value("omni-logon-failure", to_string($message.winlogbeat_winlog_event_data_Status)));
end
EOF

ensure_rule "omni-winsec-05-echec-kerberos" <<'EOF'
rule "omni-winsec-05-echec-kerberos"
when
  (to_string($message.winlogbeat_winlog_event_id) == "4768"
   OR to_string($message.winlogbeat_winlog_event_id) == "4771")
  AND has_field("winlogbeat_winlog_event_data_Status")
then
  set_field("failure_reason", lookup_value("omni-kerb-failure", to_string($message.winlogbeat_winlog_event_data_Status)));
end
EOF

ensure_rule "omni-winsec-05-groupe-privilegie" <<'EOF'
rule "omni-winsec-05-groupe-privilegie"
when
  has_field("winlogbeat_winlog_event_data_TargetSid")
  AND (to_string($message.winlogbeat_winlog_event_id) == "4728"
    OR to_string($message.winlogbeat_winlog_event_id) == "4729"
    OR to_string($message.winlogbeat_winlog_event_id) == "4732"
    OR to_string($message.winlogbeat_winlog_event_id) == "4733"
    OR to_string($message.winlogbeat_winlog_event_id) == "4756"
    OR to_string($message.winlogbeat_winlog_event_id) == "4757")
then
  let m = regex("-([0-9]+)$", to_string($message.winlogbeat_winlog_event_data_TargetSid));
  set_field("priv_group_label", lookup_value("omni-priv-group-rid", to_string(m["0"])));
end
EOF

# Compteurs numeriques -> series sum() dans les alertes de correlation
# (permet "N echecs ET >=1 succes pour le meme compte" en une seule agregation)
ensure_rule "omni-winsec-00-compteur-echec" <<'EOF'
rule "omni-winsec-00-compteur-echec"
when
  to_string($message.winlogbeat_winlog_event_id) == "4625"
  AND to_string($message.winlogbeat_winlog_event_data_LogonType) != "4"
  AND to_string($message.winlogbeat_winlog_event_data_LogonType) != "5"
then
  set_field("logon_fail", 1);
end
EOF

# Echecs logon type 4 (batch) / 5 (service) = compte de service ou tache mal
# configure, PAS une attaque par mot de passe : compteur separe pour l'alerte
# d'hygiene dediee (sinon une boucle services.exe spamme "Force brute" en continu
# - cf. incident BX-AD02 du 12/06 : 1 echec toutes les 2 s pendant des jours).
ensure_rule "omni-winsec-00-compteur-echec-service" <<'EOF'
rule "omni-winsec-00-compteur-echec-service"
when
  to_string($message.winlogbeat_winlog_event_id) == "4625"
  AND (to_string($message.winlogbeat_winlog_event_data_LogonType) == "4"
    OR to_string($message.winlogbeat_winlog_event_data_LogonType) == "5")
then
  set_field("service_logon_fail", 1);
end
EOF

ensure_rule "omni-winsec-00-compteur-succes" <<'EOF'
rule "omni-winsec-00-compteur-succes"
when
  to_string($message.winlogbeat_winlog_event_id) == "4624"
  AND (to_string($message.winlogbeat_winlog_event_data_LogonType) == "2"
    OR to_string($message.winlogbeat_winlog_event_data_LogonType) == "7"
    OR to_string($message.winlogbeat_winlog_event_data_LogonType) == "10"
    OR to_string($message.winlogbeat_winlog_event_data_LogonType) == "11")
then
  // logon_ok seulement sur logons INTERACTIFS (2/7/10/11) : symetrie avec logon_fail
  // (qui exclut deja 4/5) -> evite que "force brute suivie d'un succes" se declenche
  // sur un simple 4624 reseau/service.
  set_field("logon_ok", 1);
end
EOF

ensure_rule "omni-winsec-10-adcs" <<'EOF'
rule "omni-winsec-10-adcs"
when
  to_string($message.winlogbeat_winlog_event_id) == "4886"
  OR to_string($message.winlogbeat_winlog_event_id) == "4887"
  OR to_string($message.winlogbeat_winlog_event_id) == "4888"
  OR to_string($message.winlogbeat_winlog_event_id) == "4889"
  OR to_string($message.winlogbeat_winlog_event_id) == "4870"
  OR to_string($message.winlogbeat_winlog_event_id) == "4882"
then
  set_field("event_source", "adcs");
  set_field("event_category", "pki");
  set_field("cert_requester", to_string($message.winlogbeat_winlog_event_data_Requester));
  set_field("cert_request_id", to_string($message.winlogbeat_winlog_event_data_RequestId));
  // un refus (4888) ou une revocation (4870) merite un oeil
  let eid = to_string($message.winlogbeat_winlog_event_id);
  set_field("cert_subject_disp", to_string($message.winlogbeat_winlog_event_data_SubjectName));
end
EOF

ensure_rule "omni-winsec-10-canary" <<'EOF'
rule "omni-winsec-10-canary"
when
  is_not_null(lookup_value("omni-canary", lowercase(to_string($message.user))))
  OR is_not_null(lookup_value("omni-canary", lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName))))
  OR is_not_null(lookup_value("omni-canary", lowercase(to_string($message.winlogbeat_winlog_event_data_SubjectUserName))))
  OR is_not_null(lookup_value("omni-canary", lowercase(regex_replace("\\$$", to_string($message.winlogbeat_winlog_event_data_ServiceName), ""))))
then
  set_field("alert_tag", "canary");
  set_field("event_category", "intrusion_canari");
end
EOF

ensure_rule "omni-winsec-10-partage-admin" <<'EOF'
rule "omni-winsec-10-partage-admin"
when
  (to_string($message.winlogbeat_winlog_event_id) == "5140"
   OR to_string($message.winlogbeat_winlog_event_id) == "5145")
  AND has_field("winlogbeat_winlog_event_data_ShareName")
  AND (contains(to_string($message.winlogbeat_winlog_event_data_ShareName), "ADMIN$", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_ShareName), "\\C$", true))
then
  set_field("alert_tag", "admin_share");
end
EOF

ensure_rule "omni-winsec-10-sabotage-audit" <<'EOF'
rule "omni-winsec-10-sabotage-audit"
when
  to_string($message.winlogbeat_winlog_event_id) == "1102"
  OR to_string($message.winlogbeat_winlog_event_id) == "1104"
  OR to_string($message.winlogbeat_winlog_event_id) == "4794"
  OR to_string($message.winlogbeat_winlog_event_id) == "4765"
  OR to_string($message.winlogbeat_winlog_event_id) == "4766"
then
  // 1100 (arret du service de journalisation) retire : bruit a chaque reboot.
  // Vrais signaux conserves : 1102/1104 (log efface/plein), 4794 (DSRM), 4765/66 (SID history).
  set_field("alert_tag", "winsec_critique");
end
EOF

ensure_rule "omni-winsec-10-auditpol-humain" <<'EOF'
rule "omni-winsec-10-auditpol-humain"
when
  to_string($message.winlogbeat_winlog_event_id) == "4719"
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "$", false)
then
  // 4719 (modif politique audit par un humain) = tag INFORMATIF, pas critique :
  // declenche en routine (GPO, auditpol admin) -> ne doit pas sonner "Sabotage audit".
  // Conserve, cherchable, mais hors alerte mail critique.
  set_field("alert_tag", "audit_config_change");
end
EOF

ensure_rule "omni-winsec-10-dcsync" <<'EOF'
rule "omni-winsec-10-dcsync"
when
  to_string($message.winlogbeat_winlog_event_id) == "4662"
  AND has_field("winlogbeat_winlog_event_data_Properties")
  AND (contains(to_string($message.winlogbeat_winlog_event_data_Properties), "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_Properties), "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", true))
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "$", false)
  AND NOT starts_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "MSOL_", true)
then
  set_field("alert_tag", "dcsync");
end
EOF

ensure_rule "omni-winsec-10-kerberoasting" <<'EOF'
rule "omni-winsec-10-kerberoasting"
when
  to_string($message.winlogbeat_winlog_event_id) == "4769"
  AND to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x17"
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_ServiceName), "$", false)
then
  set_field("alert_tag", "kerberoasting");
end
EOF

# ==========================================================================
echo "==> [2/6] Regles - Sysmon"
# ==========================================================================

ensure_rule "omni-sysmon-00-normalisation" <<'EOF'
rule "omni-sysmon-00-normalisation"
when
  has_field("winlogbeat_winlog_event_id")
then
  set_field("event_id", to_string($message.winlogbeat_winlog_event_id));
  set_field("event_source", "sysmon");
  set_field("host", to_string($message.winlogbeat_winlog_computer_name));
  set_field("user", to_string($message.winlogbeat_winlog_event_data_User));
end
EOF

ensure_rule "omni-sysmon-00-process" <<'EOF'
rule "omni-sysmon-00-process"
when
  has_field("winlogbeat_winlog_event_data_Image")
then
  let img = to_string($message.winlogbeat_winlog_event_data_Image);
  let m = regex("([^\\\\]+)$", img);
  set_field("process_path", img);
  set_field("process_name", to_string(m["0"]));
  set_field("command_line", to_string($message.winlogbeat_winlog_event_data_CommandLine));
  set_field("parent_process", to_string($message.winlogbeat_winlog_event_data_ParentImage));
end
EOF

ensure_rule "omni-sysmon-00-reseau" <<'EOF'
rule "omni-sysmon-00-reseau"
when
  to_string($message.winlogbeat_winlog_event_id) == "3"
then
  set_field("src_ip",    to_string($message.winlogbeat_winlog_event_data_SourceIp));
  set_field("dest_ip",   to_string($message.winlogbeat_winlog_event_data_DestinationIp));
  set_field("dest_port", to_string($message.winlogbeat_winlog_event_data_DestinationPort));
end
EOF

ensure_rule "omni-sysmon-00-dns" <<'EOF'
rule "omni-sysmon-00-dns"
when
  to_string($message.winlogbeat_winlog_event_id) == "22"
then
  set_field("dns_query", to_string($message.winlogbeat_winlog_event_data_QueryName));
end
EOF

ensure_rule "omni-sysmon-05-action" <<'EOF'
rule "omni-sysmon-05-action"
when
  has_field("event_id")
then
  set_field("event_action", lookup_value("omni-sysmon-event-action", to_string($message.event_id)));
end
EOF

ensure_rule "omni-sysmon-10-ransomware" <<'EOF'
rule "omni-sysmon-10-ransomware"
when
  to_string($message.winlogbeat_winlog_event_id) == "1"
  AND has_field("winlogbeat_winlog_event_data_CommandLine")
  AND (
    (contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "vssadmin", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "delete", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "shadow", true))
    OR (contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "wbadmin", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "delete", true))
    OR (contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "bcdedit", true)
      AND contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "recoveryenabled", true))
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "wmic shadowcopy delete", true)
  )
then
  set_field("alert_tag", "ransomware_indicator");
end
EOF

ensure_rule "omni-sysmon-10-lsass-access" <<'EOF'
rule "omni-sysmon-10-lsass-access"
when
  to_string($message.winlogbeat_winlog_event_id) == "10"
  AND ends_with(to_string($message.winlogbeat_winlog_event_data_TargetImage), "lsass.exe", true)
  AND (to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x1010"
    OR to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x1410"
    OR to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x1438"
    OR to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x143a"
    OR to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x1f0fff"
    OR to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x1f1fff"
    OR to_string($message.winlogbeat_winlog_event_data_GrantedAccess) == "0x1fffff")
  // WHITELIST des process de gestion/securite LEGITIMES accedant a LSASS, par
  // CHEMIN COMPLET (anti-usurpation : un binaire du meme nom ailleurs DECLENCHE).
  // Pour en ajouter : completer la liste OR ci-dessous avec le chemin exact.
  AND NOT (
       to_string($message.winlogbeat_winlog_event_data_SourceImage) == "C:\\Program Files (x86)\\NinjaOne\\NinjaRMMAgent.exe"
    OR to_string($message.winlogbeat_winlog_event_data_SourceImage) == "C:\\Program Files\\NinjaOne\\NinjaRMMAgent.exe"
  )
then
  set_field("alert_tag", "lsass_access");
end
EOF

ensure_rule "omni-sysmon-10-injection" <<'EOF'
rule "omni-sysmon-10-injection"
when
  (to_string($message.winlogbeat_winlog_event_id) == "8"
   OR to_string($message.winlogbeat_winlog_event_id) == "25")
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\dwm.exe", true)
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\winlogon.exe", true)
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\csrss.exe", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_SourceImage), "<unknown", true)
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\bash.exe", true)
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\node.exe", true)
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\code.exe", true)
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\git.exe", true)
then
  set_field("alert_tag", "sysmon_injection");
end
EOF

ensure_rule "omni-sysmon-10-powershell-suspect" <<'EOF'
rule "omni-sysmon-10-powershell-suspect"
when
  to_string($message.winlogbeat_winlog_event_id) == "1"
  AND has_field("winlogbeat_winlog_event_data_CommandLine")
  AND (contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), " -enc", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "frombase64string", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "downloadstring", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "downloadfile", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "invoke-expression", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "mimikatz", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "-nop -w hidden", true))
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_ParentImage), "Citrix\\Secure Access", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_ParentImage), "Dell\\TrustedDevice", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_ParentImage), "NinjaRMMAgent", true)
then
  set_field("alert_tag", "powershell_suspect");
end
EOF

# ==========================================================================
echo "==> [3/6] Regles - Windows autres canaux"
# ==========================================================================

ensure_rule "omni-winother-00-normalisation" <<'EOF'
rule "omni-winother-00-normalisation"
when
  has_field("winlogbeat_winlog_event_id")
then
  set_field("event_id", to_string($message.winlogbeat_winlog_event_id));
  set_field("event_source", "windows");
  set_field("channel", to_string($message.winlogbeat_winlog_channel));
  set_field("host", to_string($message.winlogbeat_winlog_computer_name));
end
EOF

# Inventaire logiciel / OS (Get-OmniInventory.ps1, canal OMNI-Inventaire) :
# parse les paires key=value|... -> inv_product/inv_version/inv_publisher (9101)
# ou os_caption/os_build/os_last_patch/... (9102). Source de la detection de
# vulnerabilites (omni-vuln-scan, cote SIEM). Doit passer APRES la normalisation
# (qui met event_source=windows) -> on repositionne event_source=inventory.
ensure_rule "omni-winother-00-inventory" <<'EOF'
rule "omni-winother-00-inventory"
when
  to_string($message.winlogbeat_winlog_channel) == "OMNI-Inventaire"
then
  set_fields(key_value(
    value: to_string($message.message),
    delimiters: "|", kv_delimiters: "=",
    ignore_empty_values: true, trim_value_chars: " "
  ));
  set_field("event_source", "inventory");
end
EOF

ensure_rule "omni-winother-05-action" <<'EOF'
rule "omni-winother-05-action"
when
  has_field("event_id") AND has_field("channel")
then
  let key = concat(concat(to_string($message.channel), ":"), to_string($message.event_id));
  set_field("event_action", lookup_value("omni-winother-action", key));
end
EOF

ensure_rule "omni-winother-10-defender" <<'EOF'
rule "omni-winother-10-defender"
when
  contains(to_string($message.winlogbeat_winlog_channel), "Windows Defender", true)
  AND (to_string($message.winlogbeat_winlog_event_id) == "1006"
    OR to_string($message.winlogbeat_winlog_event_id) == "1116"
    OR to_string($message.winlogbeat_winlog_event_id) == "1118"
    OR to_string($message.winlogbeat_winlog_event_id) == "1119"
    OR to_string($message.winlogbeat_winlog_event_id) == "5001")
then
  set_field("alert_tag", "defender");
end
EOF

ensure_rule "omni-winother-10-scriptblock-suspect" <<'EOF'
rule "omni-winother-10-scriptblock-suspect"
when
  to_string($message.winlogbeat_winlog_event_id) == "4104"
  AND has_field("winlogbeat_winlog_event_data_ScriptBlockText")
  AND (contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "frombase64string", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "downloadstring", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "mimikatz", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "invoke-reflectivepeinjection", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "getdelegateforfunctionpointer", true))
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_Path), "\\Microsoft Azure AD Sync\\", true)
  // Script interne legitime "wake-up SSRS" (keep-alive Reporting Services via
  // DownloadString) -> faux positif massif sur les postes dev/QA. Exclu par signature.
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_ScriptBlockText), "wake-up SSRS", true)
then
  set_field("alert_tag", "powershell_suspect");
end
EOF

ensure_rule "omni-winother-10-journal-systeme-efface" <<'EOF'
rule "omni-winother-10-journal-systeme-efface"
when
  to_string($message.winlogbeat_winlog_channel) == "System"
  AND to_string($message.winlogbeat_winlog_event_id) == "104"
then
  set_field("alert_tag", "winsec_critique");
end
EOF

# Surveillance des certificats du parc (journal OMNI-Certificats alimente par
# Get-OmniCertExpiry.ps1 sur la PKI et les serveurs). Parse le message
# "CERT_EXPIRE | machine=.. | store=.. | subject=.. | expiry=.. | days=N | .."
ensure_rule "omni-winother-10-cert-parc" <<'EOF'
rule "omni-winother-10-cert-parc"
when
  to_string($message.winlogbeat_winlog_channel) == "OMNI-Certificats"
then
  set_field("event_source", "cert_parc");
  set_field("event_category", "certificats");
  let m = to_string($message.message);
  let s = regex("subject=([^|]+)", m);
  set_field("cert_subject", s["0"]);
  let st = regex("store=([^|]+)", m);
  set_field("cert_store", st["0"]);
  let mc = regex("machine=([^|]+)", m);
  set_field("cert_machine", mc["0"]);
  let ex = regex("expiry=([0-9-]+)", m);
  set_field("cert_expiry", ex["0"]);
  let d = regex("days=([0-9]+)", m);
  set_field("cert_days", to_long(d["0"], 999));
  set_field("alert_tag", "cert_expire_parc");
end
EOF

# Veeam Backup & Replication : le canal "Veeam Backup" est collecte sur le
# serveur Veeam (ajout automatique par Install-OmniSiem-NinjaOne.ps1) et
# arrive dans ce stream via la regle d'exclusion. Normalisation + detection
# des jobs en echec/avertissement (level error/warning ou message "failed").
ensure_rule "omni-winother-10-veeam" <<'EOF'
rule "omni-winother-10-veeam"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup"
then
  set_field("event_source", "veeam");
  set_field("event_category", "sauvegarde");
end
EOF

# Echec REEL d'un job = resultat FINAL du job en echec ("...finished with
# Failed/Error", apres epuisement des retries). On NE tague PAS les echecs de
# TACHE par-VM transitoires (eid 450 "task has finished with 'Failed' state",
# ex. "Source restore point is locked by another job") que Veeam REESSAIE et
# reussit : sinon faux "backup echoue" alors que la sauvegarde a bien abouti.
ensure_rule "omni-winother-10-veeam-echec" <<'EOF'
rule "omni-winother-10-veeam-echec"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup"
  AND to_string($message.winlogbeat_winlog_event_id) == "190"
  AND ( contains(to_string($message.message), "finished with Failed", true)
     OR contains(to_string($message.message), "finished with Error", true) )
then
  set_field("alert_tag", "veeam_job_echec");
end
EOF

# Avertissement / echec transitoire reessaye : visibilite tableau de bord
# (alert_tag:veeam_job_warn), MAIS pas d'alerte mail. Exclut explicitement les
# vrais echecs de job (taggues par la regle echec ci-dessus) pour ne pas doubler.
ensure_rule "omni-winother-10-veeam-warn" <<'EOF'
rule "omni-winother-10-veeam-warn"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup"
  AND ( ( to_string($message.winlogbeat_winlog_event_id) == "450"
          AND contains(to_string($message.message), "'Failed'", true) )
     OR contains(to_string($message.message), "finished with Warning", true)
     OR contains(to_string($message.message), "is locked by another job", true) )
then
  set_field("alert_tag", "veeam_job_warn");
end
EOF

# ==========================================================================
echo "==> [4/6] Regles - FortiGate"
# ==========================================================================

ensure_rule "omni-forti-00-keyvalue" <<'EOF'
rule "omni-forti-00-keyvalue"
when
  has_field("message") AND contains(to_string($message.message), "devname=", false)
then
  set_fields(
    key_value(
      value: to_string($message.message),
      delimiters: " ",
      kv_delimiters: "=",
      ignore_empty_values: true,
      allow_dup_keys: true,
      handle_dup_keys: "take_first",
      trim_value_chars: "\""
    )
  );
  set_field("event_source", "fortigate");
end
EOF

# A.8.17 (synchro horaire) : poser le timestamp depuis eventtime (epoch nanosecondes)
# du FortiGate -> heure d'EVENEMENT exacte au lieu de l'heure de reception, et
# supprime ~14k erreurs "invalid timestamp" / jour.
ensure_rule "omni-forti-05-eventtime" <<'EOF'
rule "omni-forti-05-eventtime"
when
  to_string($message.event_source) == "fortigate" AND has_field("eventtime")
then
  set_field("timestamp", parse_unix_milliseconds(to_long($message.eventtime) / 1000000));
end
EOF

ensure_rule "omni-forti-05-renommage" <<'EOF'
rule "omni-forti-05-renommage"
when
  to_string($message.event_source) == "fortigate"
then
  // srcip/dstip parfois corrompus dans le flux FAZ (octets bruts) : on ne
  // copie que des valeurs en forme d'IP, sinon les agregations se polluent.
  let sip = regex("^([0-9a-fA-F:\\.]+)$", to_string($message.srcip));
  set_field("src_ip", sip["0"]);
  remove_field("srcip");
  let dip = regex("^([0-9a-fA-F:\\.]+)$", to_string($message.dstip));
  set_field("dest_ip", dip["0"]);
  remove_field("dstip");
  rename_field("srcport", "src_port");
  rename_field("dstport", "dest_port");
  rename_field("devname", "host");
  rename_field("dstcountry", "dest_country");
  rename_field("srccountry", "src_country");
end
EOF

# Octets/volumes : le parseur key_value rend sentbyte/rcvdbyte en CHAINES ->
# l'index les mappe en keyword -> sum()/avg() impossibles. On cree des champs
# NUMERIQUES dedies (mappes long des leur 1re occurrence) pour la bande passante.
# Vaut pour les nouveaux logs (l'historique reste en keyword).
ensure_rule "omni-forti-05-octets" <<'EOF'
rule "omni-forti-05-octets"
when
  to_string($message.event_source) == "fortigate" AND has_field("sentbyte")
then
  let bs = to_long($message.sentbyte, 0);
  let br = to_long($message.rcvdbyte, 0);
  let bt = bs + br;
  set_field("bytes_sent",  bs);
  set_field("bytes_rcvd",  br);
  set_field("bytes_total", bt);
  // Champs derives lisibles (Graylog OSS n'a pas d'unites de champ natives) :
  // on fige la conversion a l'ingestion. Go/To decimaux (1 Go = 1e9 octets) =
  // convention reseau, plus intuitive que le binaire pour un debit.
  // -> KPIs totaux en To, classements par hote/app en Go (unite adaptee au contexte).
  set_field("bytes_total_gb", to_double(bt) / 1000000000.0);
  set_field("bytes_sent_gb",  to_double(bs) / 1000000000.0);
  set_field("bytes_rcvd_gb",  to_double(br) / 1000000000.0);
  set_field("bytes_total_tb", to_double(bt) / 1000000000000.0);
end
EOF

# user="N/A" (logs traffic) ou user=<une IP> : valeurs parasites du FAZ qui
# polluent les tableaux "comptes vises" et les agregations par utilisateur.
# Le champ syslog "source" valait "logver=..." (1er token non-RFC) pour ~8M
# docs/jour -> inexploitable. host = devname renomme (ex: OMNITECH-BDX_FG120G) :
# on l'utilise comme source pour separer les logs par equipement FortiGate.
ensure_rule "omni-forti-06-source-host" <<'EOF'
rule "omni-forti-06-source-host"
when
  to_string($message.event_source) == "fortigate"
  AND has_field("host") AND to_string($message.host) != ""
then
  set_field("source", to_string($message.host));
end
EOF

# Enrichissement DHCP : src_ip/dest_ip INTERNE -> hostname via le lookup CSV
# alimente par omni-fortidhcp-fetch (baux FortiGate, rafraichi /15 min). Donne le
# nom de machine derriere une IP privee dans TOUT log FortiGate -> investigation
# directe ("qui se cache derriere 10.33.x.x"). cidr_match 10/8 = cout nul sur le
# trafic externe ; lookup_value rend null sur un miss -> set_field ne pose rien.
# IMPORTANT : place en stage 6 (avec source-host qui matche ~tout log fortigate)
# et NON dans un stage dedie : un "match either" sans aucune regle satisfaite STOPPE
# le pipeline (le trafic local-out externe->externe sauterait les stages 10/11 UTM/TI).
ensure_rule "omni-forti-06-dhcp-src" <<'EOF'
rule "omni-forti-06-dhcp-src"
when
  to_string($message.event_source) == "fortigate"
  AND has_field("src_ip")
  AND cidr_match("10.0.0.0/8", to_ip(to_string($message.src_ip), "0.0.0.0"))
then
  set_field("src_hostname", lookup_value("omni-dhcp-attribution", to_string($message.src_ip)));
end
EOF

ensure_rule "omni-forti-06-dhcp-dest" <<'EOF'
rule "omni-forti-06-dhcp-dest"
when
  to_string($message.event_source) == "fortigate"
  AND has_field("dest_ip")
  AND cidr_match("10.0.0.0/8", to_ip(to_string($message.dest_ip), "0.0.0.0"))
then
  set_field("dest_hostname", lookup_value("omni-dhcp-attribution", to_string($message.dest_ip)));
end
EOF

ensure_rule "omni-forti-06-nettoyage-user" <<'EOF'
rule "omni-forti-06-nettoyage-user"
when
  to_string($message.event_source) == "fortigate"
  AND (to_string($message.user) == "N/A"
    OR regex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", to_string($message.user)).matches == true)
then
  remove_field("user");
end
EOF

# Threat Intel (plugin Tor + Spamhaus DROP, active par 11) : lookup des IP
# PUBLIQUES uniquement (cidr_match exclut le RFC1918 = 0 cout sur le trafic interne).
# threat_intel_lookup_ip ajoute <prefix>_threat_indicated (bool) + listes matchees.
ensure_rule "omni-forti-10-threatintel-dest" <<'EOF'
rule "omni-forti-10-threatintel-dest"
when
  to_string($message.event_source) == "fortigate"
  AND has_field("dest_ip")
  AND NOT cidr_match("10.0.0.0/8",     to_ip(to_string($message.dest_ip), "0.0.0.0"))
  AND NOT cidr_match("192.168.0.0/16", to_ip(to_string($message.dest_ip), "0.0.0.0"))
  AND NOT cidr_match("172.16.0.0/12",  to_ip(to_string($message.dest_ip), "0.0.0.0"))
  AND NOT cidr_match("100.64.0.0/10",  to_ip(to_string($message.dest_ip), "0.0.0.0"))
  AND NOT cidr_match("169.254.0.0/16", to_ip(to_string($message.dest_ip), "0.0.0.0"))
  AND NOT cidr_match("0.0.0.0/32",     to_ip(to_string($message.dest_ip), "0.0.0.0"))
then
  set_fields(threat_intel_lookup_ip(to_string($message.dest_ip), "dest_ip"));
end
EOF

ensure_rule "omni-forti-10-threatintel-src" <<'EOF'
rule "omni-forti-10-threatintel-src"
when
  to_string($message.event_source) == "fortigate"
  AND has_field("src_ip")
  AND NOT cidr_match("10.0.0.0/8",     to_ip(to_string($message.src_ip), "0.0.0.0"))
  AND NOT cidr_match("192.168.0.0/16", to_ip(to_string($message.src_ip), "0.0.0.0"))
  AND NOT cidr_match("172.16.0.0/12",  to_ip(to_string($message.src_ip), "0.0.0.0"))
  AND NOT cidr_match("100.64.0.0/10",  to_ip(to_string($message.src_ip), "0.0.0.0"))
  AND NOT cidr_match("169.254.0.0/16", to_ip(to_string($message.src_ip), "0.0.0.0"))
  AND NOT cidr_match("0.0.0.0/32",     to_ip(to_string($message.src_ip), "0.0.0.0"))
then
  set_fields(threat_intel_lookup_ip(to_string($message.src_ip), "src_ip"));
end
EOF

ensure_rule "omni-forti-11-threatintel-tag" <<'EOF'
rule "omni-forti-11-threatintel-tag"
when
  to_bool($message.dest_ip_threat_indicated) == true
  OR to_bool($message.src_ip_threat_indicated) == true
then
  set_field("alert_tag", "threat_intel");
end
EOF

ensure_rule "omni-forti-10-utm" <<'EOF'
rule "omni-forti-10-utm"
when
  to_string($message.event_source) == "fortigate"
  AND (to_string($message.subtype) == "virus"
    OR to_string($message.subtype) == "ips"
    OR has_field("attack"))
then
  set_field("alert_tag", "fortigate_utm");
end
EOF

# ==========================================================================
echo "==> [5/6] Pipelines + connexions aux streams"
# ==========================================================================

PL_WINSEC="$(ensure_pipeline "OMNI - Windows Security" <<'EOF'
pipeline "OMNI - Windows Security"
stage 0 match either
rule "omni-winsec-00-normalisation"
rule "omni-winsec-00-user"
rule "omni-winsec-00-user-fallback"
rule "omni-winsec-00-srcip"
rule "omni-winsec-00-compteur-echec"
rule "omni-winsec-00-compteur-echec-service"
rule "omni-winsec-00-compteur-succes"
stage 5 match either
rule "omni-winsec-05-action"
rule "omni-winsec-05-logontype"
rule "omni-winsec-05-echec-logon"
rule "omni-winsec-05-echec-ntlm"
rule "omni-winsec-05-echec-kerberos"
rule "omni-winsec-05-groupe-privilegie"
stage 10 match either
rule "omni-winsec-10-sabotage-audit"
rule "omni-winsec-10-auditpol-humain"
rule "omni-winsec-10-dcsync"
rule "omni-winsec-10-kerberoasting"
rule "omni-winsec-10-partage-admin"
rule "omni-winsec-10-canary"
rule "omni-winsec-10-adcs"
end
EOF
)"

PL_SYSMON="$(ensure_pipeline "OMNI - Sysmon" <<'EOF'
pipeline "OMNI - Sysmon"
stage 0 match either
rule "omni-sysmon-00-normalisation"
rule "omni-sysmon-00-process"
rule "omni-sysmon-00-reseau"
rule "omni-sysmon-00-dns"
stage 5 match either
rule "omni-sysmon-05-action"
stage 10 match either
rule "omni-sysmon-10-ransomware"
rule "omni-sysmon-10-lsass-access"
rule "omni-sysmon-10-injection"
rule "omni-sysmon-10-powershell-suspect"
end
EOF
)"

PL_WINOTH="$(ensure_pipeline "OMNI - Windows autres" <<'EOF'
pipeline "OMNI - Windows autres"
stage 0 match either
rule "omni-winother-00-normalisation"
rule "omni-winother-00-inventory"
stage 5 match either
rule "omni-winother-05-action"
stage 10 match either
rule "omni-winother-10-defender"
rule "omni-winother-10-scriptblock-suspect"
rule "omni-winother-10-journal-systeme-efface"
rule "omni-winother-10-veeam"
rule "omni-winother-10-veeam-echec"
rule "omni-winother-10-veeam-warn"
rule "omni-winother-10-cert-parc"
end
EOF
)"

PL_FORTI="$(ensure_pipeline "OMNI - FortiGate" <<'EOF'
pipeline "OMNI - FortiGate"
stage 0 match either
rule "omni-forti-00-keyvalue"
stage 5 match either
rule "omni-forti-05-eventtime"
rule "omni-forti-05-renommage"
rule "omni-forti-05-octets"
rule "omni-forti-05-severity"
stage 6 match either
rule "omni-forti-06-nettoyage-user"
rule "omni-forti-06-source-host"
rule "omni-forti-06-dhcp-src"
rule "omni-forti-06-dhcp-dest"
stage 10 match either
rule "omni-forti-10-utm"
rule "omni-forti-10-threatintel-dest"
rule "omni-forti-10-threatintel-src"
stage 11 match either
rule "omni-forti-11-threatintel-tag"
end
EOF
)"

ST_WINSEC="$(get_stream_id 'OMNI - Windows Security')"
ST_SYSMON="$(get_stream_id 'OMNI - Sysmon')"
ST_WINOTH="$(get_stream_id 'OMNI - Windows autres')"
ST_FORTI="$(get_stream_id  'OMNI - FortiGate')"
[[ -n "${ST_WINSEC}" && -n "${ST_SYSMON}" && -n "${ST_WINOTH}" && -n "${ST_FORTI}" ]] \
  || die "streams OMNI introuvables (lancer 10-graylog-model.sh)"

connect_pipeline "${ST_WINSEC}" "${PL_WINSEC}"
connect_pipeline "${ST_SYSMON}" "${PL_SYSMON}"
connect_pipeline "${ST_WINOTH}" "${PL_WINOTH}"
connect_pipeline "${ST_FORTI}"  "${PL_FORTI}"

# ==========================================================================
echo "==> [6/6] Ordre des processeurs (Filter Chain -> Pipelines -> GeoIP)"
# ==========================================================================
CURRENT="$(api_get "/system/messageprocessors/config")"
NEW="$(echo "${CURRENT}" | jq '
  .processor_order as $o
  | ($o | map(select(.name != "GeoIP Resolver" and .name != "Pipeline Processor"))) as $base
  | ($o | map(select(.name == "Pipeline Processor"))) as $pp
  | ($o | map(select(.name == "GeoIP Resolver"))) as $geo
  | (if ($base | map(.name) | index("Stream Rule Processor")) != null
     then "Stream Rule Processor" else "Message Filter Chain" end) as $anchor
  | ($base | map(if .name == $anchor then [., $pp[0]] else [.] end)
     | flatten | map(select(. != null))) + $geo
  | {processor_order: ., disabled_processors: []}')"
if [[ "$(echo "${CURRENT}" | jq -c '.processor_order')" == "$(echo "${NEW}" | jq -c '.processor_order')" ]]; then
  skip "ordre deja correct"
else
  echo "${NEW}" | api_put "/system/messageprocessors/config" >/dev/null
  ok "ordre mis a jour"
fi
api_get "/system/messageprocessors/config" | jq -r '.processor_order[].name' | sed 's/^/      /'

echo
echo "=== 12-graylog-pipelines.sh termine. Lancer 13-graylog-alerts.sh ==="
