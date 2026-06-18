#!/usr/bin/env bash
# =============================================================================
# 51-enrich-lot4.sh - Lot 4 (multi-agent) : 3 detections pipeline + 2 collecteurs.
#   Pipeline "OMNI - Detections Lot4" :
#     - stage 10 : wmi_lateral_exec (T1047, sysmon), shadow_credentials (T1556.005, winsec 5136)
#     - stage 11 : adcs_abuse ESC1/ESC8 (T1649, APRES adcs base de stage 10 qui pose event_source)
#   Collecteurs (ecrits par les agents) :
#     - omni-ldap-recon  (T1087.002) : enumeration LDAP/annuaire de masse (4662)
#     - omni-ndr-lateral (T1021)     : 1 compte -> N hotes en connexions reussies
# Idempotent. Prerequis : 12 + 37. Relance 13 + 14 ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }
require_api
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }

echo "==> [1/5] Mappings MITRE (format corrige)"
add_mitre adcs_abuse        T1649     "Steal or Forge Authentication Certificates" "Credential Access" critique 9
add_mitre wmi_lateral_exec  T1047     "Windows Management Instrumentation"         "Lateral Movement"  eleve    8
add_mitre shadow_credentials T1556.005 "Modify Authentication Process"             "Credential Access" critique 9
add_mitre ldap_recon        T1087.002 "Account Discovery: Domain Account"          Discovery           moyen    4
add_mitre lateral_movement  T1021     "Remote Services"                            "Lateral Movement"  eleve    7
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/5] Regles de detection"
ensure_rule "omni-l4-10-wmi-lateral" <<'EOF'
rule "omni-l4-10-wmi-lateral"
when
  to_string($message.event_source) == "sysmon"
  AND (
    ( to_string($message.winlogbeat_winlog_event_id) == "1"
      AND contains(lowercase(to_string($message.parent_process)), "wmiprvse")
      AND ( lowercase(to_string($message.process_name)) == "cmd.exe"
         OR lowercase(to_string($message.process_name)) == "powershell.exe"
         OR lowercase(to_string($message.process_name)) == "pwsh.exe"
         OR lowercase(to_string($message.process_name)) == "wscript.exe"
         OR lowercase(to_string($message.process_name)) == "cscript.exe"
         OR lowercase(to_string($message.process_name)) == "mshta.exe"
         OR lowercase(to_string($message.process_name)) == "rundll32.exe"
         OR lowercase(to_string($message.process_name)) == "regsvr32.exe"
         OR lowercase(to_string($message.process_name)) == "certutil.exe" ) )
    OR to_string($message.winlogbeat_winlog_event_id) == "19"
    OR to_string($message.winlogbeat_winlog_event_id) == "20"
    OR to_string($message.winlogbeat_winlog_event_id) == "21"
  )
  AND lowercase(to_string($message.process_name)) != "ccmexec.exe"
  AND lowercase(to_string($message.process_name)) != "monitoringhost.exe"
  AND lowercase(to_string($message.process_name)) != "mofcomp.exe"
then
  set_field("alert_tag", "wmi_lateral_exec");
  set_field("event_category", "lateral_movement");
end
EOF

ensure_rule "omni-l4-10-shadow-credentials" <<'EOF'
rule "omni-l4-10-shadow-credentials"
when
  to_string($message.winlogbeat_winlog_event_id) == "5136"
  AND lowercase(to_string($message.winlogbeat_winlog_event_data_AttributeLDAPDisplayName)) == "msds-keycredentiallink"
  AND to_string($message.winlogbeat_winlog_event_data_SubjectUserSid) != "S-1-5-18"
then
  set_field("alert_tag", "shadow_credentials");
  set_field("event_category", "persistance_identite");
end
EOF

# ESC1/ESC8 au stage 11 : event_source=adcs est pose au stage 10 par la regle de
# base omni-winsec-10-adcs (12). Scope strict event_source==adcs (evite les faux
# positifs FortiGate VoIP qui portent un champ event_id=4887/4889 parasite).
ensure_rule "omni-l4-11-adcs-esc1" <<'EOF'
rule "omni-l4-11-adcs-esc1"
when
  to_string($message.event_source) == "adcs"
  AND ( to_string($message.winlogbeat_winlog_event_id) == "4886"
     OR to_string($message.winlogbeat_winlog_event_id) == "4887" )
  AND has_field("message")
  AND NOT contains(lowercase(to_string($message.message)), lowercase("de CSR :\n\nNom demand"))
  AND contains(to_string($message.message), "@")
then
  set_field("alert_tag", "adcs_abuse");
  set_field("adcs_technique", "ESC1");
  set_field("event_category", "abus_pki");
end
EOF

ensure_rule "omni-l4-11-adcs-esc8" <<'EOF'
rule "omni-l4-11-adcs-esc8"
when
  to_string($message.event_source) == "adcs"
  AND lowercase(to_string($message.winlogbeat_winlog_event_data_AuthenticationService)) == "ntlm"
then
  set_field("alert_tag", "adcs_abuse");
  set_field("adcs_technique", "ESC8");
  set_field("event_category", "abus_pki");
end
EOF

PL="$(ensure_pipeline "OMNI - Detections Lot4" <<'PIPE'
pipeline "OMNI - Detections Lot4"
stage 10 match either
rule "omni-l4-10-wmi-lateral"
rule "omni-l4-10-shadow-credentials"
stage 11 match either
rule "omni-l4-11-adcs-esc1"
rule "omni-l4-11-adcs-esc8"
end
PIPE
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done

echo "==> [3/5] Routage collecteurs (ldap_recon, ndr_lateral) -> INT (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
M365="$(get_stream_id 'OMNI - M365')"
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
for V in ldap_recon ndr_lateral; do
  echo "${CUR}" | grep -qx "$V" && skip "$V deja route" || \
    { jq -n --arg v "$V" '{field:"event_source",type:1,value:$v,inverted:false,description:("detection "+$v)}' | api_post "/streams/${ST}/rules" >/dev/null && ok "$V route vers INT"; }
  if [[ -n "${M365}" ]]; then
    echo "${MEX}" | grep -qx "$V" && skip "M365 exclut deja $V" || \
      { jq -n --arg v "$V" '{field:"event_source",type:1,value:$v,inverted:true,description:("exclusion "+$v)}' | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut $V"; }
  fi
done

echo "==> [4/5] Timers (ldap-recon 15min ; lateral 30min)"
mk(){ cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=OMNI SIEM - $2
After=graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/$1
Nice=15
EOF
cat > "/etc/systemd/system/$1.timer" <<EOF
[Unit]
Description=OMNI SIEM - $2 (timer)
[Timer]
$3
[Install]
WantedBy=timers.target
EOF
}
mk omni-ldap-recon "reconnaissance LDAP" "OnBootSec=240
OnUnitActiveSec=900"
mk omni-ndr-lateral "mouvement lateral reussi" "OnBootSec=300
OnUnitActiveSec=1800"
systemctl daemon-reload
systemctl enable --now omni-ldap-recon.timer omni-ndr-lateral.timer >/dev/null 2>&1 || true

echo "==> [5/5] Premiers passages"
systemctl start omni-ldap-recon.service && ok "$(journalctl -u omni-ldap-recon -n1 --no-pager -o cat 2>/dev/null)" || warn "ldap-recon KO"
systemctl start omni-ndr-lateral.service && ok "$(journalctl -u omni-ndr-lateral -n1 --no-pager -o cat 2>/dev/null)" || warn "lateral KO"
echo "=== 51-enrich-lot4.sh termine. Relancer 13 (alertes) + 14 (couleurs/widgets). ==="
