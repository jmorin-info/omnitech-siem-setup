#!/usr/bin/env bash
# =============================================================================
# 50-enrich-lot3.sh - Lot 3 (multi-agent) : 3 detections pipeline + 2 collecteurs.
#   Detections (pipeline dedie stage 10, connecte winsec) :
#     - gpp_creds_access  (T1552.006) : lecture creds GPP sur SYSVOL (5145)
#     - kerberos_rc4      (T1558.003) : TGS 4769 RC4 (0x17) sur compte a SPN
#     - local_admin_add   (T1098)     : ajout au groupe admin LOCAL (4732 S-1-5-32-544)
#     - local_account_create (T1136.001) : creation compte LOCAL (4720 hors DC)
#   Collecteurs (ecrits par les agents, deployes ici) :
#     - omni-ndr-exfil          (T1048) : exfiltration par volume (FortiGate)
#     - omni-ueba-geo-newcountry (T1078.004) : nouveau pays par compte (ueba_geo)
# Idempotent. Prerequis : 12 + 37. Relance 13 + 14 ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }
require_api
WD="winlogbeat_winlog_event_data"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }

echo "==> [1/5] Mappings MITRE (format corrige)"
add_mitre data_exfil          T1048     "Exfiltration Over Alternative Protocol"        Exfiltration       eleve 6
add_mitre gpp_creds_access    T1552.006 "Unsecured Credentials: Group Policy Preferences" "Credential Access" eleve 8
add_mitre kerberos_rc4        T1558.003 "Kerberoasting"                                 "Credential Access" eleve 7
add_mitre local_admin_add     T1098     "Account Manipulation"                          Persistence        eleve 7
add_mitre local_account_create T1136.001 "Create Account: Local Account"                Persistence        eleve 6
add_mitre new_country         T1078.004 "Valid Accounts: Cloud Accounts"               "Initial Access"    eleve 6
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/5] Regles de detection"
ensure_rule "omni-l3-10-gpp-creds" <<EOF
rule "omni-l3-10-gpp-creds"
when
  to_string(\$message.winlogbeat_winlog_event_id) == "5145"
  AND contains(lowercase(to_string(\$message.${WD}_ShareName)), "sysvol")
  AND ( contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "groups.xml")
     OR contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "scheduledtasks.xml")
     OR contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "services.xml")
     OR contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "datasources.xml") )
then
  set_field("alert_tag", "gpp_creds_access");
end
EOF

ensure_rule "omni-l3-10-kerberos-rc4" <<EOF
rule "omni-l3-10-kerberos-rc4"
when
  to_string(\$message.winlogbeat_winlog_event_id) == "4769"
  AND to_string(\$message.${WD}_TicketEncryptionType) == "0x17"
  AND NOT contains(to_string(\$message.${WD}_ServiceName), "\$")
  AND lowercase(to_string(\$message.${WD}_ServiceName)) != "krbtgt"
then
  set_field("alert_tag", "kerberos_rc4");
end
EOF

# Ajout au groupe Administrateurs LOCAL (builtin S-1-5-32-544). 4732 STRICT.
ensure_rule "omni-l3-10-local-admin-add" <<EOF
rule "omni-l3-10-local-admin-add"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_string(\$message.winlogbeat_winlog_event_id) == "4732"
  AND to_string(\$message.${WD}_TargetSid) == "S-1-5-32-544"
then
  set_field("alert_tag", "local_admin_add");
  set_field("event_category", "elevation_privilege");
end
EOF

# Creation de compte LOCAL (4720) hors DC (sur un DC = compte de domaine, deja couvert).
ensure_rule "omni-l3-10-local-account-create" <<EOF
rule "omni-l3-10-local-account-create"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4720
  AND NOT starts_with(lowercase(to_string(\$message.host)), "bx-ad-01")
  AND NOT starts_with(lowercase(to_string(\$message.host)), "bx-ad02")
then
  set_field("alert_tag", "local_account_create");
end
EOF

PL="$(ensure_pipeline "OMNI - Detections Lot3" <<'PIPE'
pipeline "OMNI - Detections Lot3"
stage 10 match either
rule "omni-l3-10-gpp-creds"
rule "omni-l3-10-kerberos-rc4"
rule "omni-l3-10-local-admin-add"
rule "omni-l3-10-local-account-create"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Windows Security')"
[[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream Windows Security absent"

echo "==> [3/5] Config exfil + routage ndr_exfil -> INT (+ exclusion M365)"
grep -q '^EXFIL_BYTES_GB=' 00-vars.env || cat >> 00-vars.env <<'VARS'

# --- omni-ndr-exfil : exfiltration par VOLUME (FortiGate bytes_sent) ---------
# EXFIL_WINDOW_M (min), EXFIL_BYTES_GB (seuil Go), EXFIL_TOP (couples examines),
# EXFIL_ALLOW_DEST (IP egress legitimes, ex egress HTTPS du SIEM), EXFIL_ALLOW_SRC.
EXFIL_WINDOW_M='60'
EXFIL_BYTES_GB='1'
EXFIL_TOP='50'
EXFIL_ALLOW_DEST='160.79.104.10'
EXFIL_ALLOW_SRC=''
VARS
chmod 600 00-vars.env
ST="$(get_stream_id 'OMNI - Interne SIEM')"
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
echo "${CUR}" | grep -qx "ndr_exfil" && skip "ndr_exfil deja route" || \
  { jq -n '{field:"event_source",type:1,value:"ndr_exfil",inverted:false,description:"exfil volume"}' | api_post "/streams/${ST}/rules" >/dev/null && ok "ndr_exfil route vers INT"; }
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  echo "${MEX}" | grep -qx "ndr_exfil" && skip "M365 exclut deja ndr_exfil" || \
    { jq -n '{field:"event_source",type:1,value:"ndr_exfil",inverted:true,description:"exclusion ndr_exfil"}' | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut ndr_exfil"; }
fi

echo "==> [4/5] Timers (exfil horaire ; new-country toutes les 2h)"
mk_timer() {  # nom desc oncalendar_ou_active
  cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=OMNI SIEM - $2
After=network-online.target graylog-server.service
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
Persistent=true
[Install]
WantedBy=timers.target
EOF
}
mk_timer omni-ndr-exfil "exfiltration par volume" "OnBootSec=300
OnUnitActiveSec=3600"
mk_timer omni-ueba-geo-newcountry "nouveau pays par compte" "OnCalendar=*-*-* *:23,53:00"
systemctl daemon-reload
systemctl enable --now omni-ndr-exfil.timer omni-ueba-geo-newcountry.timer >/dev/null 2>&1 || true

echo "==> [5/5] Premiers passages"
systemctl start omni-ndr-exfil.service && ok "$(journalctl -u omni-ndr-exfil -n1 --no-pager -o cat 2>/dev/null)" || warn "exfil KO"
systemctl start omni-ueba-geo-newcountry.service && ok "$(journalctl -u omni-ueba-geo-newcountry -n1 --no-pager -o cat 2>/dev/null)" || warn "new-country KO"
echo "=== 50-enrich-lot3.sh termine. Relancer 13 (alertes) + 14 (widgets/couleurs). ==="
