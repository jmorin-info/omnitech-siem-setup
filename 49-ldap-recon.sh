#!/usr/bin/env bash
# =============================================================================
# 49-ldap-recon.sh - Active la detection de reconnaissance LDAP / annuaire
#   (BloodHound / SharpHound) via le collecteur omni-ldap-recon.
#   1. mappe ldap_recon -> MITRE T1087.002 / T1069.002 (CSV)
#   2. route event_source=ldap_recon -> stream "OMNI - Interne SIEM" (+ excl M365)
#   3. timer 10 min + premier passage
# Idempotent. Prerequis : collecteur /usr/local/sbin/omni-ldap-recon en place,
#   21 (stream interne) + 37 (CSV MITRE). Relancer 13 (alerte) + 14 (widget).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
[[ -x /usr/local/sbin/omni-ldap-recon ]] || die "/usr/local/sbin/omni-ldap-recon absent."
require_api

echo "==> [1/3] Mapping MITRE (ldap_recon -> T1087.002 / T1069.002)"
CSV="lookups/mitre-attack.csv"
grep -q '^ldap_recon,' "${CSV}" || { echo 'ldap_recon,T1087.002,Account Discovery: Domain Account,Discovery,eleve,5' >> "${CSV}"; ok "MITRE +ldap_recon (T1087.002)"; }
grep -q '^ldap_recon_groups,' "${CSV}" || { echo 'ldap_recon_groups,T1069.002,Permission Groups Discovery: Domain Groups,Discovery,eleve,5' >> "${CSV}"; ok "MITRE +ldap_recon_groups (T1069.002)"; }
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/3] Routage event_source=ldap_recon -> INT (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"; [[ -n "${ST}" ]] || die "stream interne introuvable."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "ldap_recon"; then skip "regle ldap_recon deja la"
else jq -n '{field:"event_source",type:1,value:"ldap_recon",inverted:false,description:"reconnaissance LDAP (BloodHound/SharpHound)"}' \
  | api_post "/streams/${ST}/rules" >/dev/null && ok "regle ldap_recon ajoutee"; fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "ldap_recon"; then skip "M365 exclut deja ldap_recon"
  else jq -n '{field:"event_source",type:1,value:"ldap_recon",inverted:true,description:"exclusion ldap_recon (anti-dup)"}' \
    | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut ldap_recon"; fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [3/3] Service + timer (10 min) + premier passage"
cat > /etc/systemd/system/omni-ldap-recon.service <<'EOF'
[Unit]
Description=OMNI SIEM - detection reconnaissance LDAP (BloodHound/SharpHound)
After=network-online.target graylog-server.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ldap-recon
Nice=15
EOF
cat > /etc/systemd/system/omni-ldap-recon.timer <<'EOF'
[Unit]
Description=OMNI SIEM - reconnaissance LDAP (10 min)
[Timer]
OnBootSec=240
OnUnitActiveSec=600
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-ldap-recon.timer >/dev/null 2>&1 || true
systemctl start omni-ldap-recon.service && ok "$(journalctl -u omni-ldap-recon.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"
echo "=== 49-ldap-recon.sh termine. Relancer 13 (alerte) + 14 (widget/couleur). ==="
