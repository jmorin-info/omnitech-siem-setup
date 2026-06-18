#!/usr/bin/env bash
# =============================================================================
# 48-ndr-scan.sh - Active la detection de scan reseau interne (omni-ndr-scan)
#   1. mappe network_scan -> MITRE T1046 (CSV 37)
#   2. route event_source=ndr_scan -> INT (+ exclusion M365)
#   3. timer 15 min + premier passage
# Idempotent. Prerequis : 21 + 37. Relance 13 + 14 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
[[ -x /usr/local/sbin/omni-ndr-scan ]] || die "/usr/local/sbin/omni-ndr-scan absent."
require_api

echo "==> [1/3] Mapping MITRE (network_scan -> T1046)"
CSV="lookups/mitre-attack.csv"
grep -q '^network_scan,' "${CSV}" || { echo 'network_scan,T1046,Network Service Discovery,Discovery,eleve,5' >> "${CSV}"; ok "MITRE +network_scan"; }
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/3] Routage event_source=ndr_scan -> INT (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"; [[ -n "${ST}" ]] || die "stream interne introuvable."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "ndr_scan"; then skip "regle ndr_scan deja la"
else jq -n '{field:"event_source",type:1,value:"ndr_scan",inverted:false,description:"detection scan reseau"}' \
  | api_post "/streams/${ST}/rules" >/dev/null && ok "regle ndr_scan ajoutee"; fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "ndr_scan"; then skip "M365 exclut deja ndr_scan"
  else jq -n '{field:"event_source",type:1,value:"ndr_scan",inverted:true,description:"exclusion ndr_scan (anti-dup)"}' \
    | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut ndr_scan"; fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [3/3] Service + timer (15 min) + premier passage"
cat > /etc/systemd/system/omni-ndr-scan.service <<'EOF'
[Unit]
Description=OMNI SIEM - detection de scan reseau interne
After=network-online.target graylog-server.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ndr-scan
Nice=15
EOF
cat > /etc/systemd/system/omni-ndr-scan.timer <<'EOF'
[Unit]
Description=OMNI SIEM - scan reseau (15 min)
[Timer]
OnBootSec=180
OnUnitActiveSec=900
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-ndr-scan.timer >/dev/null 2>&1 || true
systemctl start omni-ndr-scan.service && ok "$(journalctl -u omni-ndr-scan.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"
echo "=== 48-ndr-scan.sh termine. Relancer 13 (alerte) + 14 (widget/couleur). ==="
