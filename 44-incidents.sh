#!/usr/bin/env bash
# =============================================================================
# 44-incidents.sh - Active la correlation attack-chain -> incidents
#   1. route event_source=incident -> "OMNI - Interne SIEM" (+ exclusion M365)
#   2. timer systemd (toutes les 15 min) + premier passage
#   Le correlateur /usr/local/sbin/omni-incident-correlate agrege les detections
#   MITRE par entite et reconstruit la kill-chain. Pas de mapping MITRE (les
#   evenements incident portent incident_score, pas d'alert_tag).
# Idempotent. Prerequis : 21 + 37 (enrichissement MITRE). Relance 14 + 13 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
[[ -x /usr/local/sbin/omni-incident-correlate ]] || die "/usr/local/sbin/omni-incident-correlate absent."
require_api

echo "==> [1/2] Routage event_source=incident -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream interne introuvable (lancer 21)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "incident"; then skip "regle event_source=incident deja presente"
else
  jq -n '{field:"event_source", type:1, value:"incident", inverted:false, description:"correlation attack-chain"}' \
    | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=incident ajoutee"
fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "incident"; then skip "M365 exclut deja incident"
  else
    jq -n '{field:"event_source", type:1, value:"incident", inverted:true, description:"exclusion incident (anti-dup)"}' \
      | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais incident"
  fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [2/2] Service + timer (15 min) + premier passage"
cat > /etc/systemd/system/omni-incident-correlate.service <<'EOF'
[Unit]
Description=OMNI SIEM - correlation attack-chain (incidents)
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-incident-correlate
Nice=15
EOF
cat > /etc/systemd/system/omni-incident-correlate.timer <<'EOF'
[Unit]
Description=OMNI SIEM - correlation incidents (15 min)

[Timer]
OnBootSec=120
OnUnitActiveSec=900
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-incident-correlate.timer >/dev/null 2>&1 || true
systemctl start omni-incident-correlate.service && ok "$(journalctl -u omni-incident-correlate.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"

echo
echo "=== 44-incidents.sh termine. Relancer 14 (page Incidents) + 13 (alerte). ==="
