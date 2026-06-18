#!/usr/bin/env bash
# 46-self-health.sh - Auto-supervision des robots d'analyse (omni-self-health).
#   Route event_source=siem_health -> INT (+ exclusion M365), timer 30 min.
set -euo pipefail
cd "$(dirname "$0")"; source ./00-vars.env; source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis."
[[ -x /usr/local/sbin/omni-self-health ]] || die "omni-self-health absent."
require_api

echo "==> [1/2] Routage event_source=siem_health -> INT (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"; [[ -n "${ST}" ]] || die "stream interne introuvable."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "siem_health"; then skip "regle siem_health deja la"
else jq -n '{field:"event_source",type:1,value:"siem_health",inverted:false,description:"auto-supervision"}' \
  | api_post "/streams/${ST}/rules" >/dev/null && ok "regle siem_health ajoutee"; fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "siem_health"; then skip "M365 exclut deja siem_health"
  else jq -n '{field:"event_source",type:1,value:"siem_health",inverted:true,description:"exclusion siem_health"}' \
    | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut siem_health"; fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [2/2] Service + timer (30 min) + premier passage"
cat > /etc/systemd/system/omni-self-health.service <<'EOF'
[Unit]
Description=OMNI SIEM - auto-supervision des robots d'analyse
After=graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-self-health
Nice=15
EOF
cat > /etc/systemd/system/omni-self-health.timer <<'EOF'
[Unit]
Description=OMNI SIEM - auto-supervision (30 min)
[Timer]
OnBootSec=300
OnUnitActiveSec=1800
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-self-health.timer >/dev/null 2>&1 || true
systemctl start omni-self-health.service && ok "$(journalctl -u omni-self-health.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"
echo "=== 46-self-health.sh termine. Relancer 14 + 13. ==="
