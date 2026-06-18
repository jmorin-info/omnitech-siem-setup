#!/usr/bin/env bash
# =============================================================================
# 39-collect-health.sh - Active la supervision de collecte (couverture SLA + go-dark)
#   1. route les resultats (event_source=collecte_sla) vers "OMNI - Interne SIEM"
#      et les EXCLUT de "OMNI - M365" (qui avale tout GELF -> anti double-comptage)
#   2. installe le timer systemd omni-collect-health (horaire)
#   3. premier passage immediat
#   Le generateur est /usr/local/sbin/omni-collect-health (derive le parc gere du
#   baseline 30j, calcule le silence par hote, renvoie en GELF).
# Idempotent. Prerequis : 21 (stream interne) + 12 (event_source). Relance 14 + 13.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
[[ -x /usr/local/sbin/omni-collect-health ]] || die "/usr/local/sbin/omni-collect-health absent."
require_api

# --- 1. Routage event_source=collecte_sla -----------------------------------
echo "==> [1/3] Routage event_source=collecte_sla -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream 'OMNI - Interne SIEM' introuvable (lancer 21 d'abord)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "collecte_sla"; then skip "regle event_source=collecte_sla deja presente"
else
  jq -n '{field:"event_source", type:1, value:"collecte_sla", inverted:false,
          description:"collect-health: supervision collecte"}' \
    | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=collecte_sla ajoutee"
fi

M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "collecte_sla"; then skip "M365 exclut deja event_source=collecte_sla"
  else
    jq -n '{field:"event_source", type:1, value:"collecte_sla", inverted:true,
            description:"exclusion collecte_sla (anti-dup)"}' \
      | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais event_source=collecte_sla"
  fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 2. Service + timer systemd (horaire) ------------------------------------
echo "==> [2/3] Service + timer systemd (horaire)"
cat > /etc/systemd/system/omni-collect-health.service <<'EOF'
[Unit]
Description=OMNI SIEM - supervision de collecte (couverture SLA + go-dark)
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-collect-health
Nice=10
EOF
cat > /etc/systemd/system/omni-collect-health.timer <<'EOF'
[Unit]
Description=OMNI SIEM - supervision de collecte horaire

[Timer]
OnCalendar=*-*-* *:07:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-collect-health.timer >/dev/null 2>&1 || true
ok "timer omni-collect-health actif (horaire, minute 07)"

# --- 3. Premier passage -------------------------------------------------------
echo "==> [3/3] Premier passage"
systemctl start omni-collect-health.service || warn "passage immediat KO (voir journalctl -u omni-collect-health)"
sleep 1
journalctl -u omni-collect-health.service -n 4 --no-pager 2>/dev/null | sed -n '1,4p' || true
systemctl list-timers omni-collect-health.timer --no-pager | sed -n '1,2p'

echo
echo "=== 39-collect-health.sh termine. Relancer 14 (page Sante collecte) + 13 (alerte go-dark). ==="
