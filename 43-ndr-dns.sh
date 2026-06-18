#!/usr/bin/env bash
# =============================================================================
# 43-ndr-dns.sh - Active la detection d'exfiltration/tunneling DNS (omni-ndr-dns)
#   1. mappe dns_tunneling -> MITRE T1071.004 (DNS) dans le CSV (risk_score + ATT&CK)
#   2. route event_source=ndr_dns -> "OMNI - Interne SIEM" (+ exclusion M365)
#   3. timer systemd horaire + premier passage
# Idempotent. Prerequis : 21 (stream) + 37 (lookup MITRE). Relance 14 + 13 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
[[ -x /usr/local/sbin/omni-ndr-dns ]] || die "/usr/local/sbin/omni-ndr-dns absent."
require_api

# --- 1. Mapping MITRE dns_tunneling -----------------------------------------
echo "==> [1/3] Mapping MITRE (dns_tunneling -> T1071.004)"
CSV="lookups/mitre-attack.csv"
if grep -q '^dns_tunneling,' "${CSV}"; then skip "dns_tunneling deja dans le CSV"
else
  echo 'dns_tunneling,T1071.004,DNS,Command and Control,eleve,8' >> "${CSV}"
  ok "ligne dns_tunneling ajoutee au CSV"
fi
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "CSV deploye (adapter recharge sous 60s)"

# --- 2. Routage event_source=ndr_dns ----------------------------------------
echo "==> [2/3] Routage event_source=ndr_dns -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream interne introuvable (lancer 21)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "ndr_dns"; then skip "regle event_source=ndr_dns deja presente"
else
  jq -n '{field:"event_source", type:1, value:"ndr_dns", inverted:false, description:"ndr: tunneling DNS"}' \
    | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=ndr_dns ajoutee"
fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "ndr_dns"; then skip "M365 exclut deja ndr_dns"
  else
    jq -n '{field:"event_source", type:1, value:"ndr_dns", inverted:true, description:"exclusion ndr_dns (anti-dup)"}' \
      | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais ndr_dns"
  fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 3. Service + timer (horaire) + premier passage --------------------------
echo "==> [3/3] Service + timer (horaire) + premier passage"
cat > /etc/systemd/system/omni-ndr-dns.service <<'EOF'
[Unit]
Description=OMNI SIEM - detection exfiltration/tunneling DNS
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ndr-dns
Nice=15
EOF
cat > /etc/systemd/system/omni-ndr-dns.timer <<'EOF'
[Unit]
Description=OMNI SIEM - tunneling DNS (horaire)

[Timer]
OnCalendar=*-*-* *:42:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-ndr-dns.timer >/dev/null 2>&1 || true
systemctl start omni-ndr-dns.service && ok "$(journalctl -u omni-ndr-dns.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"

echo
echo "=== 43-ndr-dns.sh termine. Relancer 14 (widget) + 13 (alerte). ==="
