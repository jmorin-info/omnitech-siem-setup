#!/usr/bin/env bash
# =============================================================================
# 38-vuln-scan.sh - Active la detection de vulnerabilites (KEV + anciennete patch)
#   1. installe le timer systemd omni-vuln-scan (quotidien 07:15)
#   2. route les resultats (event_source=vuln / siem_vuln) vers le stream
#      "OMNI - Interne SIEM" (idempotent, via API)
#   Le generateur est /usr/local/sbin/omni-vuln-scan (lit l'inventaire pose par
#   Get-OmniInventory.ps1, croise CISA KEV, calcule l'anciennete des correctifs,
#   renvoie en GELF). Se remplit une fois le collecteur deploye sur le parc.
# Idempotent. Prerequis : inventaire (Get-OmniInventory) + 12 (parsing) + 21 (stream).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
[[ -x /usr/local/sbin/omni-vuln-scan ]] || die "/usr/local/sbin/omni-vuln-scan absent."
require_api

# --- 1. Routage des resultats vers le stream interne -------------------------
echo "==> [1/3] Routage event_source=vuln/siem_vuln -> 'OMNI - Interne SIEM'"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream 'OMNI - Interne SIEM' introuvable (lancer 21 d'abord)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
for V in vuln siem_vuln; do
  if echo "${CUR}" | grep -qx "${V}"; then skip "regle event_source=${V} deja presente"
  else
    jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:false,
        description:("vuln-scan: "+$v)}' \
      | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=${V} ajoutee"
  fi
done

# Anti-duplication : le stream M365 avale TOUT GELF (matching gl2_source_input).
# On en EXCLUT les resultats vuln (sinon ecrits dans 2 index sets -> double compte).
echo "==> [1bis] Exclusion vuln du stream 'OMNI - M365' (evite le double comptage)"
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  for V in vuln siem_vuln; do
    if echo "${MEX}" | grep -qx "${V}"; then skip "M365 exclut deja event_source=${V}"
    else
      jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:true,
          description:("exclusion vuln (anti-dup): "+$v)}' \
        | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais event_source=${V}"
    fi
  done
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 2. Service + timer systemd ----------------------------------------------
echo "==> [2/3] Service + timer systemd (quotidien 07:15)"
cat > /etc/systemd/system/omni-vuln-scan.service <<'EOF'
[Unit]
Description=OMNI SIEM - scan de vulnerabilites (KEV + anciennete correctifs)
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-vuln-scan
Nice=10
EOF
cat > /etc/systemd/system/omni-vuln-scan.timer <<'EOF'
[Unit]
Description=OMNI SIEM - scan de vulnerabilites quotidien

[Timer]
OnCalendar=*-*-* 07:15:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-vuln-scan.timer >/dev/null 2>&1 || true
ok "timer omni-vuln-scan actif"

# --- 3. Premier scan ----------------------------------------------------------
echo "==> [3/3] Premier scan (telecharge KEV ; 0 resultat tant que l'inventaire est vide)"
systemctl start omni-vuln-scan.service || warn "scan immediat KO (voir journalctl -u omni-vuln-scan)"
systemctl list-timers omni-vuln-scan.timer --no-pager | sed -n '1,2p'

echo
echo "=== 38-vuln-scan.sh termine. Deployer Get-OmniInventory.ps1 sur le parc"
echo "    (tache quotidienne SYSTEM) + canal OMNI-Inventaire dans winlogbeat.yml. ==="
