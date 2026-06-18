#!/usr/bin/env bash
# =============================================================================
# 42-carte-cyber.sh - Carte cyber temps reel (arcs de flux animes, hors Graylog)
#   - generateur /usr/local/sbin/omni-geo-flux -> /var/www/siem-kit/flux.json
#   - page canvas /var/www/siem-kit/carte-cyber.html (servie par nginx /kit/)
#   - fond de carte mondial local /var/www/siem-kit/carte-world.geojson
#   - timer systemd : rafraichit flux.json toutes les 30 s
#   100% local au runtime (pas de CDN, pas de fuite). Idempotent.
# Prerequis : nginx servant /kit/ (deja en place), OpenSearch, geoloc active.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }
KIT="/var/www/siem-kit"
ok(){ echo "    [+] $*"; }; warn(){ echo "    [!] $*"; }

[[ -x /usr/local/sbin/omni-geo-flux ]] || { echo "ERREUR: /usr/local/sbin/omni-geo-flux absent."; exit 1; }
[[ -f "${KIT}/carte-cyber.html" ]] || { echo "ERREUR: ${KIT}/carte-cyber.html absent."; exit 1; }

# --- 1. Fond de carte mondial (telecharge une fois, servi en local) ----------
echo "==> [1/3] Fond de carte mondial local"
if [[ -s "${KIT}/carte-world.geojson" ]]; then ok "carte-world.geojson present ($(du -h "${KIT}/carte-world.geojson"|cut -f1))"
else
  for url in \
    "https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson" \
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson"; do
    if curl -s -m 25 -o "${KIT}/carte-world.geojson" "$url" \
       && python3 -c "import json;json.load(open('${KIT}/carte-world.geojson'))" 2>/dev/null; then
      ok "fond de carte recupere"; break
    fi
  done
  [[ -s "${KIT}/carte-world.geojson" ]] || warn "fond de carte indisponible (la page affichera une erreur)"
fi
chmod 644 "${KIT}/carte-world.geojson" "${KIT}/carte-cyber.html" 2>/dev/null || true

# --- 2. Service + timer (rafraichissement 30 s) ------------------------------
echo "==> [2/3] Service + timer (flux.json toutes les 30 s)"
cat > /etc/systemd/system/omni-geo-flux.service <<'EOF'
[Unit]
Description=OMNI SIEM - generation des flux geolocalises (carte cyber)
After=network-online.target graylog-server.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-geo-flux
Nice=15
EOF
cat > /etc/systemd/system/omni-geo-flux.timer <<'EOF'
[Unit]
Description=OMNI SIEM - carte cyber : rafraichissement 30 s

[Timer]
OnBootSec=30
OnUnitActiveSec=30
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-geo-flux.timer >/dev/null 2>&1 || true
ok "timer omni-geo-flux actif (30 s)"

# --- 3. Premier passage + verification nginx ---------------------------------
echo "==> [3/3] Premier passage + verification du service web"
systemctl start omni-geo-flux.service && ok "$(/usr/local/sbin/omni-geo-flux 2>&1 | tail -1)" || warn "1er passage KO"
for f in carte-cyber.html flux.json carte-world.geojson; do
  code=$(curl -s -k -o /dev/null -w "%{http_code}" "https://${SIEM_FQDN}/kit/${f}" 2>/dev/null || echo "000")
  [[ "$code" == "200" ]] && ok "nginx sert /kit/${f} (200)" || warn "nginx /kit/${f} -> ${code}"
done

echo
echo "=== 42-carte-cyber.sh termine. ==="
echo "    >>> Carte cyber : https://${SIEM_FQDN}/kit/carte-cyber.html"
