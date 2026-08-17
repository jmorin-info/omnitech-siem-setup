#!/usr/bin/env bash
# =============================================================================
# 71-soc-console.sh - Console SOC web "OMNI SOC" (desktop, dark/cyber, VPN-only)
#   Reutilise le backend omni-mobile-api (auth Graylog + endpoints graphes ajoutes).
#   Frontend riche (mobile/soc) : KPI, area detections 24h, donut tactiques ATT&CK,
#   top detections/sources, feed incidents oms-xdr. Chart.js vendore localement.
#   Servi par nginx sous /soc/ ; API sous /m/api/ (deja proxifiee par 65).
#   Idempotent. Prerequis : 65 (backend + route nginx /m/api/).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
APP=/root/omnitech-siem-setup/mobile
WWW=/var/www/siem-soc

echo "==> [1/5] Redemarrage backend omni-mobile-api (nouveaux endpoints graphes)"
"${APP}/.venv/bin/python" -m py_compile "${APP}/omni-mobile-api.py" && ok "backend compile" || die "backend KO"
systemctl restart omni-mobile-api.service; sleep 1
systemctl is-active omni-mobile-api.service | grep -q active && ok "backend actif" || warn "backend KO (journalctl -u omni-mobile-api)"

echo "==> [2/5] Vendoring de Chart.js (local, pas de CDN au runtime)"
CJS="${APP}/soc/chart.min.js"
if [[ ! -s "$CJS" ]]; then
  for url in \
    "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" \
    "https://unpkg.com/chart.js@4.4.1/dist/chart.umd.min.js" \
    "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"; do
    if curl -fsSL --max-time 25 "$url" -o "$CJS" 2>/dev/null && [[ -s "$CJS" ]]; then
      ok "Chart.js telecharge ($(du -h "$CJS"|cut -f1)) depuis ${url%%/npm*}"; break
    fi
  done
  [[ -s "$CJS" ]] || warn "Chart.js NON telecharge (egress CDN ?) -> graphes absents, reste OK"
else skip "Chart.js deja vendore"; fi

echo "==> [3/5] Deploiement statique -> ${WWW}"
mkdir -p "${WWW}"
install -m 644 "${APP}/soc/index.html" "${WWW}/"
[[ -s "$CJS" ]] && install -m 644 "$CJS" "${WWW}/chart.min.js"
chown -R www-data:www-data "${WWW}" 2>/dev/null || true
ok "console deployee"

echo "==> [4/5] Route nginx /soc/ (sauvegarde + nginx -t + revert)"
NGX=/etc/nginx/sites-enabled/graylog
if grep -q 'location /soc/' "$NGX"; then
  skip "route /soc/ deja presente"
else
  mkdir -p /etc/nginx/archives && cp "$NGX" "/etc/nginx/archives/graylog.bak.soc"
  SNIP='    location /soc/ {\n        alias /var/www/siem-soc/;\n        try_files $uri $uri/ /soc/index.html;\n    }\n'
  awk -v snip="$SNIP" '!done && /location \/ \{/{printf snip; done=1} {print}' "$NGX" > "${NGX}.new" && mv "${NGX}.new" "$NGX"
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx && ok "route /soc/ ajoutee"
  else mv "${NGX}.bak.soc" "$NGX"; warn "nginx -t ECHEC -> conf restauree"; fi
fi

echo "==> [4bis] Rate-limiting (anti brute-force, console exposee toute source)"
# Zones dans conf.d (contexte http) + limit_req sur le login Graylog et /m/api/.
# Ajout 02/07/2026 : fail2ban ne couvre que SSH ; la console est en 80/443
# toute source depuis le 24/06 (decision RSSI). 429 au-dela des seuils.
cat > /etc/nginx/conf.d/omni-ratelimit.conf <<'RLEOF'
# Rate-limiting OMNI (02/07/2026) - console exposee 80/443 toute source depuis
# le 24/06 ; fail2ban ne couvre que SSH. Deux zones par IP source :
#   omni_auth : login Graylog (brute force) - 30 req/min, rafale 15
#   omni_api  : API PWA mobile (/m/api/)    - 5 req/s,    rafale 50
limit_req_zone $binary_remote_addr zone=omni_auth:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=omni_api:10m  rate=5r/s;
limit_req_status 429;
RLEOF
if grep -q 'omni_api' "$NGX"; then
  skip "limit_req deja en place"
else
  mkdir -p /etc/nginx/archives && cp "$NGX" "/etc/nginx/archives/graylog.bak.ratelimit"
  python3 - "$NGX" <<'PYRL'
import sys
p = sys.argv[1]; s = open(p).read()
s = s.replace("""    location /m/api/ {
        proxy_set_header X-Real-IP $remote_addr;""",
"""    location /m/api/ {
        limit_req zone=omni_api burst=50 nodelay;
        proxy_set_header X-Real-IP $remote_addr;""", 1)
s = s.replace("""    location / {
        proxy_pass https://127.0.0.1:9000;""",
"""    # Login Graylog : anti brute-force (POST /api/system/sessions)
    location = /api/system/sessions {
        limit_req zone=omni_auth burst=15 nodelay;
        proxy_pass https://127.0.0.1:9000;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/graylog/certs/omnitech-rootca.crt;
        proxy_ssl_server_name on;
        proxy_ssl_name bx-it-graylog-vm.omnitech.security;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Server $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Graylog-Server-URL https://$host/;
    }
    location / {
        proxy_pass https://127.0.0.1:9000;""", 1)
open(p, "w").write(s)
PYRL
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx && ok "rate-limit actif (auth 30r/m, api 5r/s)"
  else cp "/etc/nginx/archives/graylog.bak.ratelimit" "$NGX"; warn "nginx -t ECHEC -> conf restauree"; fi
fi

echo "==> [5/5] Tests"
echo -n "  /soc/ -> "; curl -sk -o /dev/null -w '%{http_code}\n' "https://${SIEM_FQDN}/soc/"
echo -n "  /soc/chart.min.js -> "; curl -sk -o /dev/null -w '%{http_code}\n' "https://${SIEM_FQDN}/soc/chart.min.js"
echo -n "  /m/api/timeseries (sans auth -> 401 attendu) -> "; curl -sk -o /dev/null -w '%{http_code}\n' "https://${SIEM_FQDN}/m/api/timeseries"
echo "  couche donnees graphes :"
"${APP}/.venv/bin/python" - <<'PY'
import importlib.util
s=importlib.util.spec_from_file_location("m","/root/omnitech-siem-setup/mobile/omni-mobile-api.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
print("   timeseries pts:",len(m.get_timeseries()),"| tactiques:",len(m.get_terms("mitre_tactic")),
      "| top-det:",len(m.get_terms("alert_tag")),"| sources:",len(m.get_terms("event_source")))
PY

echo
echo "=== 71 termine. Console SOC : https://${SIEM_FQDN}/soc/ (via VPN, login AD). ==="
