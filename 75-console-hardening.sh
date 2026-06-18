#!/usr/bin/env bash
# =============================================================================
# 75-console-hardening.sh - Durcissement de la console/PWA (en-tetes securite)
#   - Snippet d'en-tetes de securite (CSP, X-Frame-Options, nosniff, Referrer,
#     HSTS) inclus dans les locations /m/ et /soc/.
#   - X-Real-IP transmis a l'API (/m/api/) pour le rate-limit login par IP.
#   (Le rate-limit login lui-meme est dans omni-mobile-api.py : 5 essais/15min.)
#   nginx -t avant reload + revert si echec. Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env 2>/dev/null || true
NGX=/etc/nginx/sites-enabled/graylog
SNIP=/etc/nginx/snippets/omni-sec-headers.conf
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

echo "==> [1/3] Snippet d'en-tetes de securite"
mkdir -p /etc/nginx/snippets
cat > "$SNIP" <<'EOF'
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Strict-Transport-Security "max-age=31536000" always;
EOF
echo "    snippet ecrit : $SNIP"

echo "==> [2/3] Insertion dans /m/ et /soc/ + X-Real-IP sur /m/api/"
if grep -q 'omni-sec-headers' "$NGX"; then
  echo "    [=] deja durci"
else
  cp "$NGX" "${NGX}.bak.hard"
  sed -i 's#\(add_header Service-Worker-Allowed "/m/";\)#\1\n        include snippets/omni-sec-headers.conf;#' "$NGX"
  sed -i 's#\(try_files \$uri \$uri/ /soc/index.html;\)#\1\n        include snippets/omni-sec-headers.conf;#' "$NGX"
  grep -q 'X-Real-IP' "$NGX" || sed -i 's#\(location /m/api/ {\)#\1\n        proxy_set_header X-Real-IP $remote_addr;#' "$NGX"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx && echo "    [+] en-tetes ajoutes + nginx recharge"
  else
    mv "${NGX}.bak.hard" "$NGX"; echo "    [!] nginx -t ECHEC -> conf restauree (rien change)"
  fi
fi

echo "==> [3/3] Verification des en-tetes"
for u in /m/ /soc/; do
  echo "  ${u} :"
  curl -skI "https://${SIEM_FQDN:-127.0.0.1}${u}" 2>/dev/null | grep -iE 'content-security-policy|x-frame-options|x-content-type|strict-transport|referrer-policy' | sed 's/^/    /'
done
echo
echo "=== 75 termine. Console durcie (CSP/HSTS/anti-clickjacking + rate-limit login). ==="
