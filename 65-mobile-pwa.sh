#!/usr/bin/env bash
# =============================================================================
# 65-mobile-pwa.sh - PWA mobile SIEM OMNITECH (acces RSSI, VPN-only)
#   - Backend omni-mobile-api (mobile/omni-mobile-api.py) en venv : auth deleguee
#     a Graylog (AD/LDAPS), lecture OpenSearch (alertes/incidents/KPI), web-push.
#   - PWA statique (mobile/www) servie par nginx sous /m/ (installable iOS/Android).
#   - Cle VAPID, service systemd, route nginx, notification Graylog -> push critique.
#   Idempotent. Prerequis : 04/05 (Graylog+nginx) + 12/13 (detections/alertes).
#   RESTE COTE JULIEN : (1) ouvrir l'egress FortiGate du SIEM vers les serveurs
#   push (web.push.apple.com:443, fcm.googleapis.com:443) pour le web-push ;
#   (2) sur le tel (via VPN) : https://bx-it-graylog-vm.omnitech.security/m/ ->
#   Partager -> "Sur l'ecran d'accueil" -> ouvrir -> "Activer" les notifications.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
APP=/root/omnitech-siem-setup/mobile
WWW=/var/www/siem-mobile

echo "==> [1/7] venv + pywebpush"
python3 -m venv "${APP}/.venv" 2>/dev/null
"${APP}/.venv/bin/pip" install -q -U pip >/dev/null 2>&1
"${APP}/.venv/bin/pip" install -q pywebpush >/dev/null 2>&1 && ok "pywebpush installe" || warn "pip pywebpush : verifier l'egress PyPI"

echo "==> [2/7] Cles VAPID + secrets + /etc/default/omni-mobile"
mkdir -p /etc/omni-mobile /var/lib/omni-mobile
if [[ ! -f /etc/omni-mobile/vapid_private.pem ]]; then
  openssl ecparam -genkey -name prime256v1 -noout -out /etc/omni-mobile/vapid_private.pem 2>/dev/null
  chmod 600 /etc/omni-mobile/vapid_private.pem
fi
VAPID_PUB="$(openssl ec -in /etc/omni-mobile/vapid_private.pem -pubout -outform DER 2>/dev/null | tail -c 65 | base64 | tr -d '=\n' | tr '/+' '_-')"
if [[ ! -f /etc/default/omni-mobile ]]; then
  MS="$(openssl rand -hex 32)"; PS="$(openssl rand -hex 24)"
  cat > /etc/default/omni-mobile <<EOF
MOBILE_PORT=8090
OPENSEARCH=http://127.0.0.1:9200
GRAYLOG_API=https://${SIEM_FQDN}:9000/api
GRAYLOG_CACERT=/etc/graylog/certs/omnitech-rootca.crt
MOBILE_SECRET=${MS}
MOBILE_PUSH_SECRET=${PS}
VAPID_PUBLIC_KEY=${VAPID_PUB}
VAPID_PRIVATE_FILE=/etc/omni-mobile/vapid_private.pem
VAPID_SUBJECT=mailto:${ALERT_EMAIL:-informatique@omnitech-security.fr}
MOBILE_SUBS_FILE=/var/lib/omni-mobile/subscriptions.json
EOF
  chmod 600 /etc/default/omni-mobile; ok "env cree (secrets generes)"
else
  sed -i "s|^VAPID_PUBLIC_KEY=.*|VAPID_PUBLIC_KEY=${VAPID_PUB}|" /etc/default/omni-mobile
  skip "env existe (VAPID public resynchronise)"
fi
PUSH_SECRET="$(grep '^MOBILE_PUSH_SECRET=' /etc/default/omni-mobile | cut -d= -f2)"

echo "==> [3/7] Icones PWA (generation locale, fond sombre)"
"${APP}/.venv/bin/python" - <<'PY'
import zlib, struct
def png(size, path, rgb=(13,17,23)):
    raw = b"".join(b"\x00" + bytes(rgb)*size for _ in range(size))
    def chunk(t, d):
        c = t+d; return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    data = zlib.compress(raw, 9)
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", data) + chunk(b"IEND", b""))
for s, p in [(192,"/var/www/siem-mobile/icon-192.png"),(512,"/var/www/siem-mobile/icon-512.png"),(180,"/var/www/siem-mobile/icon-180.png")]:
    import os; os.makedirs("/var/www/siem-mobile", exist_ok=True); png(s, p)
print("icones ok")
PY

echo "==> [4/7] Deploiement de la PWA statique -> ${WWW}"
mkdir -p "${WWW}"
install -m 644 "${APP}/www/index.html" "${APP}/www/sw.js" "${APP}/www/manifest.json" "${WWW}/"
# Chart.js (graphes) - partage avec la console SOC ; telecharge si absent
CJS="${APP}/soc/chart.min.js"
[[ -s "$CJS" ]] || { mkdir -p "${APP}/soc"; curl -fsSL --max-time 25 "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" -o "$CJS" 2>/dev/null || true; }
[[ -s "$CJS" ]] && install -m 644 "$CJS" "${WWW}/chart.min.js" && ok "Chart.js dans /m/" || warn "Chart.js absent (graphes PWA off)"
chown -R www-data:www-data "${WWW}" 2>/dev/null || true
ok "PWA copiee"

echo "==> [5/7] Service systemd omni-mobile-api"
cat > /etc/systemd/system/omni-mobile-api.service <<EOF
[Unit]
Description=OMNI - Backend PWA mobile SIEM
After=network-online.target graylog-server.service opensearch.service
[Service]
EnvironmentFile=/etc/default/omni-mobile
ExecStart=${APP}/.venv/bin/python ${APP}/omni-mobile-api.py
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now omni-mobile-api.service >/dev/null 2>&1
sleep 1
systemctl is-active omni-mobile-api.service | grep -q active && ok "omni-mobile-api actif (127.0.0.1:8090)" || warn "service KO (journalctl -u omni-mobile-api)"

echo "==> [6/7] Route nginx /m/ (sauvegarde + nginx -t avant reload)"
NGX=/etc/nginx/sites-enabled/graylog
if grep -q 'location /m/' "$NGX"; then
  skip "route /m/ deja presente"
else
  cp "$NGX" "${NGX}.bak.$(date +%s 2>/dev/null || echo bak)"
  SNIP='    # PWA mobile SIEM (VPN-only)\n    location = /m/api/push { return 404; }\n    location /m/api/ {\n        proxy_pass http://127.0.0.1:8090;\n        proxy_set_header Host $host;\n        proxy_read_timeout 60s;\n    }\n    location /m/ {\n        alias /var/www/siem-mobile/;\n        try_files $uri $uri/ /m/index.html;\n        add_header Service-Worker-Allowed "/m/";\n    }\n'
  # insere avant le premier "location / {"
  awk -v snip="$SNIP" '!done && /location \/ \{/{printf snip; done=1} {print}' "$NGX" > "${NGX}.new" && mv "${NGX}.new" "$NGX"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx && ok "route /m/ ajoutee + nginx recharge"
  else
    mv "${NGX}.bak."* "$NGX" 2>/dev/null; warn "nginx -t ECHEC -> conf restauree (route NON ajoutee)"
  fi
fi

echo "==> [6b/7] Allowlist URL Graylog (sinon les notifications HTTP sont bloquees)"
BEAN="org.graylog2.system.urlallowlist.UrlAllowlist"
if ! api_get "/system/cluster_config/$BEAN" | jq -e '.entries[]?|select(.value|test("8090/m/api/push"))' >/dev/null 2>&1; then
  UUID="$(cat /proc/sys/kernel/random/uuid)"
  api_get "/system/cluster_config/$BEAN" \
    | jq --arg id "$UUID" '(.entries //= []) | .entries += [{id:$id,title:"OMNI mobile push",value:"^http://127\\.0\\.0\\.1:8090/m/api/push.*$",type:"regex"}]' \
    | api_put "/system/cluster_config/$BEAN" >/dev/null 2>&1 && ok "URL push allowlistee" || warn "allowlist KO"
else skip "URL push deja allowlistee"; fi

echo "==> [7/7] Notification Graylog 'OMNI - Mobile push' -> alertes critiques (P3)"
NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mobile push")|.id')"
if [[ -z "$NID" || "$NID" == "null" ]]; then
  NID="$(jq -n --arg u "http://127.0.0.1:8090/m/api/push?secret=${PUSH_SECRET}" \
    '{title:"OMNI - Mobile push", description:"Web-push PWA mobile (provisionne par 65-mobile-pwa.sh)",
      config:{type:"http-notification-v1", url:$u, api_key_as_header:false, api_key:"", api_secret:null, basic_auth:null, skip_tls_verification:true}}' \
    | post_entity "/events/notifications" | jqr '.id')"
  [[ -n "$NID" && "$NID" != "null" ]] && ok "notification push creee" || warn "notification push REFUSEE"
else skip "notification push existe"; fi
# Attache aux definitions critiques (priority 3)
ATT=0
for id in $(api_get "/events/definitions?per_page=300" | jq -r '.event_definitions[]?|select(.priority==3)|.id'); do
  DEF="$(api_get "/events/definitions/${id}")"
  echo "$DEF" | jq -e --arg n "$NID" '.notifications[]?|select(.notification_id==$n)' >/dev/null && continue
  echo "$DEF" | jq --arg n "$NID" 'del(._scope,.matched_at,.updated_at,.scheduler) | .notifications += [{notification_id:$n, notification_parameters:null}]' \
    | api_put "/events/definitions/${id}?schedule=true" >/dev/null 2>&1 && ATT=$((ATT+1))
done
ok "push attache a ${ATT} alertes critiques"

echo
echo "=== 65-mobile-pwa.sh termine. URL (via VPN) : https://${SIEM_FQDN}/m/"
echo "    RESTE COTE JULIEN : (1) egress FortiGate SIEM -> web.push.apple.com:443 +"
echo "    fcm.googleapis.com:443 (pour le web-push) ; (2) sur le tel : ouvrir /m/,"
echo "    Partager -> Sur l'ecran d'accueil -> ouvrir l'app -> bouton Activer. ==="
