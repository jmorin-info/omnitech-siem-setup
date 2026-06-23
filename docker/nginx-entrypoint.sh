#!/bin/sh
# Genere un certificat auto-signe au 1er demarrage (remplacable par un vrai cert monte),
# puis lance nginx. Pour de la prod : monter un cert valide sur /etc/nginx/certs/.
set -e
CD=/etc/nginx/certs
if [ ! -f "$CD/omni.crt" ]; then
  command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl >/dev/null 2>&1
  mkdir -p "$CD"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$CD/omni.key" -out "$CD/omni.crt" \
    -subj "/CN=${SERVER_NAME:-omni-siem.local}" \
    -addext "subjectAltName=DNS:${SERVER_NAME:-omni-siem.local},DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi
exec nginx -g 'daemon off;'
