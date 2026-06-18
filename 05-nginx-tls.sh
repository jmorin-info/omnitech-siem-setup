#!/usr/bin/env bash
# ==============================================================================
# 05-nginx-tls.sh - Nginx reverse proxy TLS devant Graylog (127.0.0.1:9000)
#   - genere cle privee + CSR (SAN: FQDN + IP) a faire signer par la PKI interne
#     (Root CA OMNITECH SECURITY / BX-PKI2022) -> cf. README, section PKI
#   - installe un certificat auto-signe TEMPORAIRE pour demarrer tout de suite
#   - prepare aussi le certificat au format attendu par l'input Beats de
#     Graylog (cle convertie en PKCS#8, lisible par le user graylog)
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

SSLDIR="/etc/nginx/ssl"
GLCERTS="/etc/graylog/server/certs"
mkdir -p "${SSLDIR}" "${GLCERTS}"

echo "==> [1/4] Cle privee + CSR (a soumettre a BX-PKI2022)"
cat > "${SSLDIR}/openssl-san.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no
[dn]
C  = FR
O  = OMNITECH Security
CN = ${SIEM_FQDN}
[v3_req]
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt
[alt]
DNS.1 = ${SIEM_FQDN}
DNS.2 = ${SIEM_HOSTNAME}
IP.1  = ${SIEM_IP}
EOF
if [[ ! -f "${SSLDIR}/graylog.key" ]]; then
  openssl req -new -newkey rsa:4096 -nodes \
    -keyout "${SSLDIR}/graylog.key" -out "${SSLDIR}/graylog.csr" \
    -config "${SSLDIR}/openssl-san.cnf"
  chmod 600 "${SSLDIR}/graylog.key"
fi
echo "    CSR pret : ${SSLDIR}/graylog.csr  (procedure de signature -> README §PKI)"

echo "==> [2/4] Certificat auto-signe temporaire (a remplacer par le cert PKI)"
if [[ ! -f "${SSLDIR}/graylog.crt" ]]; then
  openssl x509 -req -in "${SSLDIR}/graylog.csr" -signkey "${SSLDIR}/graylog.key" \
    -days 365 -out "${SSLDIR}/graylog.crt" \
    -extfile "${SSLDIR}/openssl-san.cnf" -extensions v3_req
fi

echo "==> [3/4] Vhost Nginx"
apt-get install -y -qq nginx
cat > /etc/nginx/sites-available/graylog <<EOF
# Reverse proxy TLS -> Graylog (genere par 05-nginx-tls.sh)
server {
    listen 80;
    server_name ${SIEM_FQDN} ${SIEM_IP};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    http2 on;
    server_name ${SIEM_FQDN} ${SIEM_IP};

    ssl_certificate     ${SSLDIR}/graylog.crt;
    ssl_certificate_key ${SSLDIR}/graylog.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Server \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Graylog-Server-URL https://\$host/;
        proxy_read_timeout 300;
        client_max_body_size 100m;
    }
}
EOF
ln -sf /etc/nginx/sites-available/graylog /etc/nginx/sites-enabled/graylog
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx && systemctl reload nginx

echo "==> [4/4] Certificat pour l'input Beats (TLS sur 5044, cle en PKCS#8)"
# Le moteur Java de Graylog exige une cle privee au format PKCS#8.
openssl pkcs8 -topk8 -nocrypt -in "${SSLDIR}/graylog.key" \
  -out "${GLCERTS}/graylog-pkcs8.key"
cp -f "${SSLDIR}/graylog.crt" "${GLCERTS}/graylog.crt"
chown -R root:graylog "${GLCERTS}"
chmod 750 "${GLCERTS}"
chmod 640 "${GLCERTS}/graylog-pkcs8.key" "${GLCERTS}/graylog.crt"

echo
echo "=== 05-nginx-tls.sh termine. Console : https://${SIEM_FQDN}/ ==="
echo "    (Avertissement navigateur normal tant que le cert PKI n'est pas en place.)"
echo "    Apres signature PKI : remplacer graylog.crt, relancer ce script puis"
echo "    'systemctl reload nginx' et redemarrer l'input Beats dans Graylog."
echo "    Lancer ensuite 06-firewall.sh"
