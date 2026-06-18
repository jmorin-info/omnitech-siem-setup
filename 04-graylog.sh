#!/usr/bin/env bash
# ==============================================================================
# 04-graylog.sh - Graylog 7.1 (depot officiel)
#   - bind web/API en 127.0.0.1:9000 (Nginx fera le TLS devant)
#   - connexion MongoDB rs0 authentifiee + OpenSearch localhost
#   - journal disque (tampon si OpenSearch indisponible)
#   - SMTP interne pour les notifications d'alertes
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

GLCONF="/etc/graylog/server/server.conf"

# Petit utilitaire: fixe "cle = valeur" dans server.conf (decommente ou ajoute)
gl_set() {
  local key="$1"; local val="$2"
  if grep -qE "^#?\s*${key}\s*=" "${GLCONF}"; then
    sed -i -E "s|^#?\s*${key}\s*=.*|${key} = ${val}|" "${GLCONF}"
  else
    echo "${key} = ${val}" >> "${GLCONF}"
  fi
}

echo "==> [1/5] Depot + installation Graylog 7.1"
wget -q https://packages.graylog2.org/repo/packages/graylog-7.1-repository_latest.deb -O /tmp/graylog-repo.deb
dpkg -i /tmp/graylog-repo.deb >/dev/null
apt-get update -qq
apt-get install -y -qq graylog-server
systemctl stop graylog-server || true

echo "==> [2/5] Secrets"
SECRET_FILE="/root/.graylog_password_secret"
if [[ ! -s "${SECRET_FILE}" ]]; then
  openssl rand -hex 48 > "${SECRET_FILE}"
  chmod 600 "${SECRET_FILE}"
fi
PASSWORD_SECRET="$(cat "${SECRET_FILE}")"
ROOT_SHA2="$(printf '%s' "${GRAYLOG_ADMIN_PASS}" | sha256sum | cut -d' ' -f1)"

echo "==> [3/5] Configuration ${GLCONF}"
gl_set "is_leader" "true"
gl_set "password_secret" "${PASSWORD_SECRET}"
gl_set "root_password_sha2" "${ROOT_SHA2}"
gl_set "root_timezone" "Europe/Paris"
gl_set "root_email" "${SMTP_FROM}"
gl_set "http_bind_address" "127.0.0.1:9000"
gl_set "http_external_uri" "https://${SIEM_FQDN}/"
gl_set "elasticsearch_hosts" "http://127.0.0.1:9200"
# Necessaire aux requetes de detection (*lsass.exe, *1131f6a*) du script 10 :
gl_set "allow_leading_wildcard_searches" "true"
gl_set "mongodb_uri" "mongodb://graylog:${MONGO_GRAYLOG_PASS}@127.0.0.1:27017/graylog?replicaSet=rs0\&authSource=graylog"
gl_set "message_journal_enabled" "true"
gl_set "message_journal_max_size" "${JOURNAL_SIZE}"
# Journal sur le grand disque (sinon il remplit /var, qui ne fait que ~21 Go)
GL_JOURNAL="/var/lib/graylog-server/journal"
[[ -n "${DATA_MOUNT:-}" ]] && GL_JOURNAL="${DATA_MOUNT}/graylog-journal"
mkdir -p "${GL_JOURNAL}"
chown -R graylog:graylog "${GL_JOURNAL}"
gl_set "message_journal_dir" "${GL_JOURNAL}"
# Notifications par e-mail via le relais interne (anonyme, port 25, sans TLS)
gl_set "transport_email_enabled" "true"
gl_set "transport_email_hostname" "${SMTP_RELAY}"
gl_set "transport_email_port" "${SMTP_PORT}"
gl_set "transport_email_use_auth" "false"
gl_set "transport_email_use_tls" "false"
gl_set "transport_email_use_ssl" "false"
gl_set "transport_email_from_email" "${SMTP_FROM}"
gl_set "transport_email_subject_prefix" "[SIEM OMNITECH]"
chown root:graylog "${GLCONF}"; chmod 640 "${GLCONF}"

echo "==> [4/5] Heap JVM = ${GL_HEAP}"
sed -i -E "s/-Xms[0-9]+[gm]/-Xms${GL_HEAP}/; s/-Xmx[0-9]+[gm]/-Xmx${GL_HEAP}/" \
  /etc/default/graylog-server
grep GRAYLOG_SERVER_JAVA_OPTS /etc/default/graylog-server | head -1

echo "==> [5/5] Demarrage et attente de l'API (1er demarrage = migrations, patience)"
systemctl enable --now graylog-server
OK=0
for i in $(seq 1 60); do
  if curl -s http://127.0.0.1:9000/api/system/lbstatus | grep -q ALIVE; then OK=1; break; fi
  sleep 5
done
if [[ "${OK}" == "1" ]]; then
  echo "    API Graylog: ALIVE"
  curl -s -u "admin:${GRAYLOG_ADMIN_PASS}" http://127.0.0.1:9000/api/system \
    | jq '{version:.version, hostname:.hostname}' || true
else
  echo "ERREUR: API injoignable. Voir /var/log/graylog-server/server.log"; exit 1
fi

echo
echo "=== 04-graylog.sh termine. Lancer 05-nginx-tls.sh ==="
echo "    Connexion future : https://${SIEM_FQDN}/  (admin / mot de passe du vars.env)"
