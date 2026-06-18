#!/usr/bin/env bash
# ==============================================================================
# 07-inputs.sh - Creation des inputs Graylog via l'API REST
#   - Beats TCP 5044 (TLS)        : Winlogbeat des postes/serveurs Windows
#   - Syslog TCP/UDP 1514         : forwarding FortiAnalyzer
#   (le CEF 5555 se cree en 2 clics dans l'UI si tu choisis le format CEF
#    cote FAZ : System > Inputs > CEF TCP, port 5555)
#
# Si un appel echoue (schema de champs different selon version), creer l'input
# equivalent via l'interface : System > Inputs. Le script est idempotent
# (il ne recree pas un input portant le meme titre).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

API="https://${SIEM_FQDN}:9000/api"
CURL=(curl -s --cacert /etc/graylog/certs/omnitech-rootca.crt -u "admin:${GRAYLOG_ADMIN_PASS}" -H "Content-Type: application/json" -H "X-Requested-By: 07-inputs.sh")

input_exists() {  # $1 = titre
  "${CURL[@]}" "${API}/system/inputs" | jq -e --arg t "$1" '.inputs[] | select(.title == $t)' >/dev/null 2>&1
}

create_input() {  # $1 = titre, $2 = JSON
  if input_exists "$1"; then echo "    [=] '$1' existe deja."; return; fi
  RES="$("${CURL[@]}" -X POST "${API}/system/inputs" -d "$2")"
  if echo "${RES}" | jq -e .id >/dev/null 2>&1; then
    echo "    [+] '$1' cree (id $(echo "${RES}" | jq -r .id))."
  else
    echo "    [!] Echec creation '$1' -> creer via l'UI. Reponse API :"
    echo "${RES}" | sed 's/^/        /'
  fi
}

echo "==> Input Beats 5044 (TLS) - Winlogbeat"
create_input "Winlogbeat (Beats TLS 5044)" "$(cat <<EOF
{
  "title": "Winlogbeat (Beats TLS 5044)",
  "type": "org.graylog.plugins.beats.Beats2Input",
  "global": true,
  "configuration": {
    "bind_address": "0.0.0.0",
    "port": 5044,
    "recv_buffer_size": 1048576,
    "no_beats_prefix": false,
    "tls_enable": true,
    "tls_cert_file": "/etc/graylog/server/certs/graylog.crt",
    "tls_key_file": "/etc/graylog/server/certs/graylog-pkcs8.key",
    "tls_key_password": "",
    "tls_client_auth": "disabled",
    "tls_client_auth_cert_file": ""
  }
}
EOF
)"

echo "==> Input Syslog TCP 1514 - FortiAnalyzer"
create_input "FortiAnalyzer (Syslog TCP 1514)" "$(cat <<EOF
{
  "title": "FortiAnalyzer (Syslog TCP 1514)",
  "type": "org.graylog2.inputs.syslog.tcp.SyslogTCPInput",
  "global": true,
  "configuration": {
    "bind_address": "0.0.0.0",
    "port": 1514,
    "recv_buffer_size": 1048576,
    "allow_override_date": true,
    "expand_structured_data": false,
    "force_rdns": false,
    "store_full_message": false,
    "use_null_delimiter": false
  }
}
EOF
)"

echo "==> Input Syslog UDP 1514 - FortiAnalyzer (secours/equipements legers)"
create_input "FortiAnalyzer (Syslog UDP 1514)" "$(cat <<EOF
{
  "title": "FortiAnalyzer (Syslog UDP 1514)",
  "type": "org.graylog2.inputs.syslog.udp.SyslogUDPInput",
  "global": true,
  "configuration": {
    "bind_address": "0.0.0.0",
    "port": 1514,
    "recv_buffer_size": 1048576,
    "allow_override_date": true,
    "expand_structured_data": false,
    "force_rdns": false,
    "store_full_message": false
  }
}
EOF
)"

echo
echo "==> Etat des inputs :"
"${CURL[@]}" "${API}/system/inputs" | jq -r '.inputs[] | "    - \(.title)  [\(.type)]"'
echo
echo "=== 07-inputs.sh termine. Lancer 08-backup.sh ==="
