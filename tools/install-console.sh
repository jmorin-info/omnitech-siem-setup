#!/usr/bin/env bash
# Install the console on an existing local Graylog/OpenSearch/nginx host.
# No Graylog configuration or alert notifications are changed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root." >&2; exit 1; }
for c in python3 nginx systemctl curl openssl; do
  command -v "$c" >/dev/null || { echo "Missing prerequisite: $c" >&2; exit 1; }
done
SITE="${NGINX_SITE:-/etc/nginx/sites-enabled/graylog}"
python3 "$ROOT/tools/deploy-console.py" --site "$SITE"
[[ "${1:-}" == "--apply" ]] || { echo "Plan only. Use --apply to install."; exit 0; }
umask 022
FRESH_BACKEND=0

if ! systemctl cat omni-mobile-api.service >/dev/null 2>&1; then
  APP=/opt/omni-siem/console
  STATE=/var/lib/omni-mobile
  getent passwd omni-console >/dev/null || useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin omni-console
  install -d -m 755 "$APP" /etc/omni-mobile
  install -d -o omni-console -g omni-console -m 750 "$STATE"
  install -m 644 "$ROOT/mobile/omni-mobile-api.py" "$APP/omni-mobile-api.py"
  install -d -m 755 "$APP/tools"
  install -m 644 "$ROOT/tools/omni-soc-kpi.py" "$APP/tools/omni-soc-kpi.py"
  install -d -m 755 "$APP/lookups"
  install -m 644 "$ROOT/lookups/mitre-attack.csv" "$APP/lookups/mitre-attack.csv"
  if [[ ! -f /etc/default/omni-mobile ]]; then
    API=http://127.0.0.1:9000/api
    CA="${GRAYLOG_API_CA:-/etc/graylog/certs/omnitech-rootca.crt}"
    if grep -Eq '^http_enable_tls[[:space:]]*=[[:space:]]*true' /etc/graylog/server/server.conf; then
      [[ -n "${SIEM_FQDN:-}" && -r "$CA" ]] || { echo "TLS API requires SIEM_FQDN and readable GRAYLOG_API_CA." >&2; exit 1; }
      API="https://${SIEM_FQDN}:9000/api"
      install -o root -g omni-console -m 640 "$CA" /etc/omni-mobile/graylog-ca.crt
    fi
    umask 027
    cat > /etc/default/omni-mobile <<EOF
MOBILE_BIND=127.0.0.1
MOBILE_PORT=8090
OPENSEARCH=http://127.0.0.1:9200
GRAYLOG_API=${API}
GRAYLOG_CACERT=/etc/omni-mobile/graylog-ca.crt
MOBILE_SECRET=$(openssl rand -hex 32)
MOBILE_PUSH_SECRET=$(openssl rand -hex 32)
MOBILE_SUBS_FILE=${STATE}/subscriptions.json
MOBILE_CASES_FILE=${STATE}/cases.json
MOBILE_WATCH_FILE=${STATE}/watchlist.json
MITRE_LOOKUP=${APP}/lookups/mitre-attack.csv
OMNI_REPO_DIR=${ROOT}
SOC_KPI_TOOL=${APP}/tools/omni-soc-kpi.py
SOC_ORIGINS=${SOC_ORIGINS:-${SIEM_FQDN:-localhost}${SIEM_IP:+,$SIEM_IP}}
SIEM_FQDN=${SIEM_FQDN:-}
SIEM_IP=${SIEM_IP:-}
SOC_LOG_INDICES=${SOC_LOG_INDICES:-omni-*,graylog_*}
SOC_EXPECTED_SOURCES=${SOC_EXPECTED_SOURCES:-}
SOC_ADMINS=${SOC_ADMINS:-}
EOF
    chown root:omni-console /etc/default/omni-mobile
    chmod 640 /etc/default/omni-mobile
  else
    echo "Existing console configuration retained; verify its API URL and file paths."
    chgrp omni-console /etc/default/omni-mobile
    chmod 640 /etc/default/omni-mobile
  fi
  cat > /etc/systemd/system/omni-mobile-api.service <<EOF
[Unit]
Description=OMNI SOC console backend
After=network-online.target graylog-server.service opensearch.service
[Service]
User=omni-console
Group=omni-console
ExecStart=/usr/bin/python3 ${APP}/omni-mobile-api.py
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${STATE}
PrivateTmp=true
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now omni-mobile-api.service
  FRESH_BACKEND=1
else
  if [[ -f /opt/omni-siem/console/backend.json ]] && \
     systemctl show omni-mobile-api.service -p ExecStart --value | grep -Fq '/opt/omni-siem/console/omni-mobile-api.py'; then
    # The managed activator owns only the main backend file. Never report a
    # complete update while leaving a different packaged KPI tool in service.
    if [[ ! -f /opt/omni-siem/console/tools/omni-soc-kpi.py ]] || \
       ! cmp -s "$ROOT/tools/omni-soc-kpi.py" /opt/omni-siem/console/tools/omni-soc-kpi.py; then
      echo "Managed console KPI tool requires an explicit publication: reconcile /opt/omni-siem/console/tools/omni-soc-kpi.py and SOC_KPI_TOOL before retrying. No backend changed." >&2
      exit 1
    fi
    python3 "$ROOT/tools/manage-console-backend.py" --source "$ROOT/mobile/omni-mobile-api.py"
  else
    echo "Existing backend service/configuration retained; legacy code activation remains explicit."
  fi
fi

curl --fail --silent --show-error --retry 5 --retry-connrefused --retry-delay 1 --max-time 5 \
  http://127.0.0.1:8090/m/api/vapid >/dev/null
if [[ "$FRESH_BACKEND" == 1 ]]; then
  python3 "$ROOT/tools/manage-console-backend.py" --source "$ROOT/mobile/omni-mobile-api.py" --record
fi
python3 "$ROOT/tools/deploy-console.py" --site "$SITE" --apply
echo "Console installed at https://${SIEM_FQDN:-<your-siem-host>}/soc/ (HTTPS port 443)."
