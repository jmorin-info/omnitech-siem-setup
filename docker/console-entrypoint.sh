#!/usr/bin/env bash
# Generate a private config in the directory writable by the unprivileged image user.
set -euo pipefail
umask 077
DATA_DIR="${MOBILE_DATA_DIR:-/app/data}"
mkdir -p "$DATA_DIR"
export MOBILE_CONFIG="$DATA_DIR/omni-mobile.conf"

# Support docker secrets : si <VAR>_FILE pointe un fichier (ex. /run/secrets/...),
# charge <VAR> depuis son contenu (precede la valeur d'environnement en clair).
load_file_secret() {
  local file_variable="${1}_FILE" f
  f="${!file_variable:-}"
  if [[ -n "$f" ]]; then
    [[ -r "$f" ]] || { echo "Unreadable secret file: $file_variable" >&2; return 1; }
    printf -v "$1" '%s' "$(cat -- "$f")"
    export "$1"
  fi
  return 0
}
load_file_secret MOBILE_SECRET
load_file_secret MOBILE_PUSH_SECRET
cat > "$MOBILE_CONFIG" <<EOF
MOBILE_BIND=0.0.0.0
MOBILE_PORT=${MOBILE_PORT:-8090}
OPENSEARCH=${OPENSEARCH:-http://opensearch:9200}
GRAYLOG_API=${GRAYLOG_API:-http://graylog:9000/api}
MOBILE_ALLOW_HTTP_DOCKER=1
MITRE_LOOKUP=/app/lookups/mitre-attack.csv
MOBILE_SECRET=${MOBILE_SECRET:?MOBILE_SECRET requis (cf .env)}
MOBILE_PUSH_SECRET=${MOBILE_PUSH_SECRET:-${MOBILE_SECRET}}
MOBILE_REDACT=${MOBILE_REDACT:-0}
MOBILE_SESSION_TTL=${MOBILE_SESSION_TTL:-43200}
SIEM_FQDN=${SIEM_FQDN:-${SERVER_NAME:-}}
SIEM_IP=${SIEM_IP:-}
SOC_ORIGINS=${SOC_ORIGINS:-${SERVER_NAME:-localhost}}
SOC_LOG_INDICES=${SOC_LOG_INDICES:-omni-*,graylog_*}
SOC_EXPECTED_SOURCES=${SOC_EXPECTED_SOURCES:-}
SOC_ADMINS=${SOC_ADMINS:-}
MOBILE_SUBS_FILE=${DATA_DIR}/subs.json
MOBILE_CASES_FILE=${DATA_DIR}/cases.json
MOBILE_WATCH_FILE=${DATA_DIR}/watch.json
VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY:-}
VAPID_PRIVATE_FILE=${VAPID_PRIVATE_FILE:-/app/data/vapid_private.pem}
VAPID_SUBJECT=${VAPID_SUBJECT:-mailto:soc@omnitech-security.fr}
EOF
exec python "${MOBILE_APP_DIR:-/app/mobile}/omni-mobile-api.py"
