#!/usr/bin/env bash
# Genere /etc/default/omni-mobile depuis l'environnement (12-factor) puis lance la console.
set -e
mkdir -p /etc/default /app/data

# Support docker secrets : si <VAR>_FILE pointe un fichier (ex. /run/secrets/...),
# charge <VAR> depuis son contenu (precede la valeur d'environnement en clair).
load_file_secret() {
  local f; eval "f=\${${1}_FILE:-}"
  [ -n "$f" ] && [ -r "$f" ] && eval "export ${1}=\"\$(cat \"$f\")\""
}
load_file_secret MOBILE_SECRET
load_file_secret MOBILE_PUSH_SECRET
cat > /etc/default/omni-mobile <<EOF
MOBILE_BIND=0.0.0.0
MOBILE_PORT=${MOBILE_PORT:-8090}
OPENSEARCH=${OPENSEARCH:-http://opensearch:9200}
GRAYLOG_API=${GRAYLOG_API:-http://graylog:9000/api}
MOBILE_SECRET=${MOBILE_SECRET:?MOBILE_SECRET requis (cf .env)}
MOBILE_PUSH_SECRET=${MOBILE_PUSH_SECRET:-${MOBILE_SECRET}}
MOBILE_REDACT=${MOBILE_REDACT:-0}
MOBILE_SESSION_TTL=${MOBILE_SESSION_TTL:-43200}
MOBILE_SUBS_FILE=/app/data/subs.json
MOBILE_CASES_FILE=/app/data/cases.json
MOBILE_WATCH_FILE=/app/data/watch.json
VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY:-}
VAPID_PRIVATE_FILE=${VAPID_PRIVATE_FILE:-/app/data/vapid_private.pem}
VAPID_SUBJECT=${VAPID_SUBJECT:-mailto:soc@omnitech-security.fr}
EOF
exec python /app/mobile/omni-mobile-api.py
