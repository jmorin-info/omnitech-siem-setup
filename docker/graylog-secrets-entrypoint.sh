#!/bin/sh
# Wrapper docker-secrets pour Graylog (l'image officielle ne supporte pas la convention _FILE).
# Charge les GRAYLOG_* depuis /run/secrets si presents (ecrase le placeholder .env), puis lance
# la chaine d'origine de l'image (tini -> wait-for-it -> docker-entrypoint).
set -e

for pair in \
  "GRAYLOG_PASSWORD_SECRET:/run/secrets/graylog_password_secret" \
  "GRAYLOG_ROOT_PASSWORD_SHA2:/run/secrets/graylog_root_password_sha2"; do
  var="${pair%%:*}"; file="${pair#*:}"
  if [ -r "$file" ]; then eval "export ${var}=\"\$(cat \"$file\")\""; fi
done

exec /usr/bin/tini -- wait-for-it opensearch:9200 -- /docker-entrypoint.sh "$@"
