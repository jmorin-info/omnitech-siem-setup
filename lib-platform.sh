#!/usr/bin/env bash
# Shared platform selection. Sourcing this file has no side effects.
omni_platform() {
  local file="${1:-/etc/os-release}"
  local ID VERSION_ID VERSION_CODENAME
  . "$file"
  case "${ID}:${VERSION_ID}" in
    ubuntu:22.04) OMNI_MONGO_OS=ubuntu; OMNI_MONGO_SUITE=jammy; OMNI_MONGO_COMPONENT=multiverse ;;
    ubuntu:24.04) OMNI_MONGO_OS=ubuntu; OMNI_MONGO_SUITE=noble; OMNI_MONGO_COMPONENT=multiverse ;;
    debian:12|debian:13) OMNI_MONGO_OS=debian; OMNI_MONGO_SUITE=bookworm; OMNI_MONGO_COMPONENT=main ;;
    *) echo "Unsupported platform: ${ID:-unknown} ${VERSION_ID:-unknown}." >&2; return 1 ;;
  esac
  OMNI_OS="$ID"; OMNI_OS_VERSION="$VERSION_ID"
}

omni_api_setup() {
  API="${GRAYLOG_API_URL:-}"
  if [[ -z "$API" ]]; then
    if grep -Eq '^http_enable_tls[[:space:]]*=[[:space:]]*true' /etc/graylog/server/server.conf 2>/dev/null; then
      API="https://${SIEM_FQDN}:9000/api"
    else
      API="http://127.0.0.1:9000/api"
    fi
  fi
  API="${API%/}"
  API_CA="${GRAYLOG_API_CA:-/etc/graylog/certs/omnitech-rootca.crt}"
  CURL=(curl --silent --show-error --fail --connect-timeout 10 --max-time 90
        -u "admin:${GRAYLOG_ADMIN_PASS}" -H "Content-Type: application/json" -H "X-Requested-By: omni-provision")
  case "$API" in
    https://*) CURL+=(--cacert "$API_CA") ;;
    http://127.0.0.1:9000/api|http://localhost:9000/api) ;;
    *) echo "Use HTTPS for remote API access; local HTTP bootstrap is allowed only on port9000." >&2; return 1 ;;
  esac
  export GRAYLOG_API_URL="$API" GRAYLOG_API_CA="$API_CA"
}
