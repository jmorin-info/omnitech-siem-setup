#!/usr/bin/env bash
# Shared platform selection. Sourcing this file has no side effects.
omni_platform() {
  local file="${1:-/etc/os-release}"
  local ID VERSION_ID VERSION_CODENAME
  . "$file"
  case "${ID}:${VERSION_ID}" in
    ubuntu:22.04) OMNI_MONGO_OS=ubuntu; OMNI_MONGO_SUITE=jammy; OMNI_MONGO_COMPONENT=multiverse ;;
    ubuntu:24.04) OMNI_MONGO_OS=ubuntu; OMNI_MONGO_SUITE=noble; OMNI_MONGO_COMPONENT=multiverse ;;
    ubuntu:26.04)
      [[ "${OMNI_EXPERIMENTAL_UBUNTU_2604:-0}" == 1 ]] || {
        echo "Ubuntu 26.04 requires explicit experimental opt-in; prefer Ubuntu 24.04 for this stack." >&2; return 1;
      }
      OMNI_MONGO_OS=ubuntu; OMNI_MONGO_SUITE=noble; OMNI_MONGO_COMPONENT=multiverse
      echo "EXPERIMENTAL: Ubuntu 26.04 with MongoDB 8.0 packages for Ubuntu 24.04 (noble); no vendor support guarantee." >&2 ;;
    debian:12|debian:13) OMNI_MONGO_OS=debian; OMNI_MONGO_SUITE=bookworm; OMNI_MONGO_COMPONENT=main ;;
    *) echo "Unsupported platform: ${ID:-unknown} ${VERSION_ID:-unknown}." >&2; return 1 ;;
  esac
  OMNI_OS="$ID"; OMNI_OS_VERSION="$VERSION_ID"
}

omni_mongodb_kernel_check() {
  local release="${1:-$(uname -r)}" major minor patch
  if [[ "$release" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
    major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[4]:-0}"
    if (( major == 6 && minor >= 19 || major == 7 && minor == 0 && patch < 14 )) \
       || { (( major == 7 && minor == 0 && patch == 14 )) && [[ "$release" == *rc* ]]; }; then
      echo "MongoDB 8.0 is incompatible with kernel ${release}: use a compatible kernel (7.0.14+ fixes the affected range 6.19 through 7.0.13). Do not bypass this check." >&2
      return 1
    fi
  fi
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
