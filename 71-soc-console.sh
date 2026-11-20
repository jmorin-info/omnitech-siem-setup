#!/usr/bin/env bash
# Deploy the complete SOC console, its backend and missing nginx routes.
# Existing backend configuration and local nginx access rules are preserved.
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f ./00-vars.env ]]; then
  source ./00-vars.env
  export SIEM_FQDN SIEM_IP GRAYLOG_API_CA SOC_ORIGINS SOC_LOG_INDICES SOC_ADMINS SOC_EXPECTED_SOURCES
fi
exec bash ./tools/install-console.sh --apply
