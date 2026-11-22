#!/usr/bin/env bash
# Restauration dans un enfant mongod possédé, lié uniquement à un socket Unix
# privé. Compare les comptages de collections, pas le contenu des documents.
# Usage : sudo bash tools/omni-mongo-restore-test.sh [archive.gz]
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DEPOT="${OMNI_SIEM_HOME:-/opt/omni-siem/repository}"
ENVFILE="${OMNI_VARS_FILE:-$HOME_DEPOT/00-vars.env}"
[[ -r "$ENVFILE" ]] || { echo 'Configuration du site illisible.' >&2; exit 2; }
# shellcheck disable=SC1090
set -a; source "$ENVFILE"; set +a
exec python3 "$SCRIPT_DIR/mongo-restore-test.py" "$@"
