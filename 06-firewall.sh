#!/usr/bin/env bash
# Apply a validated, namespaced firewall configuration using site networks only.
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "root required" >&2; exit 1; }
set -a
source ./00-vars.env
set +a
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
python3 ./tools/render-firewall.py > "$TMP"
nft -c -f "$TMP"
# Apply only our table. Restarting nftables invokes its global ExecStop flush.
# The helper preserves the boot configuration and adds a dedicated include.
python3 ./tools/install-firewall.py --candidate "$TMP"
