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
if [[ -f /etc/nftables.conf ]]; then
  install -d -m 700 /var/backups/omni-siem
  cp -p /etc/nftables.conf "/var/backups/omni-siem/nftables.$(date +%s).conf"
fi
install -m 600 "$TMP" /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
