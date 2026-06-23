#!/usr/bin/env bash
# Telecharge les bases DB-IP Lite (mmdb) du mois courant. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
YM="$(date +%Y-%m)"
for b in dbip-city-lite dbip-asn-lite; do
  echo "==> $b-$YM"
  curl -fsSL "https://download.db-ip.com/free/${b}-${YM}.mmdb.gz" -o "${b}.mmdb.gz" \
    && gunzip -f "${b}.mmdb.gz" && echo "   ok ${b}.mmdb" \
    || echo "   [!] echec ${b} (verifier la connectivite / le mois)"
done
