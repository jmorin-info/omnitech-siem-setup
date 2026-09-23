#!/usr/bin/env bash
# =============================================================================
# fix-tor-detection-groupby.sh - Correctif live de la detection Tor SSL-VPN.
#   La def "OMNI - Login SSL-VPN depuis IP malveillante ou Tor (T1133)" groupait
#   par [user,remip,ti_reputation] ; ti_reputation n'est mappe sur AUCUN doc
#   FortiGate (le tag n'est ecrit que sur un hit, et il n'y en a jamais eu)
#   -> l'agregation echoue en boucle ("failed: null"). On retire ti_reputation.
#   Le code source (28-vpn-remip-ti.sh) est deja corrige ; ceci corrige la def
#   DEJA CREEE en base (le script 28 ne recree pas une def existante).
#   Idempotent. Lecture puis PUT. Aucune donnee touchee.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api
ID="6a46d1943411482ad6d54342"

CUR="$(api_get "/events/definitions/${ID}")"
GB="$(echo "$CUR" | jq -c '.config.group_by')"
echo "group_by actuel : ${GB}"
if [[ "$GB" == '["user","remip"]' ]]; then
  ok "deja corrige (rien a faire)"; exit 0
fi
REP="$(echo "$CUR" | jq '.config.group_by=["user","remip"]' \
       | api_put "/events/definitions/${ID}?schedule=true")"
NEW="$(echo "$REP" | jq -c '.config.group_by' 2>/dev/null)"
if [[ "$NEW" == '["user","remip"]' ]]; then
  # re-arme la planification (sans effet si deja planifiee)
  "${CURL[@]}" -X PUT "${API}/events/definitions/${ID}/schedule" >/dev/null 2>&1 || true
  ok "group_by corrige -> ${NEW}"
else
  warn "echec PUT -> $(echo "$REP" | head -c 200)"
  exit 1
fi
