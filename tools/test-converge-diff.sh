#!/usr/bin/env bash
# =============================================================================
# test-converge-diff.sh - Test HORS-LIGNE du calcul de derive (RC-7).
# Aucun reseau : on ne charge que _event_desired_json / _event_canon de
# lib-graylog.sh et on compare des JSON en dur. Verifie que le canonicalizer :
#   T1 - ne signale PAS de derive quand seuls des champs poses par le serveur
#        different (id, _scope, updated_at, matched_at, filters, series.field=null,
#        storage, scheduler, litteral 10.0 vs 10, notifications en plus) ;
#   T2 - signale une derive quand la LOGIQUE change (query differente) ;
#   T3 - signale une derive quand un SEUIL change (conditions 10 -> 20) ;
#   T4 - _event_desired_json borne execute_every au minimum de search_within.
#
# Sortie : "OK" par test ; code de sortie != 0 si un test echoue.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

# On charge lib-graylog.sh sans toucher au reseau : les fonctions pures
# (_event_desired_json/_event_canon) n'appellent pas l'API. On neutralise les
# variables que le source attend (API/CURL sont definis mais jamais appeles ici).
SIEM_FQDN="test.local"; GRAYLOG_ADMIN_PASS="x"
# shellcheck disable=SC1091
source lib-graylog.sh

fail=0
check() { # <nom> <attendu drift: yes|no> <canonA> <canonB>
  local name="$1" want="$2" a="$3" b="$4" got
  if [[ "$a" == "$b" ]]; then got="no"; else got="yes"; fi
  if [[ "$got" == "$want" ]]; then
    echo "OK   $name (derive=$got)"
  else
    echo "FAIL $name : attendu derive=$want, obtenu=$got"; fail=1
    diff <(echo "$a") <(echo "$b") | sed 's/^/     /'
  fi
}

# --- JSON "live" bruite : tel que l'API le rend (champs serveur + 10.0 + 3 notif)
LIVE='{
  "_scope":"DEFAULT","id":"abc123","updated_at":"2026-07-08T13:01:10Z",
  "matched_at":"2026-07-17T19:25:16Z",
  "title":"OMNI - Demo","description":"P3 - provisionne par 13-graylog-alerts.sh",
  "priority":3,"alert":true,
  "config":{"type":"aggregation-v1","query":"event_id:4625","query_parameters":[],
    "filters":[],"streams":["S1"],"stream_categories":[],"group_by":["user"],
    "series":[{"type":"count","id":"count()","field":null}],
    "conditions":{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},
      "right":{"expr":"number","value":10.0}}},
    "search_within_ms":600000,"execute_every_ms":600000,"use_cron_scheduling":false,
    "cron_expression":null,"cron_timezone":null,"event_limit":100},
  "field_spec":{"user":{"data_type":"string","providers":[{"type":"template-v1",
    "template":"${source.user}","require_values":false}]}},
  "key_spec":["user"],
  "notification_settings":{"grace_period_ms":600000,"backlog_size":5},
  "notifications":[{"notification_id":"N1"},{"notification_id":"N2"},{"notification_id":"N3"}],
  "storage":[{"type":"persist-to-streams-v1","streams":["000000000000000000000002"]}],
  "scheduler":{"data":"noise"}
}'

# Desire construit par la MEME fonction que ensure_event, memes valeurs logiques.
export NOTIF_ID="N1"
DES_SAME="$(_event_desired_json "OMNI - Demo" 3 "event_id:4625" '["S1"]' '["user"]' \
  '[{"id":"count()","type":"count"}]' \
  '{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":10}}}' \
  10 2)"

# T1 : seuls les champs serveur/notifs different -> PAS de derive
check "T1 bruit-serveur-ignore" no \
  "$(echo "$LIVE" | _event_canon)" "$(echo "$DES_SAME" | _event_canon)"

# T2 : query differente -> derive
DES_QUERY="$(_event_desired_json "OMNI - Demo" 3 "event_id:9999" '["S1"]' '["user"]' \
  '[{"id":"count()","type":"count"}]' \
  '{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":10}}}' \
  10 2)"
check "T2 query-modifiee" yes \
  "$(echo "$LIVE" | _event_canon)" "$(echo "$DES_QUERY" | _event_canon)"

# T3 : seuil 10 -> 20 -> derive
DES_THRESH="$(_event_desired_json "OMNI - Demo" 3 "event_id:4625" '["S1"]' '["user"]' \
  '[{"id":"count()","type":"count"}]' \
  '{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":20}}}' \
  10 2)"
check "T3 seuil-modifie" yes \
  "$(echo "$LIVE" | _event_canon)" "$(echo "$DES_THRESH" | _event_canon)"

# T4 : bornage execute_every (EVERY=2 < WITHIN=10 -> 600000, pas 120000)
EV="$(echo "$DES_SAME" | jq -r '.config.execute_every_ms')"
if [[ "$EV" == "600000" ]]; then echo "OK   T4 borne-execute_every ($EV)"; else echo "FAIL T4 : execute_every=$EV (attendu 600000)"; fail=1; fi

echo
[[ $fail -eq 0 ]] && echo "==> TOUS LES TESTS PASSENT" || echo "==> ECHEC"
exit $fail
