#!/usr/bin/env bash
# =============================================================================
# 21-alert-hygiene.sh - Surcouche anti-tempete des definitions d'evenements
# -----------------------------------------------------------------------------
# Pourquoi (incident nuit 11->12/06/2026) : une boucle services.exe sur
# BX-AD02 (echec logon type 5 toutes les 2 s) a declenche "Force brute" en
# continu : ~50 mails (classes spam par Exchange) + epuisement du flux Power
# Automate -> PLUS AUCUNE alerte Teams de la nuit, y compris le vrai spraying
# VPN qui verrouillait des comptes AD. Lecons appliquees ici :
#   1. grace_period long sur les alertes d'ETAT PERSISTANT (une condition qui
#      dure ne doit pas re-notifier toutes les 10 min) ;
#   2. key_spec sur les alertes par compte/IP : le grace s'applique PAR CLE,
#      donc un NOUVEAU compte attaque notifie immediatement malgre le grace ;
#   3. requete Force brute limitee aux echecs "humains" (logon_fail, pose par
#      le pipeline, exclut les types 4/5) + alerte d'hygiene dediee aux
#      comptes de service casses (service_logon_fail), mail toutes les 4 h max.
# Idempotent. A relancer APRES toute re-execution de 13-graylog-alerts.sh
# (13 cree les definitions avec grace=600000 et key=[] par defaut).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh
require_api

echo "==> [1/2] Tuning grace / cle / requete des definitions existantes"

DEFS="$(api_get "/events/definitions?per_page=200")"

# Format : TITRE|grace_ms|key_spec_json|query ("-" = requete inchangee)
while IFS='|' read -r TITLE GRACE KEYS QUERY; do
  [[ -z "${TITLE}" ]] && continue
  ID="$(echo "${DEFS}" | jq -r --arg t "${TITLE}" \
        '.event_definitions[] | select(.title==$t) | .id')"
  if [[ -z "${ID}" || "${ID}" == "null" ]]; then
    warn "definition '${TITLE}' introuvable"
    continue
  fi
  # key_spec n'est valide que si chaque cle existe dans field_spec : on genere
  # automatiquement un champ template ${source.<cle>} (le groupe d'agregation
  # alimente ces valeurs au declenchement).
  REP="$(api_get "/events/definitions/${ID}" \
    | jq --argjson g "${GRACE}" --argjson k "${KEYS}" --arg q "${QUERY}" '
        del(._scope, .matched_at, .updated_at, .scheduler)
        | .notification_settings.grace_period_ms = $g
        | .key_spec = $k
        | .field_spec = ($k | map({key: ., value: {data_type: "string",
            providers: [{type: "template-v1",
                         template: ("${source." + . + "}"),
                         require_values: false}]}}) | from_entries)
        | (if $q != "-" then .config.query = $q else . end)' \
    | api_put "/events/definitions/${ID}?schedule=true")"
  if echo "${REP}" | jq -e '.id' >/dev/null 2>&1; then
    ok "'${TITLE}' -> grace=$((GRACE/60000))min key=${KEYS}"
  else
    warn "'${TITLE}' : echec -> $(echo "${REP}" | head -c 200)"
  fi
done <<'EOT'
OMNI - Force brute (>=10 echecs / compte / 10 min)|3600000|["user"]|event_id:4625 AND logon_fail:1
OMNI - Force brute SUIVIE d'un succes (meme compte / 15 min)|3600000|["user"]|-
OMNI - Password spraying (>=8 comptes / IP / 10 min)|1800000|["src_ip"]|-
OMNI - Force brute portail VPN (>=30 echecs / IP / h)|3600000|[]|-
OMNI - Compte verrouille (4740)|3600000|[]|-
OMNI - Injection de processus (Sysmon 8/25)|3600000|[]|-
OMNI - PowerShell suspect|3600000|[]|-
OMNI - Silence Winlogbeat (0 log Windows / 15 min)|1800000|[]|-
EOT

echo "==> [2/2] Alerte d'hygiene dediee : comptes de service casses"

TITLE_SVC="OMNI - Echec logon service/batch (compte de service casse)"
EXIST="$(echo "${DEFS}" | jq -r --arg t "${TITLE_SVC}" \
        '.event_definitions[] | select(.title==$t) | .id')"
if [[ -n "${EXIST}" && "${EXIST}" != "null" ]]; then
  skip "definition '${TITLE_SVC}' existe deja"
else
  ST_WINSEC="$(get_stream_id 'OMNI - Windows Security')"
  NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" \
    | jq -r '.notifications[] | select(.title=="OMNI - Mail equipe IT") | .id')"
  [[ -n "${ST_WINSEC}" && -n "${NOTIF_MAIL}" ]] \
    || die "stream winsec ou notification mail introuvable"
  NEWID="$(jq -n --arg t "${TITLE_SVC}" --arg st "${ST_WINSEC}" --arg n "${NOTIF_MAIL}" '{
    title: $t,
    description: "P3 hygiene - un service ou une tache Windows tourne avec un mauvais compte / mot de passe / droit (4625 type 4-5). Sur l hote concerne : Get-CimInstance Win32_Service | ? StartName -match <compte>. Provisionne par 21-alert-hygiene.sh",
    priority: 3,
    alert: true,
    config: {
      type: "aggregation-v1",
      query: "service_logon_fail:1",
      query_parameters: [],
      streams: [$st],
      group_by: ["user", "source"],
      series: [{id: "count()", type: "count"}],
      conditions: {expression: {expr: ">=",
        left: {expr: "number-ref", ref: "count()"},
        right: {expr: "number", value: 10}}},
      search_within_ms: 900000,
      execute_every_ms: 900000,
      use_cron_scheduling: false,
      event_limit: 100
    },
    field_spec: {
      user:   {data_type: "string", providers: [{type: "template-v1", template: "${source.user}",   require_values: false}]},
      source: {data_type: "string", providers: [{type: "template-v1", template: "${source.source}", require_values: false}]}
    },
    key_spec: ["user", "source"],
    notification_settings: {grace_period_ms: 14400000, backlog_size: 5},
    notifications: [{notification_id: $n, notification_parameters: null}]
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  if [[ -n "${NEWID}" && "${NEWID}" != "null" ]]; then
    ok "definition '${TITLE_SVC}' creee (mail seul, grace 4 h, cle user+source)"
  else
    warn "creation '${TITLE_SVC}' REFUSEE"
  fi
fi

echo "==> [3/3] Alerte Veeam : job de sauvegarde en echec / avertissement"

TITLE_VEEAM="OMNI - Veeam : job en echec ou avertissement"
EXIST="$(api_get "/events/definitions?per_page=200" | jq -r --arg t "${TITLE_VEEAM}" \
        '.event_definitions[] | select(.title==$t) | .id')"
if [[ -n "${EXIST}" && "${EXIST}" != "null" ]]; then
  skip "definition '${TITLE_VEEAM}' existe deja"
else
  ST_WINOTH="$(get_stream_id 'OMNI - Windows autres')"
  NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" \
    | jq -r '.notifications[] | select(.title=="OMNI - Mail equipe IT") | .id')"
  [[ -n "${ST_WINOTH}" && -n "${NOTIF_MAIL}" ]] \
    || die "stream winother ou notification mail introuvable"
  NEWID="$(jq -n --arg t "${TITLE_VEEAM}" --arg st "${ST_WINOTH}" --arg n "${NOTIF_MAIL}" '{
    title: $t,
    description: "P3 sauvegardes - un job Veeam B&R a echoue ou fini en avertissement (canal Windows Veeam Backup, collecte par Install-OmniSiem sur le serveur Veeam). Provisionne par 21-alert-hygiene.sh",
    priority: 3,
    alert: true,
    config: {
      type: "aggregation-v1",
      query: "alert_tag:veeam_job_echec",
      query_parameters: [],
      streams: [$st],
      group_by: [],
      series: [{id: "count()", type: "count"}],
      conditions: {expression: {expr: ">=",
        left: {expr: "number-ref", ref: "count()"},
        right: {expr: "number", value: 1}}},
      search_within_ms: 900000,
      execute_every_ms: 900000,
      use_cron_scheduling: false,
      event_limit: 100
    },
    field_spec: {},
    key_spec: [],
    notification_settings: {grace_period_ms: 14400000, backlog_size: 5},
    notifications: [{notification_id: $n, notification_parameters: null}]
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  if [[ -n "${NEWID}" && "${NEWID}" != "null" ]]; then
    ok "definition '${TITLE_VEEAM}' creee (mail, grace 4 h)"
  else
    warn "creation '${TITLE_VEEAM}' REFUSEE"
  fi
fi

echo "==> [4/4] Auto-surveillance de la sauvegarde config (30-backup-config)"

# Les messages GELF du backup/garde-fou arrivent par l'input GELF, que le
# stream M365 capte par regle "source input" -> stream dedie route par
# event_source, sinon les definitions ci-dessous ne voient jamais rien.
ST_INTERNE="$(get_stream_id 'OMNI - Interne SIEM')"
if [[ -z "${ST_INTERNE}" ]]; then
  IDX_DEFAUT="$(api_get '/system/indices/index_sets?skip=0&limit=100' \
    | jq -r '.index_sets[] | select(.index_prefix=="graylog") | .id')"
  ST_INTERNE="$(jq -n --arg idx "${IDX_DEFAUT}" '{
      title: "OMNI - Interne SIEM",
      description: "Auto-surveillance du SIEM (backup config, garde-fou disque) - provisionne par 21-alert-hygiene.sh",
      matching_type: "OR",
      remove_matches_from_default_stream: false,
      index_set_id: $idx,
      rules: [
        {field: "event_source", type: 1, value: "siem_backup",     inverted: false},
        {field: "event_source", type: 1, value: "siem_disk_guard", inverted: false},
        {field: "event_source", type: 1, value: "siem_report",     inverted: false},
        {field: "event_source", type: 1, value: "siem_soar",       inverted: false},
        {field: "event_source", type: 1, value: "siem_cert",       inverted: false}
      ]}' | post_entity "/streams" | jqr '.stream_id // .id')"
  if [[ -n "${ST_INTERNE}" && "${ST_INTERNE}" != "null" ]]; then
    "${CURL[@]}" -X POST "${API}/streams/${ST_INTERNE}/resume" >/dev/null
    ok "stream 'OMNI - Interne SIEM' cree et demarre (${ST_INTERNE})"
  else
    die "creation du stream 'OMNI - Interne SIEM' REFUSEE"
  fi
fi

# Anti-duplication : le stream M365 capte TOUT le GELF (regle gl2_source_input)
# -> il faut EXCLURE les event_source internes, sinon double-indexation (graylog_0
# + omni-m365 avec retention M365 appliquee a tort). Meme pattern que 38-46.
M365_ID="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365_ID}" ]]; then
  MEX="$(api_get "/streams/${M365_ID}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  for V in siem_backup siem_disk_guard siem_report siem_soar siem_cert; do
    if echo "${MEX}" | grep -qx "${V}"; then skip "M365 exclut deja ${V}"
    else
      jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:true,
          description:("exclusion interne (anti-dup): "+$v)}' \
        | api_post "/streams/${M365_ID}/rules" >/dev/null && ok "M365 exclut desormais ${V}"
    fi
  done
else warn "stream M365 introuvable (exclusion interne non posee)"; fi

NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" \
  | jq -r '.notifications[] | select(.title=="OMNI - Mail equipe IT") | .id')"

ensure_def_simple() {  # TITLE QUERY COND_JSON WITHIN_MS EXEC_MS GRACE_MS
  local TITLE="$1" QUERY="$2" COND="$3" WITHIN="$4" EXEC="$5" GRACE="$6"
  local EXIST NEWID
  EXIST="$(api_get "/events/definitions?per_page=200" | jq -r --arg t "${TITLE}" \
          '.event_definitions[] | select(.title==$t) | .id')"
  if [[ -n "${EXIST}" && "${EXIST}" != "null" ]]; then skip "definition '${TITLE}' existe deja"; return; fi
  NEWID="$(jq -n --arg t "${TITLE}" --arg q "${QUERY}" --arg st "${ST_INTERNE}" \
              --arg n "${NOTIF_MAIL}" --argjson co "${COND}" \
              --argjson w "${WITHIN}" --argjson e "${EXEC}" --argjson g "${GRACE}" '{
    title: $t,
    description: "P3 resilience - sauvegarde config SIEM (30-backup-config.sh). Provisionne par 21-alert-hygiene.sh",
    priority: 3, alert: true,
    config: {
      type: "aggregation-v1", query: $q, query_parameters: [],
      streams: [$st], group_by: [],
      series: [{id: "count()", type: "count"}],
      conditions: $co,
      search_within_ms: $w, execute_every_ms: $e,
      use_cron_scheduling: false, event_limit: 100
    },
    field_spec: {}, key_spec: [],
    notification_settings: {grace_period_ms: $g, backlog_size: 3},
    notifications: [{notification_id: $n, notification_parameters: null}]
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  [[ -n "${NEWID}" && "${NEWID}" != "null" ]] && ok "definition '${TITLE}' creee" \
    || warn "creation '${TITLE}' REFUSEE"
}

COND_GE1='{"expression":{"expr":">=","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":1}}}'
COND_LT1='{"expression":{"expr":"<","left":{"expr":"number-ref","ref":"count()"},"right":{"expr":"number","value":1}}}'

ensure_def_simple "OMNI - Backup config SIEM en echec" \
  "event_action:backup_config_echec" "${COND_GE1}" 1800000 1800000 14400000
ensure_def_simple "OMNI - Backup config SIEM absent (>26h)" \
  "event_action:backup_config_ok" "${COND_LT1}" 93600000 21600000 43200000

echo "==> [5/5] Garde-fou disque /data (32-disk-guard)"

ensure_def_simple "OMNI - Disque SIEM >80% (/data)" \
  "event_action:disk_warn" "${COND_GE1}" 23400000 21600000 86400000
ensure_def_simple "OMNI - PURGE D'URGENCE retention (disque presque plein)" \
  "event_action:disk_guard_prune" "${COND_GE1}" 23400000 1800000 14400000
ensure_def_simple "OMNI - Rapport hebdomadaire en echec" \
  "event_action:report_echec" "${COND_GE1}" 1800000 1800000 14400000
ensure_def_simple "OMNI - Certificat SIEM expire bientot (<45j)" \
  "event_action:cert_expire_proche" "${COND_GE1}" 604800000 86400000 604800000

# Re-pointage idempotent des 4 definitions vers le stream interne (au cas ou
# elles auraient ete creees avant le stream, sur le mauvais stream)
for T in "OMNI - Backup config SIEM en echec" "OMNI - Backup config SIEM absent (>26h)" \
         "OMNI - Disque SIEM >80% (/data)" "OMNI - PURGE D'URGENCE retention (disque presque plein)" \
         "OMNI - Rapport hebdomadaire en echec"; do
  ID="$(api_get "/events/definitions?per_page=200" | jq -r --arg t "${T}" \
       '.event_definitions[] | select(.title==$t) | .id')"
  [[ -z "${ID}" || "${ID}" == "null" ]] && continue
  REP="$(api_get "/events/definitions/${ID}" \
    | jq --arg st "${ST_INTERNE}" \
        'del(._scope, .matched_at, .updated_at, .scheduler) | .config.streams = [$st]' \
    | api_put "/events/definitions/${ID}?schedule=true")"
  echo "${REP}" | jq -e '.id' >/dev/null 2>&1 \
    && ok "'${T}' -> stream interne" || warn "'${T}' : echec re-pointage"
done

echo "=== 21-alert-hygiene.sh termine ==="
