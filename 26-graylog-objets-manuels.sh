#!/usr/bin/env bash
# =============================================================================
# 26-graylog-objets-manuels.sh - OBJETS GRAYLOG CREES A LA MAIN, VERSIONNES
#
#   Recree a l'identique, apres une reconstruction, les objets Graylog poses a la
#   main en production en novembre 2026 (audit de coherence du 21/11/2026, E5,
#   G2 et G3), et CONTROLE ceux dont la creation releve d'un autre script :
#     - definitions d'evenements (CREEES ici, aucun autre script ne les porte) :
#       balayage IKE FortiGate (-> SOAR), scan applicatif WAF (404), lecture
#       d'un mot de passe LAPS (couche v3) ;
#     - regles de pipeline omni-v3-laps-lecture, omni-v3-laps-lecture-it et les
#       15 omni-fp-26-*, et leur raccordement a l'etape attendue (CONTROLE seul,
#       aucune ecriture).
#
#   POURQUOI LE CONTROLE SEUL POUR LES REGLES (22/11/2026) : les pipelines
#   « OMNI - Exposition reseau » (49-expo-port-class.sh, 49-enrich-lots.sh),
#   « OMNI - Allowlist FP » (81-fp-allowlist.sh) et « OMNI v3 - Detections et
#   correlation » (tools/omni-v3/v3_build.py) sont reecrits en entier par leur
#   script proprietaire. Ces scripts incluent desormais eux-memes les regles
#   versionnees (creation si absentes + ligne rule a la bonne etape), lues dans
#   l'inventaire unique objets-graylog/raccordements.txt et les fichiers .rule.
#   Si 26 raccordait encore, deux scripts ecriraient le meme pipeline et l'ordre
#   d'execution compterait de nouveau : il ne fait donc plus que verifier.
#
#   SOURCES VERSIONNEES (aucun identifiant d'instance) :
#     objets-graylog/raccordements.txt    inventaire : regle, source, pipeline, etape
#     objets-graylog/regles/*.rule        6 regles (2 LAPS + 4 omni-fp-26-* v3)
#     tools/alertes-v2/regles/*.rule      11 regles omni-fp-26-* v2
#     objets-graylog/definitions/*.json   3 definitions ; flux et notifications
#                                         designes par TITRE, resolus a l'execution
#                                         (flux_par_titre, notifications_par_titre).
#   Le flux de stockage 000000000000000000000002 est la constante Graylog du flux
#   « All events » (identique sur toute instance).
#
#   MODE PLAN PAR DEFAUT : uniquement des GET, aucune ecriture. --apply cree les
#   definitions manquantes (seule ecriture possible de ce script). Garde
#   d'existence par TITRE (definitions paginees via all_event_defs) : un objet
#   present n'est JAMAIS modifie, meme s'il differe de la source (l'ecart est
#   signale « non modifie »). Regle absente ou non raccordee : prerequis
#   manquant, le script proprietaire du pipeline est indique.
#
#   PREREQUIS : pipelines et regles ci-dessus (scripts proprietaires) ; flux
#   FortiGate, BunkerWeb et Windows Security ; notifications « OMNI - SOAR
#   auto-block » (36), « OMNI - Teams SOC » et « OMNI - Triage (mail critique) »
#   (38). Plus aucune contrainte d'ordre avec 49, 81 ou v3_build.py.
#   Lookups : aucune des regles versionnees ici n'en utilise.
#
#   Usage : ./26-graylog-objets-manuels.sh [--apply] [--vars FICHIER]
#   Code retour : 0 si tout est present (ou cree) ; 1 si un prerequis manque ou
#   si une ecriture est refusee ; 2 erreur d'usage.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")" || exit 2

APPLY=0
VARS_FILE="./00-vars.env"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --vars) VARS_FILE="${2:-}"; shift ;;
    -h|--help) sed -n '2,51p' "$0"; exit 0 ;;
    *) echo "option inconnue : $1 (voir --help)" >&2; exit 2 ;;
  esac
  shift
done
[[ -r "${VARS_FILE}" ]] || { echo "fichier de variables illisible : ${VARS_FILE}" >&2; exit 2; }
# shellcheck disable=SC1090
source "${VARS_FILE}"
source ./lib-graylog.sh || exit 2
source ./lib-regles-versionnees.sh || exit 2
command -v jq >/dev/null || die "jq requis"
require_api

# ------------------------------------------------------------------ inventaire
# titre | fichier source | description | pipeline | etape | position
verifier_raccordements || die "inventaire objets-graylog/raccordements.txt incoherent"
REGLES="$(grep -vE '^[[:space:]]*(#|$)' objets-graylog/raccordements.txt)"
DEFINITIONS=(
  objets-graylog/definitions/fortigate-balayage-ike.json
  objets-graylog/definitions/waf-scan-applicatif-404.json
  objets-graylog/definitions/v3-laps-lecture.json
)

N_PRESENT=0; N_CREER=0; N_ECART=0; N_MANQUE=0; N_REFUS=0
present() { N_PRESENT=$((N_PRESENT + 1)); skip "déjà présent : $*"; }
a_creer() { N_CREER=$((N_CREER + 1)); if [[ ${APPLY} -eq 1 ]]; then echo "    [+] création : $*"; else echo "    [+] à créer : $*"; fi; }
# Objet attendu dont la creation releve du script proprietaire de son pipeline.
a_poser()  { N_MANQUE=$((N_MANQUE + 1)); warn "absent (relancer $(proprietaire_pipeline "$1")) : $2"; }
ecart()   { N_ECART=$((N_ECART + 1)); warn "écart (non modifié) : $*"; }
manque()  { N_MANQUE=$((N_MANQUE + 1)); warn "prérequis manquant : $*"; }
refus()   { N_REFUS=$((N_REFUS + 1)); warn "REFUSÉ par l'API : $*"; }

# etape_regle <titre> : etape (numero) ou figure la regle dans la source de
# pipeline lue sur stdin ; vide si absente.
etape_regle() {
  awk -v r="$1" '
    /^[[:space:]]*stage[[:space:]]+-?[0-9]+/ { s = $2 }
    { l = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", l); if (l == "rule \"" r "\"") { print s; exit } }'
}

# resoudre_definition <fichier> : JSON pret a poster (flux et notifications
# resolus par titre) ; liste des titres introuvables sur stderr, code 1.
resoudre_definition() {
  local F="$1" RES
  RES="$(jq -n --slurpfile d "$F" --argjson s "${FLUX_JSON}" --argjson n "${NOTIF_JSON}" '
    $d[0] as $def
    | ([$def.flux_par_titre[] | select($s[.] == null)] + [$def.notifications_par_titre[] | select($n[.] == null)]) as $manq
    | if ($manq | length) > 0 then {manquants: $manq}
      else {def: ($def
        | .config.streams = [$def.flux_par_titre[] | $s[.]]
        | .notifications = [$def.notifications_par_titre[] | {notification_id: $n[.], notification_parameters: null}]
        | del(.flux_par_titre, .notifications_par_titre))}
      end')" || return 2
  if echo "${RES}" | jq -e 'has("manquants")' >/dev/null; then
    echo "${RES}" | jq -r '.manquants | join(", ")' >&2
    return 1
  fi
  echo "${RES}" | jq -c '.def'
}

# Sous-ensemble compare (champs logiques) ; nombres normalises (10.0 -> 10).
canon_definition() {
  jq -S 'walk(if type == "number" then . + 0 else . end) | {
    title, description, priority, alert,
    query: .config.query, streams: (.config.streams // [] | sort),
    group_by: .config.group_by, series: .config.series, conditions: .config.conditions,
    search_within_ms: .config.search_within_ms, execute_every_ms: .config.execute_every_ms,
    event_limit: .config.event_limit, key_spec, field_spec,
    notification_settings, notifications: ([.notifications[]?.notification_id] | sort),
    storage}'
}

if [[ ${APPLY} -eq 1 ]]; then
  echo "==> Mode APPLICATION (--apply) : création des objets manquants uniquement"
else
  echo "==> Mode PLAN (lecture seule, requêtes GET uniquement). Ajouter --apply pour écrire."
fi

# ---------------------------------------------------------------- 1. regles
echo "==> [1/3] Règles de pipeline ($(echo "${REGLES}" | grep -c .)) : contrôle seul (créées par le script propriétaire du pipeline)"
RULES_JSON="$(api_get "/system/pipelines/rule")" || die "lecture des règles impossible"
while IFS='|' read -r TITRE FICHIER _DESC PIPE _ETAPE _POS; do
  [[ -n "${TITRE}" ]] || continue
  COURANTE="$(echo "${RULES_JSON}" | jq -r --arg t "${TITRE}" '[.[] | select(.title == $t)][0] // empty | .source')"
  if [[ -z "${COURANTE}" ]]; then
    a_poser "${PIPE}" "règle ${TITRE} (${FICHIER})"
  elif [[ "$(printf '%s' "${COURANTE}" | _normaliser_source)" == "$(_normaliser_source < "${FICHIER}")" ]]; then
    present "règle ${TITRE}"
  else
    ecart "règle ${TITRE} : source en service différente de ${FICHIER}"
  fi
done <<< "${REGLES}"

# ------------------------------------------------------- 2. raccordement
echo "==> [2/3] Raccordement aux pipelines : contrôle seul"
PIPES_JSON="$(api_get "/system/pipelines/pipeline")" || die "lecture des pipelines impossible"
while IFS='|' read -r TITRE _FICHIER _DESC PIPE ETAPE _POS; do
  [[ -n "${TITRE}" ]] || continue
  PL="$(echo "${PIPES_JSON}" | jq -c --arg t "${PIPE}" '[.[] | select(.title == $t)][0] // empty')"
  if [[ -z "${PL}" ]]; then
    a_poser "${PIPE}" "pipeline « ${PIPE} » : ${TITRE} non raccordée"
    continue
  fi
  ACTUELLE="$(echo "${PL}" | jq -r '.source' | etape_regle "${TITRE}")"
  if [[ "${ACTUELLE}" == "${ETAPE}" ]]; then
    present "${TITRE} dans « ${PIPE} », étape ${ETAPE}"
  elif [[ -n "${ACTUELLE}" ]]; then
    ecart "${TITRE} raccordée à l'étape ${ACTUELLE} de « ${PIPE} » (attendu ${ETAPE})"
  else
    a_poser "${PIPE}" "raccordement ${TITRE} -> « ${PIPE} », étape ${ETAPE}"
  fi
done <<< "${REGLES}"

# Connexions des pipelines aux flux : signalees seulement (gerees par les
# scripts proprietaires des pipelines).
FLUX_LISTE="$(api_get "/streams" | jq -c '.streams // []')" || die "lecture des flux impossible"
CONNEXIONS="$(api_get "/system/pipelines/connections" 2>/dev/null || echo '[]')"
while IFS= read -r PIPE; do
  [[ -n "${PIPE}" ]] || continue
  PID="$(echo "${PIPES_JSON}" | jq -r --arg t "${PIPE}" '[.[] | select(.title == $t)][0].id // empty')"
  [[ -n "${PID}" ]] || continue
  LISTE="$(jq -rn --argjson c "${CONNEXIONS}" --argjson f "${FLUX_LISTE}" --arg p "${PID}" '
    [$c[] | select((.pipeline_ids // []) | index($p)) | .stream_id] as $ids
    | [$f[] | select(.id as $i | $ids | index($i)) | .title] | join(", ")')"
  if [[ -n "${LISTE}" ]]; then
    echo "    [i] « ${PIPE} » connecté à : ${LISTE}"
  else
    warn "« ${PIPE} » connecté à aucun flux (connexion gérée par son script propriétaire)"
  fi
done <<< "$(echo "${REGLES}" | cut -d'|' -f4 | sort -u)"

# ------------------------------------------------------ 3. definitions
echo "==> [3/3] Définitions d'événements (${#DEFINITIONS[@]})"
FLUX_JSON="$(echo "${FLUX_LISTE}" | jq -c 'map({(.title): .id}) | add // {}')"
NOTIF_JSON="$(api_get "/events/notifications?per_page=500" | jq -c '(.notifications // .elements // []) | map({(.title): .id}) | add // {}')" \
  || die "lecture des notifications impossible"
DEFS_JSON="$(all_event_defs)"
for F in "${DEFINITIONS[@]}"; do
  [[ -r "${F}" ]] || die "source absente du dépôt : ${F}"
  TITRE="$(jq -r '.title' "${F}")"
  ID="$(echo "${DEFS_JSON}" | jq -r --arg t "${TITRE}" '[.event_definitions[] | select(.title == $t)][0].id // empty')"
  if MANQUANTS="$(resoudre_definition "${F}" 2>&1 >/dev/null)"; then
    VOULUE="$(resoudre_definition "${F}")"
  else
    VOULUE=""
  fi
  if [[ -n "${ID}" ]]; then
    COURANTE="$(echo "${DEFS_JSON}" | jq -c --arg i "${ID}" '[.event_definitions[] | select(.id == $i)][0]')"
    if [[ -n "${VOULUE}" && "$(echo "${VOULUE}" | canon_definition)" == "$(echo "${COURANTE}" | canon_definition)" ]]; then
      present "définition « ${TITRE} »"
    elif [[ -z "${VOULUE}" ]]; then
      ecart "définition « ${TITRE} » présente, comparaison impossible (introuvable : ${MANQUANTS})"
    else
      ecart "définition « ${TITRE} » : champs différents de ${F} : $(diff <(echo "${COURANTE}" | canon_definition | jq -c 'to_entries[]') \
                <(echo "${VOULUE}" | canon_definition | jq -c 'to_entries[]') | grep '^>' | sed -E 's/^> \{"key":"([^"]+)".*/\1/' | paste -sd, -)"
    fi
    continue
  fi
  if [[ -z "${VOULUE}" ]]; then
    manque "définition « ${TITRE} » : flux ou notification introuvable (${MANQUANTS})"
    continue
  fi
  a_creer "définition « ${TITRE} » (${F})"
  [[ ${APPLY} -eq 1 ]] || continue
  NID="$(echo "${VOULUE}" | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  if [[ -n "${NID}" && "${NID}" != "null" ]]; then ok "définition « ${TITRE} » (${NID})"; else refus "définition « ${TITRE} »"; fi
done

echo
echo "Synthèse : ${N_PRESENT} déjà présent(s), ${N_CREER} $([[ ${APPLY} -eq 1 ]] && echo créé\(s\) || echo à créer), ${N_ECART} écart(s) non modifié(s), ${N_MANQUE} prérequis manquant(s), ${N_REFUS} refus"
if [[ ${APPLY} -eq 0 && ${N_CREER} -gt 0 ]]; then
  echo "Relancer avec --apply pour créer les objets manquants."
fi
[[ ${N_MANQUE} -eq 0 && ${N_REFUS} -eq 0 ]] || exit 1
exit 0
