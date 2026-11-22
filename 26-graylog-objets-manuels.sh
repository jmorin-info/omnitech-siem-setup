#!/usr/bin/env bash
# =============================================================================
# 26-graylog-objets-manuels.sh - OBJETS GRAYLOG CREES A LA MAIN, VERSIONNES
#
#   Recree a l'identique, apres une reconstruction, les objets Graylog poses a la
#   main en production en novembre 2026 (audit de coherence du 21/11/2026, E5,
#   G2 et G3) :
#     - definitions d'evenements : balayage IKE FortiGate (-> SOAR), scan
#       applicatif WAF (404), lecture d'un mot de passe LAPS (couche v3) ;
#     - regles de pipeline : omni-v3-laps-lecture, omni-v3-laps-lecture-it et
#       les 15 regles de faux positifs omni-fp-26-* ;
#     - raccordement de ces regles a leur pipeline et a leur etape.
#
#   SOURCES VERSIONNEES (aucun identifiant d'instance) :
#     objets-graylog/regles/*.rule        6 regles (2 LAPS + 4 omni-fp-26-* v3)
#     tools/alertes-v2/regles/*.rule      11 regles omni-fp-26-* v2 (deja au depot)
#     objets-graylog/definitions/*.json   3 definitions ; flux et notifications
#                                         designes par TITRE, resolus a l'execution
#                                         (flux_par_titre, notifications_par_titre).
#   Le flux de stockage 000000000000000000000002 est la constante Graylog du flux
#   « All events » (identique sur toute instance).
#
#   MODE PLAN PAR DEFAUT : uniquement des GET, aucune ecriture. --apply cree ce
#   qui manque. Garde d'existence par TITRE (definitions paginees via
#   all_event_defs, regles, pipelines) : un objet present n'est JAMAIS modifie,
#   meme s'il differe de la source (l'ecart est signale « non modifie »).
#   Raccordement aux pipelines : ADDITIF (insertion de la ligne rule "..." dans
#   l'etape attendue, creee si absente) ; aucune ligne existante n'est retiree.
#
#   PREREQUIS : pipelines « OMNI - Exposition reseau » (49-expo-port-class.sh),
#   « OMNI - Allowlist FP » (81-fp-allowlist.sh), « OMNI v3 - Detections et
#   correlation » (tools/omni-v3/v3_build.py) ; flux FortiGate, BunkerWeb et
#   Windows Security ; notifications « OMNI - SOAR auto-block » (36),
#   « OMNI - Teams SOC » et « OMNI - Triage (mail critique) » (38).
#   A RELANCER APRES 49-expo-port-class.sh, 49-enrich-lots.sh, 81-fp-allowlist.sh
#   et v3_build.py : ces scripts reecrivent la source complete de leur pipeline
#   et en retirent les regles raccordees ici.
#   Lookups : aucune des regles versionnees ici n'en utilise.
#
#   Usage : ./26-graylog-objets-manuels.sh [--apply] [--vars FICHIER]
#   Code retour : 0 si tout est present (ou cree) ; 1 si un prerequis manque ou
#   si une ecriture est refusee ; 2 erreur d'usage.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

APPLY=0
VARS_FILE="./00-vars.env"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --vars) VARS_FILE="${2:-}"; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "option inconnue : $1 (voir --help)" >&2; exit 2 ;;
  esac
  shift
done
[[ -r "${VARS_FILE}" ]] || { echo "fichier de variables illisible : ${VARS_FILE}" >&2; exit 2; }
# shellcheck disable=SC1090
source "${VARS_FILE}"
source ./lib-graylog.sh || exit 2
command -v jq >/dev/null || die "jq requis"
require_api

# ------------------------------------------------------------------ inventaire
# titre | fichier source | description | pipeline | etape
REGLES="$(cat <<'EOF'
omni-v3-laps-lecture|objets-graylog/regles/omni-v3-laps-lecture.rule|OMNITECH v3 11/11/2026|OMNI v3 - Detections et correlation|40
omni-v3-laps-lecture-it|objets-graylog/regles/omni-v3-laps-lecture-it.rule|OMNITECH v3 11/11/2026|OMNI v3 - Detections et correlation|41
omni-fp-26-expo-ztna-vaultwarden|objets-graylog/regles/omni-fp-26-expo-ztna-vaultwarden.rule|OMNITECH v3 11/11/2026|OMNI - Exposition reseau|17
omni-fp-26-service-veeam-vss|objets-graylog/regles/omni-fp-26-service-veeam-vss.rule|OMNITECH v3 11/11/2026|OMNI - Allowlist FP|25
omni-fp-26-lsass-ninjaone-metering|objets-graylog/regles/omni-fp-26-lsass-ninjaone-metering.rule|OMNITECH v3 11/11/2026|OMNI - Allowlist FP|25
omni-fp-26-adexplorer-dev-seal|objets-graylog/regles/omni-fp-26-adexplorer-dev-seal.rule|OMNITECH v3 11/11/2026|OMNI - Allowlist FP|25
omni-fp-26-adminshare-veeam-dc|tools/alertes-v2/regles/omni-fp-26-adminshare-veeam-dc.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-explicit-cred-admin|tools/alertes-v2/regles/omni-fp-26-explicit-cred-admin.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-injection-outils|tools/alertes-v2/regles/omni-fp-26-injection-outils.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-lsass-defender|tools/alertes-v2/regles/omni-fp-26-lsass-defender.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-ntds-surebackup-mh|tools/alertes-v2/regles/omni-fp-26-ntds-surebackup-mh.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-outlook-liens|tools/alertes-v2/regles/omni-fp-26-outlook-liens.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-schtask-oms|tools/alertes-v2/regles/omni-fp-26-schtask-oms.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-wbadmin-retention-dc|tools/alertes-v2/regles/omni-fp-26-wbadmin-retention-dc.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-webshell-proactive|tools/alertes-v2/regles/omni-fp-26-webshell-proactive.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-zerologon-mdp-machine|tools/alertes-v2/regles/omni-fp-26-zerologon-mdp-machine.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
omni-fp-26-webshell-dev-central6|tools/alertes-v2/regles/omni-fp-26-webshell-dev-central6.rule|Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md|OMNI - Allowlist FP|25
EOF
)"
DEFINITIONS=(
  objets-graylog/definitions/fortigate-balayage-ike.json
  objets-graylog/definitions/waf-scan-applicatif-404.json
  objets-graylog/definitions/v3-laps-lecture.json
)

N_PRESENT=0; N_CREER=0; N_ECART=0; N_MANQUE=0; N_REFUS=0
present() { N_PRESENT=$((N_PRESENT + 1)); skip "déjà présent : $*"; }
a_creer() { N_CREER=$((N_CREER + 1)); if [[ ${APPLY} -eq 1 ]]; then echo "    [+] création : $*"; else echo "    [+] à créer : $*"; fi; }
ecart()   { N_ECART=$((N_ECART + 1)); warn "écart (non modifié) : $*"; }
manque()  { N_MANQUE=$((N_MANQUE + 1)); warn "prérequis manquant : $*"; }
refus()   { N_REFUS=$((N_REFUS + 1)); warn "REFUSÉ par l'API : $*"; }

# Source sans les blancs de fin (la production stocke certaines regles sans
# saut de ligne final).
normaliser_source() { sed -e 's/[[:space:]]*$//' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'; }

# etape_regle <titre> : etape (numero) ou figure la regle dans la source de
# pipeline lue sur stdin ; vide si absente.
etape_regle() {
  awk -v r="$1" '
    /^[[:space:]]*stage[[:space:]]+-?[0-9]+/ { s = $2 }
    { l = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", l); if (l == "rule \"" r "\"") { print s; exit } }'
}

# inserer_regle <etape> <titre> : source de pipeline (stdin) -> source avec la
# ligne rule "<titre>" ajoutee en fin de l'etape ; etape creee (match either),
# a sa place dans l'ordre numerique, si elle n'existe pas. N'enleve rien.
inserer_regle() {
  awk -v st="$1" -v r="$2" '
    function regle() { if (!fait) { print "rule \"" r "\""; fait = 1 } }
    function etape() { if (!fait) { print "stage " st " match either"; regle() } }
    /^[[:space:]]*stage[[:space:]]+-?[0-9]+/ {
      n = $2 + 0
      if (cible) regle()
      cible = (n == st + 0)
      if (!cible && n > st + 0) etape()
      print; next
    }
    /^[[:space:]]*end[[:space:]]*$/ { if (cible) regle(); etape(); cible = 0; print; next }
    { print }'
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
echo "==> [1/3] Règles de pipeline ($(echo "${REGLES}" | grep -c .))"
RULES_JSON="$(api_get "/system/pipelines/rule")" || die "lecture des règles impossible"
while IFS='|' read -r TITRE FICHIER DESC _PIPE _ETAPE; do
  [[ -n "${TITRE}" ]] || continue
  [[ -r "${FICHIER}" ]] || die "source absente du dépôt : ${FICHIER}"
  grep -q "^rule \"${TITRE}\"" "${FICHIER}" || die "${FICHIER} ne déclare pas rule \"${TITRE}\""
  COURANTE="$(echo "${RULES_JSON}" | jq -r --arg t "${TITRE}" '[.[] | select(.title == $t)][0] // empty | .source')"
  if [[ -n "${COURANTE}" ]]; then
    if [[ "$(printf '%s' "${COURANTE}" | normaliser_source)" == "$(normaliser_source < "${FICHIER}")" ]]; then
      present "règle ${TITRE}"
    else
      ecart "règle ${TITRE} : source en service différente de ${FICHIER}"
    fi
    continue
  fi
  a_creer "règle ${TITRE} (${FICHIER})"
  [[ ${APPLY} -eq 1 ]] || continue
  ID="$(jq -n --arg t "${TITRE}" --arg d "${DESC}" --rawfile s "${FICHIER}" '{title: $t, description: $d, source: $s}' \
        | api_post "/system/pipelines/rule" | jqr '.id')"
  if [[ -n "${ID}" && "${ID}" != "null" ]]; then ok "règle ${TITRE} (${ID})"; else refus "règle ${TITRE}"; fi
done <<< "${REGLES}"

# ------------------------------------------------------- 2. raccordement
echo "==> [2/3] Raccordement aux pipelines"
while IFS='|' read -r TITRE _FICHIER _DESC PIPE ETAPE; do
  [[ -n "${TITRE}" ]] || continue
  PL="$(api_get "/system/pipelines/pipeline" | jq -c --arg t "${PIPE}" '[.[] | select(.title == $t)][0] // empty')"
  if [[ -z "${PL}" ]]; then
    manque "pipeline « ${PIPE} » absent : ${TITRE} non raccordée (voir PREREQUIS en tête)"
    continue
  fi
  SRC="$(echo "${PL}" | jq -r '.source')"
  ACTUELLE="$(printf '%s\n' "${SRC}" | etape_regle "${TITRE}")"
  if [[ "${ACTUELLE}" == "${ETAPE}" ]]; then
    present "${TITRE} dans « ${PIPE} », étape ${ETAPE}"
    continue
  elif [[ -n "${ACTUELLE}" ]]; then
    ecart "${TITRE} raccordée à l'étape ${ACTUELLE} de « ${PIPE} » (attendu ${ETAPE})"
    continue
  fi
  a_creer "raccordement ${TITRE} -> « ${PIPE} », étape ${ETAPE}"
  [[ ${APPLY} -eq 1 ]] || continue
  if ! echo "${RULES_JSON}" | jq -e --arg t "${TITRE}" 'any(.[]; .title == $t)' >/dev/null \
     && ! api_get "/system/pipelines/rule" | jq -e --arg t "${TITRE}" 'any(.[]; .title == $t)' >/dev/null; then
    refus "raccordement ${TITRE} : la règle n'existe pas"
    continue
  fi
  NOUVELLE="$(printf '%s\n' "${SRC}" | inserer_regle "${ETAPE}" "${TITRE}")"
  if echo "${PL}" | jq --arg s "${NOUVELLE}" '{id, title, description, source: $s}' \
       | api_put "/system/pipelines/pipeline/$(echo "${PL}" | jq -r '.id')" >/dev/null; then
    ok "${TITRE} raccordée à « ${PIPE} », étape ${ETAPE}"
  else
    refus "raccordement ${TITRE}"
  fi
done <<< "${REGLES}"

# Connexions des pipelines aux flux : signalees seulement (gerees par les
# scripts proprietaires des pipelines).
FLUX_LISTE="$(api_get "/streams" | jq -c '.streams // []')" || die "lecture des flux impossible"
CONNEXIONS="$(api_get "/system/pipelines/connections" 2>/dev/null || echo '[]')"
PIPES_JSON="$(api_get "/system/pipelines/pipeline")"
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
