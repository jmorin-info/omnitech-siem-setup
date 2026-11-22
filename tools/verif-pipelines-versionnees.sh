#!/usr/bin/env bash
# =============================================================================
# verif-pipelines-versionnees.sh - Compare la source de pipeline que generent
# les scripts proprietaires avec celle en service (lecture seule).
#
#   Pour chaque pipeline qui recoit des regles versionnees
#   (objets-graylog/raccordements.txt) :
#     49-expo-port-class.sh --source-pipeline   OMNI - Exposition reseau
#     49-enrich-lots.sh --source-pipeline       OMNI - Exposition reseau
#     81-fp-allowlist.sh --source-pipeline      OMNI - Allowlist FP
#     tools/omni-v3/v3_build.py --source-pipeline  OMNI v3 - Detections et correlation
#   la source generee (hors ligne, aucune ecriture) est comparee a la source lue
#   par GET /system/pipelines/pipeline (diff unifie, blancs de fin ignores).
#
#   LECTURE SEULE : un unique GET sur l'API Graylog ; aucun POST/PUT/DELETE.
#   --hors-ligne FICHIER : compare a un export JSON de /system/pipelines/pipeline
#   au lieu d'interroger l'API (tests).
#
#   Usage : tools/verif-pipelines-versionnees.sh [--vars FICHIER] [--hors-ligne FICHIER]
#   Code retour : 0 si toutes les sources sont identiques ; 1 si un ecart ;
#   2 erreur d'usage ou de lecture.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

VARS_FILE="./00-vars.env"
EXPORT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vars) VARS_FILE="${2:-}"; shift ;;
    --hors-ligne) EXPORT="${2:-}"; shift ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "option inconnue : $1 (voir --help)" >&2; exit 2 ;;
  esac
  shift
done
command -v jq >/dev/null || { echo "jq requis" >&2; exit 2; }
PYTHON="${PYTHON:-python3}"

if [[ -n "${EXPORT}" ]]; then
  PIPES_JSON="$(cat "${EXPORT}")" || exit 2
else
  [[ -r "${VARS_FILE}" ]] || { echo "fichier de variables illisible : ${VARS_FILE}" >&2; exit 2; }
  PIPES_JSON="$(
    set -a
    # shellcheck disable=SC1090
    source "${VARS_FILE}"
    set +a
    source ./lib-graylog.sh || exit 2
    api_get "/system/pipelines/pipeline"
  )" || { echo "lecture des pipelines impossible (GET /system/pipelines/pipeline)" >&2; exit 2; }
fi

sans_blancs_fin() { sed -e 's/[[:space:]]*$//' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'; }

RC=0
comparer() {
  local LIBELLE="$1" PIPE="$2" GENEREE EN_SERVICE
  shift 2
  if ! GENEREE="$("$@")"; then
    echo "[ERREUR] ${LIBELLE} : generation impossible"; RC=2; return
  fi
  EN_SERVICE="$(jq -r --arg t "${PIPE}" '[.[] | select(.title == $t)][0] // empty | .source' <<< "${PIPES_JSON}")"
  if [[ -z "${EN_SERVICE}" ]]; then
    echo "[ECART] ${LIBELLE} : pipeline « ${PIPE} » absent en service"; [[ ${RC} -eq 2 ]] || RC=1; return
  fi
  if diff -u --label "en service : ${PIPE}" --label "genere : ${LIBELLE}" \
       <(sans_blancs_fin <<< "${EN_SERVICE}") <(sans_blancs_fin <<< "${GENEREE}"); then
    echo "[IDENTIQUE] ${LIBELLE} -> « ${PIPE} » ($(grep -c '^rule ' <<< "${GENEREE}") regles, $(grep -c '^stage ' <<< "${GENEREE}") etapes)"
  else
    echo "[ECART] ${LIBELLE} -> « ${PIPE} » (diff ci-dessus)"; [[ ${RC} -eq 2 ]] || RC=1
  fi
}

comparer "49-expo-port-class.sh" "OMNI - Exposition reseau" bash ./49-expo-port-class.sh --source-pipeline
comparer "49-enrich-lots.sh" "OMNI - Exposition reseau" bash ./49-enrich-lots.sh --source-pipeline
comparer "81-fp-allowlist.sh" "OMNI - Allowlist FP" bash ./81-fp-allowlist.sh --source-pipeline
comparer "tools/omni-v3/v3_build.py" "OMNI v3 - Detections et correlation" \
  env OMNI_REPO="${PWD}" "${PYTHON}" -I tools/omni-v3/v3_build.py --source-pipeline
exit "${RC}"
