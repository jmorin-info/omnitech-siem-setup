#!/usr/bin/env bash
# =============================================================================
# maj-cert-orchestrator-prod.sh : alignement d'une production où 99-cert-orchestrator.sh
# a déjà été appliqué avant le 22/11/2026.
#
#   bash tools/maj-cert-orchestrator-prod.sh            plan (défaut, lecture seule : GET)
#   sudo bash tools/maj-cert-orchestrator-prod.sh --apply
#
# Deux corrections, idempotentes, sans création ni suppression d'objet :
#   1. Règles de pipeline omni-cert-* (5 règles déjà créées) : la source Cert Orchestrator
#      devient event_source=cert_orchestrator (cert_parc est la source PKI Windows de
#      bx-pki2022, à laquelle ce script ne touche pas). Le texte attendu est lu dans
#      99-cert-orchestrator.sh (source unique) ; une règle différente est mise à jour par
#      PUT /system/pipelines/rule/<id>, puis relue.
#   2. Index set omni-cert : rotation P1M et 3 index conservés (90 j, comme
#      83-retention-consolidee.sh et POLITIQUE-RETENTION.md) au lieu de P1D x 90 copié du
#      modèle omni-fortigate. PUT /system/indices/index_sets/<id> sur la configuration relue,
#      seuls la période et le compteur changent. Refus si la stratégie n'est pas la rotation
#      temporelle héritée avec suppression, si OpenSearch est illisible, si plus de 3 index
#      omni-cert existent (Graylog supprimerait les plus anciens) ou si la configuration a
#      changé entre le plan et l'écriture. Aucun index n'est supprimé ni réindexé.
# Le seuil du watchdog pour cert_orchestrator (/etc/default/omni-watchdog) est affiché,
# jamais écrit : il ne doit être ajouté qu'après réception du premier message.
# Code retour : 0 conforme ou appliqué ; 2 refus ou écart en plan ; 1 erreur.
# Variables : OMNI_CONFIG_FILE (défaut <dépôt>/00-vars.env), OS_URL (http://127.0.0.1:9200).
# =============================================================================
set -uo pipefail
export LANG=C.UTF-8
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --plan) APPLY=0 ;;
    -h|--help) sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "option inconnue : $arg (voir --help)" >&2; exit 2 ;;
  esac
done
cd "$ROOT" || exit 1
CONFIG="${OMNI_CONFIG_FILE:-$ROOT/00-vars.env}"
[[ -r "$CONFIG" ]] || { echo "ERREUR : $CONFIG illisible (lancer en root depuis le dépôt canonique)" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONFIG"
# shellcheck disable=SC1091
source ./lib-graylog.sh
[[ $APPLY == 0 || $EUID -eq 0 || "${OMNI_TEST_MODE:-}" == 1 ]] || die "--apply exige root"
require_api || exit 1
OS="${OS_URL:-http://127.0.0.1:9200}"
PREFIXE=omni-cert
PERIODE=P1M
CONSERVES=3
REGLES=(omni-cert-00-tag omni-cert-05-sev-eleve omni-cert-05-sev-moyen omni-cert-05-sev-info omni-cert-10-error)
TIMEBASED="org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"
DELETION="org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"
ECARTS=0; REFUS=0

# source_attendue TITRE : corps du heredoc ensure_rule "TITRE" de 99-cert-orchestrator.sh.
source_attendue() {
  awk -v t="$1" '$0 == "ensure_rule \"" t "\" <<'"'"'EOF'"'"'" {f=1; next} f && $0 == "EOF" {exit} f {print}' 99-cert-orchestrator.sh
}

echo "=============================================================================="
echo " maj-cert-orchestrator-prod.sh (mode : $([[ $APPLY == 1 ]] && echo 'APPLICATION (--apply)' || echo 'PLAN (lecture seule)'))"
echo "=============================================================================="

echo "==> [1/2] Règles de pipeline omni-cert-* (source cert_orchestrator)"
TOUTES="$(api_get /system/pipelines/rule)" || die "lecture des règles en échec"
declare -A A_METTRE=()
for T in "${REGLES[@]}"; do
  ATT="$(source_attendue "$T")"
  if [[ -z "$ATT" || "$ATT" != *cert_orchestrator* || "$ATT" == *'"cert_parc"'* ]]; then
    warn "$T : texte attendu introuvable ou incohérent dans 99-cert-orchestrator.sh"; REFUS=$((REFUS + 1)); continue
  fi
  CUR="$(jq -c --arg t "$T" '[.[] | select(.title==$t)]' <<<"$TOUTES")"
  case "$(jq 'length' <<<"$CUR")" in
    0) warn "$T : règle absente en production (non créée ici : rejouer 99-cert-orchestrator.sh)"; REFUS=$((REFUS + 1)); continue ;;
    1) ;;
    *) warn "$T : plusieurs règles portent ce titre, aucune modification"; REFUS=$((REFUS + 1)); continue ;;
  esac
  ID="$(jq -r '.[0].id' <<<"$CUR")"
  if [[ "$(jq -r '.[0].source' <<<"$CUR")" == "$ATT" ]]; then
    skip "$T ($ID) conforme"
  else
    echo "    [~] $T ($ID) à mettre à jour :"
    diff <(jq -r '.[0].source' <<<"$CUR") <(printf '%s\n' "$ATT") | sed -n 's/^[<>].*/        &/p'
    A_METTRE[$T]="$ID"; ECARTS=$((ECARTS + 1))
  fi
done

echo "==> [2/2] Index set $PREFIXE (rotation $PERIODE, $CONSERVES index conservés)"
SETS="$(api_get '/system/indices/index_sets?skip=0&limit=200')" || die "lecture des index sets en échec"
JSET="$(jq -c --arg p "$PREFIXE" '[.index_sets[]|select(.index_prefix==$p)][0] // empty' <<<"$SETS")"
IS_APPLIQUER=0
if [[ -z "$JSET" ]]; then
  warn "index set $PREFIXE absent (non créé ici)"; REFUS=$((REFUS + 1))
else
  IS_ID="$(jq -r '.id' <<<"$JSET")"
  PCUR="$(jq -r '.rotation_strategy.rotation_period // ""' <<<"$JSET")"
  KCUR="$(jq -r '.retention_strategy.max_number_of_indices // ""' <<<"$JSET")"
  INDEX="$(curl -s -m 30 "$OS/_cat/indices/${PREFIXE}_*?h=index,docs.count" 2>/dev/null)"; RC=$?
  NB="?"; [[ $RC == 0 ]] && NB="$(grep -cE "^${PREFIXE}_[0-9]+ " <<<"$INDEX")"
  DOCS="$(awk '{s += $2} END {print s + 0}' <<<"$INDEX")"
  echo "    actuel : rotation ${PCUR:-?} x ${KCUR:-?} index ; index existants : $NB ; documents : $DOCS"
  if [[ "$(jq -r '.rotation_strategy_class // ""' <<<"$JSET")" != "$TIMEBASED" \
     || "$(jq -r '.retention_strategy_class // ""' <<<"$JSET")" != "$DELETION" \
     || "$(jq -r '.use_legacy_rotation' <<<"$JSET")" != true \
     || "$(jq -r '.data_tiering' <<<"$JSET")" != null ]]; then
    warn "stratégie autre que rotation temporelle héritée + suppression : aucune modification"; REFUS=$((REFUS + 1))
  elif [[ "$PCUR" == "$PERIODE" && "$KCUR" == "$CONSERVES" ]]; then
    skip "index set $PREFIXE conforme"
  elif [[ "$NB" == "?" ]]; then
    warn "OpenSearch illisible : nombre d'index inconnu, aucune modification"; REFUS=$((REFUS + 1))
  elif (( NB > CONSERVES )); then
    warn "$NB index existants pour $CONSERVES conservés : Graylog supprimerait des index, aucune modification"; REFUS=$((REFUS + 1))
  else
    echo "    [~] à aligner : ${PCUR} x ${KCUR} -> ${PERIODE} x ${CONSERVES} (aucun index supprimé : $NB <= $CONSERVES)"
    IS_APPLIQUER=1; ECARTS=$((ECARTS + 1))
  fi
fi

echo
if [[ $APPLY == 0 ]]; then
  echo "Plan : $ECARTS écart(s) à corriger, $REFUS refus. Appliquer : sudo bash $0 --apply"
  ECHEC=0
else
  ECHEC=0
  for T in "${!A_METTRE[@]}"; do
    ID="${A_METTRE[$T]}"
    ACTUELLE="$(api_get "/system/pipelines/rule/$ID")" || { warn "$T : relecture en échec"; ECHEC=1; continue; }
    CORPS="$(jq -c --arg s "$(source_attendue "$T")" '{id, title, description, source: $s}' <<<"$ACTUELLE")"
    if api_put "/system/pipelines/rule/$ID" <<<"$CORPS" >/dev/null \
       && [[ "$(api_get "/system/pipelines/rule/$ID" | jq -r '.source')" == "$(source_attendue "$T")" ]]; then
      ok "$T mise à jour et relue"
    else
      warn "$T : mise à jour en échec"; ECHEC=1
    fi
  done
  if [[ $IS_APPLIQUER == 1 ]]; then
    COURANT="$(api_get "/system/indices/index_sets/$IS_ID")" || die "relecture de l'index set en échec"
    if [[ "$(jq -Sc . <<<"$COURANT")" != "$(jq -Sc . <<<"$JSET")" ]]; then
      warn "index set modifié depuis le plan : aucune écriture"; ECHEC=1
    else
      CORPS="$(jq -c --arg p "$PERIODE" --argjson k "$CONSERVES" \
        '.rotation_strategy.rotation_period = $p | .retention_strategy.max_number_of_indices = $k' <<<"$COURANT")"
      REP="$(api_put "/system/indices/index_sets/$IS_ID" <<<"$CORPS")"
      if jq -e --arg id "$IS_ID" --arg p "$PERIODE" --argjson k "$CONSERVES" \
           '.id == $id and .rotation_strategy.rotation_period == $p and .retention_strategy.max_number_of_indices == $k' >/dev/null 2>&1 <<<"$REP"; then
        ok "index set $PREFIXE -> $PERIODE x $CONSERVES"
      else
        warn "index set $PREFIXE : confirmation invalide"; ECHEC=1
      fi
    fi
  fi
  [[ $ECHEC == 0 ]] && echo "Application terminée." || echo "Application incomplète : voir les avertissements." >&2
fi
cat <<EOF

Contrôles et étape manuelle (non exécutés) :
  - réception : curl -s '$OS/omni-*/_count?q=event_source:cert_orchestrator' | jq .count
  - PKI intacte : curl -s '$OS/omni-winother_*/_count?q=event_source:cert_parc' | jq .count
  - après le premier message cert_orchestrator : ajouter ',cert_orchestrator:2880' à la ligne
    WATCHDOG_SOURCES de /etc/default/omni-watchdog (cert_parc:2880 reste pour la PKI).
EOF
[[ $ECHEC == 1 ]] && exit 1
[[ $REFUS -gt 0 ]] && exit 2
[[ $APPLY == 0 && $ECARTS -gt 0 ]] && exit 2
exit 0
