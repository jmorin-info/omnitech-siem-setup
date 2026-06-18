#!/usr/bin/env bash
# =============================================================================
# 32-disk-guard.sh - Garde-fou disque /data (toutes les 6 h via timer systemd)
# -----------------------------------------------------------------------------
# Reponse au "et si le disque se remplit ?" :
#   < 80 %  : rien (la retention normale supprime les index a J+retention).
#   >= 80 % : alerte mail "Disque SIEM >80%" (revoir le plan 31-retention-iso).
#   >= 88 % : PURGE D'URGENCE -> suppression des index omni-* les plus ANCIENS
#             (jamais l'index actif d'un flux) jusqu'a repasser sous 82 %,
#             + alerte mail. Derniere ligne de defense AVANT les watermarks
#             OpenSearch (95 % = indices en lecture seule = collecte stoppee).
# Statuts envoyes en GELF -> alertes provisionnees par 21 (section [5/5]).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh

GELF_URL="http://127.0.0.1:12201/gelf"
SEUIL_WARN=80
SEUIL_PRUNE=88
CIBLE=82
MAX_SUPPR=20    # garde-fou du garde-fou

usage_pct() { df --output=pcent /data | tail -1 | tr -dc '0-9'; }
gelf() {  # gelf <action> <message>
  curl -s -m 10 -X POST "${GELF_URL}" -H 'Content-Type: application/json' -d "{
    \"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",
    \"short_message\":\"disk guard: ${2}\",
    \"_event_source\":\"siem_disk_guard\",\"_event_action\":\"${1}\",
    \"_disk_pct\":$(usage_pct)}" >/dev/null 2>&1 || true
}

U="$(usage_pct)"
if (( U < SEUIL_WARN )); then
  echo "/data a ${U}% : OK"
  exit 0
fi
if (( U < SEUIL_PRUNE )); then
  gelf disk_warn "/data a ${U}% (seuil ${SEUIL_WARN}%) - revoir 31-retention-iso.sh"
  echo "WARN : /data a ${U}%"
  exit 0
fi

# --- Purge d'urgence : index omni-* les plus anciens d'abord ------------------
gelf disk_guard_prune "demarrage purge d'urgence a ${U}%"
SUPPR=0
while (( $(usage_pct) > CIBLE && SUPPR < MAX_SUPPR )); do
  IDX="$(curl -s '127.0.0.1:9200/_cat/indices/omni-*?h=index,creation.date&s=creation.date' \
        | head -1 | awk '{print $1}')"
  [[ -z "${IDX}" ]] && break
  PFX="${IDX%_*}"
  NB="$(curl -s "127.0.0.1:9200/_cat/indices/${PFX}_*?h=index" | wc -l)"
  if (( NB <= 1 )); then break; fi   # jamais le seul/actif index d'un flux
  api_del "/system/indexer/indices/${IDX}" >/dev/null || break
  echo "supprime : ${IDX}"
  SUPPR=$((SUPPR+1))
  sleep 3
done
gelf disk_guard_prune "purge terminee : ${SUPPR} index supprimes, /data a $(usage_pct)%"
echo "PURGE : ${SUPPR} index supprimes, /data a $(usage_pct)%"
