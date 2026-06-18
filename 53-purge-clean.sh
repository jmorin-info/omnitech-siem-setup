#!/usr/bin/env bash
# =============================================================================
# 53-purge-clean.sh - PURGE des donnees (repartir propre). DESTRUCTIF.
#   Supprime toutes les donnees de logs + l'historique d'alertes, en conservant
#   TOUTE la configuration (streams, pipelines, regles, lookups, inputs, alertes,
#   notifications, dashboards). Methode : cycle deflector (nouvel index d'ecriture
#   vide) puis suppression des anciens index via l'API Graylog (nettoie les ranges).
#   gl-system-events (interne Graylog) est conserve.
# A n'executer qu'apres validation des correctifs de faux positifs.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
GL="https://127.0.0.1:9000/api"; AUTH=(-u "admin:${GRAYLOG_ADMIN_PASS}")
C=(curl -sk -H X-Requested-By:cli)
OSURL="http://127.0.0.1:9200"

PREFIXES="graylog gl-events omni-bunkerweb omni-eset omni-fortigate omni-m365 omni-sysmon omni-vsphere omni-winother omni-winsec"

# id d'index set par prefixe
declare -A IDSET
while IFS=$'\t' read -r pfx id; do IDSET[$pfx]="$id"; done < <(
  "${C[@]}" "${AUTH[@]}" "$GL/system/indices/index_sets?limit=200&stats=false" \
    | python3 -c "import sys,json;[print(s['index_prefix']+chr(9)+s['id']) for s in json.load(sys.stdin)['index_sets']]")

before=$(curl -s "$OSURL/_cat/indices/omni-*,graylog_*,gl-events_*?h=docs.count" 2>/dev/null | awk '{s+=$1} END{print s}')
echo "==> Docs avant purge : ${before}"

for pfx in $PREFIXES; do
  id="${IDSET[$pfx]:-}"
  [[ -z "$id" ]] && { echo "  [!] $pfx : index set introuvable, saute"; continue; }
  # 1) cycle -> nouvel index d'ecriture vide. ATTENTION : l'id va dans le CHEMIN
  # (/system/deflector/{id}/cycle) ; la variante ?index_set_id= cycle le set par defaut.
  "${C[@]}" "${AUTH[@]}" -X POST "$GL/system/deflector/${id}/cycle" -o /dev/null
  sleep 2
  # 2) index d'ecriture actif (a conserver)
  active="$(curl -s "$OSURL/_cat/aliases/${pfx}_deflector?h=index" 2>/dev/null | head -1 | tr -d ' ')"
  # 3) supprimer tous les autres index du prefixe via l'API Graylog (range inclus)
  for idx in $(curl -s "$OSURL/_cat/indices/${pfx}_*?h=index" 2>/dev/null | tr -d ' '); do
    [[ "$idx" == "$active" ]] && continue
    "${C[@]}" "${AUTH[@]}" -X DELETE "$GL/system/indexer/indices/${idx}" -o /dev/null \
      && echo "  [-] supprime ${idx}"
  done
  echo "  [=] ${pfx} : conserve ${active} (vide)"
done

# 4) recalcul des ranges
"${C[@]}" "${AUTH[@]}" -X POST "$GL/system/indices/ranges/rebuild" -o /dev/null
sleep 2
after=$(curl -s "$OSURL/_cat/indices/omni-*,graylog_*,gl-events_*?h=docs.count" 2>/dev/null | awk '{s+=$1} END{print s}')
echo "==> Docs apres purge : ${after} (avant ${before})"
echo "=== Purge terminee. Ingestion reprend dans des index vides. Config intacte. ==="

# Repopulation automatique : enchaine sur 54 pour relancer les robots et eviter
# que les dashboards derives restent vides en attendant les timers (anti-purge).
if [[ "${PURGE_NO_REPOP:-0}" != "1" && -x ./54-post-purge-repopulate.sh ]]; then
  echo; echo "==> Enchainement repopulation (54-post-purge-repopulate.sh)"
  bash ./54-post-purge-repopulate.sh
fi
