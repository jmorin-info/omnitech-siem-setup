#!/usr/bin/env bash
# =============================================================================
# 40-purge-logs.sh - PURGE des LOGS (repart d'une base saine) - MANUEL UNIQUEMENT
# -----------------------------------------------------------------------------
# Efface le CONTENU des index de logs (omni-*, gl-events, gl-system-events,
# graylog default) pour repartir propre apres la phase de build/tests.
# NE TOUCHE PAS a la configuration (MongoDB : streams, pipelines, alertes,
# dashboards, users, backends) ni aux docs.
#
# ATTENTION : IRREVERSIBLE (les logs ne sont pas sauvegardes). Action de
# maintenance ponctuelle, JAMAIS planifiee. Garde-fou : exige CONFIRM=OUI.
#
# Methode (propre, supportee) : stop graylog -> delete index OpenSearch ->
# start graylog (recree des index vides _0) -> purge indexer failures ->
# recalcul des ranges. Interruption de collecte ~1-2 min (agents/FAZ
# bufferisent et retransmettent).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh

[[ "${CONFIRM:-}" == "OUI" ]] || { echo "Refus : relancer avec CONFIRM=OUI (action destructive irreversible)"; exit 1; }

PATTERNS="omni-fortigate_* omni-winsec_* omni-winother_* omni-sysmon_* omni-vsphere_* omni-m365_* gl-events_* gl-system-events_*"

echo "==> [1/6] Sauvegarde config de securite"
bash ./30-backup-config.sh 2>&1 | tail -1 || echo "  (sauvegarde non bloquante)"

echo "==> [2/6] Arret de Graylog (l'ingestion s'arrete, les agents bufferisent)"
systemctl stop graylog-server

echo "==> [3/6] Suppression des index de logs (OpenSearch)"
for P in ${PATTERNS}; do
  curl -s -X DELETE "127.0.0.1:9200/${P}" -o /dev/null -w "  ${P} -> %{http_code}\n"
done
# index "default" graylog : on vide le contenu (garde l'index systeme)
curl -s -X POST "127.0.0.1:9200/graylog_*/_delete_by_query?conflicts=proceed&refresh=true" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' -o /dev/null -w "  graylog_* (vide) -> %{http_code}\n"

echo "==> [4/6] Purge de l'historique des echecs d'indexation (MongoDB)"
MONGO_URI="$(grep -E '^mongodb_uri' /etc/graylog/server/server.conf | sed 's/^[^=]*=[[:space:]]*//')"
mongosh "${MONGO_URI}" --quiet --eval 'db.index_failures.deleteMany({}); print("index_failures purgee")' || echo "  (purge failures non bloquante)"

echo "==> [5/6] Redemarrage de Graylog (recreation des index vides)"
systemctl start graylog-server
printf "  attente du demarrage"
for i in $(seq 1 60); do
  if curl -s -o /dev/null -w '%{http_code}' --cacert /etc/graylog/certs/omnitech-rootca.crt \
       -u "admin:${GRAYLOG_ADMIN_PASS}" "https://${SIEM_FQDN}:9000/api/system/lbstatus" | grep -q 200; then
    echo " OK"; break
  fi
  printf "."; sleep 5
done

echo "==> [6/6] Recalcul des index ranges"
"${CURL[@]}" -X POST -H "X-Requested-By: cli" "${API}/system/indices/ranges/rebuild" -o /dev/null -w "  rebuild ranges -> %{http_code}\n" || true

echo
echo "Etat des index apres purge :"
curl -s "127.0.0.1:9200/_cat/indices/omni-*,gl-events*,gl-system*?h=index,docs.count,store.size&s=index"
echo "=== 40-purge-logs.sh termine : base de logs saine. La collecte temps reel reprend. ==="
