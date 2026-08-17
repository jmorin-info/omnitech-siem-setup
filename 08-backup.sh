#!/usr/bin/env bash
# ==============================================================================
# 08-backup.sh - Sauvegardes applicatives quotidiennes (ISO A.8.13)
#   Installe /usr/local/sbin/siem-backup.sh + timer systemd (02:30) :
#     1. mongodump (config Graylog : users, dashboards, streams, pipelines...)
#     2. snapshot OpenSearch (donnees indexees, incremental)
#     3. tar des configurations (/etc/graylog, opensearch, mongod, nginx, nft)
#     4. retention locale RETENTION_DAYS jours
#   Veeam sauvegarde la VM entiere ; ces dumps applicatifs garantissent en plus
#   une restauration coherente/granulaire. Exporter BACKUP_DIR vers le NAS
#   (rsync/NFS) pour sortir les preuves de l'hote (anti-effacement).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

mkdir -p "${BACKUP_DIR}/mongo" "${BACKUP_DIR}/configs" "${BACKUP_DIR}/opensearch-snapshots"
# 751 : permet a l'utilisateur opensearch de TRAVERSER jusqu'a son depot de
# snapshots, sans pouvoir lister le contenu de BACKUP_DIR.
chmod 751 "${BACKUP_DIR}"
# 700 : dumps Mongo + archives de configs contiennent des secrets (keyfile,
# password_secret, hashs) -> root uniquement.
chmod 700 "${BACKUP_DIR}/mongo" "${BACKUP_DIR}/configs"
chown opensearch:opensearch "${BACKUP_DIR}/opensearch-snapshots"

echo "==> [1/3] Enregistrement du depot de snapshots OpenSearch"
curl -s -X PUT "http://127.0.0.1:9200/_snapshot/graylog_fs" \
  -H 'Content-Type: application/json' \
  -d "{\"type\":\"fs\",\"settings\":{\"location\":\"${BACKUP_DIR}/opensearch-snapshots\",\"compress\":true}}" | jq .

echo "==> [2/3] Script /usr/local/sbin/siem-backup.sh"
cat > /usr/local/sbin/siem-backup.sh <<'EOF'
#!/usr/bin/env bash
# Sauvegarde quotidienne SIEM OMNITECH (installe par 08-backup.sh)
# Durci 02/07/2026 : chaque etape est CONTROLEE et tout echec remonte en GELF
# (event_source=siem_backup, alert_tag=backup_daily_echec) -> alerte Graylog.
# Motif : le snapshot OpenSearch a echoue EN SILENCE du 15/06 au 02/07 (depot
# perdu apres le crash Mongo du 26/06, erreur jq avalee par le pipe).
# Les parametres (MONGO_ADMIN_PASS, BACKUP_DIR, RETENTION_DAYS) sont lus a
# l'EXECUTION dans 00-vars.env (600 root) : pas de secret duplique ici.
set -uo pipefail
source /root/omnitech-siem-setup/00-vars.env
TS="$(date +%Y%m%d-%H%M)"
LOG="/var/log/siem-backup.log"
exec >>"${LOG}" 2>&1
echo "===== ${TS} : debut sauvegarde ====="

GELF_URL="http://127.0.0.1:12201/gelf"
gelf() {  # gelf <ok|echec> <message>
  curl -s -m 10 -X POST "${GELF_URL}" -H 'Content-Type: application/json' -d "{
    \"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",
    \"short_message\":\"sauvegarde quotidienne SIEM ${1}: ${2}\",
    \"_event_source\":\"siem_backup\",\"_event_action\":\"backup_daily_${1}\",
    \"_alert_tag\":\"backup_daily_${1}\"}" >/dev/null || true
}
ECHEC=0
ko() { echo "ERREUR: $*"; gelf echec "$*"; ECHEC=1; }

# 1) MongoDB (configuration Graylog)
if mongodump --quiet --gzip \
  --uri "mongodb://admin:${MONGO_ADMIN_PASS}@127.0.0.1:27017/?replicaSet=rs0&authSource=admin" \
  --archive="${BACKUP_DIR}/mongo/graylog-mongo-${TS}.archive.gz"; then
  echo "mongodump OK"
else
  ko "mongodump rc=$?"
fi

# 2) Snapshot OpenSearch (incremental) - VERIFIE que le depot existe et que
#    la demande est acceptee (le depot peut disparaitre : crash du 26/06/2026).
if ! curl -s "http://127.0.0.1:9200/_snapshot/graylog_fs" | grep -q '"graylog_fs"'; then
  ko "depot de snapshots graylog_fs ABSENT (repository_missing) - relancer l'etape 1/3 de 08-backup.sh"
else
  R="$(curl -s -X PUT "http://127.0.0.1:9200/_snapshot/graylog_fs/snap-${TS}?wait_for_completion=false")"
  if echo "${R}" | grep -q '"accepted":true'; then
    echo "snapshot OpenSearch snap-${TS} lance"
  else
    ko "snapshot refuse: ${R:0:200}"
  fi
fi

# 2bis) Controle du snapshot de la VEILLE : lance hier, il doit etre SUCCESS
#       aujourd'hui (detecte PARTIAL/FAILED/ABSENT, pas seulement le refus).
HIER="$(date -d yesterday +%Y%m%d)"
ETAT_HIER="$(curl -s "http://127.0.0.1:9200/_snapshot/graylog_fs/snap-${HIER}-*" 2>/dev/null \
  | jq -r '.snapshots[-1].state // "ABSENT"' 2>/dev/null || echo INCONNU)"
case "${ETAT_HIER}" in
  SUCCESS|IN_PROGRESS|STARTED) echo "snapshot veille (${HIER}): ${ETAT_HIER}" ;;
  *) ko "snapshot de la veille ${HIER}: ${ETAT_HIER}" ;;
esac

# 3) Configurations
if tar czf "${BACKUP_DIR}/configs/siem-configs-${TS}.tar.gz" \
  /etc/graylog /etc/opensearch /etc/mongod.conf /etc/mongod.keyfile /etc/nginx/ssl \
  /etc/nginx/sites-available/graylog /etc/nftables.conf \
  /etc/chrony/chrony.conf /root/.graylog_password_secret 2>/dev/null; then
  echo "tar configs OK"
else
  ko "tar configs rc=$?"
fi

# 4) Retention : fichiers locaux
find "${BACKUP_DIR}/mongo"   -name '*.archive.gz' -mtime +${RETENTION_DAYS} -delete
find "${BACKUP_DIR}/configs" -name '*.tar.gz'     -mtime +${RETENTION_DAYS} -delete

# 4bis) Retention : snapshots (suppression via API, JAMAIS via find !)
CUTOFF=$(( $(date +%s) - RETENTION_DAYS * 86400 ))
for SNAP in $(curl -s "http://127.0.0.1:9200/_snapshot/graylog_fs/_all" \
  | jq -r --argjson c "${CUTOFF}" '.snapshots[] | select(.state=="SUCCESS" and (.end_time_in_millis/1000) < $c) | .snapshot' 2>/dev/null); do
  curl -s -X DELETE "http://127.0.0.1:9200/_snapshot/graylog_fs/${SNAP}" >/dev/null
  echo "snapshot ${SNAP} purge"
done

if [[ "${ECHEC}" -eq 0 ]]; then
  gelf ok "mongodump + snapshot + configs ${TS}"
  echo "===== ${TS} : fin sauvegarde (OK) ====="
else
  echo "===== ${TS} : fin sauvegarde (AU MOINS UN ECHEC) ====="
  exit 1
fi
EOF
chmod 700 /usr/local/sbin/siem-backup.sh   # contient des secrets

echo "==> [3/3] Timer systemd (02:30 quotidien)"
cat > /etc/systemd/system/siem-backup.service <<'EOF'
[Unit]
Description=Sauvegarde applicative SIEM (Mongo + OpenSearch + configs)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/siem-backup.sh
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF
cat > /etc/systemd/system/siem-backup.timer <<'EOF'
[Unit]
Description=Declencheur quotidien sauvegarde SIEM
[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=10m
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now siem-backup.timer
systemctl list-timers siem-backup.timer --no-pager

echo
echo "==> Test immediat ? /usr/local/sbin/siem-backup.sh puis tail /var/log/siem-backup.log"
echo "=== 08-backup.sh termine. (Optionnel : 09-snmpd.sh pour Centreon) ==="
