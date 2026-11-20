#!/usr/bin/env bash
# ==============================================================================
# 08-backup.sh - Sauvegardes applicatives quotidiennes (ISO A.8.13)
#   Installe /usr/local/sbin/siem-backup.sh + timer systemd (02:30) :
#     1. mongodump (config Graylog : users, dashboards, streams, pipelines...)
#     2. snapshot OpenSearch (donnees indexees, incremental)
#     3. tar des configurations (/etc/graylog, opensearch, mongod, nginx, nft)
#     4. retention locale RETENTION_DAYS jours
#   La sauvegarde de VM et le test de restauration se configurent separement.
#   Exporter BACKUP_DIR vers un stockage protege hors du serveur
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
jq -n --arg path "${BACKUP_DIR}/opensearch-snapshots" \
  '{type:"fs",settings:{location:$path,compress:true}}' \
  | curl --fail --silent --show-error --connect-timeout 10 --max-time 60 \
      -X PUT "http://127.0.0.1:9200/_snapshot/graylog_fs" \
      -H 'Content-Type: application/json' -d @- \
  | jq -e '.acknowledged == true' >/dev/null

echo "==> [2/3] Script /usr/local/sbin/siem-backup.sh"
cat > /usr/local/sbin/siem-backup.sh <<'EOF'
#!/usr/bin/env bash
# Daily native MongoDB, OpenSearch and configuration backup.
# Site credentials are read privately at execution time, never embedded here.
set -uo pipefail
umask 077
source "${OMNI_CONFIG_FILE:?OMNI_CONFIG_FILE must point to the site configuration}" || exit 1
[[ "${RETENTION_DAYS}" =~ ^[1-9][0-9]*$ ]] || { echo "RETENTION_DAYS must be a positive integer." >&2; exit 1; }
SNAPSHOT_TIMEOUT="${BACKUP_SNAPSHOT_TIMEOUT_SECONDS:-3600}"
[[ "$SNAPSHOT_TIMEOUT" =~ ^[1-9][0-9]{0,4}$ ]] && (( SNAPSHOT_TIMEOUT <= 86400 )) \
  || { echo "BACKUP_SNAPSHOT_TIMEOUT_SECONDS must be an integer from 1 to 86400." >&2; exit 1; }
TS="$(date +%Y%m%d-%H%M%S)"
TODAY="$(date +%Y%m%d)"
LOG="${OMNI_BACKUP_LOG:-/var/log/siem-backup.log}"
exec >>"${LOG}" 2>&1
exec 9>"${BACKUP_DIR}/.native-backup.lock"
flock -n 9 || { echo "A native backup is already running."; exit 1; }
if [[ -e "${BACKUP_DIR}/mongo/graylog-mongo-${TS}.archive.gz" || -e "${BACKUP_DIR}/configs/siem-configs-${TS}.tar.gz" ]]; then
  sleep 1
  TS="$(date +%Y%m%d-%H%M%S)"
fi
echo "===== ${TS} : debut sauvegarde ====="

GELF_URL="http://127.0.0.1:12201/gelf"
gelf() {
  jq -cn --arg host "${SIEM_HOSTNAME:-$(hostname)}" --arg state "$1" --arg detail "$2" \
    '{version:"1.1",host:$host,short_message:("sauvegarde quotidienne SIEM " + $state + ": " + $detail),
      _event_source:"siem_backup",_event_action:("backup_daily_"+$state),_alert_tag:("backup_daily_"+$state)}' \
    | curl -s -m 10 -X POST "${GELF_URL}" -H 'Content-Type: application/json' -d @- >/dev/null || true
}
ECHEC=0
ko() { echo "ERREUR: $*"; gelf echec "$*"; ECHEC=1; }

# MongoDB: validate the generated compressed archive as well as mongodump's exit.
MONGO_BACKUP_PASS="$(MONGO_PASSWORD="$MONGO_ADMIN_PASS" python3 -c 'import os,urllib.parse; print(urllib.parse.quote(os.environ["MONGO_PASSWORD"],safe=""))')"
MONGO_ARCHIVE="${BACKUP_DIR}/mongo/graylog-mongo-${TS}.archive.gz"
if mongodump --quiet --gzip \
  --uri "mongodb://admin:${MONGO_BACKUP_PASS}@127.0.0.1:27017/?replicaSet=rs0&authSource=admin" \
  --archive="${MONGO_ARCHIVE}"; then
  if [[ -s "${MONGO_ARCHIVE}" ]] && gzip -t "${MONGO_ARCHIVE}"; then
    echo "mongodump OK"
  else ko "mongodump archive missing or invalid"; fi
else ko "mongodump failed"; fi

# A successful request is not a successful snapshot. Wait for this run's snapshot
# within the configured deadline, then fail the job if still incomplete.
OS_CURL=(curl --fail --silent --show-error --connect-timeout 10 --max-time 30)
OS_REPO="http://127.0.0.1:9200/_snapshot/graylog_fs"
if ! "${OS_CURL[@]}" "${OS_REPO}" | jq -e 'has("graylog_fs")' >/dev/null; then
  ko "snapshot repository graylog_fs is missing or inaccessible"
else
  if R="$("${OS_CURL[@]}" -X PUT "${OS_REPO}/snap-${TS}?wait_for_completion=false")" \
      && jq -e '.accepted == true' <<<"${R}" >/dev/null; then
    DEADLINE=$((SECONDS + SNAPSHOT_TIMEOUT)); SNAPSHOT_OK=0
    while (( SECONDS < DEADLINE )); do
      REMAINING=$((DEADLINE - SECONDS)); REQUEST_LIMIT=$((REMAINING < 20 ? REMAINING : 20))
      if CURRENT="$("${OS_CURL[@]}" --max-time "${REQUEST_LIMIT}" "${OS_REPO}/snap-${TS}")"; then
        STATE="$(jq -r '.snapshots[0].state // "ABSENT"' <<<"${CURRENT}")"
        case "$STATE" in
          SUCCESS) SNAPSHOT_OK=1; break ;;
          IN_PROGRESS|STARTED) ;;
          *) break ;;
        esac
      else break; fi
      (( SECONDS < DEADLINE )) && sleep 1
    done
    if [[ "$SNAPSHOT_OK" == 1 ]]; then echo "snapshot snap-${TS}: SUCCESS"
    else ko "snapshot snap-${TS} did not reach SUCCESS within ${SNAPSHOT_TIMEOUT} seconds"; fi
  else ko "snapshot request refused"; fi
fi

# Missing yesterday is normal on the first successful backup day, including a
# second manual run that day. Later days still detect a missed/failed backup.
FIRST_SUCCESS="${BACKUP_DIR}/.native-backup-first-success"
FIRST_DAY="$(cat "${FIRST_SUCCESS}" 2>/dev/null || true)"
if [[ -f "$FIRST_SUCCESS" && ! "$FIRST_DAY" =~ ^[0-9]{8}$ ]]; then
  ko "invalid first-success backup marker"
elif [[ -n "$FIRST_DAY" && "$FIRST_DAY" != "$TODAY" ]]; then
  HIER="$(date -d yesterday +%Y%m%d)"
  if PREVIOUS="$("${OS_CURL[@]}" "${OS_REPO}/snap-${HIER}-*")"; then
    ETAT_HIER="$(jq -r 'if any(.snapshots[]?; .state=="SUCCESS") then "SUCCESS" else "ABSENT_OR_FAILED" end' <<<"${PREVIOUS}")"
    [[ "$ETAT_HIER" == SUCCESS ]] && echo "snapshot veille (${HIER}): SUCCESS" || ko "snapshot de la veille absent ou incomplet"
  else ko "snapshot de la veille inaccessible"; fi
else
  echo "First successful backup day: no previous-day snapshot required."
fi

# Site credentials and optional console state are necessary to recover this site.
CONFIG_ARCHIVE="${BACKUP_DIR}/configs/siem-configs-${TS}.tar.gz"
CONFIG_PATHS=(/etc/graylog /etc/opensearch /etc/mongod.conf /etc/mongod.keyfile /etc/nginx/ssl
  /etc/nginx/sites-available/graylog /etc/nftables.conf /etc/chrony/chrony.conf
  /root/.graylog_password_secret "${OMNI_CONFIG_FILE}")
for OPTIONAL_PATH in /etc/default/omni-mobile /etc/omni-mobile /var/lib/omni-mobile /etc/nftables.d /etc/omni-siem; do
  [[ -e "$OPTIONAL_PATH" ]] && CONFIG_PATHS+=("$OPTIONAL_PATH")
done
if tar czf "${CONFIG_ARCHIVE}" "${CONFIG_PATHS[@]}" 2>/dev/null; then
  if [[ -s "${CONFIG_ARCHIVE}" ]] && tar tzf "${CONFIG_ARCHIVE}" >/dev/null 2>&1; then
    echo "tar configs OK"
  else ko "configuration archive missing or invalid"; fi
else ko "tar configs failed"; fi

# Only native backup names are owned here; unrelated archives/snapshots stay.
if [[ "${ECHEC}" -eq 0 ]]; then
find "${BACKUP_DIR}/mongo" -name 'graylog-mongo-*.archive.gz' -mtime +"${RETENTION_DAYS}" -delete || ko "MongoDB retention failed"
find "${BACKUP_DIR}/configs" -name 'siem-configs-*.tar.gz' -mtime +"${RETENTION_DAYS}" -delete || ko "configuration retention failed"
CUTOFF=$(( $(date +%s) - RETENTION_DAYS * 86400 ))
if SNAPSHOTS="$("${OS_CURL[@]}" "${OS_REPO}/_all")"; then
  if EXPIRED="$(jq -r --argjson c "${CUTOFF}" '.snapshots[] | select(.snapshot | test("^snap-[0-9]{8}-[0-9]{4}([0-9]{2})?$")) | select(.state=="SUCCESS" and (.end_time_in_millis/1000) < $c) | .snapshot' <<<"${SNAPSHOTS}")"; then
    for SNAP in $EXPIRED; do
      SNAP_DATE="${SNAP#snap-}"; SNAP_DAY="${SNAP_DATE%%-*}"; SNAP_CLOCK="${SNAP_DATE#*-}"
      SNAP_SECONDS="${SNAP_CLOCK:4:2}"; SNAP_SECONDS="${SNAP_SECONDS:-00}"
      date -d "${SNAP_DAY:0:4}-${SNAP_DAY:4:2}-${SNAP_DAY:6:2} ${SNAP_CLOCK:0:2}:${SNAP_CLOCK:2:2}:${SNAP_SECONDS}" >/dev/null 2>&1 || continue
      if "${OS_CURL[@]}" -X DELETE "${OS_REPO}/${SNAP}" | jq -e '.acknowledged == true' >/dev/null; then
        echo "snapshot ${SNAP} purge"
      else ko "snapshot retention failed"; fi
    done
  else ko "snapshot retention response invalid"; fi
else ko "snapshot retention inventory failed"; fi
fi

if [[ "${ECHEC}" -eq 0 ]]; then
  if [[ ! -f "$FIRST_SUCCESS" ]]; then
    printf '%s\n' "$TODAY" >"${FIRST_SUCCESS}.tmp" && mv -f "${FIRST_SUCCESS}.tmp" "${FIRST_SUCCESS}" || exit 1
  fi
  gelf ok "mongodump + snapshot + configs ${TS}"
  echo "===== ${TS} : fin sauvegarde (OK) ====="
else
  echo "===== ${TS} : fin sauvegarde (AU MOINS UN ECHEC) ====="
  exit 1
fi
EOF
chmod 700 /usr/local/sbin/siem-backup.sh   # contient des secrets
INSTALL_CONFIG="$(pwd)/00-vars.env"

echo "==> [3/3] Timer systemd (02:30 quotidien)"
cat > /etc/systemd/system/siem-backup.service <<EOF
[Unit]
Description=Sauvegarde applicative SIEM (Mongo + OpenSearch + configs)
[Service]
Type=oneshot
TimeoutStartSec=0
Environment="OMNI_CONFIG_FILE=${INSTALL_CONFIG}"
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
echo "==> Test immediat : systemctl start siem-backup.service puis consulter son resultat."
echo "=== 08-backup.sh termine. (Optionnel : 09-snmpd.sh pour Centreon) ==="
