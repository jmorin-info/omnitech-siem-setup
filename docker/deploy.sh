#!/usr/bin/env bash
# =============================================================================
# docker/deploy.sh - Monte la stack SIEM Docker et (option) RESTAURE la conf complete.
#   ./deploy.sh up                         # monte Graylog + OpenSearch + MongoDB
#   ./deploy.sh restore <archive[.enc]>    # + restaure la conf (dump 30-backup-config.sh)
#   ./deploy.sh status | down | logs
#
#   MongoDB restores Graylog configuration; OpenSearch logs and external service
#   state require separate recovery. See README-DOCKER.md for compatibility.
#   Le dechiffrement reprend les parametres de 30-backup-config.sh (aes-256-cbc
#   pbkdf2 iter 200000) -> demande la BACKUP_PASSPHRASE (du coffre).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
DC="docker compose"
command -v docker >/dev/null || { echo "Docker requis."; exit 1; }
[[ -f .env ]] || { echo "[!] copier .env.example en .env et renseigner les secrets."; [[ "${1:-}" == "up" || "${1:-}" == "restore" ]] && exit 1; }

check_existing_database() {
  local mid image gid
  mid="$($DC ps -aq mongodb)"
  if [[ -n "$mid" ]]; then
    image="$(docker inspect --format '{{.Config.Image}}' "$mid")"
    [[ "$image" == mongo:8.0* ]] || { echo "Refus: existing Mongo image $image needs a documented migration to8.0 before this bundle." >&2; exit 1; }
  elif docker volume inspect omni-siem_mongo_data >/dev/null 2>&1; then
    echo "Refus: an orphan Mongo volume exists. Verify its version and restore on fresh volumes; no automatic DB migration." >&2
    exit 1
  fi
  gid="$($DC ps -aq graylog)"
  if [[ -n "$gid" ]]; then
    image="$(docker inspect --format '{{.Config.Image}}' "$gid")"
    [[ "$image" == graylog/graylog:7.2.* ]] || { echo "Refus: existing Graylog image $image needs a separate migration to7.2." >&2; exit 1; }
  fi
}

case "${1:-help}" in
  up)
    check_existing_database
    $DC config --quiet
    $DC up -d
    echo "Stack montee. Console : $(grep -E '^GRAYLOG_HTTP_EXTERNAL_URI' .env 2>/dev/null | cut -d= -f2 || echo http://127.0.0.1:9000/)"
    echo "Le 1er demarrage de Graylog prend ~1-2 min (indices + migrations)." ;;
  down)    $DC down ;;
  status)  $DC ps ;;
  logs)    $DC logs -f --tail=120 "${2:-graylog}" ;;
  restore)
    [[ "${CONFIRM_RESTORE:-}" == YES ]] || { echo "Restore overwrites Graylog configuration. Require CONFIRM_RESTORE=YES." >&2; exit 1; }
    [[ "${SOURCE_MONGODB_SERIES:-}" == 8.0 && "${SOURCE_GRAYLOG_SERIES:-}" == 7.2 ]] || { echo "Verify backup metadata, then set SOURCE_MONGODB_SERIES=8.0 SOURCE_GRAYLOG_SERIES=7.2. Other versions require a separate migration." >&2; exit 1; }
    check_existing_database
    ARCH="${2:?usage: $0 restore <archive.tar.gz[.enc]>}"
    [[ -f "$ARCH" ]] || { echo "archive introuvable: $ARCH"; exit 1; }
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    echo "==> [1/5] Extraction de l'archive de conf"
    if [[ "$ARCH" == *.enc ]]; then
      read -rsp "BACKUP_PASSPHRASE (coffre) : " PASS; echo
      OMNI_RESTORE_PASSPHRASE="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$ARCH" -pass env:OMNI_RESTORE_PASSPHRASE > "$TMP/archive.tar.gz"
      unset PASS
    else
      cp "$ARCH" "$TMP/archive.tar.gz"
    fi
    python3 - "$TMP/archive.tar.gz" "$TMP" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2], filter="data")
PY
    [[ -d "$TMP/mongodump/graylog" ]] || { echo "[KO] dump Mongo Graylog absent de l'archive."; exit 1; }
    echo "==> [2/5] Demarrage de MongoDB"
    $DC up -d mongodb
    for i in $(seq 1 30); do $DC exec -T mongodb mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1 && break; sleep 2; done
    echo "==> [3/5] mongorestore de la conf Graylog (--drop)"
    $DC stop graylog console nginx
    MID="$($DC ps -q mongodb)"
    docker cp "$TMP/mongodump/graylog" "${MID}:/tmp/dump_graylog"
    $DC exec -T mongodb mongorestore --drop --db graylog /tmp/dump_graylog
    echo "==> [4/5] Demarrage de la stack + lookups"
    if [[ -d "$TMP/etc/graylog/lookup" ]]; then
      # Lookups are bind mounted read-only, so restore the host directory first.
      mkdir -p runtime-lookups
      cp -a "$TMP/etc/graylog/lookup/." runtime-lookups/
      export GRAYLOG_LOOKUP_DIR=./runtime-lookups
      python3 - <<'PY'
from pathlib import Path
p = Path('.env')
lines = [line for line in p.read_text().splitlines() if not line.startswith('GRAYLOG_LOOKUP_DIR=')]
p.write_text('\n'.join([*lines, 'GRAYLOG_LOOKUP_DIR=./runtime-lookups']) + '\n')
p.chmod(0o600)
PY
    fi
    $DC up -d
    echo "==> [5/5] Redemarrage de Graylog (prise en compte conf + lookups)"
    $DC restart graylog
    echo "=== Conf restauree. Console prete dans ~1-2 min : verifier streams/pipelines/detections. ===" ;;
  *)
    echo "Usage: $0 {up|down|status|logs [svc]|restore <archive.tar.gz[.enc]>}" ;;
esac
