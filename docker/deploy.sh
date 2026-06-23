#!/usr/bin/env bash
# =============================================================================
# docker/deploy.sh - Monte la stack SIEM Docker et (option) RESTAURE la conf complete.
#   ./deploy.sh up                         # monte Graylog + OpenSearch + MongoDB
#   ./deploy.sh restore <archive[.enc]>    # + restaure la conf (dump 30-backup-config.sh)
#   ./deploy.sh status | down | logs
#
#   La conf Graylog ENTIERE (streams, pipelines, 136 detections, lookups, alertes,
#   notifications) est dans MongoDB : un mongorestore = la plateforme complete.
#   Le dechiffrement reprend les parametres de 30-backup-config.sh (aes-256-cbc
#   pbkdf2 iter 200000) -> demande la BACKUP_PASSPHRASE (du coffre).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
DC="docker compose"
command -v docker >/dev/null || { echo "Docker requis."; exit 1; }
[[ -f .env ]] || { echo "[!] copier .env.example en .env et renseigner les secrets."; [[ "${1:-}" == "up" || "${1:-}" == "restore" ]] && exit 1; }

case "${1:-help}" in
  up)
    $DC up -d
    echo "Stack montee. Console : $(grep -E '^GRAYLOG_HTTP_EXTERNAL_URI' .env 2>/dev/null | cut -d= -f2 || echo http://127.0.0.1:9000/)"
    echo "Le 1er demarrage de Graylog prend ~1-2 min (indices + migrations)." ;;
  down)    $DC down ;;
  status)  $DC ps ;;
  logs)    $DC logs -f --tail=120 "${2:-graylog}" ;;
  restore)
    ARCH="${2:?usage: $0 restore <archive.tar.gz[.enc]>}"
    [[ -f "$ARCH" ]] || { echo "archive introuvable: $ARCH"; exit 1; }
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    echo "==> [1/5] Extraction de l'archive de conf"
    if [[ "$ARCH" == *.enc ]]; then
      read -rsp "BACKUP_PASSPHRASE (coffre) : " PASS; echo
      openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$ARCH" -pass "pass:${PASS}" | tar xz -C "$TMP"
    else
      tar xzf "$ARCH" -C "$TMP"
    fi
    [[ -d "$TMP/mongodump/graylog" ]] || { echo "[KO] dump Mongo Graylog absent de l'archive."; exit 1; }
    echo "==> [2/5] Demarrage de MongoDB"
    $DC up -d mongodb
    for i in $(seq 1 30); do $DC exec -T mongodb mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1 && break; sleep 2; done
    echo "==> [3/5] mongorestore de la conf Graylog (--drop)"
    MID="$($DC ps -q mongodb)"
    docker cp "$TMP/mongodump/graylog" "${MID}:/tmp/dump_graylog"
    $DC exec -T mongodb mongorestore --drop --db graylog /tmp/dump_graylog
    echo "==> [4/5] Demarrage de la stack + lookups"
    $DC up -d
    if [[ -d "$TMP/etc/graylog/lookup" ]]; then
      sleep 6; GID="$($DC ps -q graylog)"
      docker exec "$GID" mkdir -p /etc/graylog/lookup 2>/dev/null || true
      docker cp "$TMP/etc/graylog/lookup/." "${GID}:/etc/graylog/lookup/" 2>/dev/null || true
    fi
    echo "==> [5/5] Redemarrage de Graylog (prise en compte conf + lookups)"
    $DC restart graylog
    echo "=== Conf restauree. Console prete dans ~1-2 min : verifier streams/pipelines/detections. ===" ;;
  *)
    echo "Usage: $0 {up|down|status|logs [svc]|restore <archive.tar.gz[.enc]>}" ;;
esac
