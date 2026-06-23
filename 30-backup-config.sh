#!/usr/bin/env bash
# =============================================================================
# 30-backup-config.sh - Sauvegarde CONFIG du SIEM (sans les logs) + export SMB
# -----------------------------------------------------------------------------
# Contenu : dump MongoDB (toute la conf Graylog : streams, pipelines, alertes,
# dashboards, inputs, users...) + /etc/graylog (server.conf, certs, lookups)
# + opensearch/mongo/nginx conf + collecteurs omni-* + units systemd + kit
# + ~/omnitech-siem-setup (IaC). PAS les indices OpenSearch (logs).
#
# Archive CHIFFREE (AES-256, la destination est un partage "Public") puis
# poussee vers ${SMB_BACKUP_UNC} avec retention ${BACKUP_RETENTION_J} jours
# (locale ET distante). Statut envoye au SIEM lui-meme via GELF (alertes
# "Backup config SIEM en echec" / "absent >26h" provisionnees par 21).
#
# Planification : omni-backup-config.timer (03:15, Persistent).
# Restauration : cf. RESTORE.md.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env

SMB_BACKUP_UNC="${SMB_BACKUP_UNC:-//10.33.50.5/Public}"
SMB_BACKUP_DIR="${SMB_BACKUP_DIR:-SIEM}"
SMB_CRED_FILE="${SMB_CRED_FILE:-/root/.smb-siem.cred}"
BACKUP_RETENTION_J="${BACKUP_RETENTION_J:-14}"
WORK=/var/backups/siem
MNT=/mnt/siem-backup
GELF_URL="http://127.0.0.1:12201/gelf"

STAMP="$(date +%F)"
ARCH="${WORK}/omni-siem-config_${STAMP}.tar.gz"
TMP="$(mktemp -d)"

gelf() {  # gelf <ok|echec> <message> [taille_mb]
  curl -s -m 10 -X POST "${GELF_URL}" -H 'Content-Type: application/json' -d "{
    \"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",
    \"short_message\":\"backup config SIEM ${1}: ${2}\",
    \"_event_source\":\"siem_backup\",\"_event_action\":\"backup_config_${1}\",
    \"_backup_size_mb\":${3:-0}}" >/dev/null 2>&1 || true
}
fail() { echo "ERREUR: $*" >&2; gelf echec "$*"; rm -rf "${TMP}"; exit 1; }
trap 'fail "interrompu a la ligne ${LINENO}"' ERR

# --- 0. Passphrase de chiffrement (generee au premier run) -------------------
if [[ -z "${BACKUP_PASSPHRASE:-}" ]]; then
  BACKUP_PASSPHRASE="$(openssl rand -base64 32)"
  printf '\n# Passphrase chiffrement des sauvegardes config (A COPIER DANS LE\n# COFFRE-FORT : sans elle, les archives sont irrecuperables)\nBACKUP_PASSPHRASE=%q\n' \
    "${BACKUP_PASSPHRASE}" >> ./00-vars.env
  echo "[!] BACKUP_PASSPHRASE generee et ajoutee a 00-vars.env -> LA METTRE AU COFFRE"
fi

mkdir -p "${WORK}" "${MNT}"

# --- 1. Dump MongoDB (config Graylog complete) --------------------------------
# (mongo en mode authentifie : on reutilise l'URI de Graylog)
MONGO_URI="$(grep -E '^mongodb_uri' /etc/graylog/server/server.conf | sed 's/^[^=]*=[[:space:]]*//')"
mongodump --quiet --uri="${MONGO_URI}" --out "${TMP}/mongodump"

# --- 1b. Header LUKS de /data (recovery du chiffrement au repos) ----------------
# Sans ce header, /data (chiffre) est irrecuperable. Inclus dans l'archive (elle-meme
# chiffree AES-256) -> copie hors-bande FRAICHE a chaque sauvegarde, suit tout
# changement de keyslot. La passphrase de secours reste AU COFFRE uniquement.
if cryptsetup isLuks /dev/sda1 2>/dev/null; then
  cryptsetup luksHeaderBackup /dev/sda1 --header-backup-file "${TMP}/luks-data-header.img" 2>/dev/null \
    && echo "[+] header LUKS /data inclus" || echo "[!] header LUKS non sauvegarde (non bloquant)"
fi

# --- 2. Archive ----------------------------------------------------------------
tar czf "${ARCH}" --ignore-failed-read \
  -C / \
    etc/graylog \
    etc/default/graylog-server \
    etc/opensearch \
    etc/mongod.conf \
    etc/nginx \
    etc/hosts \
    etc/nftables.conf \
    etc/systemd/system \
    usr/local/sbin \
    var/www/siem-kit \
    root/omnitech-siem-setup \
  -C "${TMP}" mongodump $([ -f "${TMP}/luks-data-header.img" ] && echo luks-data-header.img)

# --- 3. Chiffrement ------------------------------------------------------------
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -in "${ARCH}" -out "${ARCH}.enc" -pass "pass:${BACKUP_PASSPHRASE}"
rm -f "${ARCH}"
TAILLE_MB=$(( $(stat -c%s "${ARCH}.enc") / 1024 / 1024 ))

# --- 3b. Verification de restaurabilite (ne JAMAIS expedier un backup illisible) -
# Dechiffre l'archive qu'on vient de produire vers le scratch et controle son
# integrite tar + la presence des composants critiques (dump Mongo + server.conf).
# Capte les pannes les plus frequentes (passphrase erronee, archive corrompue,
# dump vide) AU MOMENT du backup plutot qu'au PRA. Echec -> alerte GELF + abort
# (l'archive n'est PAS expediee). Test A.8.13 en continu.
VERIF="${TMP}/verify.tar.gz"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "${ARCH}.enc" -out "${VERIF}" \
  -pass "pass:${BACKUP_PASSPHRASE}" 2>/dev/null || fail "verif restaurabilite: dechiffrement impossible"
tar tzf "${VERIF}" > "${TMP}/manifest.txt" 2>/dev/null || fail "verif restaurabilite: archive corrompue (tar illisible)"
VENTRIES="$(wc -l < "${TMP}/manifest.txt")"
[[ "${VENTRIES}" -ge 100 ]] || fail "verif restaurabilite: archive suspecte (${VENTRIES} entrees < 100)"
# Composants CRITIQUES exiges dans l'archive (sinon la restauration serait incomplete) :
# streams + pipelines + regles de detection + event definitions (alertes) + notifications,
# le server.conf, et au moins un CSV de lookup (preuve que /etc/graylog/lookup est capte).
for COMP in \
  'mongodump/graylog/streams.bson:streams' \
  'mongodump/graylog/pipeline_processor_pipelines.bson:pipelines' \
  'mongodump/graylog/pipeline_processor_rules.bson:regles de detection' \
  'mongodump/graylog/event_definitions.bson:event definitions (alertes)' \
  'mongodump/graylog/event_notifications.bson:notifications' \
  'mongodump/graylog/inputs.bson:inputs' \
  'etc/graylog/server/server.conf:server.conf' \
  'etc/graylog/lookup/mitre-attack.csv:lookups (CSV)'; do
  PAT="${COMP%%:*}"; LBL="${COMP##*:}"
  grep -q "${PAT}" "${TMP}/manifest.txt" || fail "verif restaurabilite: ${LBL} absent de l'archive (${PAT})"
done
shred -u "${VERIF}" "${TMP}/manifest.txt" 2>/dev/null || rm -f "${VERIF}" "${TMP}/manifest.txt"
echo "[+] restaurabilite verifiee : ${VENTRIES} entrees ; streams+pipelines+regles+alertes+notifs+inputs+server.conf+lookups presents"

# --- 4. Export SMB ---------------------------------------------------------------
if ! mountpoint -q "${MNT}"; then
  if [[ -f "${SMB_CRED_FILE}" ]]; then
    mount -t cifs "${SMB_BACKUP_UNC}" "${MNT}" \
      -o "credentials=${SMB_CRED_FILE},iocharset=utf8,vers=3.0" \
      || fail "montage SMB ${SMB_BACKUP_UNC} impossible (credentials)"
  else
    mount -t cifs "${SMB_BACKUP_UNC}" "${MNT}" -o "guest,iocharset=utf8,vers=3.0" \
      || fail "montage SMB ${SMB_BACKUP_UNC} impossible (guest refuse ? creer ${SMB_CRED_FILE})"
  fi
fi
mkdir -p "${MNT}/${SMB_BACKUP_DIR}"
cp "${ARCH}.enc" "${MNT}/${SMB_BACKUP_DIR}/" || fail "copie vers le partage impossible"

# --- 5. Retention (distante + locale) -------------------------------------------
find "${MNT}/${SMB_BACKUP_DIR}" -name 'omni-siem-config_*.tar.gz.enc' -mtime "+${BACKUP_RETENTION_J}" -delete || true
find "${WORK}" -name 'omni-siem-config_*' -mtime "+${BACKUP_RETENTION_J}" -delete || true
DIST=$(ls -1 "${MNT}/${SMB_BACKUP_DIR}"/omni-siem-config_*.tar.gz.enc 2>/dev/null | wc -l)
umount "${MNT}" || true

rm -rf "${TMP}"
trap - ERR
gelf ok "archive ${STAMP} (${TAILLE_MB} Mo), ${DIST} copies sur le partage" "${TAILLE_MB}"
echo "OK : ${ARCH}.enc (${TAILLE_MB} Mo) -> ${SMB_BACKUP_UNC}/${SMB_BACKUP_DIR} (${DIST} copies, retention ${BACKUP_RETENTION_J} j)"
