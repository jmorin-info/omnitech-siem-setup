#!/usr/bin/env bash
# =============================================================================
# 30-backup-config.sh - Sauvegarde CONFIG du SIEM (sans les logs) + export SMB
# -----------------------------------------------------------------------------
# Contenu : dump MongoDB (toute la conf Graylog : streams, pipelines, alertes,
# dashboards, inputs, users...) + /etc/graylog (server.conf, certs, lookups)
# + opensearch/mongo/nginx conf + cle interne MongoDB (keyFile de mongod.conf)
# + en-tete LUKS du volume /data + console /var/www/siem-soc + services maison
# (/etc/default/omni-*, /etc/omni-*, /etc/oms-*, /opt/oms-*, secrets compris)
# + collecteurs omni-* + units systemd + kit + le depot canonique (repertoire de
# ce script, /opt/omni-siem/repository par defaut). PAS les indices OpenSearch
# (logs), ni les environnements virtuels (.venv) ni les caches.
#
# Archive CHIFFREE (AES-256, la destination est un partage "Public") puis
# poussee vers ${SMB_BACKUP_UNC} avec retention ${BACKUP_RETENTION_J} jours
# (locale ET distante). Statut envoye au SIEM lui-meme via GELF (alertes
# "Backup config SIEM en echec" / "absent >26h" provisionnees par 21).
#
# Planification : omni-backup-config.timer (03:15, Persistent).
# Restauration : cf. docs/exploitation/RESTORE.md.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env

SMB_BACKUP_UNC="${SMB_BACKUP_UNC:-//10.33.50.5/Informatique}"
SMB_BACKUP_DIR="${SMB_BACKUP_DIR:-SIEM-Sauvegardes}"
SMB_CRED_FILE="${SMB_CRED_FILE:-/root/.smb-siem-backup.cred}"
BACKUP_RETENTION_J="${BACKUP_RETENTION_J:-14}"
BACKUP_LOCAL_RETENTION_J="${BACKUP_LOCAL_RETENTION_J:-3}"   # OMNITECH 2026-11-11 : copie locale courte (/var), le partage garde 14 j
# Emplacements surchargeables UNIQUEMENT pour les tests hors ligne
# (tests/test_backup_config.py) ; les valeurs par defaut sont celles de production.
RACINE="${OMNI_BACKUP_RACINE:-/}"; RACINE="${RACINE%/}/"
WORK="${OMNI_BACKUP_WORK:-/var/backups/siem}"
MNT="${OMNI_BACKUP_MNT:-/mnt/siem-backup}"
GELF_URL="${OMNI_BACKUP_GELF_URL:-http://127.0.0.1:12201/gelf}"
# Volume chiffre dont l'en-tete LUKS est archive ; LUKS_DEVICE force le peripherique
# (sinon detection : findmnt/fstab -> cryptsetup status -> lsblk -> /etc/crypttab).
LUKS_MOUNTPOINT="${LUKS_MOUNTPOINT:-/data}"
LUKS_DEVICE="${LUKS_DEVICE:-}"

STAMP="$(date +%F)"
TMP="$(mktemp -d)"
# L'archive en clair reste dans le repertoire temporaire (mode 700) : elle contient
# des secrets ; seule la version chiffree est deposee dans ${WORK}.
ARCH="${TMP}/omni-siem-config_${STAMP}.tar.gz"
ARCH_ENC="${WORK}/omni-siem-config_${STAMP}.tar.gz.enc"

gelf() {  # gelf <ok|echec> <message> [taille_mb]
  curl -s -m 10 -X POST "${GELF_URL}" -H 'Content-Type: application/json' -d "{
    \"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",
    \"short_message\":\"backup config SIEM ${1}: ${2}\",
    \"_event_source\":\"siem_backup\",\"_event_action\":\"backup_config_${1}\",
    \"_backup_size_mb\":${3:-0}}" >/dev/null 2>&1 || true
}
nettoyer() { shred -u "${TMP}"/luks/* 2>/dev/null || true; rm -rf "${TMP}"; }
fail() { echo "ERREUR: $*" >&2; gelf echec "$*"; nettoyer; exit 1; }
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
# server.conf peut contenir plusieurs lignes mongodb_uri (4 en production le
# 22/11/2026) : comme Graylog, on retient la DERNIERE ligne non commentee.
MONGO_URI="$(grep -E '^[[:space:]]*mongodb_uri[[:space:]]*=' "${RACINE}etc/graylog/server/server.conf" \
  | tail -n 1 | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//' || true)"
[[ -n "${MONGO_URI}" ]] || fail "mongodb_uri introuvable dans server.conf"
mongodump --quiet --uri="${MONGO_URI}" --out "${TMP}/mongodump"

# --- 1b. En-tete LUKS de /data (recovery du chiffrement au repos) ---------------
# Sans cet en-tete, /data (chiffre) est irrecuperable s'il est endommage. Inclus dans
# l'archive (elle-meme chiffree AES-256) -> copie hors-bande FRAICHE a chaque
# sauvegarde, suit tout changement de keyslot. La passphrase de secours reste AU
# COFFRE uniquement. Le peripherique est DETECTE (constat du 22/11/2026 : l'ancien
# test visait /dev/sda1 = /boot/efi, l'en-tete n'etait jamais archive).
# Non bloquant : un echec ici n'empeche pas l'expedition de l'archive, mais il
# emet un evenement GELF backup_config_echec (alerte « Backup config SIEM en echec »).
luks_detecter() {  # renseigne LUKS_SRC (source de ${LUKS_MOUNTPOINT}) et LUKS_DEV
  local nom ligne
  LUKS_SRC="$(findmnt -nro SOURCE --mountpoint "${LUKS_MOUNTPOINT}" 2>/dev/null | head -n 1 || true)"
  if [[ -z "${LUKS_SRC}" ]]; then  # volume non monte (nofail) : source declaree dans fstab
    LUKS_SRC="$(awk -v m="${LUKS_MOUNTPOINT}" '$1 !~ /^#/ && $2 == m {print $1; exit}' "${RACINE}etc/fstab" 2>/dev/null || true)"
  fi
  if [[ -n "${LUKS_DEVICE}" ]]; then LUKS_DEV="${LUKS_DEVICE}"; return 0; fi
  [[ -n "${LUKS_SRC}" ]] || return 0
  nom="${LUKS_SRC#/dev/mapper/}"
  # 1. mappage dm-crypt actif : « device: » de cryptsetup status
  if [[ "${nom}" != "${LUKS_SRC}" ]]; then
    LUKS_DEV="$(cryptsetup status "${nom}" 2>/dev/null | awk '$1 == "device:" {print $2; exit}' || true)"
    [[ -z "${LUKS_DEV}" ]] || return 0
  fi
  # 2. ascendants de la source dans l'arbre des peripheriques blocs
  LUKS_DEV="$(lsblk -nrspo NAME,FSTYPE "${LUKS_SRC}" 2>/dev/null | awk '$2 == "crypto_LUKS" {print $1; exit}' || true)"
  [[ -z "${LUKS_DEV}" ]] || return 0
  # 3. /etc/crypttab (mappage ferme)
  if [[ "${nom}" != "${LUKS_SRC}" ]]; then
    ligne="$(awk -v n="${nom}" '$1 !~ /^#/ && $1 == n {print $2; exit}' "${RACINE}etc/crypttab" 2>/dev/null || true)"
    case "${ligne}" in
      UUID=*) LUKS_DEV="$(blkid -U "${ligne#UUID=}" 2>/dev/null || true)" ;;
      /dev/*) LUKS_DEV="${ligne}" ;;
    esac
  fi
  return 0
}
luks_entete_valide() {  # <fichier> <uuid attendu> : signature LUKS + UUID du volume
  local magie uuid
  magie="$(head -c 6 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)"
  [[ "${magie}" == "4c554b53babe" ]] || return 1        # « LUKS\xba\xbe » (LUKS1 et LUKS2)
  uuid="$(head -c 208 "$1" | tail -c 40 | tr -d '\0' || true)"   # UUID a l'offset 168
  [[ -n "$2" && "${uuid}" == "$2" ]]
}
LUKS_SRC=""; LUKS_DEV=""; LUKS_ETAT="non concerne"; LUKS_ATTENDU=0
luks_detecter
[[ -z "${LUKS_DEV}" && "${LUKS_SRC}" != /dev/mapper/* ]] || LUKS_ATTENDU=1
if [[ -n "${LUKS_DEV}" ]]; then
  if cryptsetup isLuks "${LUKS_DEV}" 2>/dev/null; then
    mkdir -m 700 "${TMP}/luks"
    LUKS_UUID="$(cryptsetup luksUUID "${LUKS_DEV}" 2>/dev/null || true)"
    if cryptsetup luksHeaderBackup "${LUKS_DEV}" --header-backup-file "${TMP}/luks/data-header.img" 2>/dev/null \
       && luks_entete_valide "${TMP}/luks/data-header.img" "${LUKS_UUID}"; then
      printf 'point_de_montage=%s\nsource=%s\nperipherique=%s\nuuid=%s\ndate=%s\nsha256=%s\n' \
        "${LUKS_MOUNTPOINT}" "${LUKS_SRC}" "${LUKS_DEV}" "${LUKS_UUID}" "$(date '+%F %T')" \
        "$(sha256sum "${TMP}/luks/data-header.img" | cut -d' ' -f1)" > "${TMP}/luks/data-header.txt"
      LUKS_ETAT="inclus"
      echo "[+] en-tete LUKS ${LUKS_MOUNTPOINT} inclus (${LUKS_DEV}, UUID ${LUKS_UUID})"
    else
      LUKS_ETAT="copie ou verification de l'en-tete de ${LUKS_DEV} impossible"
    fi
  else
    LUKS_ETAT="${LUKS_DEV} n'est pas un volume LUKS"
  fi
elif [[ "${LUKS_ATTENDU}" == 1 ]]; then
  LUKS_ETAT="peripherique LUKS sous-jacent a ${LUKS_MOUNTPOINT} (${LUKS_SRC}) introuvable"
fi
if [[ "${LUKS_ETAT}" != inclus ]]; then
  rm -rf "${TMP}/luks"
  [[ "${LUKS_ATTENDU}" == 0 ]] || echo "[!] en-tete LUKS NON sauvegarde : ${LUKS_ETAT} (non bloquant, alerte emise)"
fi

# --- 2. Archive ----------------------------------------------------------------
# Socle historique, puis elements de reprise ajoutes le 22/11/2026. Seuls les chemins
# presents sont archives (un element facultatif absent ne fait jamais echouer), et
# chacun d'eux est ensuite EXIGE dans l'archive par la verification §3b.
CHEMINS=(etc/graylog etc/default/graylog-server etc/opensearch etc/mongod.conf etc/nginx
         etc/hosts etc/nftables.conf etc/systemd/system usr/local/sbin var/www/siem-kit)
AJOUTS=(var/www/siem-soc)
# Cle interne MongoDB (keyFile exige par mongod.conf ; /etc/mongod.keyfile en production)
KEYFILE="$(awk '$1 == "keyFile:" {print $2; exit}' "${RACINE}etc/mongod.conf" 2>/dev/null || true)"
KEYFILE="${KEYFILE:-/etc/mongod.keyfile}"
AJOUTS+=("${KEYFILE#/}")
shopt -s nullglob
for P in "${RACINE}"etc/default/omni-* "${RACINE}"etc/omni-* "${RACINE}"etc/oms-* "${RACINE}"opt/oms-*; do
  AJOUTS+=("${P#"${RACINE}"}")
done
shopt -u nullglob
# Elements a controler dans l'archive (s'ils existent sur la source)
ATTENDUS=(etc/graylog/lookup etc/nginx/sites-available etc/nginx/sites-enabled etc/nginx/snippets
          etc/nginx/conf.d/omni-ratelimit.conf)
for P in "${AJOUTS[@]}"; do
  if [[ -e "${RACINE}${P}" ]]; then CHEMINS+=("${P}"); ATTENDUS+=("${P}"); fi
done
PRESENTS=()
for P in "${CHEMINS[@]}"; do if [[ -e "${RACINE}${P}" ]]; then PRESENTS+=("${P}"); fi; done
REPO_REL="${PWD#"${RACINE%/}"}"; REPO_REL="${REPO_REL#/}"
if [[ -e "${RACINE}${REPO_REL}" ]]; then PRESENTS+=("${REPO_REL}"); fi
SCRATCH=(mongodump)
if [[ "${LUKS_ETAT}" == inclus ]]; then SCRATCH+=(luks); ATTENDUS+=(luks/data-header.img luks/data-header.txt); fi
tar czf "${ARCH}" --ignore-failed-read \
  --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache --exclude=.mypy_cache \
  --exclude=.ruff_cache --exclude=.cache --exclude=node_modules --exclude='*.pyc' \
  -C "${RACINE}" "${PRESENTS[@]}" \
  -C "${TMP}" "${SCRATCH[@]}"

# --- 3. Chiffrement ------------------------------------------------------------
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -in "${ARCH}" -out "${ARCH_ENC}" -pass "pass:${BACKUP_PASSPHRASE}"
rm -f "${ARCH}"
shred -u "${TMP}"/luks/* 2>/dev/null || true
TAILLE_MB=$(( $(stat -c%s "${ARCH_ENC}") / 1024 / 1024 ))

# --- 3b. Verification de restaurabilite (ne JAMAIS expedier un backup illisible) -
# Dechiffre l'archive qu'on vient de produire vers le scratch et controle son
# integrite tar + la presence des composants critiques (dump Mongo + server.conf).
# Capte les pannes les plus frequentes (passphrase erronee, archive corrompue,
# dump vide) AU MOMENT du backup plutot qu'au PRA. Echec -> alerte GELF + abort
# (l'archive n'est PAS expediee). Test A.8.13 en continu.
VERIF="${TMP}/verify.tar.gz"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "${ARCH_ENC}" -out "${VERIF}" \
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
# Elements de reprise presents sur la source : en-tete LUKS, cle MongoDB, nginx de la
# console, /var/www/siem-soc, environnements et secrets des services maison, lookups.
for P in "${ATTENDUS[@]}"; do
  [[ "${P}" == luks/* || -e "${RACINE}${P}" ]] || continue
  grep -qxF -e "${P}" -e "${P}/" "${TMP}/manifest.txt" || fail "verif restaurabilite: ${P} absent de l'archive"
done
if grep -qE '(^|/)(\.venv|__pycache__)/' "${TMP}/manifest.txt"; then
  fail "verif restaurabilite: environnement virtuel ou cache present dans l'archive"
fi
shred -u "${VERIF}" "${TMP}/manifest.txt" 2>/dev/null || rm -f "${VERIF}" "${TMP}/manifest.txt"
echo "[+] restaurabilite verifiee : ${VENTRIES} entrees ; streams+pipelines+regles+alertes+notifs+inputs+server.conf+lookups presents ; ${#ATTENDUS[@]} elements de reprise controles ; en-tete LUKS : ${LUKS_ETAT}"

# --- 4. Export SMB ---------------------------------------------------------------
if ! mountpoint -q "${MNT}"; then
  [[ -f "${SMB_CRED_FILE}" ]] || fail "fichier d'identifiants ${SMB_CRED_FILE} absent (repli invite supprime le 2026-11-11)"
    mount -t cifs "${SMB_BACKUP_UNC}" "${MNT}" \
      -o "credentials=${SMB_CRED_FILE},iocharset=utf8,vers=3.0" \
      || fail "montage SMB ${SMB_BACKUP_UNC} impossible (credentials)"
fi
mkdir -p "${MNT}/${SMB_BACKUP_DIR}"
cp "${ARCH_ENC}" "${MNT}/${SMB_BACKUP_DIR}/" || fail "copie vers le partage impossible"

# --- 5. Retention (distante + locale) -------------------------------------------
find "${MNT}/${SMB_BACKUP_DIR}" -name 'omni-siem-config_*.tar.gz.enc' -mtime "+${BACKUP_RETENTION_J}" -delete || true
find "${WORK}" -name 'omni-siem-config_*' -mtime "+${BACKUP_LOCAL_RETENTION_J}" -delete || true
DIST=$(ls -1 "${MNT}/${SMB_BACKUP_DIR}"/omni-siem-config_*.tar.gz.enc 2>/dev/null | wc -l)
umount "${MNT}" || true

nettoyer
trap - ERR
gelf ok "archive ${STAMP} (${TAILLE_MB} Mo), ${DIST} copies sur le partage, en-tete LUKS : ${LUKS_ETAT}" "${TAILLE_MB}"
# L'archive est expediee, mais un en-tete LUKS attendu et absent doit etre visible.
[[ "${LUKS_ATTENDU}" == 0 || "${LUKS_ETAT}" == inclus ]] \
  || gelf echec "archive ${STAMP} expediee SANS en-tete LUKS de ${LUKS_MOUNTPOINT} : ${LUKS_ETAT}"
echo "OK : ${ARCH_ENC} (${TAILLE_MB} Mo) -> ${SMB_BACKUP_UNC}/${SMB_BACKUP_DIR} (${DIST} copies, retention ${BACKUP_RETENTION_J} j)"
