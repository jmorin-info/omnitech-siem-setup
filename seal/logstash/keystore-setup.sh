#!/usr/bin/env bash
# ============================================================================
# keystore-setup.sh — Amorcage du logstash-keystore pour l'ingestion SEAL
# OMNITECH SECURITY · MISSION_SEAL_GRAYLOG · Couche Logstash
# ----------------------------------------------------------------------------
# Alimente le keystore Logstash avec les identifiants du compte de service SQL
# (svc_graylog_seal). AUCUN secret n'est ecrit dans un fichier ni journalise :
# les valeurs sont lues depuis l'ENVIRONNEMENT et transmises via STDIN.
#
# Prerequis (a exporter dans le shell appelant, PUIS unset apres coup) :
#   export SEAL_DB_SVC_USER='svc_graylog_seal'
#   export SEAL_DB_SVC_PWD='<mot_de_passe>'      # jamais commite, jamais logge
#
# Idempotent : logstash-keystore add --force ecrase la valeur si la cle existe
# deja, sans invite interactive. Rejouable a volonte.
#
# Usage :
#   sudo -E LOGSTASH_KEYSTORE_PASS='<...>' ./keystore-setup.sh
#   (sudo -E pour propager les variables d'env vers logstash-keystore)
# ============================================================================
set -euo pipefail

# Binaire keystore (surchargables selon l'installation).
LOGSTASH_KEYSTORE_BIN="${LOGSTASH_KEYSTORE_BIN:-/usr/share/logstash/bin/logstash-keystore}"
LOGSTASH_PATH_SETTINGS="${LOGSTASH_PATH_SETTINGS:-/etc/logstash}"
CONF_FILE="${CONF_FILE:-/etc/logstash/seal/seal.conf}"

fail() { echo "ERREUR: $*" >&2; exit 1; }

[ -x "$LOGSTASH_KEYSTORE_BIN" ] || fail "logstash-keystore introuvable: $LOGSTASH_KEYSTORE_BIN"
: "${SEAL_DB_SVC_USER:?SEAL_DB_SVC_USER absent de l'environnement}"
: "${SEAL_DB_SVC_PWD:?SEAL_DB_SVC_PWD absent de l'environnement}"

ks() { "$LOGSTASH_KEYSTORE_BIN" --path.settings "$LOGSTASH_PATH_SETTINGS" "$@"; }

# Cree le keystore s'il n'existe pas (idempotent : ignore si deja present).
ks list >/dev/null 2>&1 || ks create --silent || true

# Ajout des cles. --stdin : la valeur ne transite jamais par argv (invisible
# dans ps/history). --force : ecrase sans invite => idempotent.
printf '%s' "$SEAL_DB_SVC_USER" | ks add SEAL_DB_SVC_USER --stdin --force
printf '%s' "$SEAL_DB_SVC_PWD"  | ks add SEAL_DB_SVC_PWD  --stdin --force

# Verification : on liste UNIQUEMENT les noms de cles (jamais les valeurs).
echo "Cles presentes dans le keystore :"
ks list | grep -E '^SEAL_DB_SVC_(USER|PWD)$' || fail "cles SEAL absentes apres ajout"

cat <<EOF

Keystore alimente (SEAL_DB_SVC_USER / SEAL_DB_SVC_PWD).
Pensez a: unset SEAL_DB_SVC_USER SEAL_DB_SVC_PWD   (purge du shell courant)

Test de la configuration AVANT deploiement :
  ${LOGSTASH_KEYSTORE_BIN%/logstash-keystore}/logstash \\
    --path.settings ${LOGSTASH_PATH_SETTINGS} \\
    --config.test_and_exit -f ${CONF_FILE}
EOF
