#!/usr/bin/env bash
# =============================================================================
# install-logstash-siem.sh
# Installation de Logstash sur la VM SIEM Debian (10.33.220.10) — PAS sur SEAL.
# OMNITECH SECURITY — etape OPERATEUR prealable au deploiement de seal/logstash/
#
# CONTEXTE
#   Le collecteur SEAL->Graylog fonctionne en PULL JDBC : Logstash tourne sur la
#   VM SIEM (aux cotes de Graylog) et lit la base SEAL en lecture seule. Aucun
#   binaire n'est installe sur BX-QA-SEAL-VM.
#
#   Ce script prepare UNIQUEMENT le socle Logstash (paquet, plugins, driver JDBC,
#   arborescence, keystore). Les fichiers de configuration (seal.conf, requetes
#   *.sql) sont le livrable de la Phase 2 de Claude Code : ce script ne les ecrit
#   PAS, il prepare le terrain pour les recevoir.
#
# A LANCER
#   Sur la VM SIEM Debian, en root/sudo. Idempotent (re-executable).
#     sudo bash install-logstash-siem.sh
#   Puis renseigner les secrets du keystore (interactif, voir fin de script).
#
# CE QUE CE SCRIPT NE FAIT PAS
#   - Il ne deploie pas seal.conf ni les vues .sql (-> Claude Code Phase 2).
#   - Il ne demarre pas la collecte tant que la conf n'est pas en place.
#   - Il ne touche pas a la machine SEAL.
# =============================================================================

set -euo pipefail

# --- Parametres ajustables ---------------------------------------------------
LOGSTASH_MAJOR="1:8"                       # famille de version (depot Elastic 8.x)
MSSQL_JDBC_VERSION="12.8.1"                # driver JDBC SQL Server (variante jre11)
JDBC_DIR="/opt/mssql-jdbc"                 # chemin attendu par seal.conf (Phase 2)
SQL_DIR="/etc/logstash/sql"               # requetes SQL des inputs
HEAP="512m"                                # tas JVM : volume d'events faible ici

log()  { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[0;32m[OK]\033[0m   %s\n' "$*"; }
warn() { printf '  \033[0;33m[WARN]\033[0m %s\n' "$*"; }
info() { printf '  \033[0;90m[..]\033[0m   %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
  echo "Ce script doit etre execute en root (sudo)." >&2
  exit 1
fi

# --- Garde-fou : ne pas jouer ce script sur la machine SEAL ------------------
host="$(hostname -f 2>/dev/null || hostname)"
if [[ "${host,,}" == *seal* ]]; then
  echo "ERREUR : '$host' ressemble a la machine SEAL. Logstash s'installe sur la VM SIEM, pas ici." >&2
  echo "Si c'est un faux positif (hostname trompeur), commenter ce garde-fou." >&2
  exit 1
fi
info "Hote cible : $host"

# =============================================================================
# 1) Depot APT Elastic + installation de Logstash
# =============================================================================
log "1. Paquet Logstash (depot Elastic 8.x)"
if command -v logstash >/dev/null 2>&1 || dpkg -s logstash >/dev/null 2>&1; then
  ok "Logstash deja installe ($(dpkg-query -W -f='${Version}' logstash 2>/dev/null || echo '?'))"
else
  info "Prerequis (apt-transport-https, gpg, openjdk pour keytool eventuel)"
  apt-get update -qq
  apt-get install -y -qq apt-transport-https ca-certificates curl gnupg

  install -d -m 0755 /usr/share/keyrings
  if [[ ! -f /usr/share/keyrings/elastic-keyring.gpg ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
      | gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
    ok "Cle GPG Elastic installee"
  fi
  echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list

  apt-get update -qq
  # Epingle la famille de version pour eviter un saut majeur non maitrise.
  apt-get install -y -qq "logstash=${LOGSTASH_MAJOR}*" || apt-get install -y -qq logstash
  ok "Logstash installe ($(dpkg-query -W -f='${Version}' logstash))"
fi

LS_HOME="/usr/share/logstash"
LS_BIN="${LS_HOME}/bin/logstash"
LS_PLUGIN="${LS_HOME}/bin/logstash-plugin"
[[ -x "$LS_BIN" ]] || { echo "logstash introuvable sous $LS_HOME" >&2; exit 1; }

# =============================================================================
# 2) Plugins : GELF (output) et JDBC (input)
#    PIEGE : le plugin de SORTIE GELF n'est PAS embarque -> installation explicite.
#    (l'integration JDBC, elle, est presente par defaut, mais on verifie.)
# =============================================================================
log "2. Plugins Logstash"
installed_plugins="$("$LS_PLUGIN" list 2>/dev/null || true)"

if grep -q 'logstash-output-gelf' <<<"$installed_plugins"; then
  ok "logstash-output-gelf deja present"
else
  info "Installation de logstash-output-gelf (non embarque)"
  "$LS_PLUGIN" install logstash-output-gelf
  ok "logstash-output-gelf installe"
fi

if grep -Eq 'logstash-(input-jdbc|integration-jdbc)' <<<"$installed_plugins"; then
  ok "input JDBC present (integration-jdbc)"
else
  info "Installation de logstash-integration-jdbc"
  "$LS_PLUGIN" install logstash-integration-jdbc
  ok "logstash-integration-jdbc installe"
fi

# =============================================================================
# 3) Driver JDBC Microsoft SQL Server
#    seal.conf (Phase 2) attend le jar sous /opt/mssql-jdbc/mssql-jdbc.jar
#    Variante jre11 : compatible avec le JDK embarque de Logstash 8.x.
# =============================================================================
log "3. Driver JDBC SQL Server (${MSSQL_JDBC_VERSION}, jre11)"
install -d -m 0755 "$JDBC_DIR"
JAR_VERSIONED="${JDBC_DIR}/mssql-jdbc-${MSSQL_JDBC_VERSION}.jre11.jar"
JAR_LINK="${JDBC_DIR}/mssql-jdbc.jar"

if [[ -f "$JAR_VERSIONED" ]]; then
  ok "Driver deja present : $JAR_VERSIONED"
else
  url="https://github.com/microsoft/mssql-jdbc/releases/download/v${MSSQL_JDBC_VERSION}/mssql-jdbc-${MSSQL_JDBC_VERSION}.jre11.jar"
  info "Telechargement : $url"
  if curl -fsSL -o "$JAR_VERSIONED" "$url"; then
    ok "Driver telecharge"
  else
    warn "Echec du telechargement automatique."
    warn "Recuperer manuellement mssql-jdbc-${MSSQL_JDBC_VERSION}.jre11.jar depuis"
    warn "  https://learn.microsoft.com/sql/connect/jdbc/download-microsoft-jdbc-driver-for-sql-server"
    warn "et le deposer dans $JAR_VERSIONED, puis relancer ce script."
    exit 1
  fi
fi

# Lien stable attendu par la conf (independant de la version)
ln -sf "$JAR_VERSIONED" "$JAR_LINK"
ok "Lien stable : $JAR_LINK -> $(basename "$JAR_VERSIONED")"

# Verif de coherence : le driver se charge-t-il dans la JVM de Logstash ?
if command -v unzip >/dev/null 2>&1; then
  if unzip -l "$JAR_LINK" 2>/dev/null | grep -q 'com/microsoft/sqlserver/jdbc/SQLServerDriver.class'; then
    ok "Classe SQLServerDriver presente dans le jar"
  else
    warn "SQLServerDriver.class introuvable dans le jar — driver corrompu ?"
  fi
fi

# =============================================================================
# 3b) Truststore Java : CA racine OMNITECH
#     Le driver JDBC valide STRICTEMENT le certificat SEAL
#     (encrypt=true;trustServerCertificate=false). La CA racine interne doit donc
#     etre dans le truststore du JDK embarque de Logstash, sinon : PKIX path
#     building failed. Idempotent. NB : une MAJ de Logstash remplace le JDK ->
#     re-jouer ce script (ou ce bloc) apres upgrade.
# =============================================================================
log "3b. CA racine OMNITECH dans le truststore JDK de Logstash"
CACERTS="${LS_HOME}/jdk/lib/security/cacerts"
KEYTOOL="${LS_HOME}/jdk/bin/keytool"
CA_SRC="/etc/graylog/certs/omnitech-rootca.crt"
if [[ -f "$CA_SRC" && -x "$KEYTOOL" && -f "$CACERTS" ]]; then
  "$KEYTOOL" -delete -alias omnitech-rootca -keystore "$CACERTS" -storepass changeit >/dev/null 2>&1 || true
  if "$KEYTOOL" -importcert -noprompt -trustcacerts -alias omnitech-rootca \
       -file "$CA_SRC" -keystore "$CACERTS" -storepass changeit >/dev/null 2>&1; then
    ok "CA racine OMNITECH importee dans $CACERTS"
  else
    warn "Import CA echoue - la connexion JDBC TLS stricte echouera (PKIX)."
  fi
else
  warn "CA racine ($CA_SRC) ou keytool/cacerts introuvable - importer manuellement."
fi

# =============================================================================
# 4) Arborescence + permissions
# =============================================================================
log "4. Arborescence de configuration"
install -d -m 0750 -o root -g logstash "$SQL_DIR"
install -d -m 0750 -o root -g logstash /etc/logstash/conf.d
# last_run_metadata (watermarks) : ecrit par l'utilisateur logstash
install -d -m 0750 -o logstash -g logstash /var/lib/logstash
ok "$SQL_DIR, /etc/logstash/conf.d, /var/lib/logstash prets"

# Tas JVM (volume faible : 512m suffit, evite de reserver trop de RAM)
JVM_OPTS="/etc/logstash/jvm.options"
if [[ -f "$JVM_OPTS" ]]; then
  sed -i -E "s/^-Xms.*/-Xms${HEAP}/; s/^-Xmx.*/-Xmx${HEAP}/" "$JVM_OPTS"
  ok "Tas JVM fixe a ${HEAP}"
fi

# =============================================================================
# 5) Keystore Logstash (secrets hors des fichiers de conf)
#    On CREE le keystore ; le remplissage des valeurs est interactif (ci-dessous).
# =============================================================================
log "5. Keystore Logstash"
KS_PATH="/etc/logstash/logstash.keystore"
# Keystore sans passphrase interactive au boot : variable d'env persistante.
# (Alternative : definir LOGSTASH_KEYSTORE_PASS. Ici on reste simple pour la QA.)
if [[ -f "$KS_PATH" ]]; then
  ok "Keystore deja present : $KS_PATH"
else
  # -Path.settings pointe la conf ; le keystore atterrit dans /etc/logstash
  sudo -u logstash LOGSTASH_KEYSTORE_PASS="" "$LS_HOME/bin/logstash-keystore" \
    --path.settings /etc/logstash create 2>/dev/null \
    && ok "Keystore cree" \
    || warn "Creation keystore : verifier les droits de /etc/logstash"
fi

# =============================================================================
# 6) Service systemd : NE PAS demarrer maintenant (pas de conf = pas de collecte)
# =============================================================================
log "6. Service"
systemctl daemon-reload 2>/dev/null || true
# On active le demarrage auto mais on NE lance PAS : la conf seal.conf arrive apres.
systemctl enable logstash >/dev/null 2>&1 && ok "Service active (enable), NON demarre" \
  || warn "Impossible d'activer le service (a verifier)"

# =============================================================================
# Recapitulatif + prochaines etapes (cote operateur, PUIS Claude Code)
# =============================================================================
cat <<'EOF'

============================================================================
  SOCLE LOGSTASH PRET (VM SIEM). Rien n'a ete installe sur SEAL.
============================================================================

  PROCHAINES ETAPES, DANS L'ORDRE :

  1) Renseigner les SECRETS dans le keystore (interactif, valeurs non affichees).
     Les cles ci-dessous sont celles attendues par seal.conf (Phase 2) :

       cd /usr/share/logstash
       KS="bin/logstash-keystore --path.settings /etc/logstash"
       sudo -u logstash $KS add SEAL_DB_HOST
       sudo -u logstash $KS add SEAL_DB_NAME
       sudo -u logstash $KS add SEAL_DB_SVC_USER
       sudo -u logstash $KS add SEAL_DB_SVC_PWD      # <- depuis Vaultwarden
       sudo -u logstash $KS add GRAYLOG_GELF_HOST
       sudo -u logstash $KS add GRAYLOG_GELF_PORT
     (verifier la liste : sudo -u logstash $KS list)

  2) DEPLOYER LA CONF (livrable Claude Code, Phase 2) :
       - copier seal/logstash/seal.conf        -> /etc/logstash/conf.d/
       - copier seal/logstash/sql/*.sql        -> /etc/logstash/sql/
       - ajuster les droits : chown root:logstash, chmod 0640

  3) TESTER LA CONF avant de lancer le service :
       sudo -u logstash /usr/share/logstash/bin/logstash \
         --path.settings /etc/logstash -t

  4) PREALABLE COTE SEAL (SSMS admin) : avoir execute seal/sql/01->05 + 90_provision.sql
     (les vues doivent exister, sinon les inputs JDBC echouent).

  5) DEMARRER puis SURVEILLER :
       systemctl start logstash
       journalctl -u logstash -f
     (premiere execution : les watermarks se seedent a la valeur courante ;
      pas de rapatriement d'historique.)

  Rappel reseau : la route SIEM(10.33.220.10) -> SEAL:1433 doit etre ouverte
  (pare-feu Windows OK ; politique FortiGate si le flux traverse un FGT).
============================================================================
EOF
