#!/usr/bin/env bash
# ==============================================================================
# 02-mongodb.sh - MongoDB 8.0 (depot officiel, composant bookworm sur Debian 13)
#   - replica set mono-noeud "rs0" + authentification keyFile
#   - bind 127.0.0.1 uniquement (jamais expose au reseau)
#   - cache WiredTiger plafonne (VM mutualisee avec OpenSearch/Graylog)
#   - utilisateurs: admin (root) + graylog (readWrite/dbAdmin sur la base graylog)
#
# PREREQUIS PROXMOX : CPU de la VM en type "host" -> MongoDB >= 5 exige AVX.
# Avec le type kvm64 par defaut, mongod plante en "Illegal instruction".
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

echo "==> [0/6] Controle AVX (CPU Proxmox = host ?)"
grep -q avx /proc/cpuinfo || { echo "ERREUR: pas d'AVX visible. Passer le CPU de la VM en type 'host' dans Proxmox."; exit 1; }

echo "==> [1/6] Depot MongoDB 8.0"
# NOTE: on pointe volontairement sur 'bookworm' : le composant 'trixie' du depot
# MongoDB ne contient pas (encore) le serveur. Les paquets bookworm fonctionnent
# sur Debian 13 amd64 (libssl3t64 fournit libssl3).
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc \
  | gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg
cat > /etc/apt/sources.list.d/mongodb-org-8.0.list <<'EOF'
deb [arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main
EOF
apt-get update -qq
apt-get install -y -qq mongodb-org
apt-mark hold mongodb-org mongodb-org-server mongodb-org-mongos \
  mongodb-org-tools mongodb-org-database mongodb-org-database-tools-extra >/dev/null
systemctl stop mongod || true

echo "==> [2/6] KeyFile (auth interne du replica set)"
if [[ ! -f /etc/mongod.keyfile ]]; then
  openssl rand -base64 756 > /etc/mongod.keyfile
fi
chown mongodb:mongodb /etc/mongod.keyfile
chmod 400 /etc/mongod.keyfile

echo "==> [3/6] /etc/mongod.conf"
cat > /etc/mongod.conf <<EOF
# MongoDB - stack SIEM Graylog OMNITECH (genere par 02-mongodb.sh)
storage:
  dbPath: /var/lib/mongodb
  wiredTiger:
    engineConfig:
      cacheSizeGB: ${MONGO_CACHE_GB}   # plafond memoire: VM mutualisee

systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  logRotate: reopen

net:
  port: 27017
  bindIp: 127.0.0.1        # JAMAIS expose : Graylog est sur la meme VM

processManagement:
  timeZoneInfo: /usr/share/zoneinfo

replication:
  replSetName: rs0

security:
  keyFile: /etc/mongod.keyfile   # implique authorization: enabled
EOF
systemctl enable --now mongod
echo "    Attente de mongod..."
for i in $(seq 1 24); do
  mongosh --quiet --eval 'db.runCommand({ping:1})' >/dev/null 2>&1 && break
  sleep 5
done
mongosh --quiet --eval 'db.runCommand({ping:1})' >/dev/null 2>&1 \
  || { echo "ERREUR: mongod ne repond pas (journalctl -u mongod)"; exit 1; }

echo "==> [4/6] Initialisation du replica set rs0"
mongosh --quiet --eval '
try { rs.status(); print("rs0 deja initialise."); }
catch (e) {
  rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27017"}]});
  print("rs0 initialise.");
}' || true
sleep 5

echo "==> [5/6] Creation des utilisateurs (admin + graylog)"
# L'exception localhost autorise la creation du premier utilisateur.
mongosh --quiet <<EOF
const adminDb = db.getSiblingDB("admin");
try {
  adminDb.createUser({ user: "admin",
    pwd: "${MONGO_ADMIN_PASS}",
    roles: [ { role: "root", db: "admin" } ] });
  print("Utilisateur admin cree.");
} catch (e) { print("admin: " + e.message); }
EOF
mongosh --quiet -u admin -p "${MONGO_ADMIN_PASS}" --authenticationDatabase admin <<EOF
const gl = db.getSiblingDB("graylog");
try {
  gl.createUser({ user: "graylog",
    pwd: "${MONGO_GRAYLOG_PASS}",
    roles: [ { role: "readWrite", db: "graylog" },
             { role: "dbAdmin",  db: "graylog" } ] });
  print("Utilisateur graylog cree.");
} catch (e) { print("graylog: " + e.message); }
EOF

echo "==> [6/6] Verification de l'authentification"
mongosh --quiet -u graylog -p "${MONGO_GRAYLOG_PASS}" \
  --authenticationDatabase graylog \
  "mongodb://127.0.0.1:27017/graylog?replicaSet=rs0" \
  --eval 'db.runCommand({ping:1}).ok === 1 ? print("AUTH graylog: OK") : print("AUTH graylog: ECHEC")'

echo
echo "=== 02-mongodb.sh termine. Lancer 03-opensearch.sh ==="
