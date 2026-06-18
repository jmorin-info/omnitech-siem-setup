#!/usr/bin/env bash
# ==============================================================================
# 03-opensearch.sh - OpenSearch 2.19.x (canal apt 2.x, JAMAIS la 3.x)
#   - mono-noeud, bind 127.0.0.1 uniquement
#   - plugin de securite DESACTIVE (acces local seul -> recommandation Graylog)
#   - heap fixee, memory_lock, depot de snapshots pour les sauvegardes
#
# !! Graylog 7.1 supporte OpenSearch au maximum en 2.19.5. La 3.x CASSE
# !! l'instance. On installe depuis le canal 2.x et on gele le paquet.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

echo "==> [1/6] Depot OpenSearch (canal 2.x uniquement)"
curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp \
  | gpg --dearmor -o /usr/share/keyrings/opensearch-keyring.gpg
cat > /etc/apt/sources.list.d/opensearch-2.x.list <<'EOF'
deb [signed-by=/usr/share/keyrings/opensearch-keyring.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main
EOF
apt-get update -qq

echo "==> [2/6] Installation (mot de passe bootstrap exige par le paquet >= 2.12)"
OPENSEARCH_INITIAL_ADMIN_PASSWORD="${OPENSEARCH_BOOTSTRAP_PASS}" \
  apt-get install -y -qq opensearch
apt-mark hold opensearch >/dev/null
echo "    Paquet 'opensearch' gele (apt-mark hold). MAJ uniquement en controle,"
echo "    en restant <= a la version max supportee par Graylog (2.19.5 pour 7.1)."
systemctl stop opensearch || true
# Le performance-analyzer consomme CPU/RAM pour rien sur un mono-noeud supervise par Centreon
systemctl disable --now opensearch-performance-analyzer 2>/dev/null || true

echo "==> [3/6] /etc/opensearch/opensearch.yml"
# Repertoire de donnees : sur le grand disque si DATA_MOUNT est defini
OS_DATA="/var/lib/opensearch"
[[ -n "${DATA_MOUNT:-}" ]] && OS_DATA="${DATA_MOUNT}/opensearch"
mkdir -p "${OS_DATA}" "${BACKUP_DIR}/opensearch-snapshots"
cat > /etc/opensearch/opensearch.yml <<EOF
# OpenSearch - backend d'indexation Graylog (genere par 03-opensearch.sh)
cluster.name: graylog
node.name: ${SIEM_HOSTNAME}

path.data: ${OS_DATA}
path.logs: /var/log/opensearch
path.repo: ["${BACKUP_DIR}/opensearch-snapshots"]

network.host: 127.0.0.1          # JAMAIS expose : Graylog est sur la meme VM
http.port: 9200
discovery.type: single-node

# Recommandations Graylog
action.auto_create_index: false
indices.query.bool.max_clause_count: 32768

# Acces uniquement local -> plugin de securite inutile (TLS/Nginx cote Graylog)
plugins.security.disabled: true

bootstrap.memory_lock: true
EOF
chown -R opensearch:opensearch "${OS_DATA}" "${BACKUP_DIR}/opensearch-snapshots"

echo "==> [4/6] Heap JVM = ${OS_HEAP}"
sed -i -E "s/^-Xms[0-9]+[gm]/-Xms${OS_HEAP}/; s/^-Xmx[0-9]+[gm]/-Xmx${OS_HEAP}/" \
  /etc/opensearch/jvm.options
grep -E '^-Xm[sx]' /etc/opensearch/jvm.options

echo "==> [5/6] Override systemd (memory lock)"
mkdir -p /etc/systemd/system/opensearch.service.d
cat > /etc/systemd/system/opensearch.service.d/override.conf <<'EOF'
[Service]
LimitMEMLOCK=infinity
LimitNOFILE=65535
EOF
systemctl daemon-reload
systemctl enable --now opensearch

echo "==> [6/6] Attente du cluster..."
for i in $(seq 1 30); do
  STATUS="$(curl -s 'http://127.0.0.1:9200/_cluster/health' | jq -r .status 2>/dev/null || true)"
  [[ "${STATUS}" == "green" || "${STATUS}" == "yellow" ]] && break
  sleep 5
done
curl -s 'http://127.0.0.1:9200/' | jq '{name:.name, version:.version.number}' || \
  { echo "ERREUR: OpenSearch ne repond pas. Voir /var/log/opensearch/graylog.log"; exit 1; }
echo "    Etat cluster: ${STATUS:-inconnu}"

echo
echo "=== 03-opensearch.sh termine. Lancer 04-graylog.sh ==="
