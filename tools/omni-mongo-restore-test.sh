#!/usr/bin/env bash
# =============================================================================
# omni-mongo-restore-test.sh : restauration chronométrée d'une archive MongoDB
#   dans une instance mongod TEMPORAIRE et isolée (127.0.0.1, port dédié,
#   répertoire jetable), puis comparaison collection par collection avec la
#   production (base graylog). Ne touche jamais l'instance de production : seule
#   une lecture (countDocuments) y est faite. L'instance temporaire est arrêtée
#   et son répertoire supprimé en fin de test, même en cas d'erreur.
#
#   sudo bash tools/omni-mongo-restore-test.sh [archive.gz]
#     défaut : archive la plus récente de $BACKUP_DIR/mongo
#   Variables : OMNI_SIEM_HOME, RESTORE_TEST_PORT (27018), RESTORE_TEST_DIR (/data).
# Sortie : durée de démarrage et de restauration, écarts éventuels ; code 0 si
#   aucun écart, 1 sinon. Première exécution : 22/11/2026, 69 collections et
#   21 681 documents identiques, restauration en 2,6 s.
# =============================================================================
set -euo pipefail
export LC_ALL=C
HOME_DEPOT="${OMNI_SIEM_HOME:-/opt/omni-siem/repository}"
PORT="${RESTORE_TEST_PORT:-27018}"
BASE="${RESTORE_TEST_DIR:-/data}"
ENVFILE="${OMNI_VARS_FILE:-$HOME_DEPOT/00-vars.env}"
# shellcheck disable=SC1090
set -a; source "$ENVFILE"; set +a
ARCH="${1:-$(ls -t "${BACKUP_DIR:-/home/siem-backup}"/mongo/graylog-mongo-*.archive.gz 2>/dev/null | head -1)}"
[[ -f "$ARCH" ]] || { echo "archive introuvable : ${ARCH:-aucune}" >&2; exit 2; }
if ss -ltn "sport = :$PORT" | grep -q LISTEN; then echo "port $PORT déjà utilisé" >&2; exit 2; fi

TRAV="$(mktemp -d "$BASE/omni-restore-test.XXXXXX")"
nettoyer() {
  mongosh --quiet --port "$PORT" --eval 'db.getSiblingDB("admin").shutdownServer()' >/dev/null 2>&1 || true
  sleep 1; rm -rf "$TRAV"
}
trap nettoyer EXIT
mkdir -p "$TRAV/db"
echo "archive : $ARCH"

T0=$(date +%s.%N)
mongod --dbpath "$TRAV/db" --port "$PORT" --bind_ip 127.0.0.1 --wiredTigerCacheSizeGB 0.5 \
  --fork --logpath "$TRAV/mongod.log" >/dev/null
T1=$(date +%s.%N)
mongorestore --quiet --host 127.0.0.1 --port "$PORT" --gzip --archive="$ARCH" \
  --nsExclude='config.*' --nsExclude='local.*' --nsExclude='admin.system.*'
T2=$(date +%s.%N)

Q='const d=db.getSiblingDB("graylog"); const o={}; d.getCollectionNames().filter(c=>!c.startsWith("system.")).sort().forEach(c=>o[c]=d.getCollection(c).countDocuments()); print(JSON.stringify(o))'
mongosh --quiet "mongodb://127.0.0.1:$PORT/" --eval "$Q" > "$TRAV/restaure.json"
# Lecture de la production : le mot de passe est passé en argument du seul processus mongosh (même pratique que 30-backup-config.sh).
mongosh --quiet "mongodb://127.0.0.1:27017/?replicaSet=rs0&authSource=admin" -u admin \
  -p "$MONGO_ADMIN_PASS" --eval "$Q" > "$TRAV/prod.json"

python3 -I - "$TRAV/restaure.json" "$TRAV/prod.json" "$T0" "$T1" "$T2" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); p = json.load(open(sys.argv[2]))
t0, t1, t2 = map(float, sys.argv[3:6])
ecarts = [(c, p.get(c), r.get(c)) for c in sorted(set(p) | set(r)) if p.get(c) != r.get(c)]
print(f"collections : production {len(p)}, restaurées {len(r)}")
print(f"documents   : production {sum(p.values())}, restaurés {sum(r.values())}")
for k in ("event_definitions", "pipeline_processor_rules", "streams", "inputs", "index_sets", "lut_tables"):
    print(f"  {k:26} production={p.get(k)} restauré={r.get(k)}")
print(f"durée : démarrage {t1 - t0:.1f} s, restauration {t2 - t1:.1f} s, total {t2 - t0:.1f} s")
if ecarts:
    print("ÉCARTS (une écriture en production pendant le test peut en expliquer quelques-uns) :")
    for c, a, b in ecarts:
        print(f"  {c} : production={a} restauré={b}")
    sys.exit(1)
print("aucun écart")
PY
