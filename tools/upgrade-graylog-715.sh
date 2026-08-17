#!/usr/bin/env bash
# =============================================================================
# Montee Graylog 7.1.3 -> 7.1.5. A LANCER PAR L'OPERATEUR :
#   ! bash /root/omnitech-siem-setup/tools/upgrade-graylog-715.sh
#
# L'assistant a DEJA fait le travail de securite (17/07/2026 ~23:57) :
#   - mongodump FRAIS et verifie restaurable :
#       /home/siem-backup/mongo/graylog-mongo-20260717-2357-PRE-UPGRADE-715.archive.gz
#   - paquet de ROLLBACK en cache :
#       /var/cache/apt/archives/graylog-server_7.1.3-1_amd64.deb
#   - hold graylog-server LEVE (Mongo/OpenSearch restent figes)
#
# 7.1.3 -> 7.1.5 est un saut de PATCH (depot apt = graylog-7.1, aucun 8.x possible) :
# matrice de compat stable. La config existante est CONSERVEE (--force-confold).
# set -e : arret au premier echec. Rollback en bas de fichier.
# =============================================================================
set -euo pipefail
cd /root/omnitech-siem-setup
source 00-vars.env
GL="https://bx-it-graylog-vm.omnitech.security/api"
BK="/home/siem-backup/mongo/graylog-mongo-20260717-2357-PRE-UPGRADE-715.archive.gz"
log(){ printf '\n== %s\n' "$*"; }

log "0/6 Verification du filet de securite"
[ -f "$BK" ] || { echo "FATAL: backup pre-montee absent ($BK). ARRET."; exit 1; }
[ -f /var/cache/apt/archives/graylog-server_7.1.3-1_amd64.deb ] || echo "  ATTENTION: deb 7.1.3 absent du cache (rollback par restore Mongo seulement)"
echo "  backup present : $(ls -la "$BK" | awk '{print $5" o, "$6" "$7" "$8}')"

log "1/6 Installation 7.1.5 (conserve la config)"
DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confold" graylog-server
dpkg -l graylog-server | grep '^ii' | awk '{print "  paquet: "$2" "$3}'

log "2/6 Redemarrage controle"
systemctl restart graylog-server

log "3/6 Attente du retour en service (jusqu'a 180 s)"
OK=""
for i in $(seq 1 36); do
  sleep 5
  V="$(curl -sk -u "admin:${GRAYLOG_ADMIN_PASS}" "$GL/system" 2>/dev/null \
        | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("version",""),d.get("lifecycle",""),d.get("is_processing",""))' 2>/dev/null || true)"
  echo "  [$((i*5))s] ${V:-<pas encore de reponse>}"
  case "$V" in *7.1.5*running*True*) OK=1; break;; esac
done
[ "$OK" = 1 ] || { echo "  ECHEC : Graylog n'est pas revenu 7.1.5/running/processing. ROLLBACK (voir bas)."; exit 1; }
echo "  -> Graylog 7.1.5 en service, traitement actif."

log "4/6 Re-figer la version (hold)"
apt-mark hold graylog-server
echo "  holds: $(apt-mark showhold | tr '\n' ' ')"

log "5/6 Controles fonctionnels (inputs + ingestion recente)"
curl -sk -u "admin:${GRAYLOG_ADMIN_PASS}" "$GL/system/inputstates" 2>/dev/null \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);s=d.get("states",[]);r=sum(1 for x in s if x.get("state")=="RUNNING");print(f"  inputs RUNNING: {r}/{len(s)}")' 2>/dev/null || echo "  (verif inputs indisponible)"
TOT=$(curl -s -X POST "http://127.0.0.1:9200/omni-*/_count" -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-5m"}}}}' 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count","?"))' 2>/dev/null)
echo "  docs ingeres sur les 5 dernieres min: ${TOT}  (doit etre > 0 = flux repris)"

log "6/6 Veille de version : la dette graylog-server doit disparaitre"
/usr/local/sbin/omni-version-watch 2>&1 | grep -i graylog || echo "  graylog plus signale en retard -> coherent"

log "MONTEE 7.1.5 REUSSIE."
exit 0

# =============================================================================
# ROLLBACK (si l'etape 3 echoue) :
#   systemctl stop graylog-server
#   dpkg -i /var/cache/apt/archives/graylog-server_7.1.3-1_amd64.deb
#   systemctl start graylog-server
#   apt-mark hold graylog-server
# Si (et seulement si) les donnees de config sont corrompues apres coup :
#   systemctl stop graylog-server
#   source /root/omnitech-siem-setup/00-vars.env
#   mongorestore --gzip --drop --archive="/home/siem-backup/mongo/graylog-mongo-20260717-2357-PRE-UPGRADE-715.archive.gz" \
#     --uri "mongodb://admin:${MONGO_ADMIN_PASS}@127.0.0.1:27017/?replicaSet=rs0&authSource=admin"
#   systemctl start graylog-server
# =============================================================================
