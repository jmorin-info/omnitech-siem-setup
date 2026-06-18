#!/usr/bin/env bash
# ==============================================================================
# 09-snmpd.sh (OPTIONNEL) - Agent SNMPv3 pour supervision Centreon
#   Cree un utilisateur SNMPv3 lecture seule (SHA/AES) et restreint l'ecoute
#   a l'IP du SIEM. Renseigner SNMP_V3_AUTH_PASS / SNMP_V3_PRIV_PASS dans
#   00-vars.env avant execution (8 caracteres minimum chacun).
#   Ne pas oublier IP_CENTREON dans 00-vars.env + relancer 06-firewall.sh.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }
[[ -n "${SNMP_V3_AUTH_PASS}" && -n "${SNMP_V3_PRIV_PASS}" ]] || \
  { echo "ERREUR: definir SNMP_V3_AUTH_PASS et SNMP_V3_PRIV_PASS dans 00-vars.env."; exit 1; }

apt-get install -y -qq snmpd libsnmp-base snmp
systemctl stop snmpd

# Creation de l'utilisateur v3 (ecrit dans /var/lib/snmp/snmpd.conf)
net-snmp-create-v3-user -ro \
  -A "${SNMP_V3_AUTH_PASS}" -a SHA \
  -X "${SNMP_V3_PRIV_PASS}" -x AES \
  "${SNMP_V3_USER}" || echo "(utilisateur deja present ?)"

cat > /etc/snmp/snmpd.conf <<EOF
# SNMPv3 supervision Centreon (genere par 09-snmpd.sh)
agentAddress udp:${SIEM_IP}:161
rouser ${SNMP_V3_USER} priv
sysLocation  Site Omega - Saint-Medard-en-Jalles
sysContact   RSSI OMNITECH Security
sysServices  72
# Supervision disque/charge cote agent (seuils geres par Centreon de toute facon)
includeAllDisks 10%
EOF

systemctl enable --now snmpd
echo
echo "Test local :"
echo "  snmpwalk -v3 -u ${SNMP_V3_USER} -l authPriv -a SHA -A '<auth>' -x AES -X '<priv>' ${SIEM_IP} sysDescr"
echo
echo "Cote Centreon : ajouter l'hote ${SIEM_FQDN} (${SIEM_IP}), modele OS-Linux-SNMP,"
echo "services CPU / memoire / disques (/, /var/lib/opensearch, ${BACKUP_DIR}),"
echo "+ check TCP 443/5044/1514 et un check process java/mongod/opensearch."
