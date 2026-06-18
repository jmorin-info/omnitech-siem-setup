#!/usr/bin/env bash
# ==============================================================================
# 01-base.sh - Preparation systeme Debian 13 (trixie)
#   hostname, NTP (chrony -> PDC), sysctl, THP, paquets de base, fail2ban,
#   mises a jour de securite auto, disque data optionnel pour OpenSearch.
# A executer en root. Idempotent (re-executable sans casse).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

echo "==> [1/8] Hostname & /etc/hosts"
hostnamectl set-hostname "${SIEM_FQDN}"
grep -q "${SIEM_IP}.*${SIEM_FQDN}" /etc/hosts || \
  echo "${SIEM_IP}  ${SIEM_FQDN} ${SIEM_HOSTNAME}" >> /etc/hosts
timedatectl set-timezone Europe/Paris   # affichage local ; Graylog stocke en UTC

echo "==> [2/8] Paquets de base"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget gnupg ca-certificates apt-transport-https \
  lsb-release jq chrony nftables unattended-upgrades fail2ban rsync \
  qemu-guest-agent vim htop iotop net-tools uuid-runtime openssl
systemctl enable --now qemu-guest-agent || true

echo "==> [3/8] Reseau statique"
NETBLOCK="# --- SIEM ${SIEM_FQDN} ---
auto ${SIEM_IFACE}
iface ${SIEM_IFACE} inet static
    address ${SIEM_IP}/${SIEM_PREFIX}
    gateway ${SIEM_GW}
    dns-nameservers ${DNS1} ${DNS2}
    dns-search ${SIEM_DOMAIN}"
if [[ "${APPLY_NETWORK}" == "1" ]]; then
  mkdir -p /etc/network/interfaces.d
  echo "${NETBLOCK}" > /etc/network/interfaces.d/siem
  echo "    -> /etc/network/interfaces.d/siem ecrit."
  echo "    !! Verifier qu'aucune autre definition de ${SIEM_IFACE} n'existe"
  echo "    !! (grep -r ${SIEM_IFACE} /etc/network/) puis: systemctl restart networking"
else
  echo "    APPLY_NETWORK=0 : conf NON appliquee. Bloc suggere :"
  echo "${NETBLOCK}" | sed 's/^/      /'
fi

echo "==> [4/8] Chrony -> controleurs de domaine (A.8.17 ISO 27001)"
sed -i -E 's/^(pool .*)$/# \1  # remplace par les DC internes/' /etc/chrony/chrony.conf
grep -q "^server ${NTP1}" /etc/chrony/chrony.conf || cat >> /etc/chrony/chrony.conf <<EOF

# --- Sources internes OMNITECH (PDC = reference) ---
server ${NTP1} iburst prefer
server ${NTP2} iburst
makestep 1.0 3
EOF
systemctl restart chrony
chronyc sources || true

echo "==> [5/8] Sysctl (OpenSearch + syslog UDP)"
cat > /etc/sysctl.d/99-siem.conf <<'EOF'
# OpenSearch : nombre de zones memoire mappees (obligatoire)
vm.max_map_count = 262144
# Eviter le swap des heaps Java
vm.swappiness = 1
# Tampons reseau pour rafales syslog/UDP
net.core.rmem_max = 33554432
net.core.rmem_default = 8388608
EOF
sysctl --system >/dev/null

echo "==> [6/8] Desactivation Transparent Huge Pages (requis MongoDB)"
cat > /etc/systemd/system/disable-thp.service <<'EOF'
[Unit]
Description=Disable Transparent Huge Pages (MongoDB)
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=mongod.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled; echo never > /sys/kernel/mm/transparent_hugepage/defrag'

[Install]
WantedBy=basic.target
EOF
systemctl daemon-reload
systemctl enable --now disable-thp.service

echo "==> [7/8] Fail2ban (SSH) + mises a jour de securite automatiques"
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled  = true
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ${NET_ADMIN}
EOF
systemctl enable --now fail2ban
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
# Graylog/OpenSearch/MongoDB seront geles (apt-mark hold) : pas de MAJ sauvage.

echo "==> [8/8] Disque data dedie (montage sur ${DATA_MOUNT})"
if [[ -n "${DATA_DISK}" ]]; then
  if [[ -b "${DATA_DISK}" ]]; then
    if ! blkid "${DATA_DISK}"* >/dev/null 2>&1; then
      echo "    Formatage XFS de ${DATA_DISK} (donnees detruites !)"
      parted -s "${DATA_DISK}" mklabel gpt mkpart primary xfs 0% 100%
      sleep 2
      PART="$(lsblk -nrpo NAME "${DATA_DISK}" | sed -n 2p)"
      mkfs.xfs -f "${PART}"
      UUID="$(blkid -s UUID -o value "${PART}")"
      mkdir -p "${DATA_MOUNT}"
      grep -q "${UUID}" /etc/fstab || \
        echo "UUID=${UUID} ${DATA_MOUNT} xfs defaults,noatime 0 2" >> /etc/fstab
    else
      echo "    ${DATA_DISK} contient deja un systeme de fichiers -> pas de reformatage."
      echo "    (verifier que ${DATA_MOUNT} est bien monte ; sinon ajuster /etc/fstab)"
    fi
    mount -a
    # Sous-repertoires sur le grand disque (les chown vers opensearch/graylog
    # se font dans 03 et 04, une fois les comptes systeme crees par apt).
    mkdir -p "${DATA_MOUNT}/opensearch" "${DATA_MOUNT}/graylog-journal"
    echo "    ${DATA_MOUNT} : $(df -h --output=size,avail "${DATA_MOUNT}" | tail -1)"
  else
    echo "    ATTENTION: ${DATA_DISK} introuvable, etape ignoree."
  fi
else
  echo "    DATA_DISK vide -> donnees sur le disque systeme."
fi
# Repertoire de sauvegarde (sur sdb/home : separe physiquement des donnees sda)
mkdir -p "${BACKUP_DIR}"

echo
echo "=== 01-base.sh termine. Verifier 'chronyc sources' (PDC en ^*) puis lancer 02-mongodb.sh ==="
