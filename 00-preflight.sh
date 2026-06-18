#!/usr/bin/env bash
# ==============================================================================
# 00-preflight.sh - Analyse de la machine AVANT installation
#   Detecte les erreurs avant qu'elles n'apparaissent :
#     - OS, CPU (AVX !), RAM, swap, disques (propose DATA_DISK), partitions
#     - interface reseau, IP/passerelle/DNS reels vs 00-vars.env
#     - resolution DNS du FQDN, joignabilite depots apt, ports deja occupes
#     - services concurrents deja installes (mongod/opensearch/graylog/nginx)
#   Usage :
#     ./00-preflight.sh              -> rapport PASS/WARN/FAIL
#     ./00-preflight.sh --gen-vars   -> ecrit en plus 00-vars.autodetect.env
#                                       (suggestions a reporter dans 00-vars.env)
# ==============================================================================
set -uo pipefail   # pas de -e : on veut TOUT analyser meme en cas d'echec
cd "$(dirname "$0")"
source ./00-vars.env 2>/dev/null || { echo "00-vars.env introuvable"; exit 1; }

GEN=0; [[ "${1:-}" == "--gen-vars" ]] && GEN=1
P=0; W=0; F=0
pass() { echo "  [PASS] $*"; P=$((P+1)); }
warn() { echo "  [WARN] $*"; W=$((W+1)); }
fail() { echo "  [FAIL] $*"; F=$((F+1)); }

echo "================= PREFLIGHT SIEM OMNITECH - $(date '+%F %T') ================="

# ---------------------------------------------------------------- 1. Systeme
echo "--- [1] Systeme"
[[ $EUID -eq 0 ]] && pass "Execution en root" || fail "A lancer en root"
. /etc/os-release 2>/dev/null
if [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]]; then
  pass "Debian 13 (${VERSION_CODENAME:-?})"
else
  warn "OS detecte: ${PRETTY_NAME:-inconnu} (kit prevu pour Debian 13)"
fi
if grep -qw avx /proc/cpuinfo; then
  pass "AVX present ($(nproc) vCPU) - MongoDB OK"
else
  fail "AVX ABSENT : passer le CPU de la VM en type 'host' dans Proxmox (sinon mongod plantera)"
fi
systemd-detect-virt -q && pass "Virtualisation: $(systemd-detect-virt)" || true

# ---------------------------------------------------------------- 2. Memoire
echo "--- [2] Memoire"
RAM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
if   (( RAM_GB >= 30 )); then pass "RAM: ${RAM_GB} Go"
elif (( RAM_GB >= 15 )); then warn "RAM: ${RAM_GB} Go - reduire OS_HEAP (~$((RAM_GB/3))g) et GL_HEAP (2g)"
else fail "RAM: ${RAM_GB} Go - insuffisant pour le stack complet (min ~16 Go)"; fi
# suggestion de heaps
SUG_OS_HEAP="$(( RAM_GB / 3 ))"; (( SUG_OS_HEAP > 31 )) && SUG_OS_HEAP=31; (( SUG_OS_HEAP < 2 )) && SUG_OS_HEAP=2
SUG_GL_HEAP="$(( RAM_GB / 8 ))"; (( SUG_GL_HEAP < 2 )) && SUG_GL_HEAP=2; (( SUG_GL_HEAP > 8 )) && SUG_GL_HEAP=8
SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
(( SWAP_KB > 0 )) && pass "Swap present ($((SWAP_KB/1024)) Mo) - vm.swappiness sera mis a 1" \
                  || warn "Pas de swap (acceptable, heaps verrouillees - surveiller l'OOM killer)"

# ---------------------------------------------------------------- 3. Disques
echo "--- [3] Disques"
echo "      Inventaire :"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT --noheadings | sed 's/^/        /'
ROOT_FREE_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
(( ROOT_FREE_GB >= 30 )) && pass "Espace libre sur / : ${ROOT_FREE_GB} Go" \
                         || warn "Espace libre sur / : ${ROOT_FREE_GB} Go (juste ; prevoir disque data)"
# Detection d'un disque vierge candidat pour DATA_DISK
SUG_DATA_DISK=""
for D in $(lsblk -dno NAME,TYPE | awk '$2=="disk"{print $1}'); do
  DEV="/dev/${D}"
  # vierge = aucune partition, aucun FS, pas le disque racine
  if [[ -z "$(lsblk -no FSTYPE,MOUNTPOINT "${DEV}" | tr -d '[:space:]')" ]] \
     && ! lsblk -no MOUNTPOINT "${DEV}" | grep -q '^/$'; then
    SIZE=$(lsblk -dno SIZE "${DEV}")
    SUG_DATA_DISK="${DEV}"
    pass "Disque vierge detecte: ${DEV} (${SIZE}) -> candidat DATA_DISK"
  fi
done
if [[ -n "${DATA_DISK}" ]]; then
  [[ -b "${DATA_DISK}" ]] && pass "DATA_DISK=${DATA_DISK} existe" || fail "DATA_DISK=${DATA_DISK} introuvable"
elif [[ -z "${SUG_DATA_DISK}" ]]; then
  warn "Aucun disque data dedie (DATA_DISK vide, aucun disque vierge) : OpenSearch ecrira sur /"
fi
ROT=$(lsblk -dno ROTA "$(lsblk -no PKNAME "$(findmnt -no SOURCE /)" 2>/dev/null | head -1 | sed 's|^|/dev/|')" 2>/dev/null || echo "?")
[[ "${ROT}" == "0" ]] && pass "Stockage non rotatif (SSD/NVMe)" || warn "Stockage rotatif ou indetermine : indexation OpenSearch penalisee"

# ---------------------------------------------------------------- 4. Reseau
echo "--- [4] Reseau"
DEF_ROUTE="$(ip -4 route show default | head -1)"
CUR_IFACE="$(awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' <<<"${DEF_ROUTE}")"
CUR_GW="$(awk '{for(i=1;i<NF;i++) if($i=="via") print $(i+1)}' <<<"${DEF_ROUTE}")"
CUR_IP="$(ip -4 -o addr show dev "${CUR_IFACE:-lo}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
echo "      Detecte : iface=${CUR_IFACE:-?}  ip=${CUR_IP:-?}  gw=${CUR_GW:-?}"
[[ "${CUR_IFACE:-}" == "${SIEM_IFACE}" ]] && pass "SIEM_IFACE coherent (${SIEM_IFACE})" \
  || warn "SIEM_IFACE='${SIEM_IFACE}' mais interface active='${CUR_IFACE:-?}' -> corriger 00-vars.env"
[[ "${CUR_IP:-}" == "${SIEM_IP}" ]] && pass "IP deja en place (${SIEM_IP})" \
  || warn "IP actuelle=${CUR_IP:-?} ; cible=${SIEM_IP} (normal si pas encore configuree)"
[[ "${CUR_GW:-}" == "${SIEM_GW}" ]] && pass "Passerelle coherente (${SIEM_GW})" \
  || warn "SIEM_GW='${SIEM_GW}' mais passerelle active='${CUR_GW:-?}'"
ping -c1 -W2 "${CUR_GW:-${SIEM_GW}}" >/dev/null 2>&1 && pass "Passerelle joignable" || fail "Passerelle injoignable"
# doublon de definition d'interface ?
if [[ -f /etc/network/interfaces ]] && grep -qE "^\s*iface\s+${SIEM_IFACE}\b" /etc/network/interfaces \
   && [[ -f /etc/network/interfaces.d/siem ]]; then
  fail "Interface ${SIEM_IFACE} definie DANS /etc/network/interfaces ET interfaces.d/siem (doublon a resoudre)"
fi

echo "--- [5] DNS / NTP / depots"
for R in "${DNS1}" "${DNS2}"; do
  ping -c1 -W2 "${R}" >/dev/null 2>&1 && pass "DC ${R} joignable (ICMP)" || warn "DC ${R} ne repond pas au ping"
done
RES="$(getent hosts "${SIEM_FQDN}" | awk '{print $1}' | head -1)"
if [[ "${RES}" == "${SIEM_IP}" ]]; then pass "DNS: ${SIEM_FQDN} -> ${SIEM_IP}"
elif [[ -n "${RES}" ]]; then fail "DNS: ${SIEM_FQDN} -> ${RES} (attendu ${SIEM_IP}) : corriger l'enregistrement A sur le DC"
else warn "DNS: ${SIEM_FQDN} ne resout pas encore -> creer A + PTR sur ${DNS1}"; fi
for URL in deb.debian.org repo.mongodb.org artifacts.opensearch.org packages.graylog2.org; do
  curl -sI --connect-timeout 5 "https://${URL}" >/dev/null 2>&1 \
    && pass "HTTPS sortant OK vers ${URL}" || fail "Pas d'acces https://${URL} (regle FortiGate / proxy ?)"
done
ping -c1 -W2 "${IP_FAZ}" >/dev/null 2>&1 && pass "FortiAnalyzer ${IP_FAZ} joignable" || warn "FAZ ${IP_FAZ} ne repond pas au ping (ICMP filtre ?)"

echo "--- [6] Ports & services concurrents"
for PORT in 80 443 1514 5044 5555 9000 9200 27017; do
  if ss -lnt "( sport = :${PORT} )" 2>/dev/null | grep -q LISTEN; then
    warn "Port ${PORT} deja en ecoute : $(ss -lntp "( sport = :${PORT} )" | tail -1 | grep -oP '\".*?\"' | head -1)"
  else pass "Port ${PORT} libre"; fi
done
for SVC in mongod opensearch graylog-server nginx; do
  systemctl list-unit-files 2>/dev/null | grep -q "^${SVC}\." \
    && warn "Service ${SVC} deja present (machine non vierge : les scripts reconfigureront)" || true
done

echo "--- [7] Noyau"
MMC=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
(( MMC >= 262144 )) && pass "vm.max_map_count=${MMC}" || warn "vm.max_map_count=${MMC} (corrige par 01-base.sh)"
THP=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo "?")
grep -q '\[never\]' <<<"${THP}" && pass "THP desactivees" || warn "THP actives : ${THP} (corrige par 01-base.sh)"

# ---------------------------------------------------------------- Synthese
echo "==============================================================================="
echo " RESULTAT : ${P} PASS / ${W} WARN / ${F} FAIL"
if (( F > 0 )); then echo " >> Corriger les FAIL avant de lancer 01-base.sh."
elif (( W > 0 )); then echo " >> WARN a relire ; la plupart sont corriges par les scripts suivants."
else echo " >> Machine prete."; fi

if (( GEN )); then
  cat > 00-vars.autodetect.env <<EOF
# Suggestions auto-detectees le $(date '+%F %T') - A RELIRE puis reporter dans 00-vars.env
SIEM_IFACE="${CUR_IFACE:-${SIEM_IFACE}}"
SIEM_GW="${CUR_GW:-${SIEM_GW}}"
DATA_DISK="${SUG_DATA_DISK}"
OS_HEAP="${SUG_OS_HEAP}g"
GL_HEAP="${SUG_GL_HEAP}g"
EOF
  echo " >> Suggestions ecrites dans 00-vars.autodetect.env :"
  sed 's/^/      /' 00-vars.autodetect.env
fi
exit $(( F > 0 ? 1 : 0 ))
