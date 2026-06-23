#!/usr/bin/env bash
# =============================================================================
# 95-kit-deploy.sh - Publie le kit d'enrolement sous /kit/ (servi par nginx en
#   TLS, alias /var/www/siem-kit/). Source de verite = repo (kit/, windows/).
#   Substitue le FQDN/IP reels du SIEM (00-vars.env) dans les installeurs, puis
#   genere SHA256SUMS pour la verification d'integrite cote client (et le bouton
#   « verifier » de la page /soc Deploiement). Idempotent.
#
#   Materialise le « comment les artefacts arrivent sous /kit/ » jusqu'ici manuel.
#   NE TOUCHE PAS aux binaires deja deposes (Sysmon64.exe, winlogbeat *.zip) :
#   ils ne sont pas versionnes (trop gros) -> conserves s'ils existent.
#   Prerequis : artefacts Windows binaires deja presents sous /var/www/siem-kit/.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: root requis."; exit 1; }
KIT=/var/www/siem-kit
mkdir -p "$KIT"

echo "==> [1/3] Copie des installeurs + configs (repo -> $KIT)"
# Installeurs standalone (one-liner) + cœur + configs Windows + CA
install -m 644 kit/install.sh                        "$KIT/install.sh"
install -m 644 kit/install.ps1                       "$KIT/install.ps1"
for f in Install-OmniSiem-NinjaOne.ps1 Get-OmniInventory.ps1 winlogbeat.yml \
         audit-baseline.csv sysmonconfig-omnitech.xml; do
  [[ -f "windows/$f" ]] && install -m 644 "windows/$f" "$KIT/$f" && echo "    [+] $f"
done
# kit Linux historique (reference) conserve aussi
install -m 644 kit/linux-omni.sh                     "$KIT/linux-omni.sh"

echo "==> [2/3] Substitution FQDN/IP reels (${SIEM_FQDN} / ${SIEM_IP}) dans les copies servies"
# On ne modifie QUE les copies sous /kit/, pas les sources repo.
sed -i "s|bx-it-graylog-vm\.omnitech\.security|${SIEM_FQDN}|g" "$KIT/install.sh" "$KIT/install.ps1"
sed -i "s|10\.33\.220\.10|${SIEM_IP}|g" "$KIT/install.sh"

echo "==> [3/3] Checksums d'integrite (SHA256SUMS)"
( cd "$KIT" && sha256sum \
    install.sh install.ps1 linux-omni.sh \
    Install-OmniSiem-NinjaOne.ps1 Get-OmniInventory.ps1 winlogbeat.yml \
    audit-baseline.csv sysmonconfig-omnitech.xml omnitech-rootca.pem \
    Sysmon64.exe winlogbeat-oss-*.zip 2>/dev/null > SHA256SUMS ) || true
chown -R www-data:www-data "$KIT" 2>/dev/null || true
echo
echo "=== 95 termine. Kit publie sous $KIT ($(wc -l < "$KIT/SHA256SUMS") artefacts hashes)."
echo "    Verifier : curl -s https://${SIEM_FQDN}/kit/SHA256SUMS"
echo "    One-liner Linux  : curl -fsSL https://${SIEM_FQDN}/kit/install.sh | sudo bash -s -- ${SIEM_IP}"
echo "    One-liner Windows: irm https://${SIEM_FQDN}/kit/install.ps1 | iex ==="
