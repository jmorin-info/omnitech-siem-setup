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
#   Les binaires Windows sont optionnels et exclus du manifeste s'ils manquent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: root requis."; exit 1; }
KIT=/var/www/siem-kit
mkdir -p "$KIT"

required=(kit/install.sh kit/install.ps1 kit/linux-omni.sh
  windows/Install-OmniSiem-NinjaOne.ps1 windows/Get-OmniInventory.ps1
  windows/winlogbeat.yml windows/audit-baseline.csv
  windows/sysmonconfig-omnitech.xml)
for f in "${required[@]}"; do
  [[ -s "$f" ]] || { echo "ERREUR: fichier source absent ou vide: $f" >&2; exit 1; }
done
SITE_NAME="${SITE_NAME:-site-01}"
[[ "$SIEM_FQDN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "ERREUR: SIEM_FQDN invalide" >&2; exit 1; }
[[ "$SIEM_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "ERREUR: SIEM_IP doit être une IPv4" >&2; exit 1; }
IFS=. read -r -a ip_octets <<< "$SIEM_IP"
for octet in "${ip_octets[@]}"; do
  (( 10#$octet <= 255 )) || { echo "ERREUR: SIEM_IP doit être une IPv4 valide" >&2; exit 1; }
done
[[ "$SITE_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "ERREUR: SITE_NAME contient des caractères non pris en charge" >&2; exit 1; }
BEATS_CERT="${GRAYLOG_BEATS_CERT_FILE:-}"
if [[ -n "$BEATS_CERT" ]]; then
  [[ -s "$BEATS_CERT" ]] || { echo "ERREUR: GRAYLOG_BEATS_CERT_FILE absent ou vide: $BEATS_CERT" >&2; exit 1; }
elif [[ -s "$KIT/omnitech-rootca.pem" ]]; then
  BEATS_CERT="$KIT/omnitech-rootca.pem"
else
  echo "ERREUR: certificat Beats absent. Définir GRAYLOG_BEATS_CERT_FILE dans 00-vars.env ou déposer omnitech-rootca.pem sous $KIT." >&2
  exit 1
fi

# Construire dans un répertoire frère, en conservant les binaires et fichiers
# locaux déjà présents. La publication ne remplace le répertoire actif qu'après
# validation complète du manifeste ; l'ancien kit reste disponible pour retour.
STAGE="$(mktemp -d /var/www/siem-kit.stage.XXXXXX)"
trap '[[ -z "${STAGE:-}" ]] || rm -rf "$STAGE"' EXIT
cp -a "$KIT/." "$STAGE/"

echo "==> [1/3] Copie des installeurs + configs (repo -> $KIT)"
# Installeurs standalone (one-liner) + cœur + configurations Windows
install -m 644 kit/install.sh                        "$STAGE/install.sh"
install -m 644 kit/install.ps1                       "$STAGE/install.ps1"
for f in Install-OmniSiem-NinjaOne.ps1 Get-OmniInventory.ps1 winlogbeat.yml \
         audit-baseline.csv sysmonconfig-omnitech.xml; do
  [[ -f "windows/$f" ]] && install -m 644 "windows/$f" "$STAGE/$f" && echo "    [+] $f"
done
# kit Linux historique (reference) conserve aussi
install -m 644 kit/linux-omni.sh                     "$STAGE/linux-omni.sh"

echo "==> [2/3] Substitution des paramètres du site dans les copies servies"
# On ne modifie QUE les copies sous /kit/, pas les sources versionnées.
sed -i "s|__SIEM_FQDN__|${SIEM_FQDN}|g; s|__SIEM_IP__|${SIEM_IP}|g; s|__SITE_NAME__|${SITE_NAME}|g" \
  "$STAGE/install.sh" "$STAGE/install.ps1" "$STAGE/Install-OmniSiem-NinjaOne.ps1" "$STAGE/winlogbeat.yml"
if grep -nE '__SIEM_(FQDN|IP)__|__SITE_NAME__' \
  "$STAGE/install.sh" "$STAGE/install.ps1" "$STAGE/Install-OmniSiem-NinjaOne.ps1" "$STAGE/winlogbeat.yml"; then
  echo "ERREUR: un marqueur de configuration du site est resté dans le kit généré" >&2
  exit 1
fi

# Le certificat public utilisé par Winlogbeat est propre au site et ne doit
# jamais être versionné. 00-vars.env peut désigner son emplacement ; le fichier
# historique sous /kit reste accepté pour les installations existantes.
if [[ "$(realpath "$BEATS_CERT")" != "$(realpath "$KIT/omnitech-rootca.pem" 2>/dev/null || true)" ]]; then
  install -m 644 "$BEATS_CERT" "$STAGE/omnitech-rootca.pem"
fi

# Alias historique : certaines taches NinjaOne telechargent /kit/agent.ps1.
# Il etait copie A LA MAIN (date du 13/06 contre le 23/06 pour le script reel) :
# il aurait diverge silencieusement a la prochaine modification, et une machine
# aurait deploye une version perimee sans que rien ne le signale. On le regenere
# donc a chaque publication a partir de la source unique.
install -m 644 "$STAGE/Install-OmniSiem-NinjaOne.ps1" "$STAGE/agent.ps1"
echo "    [+] agent.ps1 (alias de Install-OmniSiem-NinjaOne.ps1)"

echo "==> [3/3] Checksums d'integrite (SHA256SUMS)"
files=(install.sh install.ps1 linux-omni.sh agent.ps1
  Install-OmniSiem-NinjaOne.ps1 Get-OmniInventory.ps1 winlogbeat.yml
  audit-baseline.csv sysmonconfig-omnitech.xml omnitech-rootca.pem)
for f in Sysmon64.exe winlogbeat-*-windows-x86_64.zip; do
  [[ -s "$STAGE/$f" ]] && files+=("$f")
done
(
  cd "$STAGE"
  for f in "${files[@]}"; do
    [[ -s "$f" ]] || { echo "ERREUR: artefact absent ou vide: $f" >&2; exit 1; }
  done
  sha256sum "${files[@]}" > SHA256SUMS.tmp
  mv SHA256SUMS.tmp SHA256SUMS
  sha256sum -c SHA256SUMS
)
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
PREVIOUS="${KIT}.previous.$(date +%Y%m%d%H%M%S).$$"
mv "$KIT" "$PREVIOUS"
if ! mv "$STAGE" "$KIT"; then
  mv "$PREVIOUS" "$KIT"
  echo "ERREUR: publication impossible, ancien kit restauré depuis $PREVIOUS" >&2
  exit 1
fi
STAGE=""
trap - EXIT
echo
echo "=== 95 termine. Kit publie sous $KIT ($(wc -l < "$KIT/SHA256SUMS") artefacts hashes)."
echo "    Ancien kit conservé sous $PREVIOUS"
echo "    Verifier : curl -s https://${SIEM_FQDN}/kit/SHA256SUMS"
echo "    One-liner Linux  : curl -fsSL https://${SIEM_FQDN}/kit/install.sh | sudo bash -s -- ${SIEM_IP}"
echo "    One-liner Windows: irm https://${SIEM_FQDN}/kit/install.ps1 | iex ==="
