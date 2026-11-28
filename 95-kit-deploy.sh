#!/usr/bin/env bash
# =============================================================================
# 95-kit-deploy.sh - Publie le kit d'enrolement sous /kit/ (servi par nginx en
#   TLS, alias /var/www/siem-kit/). Source de verite = depot (kit/, windows/).
#   Remplace les marqueurs du site (00-vars.env) dans les copies servies, puis
#   genere SHA256SUMS pour la verification d'integrite cote client. Idempotent.
#
#   Parametres du site (00-vars.env) :
#     SIEM_FQDN, SIEM_IP, SITE_NAME          adresse du SIEM et etiquette du site
#     GRAYLOG_BEATS_CERT_FILE                certificat public (ou CA) de l'entree
#                                            Beats ; jamais de cle privee
#     BEATS_CA_FILE                          nom publie de ce certificat
#                                            (defaut : omnitech-rootca.pem)
#     WINLOGBEAT_VERSION                     version cible ; deduite de l'archive
#                                            winlogbeat-*.zip deposee si absente
#     KIT_INSTALL_ROOT_CA                    1 = ajouter le certificat au magasin
#                                            racine des postes (defaut 0)
#   Les binaires (Sysmon64.exe, archive Winlogbeat) ne sont pas versionnes :
#   deposes une fois sous /var/www/siem-kit/, ils sont conserves et hashes.
#
#   Publication atomique : construction dans un repertoire frere, controle du
#   manifeste, puis bascule ; l'ancien kit reste dans /var/www/siem-kit.previous.*
#   (3 derniers conserves). Retour : mv du repertoire .previous a la place du kit.
#   Tests hors ligne : KIT_DIR et OMNI_VARS_FILE (tests/test_endpoint_kit.py).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
VARS_FILE="${OMNI_VARS_FILE:-./00-vars.env}"
# shellcheck source=/dev/null
source "$VARS_FILE"
KIT="${KIT_DIR:-/var/www/siem-kit}"
if [[ -z "${KIT_DIR:-}" && $EUID -ne 0 ]]; then echo "ERREUR: root requis." >&2; exit 1; fi
mkdir -p "$KIT"

required=(kit/install.sh kit/install.ps1 kit/linux-omni.sh
  windows/Install-OmniSiem-NinjaOne.ps1 windows/Get-OmniInventory.ps1
  windows/winlogbeat.yml windows/audit-baseline.csv
  windows/sysmonconfig-omnitech.xml)
for f in "${required[@]}"; do
  [[ -s "$f" ]] || { echo "ERREUR: fichier source absent ou vide: $f" >&2; exit 1; }
done

SITE_NAME="${SITE_NAME:-site-01}"
BEATS_CA_FILE="${BEATS_CA_FILE:-omnitech-rootca.pem}"
KIT_INSTALL_ROOT_CA="${KIT_INSTALL_ROOT_CA:-0}"
[[ "${SIEM_FQDN:-}" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "ERREUR: SIEM_FQDN invalide" >&2; exit 1; }
[[ "${SIEM_IP:-}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "ERREUR: SIEM_IP doit être une IPv4" >&2; exit 1; }
IFS=. read -r -a ip_octets <<< "$SIEM_IP"
for octet in "${ip_octets[@]}"; do
  (( 10#$octet <= 255 )) || { echo "ERREUR: SIEM_IP doit être une IPv4 valide" >&2; exit 1; }
done
[[ "$SITE_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "ERREUR: SITE_NAME contient des caractères non pris en charge" >&2; exit 1; }
[[ "$BEATS_CA_FILE" =~ ^[A-Za-z0-9._-]+\.(pem|crt)$ ]] || { echo "ERREUR: BEATS_CA_FILE doit être un nom de fichier .pem/.crt" >&2; exit 1; }
[[ "$KIT_INSTALL_ROOT_CA" == 0 || "$KIT_INSTALL_ROOT_CA" == 1 ]] || { echo "ERREUR: KIT_INSTALL_ROOT_CA doit valoir 0 ou 1" >&2; exit 1; }

# Version Winlogbeat : variable du site, sinon l'unique archive deposee.
shopt -s nullglob
zips=("$KIT"/winlogbeat-oss-*-windows-x86_64.zip "$KIT"/winlogbeat-[0-9]*-windows-x86_64.zip)
shopt -u nullglob
if [[ -z "${WINLOGBEAT_VERSION:-}" ]]; then
  if (( ${#zips[@]} == 1 )); then
    WINLOGBEAT_VERSION="$(basename "${zips[0]}" | sed -E 's/^winlogbeat-(oss-)?([0-9]+\.[0-9]+\.[0-9]+)-windows-x86_64\.zip$/\2/')"
  else
    echo "ERREUR: WINLOGBEAT_VERSION absent de 00-vars.env et ${#zips[@]} archive(s) winlogbeat-*.zip sous $KIT" >&2
    exit 1
  fi
fi
[[ "$WINLOGBEAT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERREUR: WINLOGBEAT_VERSION invalide: $WINLOGBEAT_VERSION" >&2; exit 1; }
if [[ ! -s "$KIT/winlogbeat-oss-$WINLOGBEAT_VERSION-windows-x86_64.zip" && ! -s "$KIT/winlogbeat-$WINLOGBEAT_VERSION-windows-x86_64.zip" ]]; then
  echo "ATTENTION: archive Winlogbeat $WINLOGBEAT_VERSION absente de $KIT : les nouveaux postes ne pourront pas l'installer" >&2
fi

# Certificat de la sortie Beats : public, propre au site, jamais versionne.
BEATS_CERT="${GRAYLOG_BEATS_CERT_FILE:-}"
if [[ -z "$BEATS_CERT" ]]; then
  if [[ -s "$KIT/$BEATS_CA_FILE" ]]; then BEATS_CERT="$KIT/$BEATS_CA_FILE"
  elif [[ -s "$KIT/omnitech-rootca.pem" ]]; then BEATS_CERT="$KIT/omnitech-rootca.pem"
  fi
fi
[[ -n "$BEATS_CERT" && -s "$BEATS_CERT" ]] || {
  echo "ERREUR: certificat Beats absent. Définir GRAYLOG_BEATS_CERT_FILE dans 00-vars.env ou déposer $BEATS_CA_FILE sous $KIT." >&2
  exit 1
}
if grep -q 'PRIVATE KEY' "$BEATS_CERT"; then
  echo "ERREUR: $BEATS_CERT contient une clé privée : publication refusée" >&2
  exit 1
fi
openssl x509 -in "$BEATS_CERT" -noout 2>/dev/null || { echo "ERREUR: $BEATS_CERT n'est pas un certificat PEM" >&2; exit 1; }

# Construire dans un répertoire frère, en conservant les binaires et fichiers
# locaux déjà présents. La publication ne remplace le répertoire actif qu'après
# validation complète du manifeste ; l'ancien kit reste disponible pour retour.
STAGE="$(mktemp -d "${KIT}.stage.XXXXXX")"
trap '[[ -z "${STAGE:-}" ]] || rm -rf "$STAGE"' EXIT
cp -a "$KIT/." "$STAGE/"

echo "==> [1/3] Copie des installeurs + configs (depot -> $KIT)"
install -m 644 kit/install.sh  "$STAGE/install.sh"
install -m 644 kit/install.ps1 "$STAGE/install.ps1"
for f in Install-OmniSiem-NinjaOne.ps1 Get-OmniInventory.ps1 winlogbeat.yml \
         audit-baseline.csv sysmonconfig-omnitech.xml; do
  install -m 644 "windows/$f" "$STAGE/$f" && echo "    [+] $f"
done
install -m 644 kit/linux-omni.sh "$STAGE/linux-omni.sh"
if [[ "$(realpath "$BEATS_CERT")" != "$(realpath "$STAGE/$BEATS_CA_FILE" 2>/dev/null || true)" ]]; then
  install -m 644 "$BEATS_CERT" "$STAGE/$BEATS_CA_FILE"
fi

echo "==> [2/3] Substitution des paramètres du site ($SITE_NAME, Winlogbeat $WINLOGBEAT_VERSION)"
# On ne modifie QUE les copies servies, pas les sources versionnées.
rendered=("$STAGE/install.sh" "$STAGE/install.ps1" "$STAGE/Install-OmniSiem-NinjaOne.ps1" "$STAGE/winlogbeat.yml")
sed -i -e "s|__SIEM_FQDN__|${SIEM_FQDN}|g" -e "s|__SIEM_IP__|${SIEM_IP}|g" \
  -e "s|__SITE_NAME__|${SITE_NAME}|g" -e "s|__BEATS_CA_FILE__|${BEATS_CA_FILE}|g" \
  -e "s|__WINLOGBEAT_VERSION__|${WINLOGBEAT_VERSION}|g" \
  -e "s|__KIT_INSTALL_ROOT_CA__|${KIT_INSTALL_ROOT_CA}|g" "${rendered[@]}"
if grep -nE '__[A-Z][A-Z0-9_]*__' "${rendered[@]}"; then
  echo "ERREUR: un marqueur de configuration du site est resté dans le kit généré" >&2
  exit 1
fi

# Alias historique : certaines taches NinjaOne telechargent /kit/agent.ps1.
# Regenere a chaque publication a partir de la source unique.
install -m 644 "$STAGE/Install-OmniSiem-NinjaOne.ps1" "$STAGE/agent.ps1"
echo "    [+] agent.ps1 (alias de Install-OmniSiem-NinjaOne.ps1)"

echo "==> [3/3] Checksums d'integrite (SHA256SUMS)"
files=(install.sh install.ps1 linux-omni.sh agent.ps1
  Install-OmniSiem-NinjaOne.ps1 Get-OmniInventory.ps1 winlogbeat.yml
  audit-baseline.csv sysmonconfig-omnitech.xml "$BEATS_CA_FILE")
shopt -s nullglob
for f in "$STAGE"/Sysmon64.exe "$STAGE"/winlogbeat-oss-*-windows-x86_64.zip "$STAGE"/winlogbeat-[0-9]*-windows-x86_64.zip; do
  [[ -s "$f" ]] && files+=("$(basename "$f")")
done
shopt -u nullglob
(
  cd "$STAGE"
  for f in "${files[@]}"; do
    [[ -s "$f" ]] || { echo "ERREUR: artefact absent ou vide: $f" >&2; exit 1; }
  done
  sha256sum "${files[@]}" > SHA256SUMS.tmp
  mv SHA256SUMS.tmp SHA256SUMS
  sha256sum -c --quiet SHA256SUMS
)
# Droits sur les seuls fichiers publiés : les sous-répertoires écrits par
# d'autres services (soar/, rapports/) gardent leurs propriétaires.
if [[ $EUID -eq 0 ]]; then
  ( cd "$STAGE" && chown root:root "${files[@]}" SHA256SUMS )
fi
( cd "$STAGE" && chmod 644 "${files[@]}" SHA256SUMS )
chmod 755 "$STAGE"
PREVIOUS="${KIT}.previous.$(date +%Y%m%d%H%M%S).$$"
mv "$KIT" "$PREVIOUS"
if ! mv "$STAGE" "$KIT"; then
  mv "$PREVIOUS" "$KIT"
  echo "ERREUR: publication impossible, ancien kit restauré depuis $PREVIOUS" >&2
  exit 1
fi
STAGE=""
trap - EXIT
# Ne garder que les 3 dernières versions précédentes (binaires volumineux).
mapfile -t old < <(ls -1d "${KIT}".previous.* 2>/dev/null | sort -r | tail -n +4)
for d in "${old[@]}"; do rm -rf -- "$d"; done
echo
echo "=== 95 termine. Kit publie sous $KIT ($(wc -l < "$KIT/SHA256SUMS") artefacts hashes)."
echo "    Ancien kit conservé sous $PREVIOUS"
echo "    Retour : mv $KIT $KIT.annule && mv $PREVIOUS $KIT"
echo "    Verifier : curl -s https://${SIEM_FQDN}/kit/SHA256SUMS"
echo "    One-liner Linux  : curl -fsSL https://${SIEM_FQDN}/kit/install.sh | sudo bash"
echo "    One-liner Windows: irm https://${SIEM_FQDN}/kit/install.ps1 | iex ==="
