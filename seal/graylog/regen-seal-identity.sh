#!/usr/bin/env bash
# =============================================================================
# regen-seal-identity.sh - CSV du PONT D'IDENTITE badge -> UPN (BEST-EFFORT).
#
#   OBJET : produire /etc/graylog/lookup/seal-identity.csv (matricule -> UPN)
#   pour que 14-seal-identity-upn.rule resolve `identity_upn` sur les evenements
#   SEAL. L'UPN est la cle de jointure avec les logons Windows/M365 (identity).
#
#   REALITE DES DONNEES (verifiee 15/07, cf docs/CORRELATION-SEAL-AD.md) :
#   le champ `identity_matricule` (milf.BADGES.MATRICULE) est un CHAMP LIBRE
#   incoherent : parfois un NOM ("Maxime Pellen"), parfois des initiales
#   ("JPA"), un numero ("666"), une serie de badge, voire du texte libre. L'AD
#   n'a PAS d'attribut fiable (employeeID = 0 utilisateur). La SEULE resolution
#   qui marche est : matricule ressemblant a un NOM -> AD displayName -> UPN.
#   => ce script est un ENRICHISSEMENT BEST-EFFORT (couverture partielle), utile
#      pour l'investigation, PAS pour de la detection fiable. La vraie correction
#      est au niveau SEAL (identifiant propre par badge). Cf CORRELATION-SEAL-AD.md.
#
#   TENANT CO-MANAGE : certains porteurs de badge (site OMEGA) resolvent vers
#   invissys.com (societe soeur). L'enrichissement (etiquetage read-only) les
#   inclut ; AUCUNE reponse automatique ne cible ce tenant (oms-xdr = dry-run).
#
#   SOURCE : les valeurs `identity_matricule` REELLEMENT presentes sur les events
#   SEAL (API Graylog, terms agg) -> resolution AD via LDAPS (lecture seule, meme
#   compte de liaison que 33-ldaps-auth.sh). Idempotent (ecriture atomique +
#   remplacement conditionnel). A lancer par cron (ex chaque nuit).
#
#   Variables (hors code) : GRAYLOG_API_URL, GRAYLOG_API_TOKEN|GRAYLOG_ADMIN_PASS,
#   LDAP_BIND_DN, LDAP_BIND_PASS, LDAP_HOST (def bx-ad-01-it-vm.omnitech.security),
#   LDAP_SEARCH_BASE (def DC=omnitech,DC=security), LDAP_CA, LOOKUP_DIR.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for cand in "${SCRIPT_DIR}/00-vars.env" "${SCRIPT_DIR}/../00-vars.env" "${SCRIPT_DIR}/../../00-vars.env"; do
  [[ -f "${cand}" ]] && . "${cand}" && break
done

LDAP_HOST="${LDAP_HOST:-bx-ad-01-it-vm.omnitech.security}"
LDAP_PORT="${LDAP_PORT:-636}"
LDAP_SEARCH_BASE="${LDAP_SEARCH_BASE:-DC=omnitech,DC=security}"
LDAP_CA="${LDAP_CA:-/etc/graylog/certs/omnitech-rootca.crt}"
LOOKUP_DIR="${LOOKUP_DIR:-/etc/graylog/lookup}"
DEST="${LOOKUP_DIR}/seal-identity.csv"
GLURL="${GRAYLOG_API_URL:-https://bx-it-graylog-vm.omnitech.security:9000}"; GLURL="${GLURL%/}"
[[ "${GLURL}" == */api ]] || GLURL="${GLURL}/api"

log() { printf '    [%s] %s\n' "$1" "$2"; }
command -v ldapsearch >/dev/null 2>&1 || { echo "ERREUR: ldapsearch absent (ldap-utils)" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERREUR: curl absent" >&2; exit 1; }
: "${LDAP_BIND_DN:?LDAP_BIND_DN absent}"; : "${LDAP_BIND_PASS:?LDAP_BIND_PASS absent}"

# Auth Graylog : token de service, sinon repli admin.
if [[ -n "${GRAYLOG_API_TOKEN:-}" ]]; then GLAUTH="${GRAYLOG_API_TOKEN}:token"
elif [[ -n "${GRAYLOG_ADMIN_PASS:-}" ]]; then GLAUTH="admin:${GRAYLOG_ADMIN_PASS}"
else echo "ERREUR: ni GRAYLOG_API_TOKEN ni GRAYLOG_ADMIN_PASS" >&2; exit 1; fi
GLCA="${GRAYLOG_API_CA:-/etc/graylog/certs/omnitech-rootca.crt}"

mkdir -p "${LOOKUP_DIR}"
PWFILE="$(mktemp)"; chmod 600 "${PWFILE}"; printf '%s' "${LDAP_BIND_PASS}" > "${PWFILE}"
TMP="$(mktemp "${LOOKUP_DIR}/.seal-identity.XXXXXX.csv")"
MATS="$(mktemp)"
trap 'rm -f "${PWFILE}" "${TMP}" "${MATS}"' EXIT

# --- 1. Valeurs identity_matricule reellement presentes sur les events SEAL ---
curl -s --cacert "${GLCA}" -u "${GLAUTH}" -H "Accept: application/json" -H "X-Requested-By: regen-seal-identity" \
     -G "${GLURL}/search/universal/relative" \
     --data-urlencode "query=event_source:seal AND _exists_:identity_matricule" \
     --data-urlencode "range=31536000" --data-urlencode "limit=5000" --data-urlencode "fields=identity_matricule" \
     | python3 -c "import sys,json
d=json.load(sys.stdin)
vals=set()
for m in d.get('messages',[]):
    v=m.get('message',{}).get('identity_matricule')
    if v: vals.add(str(v).strip())
[print(v) for v in sorted(vals)]" > "${MATS}" || true
NMAT=$(wc -l < "${MATS}" | tr -d ' ')
log "i" "${NMAT} valeur(s) distincte(s) de identity_matricule vue(s) sur les events SEAL"

export LDAPTLS_CACERT="${LDAP_CA}"; export LDAPTLS_REQCERT="demand"

# --- 2. Resolution BEST-EFFORT : matricule ressemblant a un NOM -> displayName -> UPN
ldap_escape() { python3 -c "import sys; s=sys.argv[1]; print(''.join('\\\\%02x'%ord(c) if c in '()\\\\*\0' else c for c in s))" "$1"; }
{
  echo "matricule,upn"
  while IFS= read -r m; do
    [[ -z "${m}" ]] && continue
    # heuristique NOM : au moins deux mots alphabetiques (prenom nom), pas de chiffre
    if ! printf '%s' "${m}" | grep -qiE '^[A-Za-zÀ-ÿ]+([ '"'"'-][A-Za-zÀ-ÿ]+)+$'; then continue; fi
    esc="$(ldap_escape "${m}")"
    upn="$(ldapsearch -x -LLL -o ldif-wrap=no -H "ldaps://${LDAP_HOST}:${LDAP_PORT}" \
             -D "${LDAP_BIND_DN}" -y "${PWFILE}" -b "${LDAP_SEARCH_BASE}" \
             "(&(objectCategory=person)(|(displayName=${esc})(cn=${esc}))(userPrincipalName=*))" \
             userPrincipalName 2>/dev/null | awk -F': ' 'tolower($1)=="userprincipalname"{print tolower($2); exit}')"
    [[ -n "${upn}" ]] && printf '%s,%s\n' "${m}" "${upn}"
  done < "${MATS}"
} > "${TMP}"

NRES=$(( $(wc -l < "${TMP}" | tr -d ' ') - 1 ))
INVIS=$(grep -c '@invissys' "${TMP}" 2>/dev/null || echo 0)
log "i" "${NRES} correspondance(s) nom->UPN resolue(s) (dont ${INVIS} @invissys.com = tenant co-manage, enrichissement seulement)"

# --- 3. Installation atomique + remplacement conditionnel (idempotence) -------
if [[ -f "${DEST}" ]] && cmp -s "${TMP}" "${DEST}"; then
  log "=" "seal-identity.csv inchange"; exit 0
fi
install -m 644 "${TMP}" "${DEST}"; chown root:graylog "${DEST}" 2>/dev/null || true
log "+" "seal-identity.csv installe (${DEST}, ${NRES} entrees) -> recharge adapter csvfile <=60 s"
