#!/usr/bin/env bash
# =============================================================================
# 33-ldaps-auth.sh - Authentification AD (LDAPS) sur la console Graylog
# Pre-requis et mode d'emploi : docs/LDAPS.md
#   - compte de liaison AD en lecture seule (LDAP_BIND_DN / LDAP_BIND_PASS
#     dans 00-vars.env)
#   - regle FortiGate Reseau ELK -> DC en TCP 636
# Cree le backend "Active Directory OMNITECH" (LDAPS, certificats verifies via
# le truststore JVM qui contient deja la Root CA), role par defaut Reader,
# puis l'active. Le compte local 'admin' reste utilisable en secours.
# Idempotent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh
require_api

LDAP_HOST="${LDAP_HOST:-bx-ad-01.omnitech.security}"
LDAP_PORT="${LDAP_PORT:-636}"
LDAP_SEARCH_BASE="${LDAP_SEARCH_BASE:-DC=omnitech,DC=security}"
[[ -n "${LDAP_BIND_DN:-}" && -n "${LDAP_BIND_PASS:-}" ]] \
  || die "renseigner LDAP_BIND_DN et LDAP_BIND_PASS dans 00-vars.env (cf. docs/LDAPS.md)"

# --- 1. Verification du certificat LDAPS contre la CA interne -----------------
if echo | timeout 5 openssl s_client -connect "${LDAP_HOST}:${LDAP_PORT}" \
     -CAfile /etc/graylog/certs/omnitech-rootca.crt 2>/dev/null \
     | grep -q "Verify return code: 0"; then
  ok "certificat LDAPS de ${LDAP_HOST}:${LDAP_PORT} verifie par la Root CA interne"
else
  warn "LDAPS ${LDAP_HOST}:${LDAP_PORT} injoignable ou cert non verifie (regle FW 636 ? cert PKI sur le DC ?)"
  warn "on continue : Graylog refusera la connexion tant que ce n'est pas corrige"
fi

# --- 2. Role par defaut des comptes AD ----------------------------------------
# La connexion etant restreinte par filtre LDAP aux membres (recursifs) de
# LDAP_REQUIRED_GROUP_DN ("Admins du domaine"), on attribue directement Admin.
LDAP_REQUIRED_GROUP_DN="${LDAP_REQUIRED_GROUP_DN:-CN=Admins du domaine,CN=Users,DC=omnitech,DC=security}"
ROLE_ID="$(api_get "/authz/roles?per_page=100" \
  | jq -r '.roles[] | select(.name=="Admin") | .id')"
[[ -n "${ROLE_ID}" && "${ROLE_ID}" != "null" ]] || die "role Admin introuvable"

# --- 3. Backend (creation si absent) -------------------------------------------
TITLE="Active Directory OMNITECH"
BID="$(api_get "/system/authentication/services/backends" \
  | jq -r --arg t "${TITLE}" '.backends[]? | select(.title==$t) | .id')"

if [[ -n "${BID}" && "${BID}" != "null" ]]; then
  skip "backend '${TITLE}' existe deja (${BID})"
else
  # Filtre : seul un membre (recursif, OID 1.2.840.113556.1.4.1941) du groupe
  # requis peut s'authentifier ; les autres comptes AD sont invisibles.
  PATTERN="(&(objectClass=user)(|(sAMAccountName={0})(userPrincipalName={0}))(memberOf:1.2.840.113556.1.4.1941:=${LDAP_REQUIRED_GROUP_DN}))"
  BID="$(jq -n --arg t "${TITLE}" --arg h "${LDAP_HOST}" --argjson p "${LDAP_PORT}" \
            --arg dn "${LDAP_BIND_DN}" --arg pw "${LDAP_BIND_PASS}" \
            --arg base "${LDAP_SEARCH_BASE}" --arg role "${ROLE_ID}" \
            --arg pat "${PATTERN}" '{
      title: $t,
      description: "Authentification console via AD (LDAPS, restreinte aux Admins du domaine) - provisionne par 33-ldaps-auth.sh",
      default_roles: [$role],
      config: {
        type: "active-directory",
        servers: [{host: $h, port: $p}],
        transport_security: "tls",
        verify_certificates: true,
        system_user_dn: $dn,
        system_user_password: {set_value: $pw},
        user_search_base: $base,
        user_search_pattern: $pat,
        user_name_attribute: "sAMAccountName",
        user_full_name_attribute: "displayName"
      }
    }' | post_entity "/system/authentication/services/backends" | jqr '.backend.id // .id')"
  [[ -n "${BID}" && "${BID}" != "null" ]] || die "creation du backend REFUSEE (verifier la sortie API)"
  ok "backend '${TITLE}' cree (${BID})"
fi

# --- 4. Activation ---------------------------------------------------------------
if echo "{\"active_backend\":\"${BID}\"}" \
     | api_post "/system/authentication/services/configuration" >/dev/null; then
  ok "backend ACTIF : seuls les membres de '${LDAP_REQUIRED_GROUP_DN%%,*}' (Admins du domaine) peuvent se connecter, role Admin"
else
  warn "activation a confirmer dans System > Authentication"
fi

echo
echo "Rappels :"
echo "  - se connecter avec un compte AD admin du domaine (ex: adm-jmorin)"
echo "  - 'admin' local conserve au coffre comme acces de secours"
echo "=== 33-ldaps-auth.sh termine ==="
