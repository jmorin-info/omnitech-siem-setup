#!/usr/bin/env bash
# =============================================================================
# 69-ad-response.sh - Actionneur de reponse AD : desactivation de compte compromis
#   Installe /usr/local/sbin/omni-ad-disable <sAMAccountName> [raison] qui desactive
#   un compte AD via LDAPS (bind svc_siem, reutilise - choix RSSI, risque accepte
#   documente clause 10). Met le bit ACCOUNTDISABLE (0x2) de userAccountControl.
#
#   GARDE-FOUS (essentiels car svc_siem peut desormais ecrire) :
#     1. DRY-RUN par defaut (double verrou : OMNI_AD_DISABLE_ARM=1 requis).
#     2. DENYLIST : ne desactive JAMAIS un compte protege (admin/service/secours/
#        krbtgt/adm-/svc_). Refus strict avant toute action.
#     3. Journalisation GELF (event_source=ad_response) = piste d'audit.
#     4. Human-in-the-loop : invoque manuellement ou via approbation (PWA), JAMAIS
#        en reponse auto.
#   PREREQUIS COTE AD : deleguer le droit "Disable account" (write userAccountControl)
#   au compte svc_siem sur les OU concernees (il est lecture seule aujourd'hui).
#   Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh 2>/dev/null || true
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

echo "==> [1/3] Config /etc/default/omni-ad-response (ARM=0, denylist) — sans secret"
if [[ ! -f /etc/default/omni-ad-response ]]; then
  cat > /etc/default/omni-ad-response <<'EOF'
# Reponse AD - configuration (les creds LDAPS restent dans 00-vars.env, non dupliques)
# DOUBLE VERROU : passer a 1 UNIQUEMENT apres delegation AD + validation dry-run.
OMNI_AD_DISABLE_ARM=0
# Comptes JAMAIS desactivables (exacts ou prefixes, insensible a la casse).
OMNI_AD_PROTECT=administrator,administrateur,admin,krbtgt,guest,invite,svc_,adm-,_
GELF_URL=http://127.0.0.1:12201/gelf
# CA pour valider le certificat LDAPS de l'AD (handshake TLS).
LDAP_CACERT=/etc/graylog/certs/omnitech-rootca.crt
EOF
  chmod 600 /etc/default/omni-ad-response
  ok "config creee (ARM=0 = dry-run)"
else skip "config existe (ARM inchange)"; fi

echo "==> [2/3] Actionneur /usr/local/sbin/omni-ad-disable"
cat > /usr/local/sbin/omni-ad-disable <<'SH'
#!/usr/bin/env bash
# omni-ad-disable <sAMAccountName> [raison] - desactive un compte AD (LDAPS, svc_siem).
# DRY-RUN par defaut. Voir 69-ad-response.sh.
set -uo pipefail
VARS=/root/omnitech-siem-setup/00-vars.env
CONF=/etc/default/omni-ad-response
# shellcheck disable=SC1090
source "$VARS"; [[ -f "$CONF" ]] && source "$CONF"
ARM="${OMNI_AD_DISABLE_ARM:-0}"
GELF="${GELF_URL:-http://127.0.0.1:12201/gelf}"
export LDAPTLS_CACERT="${LDAP_CACERT:-/etc/graylog/certs/omnitech-rootca.crt}"
PROTECT="${OMNI_AD_PROTECT:-administrator,administrateur,admin,krbtgt,svc_,adm-,_}"

SAM="${1:-}"; REASON="${2:-reponse incident SIEM}"
[[ -n "$SAM" ]] || { echo "usage: omni-ad-disable <sAMAccountName> [raison]"; exit 2; }

emit() {  # emit <result> <detail>
  local r="$1" d="$2"
  command -v curl >/dev/null && curl -s --max-time 5 "$GELF" -H 'Content-Type: application/json' \
    -d "$(printf '{"version":"1.1","host":"%s","short_message":"AD-response %s: %s (%s)","level":4,"_event_source":"ad_response","_event_action":"account_disable","_ad_target":"%s","_ad_result":"%s","_ad_reason":"%s","_ad_actor":"svc_siem"}' \
      "$(hostname)" "$r" "$SAM" "$d" "$SAM" "$r" "$REASON")" >/dev/null 2>&1 || true
  logger -t omni-ad-disable "result=$r target=$SAM detail=$d reason=$REASON"
}

# --- Garde-fou 2 : denylist ---
low="${SAM,,}"
IFS=',' read -ra DL <<< "$PROTECT"
for p in "${DL[@]}"; do
  p="${p,,}"; [[ -z "$p" ]] && continue
  if [[ "$low" == "$p" || "$low" == "$p"* ]]; then
    echo "REFUS: '$SAM' est un compte protege (regle denylist: '$p'). Aucune action."
    emit "refused_protected" "denylist:$p"; exit 3
  fi
done

# --- Resolution DN + userAccountControl courant (bind svc_siem lecture) ---
# LDAP_BIND_DN est en UPN (svc_siem@dom) -> base DN depuis le group DN, sinon depuis le domaine UPN.
BASE="$(echo "${LDAP_REQUIRED_GROUP_DN:-}" | grep -oiE 'DC=[^,]+(,DC=[^,]+)+' | head -1)"
if [[ -z "$BASE" ]]; then
  dom="${LDAP_BIND_DN#*@}"
  [[ "$dom" == *.* ]] && BASE="DC=${dom//./,DC=}"
fi
[[ -n "$BASE" ]] || { echo "ERREUR: base DN introuvable"; emit "error" "no_base_dn"; exit 4; }
RES="$(ldapsearch -LLL -o ldif-wrap=no -H "ldaps://${LDAP_HOST}" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" \
        -b "$BASE" "(sAMAccountName=${SAM})" dn userAccountControl 2>/dev/null)" || { echo "ERREUR: requete LDAPS echouee"; emit "error" "ldap_search_failed"; exit 4; }
DN="$(echo "$RES" | awk -F': ' '/^dn: /{print $2; exit}')"
UAC="$(echo "$RES" | awk -F': ' '/^userAccountControl: /{print $2; exit}')"
if [[ -z "$DN" ]]; then echo "Compte introuvable: $SAM"; emit "not_found" "no_dn"; exit 5; fi
[[ -n "$UAC" ]] || UAC=512
if (( UAC & 2 )); then echo "Deja desactive: $SAM (UAC=$UAC)"; emit "already_disabled" "uac=$UAC"; exit 0; fi
NEW=$(( UAC | 2 ))

# --- Garde-fou 1 : double verrou dry-run ---
if [[ "$ARM" != "1" ]]; then
  echo "[DRY-RUN] desactiverait '$SAM' (DN=$DN ; UAC $UAC -> $NEW). ARM=0 -> aucune ecriture."
  emit "dry_run" "uac:${UAC}->${NEW}"; exit 0
fi

# --- Action reelle (ARM=1) ---
if ldapmodify -H "ldaps://${LDAP_HOST}" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" >/dev/null 2>&1 <<EOF
dn: ${DN}
changetype: modify
replace: userAccountControl
userAccountControl: ${NEW}
EOF
then echo "DESACTIVE: $SAM (UAC $UAC -> $NEW)"; emit "disabled" "uac:${UAC}->${NEW}"; exit 0
else echo "ECHEC ldapmodify (droit 'Disable account' delegue a svc_siem ?)"; emit "modify_failed" "check_delegation"; exit 6; fi
SH
chmod 750 /usr/local/sbin/omni-ad-disable
ok "actionneur installe (dry-run par defaut)"

echo "==> [3/3] Tests de securite (denylist + resolution LDAPS, sans rien modifier)"
echo "--- compte protege 'administrator' (doit REFUSER) :"; /usr/local/sbin/omni-ad-disable administrator || true
echo "--- prefixe protege 'adm-jmorin' (doit REFUSER) :";   /usr/local/sbin/omni-ad-disable adm-jmorin || true
echo "--- bind lui-meme 'svc_siem' (doit REFUSER) :";       /usr/local/sbin/omni-ad-disable svc_siem || true
echo "--- compte inexistant (teste le bind LDAPS svc_siem) :"; /usr/local/sbin/omni-ad-disable zzz_inexistant_test || true

echo
echo "=== 69 termine. Actionneur en DRY-RUN (ARM=0)."
echo "    AVANT d'armer : (1) deleguer 'Disable account' a svc_siem dans AD ;"
echo "    (2) valider en dry-run sur un vrai compte ; (3) passer OMNI_AD_DISABLE_ARM=1"
echo "    dans /etc/default/omni-ad-response. Human-in-the-loop only. ==="
