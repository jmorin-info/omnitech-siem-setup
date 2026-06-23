#!/usr/bin/env bash
# =============================================================================
# 94-entra.sh - Detections Entra ID (Azure AD) - comble les GAPS.
#   Entra est DEJA collecte par le fetcher M365 (omni-m365-fetch poll signIns +
#   directoryAudits -> event_source=m365, m365_type=signin/audit). 9 detections
#   m365_* existent deja (etranger/role/risque/oauth_consent/mail_forward...).
#   Ce script AJOUTE les detections NON couvertes, sur les champs REELS mesures
#   (event_action / event_category des audits) :
#     - m365_app_credential_add : ajout de secret/cert sur une app/SP = backdoor cloud.
#     - m365_ca_change          : modif/suppression de policy Conditional Access.
#   La couverture riskDetections (m365_type=risk=0) + le blocage legacy auth (1461
#   auth SMTP mesurees) = actions cote tenant : voir docs/ENTRA-SETUP.md.
#   Idempotent. Prerequis : 16/17 (input + fetcher M365).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/3] Regles de detection Entra (stream M365, audits)"
ensure_rule "omni-entra-10-appcred" <<'EOF'
rule "omni-entra-10-appcred"
when
  to_string($message.event_source)=="m365" AND to_string($message.m365_type)=="audit"
  AND ( contains(to_string($message.event_action),"credential",true)
     OR contains(to_string($message.event_action),"service principal",true)
     OR contains(to_string($message.event_action),"key credential",true)
     OR contains(to_string($message.event_action),"password credential",true)
     OR contains(to_string($message.event_action),"Certificates and secrets management",true) )
then set_field("alert_tag","m365_app_credential_add"); end
EOF
ensure_rule "omni-entra-10-ca" <<'EOF'
rule "omni-entra-10-ca"
when
  to_string($message.event_source)=="m365" AND to_string($message.m365_type)=="audit"
  AND ( contains(to_string($message.event_action),"conditional access",true)
     OR ( contains(to_string($message.event_category),"Policy",true) AND contains(to_string($message.event_action),"policy",true) ) )
then set_field("alert_tag","m365_ca_change"); end
EOF
ensure_rule "omni-entra-00-base" <<'EOF'
rule "omni-entra-00-base"
when to_string($message.event_source)=="m365"
then set_field("event_category_sec", "identity_cloud");
end
EOF
PL="$(ensure_pipeline "OMNI - Entra (gaps)" <<'PIPE'
pipeline "OMNI - Entra (gaps)"
stage 0 match either
rule "omni-entra-00-base"
stage 10 match either
rule "omni-entra-10-appcred"
rule "omni-entra-10-ca"
end
PIPE
)"
ST="$(get_stream_id 'OMNI - M365')"
[[ -n "$ST" ]] && connect_pipeline "$ST" "$PL" || warn "stream 'OMNI - M365' absent"

echo "==> [2/3] MITRE"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; }
add_mitre m365_app_credential_add T1098.001 "Additional Cloud Credentials (app/SP secret)" "Persistence"      critique 9
add_mitre m365_ca_change          T1556.009 "Modify Authentication Process (Conditional Access)" "Defense Evasion" critique 9
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE m365_app_credential_add / m365_ca_change"

echo "==> [3/3] Rappel actions tenant (docs/ENTRA-SETUP.md)"
echo "    - riskDetections (m365_type=risk=0) : licence Entra ID P2 + permission Graph"
echo "      IdentityRiskEvent.Read.All + consentement admin -> debloque m365_risque."
echo "    - 1461 auth legacy (Authenticated SMTP) mesurees : bloquer la legacy auth (CA)."
echo
echo "=== 94 termine. Gaps Entra couverts (app credential, Conditional Access). ==="
