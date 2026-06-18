#!/usr/bin/env bash
# =============================================================================
# 48-m365-fail-codes.sh - Ventilation des echecs de connexion M365 par CODE.
#   Les sign-in M365 portent le code Azure AD dans status_code (verifie live).
#   Ce script : table de lookup status_code->libelle FR (CSV m365-status.csv),
#   + regle pipeline (stage 15) qui pose m365_fail_label sur chaque echec
#   (event_action:echec_connexion), connectee au stream 'OMNI - M365'.
#   -> page 'M365' : echecs ventiles par libelle (relancer 14 ensuite).
# Idempotent. Prerequis : 12 (streams/pipelines). Relance 14 apres.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api
LOOKUP_DIR="/etc/graylog/lookup"

# (ensure_lookup canonique en en-tete)

echo "==> [1/4] Deploiement du CSV m365-status.csv"
install -m 644 lookups/m365-status.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/m365-status.csv" 2>/dev/null || true
ok "m365-status.csv deploye"

echo "==> [2/4] Table de lookup status_code -> libelle FR"
ensure_lookup "m365-status" "OMNI status_code M365 -> libelle FR" "m365-status.csv" "status_code" "label"

echo "==> [3/4] Regle d'enrichissement (pose m365_fail_label)"
# default_single_value 'Autre echec' couvre tout code non encore reference.
ensure_rule "omni-m365-15-faillabel" <<'EOF'
rule "omni-m365-15-faillabel"
when
  to_string($message.m365_type) == "signin"
  AND to_string($message.event_action) == "echec_connexion"
then
  let code = to_string($message.status_code);
  set_field("m365_fail_code", code);
  set_field("m365_fail_label", lookup_value("omni-m365-status", code));
end
EOF

echo "==> [4/4] Pipeline dedie (stage 15) + connexion au stream OMNI - M365"
PL_M365="$(ensure_pipeline "OMNI - Enrichissement M365" <<'EOF'
pipeline "OMNI - Enrichissement M365"
stage 15 match either
rule "omni-m365-15-faillabel"
end
EOF
)"
SID="$(get_stream_id "OMNI - M365")"
[[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_M365}" || warn "stream absent: OMNI - M365"

echo
echo "=== 48-m365-fail-codes.sh termine. Les NOUVEAUX echecs M365 portent"
echo "    m365_fail_label / m365_fail_code. Relancer 14-graylog-dashboards.sh"
echo "    pour la ventilation par libelle sur la page M365. ==="
