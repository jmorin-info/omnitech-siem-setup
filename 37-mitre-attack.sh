#!/usr/bin/env bash
# ==============================================================================
# 37-mitre-attack.sh - Mapping MITRE ATT&CK + score de risque
#   alert_tag -> technique (Txxxx) / nom / tactique / severite / score, via une
#   table de lookup CSV. Un pipeline d'enrichissement DEDIE (stage 20, donc
#   APRES la pose des alert_tag en stage 10/11) pose sur chaque detection :
#     mitre_technique, mitre_tactic, risk_severity, risk_score (long).
#   -> page "ATT&CK" + classement par score de risque dans les dashboards.
#   Vaut pour les NOUVELLES detections (l'historique n'a pas ces champs).
# Idempotent. Prerequis : 11 (lookup) + 12 (pipelines/streams). Relance 14 ensuite.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api
LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/4] Deploiement du CSV MITRE"
install -m 644 lookups/mitre-attack.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/mitre-attack.csv" 2>/dev/null || true
ok "mitre-attack.csv deploye"
install -m 644 lookups/alert-explain.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/alert-explain.csv" 2>/dev/null || true
ok "alert-explain.csv deploye"

# ensure_lookup <nom> <titre> <csv> <key_col> <val_col>  (adapter+cache+table)
ensure_lookup() {
  local NAME="$1" TITLE="$2" CSV="$3" KEY="$4" VAL="$5" AID CID TID
  AID="$(api_get "/system/lookup/adapters" | jq -r --arg n "omni-${NAME}-adapter" '.data_adapters[]? | select(.name==$n) | .id')"
  if [[ -z "${AID}" ]]; then
    AID="$(jq -n --arg n "omni-${NAME}-adapter" --arg t "${TITLE} (adapter)" \
                 --arg p "${LOOKUP_DIR}/${CSV}" --arg k "${KEY}" --arg v "${VAL}" '{
            name:$n, title:$t, description:"provisionne par 37-mitre-attack.sh",
            config:{ type:"csvfile", path:$p, separator:",", quotechar:"\"",
                     key_column:$k, value_column:$v, check_interval:60,
                     case_insensitive_lookup:true, cidr_lookup:false }
          }' | api_post "/system/lookup/adapters" | jqr '.id')"
    [[ -n "${AID}" && "${AID}" != "null" ]] || { warn "adapter ${NAME} refuse"; return 1; }
  fi
  CID="$(api_get "/system/lookup/caches" | jq -r --arg n "omni-${NAME}-cache" '.caches[]? | select(.name==$n) | .id')"
  if [[ -z "${CID}" ]]; then
    CID="$(jq -n --arg n "omni-${NAME}-cache" --arg t "${TITLE} (cache)" '{
            name:$n, title:$t, description:"provisionne par 37-mitre-attack.sh",
            config:{ type:"guava_cache", max_size:1000,
                     expire_after_access:300, expire_after_access_unit:"SECONDS",
                     expire_after_write:300,  expire_after_write_unit:"SECONDS",
                     ignore_null:false, ttl_empty:60, ttl_empty_unit:"SECONDS" }
          }' | api_post "/system/lookup/caches" | jqr '.id')"
    [[ -n "${CID}" && "${CID}" != "null" ]] || { warn "cache ${NAME} refuse"; return 1; }
  fi
  TID="$(api_get "/system/lookup/tables" | jq -r --arg n "omni-${NAME}" '.lookup_tables[]? | select(.name==$n) | .id')"
  if [[ -z "${TID}" ]]; then
    jq -n --arg n "omni-${NAME}" --arg t "${TITLE}" --arg a "${AID}" --arg c "${CID}" '{
            name:$n, title:$t, description:"provisionne par 37-mitre-attack.sh",
            data_adapter_id:$a, cache_id:$c,
            default_single_value:"", default_single_value_type:"NULL",
            default_multi_value:"",  default_multi_value_type:"NULL"
          }' | api_post "/system/lookup/tables" | jqr '.id' >/dev/null \
      && ok "table 'omni-${NAME}'" || { warn "table ${NAME} refusee"; return 1; }
  else skip "table 'omni-${NAME}' existe"; fi
}

echo "==> [2/4] Tables de lookup (alert_tag -> technique / tactique / severite / score)"
ensure_lookup "mitre-technique"  "OMNI alert_tag -> technique MITRE"  "mitre-attack.csv" "alert_tag" "technique"
ensure_lookup "mitre-techname"   "OMNI alert_tag -> nom technique"    "mitre-attack.csv" "alert_tag" "technique_name"
ensure_lookup "mitre-tactic"     "OMNI alert_tag -> tactique MITRE"   "mitre-attack.csv" "alert_tag" "tactic"
ensure_lookup "mitre-severity"   "OMNI alert_tag -> severite"         "mitre-attack.csv" "alert_tag" "severity"
ensure_lookup "mitre-score"      "OMNI alert_tag -> score de risque"  "mitre-attack.csv" "alert_tag" "score"
ensure_lookup "alert-explain"    "OMNI alert_tag -> explication"      "alert-explain.csv" "alert_tag" "explication"
ensure_lookup "alert-remed"      "OMNI alert_tag -> remediation"      "alert-explain.csv" "alert_tag" "remediation"

echo "==> [3/4] Regle d'enrichissement (pose les champs MITRE + risk_score)"
ensure_rule "omni-enrich-20-mitre" <<'EOF'
rule "omni-enrich-20-mitre"
when
  has_field("alert_tag") AND NOT has_field("vuln_type") AND NOT has_field("sla_type")
then
  let tag = to_string($message.alert_tag);
  set_field("mitre_technique",      lookup_value("omni-mitre-technique", tag));
  set_field("mitre_technique_name", lookup_value("omni-mitre-techname",  tag));
  set_field("mitre_tactic",         lookup_value("omni-mitre-tactic",    tag));
  set_field("risk_severity",        lookup_value("omni-mitre-severity",  tag));
  set_field("risk_score",           to_long(lookup_value("omni-mitre-score", tag), 0));
  let explain = lookup_value("omni-alert-explain", tag);
  if (! is_null(explain)) { set_field("alert_explain", to_string(explain)); }
  let remed = lookup_value("omni-alert-remed", tag);
  if (! is_null(remed)) { set_field("alert_remediation", to_string(remed)); }
end
EOF

# Resultats de omni-vuln-scan : le host cible arrive en champ custom 'vuln_host'
# (GELF reserve 'host' pour l'emetteur). On le repositionne dans 'host' pour
# l'homogeneite (dashboards, classement par hote, score de risque).
ensure_rule "omni-enrich-20-vuln-host" <<'EOF'
rule "omni-enrich-20-vuln-host"
when
  to_string($message.event_source) == "vuln" AND has_field("vuln_host")
then
  set_field("host", to_string($message.vuln_host));
end
EOF

echo "==> [4/4] Pipeline d'enrichissement (stage 20) + connexion aux streams"
PL_ENRICH="$(ensure_pipeline "OMNI - Enrichissement ATT&CK" <<'EOF'
pipeline "OMNI - Enrichissement ATT&CK"
stage 20 match either
rule "omni-enrich-20-mitre"
rule "omni-enrich-20-vuln-host"
end
EOF
)"
# Inclut "OMNI - Interne SIEM" : les resultats de omni-vuln-scan y arrivent
# (event_source=vuln) et la regle vuln-host doit y reposer le champ host.
for ST in "OMNI - Windows Security" "OMNI - Sysmon" "OMNI - Windows autres" \
          "OMNI - FortiGate" "OMNI - M365" "OMNI - vSphere" "OMNI - Interne SIEM"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_ENRICH}" || warn "stream absent: ${ST}"
done

echo
echo "=== 37-mitre-attack.sh termine. Les nouvelles detections sont mappees ATT&CK + scorees."
echo "    Relancer 14-graylog-dashboards.sh pour la page ATT&CK et le score de risque. ==="
