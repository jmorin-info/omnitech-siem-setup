#!/usr/bin/env bash
# =============================================================================
# 91-dns.sh - Detections DNS (Windows DNS sur le DC, canal DNSServer/Audit).
#   Les events DNSServer/Audit arrivent DEJA via Winlogbeat (depuis le DC) dans le
#   stream 'OMNI - Windows autres'. Ce script AJOUTE un pipeline de detection (pas de
#   recepteur : la donnee est deja la). Mesure-first sur donnees REELLES :
#     - EID 519/520 (DYNAMIC_UPDATE / AUDIT_REC_DYN_UPDATE) = enregistrement dynamique
#       legitime des postes = BRUIT (volumineux) -> NON tague.
#     - EID 515/516 (ZONE_OP / AUDIT_REC_ADMIN) = changement d'enregistrement MANUEL
#       (admin) = signal : tracabilite + hijack potentiel si nom sensible (wpad/
#       autodiscover/_msdcs...). T1565.001 (manipulation de donnees internes).
#     - EID 536 (CACHE_OP / AUDIT_CACHE) = vidage du cache DNS (effacement, T1070).
#   Idempotent. Prerequis : 12 (streams) + 37 (MITRE). Relancer 14 (dashboard).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
CH='Microsoft-Windows-DNSServer/Audit'

echo "==> [1/3] Regles de detection DNS (stream Windows autres, canal DNSServer/Audit)"
# --- Normalisation : categorie dns + nom/zone exposes (sur le canal DNS Audit) ---
ensure_rule "omni-dns-00-tag" <<EOF
rule "omni-dns-00-tag"
when
  to_string(\$message.winlogbeat_winlog_channel) == "${CH}"
then
  set_field("event_category", "dns");
  set_field("dns_name", to_string(\$message.winlogbeat_winlog_event_data_NAME));
  set_field("dns_zone", to_string(\$message.winlogbeat_winlog_event_data_Zone));
end
EOF
# --- Changement d'enregistrement MANUEL (admin) : 515/516, hors bruit dynamique ---
ensure_rule "omni-dns-13-adminchange" <<EOF
rule "omni-dns-13-adminchange"
when
  to_string(\$message.winlogbeat_winlog_channel) == "${CH}"
  AND ( to_string(\$message.winlogbeat_winlog_event_id) == "515"
     OR to_string(\$message.winlogbeat_winlog_event_id) == "516" )
then
  set_field("alert_tag", "dns_admin_change");
  set_field("event_action", "modif_enregistrement_dns_manuelle");
end
EOF
# --- Vidage du cache DNS (EID 536) : effacement / recuperation post-empoisonnement ---
ensure_rule "omni-dns-13-cacheflush" <<EOF
rule "omni-dns-13-cacheflush"
when
  to_string(\$message.winlogbeat_winlog_channel) == "${CH}"
  AND to_string(\$message.winlogbeat_winlog_event_id) == "536"
then
  set_field("alert_tag", "dns_cache_flush");
  set_field("event_action", "vidage_cache_dns");
end
EOF
# --- ESCALADE : changement manuel d'un nom SENSIBLE = hijack potentiel (override) ---
# Stage 14 (apres 13) -> ecrase alert_tag si le nom modifie est critique.
ensure_rule "omni-dns-14-sensitive" <<EOF
rule "omni-dns-14-sensitive"
when
  to_string(\$message.event_category) == "dns"
  AND ( to_string(\$message.winlogbeat_winlog_event_id) == "515"
     OR to_string(\$message.winlogbeat_winlog_event_id) == "516" )
  AND ( contains(to_string(\$message.winlogbeat_winlog_event_data_NAME), "wpad", true)
     OR contains(to_string(\$message.winlogbeat_winlog_event_data_NAME), "autodiscover", true)
     OR contains(to_string(\$message.winlogbeat_winlog_event_data_NAME), "_msdcs", true)
     OR contains(to_string(\$message.winlogbeat_winlog_event_data_NAME), "_ldap", true)
     OR contains(to_string(\$message.winlogbeat_winlog_event_data_NAME), "_kerberos", true)
     OR contains(to_string(\$message.winlogbeat_winlog_event_data_NAME), "proxy", true) )
then
  set_field("alert_tag", "dns_sensitive_change");
  set_field("event_action", "modif_dns_nom_sensible");
end
EOF

echo "==> [2/3] Pipeline 'OMNI - DNS (DC)' + connexion stream Windows autres"
PL="$(ensure_pipeline "OMNI - DNS (DC)" <<'PIPE'
pipeline "OMNI - DNS (DC)"
stage 0 match either
rule "omni-dns-00-tag"
stage 13 match either
rule "omni-dns-13-adminchange"
rule "omni-dns-13-cacheflush"
stage 14 match either
rule "omni-dns-14-sensitive"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Windows autres')"
[[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream 'OMNI - Windows autres' absent"

echo "==> [3/3] MITRE (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || { echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; ok "MITRE +$1"; }; }
add_mitre dns_admin_change     T1565.001 "Stored Data Manipulation (enregistrement DNS)" "Impact"          moyen   5
add_mitre dns_sensitive_change T1565.001 "Manipulation DNS d'un nom sensible (hijack)"    "Impact"          eleve   8
add_mitre dns_cache_flush      T1070     "Indicator Removal (vidage cache DNS)"           "Defense Evasion" moyen   5
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE dns_admin_change / dns_sensitive_change / dns_cache_flush"
echo
echo "=== 91 termine. DNS (DC) : changements manuels + nom sensible + vidage cache."
echo "    NB requetes (tunneling/domaines malveillants) = canal DNS Analytical (a activer"
echo "    sur le DC si voulu) ; les requetes endpoint sont deja couvertes par Sysmon EID22. ==="
