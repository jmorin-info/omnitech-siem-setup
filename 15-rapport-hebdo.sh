#!/usr/bin/env bash
# ==============================================================================
# 15-rapport-hebdo.sh - Installe /etc/cron.weekly/omni-siem-rapport
# Rapport hebdomadaire (HTML, envoye via le relais SMTP interne) :
#   volumetrie par index, detections par tag, top comptes en echec,
#   hotes Windows actifs, alertes declenchees.
# Test immediat : /etc/cron.weekly/omni-siem-rapport
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

cat > /etc/cron.weekly/omni-siem-rapport <<EOF
#!/usr/bin/env bash
# Rapport hebdo SIEM OMNITECH (installe par 15-rapport-hebdo.sh)
set -euo pipefail
OS="http://127.0.0.1:9200"
Q(){ curl -s "\${OS}/\$1/_search?size=0" -H 'Content-Type: application/json' -d "\$2"; }
RANGE='{"range":{"timestamp":{"gte":"now-7d"}}}'

rows_from_agg(){ jq -r '.aggregations.x.buckets[] | "<tr><td style=\"padding:4px 10px;border-bottom:1px solid #eee\">"+(.key|tostring)+"</td><td style=\"padding:4px 10px;border-bottom:1px solid #eee;text-align:right\">"+(.doc_count|tostring)+"</td></tr>"'; }

VOL="\$(curl -s "\${OS}/_cat/indices/omni-*?h=index,docs.count,store.size&s=index" | awk '{printf "<tr><td style=\"padding:4px 10px;border-bottom:1px solid #eee\">%s</td><td style=\"padding:4px 10px;text-align:right;border-bottom:1px solid #eee\">%s</td><td style=\"padding:4px 10px;text-align:right;border-bottom:1px solid #eee\">%s</td></tr>", \$1, \$2, \$3}')"
TAGS="\$(Q "omni-*" "{\"query\":\${RANGE},\"aggs\":{\"x\":{\"terms\":{\"field\":\"alert_tag\",\"size\":15}}}}" | rows_from_agg)"
FAILS="\$(Q "omni-winsec_*" "{\"query\":{\"bool\":{\"must\":[\${RANGE},{\"term\":{\"event_id\":\"4625\"}}]}},\"aggs\":{\"x\":{\"terms\":{\"field\":\"user\",\"size\":10}}}}" | rows_from_agg)"
HOSTS="\$(Q "omni-winsec_*,omni-sysmon_*,omni-winother_*" "{\"query\":\${RANGE},\"aggs\":{\"x\":{\"cardinality\":{\"field\":\"host\"}}}}" | jq -r '.aggregations.x.value')"
# id -> titre des definitions (API Graylog), puis agregation des evenements declenches
DEFS="\$(curl -s --cacert /etc/graylog/certs/omnitech-rootca.crt -u "admin:${GRAYLOG_ADMIN_PASS}" \
  "https://${SIEM_FQDN}:9000/api/events/definitions?per_page=100" \
  | jq '[(.event_definitions // .elements // [])[] | {key:.id, value:.title}] | from_entries')"
ALERTS="\$(Q "gl-events_*" "{\"query\":{\"bool\":{\"must\":[\${RANGE},{\"term\":{\"alert\":true}}]}},\"aggs\":{\"x\":{\"terms\":{\"field\":\"event_definition_id\",\"size\":15}}}}" 2>/dev/null \
  | jq -r --argjson m "\${DEFS}" '.aggregations.x.buckets[]? | "<tr><td style=\"padding:4px 10px;border-bottom:1px solid #eee\">"+(\$m[.key] // .key)+"</td><td style=\"padding:4px 10px;border-bottom:1px solid #eee;text-align:right\">"+(.doc_count|tostring)+"</td></tr>"' || true)"

T(){ echo "<div style='margin:18px 0 6px;font-size:13px;font-weight:600;color:#1c2333'>\$1</div><table style='border-collapse:collapse;font-size:12px;width:100%'>\$2</table>"; }
BODY="<html><body style='font-family:Segoe UI,Arial,sans-serif;max-width:720px;margin:auto;color:#212529'>
<div style='background:#1c2333;color:#fff;padding:14px 20px;border-bottom:4px solid #d6336c'>
<b>SIEM OMNITECH - Rapport hebdomadaire</b><br><span style='font-size:12px;color:#8ea2c9'>\$(date -d '-7 days' +%d/%m/%Y) - \$(date +%d/%m/%Y) - \${HOSTS} hotes Windows actifs</span></div>
\$(T "Alertes declenchees (7 j)" "\${ALERTS:-<tr><td style='padding:4px 10px'>aucune</td></tr>}")
\$(T "Detections par tag (7 j)" "\${TAGS:-<tr><td style='padding:4px 10px'>aucune</td></tr>}")
\$(T "Top comptes en echec de connexion (4625)" "\${FAILS:-<tr><td style='padding:4px 10px'>aucun</td></tr>}")
\$(T "Volumetrie des index" "<tr><th style='text-align:left;padding:4px 10px'>Index</th><th style='text-align:right;padding:4px 10px'>Docs</th><th style='text-align:right;padding:4px 10px'>Taille</th></tr>\${VOL}")
<div style='margin-top:16px;font-size:11px;color:#adb5bd'>Genere le \$(date '+%d/%m/%Y %H:%M') sur ${SIEM_FQDN} - console: https://${SIEM_FQDN}</div>
</body></html>"

MAIL="From: SIEM OMNITECH <${SMTP_FROM}>
To: ${ALERT_EMAIL}
Subject: [SIEM] Rapport hebdomadaire
MIME-Version: 1.0
Content-Type: text/html; charset=us-ascii

\${BODY}"
echo "\${MAIL}" | iconv -f UTF-8 -t ASCII//TRANSLIT | curl -s --url "smtp://${SMTP_RELAY}:${SMTP_PORT}" \
  --mail-from "${SMTP_FROM}" --mail-rcpt "${ALERT_EMAIL}" --upload-file -
EOF
chmod 700 /etc/cron.weekly/omni-siem-rapport   # contient l'identifiant API
echo "[+] /etc/cron.weekly/omni-siem-rapport installe"
echo "    test : /etc/cron.weekly/omni-siem-rapport"
