#!/usr/bin/env bash
# =============================================================================
# 68-iso-evidence.sh - Genere un dossier de PREUVES date pour l'audit ISO 27001
#   Interroge le systeme VIVANT et produit docs/EVIDENCE-AUDIT-<date>.md :
#   inventaire des detections, couverture ATT&CK, KPI de surveillance (A.8.16),
#   threat intel (A.5.7), sante de collecte (A.8.15), retention/integrite.
#   = preuve datee et reproductible pour le Stage 2 (nov. 2026). Timer mensuel.
#   Idempotent. Prerequis : Graylog + OpenSearch operationnels.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api
DATE="$(date +%Y-%m-%d)"
OUT="docs/EVIDENCE-AUDIT-${DATE}.md"
OS="127.0.0.1:9200"
osc() { curl -s "${OS}/omni-*/_count" -H 'Content-Type: application/json' -d "$1" 2>/dev/null | jq -r '.count // 0'; }

echo "==> Generation du dossier de preuves ${OUT}"
NDEF=$(api_get "/events/definitions?per_page=1" | jq -r '.total // 0')
NSTREAM=$(api_get "/streams?per_page=200" | jq -r '[.streams[]?|select(.title|startswith("OMNI"))]|length')
NTAGS=$(awk -F, 'NR>1{print $1}' lookups/mitre-attack.csv | sort -u | wc -l)
NTECH=$(awk -F, 'NR>1{print $2}' lookups/mitre-attack.csv | sort -u | wc -l)
NTAC=$(awk -F, 'NR>1{print $4}' lookups/mitre-attack.csv | sort -u | wc -l)
ALERTS7=$(osc '{"query":{"bool":{"must":[{"exists":{"field":"alert_tag"}}],"filter":[{"range":{"timestamp":{"gte":"now-7d"}}}]}}}')
ALERTS30=$(osc '{"query":{"bool":{"must":[{"exists":{"field":"alert_tag"}}],"filter":[{"range":{"timestamp":{"gte":"now-30d"}}}]}}}')
INC30=$(osc '{"query":{"bool":{"must":[{"term":{"event_source":"xdr_incident"}}],"filter":[{"range":{"timestamp":{"gte":"now-30d"}}}]}}}')
TI_C2=$(($(wc -l < /etc/graylog/lookup/ti-c2-ip.csv 2>/dev/null || echo 1)-1))
TI_DOM=$(($(wc -l < /etc/graylog/lookup/ti-mal-domain.csv 2>/dev/null || echo 1)-1))
CLUSTER=$(curl -s ${OS}/_cluster/health 2>/dev/null | jq -r '.status')
IDXFAIL=$(api_get "/system/indexer/failures?limit=1" | jq -r '.total // 0')
INTEG=$(systemctl is-active omni-cert-check.timer 2>/dev/null; systemctl is-active oms-xdr.timer 2>/dev/null)
SOURCES=$(curl -s "${OS}/omni-*/_search" -H 'Content-Type: application/json' -d '{"size":0,"query":{"range":{"timestamp":{"gte":"now-24h"}}},"aggs":{"s":{"terms":{"field":"event_source","size":20}}}}' 2>/dev/null | jq -r '[.aggregations.s.buckets[]?|"\(.key)(\(.doc_count))"]|join(", ")')

cat > "${OUT}" <<EOF
# Dossier de preuves — Audit ISO/IEC 27001:2022 (généré le ${DATE})

Document **généré automatiquement** depuis la plateforme SIEM/XDR en production
(\`68-iso-evidence.sh\`). Preuve **datée et reproductible** pour le Stage 2 (nov. 2026).
Chaque section référence le ou les contrôles de l'Annexe A qu'elle atteste.

## A.8.15 — Journalisation (collecte centralisée et inviolable)
- Streams OMNI actifs : **${NSTREAM}**. Cluster OpenSearch : **${CLUSTER}**. Échecs d'indexation : **${IDXFAIL}**.
- Sources émettant sur 24 h : ${SOURCES}
- Rétention par paliers documentée (\`docs/POLITIQUE-RETENTION.md\`) ; intégrité par chaîne HMAC (\`omni-integrity\`, \`docs/PROCEDURE-INTEGRITE-PREUVE.md\`).

## A.8.16 — Surveillance des activités
- Définitions d'événements (détections) actives : **${NDEF}**.
- Tags de détection distincts : **${NTAGS}**, mappés MITRE ATT&CK.
- Volume de détections : **${ALERTS7}** sur 7 j, **${ALERTS30}** sur 30 j.
- Incidents corrélés (oms-xdr) sur 30 j : **${INC30}**.
- Tableau de bord temps réel « OMNI - SOC » + page « OMS-XDR » ; UEBA/NDR comportemental.

## A.5.7 — Renseignement sur les menaces
- Couverture MITRE ATT&CK : **${NTECH} techniques** sur **${NTAC} tactiques** (calque \`docs/mitre-navigator-layer.json\`).
- Threat intel IOC (abuse.ch, refresh quotidien) : **${TI_C2} IP de C2** (Feodo), **${TI_DOM} domaines malveillants** (URLhaus) ; + Tor/Spamhaus, CISA KEV.

## A.5.24 / A.5.25 / A.5.26 — Gestion, appréciation et réponse aux incidents
- Corrélation kill-chain (oms-xdr) + scoring de risque (MITRE + UEBA 0-100).
- Réponse : SOAR-light (blocage IP via feed FortiGate, sans creds) ; actionneurs ESET/AD en dry-run (human-in-the-loop) ; notification 2-tiers + **app mobile PWA** (alertes/push, VPN-only).
- Procédures : \`docs/PROCEDURE-INCIDENT.md\`, \`docs/REPONSE-AUTOMATISEE.md\`.

## A.8.32 — Gestion du changement / A.5.37 — Procédures d'exploitation
- Tout le provisioning sous Git (dépôt privé) ; scripts idempotents ; procédures \`docs/PRO-EXPLOITATION-SIEM.md\`.
- **Clause 10** : registre d'amélioration continue daté & vérifié — \`docs/REGISTRE-AMELIORATION-CONTINUE.md\`.

## A.8.13 — Sauvegarde / A.8.8 — Vulnérabilités
- Sauvegarde config quotidienne chiffrée + export NAS (\`30-backup-config.sh\`), PRA \`docs/PRA-RECONSTRUCTION-SIEM.md\`.
- Vulnérabilités : corrélation CISA KEV + ancienneté de patch (\`38-vuln-scan.sh\`).

---
*Services de supervision continue actifs : ${INTEG}. Pour régénérer : \`bash 68-iso-evidence.sh\`.*
EOF
ok "dossier de preuves genere : ${OUT}"

# Timer mensuel (1er du mois 07:00)
cat > /etc/systemd/system/omni-iso-evidence.service <<EOF2
[Unit]
Description=OMNI - Dossier de preuves ISO (genere docs/EVIDENCE-AUDIT-<date>.md)
[Service]
Type=oneshot
WorkingDirectory=/root/omnitech-siem-setup
ExecStart=/bin/bash /root/omnitech-siem-setup/68-iso-evidence.sh
EOF2
cat > /etc/systemd/system/omni-iso-evidence.timer <<'EOF2'
[Unit]
Description=OMNI - Preuves ISO (mensuel)
[Timer]
OnCalendar=*-*-01 07:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF2
systemctl daemon-reload 2>/dev/null; systemctl enable omni-iso-evidence.timer >/dev/null 2>&1 && ok "timer mensuel actif"
echo "=== 68 termine. Preuves : ${OUT} ==="
