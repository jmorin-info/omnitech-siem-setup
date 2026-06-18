#!/usr/bin/env bash
# =============================================================================
# 34-weekly-report.sh - Installe/active le rapport hebdomadaire (lundi 08:00)
# Le generateur est /usr/local/sbin/omni-weekly-report (Python). Config dans
# 00-vars.env (REPORT_RECIPIENTS, REPORT_FROM, REPORT_SMTP[_PORT]).
# Idempotent. Pour un envoi immediat : systemctl start omni-weekly-report.service
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
[[ -x /usr/local/sbin/omni-weekly-report ]] || { echo "ERREUR: /usr/local/sbin/omni-weekly-report absent"; exit 1; }
systemctl daemon-reload
systemctl enable --now omni-weekly-report.timer
echo "[+] timer omni-weekly-report actif :"
systemctl list-timers omni-weekly-report.timer --no-pager | sed -n '1,2p'
echo "Envoi immediat de test : systemctl start omni-weekly-report.service ; journalctl -u omni-weekly-report -n 20"
