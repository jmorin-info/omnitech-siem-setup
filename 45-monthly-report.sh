#!/usr/bin/env bash
# 45-monthly-report.sh - Rapport executif mensuel (HTML + PDF weasyprint, email).
#   Timer le 1er du mois a 06:00. Archive sous /var/www/siem-kit/rapports/.
set -euo pipefail
cd "$(dirname "$0")"; source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }
[[ -x /usr/local/sbin/omni-monthly-report ]] || { echo "generateur absent"; exit 1; }
cat > /etc/systemd/system/omni-monthly-report.service <<'EOF'
[Unit]
Description=OMNI SIEM - rapport executif mensuel (PDF)
After=network-online.target graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-monthly-report
Nice=15
EOF
cat > /etc/systemd/system/omni-monthly-report.timer <<'EOF'
[Unit]
Description=OMNI SIEM - rapport mensuel (1er du mois 06:00)
[Timer]
OnCalendar=*-*-01 06:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-monthly-report.timer >/dev/null 2>&1 || true
echo "    [+] timer mensuel actif"
systemctl list-timers omni-monthly-report.timer --no-pager | sed -n '2p'
echo "=== 45 termine. Archive + servi : https://${SIEM_FQDN}/kit/rapports/ ==="
