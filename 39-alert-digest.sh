#!/usr/bin/env bash
# =============================================================================
# 39-alert-digest.sh - Recapitulatif periodique des alertes RETENUES (non-FP).
#   Installe /usr/local/sbin/omni-alert-digest + l'unite et la minuterie systemd.
#   Cadence : du LUNDI au VENDREDI a 08h00, identique a la minuterie en production
#   (OnCalendar=Mon..Fri *-*-* 08:00:00, relevee le 22/11/2026 ; la demande RSSI
#   initiale du 23/09/2026 etait lundi et jeudi). La fenetre est calculee par le
#   script (window_hours) : lundi = 72 h (depuis vendredi 08h00), autres jours = 24 h
#   -> aucune alerte comptee deux fois, aucun trou entre deux envois.
#   Source : decisions du triage reinjectees (event_source=alert_triage,
#   triage_decision=mail) : seules les alertes JUGEES PERTINENTES y figurent.
#   Idempotent. Test a blanc : DIGEST_DRYRUN=1 /usr/local/sbin/omni-alert-digest
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

install -m 755 triage/omni-alert-digest /usr/local/sbin/omni-alert-digest
echo "  [+] /usr/local/sbin/omni-alert-digest"

cat > /etc/systemd/system/omni-alert-digest.service <<'UNIT'
[Unit]
Description=OMNI SIEM - Recapitulatif des alertes retenues (non faux positifs)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-alert-digest
Nice=10
# Durcissement : le recap lit OpenSearch en local et envoie un mail, rien d'autre.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/omni-alert-triage.env
UNIT

cat > /etc/systemd/system/omni-alert-digest.timer <<'UNIT'
[Unit]
Description=OMNI SIEM - Recapitulatif des alertes (du lundi au vendredi 08h00)

[Timer]
OnCalendar=Mon..Fri *-*-* 08:00:00
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now omni-alert-digest.timer >/dev/null 2>&1
echo "  [+] minuterie activee :"
systemctl list-timers omni-alert-digest.timer --no-pager | sed -n '2p'
