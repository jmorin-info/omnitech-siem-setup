#!/usr/bin/env bash
# =============================================================================
# 27-harden-services.sh - Durcissement systemd de MASSE des services omni-/oms-.
#
#   Neutralise le pouvoir de root en cas de RCE/bug sur chacun des robots :
#   aucune capability (CapabilityBoundingSet vide -> CAP_DAC_OVERRIDE retire),
#   systeme de fichiers en lecture seule sauf le strict necessaire, /root en
#   lecture seule, pas d'acces kernel, filtre d'appels systeme. Applique via
#   drop-in *.service.d/hardening.conf (reversible : supprimer le fichier).
#
#   Profils (ReadWritePaths adaptes aux ECRITURES REELLES, mesurees 02/07/2026) :
#     STD     : ecrit /var/lib (state des robots).
#     WEB     : STD + /var/www/siem-kit + SupplementaryGroups=www-data.
#     LOOKUP  : STD + /etc/graylog/lookup (CSV threat-intel/dhcp).
#     DOCS    : STD + /root/omnitech-siem-setup/docs (dossier de preuves ISO).
#     BACKUPS : STD + /var/backups/siem (rapport hebdo).
#   NON durcis (privileges incompressibles) : omni-backup-config et
#   omni-cert-renew montent un partage CIFS (CAP_SYS_ADMIN) et/ou renouvellent
#   des certificats + reload nginx ; a durcir manuellement plus tard.
#
#   omni-alert-triage / omni-soar / omni-mobile-api ont deja leur propre drop-in
#   (36/65) : ce script ne les touche pas.
#   Idempotent. Lecture seule cote donnees (ne modifie que des unites systemd).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

BASE='NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged'

# emet le drop-in : $1=unit  $2=ReadWritePaths  $3=SupplementaryGroups(optionnel)
emit() {
  local unit="$1" rwp="$2" grp="${3:-}"
  install -d "/etc/systemd/system/${unit}.d"
  { echo "# Durcissement systemd (27-harden-services.sh, audit 02/07/2026)."
    echo "[Service]"
    echo "${BASE}"
    echo "ReadWritePaths=${rwp}"
    [[ -n "${grp}" ]] && echo "SupplementaryGroups=${grp}"
  } > "/etc/systemd/system/${unit}.d/hardening.conf"
  echo "  durci: ${unit}  (rw=${rwp}${grp:+ ; grp=${grp}})"
}

# --- pre-requis : /var/www/siem-kit doit etre inscriptible par le groupe
#     www-data (geo-flux ecrit flux.json a la racine ; sans CAP_DAC_OVERRIDE,
#     root passe par le bit group). Les sous-dossiers rapports/soar sont deja 775.
[[ -d /var/www/siem-kit ]] && chmod g+w /var/www/siem-kit

STD_UNITS=(
  omni-cert-check omni-collect-health omni-disk-guard omni-incident-correlate
  omni-integrity omni-integrity-verify omni-ldap-recon omni-leak-dehashed
  omni-leak-github omni-leak-hibp omni-leak-ransomlook omni-leak-ransomwarelive
  omni-m365-activity omni-m365-fetch omni-m365-fwd-audit omni-ndr-beacon
  omni-ndr-dns omni-ndr-exfil omni-ndr-lateral omni-ndr-scan omni-postboot-check
  omni-self-health omni-soar-expire omni-source-watchdog omni-ti-feeds
  omni-ueba-geo omni-ueba-geo-newcountry omni-ueba-score omni-ueba-volume
  omni-vuln-scan omni-drift-check omni-fortidhcp-fetch omni-geo-flux
  omni-monthly-report omni-weekly-report omni-iso-evidence
  oms-graph oms-graph-respond oms-ml-anomaly oms-ml-fp oms-xdr
)

echo "==> Durcissement des services (drop-in hardening.conf)"
for u in "${STD_UNITS[@]}"; do
  unit="${u}.service"
  [[ -f "/etc/systemd/system/${unit}" ]] || { echo "  (absent, ignore: ${unit})"; continue; }
  case "${u}" in
    omni-geo-flux|omni-monthly-report|omni-soar-expire)
      emit "${unit}" "/var/lib /var/www/siem-kit" "www-data" ;;
    omni-ti-feeds|omni-fortidhcp-fetch)
      emit "${unit}" "/var/lib /etc/graylog/lookup" ;;
    omni-iso-evidence)
      emit "${unit}" "/var/lib /root/omnitech-siem-setup/docs" ;;
    omni-weekly-report)
      emit "${unit}" "/var/lib /var/backups/siem" ;;
    *)
      emit "${unit}" "/var/lib" ;;
  esac
done

systemctl daemon-reload
echo
echo "=== 27-harden-services.sh termine. NON durcis (voir en-tete) : omni-backup-config, omni-cert-renew."
echo "    Test : relancer un oneshot (ex systemctl start omni-ueba-score) et verifier exit 0 + absence"
echo "    d'erreur 'Read-only file system' / 'Permission denied' dans journalctl -u <service>."
