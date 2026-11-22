#!/usr/bin/env bash
# =============================================================================
# 62-auto-security-updates.sh - MAJ securite automatiques DURCIES pour le SIEM.
#   unattended-upgrades applique deja les MAJ securite Debian (timers actifs).
#   Ce script ajoute le durcissement specifique a CE serveur sensible :
#     - unattended-upgrades ne redemarre JAMAIS la machine (Automatic-Reboot
#       "false") : les correctifs quotidiens n'entrainent aucun redemarrage.
#     - Le redemarrage automatique existe, mais il est porte par la tache
#       hebdomadaire oms-maj-siem (deploye/sbin/oms-maj-siem, regle retenue par
#       l'administrateur le 22/11/2026) :
#         * oms-maj-siem.timer : dimanche 04:30 (+ 0 a 10 min aleatoires),
#           Persistent=false (pas de rattrapage si la machine est arretee) ;
#         * redemarrage seulement si /var/run/reboot-required existe a la fin du
#           passage (paquet installe le jour meme OU correctif unattended-upgrades
#           de la semaine), apres les controles prealables et la sauvegarde ;
#           reboot programme 60 s plus tard (systemd-run, unite oms-maj-siem-reboot) ;
#         * aucun redemarrage si les prealables echouent, si la sauvegarde
#           mongodump echoue, s'il n'y a rien a faire, ni en mode --simuler ;
#         * un lancement manuel (systemctl start oms-maj-siem.service) suit les
#           memes regles et peut donc redemarrer la machine hors fenetre ;
#         * au demarrage, oms-maj-siem-postboot.service (oms-maj-siem --apres-boot)
#           refait les reparations et le controle final, dont le montage de /data
#           (LUKS2 + TPM2), et envoie le compte rendu par mail.
#       Si le deverrouillage TPM2 echoue, /data n'est pas monte : le compte rendu
#       le signale et l'ouverture se fait a la main (passphrase de secours, voir
#       docs/securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md).
#     - Stack SIEM EXCLU de unattended-upgrades (repos tiers + compat stricte
#       Graylog<->OpenSearch<->Mongo) : mise a jour par oms-maj-siem dans les
#       series epinglees (/etc/apt/preferences.d/oms-siem-series).
#     - needrestart en mode LISTE : signale les services a redemarrer apres une MAJ
#       de lib (ex. openssl) SANS jamais les redemarrer tout seul.
#   Origines : on garde le defaut Debian (securite + correctifs stables ponctuels).
#   Visibilite : omni-self-health signale reboot-required + auto-patch en panne.
#   Idempotent.
# =============================================================================
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

echo "==> [1/3] Override apt durci : /etc/apt/apt.conf.d/52omni-siem.conf"
cat > /etc/apt/apt.conf.d/52omni-siem.conf <<'EOF'
// OMNITECH SIEM - durcissement MAJ securite (62-auto-security-updates.sh).
// unattended-upgrades ne redemarre jamais ; le redemarrage eventuel est fait par
// oms-maj-siem (dimanche 04:30, si /var/run/reboot-required), cf. 62-auto-security-updates.sh.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Stack SIEM EXCLU (repos tiers, compat versions) -> MAJ manuelle testee.
Unattended-Upgrade::Package-Blacklist {
  "graylog-server";
  "graylog-datanode";
  "graylog-sidecar";
  "opensearch";
  "opensearch-dashboards";
  "mongodb-org";
  "mongodb-org-server";
  "mongodb-org-database";
  "mongodb-org-mongos";
  "mongodb-org-tools";
  "mongodb-mongosh";
};

// Nettoyage prudent (evite la saturation de /boot par les vieux noyaux).
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";

// Pas de MTA sur ce serveur -> visibilite via omni-self-health (GELF), pas par mail.
Unattended-Upgrade::Mail "";
EOF
echo "    OK"

echo "==> [2/3] needrestart en mode LISTE (jamais de restart auto de service)"
DEBIAN_FRONTEND=noninteractive apt-get install -y needrestart >/dev/null 2>&1 \
  && echo "    needrestart installe" || echo "    [!] install needrestart KO (non bloquant)"
install -d -m 755 /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/zz-omni-siem.conf <<'EOF'
# SIEM sensible : lister les services a redemarrer, ne JAMAIS les redemarrer auto.
$nrconf{restart} = 'l';
EOF
echo "    OK"

echo "==> [3/3] Verification de la config effective"
echo "  -- Auto-reboot unattended-upgrades (attendu : false) --"
apt-config dump 2>/dev/null | grep -i "Unattended-Upgrade::Automatic-Reboot " | sed 's/^/    /'
echo "  -- Stack exclu (Package-Blacklist) --"
apt-config dump 2>/dev/null | grep -iA1 "Package-Blacklist" | grep -iE "graylog|opensearch|mongo" | head -3 | sed 's/^/    /'
echo "  -- Periodicite --"
apt-config dump 2>/dev/null | grep -iE "Periodic::(Update-Package-Lists|Unattended-Upgrade) " | sed 's/^/    /'
echo "  -- Redemarrage hebdomadaire (oms-maj-siem) --"
systemctl list-timers oms-maj-siem.timer --no-pager 2>/dev/null | sed -n '2p' | sed 's/^/    /'
echo "=== 62 termine. RAPPEL : unattended-upgrades ne redemarre jamais ; oms-maj-siem"
echo "    redemarre le dimanche 04:30 si /var/run/reboot-required (controle au boot). ==="
