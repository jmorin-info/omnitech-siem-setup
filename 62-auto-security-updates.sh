#!/usr/bin/env bash
# =============================================================================
# 62-auto-security-updates.sh - MAJ securite automatiques DURCIES pour le SIEM.
#   unattended-upgrades applique deja les MAJ securite Debian (timers actifs).
#   Ce script ajoute le durcissement specifique a CE serveur sensible :
#     - JAMAIS d'auto-reboot : /data est chiffre (LUKS2 + TPM2). Un reboot doit etre
#       fait EN FENETRE, operateur dispo (fallback passphrase si le TPM echoue).
#       (Le TPM n'a pas encore ete valide par un reboot -> auto-reboot = interdit.)
#     - Stack SIEM EXCLU de l'auto-upgrade (repos tiers + compat stricte
#       Graylog<->OpenSearch<->Mongo) -> mise a jour MANUELLE testee uniquement.
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
// REBOOT JAMAIS automatique : /data chiffre LUKS2+TPM2 -> reboot manuel en fenetre.
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
echo "  -- Auto-reboot --"
apt-config dump 2>/dev/null | grep -i "Unattended-Upgrade::Automatic-Reboot " | sed 's/^/    /'
echo "  -- Stack exclu (Package-Blacklist) --"
apt-config dump 2>/dev/null | grep -iA1 "Package-Blacklist" | grep -iE "graylog|opensearch|mongo" | head -3 | sed 's/^/    /'
echo "  -- Periodicite --"
apt-config dump 2>/dev/null | grep -iE "Periodic::(Update-Package-Lists|Unattended-Upgrade) " | sed 's/^/    /'
echo "=== 62 termine. RAPPEL : reboot = MANUEL en fenetre + valider le TPM. ==="
