#!/bin/bash
# =============================================================================
# OMNITECH - SIEM v5 chantier 4 - déploiement auditd + renvoi vers Graylog (entrée Linux TCP 1519)
# Préparé le 27/11/2026 ; pilote sur un serveur Debian 13 le 27/11/2026. À lancer en root sur UN serveur à la fois.
#   --simuler   (défaut) : affiche ce qui serait fait, vérifie les prérequis, n'écrit rien
#   --appliquer          : installe auditd (et rsyslog s'il manque), pose 90-omni-v5.rules, active le greffon syslog, renvoi rsyslog
#   --retour             : retire nos fichiers, recharge les règles, remet la conf rsyslog d'avant
# Prérequis réseau : TCP 1519 vers 10.33.220.10 (nftables Graylog : 10.33.0.0/16 seulement ; Ivry/Lançon = ajout nft + FG).
# Note : les installations Debian minimales récentes n'ont plus rsyslog (journald seul). Sans rsyslog, le greffon
# syslog d'auditd écrit dans journald et rien n'est renvoyé vers Graylog : --appliquer l'installe donc s'il manque
# (cas rencontré lors du pilote du 27/11/2026). Le retour arrière ne le désinstalle pas.
# =============================================================================
MODE="${1:---simuler}"
SIEM=10.33.220.10; PORT=1519
SRC="$(cd "$(dirname "$0")" && pwd)"
SAUV=/root/omni-v5-auditd-avant-$(date +%Y%m%d-%H%M)
R=/etc/audit/rules.d/90-omni-v5.rules
P=/etc/audit/plugins.d/syslog.conf
RS=/etc/rsyslog.d/60-omni-v5-siem.conf
if command -v apt-get >/dev/null; then PKG="auditd audispd-plugins"; INST="apt-get install -y $PKG"; INST_RS="apt-get install -y rsyslog"
elif command -v dnf >/dev/null; then PKG="audit audispd-plugins"; INST="dnf install -y audit"; INST_RS="dnf install -y rsyslog"; else echo "gestionnaire de paquets inconnu"; exit 2; fi

echo "Hôte $(hostname) - $(. /etc/os-release; echo "$PRETTY_NAME") - mode $MODE"
case "$MODE" in
--simuler)
  echo "paquets : $PKG ($(command -v auditctl >/dev/null && echo 'auditd déjà présent' || echo 'à installer'))"
  echo "règles  : $SRC/90-omni-v5.rules -> $R ($(grep -c '^-' "$SRC/90-omni-v5.rules") lignes actives)"
  echo "greffon : $P active = yes, args = LOG_LOCAL6"
  echo "rsyslog : $RS -> local6 (audit) + authpriv vers @@$SIEM:$PORT ($(command -v rsyslogd >/dev/null && echo 'rsyslog présent' || echo 'rsyslog ABSENT : sera installé'))"
  timeout 3 bash -c "</dev/tcp/$SIEM/$PORT" 2>/dev/null && echo "TCP $SIEM:$PORT joignable" || echo "TCP $SIEM:$PORT INJOIGNABLE (nftables/FG à ouvrir)"
  command -v augenrules >/dev/null && echo "augenrules présent" ;;
--appliquer)
  set -u; mkdir -p "$SAUV"; cp -a /etc/audit "$SAUV/" 2>/dev/null; cp -a /etc/rsyslog.d "$SAUV/" 2>/dev/null; echo "sauvegarde $SAUV"
  command -v auditctl >/dev/null || $INST || { echo "installation KO"; exit 3; }
  command -v rsyslogd >/dev/null || { $INST_RS && systemctl enable --now rsyslog; } || { echo "installation de rsyslog KO"; exit 3; }
  install -m 0640 "$SRC/90-omni-v5.rules" "$R"
  augenrules --check && augenrules --load || { echo "règles refusées -> retour"; rm -f "$R"; augenrules --load; exit 4; }
  if [ -f "$P" ]; then sed -i -e 's/^active *=.*/active = yes/' -e 's/^args *=.*/args = LOG_LOCAL6/' "$P"; fi
  cat > "$RS" <<EOF
# SIEM v5 chantier 4 (27/11/2026) - audit (local6) et authentification vers Graylog
local6.*;authpriv.*  action(type="omfwd" target="$SIEM" port="$PORT" protocol="tcp" queue.type="LinkedList" queue.size="50000" action.resumeRetryCount="-1")
EOF
  rsyslogd -N1 && systemctl restart rsyslog
  systemctl enable --now auditd; service auditd reload 2>/dev/null || systemctl kill -s HUP auditd
  auditctl -s | head -5; echo "APPLIQUÉ. Retour : $0 --retour" ;;
--retour)
  rm -f "$R" "$RS"; augenrules --load
  D=$(ls -d /root/omni-v5-auditd-avant-* 2>/dev/null | tail -1)
  [ -n "$D" ] && [ -f "$D/audit/plugins.d/syslog.conf" ] && cp -a "$D/audit/plugins.d/syslog.conf" "$P"
  service auditd reload 2>/dev/null || systemctl kill -s HUP auditd; systemctl restart rsyslog
  echo "RETOUR fait (auditd laissé installé ; « apt-get remove auditd » / « dnf remove audit » si souhaité)" ;;
*) echo "usage : $0 [--simuler|--appliquer|--retour]"; exit 1 ;;
esac
