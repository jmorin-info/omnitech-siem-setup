#!/usr/bin/env bash
# ==============================================================================
# 06-firewall.sh - Pare-feu local nftables (defense en profondeur du SIEM)
#
#   Matrice appliquee (en plus des regles FortiGate inter-VLAN) :
#     TCP 22        <- NET_ADMIN        SSH administration
#     TCP 80/443    <- NET_ADMIN        Console web Graylog (Nginx)
#     TCP 5044      <- NET_BEATS        Winlogbeat (TLS)
#     TCP/UDP 1514  <- IP_FAZ           Forwarding syslog FortiAnalyzer
#     TCP 5555      <- IP_FAZ           Forwarding CEF FortiAnalyzer (option)
#     UDP 161       <- IP_CENTREON      SNMP supervision (si defini)
#   Tout le reste en entree : DROP. 9200/27017/9000 ne sont PAS ouverts
#   (services en localhost uniquement).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

SNMP_RULE=""
if [[ -n "${IP_CENTREON}" ]]; then
  SNMP_RULE="udp dport 161 ip saddr ${IP_CENTREON} accept comment \"SNMP Centreon\""
fi

cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# Pare-feu local SIEM OMNITECH (genere par 06-firewall.sh)
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # Diagnostic reseau
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept

        # Administration
        tcp dport 22 ip saddr ${NET_ADMIN} accept comment "SSH admin"
        tcp dport { 80, 443 } ip saddr ${NET_ADMIN} accept comment "Console Graylog"

        # Collecte
        tcp dport 5044 ip saddr ${NET_BEATS} accept comment "Winlogbeat TLS"
        tcp dport 1514 ip saddr ${IP_FAZ} accept comment "Syslog TCP FortiAnalyzer"
        udp dport 1514 ip saddr ${IP_FAZ} accept comment "Syslog UDP FortiAnalyzer"
        tcp dport 5555 ip saddr ${IP_FAZ} accept comment "CEF FortiAnalyzer"
        tcp dport 1516 ip saddr ${VSPHERE_NET} accept comment "Syslog TCP vSphere"
        udp dport 1516 ip saddr ${VSPHERE_NET} accept comment "Syslog UDP vSphere"
        tcp dport ${ESET_PORT} ip saddr ${IP_ESET} accept comment "Syslog TCP ESET (514 redirige -> ${ESET_PORT})"
        tcp dport 514 ip saddr ${IP_ESET} accept comment "ESET 514 (avant redirect)"
        tcp dport ${EMS_PORT} ip saddr ${IP_EMS} accept comment "Syslog TLS FortiClient EMS (514 redirige -> ${EMS_PORT})"
        tcp dport 514 ip saddr ${IP_EMS} accept comment "FortiClient EMS 514 (avant redirect)"
        tcp dport 1519 ip saddr ${NET_BEATS} accept comment "Syslog TCP Linux (serveurs Debian)"
        tcp dport 1517 ip saddr 10.33.80.252 accept comment "Syslog TCP FortiManager"
        udp dport 1517 ip saddr 10.33.80.252 accept comment "Syslog UDP FortiManager"
        # NPS (${IP_NPS}) et BunkerWeb (${IP_BUNKERWEB}) passent par Beats 5044 (deja ouvert au ${NET_BEATS})

        # Supervision
        ${SNMP_RULE}

        counter comment "drops entrants"
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# Redirection : ESET emet sur 514 (privilegie) -> Graylog ecoute sur ${ESET_PORT}
# (non privilegie). REDIRECT en prerouting reecrit le port avant le chain input.
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 514 ip saddr ${IP_ESET} redirect to :${ESET_PORT} comment "ESET 514 -> ${ESET_PORT}"
        tcp dport 514 ip saddr ${IP_EMS} redirect to :${EMS_PORT} comment "FortiClient EMS 514 -> ${EMS_PORT}"
        tcp dport 514 ip saddr 10.33.80.252 redirect to :1517 comment "FortiManager 514 -> 1517"
        udp dport 514 ip saddr 10.33.80.252 redirect to :1517 comment "FortiManager 514 -> 1517"
    }
}
EOF

nft -c -f /etc/nftables.conf            # controle syntaxique avant application
systemctl enable nftables
systemctl restart nftables
echo "==> Ruleset applique :"
nft list ruleset | head -40

echo
echo "=== 06-firewall.sh termine. Lancer 07-inputs.sh ==="
echo "    Rappel : ouvrir les flux correspondants sur le FortiGate (cf. README §Flux)."
