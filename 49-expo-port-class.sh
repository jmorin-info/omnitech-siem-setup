#!/usr/bin/env bash
# =============================================================================
# 49-expo-port-class.sh - Exposition Internet + classe de port a risque (FortiGate)
#   Enrichit chaque flux FortiGate avec :
#     - port_class    : classe du service destination (RDP/SSH/SMB/SQL/...) via
#                       lookup CSV dest_port -> classe (lookups/port-class.csv).
#     - net_direction : entrant / sortant / interne / transit, deduit des roles
#                       d'interface (srcintfrole / dstintfrole : wan|lan|dmz).
#     - expo_internet : "oui" si flux ENTRANT depuis le WAN ACCEPTE vers un port
#                       a risque -> port reellement exposabldepuis Internet.
#   + page Reseau : top ports a risque exposes / acceptes depuis le WAN.
#
#   CHAMPS VERIFIES EN LIVE (omni-fortigate_*) :
#     - srcintfrole / dstintfrole : keyword, valeurs {lan, wan, dmz, undefined}.
#     - dest_port                 : keyword (chaine) -> lookup direct sur la valeur.
#     - action                    : keyword {accept, deny, pass, permit, blocked...}.
#     - src_ip_reserved_ip / dest_ip_reserved_ip : bool, mais SEULEMENT 'true' ou
#       ABSENT (jamais 'false') -> un IP publique = champ MANQUANT. On NE s'appuie
#       donc PAS sur reserved_ip pour la direction ; les roles d'interface (wan/lan)
#       sont le signal fiable. reserved_ip sert seulement de garde-fou secondaire.
# Idempotent. Prerequis : 12 (streams/pipelines FortiGate). Relance 14 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api
LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/4] CSV lookups/port-class.csv (dest_port -> classe de port a risque)"
cat > lookups/port-class.csv <<'CSV'
dest_port,port_class
20,FTP
21,FTP
22,SSH
23,Telnet
25,SMTP
53,DNS
69,TFTP
110,POP3
111,RPC
135,RPC-DCOM
137,NetBIOS
138,NetBIOS
139,NetBIOS
143,IMAP
161,SNMP
162,SNMP
389,LDAP
445,SMB
465,SMTPS
512,rexec
513,rlogin
514,rsh-syslog
587,SMTP-Sub
636,LDAPS
873,rsync
993,IMAPS
995,POP3S
1080,SOCKS
1099,RMI
1433,SQL-Server
1434,SQL-Browser
1521,Oracle
1723,PPTP
2049,NFS
2082,cPanel
2083,cPanel
2222,SSH-Alt
2375,Docker
2376,Docker-TLS
2483,Oracle
2484,Oracle
3000,Web-Dev
3306,MySQL
3389,RDP
3390,RDP-Alt
4444,Metasploit
5000,Web-Dev
5432,PostgreSQL
5500,VNC
5555,ADB
5601,Kibana
5631,pcAnywhere
5900,VNC
5901,VNC
5985,WinRM
5986,WinRM-TLS
6000,X11
6379,Redis
6443,Kube-API
7001,WebLogic
8000,Web-Alt
8008,Web-Alt
8080,Web-Proxy
8081,Web-Proxy
8443,Web-Alt-TLS
8888,Web-Alt
9000,Web-Alt
9090,Web-Admin
9200,Elasticsearch
9300,Elasticsearch
10000,Webmin
11211,Memcached
15672,RabbitMQ
27017,MongoDB
27018,MongoDB
50000,SAP
CSV
install -m 644 lookups/port-class.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/port-class.csv" 2>/dev/null || true
ok "port-class.csv deploye ($(($(wc -l < lookups/port-class.csv) - 1)) ports classes)"

# ensure_lookup <nom> <titre> <csv> <key_col> <val_col>  (adapter+cache+table)
# (meme implementation que 37-mitre-attack.sh ; recopie pour autonomie du script)
# ensure_lookup() centralise dans lib-graylog.sh (supprime la copie locale)

echo "==> [2/4] Table de lookup (dest_port -> port_class)"
ensure_lookup "port-class" "OMNI dest_port -> classe de port a risque" "port-class.csv" "dest_port" "port_class"

echo "==> [3/4] Regles d'enrichissement FortiGate (port_class + net_direction + expo_internet)"

# port_class : la table renvoie "" (default NULL) si le port n'est pas a risque
# -> on ne pose le champ QUE si la valeur est non vide (evite un champ vide partout).
ensure_rule "omni-forti-15-port-class" <<'EOF'
rule "omni-forti-15-port-class"
when
  to_string($message.event_source) == "fortigate" AND has_field("dest_port")
  AND to_string(lookup_value("omni-port-class", to_string($message.dest_port)), "") != ""
then
  set_field("port_class", to_string(lookup_value("omni-port-class", to_string($message.dest_port))));
end
EOF

# net_direction : posé par 4 règles dédiées omni-forti-15-dir-{entrant,interne,
# sortant,transit} (définies plus bas). NE PAS réintroduire de règle unique avec
# un 'let = if ... then ... else' (ternaire) : Graylog REFUSE cette syntaxe ->
# api_post échoue -> le script abortait (exit 5) avant la règle expo. Bug retiré le 18/06.

# expo_internet : un flux ENTRANT (source WAN), ACCEPTE, vers un port A RISQUE
# (port_class pose) = service reellement exposable depuis Internet. C'est le
# signal d'audit d'exposition. On pose aussi un alert_tag pour le remonter.
# NB : depend de l'ordre des stages -> port_class (15) et net_direction (15)
# sont poses AVANT ; cette regle est en stage 16.
ensure_rule "omni-forti-16-expo-internet" <<'EOF'
rule "omni-forti-16-expo-internet"
when
  to_string($message.event_source) == "fortigate"
  AND to_string($message.net_direction) == "entrant"
  AND has_field("port_class")
  AND to_string($message.subtype) != "local"
  AND NOT has_field("vpntype")
  AND (to_string($message.action) == "accept"
    OR to_string($message.action) == "pass"
    OR to_string($message.action) == "permit")
then
  set_field("expo_internet", "oui");
  set_field("alert_tag", "exposition_internet");
end
EOF

echo "==> [3b] Technique MITRE pour l'exposition (CSV 37 si present)"
CSV37="lookups/mitre-attack.csv"
if [[ -f "${CSV37}" ]]; then
  grep -q "^exposition_internet," "${CSV37}" \
    || { echo 'exposition_internet,T1190,Exploit Public-Facing Application,Initial Access,eleve,7' >> "${CSV37}"; ok "MITRE +exposition_internet"; }
  install -m 644 "${CSV37}" /etc/graylog/lookup/mitre-attack.csv
  chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
fi

echo "==> [4/4] Pipeline 'OMNI - Exposition reseau' (stages 14/15/16) + connexion FortiGate"
# NB : la version de reference du pipeline (stage 14 privflags + 4 regles de
# direction src/dst, anti-HALT) est portee par 49-enrich-lots.sh, qui s'execute
# AVANT ce script (ordre alphabetique) et y definit privflags + dir-interne/
# sortant/entrant/transit. On reprend ICI la MEME definition pour qu'un redeploy
# de ce script ne reintroduise pas l'ancienne version (stages 15/16 sans privflags,
# qui cassait les regles de direction). L'ancienne regle if/else omni-forti-15-net-
# direction n'est plus referencee (orpheline, inoffensive).
PL_EXPO="$(ensure_pipeline "OMNI - Exposition reseau" <<'EOF'
pipeline "OMNI - Exposition reseau"
stage 14 match either
rule "omni-forti-14-privflags"
stage 15 match either
rule "omni-forti-15-port-class"
rule "omni-forti-15-dir-interne"
rule "omni-forti-15-dir-sortant"
rule "omni-forti-15-dir-entrant"
rule "omni-forti-15-dir-transit"
stage 16 match either
rule "omni-forti-16-expo-internet"
end
EOF
)"
SID="$(get_stream_id 'OMNI - FortiGate')"
[[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_EXPO}" || warn "stream absent: OMNI - FortiGate"

echo
echo "=== 49-expo-port-class.sh termine."
echo "    Champs poses sur les NOUVEAUX flux FortiGate :"
echo "      port_class (RDP/SSH/SMB/...), net_direction (entrant/sortant/interne/transit),"
echo "      expo_internet=oui + alert_tag=exposition_internet (entrant WAN accepte vers port a risque)."
echo "    Relancer 14-graylog-dashboards.sh pour les widgets page Reseau."
echo "    (Si 37 present : exposition_internet est mappe MITRE T1190 / score 7.) ==="
