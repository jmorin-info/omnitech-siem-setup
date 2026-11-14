#!/bin/bash
# Génère manifeste-deploye.txt : chaque fichier du dépôt dont l'original en service est connu.
# À relancer quand on ajoute un script déployé (puis relire le manifeste avant de le commiter).
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1
OUT=manifeste-deploye.txt
{
echo "# Manifeste : <chemin en service><TAB><chemin dans le dépôt> (généré par generer-manifeste.sh le $(date +%d/%m/%Y))"
emit(){ [ -f "$1" ] && printf '%s\t%s\n' "$1" "$2"; }
for f in $(git ls-files deploye/sbin); do emit "/usr/local/sbin/${f#deploye/sbin/}" "$f"; done
for f in $(git ls-files deploye/systemd); do emit "/etc/systemd/system/${f#deploye/systemd/}" "$f"; done
emit /etc/apt/preferences.d/oms-siem-series deploye/apt/oms-siem-series
emit /etc/apt/apt.conf.d/52omni-siem.conf deploye/apt/52omni-siem.conf
for f in $(git ls-files deploye/logstash); do b=${f#deploye/logstash/}
  case "$b" in sql/*) emit "/etc/logstash/$b" "$f";; log4j2.properties|jvm.options) emit "/etc/logstash/$b" "$f";; *) emit "/etc/logstash/conf.d/$b" "$f";; esac; done
for f in $(git ls-files deploye/opt); do emit "/opt/${f#deploye/opt/}" "$f"; done
for f in $(git ls-files deploye/etc); do emit "/etc/${f#deploye/etc/}" "$f"; done
for f in $(git ls-files deploye/lib); do b=${f#deploye/lib/}; emit "/usr/local/lib/$b" "$f" || emit "/usr/lib/$b" "$f"; done
emit /usr/local/sbin/omni-alert-triage triage/omni-alert-triage
emit /usr/local/sbin/omni-alert-digest triage/omni-alert-digest
emit /usr/local/sbin/omni-fp tools/omni-fp
emit /usr/local/sbin/omni-version-watch tools/omni-version-watch
emit /opt/oms-seal-sla/seal_sla_poller.py seal/sla/seal_sla_poller.py
emit /root/omnitech-siem-setup/mobile/omni-mobile-api.py mobile/omni-mobile-api.py
# console SOC : coquille et scripts (les bibliothèques et images lourdes restent hors manifeste)
for p in /var/www/siem-soc/index.html /var/www/siem-soc/sw.js /var/www/siem-soc/manifest.webmanifest /var/www/siem-soc/app*.js; do emit "$p" "mobile/soc/${p#/var/www/siem-soc/}"; done
for f in $(git ls-files mobile/soc/icons); do emit "/var/www/siem-soc/${f#mobile/soc/}" "$f"; done
emit /etc/nginx/snippets/omni-sec-headers-soc.conf deploye/nginx/omni-sec-headers-soc.conf
emit /etc/nginx/snippets/omni-sec-headers.conf deploye/nginx/omni-sec-headers.conf
} > "$OUT"
echo "$(grep -vc '^#' "$OUT") entrées dans $OUT"
