#!/bin/bash
# Retour SIEM v5 chantier 3 (TI) : supprime PAR NOM tout objet omni-v5-ti-* / « OMNI v5 - TI » + timer + fichiers.
# Usage : bash /root/omni-v5-ti/retour.sh [--simuler]   (la cle /etc/omni-v5-ti/threatfox.key, propriete de jmorin, est CONSERVEE)
cd /root/omni-v5-ti || exit 1
python3 -I v5_ti_build.py --retour "$@"
if [ "$1" = "--simuler" ]; then
  echo '[simulation] systemctl disable --now omni-v5-ti-fetch.timer ; rm unites, /usr/local/sbin/omni-v5-ti-fetch, /etc/default/omni-v5-ti-fetch, /etc/graylog/lookup/ti/, /var/lib/omni-v5-ti/, /var/log/omni-v5-ti/'
  ls -la /etc/omni-v5-ti/ /etc/graylog/lookup/ti/ 2>/dev/null; exit 0
fi
systemctl disable --now omni-v5-ti-fetch.timer 2>/dev/null
rm -f /etc/systemd/system/omni-v5-ti-fetch.timer /etc/systemd/system/omni-v5-ti-fetch.service /usr/local/sbin/omni-v5-ti-fetch /etc/default/omni-v5-ti-fetch
systemctl daemon-reload
rm -rf /etc/graylog/lookup/ti /var/lib/omni-v5-ti /var/log/omni-v5-ti
find /etc/omni-v5-ti -mindepth 1 ! -name threatfox.key -delete 2>/dev/null
echo 'retour v5-ti termine (cle threatfox.key conservee)'
