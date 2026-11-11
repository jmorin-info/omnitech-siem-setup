#!/bin/bash
# RETOUR ARRIERE complet de la v2 des alertes (11/11/2026). En root sur BX-IT-GRAYLOG-VM.
# Remet : scripts de tri/recap, .env (sauvegarde), regles et pipeline Allowlist FP, regle svcstop, 4 definitions,
# regles de stream ; supprime les regles omni-fp-26-* (y compris omni-fp-26-webshell-dev-central6, ajoutee le 11/11
# sur decision jmorin), le lot horaire et ses timers. Redemarre graylog-server a la fin.
# Retour PARTIEL de la seule signature DEV VM-DEV-CENTRAL6, sans redemarrage : retour-central6.sh
set -u
B="${1:-$(cat /root/.alertes-v2-backup-dir)}"; [ -d "$B" ] || { echo "sauvegarde introuvable : $B"; exit 1; }
URI=$(grep -E "^mongodb_uri" /etc/graylog/server/server.conf | sed 's/^mongodb_uri *= *//')
systemctl disable --now omni-alert-lot.timer 2>/dev/null; rm -f /etc/systemd/system/omni-alert-lot.timer /etc/systemd/system/omni-alert-lot.service /usr/local/sbin/omni-alert-lot
cp -p "$B/omni-alert-digest.timer" /etc/systemd/system/omni-alert-digest.timer
install -m 755 "$B/omni-alert-triage" /usr/local/sbin/omni-alert-triage
install -m 755 "$B/omni-alert-digest" /usr/local/sbin/omni-alert-digest
install -m 600 "$B/omni-alert-triage.env" /etc/omni-alert-triage.env
mongosh --quiet "$URI" --eval 'db.pipeline_processor_rules.deleteMany({title:/^omni-fp-26-/}); db.streamrules.deleteMany({field:"event_source", value:"alert_triage"});'
mongoimport --quiet --uri="$URI" -c pipeline_processor_rules --mode=upsert --file="$B/rules.json"
mongoimport --quiet --uri="$URI" -c pipeline_processor_pipelines --mode=upsert --file="$B/pipeline-allowlist.json"
# seulement les 4 definitions modifiees par la v2 (ne touche pas aux changements faits depuis par d'autres)
mongoimport --quiet --uri="$URI" -c event_definitions --mode=upsert --file="$B/defs-modifiees-avant.json"
systemctl daemon-reload; systemctl restart omni-alert-triage; systemctl restart graylog-server
echo "retour termine (sauvegarde $B)"
