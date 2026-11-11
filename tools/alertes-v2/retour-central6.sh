#!/bin/bash
# RETOUR ARRIERE de la seule signature "environnement de DEV VM-DEV-CENTRAL6" (omni-fp-26-webshell-dev-central6),
# SANS redemarrer graylog-server : suppression de la regle, pipeline Allowlist FP remis tel qu'avant cet ajout, puis
# rechargement a chaud par evenements de cluster (RulesChangedEvent + PipelinesChangedEvent). En root sur BX-IT-GRAYLOG-VM.
# Effet : les "Web shell" de VM-DEV-CENTRAL6 repartent en alerte CRITIQUE (mail immediat).
set -u
B="${1:-$(cat /root/.alertes-v2-backup-dir)}"; F="$B/pipeline-allowlist-avant-central6.json"
[ -f "$F" ] || { echo "sauvegarde introuvable : $F"; exit 1; }
URI=$(grep -E "^mongodb_uri" /etc/graylog/server/server.conf | sed 's/^mongodb_uri *= *//')
NODE=$(cat /var/lib/graylog-server/server/node-id 2>/dev/null || cat /etc/graylog/server/node-id)
mongoimport --quiet --uri="$URI" -c pipeline_processor_pipelines --mode=upsert --file="$F"
mongosh --quiet "$URI" --eval "
const r=db.pipeline_processor_rules.findOne({title:'omni-fp-26-webshell-dev-central6'});
const p=db.pipeline_processor_pipelines.findOne({title:'OMNI - Allowlist FP'});
if(r){ db.pipeline_processor_rules.deleteOne({_id:r._id}); }
const now=String(Date.now());
db.cluster_events.insertOne({timestamp:Long(now), producer:'$NODE', consumers:[], event_class:'org.graylog.plugins.pipelineprocessor.events.RulesChangedEvent', payload:{updated_rules:[], deleted_rules: r ? [{id:r._id.toString(), title:r.title}] : []}});
db.cluster_events.insertOne({timestamp:Long(now), producer:'$NODE', consumers:[], event_class:'org.graylog.plugins.pipelineprocessor.events.PipelinesChangedEvent', payload:{deleted_pipeline_ids:[], updated_pipeline_ids:[p._id.toString()]}});
print('signature DEV CENTRAL6 retiree, pipeline recharge a chaud');"
rm -f /root/alertes-v2/regles/omni-fp-26-webshell-dev-central6.rule
