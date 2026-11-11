// Installation v2 (11/11/2026) dans MongoDB Graylog. Idempotent. Lancer : mongosh "$URI" --quiet installer-mongo.js
// Prise en compte des regles/pipelines/streams au redemarrage de graylog-server (un seul, regroupe).
const fs = require('fs'), DIR = '/root/alertes-v2/regles';
const now = new Date();
let journal = [];
// 1. regles de pipeline (creation ou mise a jour par titre)
fs.readdirSync(DIR).filter(f => f.endsWith('.rule')).forEach(f => {
  const src = fs.readFileSync(DIR + '/' + f, 'utf8');
  const title = src.match(/^rule\s+"([^"]+)"/)[1];
  const ex = db.pipeline_processor_rules.findOne({ title: title });
  if (ex) {
    if (ex.source !== src) { db.pipeline_processor_rules.updateOne({ _id: ex._id }, { $set: { source: src, modified_at: now } }); journal.push('regle mise a jour : ' + title); }
    else journal.push('regle inchangee : ' + title);
  } else {
    db.pipeline_processor_rules.insertOne({ title: title, description: 'Faux positifs v2 11/11/2026 (agent alertes) - voir Rapport-Alertes-v2-20261111.md', source: src, created_at: now, modified_at: now });
    journal.push('regle creee : ' + title);
  }
});
// 2. pipeline "OMNI - Allowlist FP" : ajout des regles omni-fp-26-* au stage 25
const p = db.pipeline_processor_pipelines.findOne({ title: 'OMNI - Allowlist FP' });
let psrc = p.source;
const nouvelles = db.pipeline_processor_rules.find({ title: /^omni-fp-26-/ }).toArray().map(r => r.title).sort();
nouvelles.forEach(t => { if (!psrc.includes('rule "' + t + '"')) psrc = psrc.replace(/\nend\s*$/, '\nrule "' + t + '"\nend'); });
if (psrc !== p.source) { db.pipeline_processor_pipelines.updateOne({ _id: p._id }, { $set: { source: psrc, modified_at: now } }); journal.push('pipeline Allowlist FP : ' + nouvelles.length + ' regles v2 au stage 25'); }
// 3. definitions d'evenements (requetes) : ajouts cibles, une seule fois (marqueur dans la requete)
const ajouts = [
  ["OMNI - Exécution d'un binaire déposé via archiveur ou Outlook (T1204.002)", ' AND NOT fp_allowlist:true'],
  ["OMNI - Force brute SUIVIE d'un succès (même compte / 15 min)", ' AND NOT winlogbeat_winlog_event_data_Status:0xc00002ee'],
  ["OMNI - Tunneling DNS suspect (exfiltration)", ' AND NOT dns_domain:(static.microsoft OR amazonaws.com OR webex.com)'],
  ["OMNI - Login admin hors segment admin (Aruba/EMS)", ' AND NOT src_ip:10.33.50.250 AND NOT net_octet:81'],
];
ajouts.forEach(([titre, add]) => {
  const d = db.event_definitions.findOne({ title: titre });
  if (!d) { journal.push('DEFINITION INTROUVABLE : ' + titre); return; }
  if (d.config.query.includes(add.trim())) { journal.push('definition deja a jour : ' + titre); return; }
  db.event_definitions.updateOne({ _id: d._id }, { $set: { 'config.query': '(' + d.config.query + ')' + add, updated_at: now } });
  journal.push('definition modifiee : ' + titre + ' -> ' + add.trim());
});
// 4. streams : decisions de tri (event_source alert_triage) -> OMNI - Interne SIEM au lieu de OMNI - M365
const M365 = ObjectId('6a2ac4a165bc77613c83b22a'), INT = ObjectId('6a2bd9ec65bc77613c898706');
[['alert_triage', M365, true], ['alert_triage', INT, false]].forEach(([v, sid, inv]) => {
  if (!db.streamrules.findOne({ stream_id: sid, field: 'event_source', value: v, inverted: inv })) {
    db.streamrules.insertOne({ field: 'event_source', value: v, type: 1, inverted: inv, stream_id: sid, description: 'v2 11/11/2026 : decisions de tri dans omni-interne' });
    journal.push('regle de stream ajoutee : event_source=' + v + (inv ? ' (exclue de M365)' : ' (vers Interne SIEM)'));
  }
});
print(journal.join('\n'));
