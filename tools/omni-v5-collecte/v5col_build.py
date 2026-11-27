#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# SIEM v5 - chantier 4 « Collecte » (27/11/2026) - objets Graylog omni-v5-collecte-*
#   --simuler  : affiche ce qui serait créé (aucune écriture)
#   --appliquer: sauvegarde /var/backups/siem/v5-collecte-avant-AAAAMMJJ-HHMM/,
#                crée les objets, écrit cree.json + retour.sh dans ce dossier
#   --retour <dossier> [--simuler] : supprime PAR ID les seuls objets de cree.json
#   --tester   : simulateur de pipelines sur messages synthétiques
# Garde-fous : ne modifie aucun objet existant (connexions ajoutées par
# /connections/to_pipeline = seules nos pipelines bougent), jamais de redémarrage.
# =============================================================================
import sys, os, json, time, subprocess
sys.path.insert(0, '/root/omni-v5-collecte')
from v5col_api import api  # noqa: E402  (même module que l'ancien exec())

NOM = 'omni-v5-collecte'
S_WINSEC = '6a2ab23565bc77613c834123'   # OMNI - Windows Security
S_WINOTH = '6a2ab23665bc77613c834149'   # OMNI - Windows autres
NFT_TAG = 'v5-collecte'
# ---------------------------------------------------------------------------
INDEX_SETS = [
    dict(cle='dns', title='omni-v5-collecte-dns-dc', prefix='omni-v5col-dns', shards=2, retention=4,
         description='SIEM v5 chantier 4 : requêtes DNS des 3 DC (ETW DNS-Server via NXLog, filtré)'),
    dict(cle='fgiv', title='omni-v5-collecte-fg-ivry', prefix='omni-v5col-fgiv', shards=1, retention=4,
         description='SIEM v5 chantier 4 : syslog direct IV-FW01 (event/utm, voie de secours du FAZ)'),
]
INPUTS = [
    dict(cle='dns', title='omni-v5-collecte-dns-dc (GELF TCP 12220)', type='org.graylog2.inputs.gelf.tcp.GELFTCPInput',
         attributes={"recv_buffer_size": 1048576, "port": 12220, "tls_enable": False, "use_null_delimiter": True,
                     "tcp_keepalive": True, "number_worker_threads": 2, "max_message_size": 2097152,
                     "charset_name": "UTF-8", "bind_address": "0.0.0.0", "decompress_size_limit": 8388608}),
    dict(cle='fgiv', title='omni-v5-collecte-fg-ivry (Syslog UDP 1521)', type='org.graylog2.inputs.syslog.udp.SyslogUDPInput',
         attributes={"expand_structured_data": False, "recv_buffer_size": 16777216, "port": 1521,
                     "allow_override_date": True, "force_rdns": False, "bind_address": "0.0.0.0",
                     "store_full_message": False}),
]
STREAMS = [
    dict(cle='dns', title='omni-v5-collecte-dns-dc', description='SIEM v5 : requêtes DNS des DC (entrée GELF TCP 12220)'),
    dict(cle='fgiv', title='omni-v5-collecte-fg-ivry', description='SIEM v5 : IV-FW01 en syslog direct (entrée UDP 1521)'),
]
GUID_LAPS = 'fb67b5bd-ef3d-4d01-ba85-0ab2f0ed97dd|b3f5799a-a3a6-433b-8d41-0c79fe58fa71|eaf88f9d-c28c-4f8a-992d-2b1f089f66f8|2716a678-16f9-46d4-9a00-b3cc5c55977c'
RULES = {
# --- Directory Service (DC) : canal à activer côté DC (décision) ------------
'omni-v5-collecte-ds-normalisation': '''rule "omni-v5-collecte-ds-normalisation"
// SIEM v5 chantier 4 : journal Directory Service des DC (canal ajouté au winlogbeat des DC sur décision)
when
  to_string($message.winlogbeat_winlog_channel) == "Directory Service"
then
  set_field("v5_collecte", "directory_service");
  set_field("ds_event_id", to_string($message.winlogbeat_winlog_event_id));
end''',
'omni-v5-collecte-ds-ldap-client': '''rule "omni-v5-collecte-ds-ldap-client"
// 2889 = liaison LDAP non signée / simple en clair (param1 = IP:port, param2 = identité, param3 = type 0 simple / 1 SASL)
// 3039 = liaison sans jeton de liaison de canal (CBT) valide (param1 = IP:port, param2 = identité)
when
  to_string($message.winlogbeat_winlog_channel) == "Directory Service"
  AND ( to_string($message.winlogbeat_winlog_event_id) == "2889" OR to_string($message.winlogbeat_winlog_event_id) == "3039" )
then
  let c = regex("^\\\\[?([0-9A-Fa-f\\\\.:]+?)\\\\]?:([0-9]+)$", to_string($message.winlogbeat_winlog_event_data_param1));
  set_field("ldap_client_ip", to_string(c["0"]));
  set_field("ldap_client_port", to_string(c["1"]));
  set_field("ldap_identite", to_string($message.winlogbeat_winlog_event_data_param2));
  set_field("ldap_type_liaison", to_string($message.winlogbeat_winlog_event_data_param3));
  set_field("v5_collecte_tag", "ldap_liaison_faible");
end''',
'omni-v5-collecte-ds-ldap-bilan': '''rule "omni-v5-collecte-ds-ldap-bilan"
// 2887 (accepté) / 2888 (refusé) : bilan 24 h ; param1 = liaisons simples sans TLS, param2 = SASL sans signature
// 3074/3075 : bilans channel binding
when
  to_string($message.winlogbeat_winlog_channel) == "Directory Service"
  AND ( to_string($message.winlogbeat_winlog_event_id) == "2887" OR to_string($message.winlogbeat_winlog_event_id) == "2888"
     OR to_string($message.winlogbeat_winlog_event_id) == "3074" OR to_string($message.winlogbeat_winlog_event_id) == "3075" )
then
  set_field("ldap_bilan_simples_sans_tls", to_long($message.winlogbeat_winlog_event_data_param1, 0));
  set_field("ldap_bilan_sasl_sans_signature", to_long($message.winlogbeat_winlog_event_data_param2, 0));
  set_field("v5_collecte_tag", "ldap_bilan_quotidien");
end''',
# --- AppLocker (postes, AuditOnly) : déjà collecté (NETLOGON\\SIEM\\winlogbeat.yml) --
'omni-v5-collecte-applocker-normalisation': '''rule "omni-v5-collecte-applocker-normalisation"
// SIEM v5 chantier 4 : champs normalisés AppLocker (refus et « aurait été bloqué » seulement, cf. winlogbeat GPO)
when
  starts_with(to_string($message.winlogbeat_winlog_channel), "Microsoft-Windows-AppLocker", false)
then
  set_field("v5_collecte", "applocker");
  set_field("applocker_collection", to_string($message.winlogbeat_winlog_user_data_PolicyName));
  set_field("applocker_fichier", to_string($message.winlogbeat_winlog_user_data_FullFilePath));
  set_field("applocker_editeur", to_string($message.winlogbeat_winlog_user_data_Fqbn));
  set_field("applocker_utilisateur", to_string($message.winlogbeat_winlog_user_name));
  set_field("applocker_sha256", substring(to_string($message.winlogbeat_winlog_user_data_FileHash), 0, 64));
end''',
'omni-v5-collecte-applocker-audit': '''rule "omni-v5-collecte-applocker-audit"
when
  starts_with(to_string($message.winlogbeat_winlog_channel), "Microsoft-Windows-AppLocker", false)
  AND ( to_string($message.winlogbeat_winlog_event_id) == "8003" OR to_string($message.winlogbeat_winlog_event_id) == "8006"
     OR to_string($message.winlogbeat_winlog_event_id) == "8021" OR to_string($message.winlogbeat_winlog_event_id) == "8024" )
then
  set_field("applocker_resultat", "aurait_ete_bloque");
end''',
'omni-v5-collecte-applocker-bloque': '''rule "omni-v5-collecte-applocker-bloque"
when
  starts_with(to_string($message.winlogbeat_winlog_channel), "Microsoft-Windows-AppLocker", false)
  AND ( to_string($message.winlogbeat_winlog_event_id) == "8004" OR to_string($message.winlogbeat_winlog_event_id) == "8007"
     OR to_string($message.winlogbeat_winlog_event_id) == "8022" OR to_string($message.winlogbeat_winlog_event_id) == "8025" )
then
  set_field("applocker_resultat", "bloque");
end''',
'omni-v5-collecte-applocker-chemin-utilisateur': '''rule "omni-v5-collecte-applocker-chemin-utilisateur"
// emplacement inscriptible par l'utilisateur (profil, Temp, Téléchargements, ProgramData, Public)
when
  starts_with(to_string($message.winlogbeat_winlog_channel), "Microsoft-Windows-AppLocker", false)
  AND regex("(?i)(\\\\\\\\users\\\\\\\\|\\\\\\\\appdata\\\\\\\\|\\\\\\\\temp\\\\\\\\|\\\\\\\\downloads\\\\\\\\|\\\\\\\\programdata\\\\\\\\|\\\\\\\\public\\\\\\\\)", to_string($message.winlogbeat_winlog_user_data_FullFilePath)).matches == true
then
  set_field("applocker_chemin_inscriptible", true);
end''',
# --- LAPS : 4662 sur les attributs LAPS (SACL du 11/11 à la racine du domaine) --
'omni-v5-collecte-laps-lecture': '''rule "omni-v5-collecte-laps-lecture"
// SIEM v5 chantier 4 : toute 4662 DS citant un attribut LAPS (y compris comptes machine, pour mesure et tableaux)
when
  to_string($message.winlogbeat_winlog_event_id) == "4662"
  AND to_string($message.winlogbeat_winlog_event_data_ObjectServer) == "DS"
  AND regex("(?i)(%s)", to_string($message.winlogbeat_winlog_event_data_Properties)).matches == true
then
  set_field("v5_collecte", "laps");
  set_field("laps_lecteur", to_string($message.winlogbeat_winlog_event_data_SubjectUserName));
  set_field("laps_objet", to_string($message.winlogbeat_winlog_event_data_ObjectName));
  set_field("laps_lecteur_machine", ends_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "$"));
  set_field("laps_lecture_ciblee", regex("(?s)^.{1,400}$", to_string($message.winlogbeat_winlog_event_data_Properties)).matches);
end''' % GUID_LAPS,
# --- DNS des DC (GELF NXLog im_etw, entrée 12220) ---------------------------
'omni-v5-collecte-dns-normalisation': '''rule "omni-v5-collecte-dns-normalisation"
// SIEM v5 chantier 4 : requêtes DNS reçues par les DC (ETW Microsoft-Windows-DNSServer, EventID 256)
when
  has_field("QNAME")
then
  let n = regex_replace("\\\\.$", lowercase(to_string($message.QNAME)), "");
  set_field("dns_query", n);
  set_field("dns_qtype", to_string($message.QTYPE));
  set_field("src_ip", to_string($message.Source));
  set_field("dns_serveur", lowercase(to_string($message.Hostname)));
  let d = regex("([^.]+\\\\.[^.]+)$", n);
  set_field("dns_domain", to_string(d["0"]));
  set_field("event_source", "dns_dc");
  set_field("event_category", "dns");
  set_field("v5_collecte", "dns_dc");
end''',
# --- FortiGate d'Ivry en direct (entrée UDP 1521) ----------------------------
'omni-v5-collecte-fgiv-keyvalue': '''rule "omni-v5-collecte-fgiv-keyvalue"
// SIEM v5 chantier 4 : même découpage que omni-forti-00-keyvalue, stockage séparé (pas de double alerte)
when
  has_field("message") AND contains(to_string($message.message), "devname=", false)
then
  set_fields(key_value(value: to_string($message.message), delimiters: " ", kv_delimiters: "=",
    ignore_empty_values: true, allow_dup_keys: true, handle_dup_keys: "take_first", trim_value_chars: "\\""));
  set_field("event_source", "fortigate");
  set_field("v5_collecte", "fg_ivry_direct");
  set_field("collecte_voie", "syslog_direct");
end''',
}
PIPELINES = [
    dict(cle='win', title='omni-v5-collecte - Normalisation Windows', streams=[S_WINOTH, S_WINSEC],
         description='SIEM v5 chantier 4 : Directory Service, AppLocker, lectures LAPS',
         rules=['omni-v5-collecte-ds-normalisation', 'omni-v5-collecte-ds-ldap-client', 'omni-v5-collecte-ds-ldap-bilan',
                'omni-v5-collecte-applocker-normalisation', 'omni-v5-collecte-applocker-audit', 'omni-v5-collecte-applocker-bloque',
                'omni-v5-collecte-applocker-chemin-utilisateur', 'omni-v5-collecte-laps-lecture']),
    dict(cle='dns', title='omni-v5-collecte - DNS DC', streams=['@dns'],
         description='SIEM v5 chantier 4 : normalisation des requêtes DNS des DC', rules=['omni-v5-collecte-dns-normalisation']),
    dict(cle='fgiv', title='omni-v5-collecte - FortiGate Ivry direct', streams=['@fgiv'],
         description='SIEM v5 chantier 4 : IV-FW01 syslog direct', rules=['omni-v5-collecte-fgiv-keyvalue']),
    # 27/11 : pipeline « Reduction 4662 » et sa règle SUPPRIMÉES (refus jmorin, décision 3) ; export dans le dossier de sauvegarde
]
NFT = [
    ('tcp dport 12220 ip saddr { 10.33.50.250, 10.33.50.251, 10.94.50.250 } accept', 'v5-collecte GELF TCP DNS des 3 DC 27/11/2026'),
    ('udp dport 1521 ip saddr 10.94.80.254 accept', 'v5-collecte Syslog UDP IV-FW01 direct 27/11/2026'),
]

def pipe_src(p):
    return 'pipeline "%s"\nstage 0 match either\n%s\nend' % (p['title'], '\n'.join('rule "%s"' % r for r in p['rules']))

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True); return r.returncode, (r.stdout + r.stderr).strip()

def existants():
    return dict(
        idx={x['title']: x['id'] for x in api('/system/indices/index_sets?skip=0&limit=0&stats=false')['index_sets']},
        prefixes={x['index_prefix'] for x in api('/system/indices/index_sets?skip=0&limit=0&stats=false')['index_sets']},
        inp={x['title']: x['id'] for x in api('/system/inputs')['inputs']},
        ports={x['attributes'].get('port') for x in api('/system/inputs')['inputs']},
        st={x['title']: x['id'] for x in api('/streams')['streams']},
        ru={x['title']: x['id'] for x in api('/system/pipelines/rule')},
        pi={x['title']: x['id'] for x in api('/system/pipelines/pipeline')})

def simuler():
    e = existants(); ok = True
    for x in INDEX_SETS:
        c = x['title'] in e['idx'] or x['prefix'] in e['prefixes']; ok &= not c
        print('[index set] %-32s préfixe %-18s P1M %d shard(s) rétention %d %s' % (x['title'], x['prefix'], x['shards'], x['retention'], 'EXISTE DEJA' if c else 'à créer'))
    for x in INPUTS:
        c = x['title'] in e['inp'] or x['attributes']['port'] in e['ports']; ok &= not c
        print('[entrée]    %-45s %s' % (x['title'], 'PORT/NOM DÉJÀ PRIS' if c else 'à créer'))
    for x in STREAMS:
        c = x['title'] in e['st']; ok &= not c; print('[stream]    %-32s %s' % (x['title'], 'EXISTE DEJA' if c else 'à créer'))
    for t in RULES:
        c = t in e['ru']; ok &= not c; print('[règle]     %-48s %s' % (t, 'EXISTE DEJA' if c else 'à créer'))
    for p in PIPELINES:
        c = p['title'] in e['pi']; ok &= not c; print('[pipeline]  %-58s -> %s %s' % (p['title'], p['streams'] or 'NON CONNECTÉE', 'EXISTE DEJA' if c else 'à créer'))
    for r, cm in NFT: print('[nftables]  %s comment "%s"' % (r, cm))
    rc, out = sh("nft list chain inet filter input | grep -c '%s'" % NFT_TAG); print('            règles nft déjà taguées %s : %s' % (NFT_TAG, out))
    print('SIMULATION : %s' % ('OK, rien d\'écrit' if ok else 'CONFLIT DE NOM, ne pas appliquer'))
    return ok

def sauvegarder():
    d = '/var/backups/siem/v5-collecte-avant-' + time.strftime('%Y%m%d-%H%M'); os.makedirs(d, exist_ok=True)
    for nom, chemin in [('inputs', '/system/inputs'), ('streams', '/streams'), ('index_sets', '/system/indices/index_sets?skip=0&limit=0&stats=false'),
                        ('pipelines', '/system/pipelines/pipeline'), ('rules', '/system/pipelines/rule'), ('connections', '/system/pipelines/connections')]:
        json.dump(api(chemin), open('%s/%s.json' % (d, nom), 'w'), ensure_ascii=False)
    sh('cp -a /etc/nftables.conf %s/nftables.conf && nft list ruleset > %s/nft-ruleset.txt' % (d, d))
    return d

def appliquer(reprise=None):
    if reprise:   # reprise après interruption : on repart de cree.json sans recréer l'existant
        d = reprise; cree = json.load(open(d + '/cree.json'))
    else:
        if not simuler(): sys.exit(2)
        d = sauvegarder(); cree = {'dossier': d, 'index_sets': {}, 'inputs': {}, 'streams': {}, 'rules': {}, 'pipelines': {}, 'nft': []}
    def ecrire(): json.dump(cree, open(d + '/cree.json', 'w'), ensure_ascii=False, indent=1)
    # retour.sh écrit dès le début : utilisable même si l'application s'interrompt
    open(d + '/retour.sh', 'w').write('''#!/bin/bash
# Retour chantier 4 collecte : supprime par ID les seuls objets de cree.json ; « retour.sh --simuler » = à blanc
python3 /root/omni-v5-collecte/v5col_build.py --retour %s "$@"
''' % d); os.chmod(d + '/retour.sh', 0o750)
    gabarit = api('/system/indices/index_sets/6a3a7b994b1256e1c657b0e1')   # OMNI - Aruba (P1M) comme modèle
    for x in [i for i in INDEX_SETS if i['cle'] not in cree['index_sets']]:
        b = {k: v for k, v in gabarit.items() if k not in ('id', 'creation_date', 'default', 'can_be_default', 'index_template_type')}
        b.update(title=x['title'], description=x['description'], index_prefix=x['prefix'], shards=x['shards'], replicas=0, writable=True,
                 creation_date=time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime()))
        b['retention_strategy'] = dict(gabarit['retention_strategy'], max_number_of_indices=x['retention'])
        r = api('/system/indices/index_sets', 'POST', b); cree['index_sets'][x['cle']] = r['id']; ecrire(); print('index set', x['title'], r['id'])
    for x in [i for i in INPUTS if i['cle'] not in cree['inputs']]:
        r = api('/system/inputs', 'POST', {'title': x['title'], 'type': x['type'], 'global': True, 'configuration': x['attributes']})
        cree['inputs'][x['cle']] = r['id']; ecrire(); print('entrée', x['title'], r['id'])
    for x in [s for s in STREAMS if s['cle'] not in cree['streams']]:
        # Graylog 7.2 : CreateEntityRequest {"entity": …}
        r = api('/streams', 'POST', {'entity': {'title': x['title'], 'description': x['description'], 'matching_type': 'AND',
                                     'remove_matches_from_default_stream': True, 'index_set_id': cree['index_sets'][x['cle']],
                                     'rules': [{'field': 'gl2_source_input', 'type': 1, 'value': cree['inputs'][x['cle']], 'inverted': False,
                                                'description': 'entrée ' + x['cle']}]}})
        sid = r['stream_id']; cree['streams'][x['cle']] = sid; ecrire(); api('/streams/%s/resume' % sid, 'POST'); print('stream', x['title'], sid)
    for t, s in [(t, s) for t, s in RULES.items() if t not in cree['rules']]:
        r = api('/system/pipelines/rule', 'POST', {'title': t, 'description': 'SIEM v5 chantier 4', 'source': s})
        cree['rules'][t] = r['id']; ecrire(); print('règle', t, r['id'])
    for p in [p for p in PIPELINES if p['cle'] not in cree['pipelines']]:
        r = api('/system/pipelines/pipeline', 'POST', {'title': p['title'], 'description': p['description'], 'source': pipe_src(p)})
        cree['pipelines'][p['cle']] = r['id']; ecrire(); print('pipeline', p['title'], r['id'])
        sids = [cree['streams'][s[1:]] if s.startswith('@') else s for s in p['streams']]
        if sids: api('/system/pipelines/connections/to_pipeline', 'POST', {'pipeline_id': r['id'], 'stream_ids': sids}); print('   connectée à', sids)
    # nftables : à l'exécution (avant le compteur de rejets) puis dans /etc/nftables.conf
    rc, h = sh("nft -a list chain inet filter input | grep 'drops entrants' | sed -E 's/.*# handle ([0-9]+).*/\\1/'")
    for regle, cm in [(r_, c_) for r_, c_ in NFT if c_ not in cree['nft']]:
        rc, out = sh("nft insert rule inet filter input position %s %s comment '\"%s\"'" % (h, regle, cm)); print('nft', rc, out or 'OK', regle)
        cree['nft'].append(cm); ecrire()
    lignes = open('/etc/nftables.conf').read().split('\n'); neuf = []
    deja = any(NFT_TAG in l for l in lignes)
    for l in lignes:
        if 'counter comment "drops entrants"' in l and not deja:
            neuf.append('        # SIEM v5 chantier 4 collecte (27/11/2026) - retour : retour.sh du dossier %s' % d)
            for regle, cm in NFT: neuf.append('        %s comment "%s"' % (regle, cm))
        neuf.append(l)
    open('/tmp/v5col-nftables.conf', 'w').write('\n'.join(neuf))
    rc, out = sh('nft -c -f /tmp/v5col-nftables.conf')
    if rc == 0: sh('cp /tmp/v5col-nftables.conf /etc/nftables.conf'); print('nftables.conf persistant OK (nft -c)')
    else: print('nftables.conf NON modifié (nft -c en échec) :', out)
    print('SAUVEGARDE + RETOUR :', d)

def retour(d, blanc):
    c = json.load(open(d + '/cree.json')); act = (lambda *a: None) if blanc else api
    pre = '[à blanc] ' if blanc else ''
    for k, pid in c['pipelines'].items():
        print(pre + 'déconnexion + suppression pipeline', pid)
        if not blanc:
            try: api('/system/pipelines/connections/to_pipeline', 'POST', {'pipeline_id': pid, 'stream_ids': []})
            except Exception as e: print('  déconnexion :', e)
            try: api('/system/pipelines/pipeline/' + pid, 'DELETE')
            except Exception as e: print('  suppression :', e)
    for t, rid in c['rules'].items():
        print(pre + 'suppression règle', t, rid)
        if not blanc:
            try: api('/system/pipelines/rule/' + rid, 'DELETE')
            except Exception as e: print('  ', e)
    for k, sid in c['streams'].items():
        print(pre + 'suppression stream', sid)
        if not blanc:
            try: api('/streams/' + sid, 'DELETE')
            except Exception as e: print('  ', e)
    for k, iid in c['inputs'].items():
        print(pre + 'suppression entrée', iid)
        if not blanc:
            try: api('/system/inputs/' + iid, 'DELETE')
            except Exception as e: print('  ', e)
    for k, xid in c['index_sets'].items():
        print(pre + 'suppression index set (et ses index)', xid)
        if not blanc:
            try: api('/system/indices/index_sets/%s?delete_indices=true' % xid, 'DELETE')
            except Exception as e: print('  ', e)
    rc, out = sh("nft -a list chain inet filter input | grep '%s' | sed -E 's/.*# handle ([0-9]+).*/\\1/'" % NFT_TAG)
    for h in [x for x in out.split() if x.isdigit()]:
        print(pre + 'nft delete rule inet filter input handle', h)
        if not blanc: sh('nft delete rule inet filter input handle ' + h)
    print(pre + "retrait des lignes '%s' de /etc/nftables.conf (contrôle nft -c)" % NFT_TAG)
    if not blanc:
        l = [x for x in open('/etc/nftables.conf').read().split('\n') if NFT_TAG not in x and 'SIEM v5 chantier 4 collecte' not in x]
        open('/tmp/v5col-nft-retour.conf', 'w').write('\n'.join(l))
        rc, out = sh('nft -c -f /tmp/v5col-nft-retour.conf')
        if rc == 0: sh('cp /tmp/v5col-nft-retour.conf /etc/nftables.conf'); print('  OK')
        else: print('  ÉCHEC nft -c, fichier laissé :', out)

def maj_regles(d):
    # met à jour par ID (PUT) les seules règles de cree.json dont la source a changé
    c = json.load(open(d + '/cree.json'))
    for t, rid in c['rules'].items():
        cur = api('/system/pipelines/rule/' + rid)
        if cur['source'].strip() != RULES[t].strip():
            api('/system/pipelines/rule/' + rid, 'PUT', {'title': t, 'description': cur.get('description') or 'SIEM v5 chantier 4', 'source': RULES[t]}); print('règle mise à jour', t, rid)

def tester():
    c = json.load(open(sorted([os.path.join('/var/backups/siem', x) for x in os.listdir('/var/backups/siem') if x.startswith('v5-collecte-avant-')])[-1] + '/cree.json'))
    cas = [
     ('DS 2889', S_WINOTH, {'winlogbeat_winlog_channel': 'Directory Service', 'winlogbeat_winlog_event_id': '2889', 'source': 'BX-AD-01-IT-VM',
        'winlogbeat_winlog_event_data_param1': '10.33.10.5:51234', 'winlogbeat_winlog_event_data_param2': 'SECURITY\\svc-test', 'winlogbeat_winlog_event_data_param3': '0'},
        {'v5_collecte': 'directory_service', 'ldap_client_ip': '10.33.10.5', 'ldap_client_port': '51234', 'ldap_identite': 'SECURITY\\svc-test', 'v5_collecte_tag': 'ldap_liaison_faible'}),
     ('DS 2887', S_WINOTH, {'winlogbeat_winlog_channel': 'Directory Service', 'winlogbeat_winlog_event_id': '2887', 'winlogbeat_winlog_event_data_param1': '12', 'winlogbeat_winlog_event_data_param2': '3'},
        {'ldap_bilan_simples_sans_tls': 12, 'ldap_bilan_sasl_sans_signature': 3, 'v5_collecte_tag': 'ldap_bilan_quotidien'}),
     ('AppLocker 8003', S_WINOTH, {'winlogbeat_winlog_channel': 'Microsoft-Windows-AppLocker/EXE and DLL', 'winlogbeat_winlog_event_id': '8003',
        'winlogbeat_winlog_user_data_PolicyName': 'EXE', 'winlogbeat_winlog_user_data_FullFilePath': 'C:\\Users\\test\\AppData\\Local\\Temp\\x.exe',
        'winlogbeat_winlog_user_data_FileHash': '57679C16A36D85D947C7A8BBFB62E2FF04EBC8ED2B42C0F29AB4F9E2205DA4504F003D00560041', 'winlogbeat_winlog_user_name': 'test', 'winlogbeat_winlog_user_data_Fqbn': '-'},
        {'applocker_resultat': 'aurait_ete_bloque', 'applocker_collection': 'EXE', 'applocker_chemin_inscriptible': True, 'applocker_sha256': '57679C16A36D85D947C7A8BBFB62E2FF04EBC8ED2B42C0F29AB4F9E2205DA450'}),
     ('AppLocker 8007', S_WINOTH, {'winlogbeat_winlog_channel': 'Microsoft-Windows-AppLocker/MSI and Script', 'winlogbeat_winlog_event_id': '8007',
        'winlogbeat_winlog_user_data_PolicyName': 'SCRIPT', 'winlogbeat_winlog_user_data_FullFilePath': 'C:\\Program Files\\x\\a.ps1', 'winlogbeat_winlog_user_data_FileHash': 'AB'},
        {'applocker_resultat': 'bloque', 'applocker_chemin_inscriptible': None}),
     ('4662 LAPS ciblé', S_WINSEC, {'winlogbeat_winlog_event_id': '4662', 'event_id': '4662', 'winlogbeat_winlog_event_data_ObjectServer': 'DS',
        'winlogbeat_winlog_event_data_SubjectUserName': 'bx-qa-seal-vm-test', 'winlogbeat_winlog_event_data_ObjectName': '%{11111111-2222-3333-4444-555555555555}',
        'winlogbeat_winlog_event_data_Properties': '%%7684\n\t\t{fb67b5bd-ef3d-4d01-ba85-0ab2f0ed97dd}\n\t{bf967a86-0de6-11d0-a285-00aa003049e2}', 'event_source': 'windows_security'},
        {'v5_collecte': 'laps', 'laps_lecteur_machine': False, 'laps_lecture_ciblee': True}),
     ('4662 hors LAPS', S_WINSEC, {'winlogbeat_winlog_event_id': '4662', 'event_id': '4662', 'winlogbeat_winlog_event_data_ObjectServer': 'DS',
        'winlogbeat_winlog_event_data_SubjectUserName': 'BX-AD-01-IT-VM$', 'winlogbeat_winlog_event_data_Properties': '%%7684 {e48d0154-bcf8-11d1-8702-00c04fb96050}', 'event_source': 'windows_security'},
        {'v5_collecte': None}),
     ('DNS DC', '@dns', {'QNAME': 'WWW.Example.COM.', 'QTYPE': '1', 'Source': '10.33.10.5', 'Hostname': 'BX-AD-01-IT-VM.omnitech.security', 'EventID': '256'},
        {'dns_query': 'www.example.com', 'dns_domain': 'example.com', 'src_ip': '10.33.10.5', 'event_source': 'dns_dc'}),
     ('FG Ivry direct', '@fgiv', {'message': 'date=2026-11-27 time=07:00:00 devname="IV-FW01-IT-RT" devid="FGT60FTK2109B4CE" type="event" subtype="system" logdesc="Admin login failed" user="bx-qa-seal-vm"'},
        {'devname': 'IV-FW01-IT-RT', 'logdesc': 'Admin login failed', 'collecte_voie': 'syslog_direct'}),
    ]
    ok = 0
    for nom, sid, msg, attendu in cas:
        if sid.startswith('@'): sid = c['streams'][sid[1:]]
        m = dict(msg); m.setdefault('message', 'test v5 collecte bx-qa-seal-vm'); m['_id'] = 'v5col-test-' + nom.replace(' ', '-'); m.setdefault('source', 'bx-qa-seal-vm')
        m['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S.000', time.gmtime())
        r = api('/system/pipelines/simulate', 'POST', {'stream_id': sid, 'message': m, 'input_id': ''})
        out = (r.get('messages') or [{}])[0].get('message', {}) if r.get('messages') else {}
        bon = all((out.get(k) == v) if v is not None else (k not in out) for k, v in attendu.items())
        ok += bon; print('%-4s %-18s %s' % ('OK' if bon else 'KO', nom, {k: out.get(k) for k in attendu}))
    print('%d/%d cas conformes' % (ok, len(cas)))

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a or a[0] == '--simuler': simuler()
    elif a[0] == '--appliquer': appliquer()
    elif a[0] == '--reprendre': appliquer(a[1])
    elif a[0] == '--retour': retour(a[1], '--simuler' in a)
    elif a[0] == '--tester': tester()
    elif a[0] == '--maj-regles': maj_regles(a[1])
