# Production de preuves ISO/IEC 27001:2022 — SIEM Graylog OMNITECH

Système : bx-it-graylog-vm (Debian 13, Graylog 7.1.3, OpenSearch local 127.0.0.1:9200).
Périmètre : volet journalisation / surveillance / preuves du SMSI (mesures A.8.15, A.8.16, A.8.17, A.5.25, A.5.26, A.5.28, A.8.13, A.5.37).

**Objet.** Ce document est le mode opératoire de production des preuves en séance d'audit : pour chaque mesure, l'exigence en une phrase, la ou les preuves disponibles aujourd'hui avec la commande exacte qui les produit sur CE serveur, puis le manque résiduel et l'action minimale. Il complète `docs/ISO27001-MAPPING.md`, qui établit la correspondance contrôle ↔ capacité du SIEM ↔ emplacement de la preuve : le mapping dit *quoi*, le présent document dit *comment le démontrer*. Il ne duplique pas le mapping ; s'y référer pour la couverture des autres contrôles (A.5.7, A.8.7, A.8.8, A.8.12, etc.).

Dernière vérification de l'ensemble des commandes sur ce serveur : 02/07/2026.

Préalable pour toutes les commandes `api_get` (ordre impératif, sinon la variable API est vide) :

```bash
cd /root/omnitech-siem-setup && source ./00-vars.env && source ./lib-graylog.sh
```

Documents de référence associés : `docs/ISO27001-MAPPING.md`, `docs/REGISTRE-CONFORMITE-ISO27001.md`, dossier de preuves mensuel généré par `68-iso-evidence.sh` (dernier : `docs/EVIDENCE-AUDIT-2026-07-01.md`).

---

## A.8.15 — Journalisation

**Exigence.** Produire, protéger et conserver des journaux des activités, exceptions, fautes et événements pertinents, avec une rétention définie.

### Preuves disponibles

1. Collecte active — 14 entrées en fonctionnement :

```bash
api_get '/system/inputstates' | jq -r '.states[] | [.message_input.title, .state] | @tsv'
```

Attendu : 14 lignes, toutes `RUNNING` (Beats TLS 5044, FortiAnalyzer 1514, ESET 1515, vSphere 1516, FortiManager 1517, FortiClient EMS TLS 1518, Linux 1519, Aruba 1520, GELF HTTP/UDP 12201). Les transports chiffrés (Beats TLS, Syslog TLS 1518) sont visibles dans les titres.

2. Fraîcheur et volumétrie par source (périmètre réel de collecte) :

```bash
curl -s 'http://127.0.0.1:9200/omni-*,graylog_*/_search' -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"src":{"terms":{"field":"event_source","size":50},"aggs":{"last":{"max":{"field":"timestamp"}}}}}}' \
  | jq -r '.aggregations.src.buckets[] | [.key, .doc_count, .last.value_as_string] | @tsv'
```

Attendu : ~40 valeurs `event_source`, les familles principales avec un dernier événement de moins de 35 minutes (constaté le 02/07 : fortigate 56,4 M, windows_security 21,8 M, sysmon 21,7 M, windows 6,4 M, vsphere 3,9 M, bunkerweb, m365, vaultwarden..., toutes fraîches à moins de 30 min).

3. Rétentions calibrées par index set (politique : `docs/POLITIQUE-RETENTION.md`) :

```bash
api_get '/system/indices/index_sets?skip=0&limit=0' | jq -r \
  '.index_sets[] | [.title, .rotation_strategy.rotation_period // "-", .retention_strategy.max_number_of_indices] | @tsv'
```

Attendu : rotation P1D partout ; Windows Security / vSphere / ESET = 180 j, Microsoft 365 = 365 j, autres sources = 90 j (provisionné par `41-retention-iso.sh`). Écarts connus : Cert Orchestrator à 12 j (voir manques).

4. Protection réseau de la collecte — filtrage par IP source émettrice :

```bash
nft list ruleset | grep -c saddr        # attendu : 25 règles filtrées par IP source
nft list ruleset | grep 5044            # exemple : Winlogbeat restreint à 10.33.0.0/16
```

5. Référentiels : `docs/STD-JOURNALISATION.md`, `docs/POLITIQUE-RETENTION.md`, `docs/INVENTAIRE-SOURCES.md`.

### Manques et action minimale

- Canal Cert Orchestrator mort : la règle nftables `udp dport 12201` déclarée à `06-firewall.sh:67` est absente du ruleset live (`nft list ruleset | grep 12201` vide) et `curl -s http://127.0.0.1:9200/omni-cert*/_count` = 0. Action : rejouer `06-firewall.sh` puis vérifier l'arrivée de documents dans `omni-cert_0`. Attention : les événements `event_source=cert_parc` présents viennent d'une autre source (BX-PKI2022 via Winlogbeat, règle `omni-winother-10-cert-parc` de `12-graylog-pipelines.sh`), ce qui maintient le watchdog au vert et masque le silence de l'orchestrateur.
- Rétentions incohérentes : Cert Orchestrator 12 j (à porter à 90 j minimum) ; ~70 000 événements `forti_dhcp` stockés dans les index `omni-m365_*` (365 j) faute de stream dédié ; authentification Linux/Aruba à 90 j contre 180 j pour Windows Security. Action : arbitrage RSSI documenté dans `docs/POLITIQUE-RETENTION.md`.
- Sources déclarées mais à zéro événement (NPS, Entra, NinjaOne) : activer ou documenter l'exclusion temporaire dans `docs/INVENTAIRE-SOURCES.md`.

---

## A.8.16 — Activités de surveillance

**Exigence.** Surveiller les réseaux, systèmes et applications pour détecter les comportements anormaux et évaluer les incidents potentiels.

### Preuves disponibles

1. Contenu de détection en place :

```bash
api_get '/events/definitions?per_page=500' | jq '.total'   # attendu : 142 définitions
api_get '/system/pipelines/pipeline' | jq 'length'         # attendu : 37 pipelines
api_get '/system/pipelines/rule' | jq 'length'             # attendu : 234 règles
api_get '/streams' | jq '.total'                           # attendu : 18 streams
```

2. Couverture MITRE ATT&CK : `docs/COUVERTURE-MITRE-ATTACK.md` et `docs/mitre-navigator-layer.json` (backlog priorisé : `DETECTION-BACKLOG.md`, registre : `docs/REGISTRE-DETECTIONS.md`).

3. Canaux de notification (5) :

```bash
api_get '/events/notifications' | jq -r '.notifications[] | [.title, .config.type] | @tsv'
```

Attendu : `OMNI - Mail equipe IT` (email), `OMNI - Mobile push`, `OMNI - SOAR auto-block`, `OMNI - Teams SOC`, `OMNI - Triage (mail critique)`.

4. Alertes effectivement générées (chaîne de détection vivante) :

```bash
curl -s 'http://127.0.0.1:9200/gl-events*/_count' -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' | jq .count
```

Attendu : > 0 (constaté le 02/07 : 16 647 événements d'alerte sur 24 h, avant triage).

5. Supervision à trois étages, chacune avec son journal :

```bash
journalctl -u omni-source-watchdog.service --since "1 hour ago" --no-pager | grep watchdog | tail -2
# attendu : "watchdog: 18 source(s) surveillee(s), 0 silencieuse(s)" toutes les 15 min
journalctl -u omni-self-health.service --since "1 hour ago" --no-pager | grep self-health | tail -2
# attendu : "[self-health] N/18 robots OK" toutes les 30 min
journalctl -u omni-collect-health.service --since "2 hours ago" --no-pager | tail -2
# attendu : exécution horaire (couverture SLA + go-dark)
```

6. Dossier de preuves mensuel automatisé :

```bash
systemctl list-timers --all --no-pager | grep iso   # omni-iso-evidence.timer, mensuel
ls -la /root/omnitech-siem-setup/docs/EVIDENCE-AUDIT-2026-07-01.md
```

7. Dashboards à capturer avant audit (console web) : « OMNI - SOC », « Santé collecte », « Incidents », « ATT&CK » — exports PNG à joindre au dossier de preuves du mois.

### Manques et action minimale

- Deux robots en échec depuis le wipe du 28/06 (`systemctl list-units --failed` : `omni-ueba-score`, `omni-monthly-report`, HTTP 400). Causes identifiées : conflit de mapping `src_ip` (keyword dans `omni-interne_0..4` contre ip ailleurs) pour l'UEBA ; tri sur `incident_score`/`ueba_score` absent du mapping de `graylog_0` recréé, pour le rapport. Action : corriger les requêtes (`40-ueba-ndr.sh`, `45-monthly-report.sh`), régénérer le rapport de juin.
- Fausse panne chronique : `omni-self-health` signale `omni-incident-correlate` en panne alors que sa désactivation est volontaire (`44-incidents.sh`, remplacé par `oms-xdr`). Action : retirer l'entrée de la liste JOBS (`61-supervision-robots.sh`) sans réactiver le timer.
- Angle mort : `omni-monthly-report` n'est pas dans la liste des robots surveillés par `omni-self-health` ; son échec n'est signalé nulle part. Action : l'ajouter à la liste JOBS.

---

## A.8.17 — Synchronisation des horloges

**Exigence.** Synchroniser les horloges des systèmes de traitement de l'information sur une source de temps de référence unique.

### Preuves disponibles

```bash
timedatectl show -p NTPSynchronized -p Timezone
# constaté 02/07 : Timezone=Europe/Paris, NTPSynchronized=yes
chronyc tracking
# constaté 02/07 : Reference ID = BX-AD-01-IT-VM.omnitech.security (DC interne),
#                  Stratum 3, RMS offset 0.00122 s (~1,2 ms), Leap status Normal
chronyc sources
# constaté 02/07 : 2 sources internes — BX-AD-01-IT-VM (stratum 2, sélectionnée "^*")
#                  et BX-AD02-IT-VM (stratum 3, candidate "^-"), Reach 377 pour les deux
```

Provisionnement tracé : `01-base.sh` configure chrony vers le DC interne avec mention explicite de la mesure A.8.17 (lignes 46-48). La cohérence côté émetteurs se constate indirectement par la fraîcheur homogène des sources (requête de fraîcheur du A.8.15) : des horloges divergentes produiraient des timestamps aberrants visibles dans cette agrégation.

### Manques et action minimale

- La preuve côté émetteurs (FortiGate, Windows, ESXi alignés sur la même référence) n'est pas formalisée : `68-iso-evidence.sh` ne contient aucune section horodatage. Action : ajouter la sortie `chronyc tracking` et un contrôle de dérive des timestamps par source au dossier de preuves mensuel.

---

## A.5.25 — Évaluation des événements de sécurité

**Exigence.** Évaluer les événements de sécurité et décider s'ils doivent être catégorisés en incidents.

### Preuves disponibles

1. Procédure : `docs/PROCEDURE-INCIDENT.md` (rôles RSSI/analyste, couvre A.5.24 à A.5.28).

2. Triage automatisé à trois niveaux (CRITICAL/GRAY/NOISE) en production, service `omni-alert-triage` (127.0.0.1:8089) :

```bash
systemctl is-active omni-alert-triage      # attendu : active
curl -s http://127.0.0.1:8089/stats
# attendu : compteurs cumulés, ex. le 02/07 : {"mail": 373, "drop": 3114, "mail_echec": 8, "dedup": 298}
```

3. Décisions de triage tracées et indexées (revue possible a posteriori) :

```bash
curl -s 'http://127.0.0.1:9200/omni-*/_search' -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"bool":{"filter":[{"term":{"event_source":"alert_triage"}},{"range":{"timestamp":{"gte":"now-24h"}}}]}},"aggs":{"v":{"terms":{"field":"triage_decision","size":5}}}}' \
  | jq -c '.aggregations.v.buckets'
```

Attendu : répartition drop/mail/dedup sur 24 h (constaté le 02/07 : drop 639, mail 126, dedup 116). Champs disponibles par document : `triage_decision`, `triage_tier`, `triage_score`, `triage_reason`, `alert_title`.

4. Boucle analyste (marquage faux positif) : outil `tools/omni-fp` (déployé en `/usr/local/sbin/omni-fp`) et endpoint de consultation :

```bash
curl -s 'http://127.0.0.1:8089/fp?entity=<entite>'   # attendu : liste JSON (vide si aucune règle FP)
```

5. Hygiène anti-tempête documentée et provisionnée : `21-alert-hygiene.sh`.

### Manques et action minimale

- `docs/PROCEDURE-INCIDENT.md` porte le statut « à valider/approuver par le RSSI » : apposer approbateur, date et version (idem sur `POL-SUPERVISION-JOURNALISATION.md`, `STD-JOURNALISATION.md`, `PRO-EXPLOITATION-SIEM.md` et `docs/ISO27001-MAPPING.md`).
- Preuve de revue périodique cassée : `/var/www/siem-kit/rapports/` ne contient que `rapport-2026-05.{html,pdf}` ; le rapport de juin a échoué le 01/07 (voir A.8.16). Action : corriger puis régénérer.

---

## A.5.26 — Réponse aux incidents de sécurité

**Exigence.** Répondre aux incidents de sécurité conformément aux procédures documentées.

### Preuves disponibles

1. SOAR actif (blocage d'IP attaquantes via webhook Graylog) :

```bash
systemctl is-active omni-soar              # attendu : active
cat /var/lib/omni-soar/blocklist.json      # attendu : IP bloquées avec timestamp d'expiration
```

La notification `OMNI - SOAR auto-block` figure dans la liste des notifications (voir A.8.16). Expiration automatique : `omni-soar-expire.timer` (30 min). Le contenu daté de la blocklist constitue le journal des réponses automatiques en cours.

2. Moteur de corrélation/réponse XDR, cycle de 5 minutes :

```bash
systemctl is-active oms-xdr.timer          # attendu : active
journalctl -u oms-xdr.service --no-pager | tail -3   # attendu : "Cycle termine : ..."
curl -s 'http://127.0.0.1:9200/omni-*/_count' -H 'Content-Type: application/json' \
  --data-binary '{"query":{"bool":{"filter":[{"term":{"event_source":"xdr_incident"}}]}}}' | jq .count
# attendu : > 0 (constaté le 02/07 : 53 incidents corrélés depuis le 28/06)
```

3. Playbooks documentés : `docs/SOAR-PLAYBOOKS.md`, `docs/REPONSE-AUTOMATISEE.md`, `docs/PROCEDURE-INCIDENT.md`.

### Manques et action minimale

- `oms-xdr` fonctionne en dry-run (libellé de l'unité systemd : « cycle de correlation/reponse (dry-run) ») et la réponse AD n'est pas armée (`README` l.210). Acceptable en PME, mais l'écart doc/réalité doit devenir une décision RSSI datée, versionnée dans `docs/REPONSE-AUTOMATISEE.md`.

---

## A.5.28 — Recueil de preuves

**Exigence.** Établir des procédures d'identification, de recueil et de préservation des preuves liées aux événements de sécurité.

### Preuves disponibles

1. Registre d'intégrité haché en chaîne (HMAC-SHA256, clé root-only), vérification à la demande :

```bash
omni-integrity --verify
# attendu : "[integrity] chaine OK (N maillons)" avec code retour 0 (constaté 02/07 : 21 maillons)
ls -la /var/lib/omni-integrity/chain.jsonl   # attendu : fichier root, mode 600
```

2. Automatisation : maillon quotidien 03:30 (`omni-integrity.timer`) et re-vérification complète hebdomadaire lundi 04:00 (`omni-integrity-verify.timer`) :

```bash
systemctl list-timers --all --no-pager | grep integrity
```

3. Attestations indexées dans le SIEM :

```bash
curl -s 'http://127.0.0.1:9200/omni-*/_count' -H 'Content-Type: application/json' \
  --data-binary '{"query":{"term":{"event_source":"siem_integrity"}}}' | jq .count   # attendu : > 0
```

4. Copie hors-SIEM du registre sur partage SMB (protection contre réécriture par un insider) : provisionnée par `60-integrity.sh` (étape « Timer quotidien + copie hors-SIEM (SMB) »).

5. Procédure de chaîne de possession : `docs/PROCEDURE-INTEGRITE-PREUVE.md`. Dossier de preuves mensuel daté : `docs/EVIDENCE-AUDIT-2026-07-01.md`.

### Manques et action minimale

- Le dossier de preuves mensuel n'est pas suivi par git (`git status --porcelain docs/` le liste en non suivi) : le commiter à chaque génération.
- La valeur probante des journaux bruts est affaiblie par la rétention Cert à 12 j et l'absence de snapshots OpenSearch (voir A.8.13) : traiter ces deux points en priorité.

---

## A.8.13 — Sauvegarde des informations

**Exigence.** Réaliser et tester régulièrement des copies de sauvegarde des informations, des logiciels et des systèmes.

### Preuves disponibles

1. Sauvegarde configuration quotidienne 03:15, chiffrée AES-256, exportée hors machine, avec vérification de restaurabilité à chaque exécution :

```bash
ls -lh /var/backups/siem/omni-siem-config_$(date +%F).tar.gz.enc   # attendu : archive du jour (~296 Mo)
journalctl -u omni-backup-config.service --since today --no-pager | grep -E 'restaurabilite|OK :'
# attendu : "restaurabilite verifiee : N entrees" puis
#           "OK : ... -> //10.33.50.5/Public/SIEM (14 copies, retention 14 j)"
```

Périmètre de l'archive (`30-backup-config.sh`) : working tree complet du dépôt (fichiers non commités inclus), `/usr/local/sbin`, dump Mongo — donc configuration Graylog restaurable. Alerte GELF intégrée en cas d'échec ou d'absence > 26 h.

2. Dump MongoDB quotidien 02:30 :

```bash
ls -lh /home/siem-backup/mongo/graylog-mongo-$(date +%Y%m%d)-*.archive.gz   # attendu : dump du jour
```

Constaté le 02/07 : `graylog-mongo-20260702-0230.archive.gz` daté du jour même (02:30). Restauration Mongo éprouvée en réel le 26/06 (incident WiredTiger, voir `RESTORE.md`). Trou connu : aucun dump le 26/06 (jour du crash), échec resté silencieux.

3. Filets complémentaires : sauvegarde VM Veeam, header LUKS sauvegardé, procédures `RESTORE.md` et `docs/PRA-RECONSTRUCTION-SIEM.md`.

### Manques et action minimale (point critique)

- Snapshots OpenSearch KO depuis le 15/06 : `curl -s http://127.0.0.1:9200/_snapshot/graylog_fs` renvoie `repository_missing_exception` (dépôt désenregistré lors du redémarrage OpenSearch du 14/06 ; `path.repo` intact dans `/etc/opensearch/opensearch.yml`). Les 84 indices de logs n'ont aucune sauvegarde applicative ; seule la VM Veeam couvre. Action immédiate : rejouer l'enregistrement du dépôt (étape 1/3 de `08-backup.sh`), lancer un snapshot manuel, vérifier `_snapshot/graylog_fs/_all`.
- Échec avalé silencieusement : `siem-backup.sh` masque les erreurs (`curl -s ... >/dev/null`), seule trace « jq: Cannot iterate over null » dans `/var/log/siem-backup.log` à chaque exécution depuis le 15/06. Action : contrôle du code retour HTTP + alerte GELF sur les trois étapes, sur le modèle de `30-backup-config.sh`.
- Dumps Mongo et snapshots stockés sur l'hôte SIEM lui-même : implémenter le rsync vers NAS prévu par `08-backup.sh` (l.10-11) et jamais réalisé.
- Exercice de restauration complet (VM vierge -> scripts -> restore) jamais joué de bout en bout : à planifier avant le Stage 2 avec compte rendu daté.

---

## A.5.37 — Procédures d'exploitation documentées

**Exigence.** Documenter les procédures d'exploitation des moyens de traitement de l'information et les rendre disponibles au personnel concerné.

### Preuves disponibles

1. Corpus documentaire indexé :

```bash
ls /root/omnitech-siem-setup/docs/ | wc -l    # attendu : ~40 documents (index : docs/00-INDEX.md)
```

Pièces maîtresses : `docs/DOSSIER-ARCHITECTURE-SIEM.md`, `docs/PRA-RECONSTRUCTION-SIEM.md`, `RESTORE.md`, `docs/GUIDE-DEPANNAGE.md`, `docs/PRO-EXPLOITATION-SIEM.md`, `docs/POL-SUPERVISION-JOURNALISATION.md`.

2. Provisionnement reproductible : une centaine de scripts bash idempotents numérotés à la racine du dépôt, source de vérité de la configuration (aucun binaire ni unité systemd orphelin).

3. Sauvegarde quotidienne du référentiel complet, y compris travaux non commités (voir A.8.13, `30-backup-config.sh`).

### Manques et action minimale

- Dérive du référentiel versionné : `git -C /root/omnitech-siem-setup status --porcelain` montre une trentaine de fichiers modifiés, 3 suppressions indexées et des fichiers non suivis (dont `99-cert-orchestrator.sh`, `97-multisite-soar.sh`, `38-alert-triage.sh`, `triage/omni-alert-triage`) ; dernier commit du 23/06, identique au remote. La sauvegarde chiffrée limite le risque de perte à 24 h, mais pour un auditeur le référentiel versionné ne reflète pas la production. Action : commit + push de l'état courant, puis contrôle périodique de dérive.
- Absence d'approbation formelle (nom, date, version) sur les procédures : voir A.5.25.
- Ordre d'installation documenté seulement jusqu'au script 14 : compléter le séquencement dans `docs/00-INDEX.md` ou `RESTORE.md`.

---

## Checklist de validation opérationnelle du SIEM

Vérification complète en une dizaine de minutes. Chaque commande a été testée sur ce serveur le 02/07/2026 ; le résultat attendu est indiqué. Préalable pour `api_get` : sourcer `00-vars.env` puis `lib-graylog.sh` (voir en-tête).

| # | Point de contrôle | Commande | Attendu |
|---|---|---|---|
| 1 | Services de base | `systemctl is-active graylog-server mongod opensearch nginx nftables fail2ban` | 6 x `active` |
| 2 | Aucune unité omni-*/oms-* en échec | `systemctl list-units 'omni-*' 'oms-*' --failed --no-legend --plain` | vide (au 02/07 : `omni-ueba-score` et `omni-monthly-report` en échec, correctif en cours) |
| 3 | Entrées de collecte | `api_get '/system/inputstates' \| jq -r '.states[].state' \| sort \| uniq -c` | `14 RUNNING` |
| 4 | Fraîcheur par source | requête d'agrégation `event_source` du A.8.15 (point 2) | dernier événement < 35 min pour chaque famille active |
| 5 | Supervision interne (sources + robots) | `journalctl -u omni-source-watchdog.service --since "1 hour ago" --no-pager \| grep watchdog \| tail -2` puis `journalctl -u omni-self-health.service --since "1 hour ago" --no-pager \| grep self-health \| tail -2` | `0 silencieuse(s)` ; `18/18 robots OK` (au 02/07 : 16/18, voir A.8.16) |
| 6 | Chaîne d'alerte vivante | `curl -s 'http://127.0.0.1:9200/gl-events*/_count' -H 'Content-Type: application/json' -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' \| jq .count` | > 0 (au 02/07 : 16 647) |
| 7 | Triage mail actif | `curl -s http://127.0.0.1:8089/stats` | JSON avec compteurs `mail`/`drop`/`dedup` qui progressent d'un jour à l'autre |
| 8 | Verdicts de triage du jour | requête d'agrégation `triage_decision` du A.5.25 (point 3) | buckets drop/mail/dedup non vides |
| 9 | Lookups threat-intel peuplés | `api_get '/system/lookup/tables/tor-exit-node-list/query?key=185.220.101.1' \| jq -r .single_value` et `wc -l /etc/graylog/lookup/ti-mal-domain.csv` | valeur non nulle pour une IP de sortie Tor connue ; > 2 000 lignes de domaines |
| 10 | Sauvegarde config du jour | `ls -lh /var/backups/siem/omni-siem-config_$(date +%F).tar.gz.enc` | archive du jour ~296 Mo, doublée du message `restaurabilite verifiee` dans le journal |
| 11 | Dump Mongo du jour | `ls -lh /home/siem-backup/mongo/graylog-mongo-$(date +%Y%m%d)-*.archive.gz` | dump daté du jour (au 02/07 : présent, 02:30) |
| 12 | Snapshots d'indices | `curl -s http://127.0.0.1:9200/_snapshot/graylog_fs/_all` | liste de snapshots récents (au 02/07 : `repository_missing_exception`, remédiation P0 en cours, voir A.8.13) |
| 13 | Intégrité des preuves | `omni-integrity --verify` | `chaine OK (N maillons)`, code retour 0 |
| 14 | Horloge | `chronyc tracking \| head -8` et `timedatectl show -p NTPSynchronized` | référence DC interne, RMS offset < 10 ms, `NTPSynchronized=yes` |
| 15 | Espace disque | `df -h /data /var /home` | /data < 80 %, /var < 80 % (au 02/07 : 5 %, 43 %, 8 %) |
| 16 | Certificat web console | `echo \| openssl s_client -connect 127.0.0.1:443 -servername $(hostname -f) 2>/dev/null \| openssl x509 -noout -enddate` | `notAfter` à plus de 30 jours (au 02/07 : juin 2028) |

Toute dérive sur les points 1 à 6 et 13 doit être traitée dans la journée ; les points 10 à 12 conditionnent directement la conformité A.8.13 et A.5.28.

---

## Fréquences recommandées

| Fréquence | Points | Contenu |
|---|---|---|
| Quotidien (5 min, matin) | Checklist 1-4, 10-12 | Services et unités en échec, collecte 14 RUNNING, fraîcheur des sources, sauvegarde config du jour, dump Mongo du jour, état des snapshots. Traiter dans la journée toute unité en échec ou source silencieuse. |
| Hebdomadaire (lundi, après le passage de `omni-integrity-verify.timer` à 04:00) | Checklist 5-9, 13-16 | Vérification d'intégrité complète (`omni-integrity --verify`), revue des verdicts de triage et des règles FP de la semaine, lookups threat-intel, horloge, disque, échéance certificat. Contrôle de dérive du dépôt : `git -C /root/omnitech-siem-setup status --porcelain` (attendu : vide). |
| Mensuel (le 1er, automatique) | — | Dossier de preuves généré par `omni-iso-evidence.timer` (`docs/EVIDENCE-AUDIT-AAAA-MM-JJ.md`) : vérifier sa production, le commiter, vérifier la génération du rapport exécutif mensuel dans `/var/www/siem-kit/rapports/`. |
| Avant audit (J-7) | Checklist complète 1-16 | Rejouer les 16 points et archiver les sorties datées ; générer un dossier de preuves frais (`68-iso-evidence.sh`) ; capturer les dashboards « OMNI - SOC », « Santé collecte », « Incidents », « ATT&CK » ; vérifier que les manques listés par mesure ci-dessus sont soit corrigés, soit couverts par une décision RSSI datée ; s'assurer que rapports mensuels et registre de conformité (`docs/REGISTRE-CONFORMITE-ISO27001.md`) sont à jour. |

---

*Complément opérationnel de `docs/ISO27001-MAPPING.md` — à valider et dater par le RSSI. Dernière vérification des commandes : 02/07/2026.*
