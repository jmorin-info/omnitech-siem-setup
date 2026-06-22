# Journal des modifications — SIEM OMNITECH

Toutes les évolutions notables du dispositif. Format : date — changement.
*Dernière revue : 2026-06-22.*

## 2026-06-22 (couche ML, console enrichie, qualité)

### Couche d'apprentissage `oms-ml`
- **Détection d'anomalie non-supervisée** (IsolationForest, log1p + StandardScaler)
  par entité (hôte/compte) — score 0-100 explicable (z-score), réinjecté en GELF
  (`event_source=ml_anomaly`). Déployé (`77-ml-scoring.sh`, timers).
- **Réduction de faux positifs supervisée** : labels = **disposition Vrai/Faux
  positif** posée à la clôture des cas dans la console (boucle fermée) ; s'entraîne
  dès ~30 cas qualifiés.
- **`79-interne-indexset.sh`** : index set dédié `omni-interne` pour le stream
  interne — corrige un angle mort : `ueba_score` (74 k), `collecte_sla`, `siem_health`,
  `xdr_incident`, `ml_anomaly` étaient écrits dans `graylog_0`, invisibles à la console.

### Console SOC — refonte visuelle premium + enrichissements
- Interface premium (glassmorphism, glow, KPI métalliques teintés, micro-interactions).
- **Vue d'ensemble** : cartes **Anomalies ML** + **Risque UEBA** (vrais scores),
  **tendances KPI** (▲/▼ % vs période précédente).
- **Détections** : recherche libre + export CSV + **sévérité réelle** (`risk_severity`
  au lieu de `priority`, absent) + score de risque.
- **Palette ⌘K** : recherche live d'entités → Entité-360.
- **Incidents** : disposition VP/FP (alimente le ML) + verrou `cases.json` (race).
- **Santé** : robots d'auto-supervision (X/Y), couverture de collecte (SLA),
  liste des hôtes go-dark.
- **Graphe d'attaque** filtrable (tactique / volume / centrage d'entité).
- **Entité-360** : score ML + UEBA + pagination des événements.
- **Fuites & Dark Web** : synthèse par catégorie + état « aucune fuite » rassurant.
- **Rapport exécutif** enrichi (posture opérationnelle, entités à risque ML/UEBA).

### Ergonomie / UX / mobile
- Accessibilité clavier (focus visible, focus-trap, ARIA), **toasts** de feedback,
  squelettes de chargement, **cadence de rafraîchissement** réglable, **panneau d'aide
  (?)** + **bascule de densité**.
- **PWA mobile** : onglet **Menace** (parité console : menace, KPI, ML/UEBA, détections).

### Qualité / performance / corrections d'audit
- **Cache mémoire à TTL** sur les agrégations lourdes (matrice ATT&CK ~783→7 ms,
  rapport ~811→3 ms).
- **Suite de tests** hors-ligne (`run-tests.sh`, 23 tests : rédaction + oms-ml).
- **Mode rédaction** (`MOBILE_REDACT`) pour captures anonymisées.
- Corrections de l'audit multi-agents : robots de supervision **versionnés**
  (`61-supervision-robots.sh`), `ensure_lookup` **centralisé** dans `lib-graylog.sh`
  (corrige l'échec silencieux du lookup m365), alerte **`service_stop_securite`**
  (T1489, précurseur ransomware) câblée (`78`), honnêteté de la doc d'intégrité
  (clé HMAC co-localisée).

### Détections prêtes à déployer (NON déployées — `80-detection-extra2.sh`)
3 tripwires 0 faux positif validés par sondage OpenSearch (30 j) : `defender_tamper`
(T1562.001), `schtask_payload` (T1053.005), `amsi_bypass` (T1562.001). À déployer
après revue (relancer ensuite `57` puis `14`).

### Durcissement Graylog (streams / index / dashboards / corrélation / FP)
- **Réduction des faux positifs (`81-fp-allowlist.sh`, déployé)** : pipeline
  « OMNI - Allowlist FP » (stage 25) — pour des motifs bénins **mesurés**
  (scheduled_task 97 % FP, service_install 86 % FP, dont nos propres agents
  winlogbeat/Sysmon), pose `fp_allowlist=true` et **retire `alert_tag`** (l'alerte
  ne tire plus ; l'événement reste indexé). Réversible (lookup `fp-allowlist.csv`).
- **Dashboard « OMNI - Analytics » (`82-...`, déployé)** : 5 onglets — vue
  d'ensemble, anomalies ML, UEBA, couverture & santé, bruit/FP.
- **Corrélation kill-chain (`oms-xdr/rules.yaml`)** : 4 règles multi-signaux
  (vol LSASS→persistance, PowerShell offensif→persistance, usage creds→partage
  admin, LSASS→latéral 6 h) + 6 signaux + fenêtre par signal. Additif, réponse
  dry-run préservée ; live au prochain cycle du timer `oms-xdr`.
- **Rétention consolidée (`83-...`, dry-run par défaut)** : source unique de
  vérité (valeurs = `POLITIQUE-RETENTION.md`) ; corrige le routage
  `OMNI - FortiManager` (graylog_0 → `omni-fortimanager`). `APPLY=1` pour appliquer
  (0 suppression immédiate ; auto-purge au-delà des seuils ensuite).
- **Consolidation alertes Kerberos (`84-kerberoast-dedup.sh`, dry-run par défaut)** :
  kerberoasting/RC4 ×3 et AS-REP ×2 sur le même événement → **5 alertes → 2**
  (source canonique = `73`), garde-fou anti-perte de couverture. Posture AES
  confirmée (zéro RC4/0x17 en 90 j → bruit latent). `APPLY=1` pour consolider.

## 2026-06-14 (audit de cohérence & nouvelles sources)

### Nouvelles sources intégrées (`52-new-sources.sh`)
- **ESET PROTECT** (10.33.50.20) : input Syslog TCP 1515 (514 redirigé par le
  pare-feu), stream « OMNI - ESET », `event_source=eset` (+ tag menace). Index set
  dédié `omni-eset` (rétention 365 j). Alerte « ESET : détection » (route mail).
- **BunkerWeb WAF** (10.33.70.1) : Filebeat → Beats 5044, stream « OMNI - BunkerWeb »
  (routage par `event_source=bunkerweb` posé par Filebeat), tag WAF, champs `http_*`/`waf_*`.
  Index set dédié `omni-bunkerweb` (rétention 90 j), page dashboard « WAF BunkerWeb ».
- **NPS** (10.33.50.247) : déjà mappé côté SIEM (lookup `win-events.csv` 6272/6273/6274
  + alerte ajoutée en 13). Reste à déployer Winlogbeat côté serveur — **pas encore
  remonté côté client**.

### Bugs corrigés (audit de cohérence 2026-06-14)
- **Timestamp FortiGate** : pose du `timestamp` depuis `eventtime` (epoch
  nanosecondes) — règle `omni-forti-05-eventtime`, conforme A.8.17 (synchro horaire).
- **Faux positifs brute-force** : exclusion des comptes machine (`*$`) et des comptes
  de service bruyants (`ninjaone`, `ADSyncMSA_*`) qui échouent en boucle.
- **PowerShell** : exclusion de `wakeup-ssrs.ps1` (tâche légitime récurrente).
- **vSphere brute-force** : exclusion de `vpxuser` / `dcui` / `localhost` ; **(2026-06-15)** exclusion du **bruit des services cluster ESXi** (`clusterAgent`/gRPC « authentication handshake failed », jeton **SAML expiré**) qui était mal tagué `auth_echec` (user/src_ip vides) → générait de **faux brute-force** (par IP nœud ESXi et « (Empty Value) ») et de **faux « Hôte à risque » UEBA** sur l'infra. Corrigé à la racine (`19-vsphere.sh`, règle `omni-vsphere-10-auth-fail`).
- **Déduplication des incidents** : `event_source=incident` routé vers « OMNI - Interne
  SIEM » avec exclusion symétrique côté M365 (anti-dup) — `44-incidents.sh`.
- **cert-check** passé en télémétrie permanente.

### Architecture & rétentions
- **Index sets dédiés** ESET et BunkerWeb (séparation des flux et des rétentions).
- Rétentions actuelles : **FortiGate = 180 j** ; Windows/Sysmon/vSphere/M365/ESET = 365 j ;
  **BunkerWeb = 90 j**. Disque `/data` : 7,3 To.
- FortiGate : `source` = nom de l'équipement (host).

### Routage des alertes (2 tiers — `22-alert-routing.sh`)
- **Teams = firehose** : toutes les alertes.
- **Mail = critique « réveille-moi »** uniquement (compromission confirmée + santé
  SIEM), 26 alertes. Grâce des alertes mail récurrentes relevée à ≥ 60 min.
- Templates mail/Teams enrichis et *source-aware* (script 13).

### Outillage de purge
- `53-purge-clean.sh` : purge des **données** (logs + historique d'alertes) en
  conservant **toute la configuration** (méthode : cycle deflector + suppression des
  anciens index via l'API). Enchaîne sur `54-post-purge-repopulate.sh` (reconstruction
  des ranges, re-fetch M365, relance des robots d'analyse).

### Vérifications (live)
- Dashboard unique **« OMNI - SOC » à 24 pages**, `requires={}` (100 % OSS, pas
  d'Enterprise).
- 144 règles de pipeline, 88 définitions d'événements, 13 streams actifs (dont
  ESET, BunkerWeb, FortiGate).

### Sources & enrichissements ajoutés (suite de journée)
- **Vaultwarden** (BX-VAULTWARDEN, Docker → Filebeat) : stream + pipeline dédiés
  (`55-vaultwarden.sh`), **index set dédié `omni-vaultwarden`** (90 j) — évite
  l'éviction des events internes du SIEM. Kit client `/kit/vw-filebeat.sh`
  (anti-rejeu : `ignore_older 72h` + registry persistant). Détections coffre :
  `vault_auth_fail` (brute-force avec src_ip/compte), MITRE T1555.
- **Attribution DHCP FortiGate** (`56-fortidhcp.sh`) : collecteur API REST
  (token lecture seule) → lookup `omni-dhcp-attribution` (ip→hostname/MAC), timer
  15 min. Le pipeline FortiGate pose `src_hostname`/`dest_hostname` sur les IP
  internes (règles `omni-forti-06-dhcp-src/dest`) → « qui est derrière 10.33.x.x ».
- **Identité unifiée** (`58-identity-correlation.sh`) : champs `identity`
  (compte canonique : sans domaine/upn, minuscules) + `identity_human` (regroupe
  `adm-X`/`svc-X` sous la personne) sur winsec/sysmon/winother/M365/FortiGate/vSphere.
  Page dashboard **« Identité »** (pivot 1 personne, toutes sources). Corrèle déjà
  jmorin/adm-jmorin sur FortiGate+AD+Sysmon.
- **M365 / Entra ID Protection** : ingestion des `riskDetections` (permission
  `IdentityRiskEvent.Read.All`) → `m365_type:risk`, tag `m365_risque` (atRisk),
  alerte mail. A révélé le compte **jaubert** flaggé atRisk (attaque cloud étrangère).
  Détection `m365_brute_externe` (échecs M365 hors-FR, T1110).

### Détection — couverture MITRE & nouvelles règles
- **Carte de couverture MITRE ATT&CK** (`57-mitre-coverage.sh`) : calque
  `docs/mitre-navigator-layer.json` (à charger dans ATT&CK Navigator) + bilan.
  **58 détections / 44 techniques / 12-14 tactiques** (cf. COUVERTURE-MITRE-ATTACK.md).
- **Privilege Escalation comblée** (`47-detections-extra.sh`) : `uac_bypass`
  (T1548.002), `scheduled_task` (T1053.005), `service_install` (T1543.003). +
  `remote_discovery` (T1018), `service_stop_securite` (T1489).
- **Audit fichiers sensibles** (`59-file-audit.sh`) : parse 4663/5145, tags
  `file_sensitive_access` (T1039) / `file_delete_sensible` (T1485), alertes accès/
  suppression de masse (exfil/ransomware). *Armé* — nécessite les SACL côté serveurs.

### Intégrité & chiffrement (piliers ISO)
- **Intégrité des logs** (`60-integrity.sh`, A.8.15) : registre quotidien
  **haché-en-chaîne + signé HMAC** de l'état du corpus, copie hors-SIEM (SMB),
  `omni-integrity --verify` (hebdo + alerte mail si chaîne rompue — testé : une
  falsification est détectée). **Rôle Graylog « OMNI - Analyste (lecture seule) »**
  (moindre privilège, A.8.2).
- **Chiffrement au repos** `/data` (A.8.24/A.5.33) **réalisé le 2026-06-14** :
  **LUKS2 (header inline, aes-xts 512 bits) + déverrouillage TPM2/PCR7**. Reformatage
  chiffré à neuf (config hors `/data` préservée, logs repeuplés). Voir PROCEDURE-CHIFFREMENT-REPOS.md.
- **Supervision du chiffrement** : `omni-self-health` vérifie désormais que `/data`
  (chiffré) est bien ouvert + monté (alerte si le TPM échoue au boot ou si le volume
  est démonté) ; le **header LUKS est inclus dans la sauvegarde config quotidienne**
  (chiffrée, hors-bande `/SIEM/luks/`) → recovery toujours à jour.
- **SOAR avancé** : cadrage des playbooks (isoler hôte / désactiver compte /
  ticket) en attente de l'API NinjaOne. Voir SOAR-PLAYBOOKS.md.

### Audit multi-agent & corrections (cohérence)
- **Halt-traps de pipeline corrigés** (un stage « match either » sans règle
  satisfaite stoppe le pipeline) : Exposition réseau (privflags + 4ᵉ direction
  `transit`), Sources externes (règle pass-through), Identité (pass-through/stage).
- **Veeam** : `veeam_job_echec` = échec **final** du job (eid 190) seulement ;
  les retries transitoires (eid 450, « restore point locked ») → `veeam_job_warn`
  (visu, pas d'alerte). Fini les faux « backup échoué ».
- **SOAR rebranché et rendu permanent** (le sync de 13 le préservait désormais),
  **champs ESET** corrigés (`eset_action`), **boucle Vaultwarden** droppée
  (~9k/j de bruit), **`vw_level`** unifié, **faux « robot en panne »**
  (omni-self-health : calcul d'âge robuste) supprimés. Nouveaux robots supervisés.
- **Mail anti-spam** : 26 alertes critiques en mail (tier « réveille-moi »),
  tout le reste en Teams (firehose). Ajout « Sabotage de l'audit » au mail.

### Hygiène données
- **Purge du rejeu Vaultwarden** : Filebeat avait rejoué tout l'historique
  conteneur (2023→2026). ~23 M docs antidatés purgés de l'index Default `graylog_*`
  **et** ~23 M de l'index Windows `omni-winother_*` (double routage corrigé). Les
  événements internes/Windows réels sont préservés.

## 2026-06-12 (après-midi — corrections, audit & optimisations)

### Bugs corrigés (audit de cohérence)
- **vSphere ne parsait rien** : le stage 0 du pipeline ne contenait que la
  règle « drop bruit » en *match either* — tout message non-bruit était bloqué
  avant la normalisation (0 host/event_action sur 44k logs/15 min). Corrigé.
- **Collecteur M365 Activité planté** (datetime naive vs aware) : crashait à
  chaque exécution après la première → page M365 Activité vide. Corrigé +
  reset des curseurs → 53 000+ events M365 (Exchange/SharePoint/OneDrive/Teams).
- Correctif appliqué au binaire **et** au script source (anti-régression).

### Optimisations
- **vSphere −87 %** : filtrage du bruit stockage ESXi (traces vSAN, osfsd,
  envoy-access, vmkwarning ; application_name vide côté ESXi → filtrage sur le
  contenu). 26k → 3,4k logs/5 min, événements de sécurité conservés.
- **SOAR whitelist** renseignée (IP VPN France légitimes + IP site Ivry),
  testée. À compléter par les IP publiques des sites Bordeaux/PACA.

### Vérifications
- Audit complet : 56 règles pipeline (0 erreur), 0 échec d'indexation, tous
  services/timers OK, 43 définitions, throughput nominal.
- Veeam confirmé fonctionnel (canal « Veeam Backup » + alerte d'échec active).
- Purge des logs (base saine) : collecte temps réel vérifiée sur tous les flux.

## 2026-06-12 (consolidation)

### Sécurité / détection
- **SOAR-light** : blocage automatique d'IP attaquantes (alertes VPN/spraying)
  via threat feed lu par le FortiGate. Sécurités : jamais d'IP interne/whitelist,
  seuil, plafond, expiration 24 h, traçabilité.
- **Compte canari AD** : détection d'intrusion interne (lookup + règle + alerte
  + script de création `New-OmniCanary.ps1` avec SPN piège à Kerberoasting).
- Durcissement VPN FortiGate (géo-restriction FR) — campagne de spraying stoppée.
- UTM FortiGate complet activé sur les 3 clusters (AV/IPS/web/DNS/app-control).

### Résilience / conformité
- Sauvegarde de configuration quotidienne chiffrée (AES-256) externalisée SMB,
  rétention 14 j, auto-surveillée + **PRA** (plan de reconstruction) + RESTORE.md.
- Rétentions alignées ISO (365 j identité/cloud, 180 j réseau/endpoint) + garde-fou
  disque (alerte 80 %, purge d'urgence 88 %).
- **Rapport hebdomadaire automatique** (lundi 08:00) — preuve de revue.
- **Dossier documentaire ISO 27001** : politique, standard, procédure, dossier
  d'architecture, registre de conformité, PRA, LDAPS, synthèse exécutive.
- Authentification console par **LDAPS** restreinte aux Admins du domaine.

### Exploitation
- Intégration **Veeam** (canal Windows) — a révélé un job critique en échec.
- Script d'enrôlement Windows unique `Install-OmniSiem-NinjaOne.ps1`.
- Correctif tempête d'alertes (grâces/clés, détection des comptes de service).
- **Purge des logs** (base saine) après la phase de build/tests.

## 2026-06-13 (UEBA/NDR, MITRE ATT&CK & corrélation d'incidents)

### Détection avancée (au-delà de Graylog)
- **Couche UEBA / NDR** (`40-ueba-ndr.sh`) : collecteurs `omni-ueba-volume`
  (anomalie de volume par source, z-score même-heure-du-jour), score, géo, et
  nouveau pays — robots autonomes alimentant le stream interne SIEM.
- **NDR réseau** : détection de scan interne (`48-ndr-scan.sh`, T1046),
  exfiltration/tunneling DNS (`43-ndr-dns.sh`, T1071.004), beaconing, mouvement
  latéral et exfiltration.
- **Reconnaissance LDAP / annuaire** (`49-ldap-recon.sh`) : détection
  BloodHound / SharpHound via le collecteur `omni-ldap-recon`.
- **Corrélation attack-chain → incidents** (`44-incidents.sh`) : le corrélateur
  `omni-incident-correlate` agrège les détections d'une même entité en incidents
  notés (`incident_score`), routés vers « OMNI - Interne SIEM ».
- **Détections complémentaires** (`47-detections-extra.sh`) : 5 règles issues de
  la revue multi-agent, dans un pipeline dédié.

### Cartographie & MITRE
- **Mapping MITRE ATT&CK + score de risque** (`37-mitre-attack.sh`) :
  `alert_tag` → technique (Txxxx) / tactique / sévérité / score, via lookup CSV.
- **Carte cyber temps réel** (`42-carte-cyber.sh`) : arcs de flux animés générés
  hors Graylog (`omni-geo-flux` → `flux.json`).
- **Exposition Internet & classe de port à risque** (`49-expo-port-class.sh`) :
  enrichissement des flux FortiGate.

### Exploitation & supervision
- **Auto-supervision des robots** (`46-self-health.sh`) : `omni-self-health`
  route `event_source=siem_health` → INT, timer 30 min (alerte « Robot d'analyse
  en panne »).
- **Rapport exécutif mensuel** (`45-monthly-report.sh`) : HTML + PDF (weasyprint),
  envoi le 1er du mois à 06:00, archivé sous `/var/www/siem-kit/rapports/`.
- **Ventilation des échecs M365 par code Azure AD** (`48-m365-fail-codes.sh`).

## 2026-06-11 (mise en production initiale)
- Build du SIEM : modèle (index/streams/inputs), 55 règles pipeline,
  détections, dashboard 24 pages, TLS bout-en-bout, collecte M365, FortiAnalyzer,
  vSphere, déploiement des agents Windows (NinjaOne + GPO).

---
*Tenir à jour à chaque évolution. Référence technique détaillée : `CONTEXT.md`
(racine du dépôt). Voir aussi `INTEGRATION-SOURCES.md`, `INVENTAIRE-SOURCES.md`,
`POLITIQUE-RETENTION.md` et `REPONSE-AUTOMATISEE.md` dans `docs/`.*
