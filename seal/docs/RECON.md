# RECON.md — Phase 0 : reconnaissance intégration SEAL → Graylog

OMNITECH SECURITY · SIEM (repo `omnitech-siem-setup`) · MISSION_SEAL_GRAYLOG
Statut : **CHECKPOINT Phase 0 — reconnaissance EXÉCUTÉE (lecture seule).** Infra,
Graylog, réseau ET sémantique SQL (décodage des codes, chaîne d'identité,
volumétrie, watermark) vérifiés sur la base SEAL QA via le compte de service
`svc_graylog_seal` (dérogation temporaire `db_datareader`, cf. §5). Aucune écriture,
aucun DDL. Décodages proposés au §9 — **à valider avant la Phase 1**.

Date : 2026-07-10.

---

## 1. Périmètre et cibles (vérifiés)

| Élément | Valeur | Source |
|---|---|---|
| Cible SQL (QA uniquement) | `bx-qa-seal-vm.omnitech.security` → **`10.33.120.2:1433`** | DNS + test TCP |
| Base | `SEAL` | mission |
| VM SIEM (source autorisée) | `10.33.220.10` (via passerelle `10.33.220.254`, `eno1`) | `ip route get` |
| Certificat serveur SQL | TP `E824A448…A4B3`, CN=`bx-qa-seal-vm.omnitech.security`, exp. **2028-07-09** | rapport prereq |
| Graylog | **7.1.3+c34604d**, **édition Open** | API `/system`, `/system/plugins` |
| GELF ingest | `10.33.220.10:12201` (input GELF HTTP existant) | inventaire inputs |

> Note : la mission annonçait « Graylog 6.x » ; l'instance réelle est **7.1.3**.
> Sans incidence majeure (API events/pipelines identiques), signalé pour le dossier.

---

## 2. État Graylog vérifié → impacts de conception

- **Édition Open confirmée** (aucun plugin Enterprise/Security/Correlation).
  → **Pas de Correlation event definitions natives.** Toutes les règles marquées
  `[SEQ]` (HYP-002, ALM-002, XCO-*) devront être :
  soit approximées par **état de pipeline** (rule pipeline + champ d'état + event
  d'agrégation), soit **reportées en v2**, avec la limite documentée. Décision à
  acter au checkpoint Phase 4.
- **Convention d'index sets à respecter** : titre `OMNI - <Source>`, préfixe
  `omni-<source>`, `DeletionRetentionStrategy`. Les 3 streams SEAL suivront ce
  motif : `OMNI - SEAL Accès` / `OMNI - SEAL Alarmes` / `OMNI - SEAL Audit`
  (préfixes `omni-seal-access` / `omni-seal-alarm` / `omni-seal-audit`).
  → *Écart avec le libellé mission « SEAL — Accès physique » : à trancher
  (cohérence repo vs libellé mission).*
- **BX-QA-SEAL-VM est déjà une source Windows du SIEM** (~43 000 msgs/h en
  Winlogbeat). L'identité machine est donc déjà connue : utile pour la
  corrélation croisée XCO (badge physique ↔ logon Windows) et pour la règle
  miroir `identity_upn` (Phase 3.4).

---

## 3. Conventions repo à respecter (relevées)

- Scripts d'provisioning : bash numérotés `NN-<theme>.sh`, helpers mutualisés
  dans `lib-graylog.sh` (`ensure_rule`, `ensure_pipeline`, `ensure_lookup`,
  `connect_pipeline`, `get_stream_id`, `api_get/post/put`, idempotence
  create-or-update, recherche par titre avant création).
- Secrets : `00-vars.env` (gitignoré) + variables d'environnement ; jamais en
  clair dans les scripts. `TEAMS_WEBHOOK_URL` existe déjà dans `00-vars.env`.
- Service Python de corrélation : `oms-xdr/` (venv dédié, tests pytest, config
  YAML, lecture OpenSearch local). L'orchestrateur SEAL reprend ce style.
- Lookups : adapters `csvfile` régénérés par cron (pas de lookup JDBC natif en
  Open) — cohérent avec le repli d'enrichissement prévu (Phase 3.3).
- Arborescence livrable créée : `seal/{docs,sql,logstash/sql,graylog/pipelines,lookups,detections,tests}`
  + orchestrateur `seal_graylog_setup.py` (racine repo, comme demandé).

---

## 4. Préflight (résultats réels — lecture seule)

Exécuté via `./seal_graylog_setup.py --phase preflight` (rapport
`seal/docs/preflight.json`) :

| Contrôle | Résultat | Détail |
|---|---|---|
| Route TCP `10.33.120.2:1433` | **PASS** | ouvert depuis la VM SIEM |
| Route TCP `10.108.15.143:1433` | **WARN** | fermé/filtré — IP secondaire à écarter |
| DNS `bx-qa-seal-vm` | **WARN** | **2 enregistrements A** (`10.33.120.2` + `10.108.15.143`) |
| Édition Graylog | **PASS** | 7.1.3 Open (pas de corrélation native) |
| Pilote SQL (pyodbc/pymssql) | **FAIL** | **aucun pilote installé** sur la VM SIEM |
| Client Logstash | **FAIL** | **Logstash non installé** sur la VM SIEM |
| Variables d'env mission | **FAIL** | toutes absentes sauf `TEAMS_WEBHOOK_URL` |
| Connexion SQL `SELECT 1` | SKIP | bloqué (pilote + creds absents) |

### 4.1 Diagnostic du FAIL du rapport prereq (côté VM SQL)

Le rapport `seal-sql-prereq.json` est **PASS partout sauf le dernier item**
(« Connexion chiffrée via FQDN » = FAIL). Analyse :

> `Échec de l'ouverture de session de l'utilisateur 'SECURITY\adm-jmorin'.`

Ce n'est **pas** un problème TLS/PKI ni de SAN : le handshake chiffré a
abouti, c'est SQL Server qui **rejette l'authentification Windows** du compte
`adm-jmorin` (aucun login SQL mappé pour ce compte). Les indices « chaîne PKI
absente / SAN != FQDN » du script sont ici des **fausses pistes** : le
certificat est valide (CN=FQDN, Server Authentication, lié à l'instance,
ForceEncryption=1, tous PASS). **Le chiffrement fonctionne.** Il manque
uniquement un **login SQL valide** — ce que crée précisément `90_provision.sql`
(compte de service) en Phase 1, ou un login admin temporaire pour la Phase 0.

---

## 5. Blocages à lever avant la Phase 0 (SQL) — action opérateur

1. **Pilote SQL absent sur la VM SIEM.** Installer, sur `10.33.220.10`, l'un de :
   `msodbcsql18` + `python3-pyodbc`, **ou** `pymssql`. (Requis pour `--phase
   recon` et pour Logstash ensuite.) À valider avant apply — c'est une
   installation de paquet (action modifiante) : **plan à confirmer**.
2. **Logstash absent sur la VM SIEM.** À installer (plugin `jdbc` +
   `mssql-jdbc`) pour la Phase 2. Peut être différé après la Phase 0.
3. **Aucune variable d'environnement mission fournie** (sauf `TEAMS_WEBHOOK_URL`).
   Nécessaires pour la suite (valeurs *non* à mettre dans le code) :
   `SEAL_DB_HOST`, `SEAL_DB_NAME`, `SEAL_DB_ADMIN_USER/PWD` (**recon Phase 0
   uniquement**, non stockés), puis `SEAL_DB_SVC_USER/PWD` (créés en Phase 1),
   `GRAYLOG_API_URL`, `GRAYLOG_API_TOKEN`, `GRAYLOG_GELF_HOST/PORT`.
4. **Compte de reconnaissance SQL.** Les requêtes de `seal/sql/00_recon_queries.sql`
   sont en **lecture seule** mais nécessitent un droit de SELECT de découverte.
   Le compte de service n'existe pas encore (Phase 1). → fournir un **login
   admin temporaire** (SQL auth) pour la Phase 0, **ou** m'autoriser à créer
   d'abord `90_provision.sql` en avance de phase.
5. **Double enregistrement DNS.** Décider : corriger la zone DNS
   (retirer `10.108.15.143`) **ou** épingler l'IP `10.33.120.2` dans la chaîne
   JDBC (`Server=10.33.120.2,1433` + `hostNameInCertificate=<FQDN>` pour garder
   la validation stricte du certificat). Recommandation : **épingler l'IP** côté
   Logstash (robuste, sans dépendre d'une correction DNS tierce).

---

## 6. Plan Phase 0 SQL — **EN ATTENTE** (méthode figée, prête à exécuter)

Dès qu'un accès SQL est disponible, `seal/sql/00_recon_queries.sql` produit :

- **Décodage des codes** (0.2–0.5) : recherche d'une table référentiel
  `%REEV%`/`%TYPE%` (code→libellé) ; à défaut, corrélation `REEV_CODE` ↔
  échantillon `EVEN_DESCRIPTION`. Idem `EVEN_LIFESTAGE`, `REACHED_LIFESTATUS`,
  `EVEN_LIFESTATUS`, `EVEN_DECLENCHEUR`, `TagMovements.Status` (varchar 3),
  `Operation`/`OperationChannel`.
- **Fuseau horaire** (0.6) : delta `EVEN_DATEHEURE` vs `EVEN_STORAGE_TIMESTAMP`
  vs horloge serveur → décision de conversion UTC pour le champ `timestamp`.
- **Chaîne d'identité** (0.7–0.8) : localisation du catalogue de champs de fiche
  (`CFIC`/`CHAMP_FICHE`), liste `DISTINCT SYNCHRO_LDAP_HISTORY.ATTRIBUT`,
  localisation des tables badge (`%TAG%`/`%BADGE%`), puis validation de la
  résolution `EVEN_PHYSICAL_NUMBER → fiche → matricule → UPN` sur 20 badges réels.
- **Volumétrie** (0.9) : lignes/jour EVENEMENTS et ALARMES → calibrage du
  schedule Logstash et des seuils de détection.
- **Watermark** (0.10) : confirmation `rowversion` (ALARMES.VERSION présent ;
  EVENEMENTS sans rowversion → `ALTER` en Phase 1) + `MIN_ACTIVE_ROWVERSION()`.

Le résultat sera consigné ici (tableaux code→sens) et **soumis à validation**
avant toute écriture de règle (règle d'engagement 7).

---

## 7. Décisions demandées (checkpoint Phase 0)

1. **Débloquer l'accès SQL** : fournir un login (admin temporaire SQL auth **ou**
   feu vert pour créer `90_provision.sql` en avance) + autoriser l'installation
   du pilote SQL sur la VM SIEM (plan : 1 paquet, réversible).
2. **DNS** : corriger la zone **ou** valider l'épinglage IP `10.33.120.2`.
3. **Nommage des streams** : convention repo (`OMNI - SEAL …`) **ou** libellé
   mission (`SEAL — …`) ?
4. **Rétentions** : 12/12/24 mois (accès/alarmes/audit) par défaut — à confirmer.
5. **Fournir les variables d'environnement** listées au §5.3 (hors code/commits).

---

## 8. Fait / Non-fait à ce stade

- **Fait (lecture seule)** : arborescence `seal/`, orchestrateur
  `seal_graylog_setup.py` (`--phase preflight` opérationnel), pack de requêtes de
  reconnaissance `seal/sql/00_recon_queries.sql`, détection édition/état Graylog,
  préflight réseau/DNS/TLS/outillage, diagnostic du FAIL prereq.
- **Non fait (en attente de validation/accès)** : toute requête SQL sur SEAL,
  tout DDL, toute création d'objet Graylog, toute installation de paquet.

---

## 9. Phase 0 — Résultats de la reconnaissance (exécutée le 2026-07-10)

Source : `svc_graylog_seal` (pymssql, TLS, IP épinglée 10.33.120.2). Brut :
`seal/docs/recon-raw.json` (gitignoré). SQL Server **2019 Standard 15.0.2170.1**.

### 9.1 Fuseau horaire — DÉCISION
Horloge serveur : `local_now` = UTC+2 (Europe/Paris CEST). `EVEN_DATEHEURE` est en
**heure locale serveur** (delta 0–1 min vs `EVEN_STORAGE_TIMESTAMP`, local aussi).
→ **Conversion UTC requise** dans les vues :
`EVEN_DATEHEURE AT TIME ZONE 'Romance Standard Time' AT TIME ZONE 'UTC'`
(gère l'heure d'été). Les tables `Audit.*` fournissent déjà `OperationDateUtc` → à
utiliser tel quel. **À valider.**

### 9.2 Décodage des codes (proposé — À VALIDER, règle d'engagement 7)

**Référentiel trouvé : `dbo.REF_EVENEMENT`** (`REEV_CODE` → `REEV_LIBELLE`,
`REEV_DESCRIPTION`, `REEV_DFLT_SEVERITY`, seuils `REEV_INTEMPESTIVE*`). C'est la
source de vérité du décodage : la normalisation Graylog fera un lookup
`REEV_CODE → libellé` (Data Adapter CSV régénéré depuis cette table).

REEV_CODE réels les plus fréquents (décodés) :

| REEV_CODE | Libellé (REF_EVENEMENT) | Sév. déf. | Volume | Usage détection |
|---|---|---|---|---|
| SEM0 | « Catégorie inconnue » (générique/accès) | 99 | 527 k | bruit de fond |
| SEM97 | Perte de connexion module | 113 | 87 k | supervision |
| SEM218 | Intrusion détectée par la vidéo | 0 | 35 k | — |
| SEM287/193/187 | Changement d'état capteur / entrée 4-états | 101/113 | 35 k | ALM-004 intempestif |
| **SEM113** | **Effraction porte** | 113 | 4 k | **ALM-003 porte forcée** |
| **SEM759** | **Connexion utilisateur sur la console** | 801 | 10 k | contexte HYP |
| SEM138 / SEM280 | Accès d'un usager / lecteur secondaire | 111 | — | EVT-001 |
| **SEM805** | **Déclencheur manuel percuté** (bouton panique) | 113 | 165 | alerte |
| **SEM73** | **Base de données de l'UTL modifiée** | 801 | 158 | falsification config |
| SEM70 / SEM71 | Signal de vie UTL perdu / UTL démarre | 901/801 | — | dead-man capteur |
| SEM104/105 | Porte remise normale / ouverture physique signalée | 101 | — | ALM-003 (compl.) |

Autres décodages (échantillons DISTINCT+COUNT) :
- `EVENEMENTS.EVEN_LIFESTAGE` : `INF` (info), `BEG` (début alarme), `END` (fin),
  `ACK` (acquittée), `NOP`. → cycle de vie alarme.
- `REACHED_LIFESTATUS` / `ALARMES.EVEN_LIFESTATUS` : `INF`, `LIV` (livrée ?), `END`,
  `ACK`. → statut courant. **Sens de `LIV` à confirmer.**
- `EVEN_SEVERITE` (ALARMES) : 99 (dominant, info), 113, 0, 101, 801, 111, 901,
  112, 110. **Mapping sévérité→niveau SIEM à valider** (proposé : 901/113/801→High,
  111/112/101→Medium, 0/99→Info).
- `Audit.UserConnections.Operation` : `Connection`, `Deconnection`,
  **`ConnectionFailure`** (→ HYP-001 brute force), `SwitchProfile`.
- `OperationChannel` : `SEAL Light Wall`, `SEAL Exploitation`, **`SealAdmin`**
  (console d'admin → HYP-003), `SealMillefeuille`.
- `Audit.TagMovements.Status` (badge) : `VAL` (valide), `PRE` (préparé/pré-encodé),
  `ANN` (annulé/désactivé). Transitions observées : `PRE→VAL` (activation),
  `VAL→ANN` (désactivation), **`ANN→VAL` (réactivation → ACC-004)**,
  `∅→PRE` (création). **À valider.**

### 9.3 Chaîne d'identité — badge → matricule (UPN différé)
- Ancrage : `dbo.EVENEMENTS.EVEN_PHYSICAL_NUMBER` = `milf.BADGES.PHYSICAL_NUMBER`
  (schéma `milf` = « Millefeuille », cohérent avec le canal `SealMillefeuille`).
- **`milf.BADGES` porte directement `MATRICULE`** → chaîne courte, pas besoin de
  DETAIL_FICHE/CHAMP_FICHE pour le matricule.
- **Taux de résolution réel : 153/200 (76,5 %)** sur les événements récents avec
  badge. ~23 % non résolus (badges hérités `AcApi.TAG`/`dbo`, visiteurs, supports
  hors `milf.BADGES`) → **source d'identité secondaire à ajouter** (AcApi.TAG) pour
  améliorer la couverture. À arbitrer.
- **UPN indisponible en QA** : `SYNCHRO_LDAP_HISTORY` vide et
  `CHAMP_FICHE.CFIC_LDAP_ATTRIBUT` vide → aucun mapping UPN en base QA.
  → `identity_upn` sera résolu **côté SIEM** (matricule → AD/M365) via la règle
  miroir Phase 3.4, pas en SQL. En QA, `identity_matricule` seul est fiable.

### 9.4 Watermark / rowversion — impacts Phase 1
- `dbo.ALARMES` : rowversion natif `VERSION` **présent** (+ ré-émission sur UPDATE
  de cycle de vie → flux de transitions exploitable, cf. ALM-001/002).
- **`dbo.EVENEMENTS` : PAS de rowversion** → `ALTER TABLE ADD rowversion`
  (réécriture de table ~961 k lignes → **fenêtre de maintenance en prod**).
- **Les 15 tables `Audit.*` : AUCUNE n'a de rowversion** → `ALTER ADD RowVer` sur
  les 15 (petites, instantané). Tables : AccessControlPermissionMovements,
  AccountRolesMovements, AccountsMovements, CommandObject, LocalUnitMigrationMovements,
  LogDownload, ObjectDeclarationMovements, ProfileAllowedSwitch,
  ProfileAuthorizedObjectsMovements, ProfileRoleMovements, ProfilesMovements,
  TagGroupMembersMovements, TagGroupMovements, TagMovements, UserConnections.
- `MIN_ACTIVE_ROWVERSION()` = 667422971 (borne haute sûre du motif watermark).

### 9.5 Volumétrie (calibrage schedule/seuils)
- `EVENEMENTS` sur 24 h : **158 lignes** (QA peu actif) → schedule 30 s large,
  seed des watermarks à la valeur courante sans risque de flood.
- `ALARMES` total : ~703 k. `EVEN_DECLENCHEUR` : 132 déclencheurs distincts
  (top : `QA_ULS_*`, lecteurs/détecteurs) → utile pour ALM-004 (flood/capteur).

### 9.6 Écart de dérogation à corriger en Phase 1
Le compte `svc_graylog_seal` est actuellement `db_datareader` (accès large, décidé
temporairement par l'opérateur pour la recon). `90_provision.sql` devra
**`ALTER ROLE db_datareader DROP MEMBER svc_graylog_seal` + `REVOKE` explicite sur
les tables + `GRANT SELECT` sur les seules vues SIEM** (règle d'engagement 5).

---

## 10. Décisions demandées (checkpoint Phase 0) — mise à jour

1. **Valider les décodages** §9.2 (REEV via REF_EVENEMENT, LIFESTAGE/STATUS,
   Status badge, mapping sévérité) et le sens de `LIV`.
2. **Fuseau** §9.1 : confirmer conversion `Romance Standard Time → UTC`.
3. **Identité** §9.3 : accepter matricule-seul en QA (UPN côté SIEM) ; ajouter ou
   non `AcApi.TAG` comme 2e source pour passer >76 % de résolution.
4. **Nommage streams** : convention repo `OMNI - SEAL …` (recommandé) vs mission.
5. **Rétentions** : 12/12/24 mois (accès/alarmes/audit) — confirmer.
6. **Fenêtre de maintenance** pour le rowversion d'`EVENEMENTS` (prod, plus tard).
7. **`GRAYLOG_API_TOKEN`** à fournir (token compte de service Graylog) pour la
   Phase 3 (provisioning streams/pipelines). Non requis avant.

**→ Arrêt au checkpoint Phase 0. Sur ta validation des décodages (§9.2) et des
décisions (§10), j'enchaîne la Phase 1 : rédaction du DDL `sql/01..05 + 90_provision`
(présenté pour validation AVANT toute exécution, règle 8).**
