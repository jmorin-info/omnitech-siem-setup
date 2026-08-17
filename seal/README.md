# SEAL → Graylog — Intégration SIEM (OMNITECH SECURITY)

Intégration de la GTC/contrôle d'accès **SEAL** (base SQL Server) dans le SIEM
Graylog du repo `omnitech-siem-setup`. **Périmètre : QA uniquement.**

> Autorité unique de conception : [`docs/CONTRACT.md`](docs/CONTRACT.md).
> Reconnaissance Phase 0 : [`docs/RECON.md`](docs/RECON.md).
> Recette : [`tests/RECETTE.md`](tests/RECETTE.md).

## 1. Architecture — flux de bout en bout

```
                    bx-qa-seal-vm.omnitech.security  (SQL Server 2019 Std)
                    10.33.120.2:1433   —  base SEAL   (QA UNIQUEMENT)
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Tables sources                Vues SIEM (minimisées RGPD, D1)         │
   │  dbo.EVENEMENTS  ───────────►  vw_SealEvents_SIEM   (wm: EVEN_ROWVER)  │
   │  dbo.ALARMES     ───────────►  vw_SealAlarms_SIEM   (wm: VERSION)      │
   │  Audit.* (15)    ───────────►  vw_SealAudit_SIEM    (wm: RowVer,UNION) │
   │  milf.BADGES/... ───────────►  vw_SealIdentity_SIEM (enrichissement)   │
   └───────────────────────────────────┬──────────────────────────────────┘
        JDBC (mssql-jdbc)               │  encrypt=true; trustServerCertificate=false
        Server=10.33.120.2,1433         │  hostNameInCertificate=<FQDN>  (IP épinglée)
        WHERE WatermarkBig > :sql_last_value
              AND WatermarkBig < MIN_ACTIVE_ROWVERSION()   (CONTRACT D5)
                                        ▼
                    ┌─────────────────────────────┐
                    │  Logstash (VM SIEM 10.33.220.10)
                    │  input jdbc (secret: keystore) │
                    │  output gelf → 12201           │
                    └───────────────┬────────────────┘
                                    │  GELF  10.33.220.10:12201
                                    ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Graylog 7.1.3 Open                                                    │
   │  Pipelines de normalisation (CONTRACT D4 : event_source/domain/...)   │
   │  Lookup CSV  REEV_CODE → REEV_LIBELLE  (Data Adapter régénéré/cron)    │
   │  Enrichissement identité : matricule (SQL) → UPN (SIEM-side, miroir)   │
   │  Streams / index sets :                                               │
   │    OMNI - SEAL Accès    (omni-seal-access, 12 mois)                    │
   │    OMNI - SEAL Alarmes  (omni-seal-alarm,  12 mois)                    │
   │    OMNI - SEAL Audit    (omni-seal-audit,  24 mois)                    │
   └───────────────┬───────────────────────────────┬──────────────────────┘
        Détections │ (EVT/ACC/ALM/HYP/XCO)          │ Dead man's switches
                   ▼                                ▼  (74-source-watchdog:
             Event Definitions              seal_access/alarm/audit)
                   └──────────────┬─────────────────┘
                                  ▼
                        Notification Teams  (TEAMS_WEBHOOK_URL)
```

Détails clés (cf. CONTRACT) :
- **Fuseau** : `timestamp` en UTC. EVENEMENTS/ALARMES convertis
  `AT TIME ZONE 'Romance Standard Time' AT TIME ZONE 'UTC'` ; `Audit.*` utilise
  `OperationDateUtc` (déjà UTC).
- **Identité** : `EVEN_PHYSICAL_NUMBER → milf.BADGES → MATRICULE` (~76,5 % en QA) ;
  `identity_upn` résolu côté SIEM (AD/M365), absent en QA.
- **Édition Open** : pas de Correlation event def native → règles `[SEQ]`
  approximées par état de pipeline ou reportées v2 (limite documentée).

## 2. Contenu du livrable

| Chemin | Rôle |
|---|---|
| `docs/CONTRACT.md` | Contrat d'intégration (autorité unique) |
| `docs/RECON.md` | Reconnaissance Phase 0 (lecture seule) |
| `sql/00_recon_queries.sql` | Requêtes de découverte (lecture seule) |
| `sql/01..05_*.sql`, `sql/90_provision.sql` | **DDL** : colonnes rowversion, vues SIEM, login `svc_graylog_seal` (à rédiger/valider Phase 1) |
| `logstash/` | Pipeline JDBC → GELF (Phase 2) |
| `graylog/pipelines/`, `lookups/`, `detections/` | Normalisation, lookup REEV, règles (Phases 3-4) |
| `tests/RECETTE.md` | Recette assistée + tableau règle-par-règle + test DMS |
| `tests/inject_synthetic.sql` | Injection synthétique `TEST_SIEM` (QA) |
| `tests/cleanup.sql` | Purge des marqueurs `TEST_SIEM` (QA) |
| `../seal_graylog_setup.py` | Orchestrateur (`--phase preflight/recon/plan-sql/apply-*`) |

## 3. Exploitation

- **Provisioning idempotent** : scripts bash `NN-*.sh` + `lib-graylog.sh`
  (recherche-par-titre avant création, create-or-update). Ré-exécutables sans
  effet de bord. SQL en `CREATE OR ALTER`.
- **Dry-run par défaut** : tout code modifiant nécessite `--apply` explicite.
- **Secrets** : jamais en clair. `00-vars.env` (gitignoré) + variables d'env +
  keystore Logstash. Le rapport preflight ne divulgue que la *présence* des secrets.
- **Surveillance de la source** : les 3 flux SEAL (`seal_access`, `seal_alarm`,
  `seal_audit`) sont ajoutés au watchdog (`74-source-watchdog.sh`,
  `alert_tag=source_silent`) → dead man's switch par stream (cf. RECETTE §C).
- **Lookup REEV** : Data Adapter CSV régénéré par cron depuis `dbo.REF_EVENEMENT`
  (pas de lookup JDBC natif en Open). Vérifier la fraîcheur du CSV.
- **Watermark** : monotone via rowversion + borne `MIN_ACTIVE_ROWVERSION()`. En cas
  d'arrêt Logstash, reprise au dernier `sql_last_value` (pas de perte, cf. RECETTE §C6).

## 4. ROLLBACK

Retrait complet, dans cet ordre (QA ; en prod, sous fenêtre de maintenance) :

1. **Graylog** : arrêter les notifications, supprimer les Event Definitions SEAL,
   les pipelines/règles SEAL, les connexions pipeline→stream, le lookup/adapter
   REEV, puis les 3 streams et leurs index sets (`omni-seal-access/alarm/audit`).
   Idéalement via les scripts `NN-*.sh` en mode suppression, sinon API
   (`ensure_*` recherche par titre → supprimer par id).
2. **Logstash** : arrêter et désactiver le pipeline SEAL ; retirer l'entrée du
   keystore ; retirer les 3 sources du watchdog (`/etc/default/omni-watchdog`).
3. **SQL — vues** : `DROP VIEW vw_SealEvents_SIEM, vw_SealAlarms_SIEM,
   vw_SealAudit_SIEM, vw_SealIdentity_SIEM;`
4. **SQL — login/permissions** : révoquer les GRANT sur les vues, puis
   `DROP USER svc_graylog_seal` (base) et `DROP LOGIN svc_graylog_seal` (serveur).
5. **SQL — colonnes rowversion ajoutées** (réversible) :
   `ALTER TABLE dbo.EVENEMENTS DROP COLUMN EVEN_ROWVER;` (réécriture de table →
   **fenêtre de maintenance**) et `ALTER TABLE Audit.<t> DROP COLUMN RowVer;` sur
   les 15 tables (instantané). `dbo.ALARMES.VERSION` est **natif** : NE PAS le retirer.
6. **Données de recette** : `tests/cleanup.sql` (purge `TEST_SIEM`).

> Les index SEAL déjà écrits dans Graylog restent soumis à leur rétention ; les
> supprimer explicitement si une purge immédiate est requise.

## 5. Notes PROD (avant bascule hors QA)

- **Fenêtre de maintenance — rowversion EVENEMENTS** : `ALTER TABLE ADD
  EVEN_ROWVER` réécrit ~961 k lignes (RECON §9.4) → planifier une fenêtre.
  Les 15 `Audit.*` et `dbo.ALARMES.VERSION` (natif) n'imposent pas de fenêtre.
- **Rotation du compte de service** : le mot de passe de `svc_graylog_seal` a
  transité par un canal chat lors de la mise en place → **le renouveler** avant
  prod, le stocker uniquement en keystore/variable d'env, et retirer la
  dérogation `db_datareader` de recon au profit du GRANT SELECT sur les seules
  vues (RECON §9.6).
- **Installation pilote SQL + Logstash** : le pilote (`msodbcsql18`+`pyodbc` ou
  `pymssql`) et Logstash (plugin `jdbc` + `mssql-jdbc`) sont **absents** de la VM
  SIEM (RECON §4). À installer (paquets, action modifiante, plan à confirmer).
- **DNS double enregistrement** : `bx-qa-seal-vm` a 2 A (`10.33.120.2` +
  `10.108.15.143` filtré). **Épingler l'IP** `10.33.120.2` dans la chaîne JDBC +
  `hostNameInCertificate=<FQDN>` (validation stricte du cert conservée).
- **Cert serveur SQL** : CN=`bx-qa-seal-vm.omnitech.security`, exp. 2028-07-09 —
  surveiller l'expiration.
- **Édition Graylog** : instance réelle 7.1.3 (mission annonçait 6.x). Sans
  incidence API ; les `[SEQ]` restent limitées (Open).
- **Volumétrie / seuils** : calibrés sur QA (~158 évts/24 h) — recalibrer les
  seuils de détection et le schedule Logstash sur les volumes de prod.

## 6. Checklist AIPD / RGPD (référencée — hors périmètre de ce livrable)

La minimisation est **imposée par le contrat** (`docs/CONTRACT.md` **§D1**) : les
vues SIEM excluent mots de passe/hashes/seed, photos, état civil et coordonnées ;
`milf.BADGES` limité à `PHYSICAL_NUMBER/BADGE_NUMBER/MATRICULE/STATUS/USER_TYPE/
COMPANY/SITE` ; descriptions `*_ANON` préférées ; `identity_upn` non extrait en QA.
La conformité formelle (**AIPD**, base légale, durées de conservation vs
rétentions 12/12/24 mois, information des personnes, registre) relève du DPO et
n'est **pas** produite ici — ce livrable fournit la **preuve technique de
minimisation** (colonnes interdites jamais exposées) à joindre au dossier AIPD.
Contrôle recette associé : RECETTE.md « Points d'attention → RGPD ».

## 7. Ordre exact de déploiement

Piloté par `seal_graylog_setup.py` (dry-run par défaut, `--apply` pour modifier) :

| # | Étape | Commande / script | Modifiant | Checkpoint |
|---|---|---|---|---|
| 1 | **Preflight** (réseau/DNS/TLS/édition/creds) | `./seal_graylog_setup.py --phase preflight` | non | — |
| 2 | **Recon** (SELECT lecture seule) | `./seal_graylog_setup.py --phase recon` | non | décodages validés (RECON §9) |
| 3 | **DDL** (rowversion + vues + login restreint) | `--phase plan-sql` puis `--phase apply-sql --apply` (`sql/01..05` + `90_provision.sql`) | **oui (SQL)** | valider le DDL AVANT exec |
| 4 | **Provision Graylog** (streams/index, lookup REEV, pipelines de normalisation) | `NN-*.sh` SEAL / phase dédiée `--apply` | oui (Graylog) | contrat D4 respecté |
| 5 | **Keystore + Logstash** (secret keystore, pipeline JDBC→GELF, seed watermark) | install + config Logstash | oui (VM SIEM) | flux GELF visible |
| 6 | **Détections + DMS + Teams** | scripts `detections/` + `74-source-watchdog.sh` (sources SEAL) | oui (Graylog) | règles branchées |
| 7 | **Recette** | `tests/RECETTE.md` (+ `inject_synthetic.sql`, test DMS), puis `cleanup.sql` | oui (QA data) | tableau règle-par-règle rempli |

## 8. Les 2 étapes opérateur restantes

Ces deux actions ne sont **pas** réalisées par le livrable (installation système /
DDL privilégié) et doivent être exécutées par l'opérateur.

### 8.1 DDL admin (Phase 3 du plan) — login privilégié SQL
Appliquer le DDL avec un compte **admin SQL temporaire** (le compte de service
n'a pas les droits DDL). Aucun secret dans les fichiers ; le mot de passe admin
passe par variable d'environnement, **non stocké** :
```bash
export SEAL_DB_ADMIN_USER='<admin_sql_temporaire>'
read -rs SEAL_DB_ADMIN_PWD; export SEAL_DB_ADMIN_PWD   # saisie masquée, hors historique
./seal_graylog_setup.py --phase plan-sql                # revue du DDL (aucune exec)
./seal_graylog_setup.py --phase apply-sql --apply       # exécute sql/01..05 + 90_provision.sql
unset SEAL_DB_ADMIN_PWD
```
Effet : ajoute `EVEN_ROWVER` (EVENEMENTS) et `RowVer` (15 `Audit.*`), crée les 4
vues SIEM, crée `svc_graylog_seal` restreint aux vues (retire `db_datareader`).

### 8.2 Installation du pilote SQL + Logstash (VM SIEM `10.33.220.10`)
```bash
# Pilote SQL (au choix) :
sudo apt-get install -y msodbcsql18 python3-pyodbc      # OU : pip install pymssql
# Logstash + plugins JDBC :
sudo apt-get install -y logstash
sudo /usr/share/logstash/bin/logstash-plugin install logstash-integration-jdbc
# driver mssql-jdbc déposé dans le répertoire du pipeline SEAL (cf. logstash/)
# Secret hors clair — via keystore Logstash :
sudo /usr/share/logstash/bin/logstash-keystore add SEAL_DB_SVC_PWD
```
Puis démarrer le pipeline SEAL et **seeder les watermarks** à la valeur courante
(pas de rapatriement d'historique, CONTRACT D5). Vérifier l'arrivée GELF sur
`10.33.220.10:12201`.

---

## État de déploiement (2026-07-15)

**Côté VM SIEM (10.33.220.10) — FAIT et vérifié :**
- Logstash 8.19 installé (`seal/logstash/install-logstash-siem.sh`), driver
  mssql-jdbc 12.8.1, plugins gelf/jdbc.
- `seal.conf` déployé (`/etc/logstash/conf.d/`), requêtes SQL (`/etc/logstash/sql/`),
  dossier watermark (`/var/lib/logstash/seal/`).
- Keystore Logstash peuplé (`SEAL_DB_SVC_USER/PWD`) — passphrase générée fournie
  au service via drop-in systemd `EnvironmentFile=/etc/logstash/keystore.env`
  (0640, hors dépôt). **`logstash -t` = Configuration OK.**
- **Input GELF UDP dédié SEAL `OMNI - SEAL (GELF UDP 12202)`** (127.0.0.1) — la
  sortie `gelf` (UDP) ne pouvait pas viser l'input GELF *HTTP* 12201 ; validé E2E.
- Service `logstash` **activé mais NON démarré** (attend les vues).

**Corrections de configuration appliquées :** sortie GELF (UDP→input dédié 12202) ;
chemins driver/SQL réalignés ; vue `vw_SealReev_SIEM` (06) + grant pour que la
régénération du lookup REEV survive au verrouillage `90_provision`.

**Étape opérateur restante (bloquante) — DDL sur SEAL :** mon compte de service
est en lecture seule (`db_datareader`), il ne peut pas créer les vues. Package
prêt : **`/tmp/seal-sql-package/`** (+ `.tgz`) — `Run-SealDDL.ps1` / `run-ddl.bat`
+ `sql/` (01→06, 90_provision) + README. À exécuter sur BX-QA-SEAL-VM avec un
login SQL admin (ex. `sa`).

**Ordre de mise en service :** (1) DDL sur SEAL → (2) `systemctl start logstash`
→ (3) vérifier l'arrivée dans les 3 streams → (4) repasser
`seal/dashboards/DATA_READINESS.md` au vert → (5) Phase 6 dashboards.
