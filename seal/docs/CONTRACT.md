# CONTRACT.md — Contrat d'intégration SEAL → Graylog (autorité unique)

Ce document fait FOI pour toutes les couches (SQL → Logstash → Graylog →
détections). Noms de colonnes vérifiés sur la base SEAL QA le 2026-07-10.
Toute couche DOIT s'y conformer. Décisions figées (feu vert opérateur).

## D0. Décisions actées
- **Périmètre** : QA uniquement (`bx-qa-seal-vm.omnitech.security` → `10.33.120.2:1433`, IP épinglée, `hostNameInCertificate=<FQDN>`, `encrypt=true;trustServerCertificate=false`).
- **Streams / index sets** (convention repo) :
  `OMNI - SEAL Accès` (`omni-seal-access`, rétention 12 mois),
  `OMNI - SEAL Alarmes` (`omni-seal-alarm`, 12 mois),
  `OMNI - SEAL Audit` (`omni-seal-audit`, 24 mois).
- **Fuseau** : serveur UTC+2. `timestamp` = heure métier en **UTC**.
  EVENEMENTS/ALARMES : `<col_locale> AT TIME ZONE 'Romance Standard Time' AT TIME ZONE 'UTC'`.
  Audit.* : utiliser `OperationDateUtc` (déjà UTC).
- **Décodage** : lookup `REEV_CODE → REEV_LIBELLE` via `dbo.REF_EVENEMENT` (Data Adapter CSV Graylog régénéré par cron). `severity_num` = `EVEN_SEVERITE` brut ; les détections s'appuient sur le **REEV_CODE décodé**, pas sur la sévérité SEAL (peu fiable).
- **Identité** : `EVEN_PHYSICAL_NUMBER → milf.BADGES.PHYSICAL_NUMBER → MATRICULE`.
  `identity_upn` NON résolu en SQL (absent en QA) → enrichi côté SIEM (matricule→AD, règle miroir). `AcApi.TAG` sert uniquement à savoir si un badge est **connu** (EVT-002), il ne porte pas de matricule.
- **Édition Graylog Open** : règles `[SEQ]` → approximation par état de pipeline si faisable, sinon v2, limite documentée. Pas de Correlation event def native, pas de lookup JDBC natif.

## D1. Minimisation RGPD (colonnes INTERDITES en vue SIEM)
Jamais exposer : `UTILISATEUR.UTI_PASSW`, `UTI_SEED`, `UTI_HASH_PASS`,
`UTILISATEUR_PASSWORD_HISTORY.*`, `DETAIL_FICHE.DFIC_VAL_PHOTO`.
`milf.BADGES` : n'exposer QUE `PHYSICAL_NUMBER`, `BADGE_NUMBER`, `MATRICULE`,
`STATUS`, `USER_TYPE`, `COMPANY`, `SITE`. **Exclure** PHOTO, LAST_NAME,
FIRST_NAME*, BIRTH_*, ADDRESS, CITY, ZIPCODE, NATIONALITY, SEX, MOTHER_*,
FATHER_*, MAIDEN_*, PERSONNAL_PHONE, QR_CODE* (PII, non nécessaires).
Descriptions : préférer `*_ANON` (`EVEN_USER_DESCRIPTION_ANON`, `AL_USER_DESCRIPTION_ANON`).

## D2. Colonnes source vérifiées (extraits utiles)
- `dbo.EVENEMENTS` : EVEN_ID, EVEN_GROUP_ID, EVEN_STORAGE_TIMESTAMP, EVEN_LIFESTAGE, EVEN_DATEHEURE, EVEN_DESCRIPTION, EVEN_USER_DESCRIPTION_ANON, USER_ID, REACHED_LIFESTATUS, RAW_ORIGIN_OBFI_ID, EVEN_PHYSICAL_NUMBER, EVEN_KEY_RING_SN. **Pas de rowversion → ALTER ADD EVEN_ROWVER.**
- `dbo.ALARMES` : EVEN_GROUP_ID (PK), MIN_EVEN_DATEHEURE, MAX_EVEN_STORAGE_TIMESTAMP, ACK_EVEN_ID, END_EVEN_ID, EVEN_LIFESTATUS, OBFI_ID, EVEN_DECLENCHEUR, REEV_CODE, AL_USER_DESCRIPTION_ANON, EVEN_SEVERITE, IS_INHIBITED, IS_INTEMPESTIVE, INTEMPESTIVE_COUNT, IS_PRIORITY, PRIORITY_USERCODE, **VERSION (rowversion natif)**.
- `dbo.REF_EVENEMENT` : REEV_CODE, REEV_LIBELLE, REEV_DFLT_SEVERITY, REEV_TYPE, REEV_DESCRIPTION, REEV_INTEMPESTIVEOCCUR/MAXEVENT/PERIOD.
- `dbo.Objet_Fiche` : OBFI_ID, OBJ_ID, ContextualLabel, Tags, SCOPE, OBFI_CLASS. (jointure `EVENEMENTS.RAW_ORIGIN_OBFI_ID = Objet_Fiche.OBFI_ID` et `ALARMES.OBFI_ID`).
- `Hypervision.ObjectsHierarchicalCatalog` : hierarchyid → site/zone par ancêtre.
- `milf.BADGES` : PHYSICAL_NUMBER, BADGE_NUMBER, MATRICULE, STATUS, USER_TYPE, COMPANY, SITE, ROW_VERSION.
- `AcApi.TAG` : ID (varchar16), TYPE, NUMBER, START_VALIDITY, END_VALIDITY, IS_DELETED.
- Audit.* (15 tables) colonnes communes : `Usercode`, `Operation`, `OperationChannel`, `OperationDateLocal`, **`OperationDateUtc`**. Spécifiques : cf. mission §2A. **Aucune n'a de rowversion → ALTER ADD RowVer sur les 15.**

## D3. Décodages (validés §9.2 RECON)
- LIFESTAGE : INF/BEG/END/ACK/NOP. LIFESTATUS : INF/LIV/END/ACK.
- REEV_CODE (via REF_EVENEMENT) : SEM113=Effraction porte, SEM105=ouverture physique signalée, SEM759=connexion console, SEM138/SEM280=accès usager/lecteur secondaire, SEM805=déclencheur manuel, SEM73=base UTL modifiée, SEM70/71=UTL vie perdue/démarre, SEM0=générique.
- Audit Operation : Connection/Deconnection/**ConnectionFailure**/SwitchProfile.
- OperationChannel : SEAL Light Wall / SEAL Exploitation / **SealAdmin** / SealMillefeuille.
- TagMovements.Status : VAL/PRE/ANN. **ANN→VAL = réactivation (ACC-004)**, VAL→ANN=désactivation, ∅→PRE=création.

## D4. Contrat de champs cible (normalisation Graylog) — noms figés
| Champ | Source |
|---|---|
| `event_source` | constante `seal` |
| `event_domain` | `access` / `alarm` / `hypervisor_audit` |
| `event_action` | Operation (audit) OU `REEV_LIBELLE` décodé (access/alarm) |
| `event_outcome` | success/failure/grant/deny/n.a. (déduit : ConnectionFailure→failure ; REEV accès→grant) |
| `severity_num` | `EVEN_SEVERITE` (alarm) ou mapping audit |
| `actor_usercode` | `Usercode` (audit) / `PRIORITY_USERCODE` |
| `actor_login` | `Login` (UserConnections) |
| `src_ip` | `IpAddress` (UserConnections) |
| `user_agent` | `UserAgent` |
| `operation_channel` | `OperationChannel` |
| `badge_number` | `EVEN_PHYSICAL_NUMBER` / `Number` |
| `identity_matricule` | `milf.BADGES.MATRICULE` (jointure badge) |
| `identity_upn` | (vide en QA ; enrichi SIEM-side) |
| `target_login` | `Login` (AccountsMovements) |
| `target_object_id` / `target_object_label` / `target_object_type` | `ObjectId`/`ObjectLabel`/`ObjectType` (CommandObject) ; `OBFI_ID`/`ContextualLabel` |
| `door_id` | `DoorId` (AccessControlPermissionMovements) / OBFI porte |
| `site` | résolu via ObjectsHierarchicalCatalog (ancêtre) |
| `seal_payload` | JSON audit résiduel (`FOR JSON PATH, WITHOUT_ARRAY_WRAPPER`) |
| `timestamp` | heure métier UTC (cf. D0) |
| `seal_source_table` | `SourceTable` (flux audit) |
| `seal_watermark` | `WatermarkBig` (diagnostic) |

## D5. Watermark Logstash (motif sûr)
`WHERE WatermarkBig > :sql_last_value AND WatermarkBig < CONVERT(BIGINT, MIN_ACTIVE_ROWVERSION()) ORDER BY WatermarkBig ASC`.
Vues exposant `CONVERT(BIGINT, <rowversion>) AS WatermarkBig` :
`vw_SealEvents_SIEM` (EVEN_ROWVER), `vw_SealAlarms_SIEM` (VERSION),
`vw_SealAudit_SIEM` (RowVer, UNION ALL des 15 tables — rowversion global à la base
= 1 watermark monotone). `vw_SealIdentity_SIEM` : pas de watermark (enrichissement).
Seed initial : watermark à la valeur courante (pas de rapatriement d'historique).
