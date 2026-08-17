# SEAL → Graylog — Catalogue de détection v1

> Autorité : `seal/docs/CONTRACT.md` (champs normalisés **D4**, décodages **D3**).
> Édition Graylog **Open 7.1.3** → **Aggregation event definitions uniquement**
> (pas de Correlation event def native, pas de lookup JDBC). Les règles de
> corrélation de séquence sont marquées **[SEQ]** et documentées (approximation
> par état de pipeline, ou report v2).
>
> **Calibrage seuils** : volumétrie RECON §9.5 — QA très peu actif
> (`EVENEMENTS` ≈ **158 events/24 h**, soit ≈ 6,6/h). Les seuils de brute force /
> flood sont donc placés bien au-dessus du bruit de fond QA (≥5–20 selon la
> règle) ; à re-calibrer sur la volumétrie **prod** avant bascule.
>
> **Notification** (cf. `provision_detections.py`) : une seule notification
> `teams-notification-v2` (webhook Teams = notification HTTP portant une
> **Adaptive Card** : règle, sévérité, acteur/objet, lien Graylog).
> **Multi-site** : la carte expose `seal_site` par ligne de backlog (`site:…`) pour
> identifier **quel site** a déclenché, sans modifier le `group_by`/la clé des règles.
> **Critical/High = immédiat** (Adaptive Card rattachée) ·
> **Medium/Info = digest** (pas de push temps réel ; visibles console + rapport).
>
> **Champs** : toutes les requêtes n'emploient **que** les champs normalisés
> **D4** (`event_domain`, `event_action`, `event_outcome`, `operation_channel`,
> `actor_login`, `actor_usercode`, `src_ip`, `badge_number`, `target_object_label`,
> `door_id`, `seal_source_table`, `seal_payload`, …), jamais les colonnes SQL brutes. Les specificites audit sont exposees en champs `seal_<clef>` (JSON eclate par Logstash) ; les qualificatifs d'alarme (IS_INHIBITED...) sont des colonnes directes de la vue.

## Conventions

- **Streams / index sets** (CONTRACT D0) :
  `OMNI - SEAL Accès` (`omni-seal-access`) · `OMNI - SEAL Alarmes`
  (`omni-seal-alarm`) · `OMNI - SEAL Audit` (`omni-seal-audit`).
- **event_action** (D4) = `Operation` (audit) **ou** `REEV_LIBELLE` **décodé**
  (accès/alarme) via le lookup `REEV_CODE→libellé`. Les détections s'appuient sur
  le **REEV_CODE décodé** (D0), pas sur `severity_num` SEAL (peu fiable).
- **Approximations documentées** : les transitions de mouvement (badge, permission,
  inhibition) ne disposent pas encore d'un champ D4 dédié → elles sont matchées sur
  `seal_source_table` + `seal_payload` (JSON résiduel D4). Un champ normalisé dédié
  est recommandé en v2 (colonne « Statut » = `[SEQ]` ou note *payload*).
- **Fenêtre** notée `within / every` (minutes). `grace` = anti-tempête par entité.

## Statut

| Code | Sens |
|---|---|
| `actif` | Aggregation event definition provisionnée et **activée**. |
| `[SEQ]-approx` | Séquence approximée par **état de pipeline** (tag/flag posé en pipeline) ; provisionnée, activée, mais dépend du déploiement du pipeline (Phase 3). |
| `[SEQ]-v2` | Corrélation de séquence non exprimable en aggregation simple → **reportée v2** (service `oms-xdr`, multi-stream). Cataloguée, **non** provisionnée en Graylog. |
| `désactivé (recette)` | Créée **disabled** (dead-man switch) — activation **post-recette**, quand le flux coule (cf. `provision_detections.py`). |

---

## 1. HYP — Audit hyperviseur / consoles SEAL  (stream `OMNI - SEAL Audit`)

| ID | Titre | Requête Graylog (D4) | group_by | Seuil | Fenêtre | Sév. | Technique | Notif. | Statut |
|---|---|---|---|---|---|---|---|---|---|
| HYP-001 | Brute force console (échecs d'authentification) | `event_domain:hypervisor_audit AND event_action:ConnectionFailure` | `actor_login` | `count() ≥ 5` | 10 / 1 | High | T1110 | immédiat | actif |
| HYP-002 | Brute force **suivie d'un succès** (même compte) | `event_domain:hypervisor_audit AND alert_tag:seal_bf_then_success` | `actor_login` | `count() ≥ 1` | 15 / 1 | High | T1110 / T1078 | immédiat | [SEQ]-approx |
| HYP-003 | Connexion console d'administration (`SealAdmin`) | `event_domain:hypervisor_audit AND event_action:Connection AND operation_channel:SealAdmin` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | Medium | T1078 | digest | actif |
| HYP-004 | Changement de profil en session (`SwitchProfile`) | `event_domain:hypervisor_audit AND event_action:SwitchProfile` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | Medium | T1078 | digest | actif |
| HYP-005 | Connexion admin **hors heures ouvrées** | `event_domain:hypervisor_audit AND event_action:Connection AND operation_channel:SealAdmin AND off_hours:true` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | High | T1078 | immédiat | [SEQ]-approx |
| HYP-006 | Export / téléchargement de journaux d'audit | `event_domain:hypervisor_audit AND seal_source_table:LogDownload` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | Medium | T1005 | digest | actif |
| HYP-007 | Création / modification de compte ou de rôle | `event_domain:hypervisor_audit AND seal_source_table:(AccountsMovements OR AccountRolesMovements OR ProfilesMovements)` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | High | T1136 / T1098 | immédiat | actif |
| HYP-008 | Modification des autorisations de profil | `event_domain:hypervisor_audit AND seal_source_table:(ProfileAuthorizedObjectsMovements OR ProfileAllowedSwitch OR ProfileRoleMovements)` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | Medium | T1098 | digest | actif |
| HYP-009 | Migration d'unité locale (reconfig contrôleur) | `event_domain:hypervisor_audit AND seal_source_table:LocalUnitMigrationMovements` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | Medium | T1565 | digest | actif |
| HYP-010 | Modif. d'objet physique (porte/commande) | `event_domain:hypervisor_audit AND seal_source_table:(CommandObject OR ObjectDeclarationMovements)` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | Medium | T1565.001 | digest | actif |
| HYP-011 | Sessions simultanées multi-IP (même compte) | `event_domain:hypervisor_audit AND event_action:Connection` | `actor_login` | `card(src_ip) ≥ 2` | 10 / 5 | Medium | T1078 | digest | [SEQ]-approx |
| HYP-012 | **Compte console actif sur plusieurs sites** (multi-site) | `event_domain:hypervisor_audit AND event_action:Connection` | `actor_login` | `card(seal_site) ≥ 2` | 30 / 10 | Medium | T1078 | digest | actif |

*Note — HYP-012 (multi-site) : un même compte console qui se connecte aux **deux**
sites SEAL (`bx-qa-seal-vm` **et** `bx-seal-omega`) dans la fenêtre. Signal de
compte partagé / mouvement latéral inter-sites. Volontairement **Medium/digest**
(peut être légitime pour un admin transverse → revue, pas de push Teams : anti-flood).*

*Note — SEM759 (« Connexion utilisateur sur la console ») et SEM73 (« Base de
données de l'UTL modifiée ») sont normalisés mais non alertés en v1 (contexte /
corrélation) ; candidats v2. `off_hours` est un flag posé en pipeline (Phase 3).*

## 2. ACC — Administration du contrôle d'accès / badges

| ID | Titre | Requête Graylog (D4) | group_by | Seuil | Fenêtre | Sév. | Technique | Notif. | Statut |
|---|---|---|---|---|---|---|---|---|---|
| ACC-001 | Attribution d'un **passe général** (master key → 1) | `event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_MasterKeys:true AND seal_MasterKeysOld:false` | `actor_usercode` , `target_object_label` | `count() ≥ 1` | 10 / 5 | High | T1098 / T1078 | immédiat | actif |
| ACC-002 | Attribution en masse de droits d'accès | `event_domain:hypervisor_audit AND seal_source_table:AccessControlPermissionMovements` | `actor_usercode` | `count() ≥ 5` | 10 / 5 | Medium | T1098 | digest | actif |
| ACC-003 | Création de badge (`∅→PRE`) | `event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_Status:PRE` | `actor_usercode` | `count() ≥ 1` | 15 / 10 | Info | T1136 | digest | actif |
| ACC-004 | **Réactivation** de badge (`Status ANN→VAL`) | `event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_StatusOld:ANN AND seal_Status:VAL` | `actor_usercode` , `target_login` | `count() ≥ 1` | 10 / 5 | High | T1078 | immédiat | actif |
| ACC-005 | Badge **désactivé puis utilisé** (`VAL→ANN` → accès) | *séquence TagMovements audit × EVENEMENTS accès (même badge)* | `badge_number` | — | 24 h | High | T1078 | immédiat | [SEQ]-v2 |
| ACC-006 | Accès **refusés** répétés sur une porte | `event_domain:access AND event_outcome:deny` | `target_object_label` | `count() ≥ 5` | 10 / 1 | Medium | T1110 | digest | actif |
| ACC-007 | Accès accordé **hors plage horaire** | `event_domain:access AND event_outcome:grant AND off_hours:true` | `badge_number` , `target_object_label` | `count() ≥ 1` | 15 / 5 | Medium | T1078 | digest | [SEQ]-approx |

*Note — `MasterKeys`, `Status/StatusOld` (transitions badge) ne sont pas encore des
champs D4 dédiés → matchés sur `seal_payload` (JSON D4). Champ normalisé dédié =
tâche v2. Taux de résolution badge→matricule ≈ 76,5 % (RECON §9.3) : `badge_number`
reste la clé fiable en QA.*

## 3. ALM — Alarmes  (stream `OMNI - SEAL Alarmes`)

| ID | Titre | Requête Graylog (D4) | group_by | Seuil | Fenêtre | Sév. | Technique | Notif. | Statut |
|---|---|---|---|---|---|---|---|---|---|
| ALM-001 | **Inhibition** d'une alarme (`IS_INHIBITED→1`) | `event_domain:alarm AND IS_INHIBITED:true` | `target_object_label` | `count() ≥ 1` | 10 / 5 | High | T1562.001 | immédiat | actif |
| ALM-002 | Inhibition **suivie d'une effraction** (même point) | *séquence : ALM-001 → SEM113 sur le même `target_object_label`* | `target_object_label` | — | 60 | High | T1562.001 | immédiat | [SEQ]-v2 |
| ALM-003 | **Intrusion physique** (effraction porte / bouton panique) | `event_domain:alarm AND event_action:("Effraction porte" OR "Déclencheur manuel percuté")` | `target_object_label` | `count() ≥ 1` | 5 / 1 | Critical | T1200 / physique | immédiat | actif |
| ALM-004 | Alarme **intempestive** / flood capteur | `event_domain:alarm AND IS_INTEMPESTIVE:true` | `target_object_label` | `count() ≥ 20` | 10 / 5 | Medium | T1499 / T1562.001 | digest | actif |

*Note — REEV_CODE décodés (D3) : `SEM113` = « Effraction porte », `SEM805` =
« Déclencheur manuel percuté » (bouton panique). Les libellés proviennent du lookup
`REEV_CODE→REEV_LIBELLE` (`dbo.REF_EVENEMENT`).*

## 4. EVT — Événements d'accès physique  (stream `OMNI - SEAL Accès`)

| ID | Titre | Requête Graylog (D4) | group_by | Seuil | Fenêtre | Sév. | Technique | Notif. | Statut |
|---|---|---|---|---|---|---|---|---|---|
| EVT-001 | Accès usager **accordé** (base corrélation / chasse) | `event_domain:access AND event_outcome:grant` | `badge_number` | `count() ≥ 1` | 5 / 5 | Info | — | digest | actif |
| EVT-002 | **Badge inconnu / non enrôlé** présenté | `event_domain:access AND event_outcome:grant AND NOT _exists_:identity_matricule` | `badge_number` , `door_id` | `count() ≥ 1` | 10 / 5 | Medium | T1078 | digest | [SEQ]-approx |

*Note — EVT-001 (SEM138/SEM280 « accès usager / lecteur secondaire ») est la source
d'accès accordé qui alimente XCO ; volontairement **Info/digest** (anti-firehose).
EVT-002 : `badge_known` est posé en pipeline via `AcApi.TAG` (D0 : le tag indique
seulement qu'un badge est **connu**, il ne porte pas de matricule).*

## 5. XCO — Corrélation croisée physique ↔ numérique  (multi-stream, **v2**)

Corrélations de séquence multi-sources **non exprimables** en aggregation Graylog
Open (jointure inter-stream + résolution d'identité SIEM-side). Cataloguées ;
implémentation en **v2** dans le service `oms-xdr` (lecture OpenSearch). **Non**
provisionnées en Graylog.

| ID | Titre | Logique | Corrèle | Sév. | Technique | Statut |
|---|---|---|---|---|---|---|
| XCO-001 | Voyage impossible physique ↔ logon | Badge sur site **et** logon Windows distant du même matricule dans un délai incompatible | `identity_matricule` (accès SEAL) × 4624 Windows | High | T1078 | [SEQ]-v2 |
| XCO-002 | Accès badge **sans** logon corrélé (talonnage / clonage) | Accès physique accordé sans session Windows attendue sur la même identité | accès SEAL × sessions Windows | Medium | T1078 | [SEQ]-v2 |
| XCO-003 | Reconfig hyperviseur **suivie** d'une effraction | Changement de config (HYP-009/010) puis effraction (ALM-003) sur le même objet | audit SEAL × alarme SEAL | High | T1565 / T1562 | [SEQ]-v2 |

## 6. Dead-man switches — supervision du flux (**créés DÉSACTIVÉS**)

> **Ne pas activer** tant que le flux ne coule pas : une règle d'absence se
> déclenche immédiatement à vide → faux positif permanent. Créées **disabled**,
> activation **post-recette** (`provision_detections.py` les crée avec
> `?schedule=false` ; activation manuelle dans Graylog ou re-run après validation
> du flux). Motif *go-dark* : **aucun `group_by`**, `count() < 1` (une aggregation
> à vide sans group_by évalue bien `count = 0`).

| ID | Titre | Requête Graylog (D4) | group_by | Seuil | Fenêtre | Sév. | Réf. | Notif. | Statut |
|---|---|---|---|---|---|---|---|---|---|
| DMS-001 | Flux **Audit** interrompu (>15 min, tous sites) | `event_source:seal AND event_domain:hypervisor_audit` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-002 | Flux **Accès** interrompu (>15 min, tous sites) | `event_source:seal AND event_domain:access` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-003 | Flux **Alarmes** interrompu (>15 min, tous sites) | `event_source:seal AND event_domain:alarm` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |

### 6.1 Dead-man switches **par site** (multi-site) — créés DÉSACTIVÉS

> **Motif** : DMS-001/002/003 surveillent l'arrêt d'un **domaine tous sites
> confondus** ; si **un seul** site (`bx-qa-seal-vm` **ou** `bx-seal-omega`) se tait
> alors que l'autre continue d'émettre, ils restent **muets**. Les variantes ci-dessous
> ajoutent un DMS par **(domaine × site)** pour détecter qu'un site précis décroche.
> Même motif *go-dark* (aucun `group_by`, `count() < 1`), **créés `disabled`**
> (activation post-recette, cf. §5 points d'attention). Générées par boucle dans
> `provision_detections.py` (`SEAL_SITES × _DMS_SITE_DOMAINS`).

| ID | Titre | Requête Graylog (D4) | group_by | Seuil | Fenêtre | Sév. | Réf. | Notif. | Statut |
|---|---|---|---|---|---|---|---|---|---|
| DMS-004 | Flux **Audit** interrompu — site `bx-qa-seal-vm` | `event_source:seal AND event_domain:hypervisor_audit AND seal_site:"bx-qa-seal-vm"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-005 | Flux **Audit** interrompu — site `bx-seal-omega` | `event_source:seal AND event_domain:hypervisor_audit AND seal_site:"bx-seal-omega"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-006 | Flux **Accès** interrompu — site `bx-qa-seal-vm` | `event_source:seal AND event_domain:access AND seal_site:"bx-qa-seal-vm"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-007 | Flux **Accès** interrompu — site `bx-seal-omega` | `event_source:seal AND event_domain:access AND seal_site:"bx-seal-omega"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-008 | Flux **Alarmes** interrompu — site `bx-qa-seal-vm` | `event_source:seal AND event_domain:alarm AND seal_site:"bx-qa-seal-vm"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |
| DMS-009 | Flux **Alarmes** interrompu — site `bx-seal-omega` | `event_source:seal AND event_domain:alarm AND seal_site:"bx-seal-omega"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immédiat | désactivé (recette) |

> **Attention activation** : à n'activer (`--enable-deadman`) qu'**après** avoir
> confirmé que **chaque** site émet réellement sur **chaque** domaine. Un site qui
> n'émet légitimement pas un domaine (ex. pas d'alarme configurée) déclencherait un
> FP permanent → n'activer que les DMS par site des couples réellement alimentés.

---

## Récapitulatif

- **37 règles** : 12 HYP · 7 ACC · 4 ALM · 2 EVT · 3 XCO · 9 DMS (3 globaux + 6 par site).
- **Provisionnées Graylog** (`provision_detections.py`) : **23 aggregations actives**
  (dont 4 `[SEQ]-approx` dépendant d'un flag pipeline, + HYP-012 multi-site) +
  **9 dead-man switches désactivés** (3 globaux DMS-001/002/003 + 6 par site
  DMS-004..009) = 32 event definitions.
- **Reportées v2** (`oms-xdr`, non Graylog) : ACC-005, ALM-002, XCO-001/002/003 = 5.
- **Notification immédiate** (Adaptive Card Teams) : Critical + High
  (HYP-001/002/005/007, ACC-001/004, ALM-001/003, + DMS à l'activation).
  **Digest** (Medium/Info, dont HYP-012 multi-site) : le reste.
  La carte porte désormais `seal_site` par ligne de backlog (**quel site**).

## Points d'attention

1. **Streams pré-requis** : les 3 streams SEAL (D0) doivent exister avant
   provisioning ; sinon `provision_detections.py` saute la règle avec un WARN.
2. **Dépendances pipeline** : `off_hours`, `badge_known`, `alert_tag:seal_bf_then_success`
   sont posés par le pipeline SEAL (Phase 3). Tant qu'ils n'existent pas, les règles
   `[SEQ]-approx` **ne matchent rien** (silencieux, pas de FP) — à vérifier en recette.
3. **Champs `seal_payload`** : approximation v1 pour les transitions (MasterKeys,
   Status badge, IS_INHIBITED, IS_INTEMPESTIVE). À promouvoir en champs D4 dédiés v2.
4. **Seuils QA→prod** : calibrés sur QA (~158 ev/24 h). Re-calibrer avant bascule prod.
5. **Dead-man switches** : rester **désactivés** jusqu'à flux stable (sinon FP immédiat).
   Pour les DMS **par site** (§6.1), n'activer que les couples (domaine × site)
   réellement alimentés (sinon FP permanent sur un domaine légitimement muet côté un site).
6. **Seuils multi-site (revue, à décider avant activation d'agrégats par entité)** :
   les règles de rafale/cardinalité par **porte / badge / compte / IP** agrègent
   aujourd'hui **tous sites confondus** (`group_by` sans `seal_site`). Deux effets à
   trancher en recette prod :
   - **Collision de libellés inter-sites** : un même `target_object_label` (ou
     `door_id`) peut désigner **deux portes physiques distinctes** sur `bx-qa-seal-vm`
     et `bx-seal-omega`. ACC-006 (accès refusés/porte), ACC-007, EVT-002, ALM-001/003/004
     mélangent alors deux portes sous une seule clé → seuil atteint « à cheval » ou
     attribution ambiguë. **Reco** : ajouter `seal_site` au `group_by` de ces règles
     (clé = site + objet) — **non appliqué en v1** pour ne pas modifier le comportement
     des règles actives en prod ; à valider puis appliquer en lot.
   - **Seuils par site vs cumulés** : brute force (HYP-001), refus répétés (ACC-006),
     flood capteur (ALM-004) — un seuil global peut masquer une attaque localisée sur
     un seul site (bruit de l'autre) **ou** cumuler à tort. Décider par règle si le
     seuil doit être **par site** (via `seal_site` au `group_by`) ou rester cumulé.
   - **Piste multi-site nouvelle** : HYP-012 (compte console sur ≥2 sites) couvre le
     compte partagé / latéral. Un équivalent **badge cross-site** (même `badge_number`
     accordé sur les 2 sites dans un délai incompatible) relève d'une **corrélation de
     séquence** (multi-stream + délai) → **candidat `oms-xdr` v2** (cf. XCO), non
     exprimable en aggregation simple ici.
