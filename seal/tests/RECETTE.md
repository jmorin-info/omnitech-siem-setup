# RECETTE — Intégration SEAL → Graylog (QA UNIQUEMENT)

OMNITECH SECURITY · SIEM (`omnitech-siem-setup`) · MISSION_SEAL_GRAYLOG
Autorité : `seal/docs/CONTRACT.md`. Périmètre : `bx-qa-seal-vm.omnitech.security`
(`10.33.120.2:1433`) — **jamais la production**.

> Cette recette valide la chaîne complète
> SEAL (SQL) → vues SIEM → Logstash (JDBC, watermark) → GELF `10.33.220.10:12201`
> → streams/pipelines Graylog → détections → notifications Teams.
> Elle combine (A) des actions manuelles dans l'IHM SEAL QA, (B) une injection
> SQL synthétique marquée `TEST_SIEM` pour les cas non reproductibles à l'IHM
> (`inject_synthetic.sql` / `cleanup.sql`), et (C) le test des 3 dead man's switches.

## Pré-requis avant recette

- [ ] DDL appliqué (`sql/01..05` + `90_provision.sql`) : colonnes `EVEN_ROWVER`
      (EVENEMENTS) et `RowVer` (15 tables `Audit.*`) présentes, vues
      `vw_SealEvents_SIEM` / `vw_SealAlarms_SIEM` / `vw_SealAudit_SIEM` /
      `vw_SealIdentity_SIEM` créées, login `svc_graylog_seal` restreint aux vues
      (cf. RECON §9.6).
- [ ] Logstash installé (plugin `jdbc` + `mssql-jdbc`), pipeline SEAL démarré,
      chaîne JDBC épinglée IP `10.33.120.2` + `hostNameInCertificate=<FQDN>`,
      `encrypt=true;trustServerCertificate=false`. Secret via keystore Logstash
      (jamais en clair).
- [ ] Graylog : 3 streams (`OMNI - SEAL Accès` / `Alarmes` / `Audit`), pipelines
      de normalisation (contrat D4), Data Adapter CSV `REEV_CODE → REEV_LIBELLE`
      régénéré, notification Teams (`TEAMS_WEBHOOK_URL`) branchée sur les
      définitions d'événement SEAL.
- [ ] Watermarks seedés à la valeur courante (pas de rapatriement d'historique,
      cf. CONTRACT D5). Vérifier `MIN_ACTIVE_ROWVERSION()` non bloqué par une
      transaction ouverte.
- [ ] Fenêtre horaire QA calme (volumétrie ~158 événements/24 h) pour lecture claire.

Pour chaque test : noter l'**heure d'injection**, l'**heure d'arrivée** du message
dans Graylog (`Search` filtré `event_source:seal`), et la **latence** observée.

---

## A. Recette assistée — actions IHM SEAL QA

Convention de recherche Graylog pour chaque étape :
`event_source:seal AND actor_usercode:TEST_SIEM*` (si scénario injecté) ou filtre
sur `actor_login` / `door_id` / `operation_channel` selon le cas.

### A1. Échec de connexion ×5 puis succès (console) — HYP-001 / HYP-002
- **Action IHM** : sur `SEAL Exploitation` ou console `SealAdmin`, tenter 5
  connexions avec un mauvais mot de passe pour un même compte de test, puis 1
  connexion réussie.
- **Table source** : `Audit.UserConnections` (`Operation` = `ConnectionFailure` ×5
  puis `Connection`).
- **Vérifications attendues** :
  1. Arrivée : 6 messages `event_domain:hypervisor_audit`,
     `event_action:"Connection*"` sous 1 cycle de watermark (~30 s).
  2. Normalisation (contrat D4) : `event_outcome=failure` sur les 5 échecs,
     `success` sur le 6e ; `actor_login`, `src_ip` (`IpAddress`), `user_agent`,
     `operation_channel` renseignés.
  3. Détection : **HYP-001** (≥5 `ConnectionFailure` / fenêtre / même login) se
     déclenche. **HYP-002 [SEQ]** (échecs répétés PUIS succès) se déclenche si
     l'approximation par état de pipeline est active ; sinon consigner « reporté
     v2 » (édition Open, cf. CONTRACT D0).
  4. Teams : notification reçue (titre HYP-001, `actor_login`, compte d'échecs).

### A2. Réactivation d'un badge de test — ACC-004
- **Action IHM** : dans SEAL Millefeuille, prendre un badge **annulé** (`ANN`) et
  le repasser **valide** (`VAL`).
- **Table source** : `Audit.TagMovements` (transition `ANN → VAL`).
- **Vérifications** :
  1. Arrivée : message `event_domain:hypervisor_audit`, `badge_number` = numéro
     du badge de test.
  2. Normalisation : transition de statut lisible (contrat D3 : `ANN→VAL =
     réactivation`) ; `identity_matricule` résolu si le badge est dans `milf.BADGES`.
  3. Détection : **ACC-004** (réactivation de badge) se déclenche.
  4. Teams : notification reçue.

### A3. Élévation de privilège d'un compte de test (OldIsAdmin 0→1)
- **Action IHM** : sur un compte opérateur de test, cocher le rôle
  administrateur (`SealAdmin`).
- **Table source** : `Audit.AccountsMovements` (`OldIsAdmin=0 → NewIsAdmin=1`).
  Voir aussi `Audit.AccountRolesMovements` / `ProfileRoleMovements`.
- **Vérifications** :
  1. Arrivée : message audit, `target_login` = compte modifié.
  2. Normalisation : `event_action` reflète l'octroi de droit admin,
     `actor_usercode` = opérateur ayant fait la modif.
  3. Détection : règle « octroi de privilège administrateur SEAL » se déclenche
     (référence détection : *à figer au backlog Phase 4* ; classe MITRE
     Privilege Escalation).
  4. Teams : notification reçue.

### A4. Commande manuelle sur une porte de test — CommandObject
- **Action IHM** : depuis le mur d'exploitation, envoyer une commande manuelle
  (ouverture/déverrouillage) sur une **porte de test**.
- **Table source** : `Audit.CommandObject` (`ObjectType` porte, `ObjectId` /
  `ObjectLabel` de la porte de test).
- **Vérifications** :
  1. Arrivée : message audit avec `target_object_type`, `target_object_id`,
     `target_object_label`, `door_id` renseignés.
  2. Normalisation : `event_action` = commande, `actor_usercode` = opérateur ;
     `site` résolu via `ObjectsHierarchicalCatalog` si mappé.
  3. Détection : règle « commande manuelle de porte » se déclenche (surveillance
     des ouvertures hors flux d'accès normal).
  4. Teams : notification reçue.

### A5. Inhibition d'une alarme de test — ALM (inhibition)
- **Action IHM** : inhiber (`IS_INHIBITED`) une alarme active de test dans la
  supervision.
- **Table source** : `dbo.ALARMES` (`IS_INHIBITED` bascule ; rowversion `VERSION`
  ré-émis sur UPDATE de cycle de vie).
- **Vérifications** :
  1. Arrivée : message `event_domain:alarm` reflétant l'inhibition.
  2. Normalisation : `severity_num` = `EVEN_SEVERITE`, `event_action` =
     `REEV_LIBELLE` décodé, indicateur d'inhibition présent dans `seal_payload`.
  3. Détection : règle « inhibition d'alarme » se déclenche (action opérateur
     potentiellement masquante — à corréler).
  4. Teams : notification reçue.

### A6. Effraction / porte forcée de test — ALM-003
- **Action IHM** (si banc le permet) : forcer un contact de porte de test
  (ouverture physique non autorisée) OU simuler via l'injection (voir §B).
- **Table source** : `dbo.EVENEMENTS` / `dbo.ALARMES` (`REEV_CODE` = **SEM113**
  effraction, compl. SEM105 ouverture physique signalée).
- **Vérifications** :
  1. Arrivée : message `event_domain:alarm`, `event_action` = « Effraction porte ».
  2. Normalisation : décodage `SEM113 → REEV_LIBELLE` via lookup CSV OK
     (pas de `SEM113` brut dans `event_action`).
  3. Détection : **ALM-003** (porte forcée) se déclenche.
  4. Teams : notification reçue (priorité haute).

### A7. Export de journal — LogDownload
- **Action IHM** : déclencher un export/téléchargement de journal depuis la console.
- **Table source** : `Audit.LogDownload`.
- **Vérifications** :
  1. Arrivée : message audit `event_domain:hypervisor_audit`.
  2. Normalisation : `actor_usercode`, `operation_channel`, volume/objet exporté
     dans `seal_payload`.
  3. Détection : règle « export de journaux SEAL » se déclenche (surveillance
     d'exfiltration / MITRE Collection).
  4. Teams : notification reçue.

### A8. Connexion sur la console d'administration — HYP-003
- **Action IHM** : se connecter via le canal **`SealAdmin`**.
- **Table source** : `Audit.UserConnections` (`OperationChannel = SealAdmin`).
- **Vérifications** :
  1. Arrivée : message audit, `operation_channel:SealAdmin`.
  2. Normalisation conforme D4.
  3. Détection : **HYP-003** (accès console admin) se déclenche.
  4. Teams : notification reçue.

### A9. Accès badge nominal — EVT-001 / EVT-002
- **Action IHM** : passer un badge **connu** puis un badge **inconnu** sur un
  lecteur de test.
- **Table source** : `dbo.EVENEMENTS` (`REEV_CODE` SEM138/SEM280) + lookup
  `AcApi.TAG` / `milf.BADGES` pour la connaissance du badge.
- **Vérifications** :
  1. **EVT-001** : accès usager normalisé (`event_outcome=grant`), matricule
     résolu (~76,5 % de couverture attendue, cf. RECON §9.3).
  2. **EVT-002** : badge **inconnu** (absent des tables de badges) → alerte.
  3. Teams : notification EVT-002 reçue pour le badge inconnu.

---

## B. Tableau de couverture — règle par règle (à remplir)

Latence = arrivée message → notification. FP = faux positif (O/N + commentaire).
Renseigner la colonne « Réf. script » avec le script de détection `seal/detections`
correspondant une fois figé au backlog Phase 4.

| Règle | Libellé | Source / condition | Déclenchée (O/N) | Latence | FP (O/N) | Réf. script | Notes |
|---|---|---|---|---|---|---|---|
| EVT-001 | Accès usager (badge connu) | EVENEMENTS SEM138/SEM280 | | | | | |
| EVT-002 | Badge inconnu | accès sans badge connu (AcApi.TAG/milf.BADGES) | | | | | |
| ACC-004 | Réactivation badge | TagMovements `ANN→VAL` | | | | | |
| ACC-PRIV* | Octroi admin SEAL | AccountsMovements `OldIsAdmin 0→1` | | | | | *code à figer |
| ACC-CMD* | Commande manuelle porte | CommandObject (porte) | | | | | *code à figer |
| ALM-001 | Cycle de vie alarme | ALARMES transitions (VERSION) | | | | | |
| ALM-002 [SEQ] | Alarme non acquittée | absence d'`ACK` sous délai | | | | | approx. état pipeline / v2 |
| ALM-003 | Effraction / porte forcée | REEV_CODE SEM113 (+SEM105) | | | | | |
| ALM-004 | Alarme intempestive / flood | IS_INTEMPESTIVE / SEM287/193/187 | | | | | |
| ALM-INH* | Inhibition d'alarme | ALARMES `IS_INHIBITED` | | | | | *code à figer |
| HYP-001 | Brute force console | UserConnections ≥5 `ConnectionFailure` | | | | | |
| HYP-002 [SEQ] | Échecs puis succès | 5 échecs → 1 succès (même login) | | | | | approx. état pipeline / v2 |
| HYP-003 | Accès console admin | OperationChannel `SealAdmin` | | | | | |
| AUD-LOGDL* | Export de journaux | LogDownload | | | | | *code à figer |
| XCO-* | Corrélation croisée badge↔logon Windows | SEAL ↔ Winlogbeat BX-QA-SEAL-VM | | | | | v2 / approx. Open |
| DMS-ACCESS | Dead man access | silence flux `omni-seal-access` | | | | | cf. §C |
| DMS-ALARM | Dead man alarmes | silence flux `omni-seal-alarm` | | | | | cf. §C |
| DMS-AUDIT | Dead man audit | silence flux `omni-seal-audit` | | | | | cf. §C |

---

## C. Test des 3 dead man's switches (silence de source)

Objectif : prouver que l'arrêt du flux SEAL (agent mort, coupure JDBC, journal
désactivé par un attaquant) déclenche une alerte de **source silencieuse** par
stream. Réutilise le motif du watchdog SIEM (`74-source-watchdog.sh`,
`alert_tag=source_silent`) étendu aux 3 sources SEAL :
`seal_access`, `seal_alarm`, `seal_audit`.

Chaque flux alimente un stream/index distinct (CONTRACT D5 : 3 vues, 3
watermarks). Les 3 DMS sont donc **indépendants**.

### Procédure
1. **Baseline** : vérifier que les 3 streams reçoivent (fraîcheur < seuil).
   Générer au besoin 1 événement par flux (§A ou §B) pour horodater le `last_seen`.
2. **Configurer les seuils** DMS pour SEAL (fichier `/etc/default/omni-watchdog`) :
   ex. `seal_access:30,seal_alarm:30,seal_audit:30` (minutes) — adapter à la
   cadence QA. Un seuil ≤ 20 min garantit un déclenchement pendant la fenêtre de test.
3. **Arrêter Logstash 20 min** (arrêt du transport, pas de la base) :
   `sudo systemctl stop logstash` (noter l'heure). Aucun DDL, aucune écriture SQL.
4. **Attendre le passage du watchdog** (timer 15 min) au-delà du seuil.
5. **Vérifications attendues** :
   - 3 alertes distinctes `alert_tag=source_silent` pour `seal_access`,
     `seal_alarm`, `seal_audit`.
   - 3 notifications Teams distinctes (une par stream).
   - Aucune fausse alerte sur les autres sources SIEM.
6. **Rétablir** : `sudo systemctl start logstash`. Le watermark reprend au dernier
   `sql_last_value` — vérifier qu'il **rattrape** les événements de la fenêtre
   d'arrêt (pas de perte) et que les 3 DMS **repassent au vert** au cycle suivant.

### Grille DMS (à remplir)

| DMS | Stream / source | Seuil (min) | Heure stop Logstash | Heure alerte | Notif Teams (O/N) | Repassé vert (O/N) | Rattrapage OK (O/N) |
|---|---|---|---|---|---|---|---|
| DMS-ACCESS | `omni-seal-access` / `seal_access` | | | | | | |
| DMS-ALARM | `omni-seal-alarm` / `seal_alarm` | | | | | | |
| DMS-AUDIT | `omni-seal-audit` / `seal_audit` | | | | | | |

> Note complémentaire (hors périmètre DMS transport) : le signal de vie UTL
> `SEM70/SEM71` (RECON §9.2) est un dead-man **capteur** côté SEAL, distinct des
> 3 DMS de transport ci-dessus. À couvrir séparément au backlog détection.

---

## Nettoyage

Après recette : `cleanup.sql` (supprime tout marqueur `TEST_SIEM`). Les messages
déjà ingérés dans Graylog restent dans les index SEAL (rétention 12/12/24 mois) —
les filtrer par `actor_usercode:TEST_SIEM*` pour les distinguer. Redémarrer
Logstash si arrêté pour le test C.

## Points d'attention

- **Non-régression volumétrie** : après recette, confirmer que le débit SEAL
  redescend à la baseline (~158 évts/24 h) — pas de boucle de watermark.
- **Édition Open** : les règles `[SEQ]` (HYP-002, ALM-002, XCO-*) peuvent être en
  approximation par état de pipeline ou reportées v2 ; consigner le statut réel
  observé, ne pas marquer « échec » si la limite est documentée (CONTRACT D0).
- **RGPD** : vérifier qu'aucun message SEAL n'expose une colonne interdite
  (CONTRACT D1) — inspecter un échantillon de chaque stream (pas de photo, nom,
  hash de mot de passe, etc.).
