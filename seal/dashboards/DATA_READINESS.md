# DATA_READINESS.md — Checkpoint d'entrée Phase 6 (Dashboards SEAL)

OMNITECH SECURITY · MISSION_SEAL_GRAYLOG Phase 6 · repo `omnitech-siem-setup/seal`
Date de contrôle : 2026-07-15.

> **STATUT : PRÊT (mis à jour 15/07 après-midi).** Le flux réel coule : DDL
> exécuté, Logstash en collecte, **backfill complet effectué** (1,67 M lignes,
> 0 erreur). Les 3 streams sont peuplés avec l'historique normalisé. La porte
> d'entrée Phase 6 est franchie ; la matrice de faisabilité (§2) reste la
> référence des widgets à provisionner. **Reste : validation opérateur de la
> matrice, puis provisioning des dashboards.**

---

## 1. Prérequis Phase 6 — état vérifié (bloquant)

| Prérequis | Attendu | Observé (2026-07-15) | Verdict |
|---|---|---|---|
| Événements réels `event_domain:access` /24 h | > 0 | **0** | ❌ |
| Événements réels `event_domain:alarm` /24 h | > 0 | **0** | ❌ |
| Événements réels `event_domain:hypervisor_audit` /24 h | > 0 | **0** | ❌ |
| Injections de synthèse `TEST_SIEM` (à ignorer) | — | 6 (mes tests E2E Phase 3) | ℹ️ |
| Logstash installé + actif (VM SIEM) | actif | **inactif / non installé** | ❌ |
| `seal.conf` déployé | présent | **absent** | ❌ |
| Vues `vw_Seal*_SIEM` créées (DDL Phase 1) | 4 vues | **aucune** | ❌ |

**Conclusion : la chaîne de collecte n'est pas encore établie.** Les widgets se
mesureraient tous à zéro → non vérifiables. On s'arrête ici (conforme au
rappel de séquencement de la mission).

### Chemin critique pour lever le blocage (ordre imposé, côté opérateur)
1. **DDL SEAL** (SSMS admin) : `seal/sql/01_ → 05_ + 90_provision.sql`. Sans les
   vues, les inputs JDBC échouent. Rappel : rowversion sur `EVENEMENTS` =
   réécriture de table → fenêtre de maintenance (instantané en QA).
2. **Socle Logstash** : `install-logstash-siem.sh` (fourni, prêt, idempotent) sur
   la VM SIEM → paquet + plugins GELF/JDBC + driver mssql-jdbc + keystore.
3. **Déployer** `seal/logstash/seal.conf` + `seal/logstash/sql/*.sql`, renseigner
   le keystore (secrets Vaultwarden), tester `logstash -t`, démarrer.
4. Laisser tourner **quelques heures** (idéalement 24 h incluant une plage ouvrée)
   pour un échantillon représentatif, puis **repasser ce contrôle** : les 3 lignes
   de volume doivent être > 0.

---

## 2. Matrice de faisabilité des widgets (dérivée du CONTRAT, à confirmer sur données)

Cette matrice ne dépend pas des volumes : elle découle du **contrat de champs**
(`seal/docs/CONTRACT.md`) et de la logique des vues SQL (quels champs sont peuplés
vs connus vides). Elle permet de savoir *à l'avance* quels widgets seront
`FAISABLE` et lesquels sont `[BLOQUÉ: dépend de X]`, pour ne pas provisionner de
panneau trompeusement vide.

### 2.1 Réalité de peuplement des champs (par domaine)

| Champ (contrat D4) | access | alarm | hypervisor_audit | Remarque |
|---|---|---|---|---|
| `event_source`,`event_domain`,`timestamp` | ✅ | ✅ | ✅ | posés par vue/collecteur |
| `event_action` | ✅ (via alarme corrélée) | ✅ REEV_LIBELLE | ✅ Operation | access : dépend de l'alarme liée |
| `event_outcome` (grant/deny/na) | ✅ | ✅ | ✅ (success/failure) | dérivé REEV (144 deny/255 grant mesurés en base) |
| `severity_num` | — | ✅ EVEN_SEVERITE | ✅ mapping | — |
| `actor_usercode` | — | ✅ | ✅ | — |
| `actor_login` | — | — | ✅ (`seal_Login`) | console : UserConnections |
| `src_ip` | — | — | ✅ (`seal_IpAddress`) | — |
| `operation_channel` | — | — | ✅ | SealAdmin/Exploitation… |
| `badge_number` | ✅ | (si déclencheur) | ✅ (`seal_Number`) | — |
| `identity_matricule` | ⚠️ ~76,5 % | — | — | badge→milf.BADGES ; ~23,5 % non résolus |
| **`identity_upn`** | ❌ **vide** | ❌ **vide** | ❌ **vide** | non résolu en QA (SIEM-side, non câblé) |
| `target_object_label/id/type` | ⚠️ ~62 % | ✅ | ✅ (`seal_Object*`) | access : `RAW_ORIGIN_OBFI_ID` NULL ~38 % |
| **`site`** | ❌ **NULL** | ❌ **NULL** | ❌ **NULL** | topologie non mappée (NodeObjectId≠OBJ_ID) |
| **`door_id`** | ❌ absent | ❌ absent | ⚠️ audit only (`seal_DoorId`) | access : porte = `target_object_label` |
| `off_hours` | ✅ | — | ✅ | heure locale 07–19 |
| `IS_INHIBITED`,`IS_INTEMPESTIVE`,`INTEMPESTIVE_COUNT` | — | ✅ | — | colonnes directes |
| `seal_source_table`,`seal_payload`,`seal_*` | — | — | ✅ | JSON éclaté |

Légende : ✅ peuplé · ⚠️ partiel · ❌ vide/bloqué · — non applicable au domaine.

### 2.2 Widgets par vue — faisable vs bloqué

**Vue A — SOC opérationnel** (public : exploitant ; fenêtre 15 min–24 h)

| Widget | Requête (streams SEAL) | Statut |
|---|---|---|
| Compteur refus d'accès 1 h | `event_domain:access AND event_outcome:deny` | FAISABLE |
| Compteur connexions console échouées 1 h | `event_domain:hypervisor_audit AND event_action:ConnectionFailure` | FAISABLE |
| Compteur alarmes actives | `event_domain:alarm AND NOT _exists_:END_EVEN_ID` | FAISABLE (à confirmer) |
| Flux dernières alarmes (table) | `event_domain:alarm` → time, `severity_num`, `target_object_label`, `event_outcome` | FAISABLE |
| Top 10 badges en refus /24 h | `event_domain:access AND event_outcome:deny` group by `badge_number` | FAISABLE (fallback badge) ; **`identity_upn` [BLOQUÉ: identity_upn]** |
| Console : échecs récents | `hypervisor_audit AND event_action:ConnectionFailure` → `actor_login`,`src_ip`,`operation_channel` | FAISABLE |
| Refus par **porte** | group by `target_object_label` (PAS `door_id` sur access) | FAISABLE ⚠️ ~62 % objets résolus |
| Refus **par site** | group by `site` | **[BLOQUÉ: site]** |

**Vue B — Pilotage & preuve d'audit** (public : RSSI/Bureau Veritas ; 7/30/90 j)

| Widget | Requête | Statut |
|---|---|---|
| Volume par `event_domain` dans le temps (empilé) | `event_source:seal` group by `event_domain` histogram | FAISABLE — **preuve A.8.15** |
| Répartition grant/deny dans le temps | `event_domain:access` group by `event_outcome` histogram | FAISABLE |
| Mouvements de droits (table) | `hypervisor_audit AND seal_source_table:(AccessControlPermissionMovements OR AccountsMovements OR ProfilesMovements OR ProfileRoleMovements OR TagMovements)` | FAISABLE — **cœur A.8.16** |
| Activations passe/immunité | `hypervisor_audit AND seal_source_table:TagMovements AND (seal_MasterKeys:true OR seal_ApbImmunity:true OR seal_AptImmunity:true OR seal_DoubleBadgedImmunity:true)` | FAISABLE (à confirmer noms `seal_*`) |
| Créations/élévations comptes opérateurs | `hypervisor_audit AND seal_source_table:AccountsMovements` | FAISABLE |
| Top comptes opérateurs par volume d'admin | `hypervisor_audit` group by `actor_usercode`/`actor_login` | FAISABLE |
| Exports de journaux dans le temps | `hypervisor_audit AND seal_source_table:LogDownload` | FAISABLE — méta-supervision |
| Tendance par **site** | group by `site` | **[BLOQUÉ: site]** |

**Vue C — Santé de la supervision** (public : RSSI/SOC)

| Widget | Requête | Statut |
|---|---|---|
| Fraîcheur par domaine (âge dernier événement) | 3× `event_domain:X` → dernier `timestamp` | FAISABLE |
| Débit par domaine (evt/heure) | `event_source:seal` group by `event_domain` histogram 1 h | FAISABLE |
| État des 3 dead man's switches | définitions DMS-001/002/003 (créées désactivées Phase 4) | FAISABLE une fois DMS activés |
| Latence de collecte (écart timestamp vs réception) | nécessite champ d'écart | **[BLOQUÉ: champ latence non normalisé]** — voir §4 |

---

## 3. Volumétrie observée (à remplir une fois le flux établi)

| Domaine | Volume total (backfill) | Champs peuplés | Prêt pour widgets ? |
|---|---|---|---|
| access | **961 268** | event_action/outcome/off_hours/badge_number ; ~62 % target_object ; ~76 % identity_matricule | OUI |
| alarm | **703 636** | event_action(REEV)/outcome/severity_num/IS_INHIBITED/IS_INTEMPESTIVE | OUI |
| hypervisor_audit | **3 557** | Operation/actor_usercode ; actor_login/src_ip/target_* (audit console) | OUI |

Ordres de grandeur observés (30 j) : refus d'accès `event_outcome:deny` ≈ 147.
Rappels bloqués (§2/§4) inchangés : `site`=NULL, `identity_upn` vide.
Incrémental actif : nouveaux événements collectés en continu (~30 s).

---

## 4. Recommandations d'évolution (hors périmètre Phase 6 — NE PAS corriger ici)

Signalées comme le demande la mission (§5), sans les implémenter :
1. **`site` NULL** : établir le mapping topologie avec l'opérateur
   (`ObjectsHierarchicalCatalog` : espace d'ID distinct de `Objet_Fiche.OBJ_ID`).
   Débloque tous les widgets « par site » (A et B).
2. **`identity_upn` vide en QA** : câbler la résolution matricule→AD/M365 côté SIEM
   (règle miroir `13-identity-mirror.rule`). Débloque le pivot identité et la
   corrélation croisée XCO. En attendant, les widgets retombent sur `badge_number`.
3. **Latence de collecte** (Vue C) : aucun champ ne porte l'écart
   `timestamp_événement` vs réception Graylog. Poser un champ dédié dans le
   pipeline (ex. delta calculé) si ce widget est jugé prioritaire pour l'audit.
4. **`target_object_*` ~62 % sur access** : les 38 % d'événements sans
   `RAW_ORIGIN_OBFI_ID` n'ont pas d'objet cible → widgets « par porte » côté access
   sous-comptent. À accepter ou à enrichir en amont.

---

## 5. Décision demandée (checkpoint d'entrée)
1. Lancer le chemin critique §1 (DDL → Logstash → collecte) puis laisser tourner.
2. Valider la matrice §2 (widgets faisables vs bloqués) — notamment : accepte-t-on
   les widgets `access` « par porte » à ~62 %, et le fallback `badge_number` en
   l'absence d'`identity_upn` ?
3. Sur flux réel confirmé, je provisionne les 3 vues (widgets FAISABLE uniquement)
   via `provision_dashboards.py` idempotent, puis recette widget-par-widget.

**→ Arrêt au checkpoint d'entrée Phase 6. En attente de l'établissement du flux réel
et de la validation de cette matrice avant tout provisioning.**
