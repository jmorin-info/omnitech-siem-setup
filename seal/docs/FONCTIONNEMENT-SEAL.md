# Fonctionnement de SEAL — hyperviseur de sûreté physique

**OMNITECH SECURITY — document d'analyse technique**
**Version 2 — 16/07/2026** (v1 corrigée : voir [§0](#0-ce-qui-change-depuis-la-v1))
Destination : support à la rédaction de la documentation ISO 27001 du contrôle
d'accès (A.5.15 contrôle d'accès, A.5.16 gestion des identités, A.5.18 droits
d'accès, A.7.1 à A.7.4 sécurité physique).

Base d'analyse : extraction du **modèle complet de la base SEAL de production**
(`BX-SEAL-OMEGA`, 16/07/2026) — **358 tables**, 1 255 vues, relations, volumes, et
contenu des tables de paramétrage. Complétée par 1,7 M d'événements réellement
collectés dans le SIEM.

---

## 0. Ce qui change depuis la v1

La v1 avait été écrite sans accès à la base (le compte de service ne voit que
5 vues). L'extraction de la structure réelle **contredit trois de ses conclusions**.
Elles sont corrigées ici.

| Point | v1 (déduit) | v2 (mesuré) |
|---|---|---|
| **Pont badge → AD** | « la donnée n'existe pas, c'est une dette de gouvernance » | **Faux.** `milf.BADGES` contient une colonne `MATRICULE` sur **443 badges**, reliée aux fiches par `SEAL_ID`. La donnée existe : elle n'est simplement pas exposée au SIEM. |
| **Topologie des zones** | hiérarchie « parent → enfant » avec libellé et classe | **Faux.** La table n'a que 4 colonnes et utilise un `hierarchyid` SQL Server. Aucun libellé, aucune classe. Mon script de vue zone était bâti sur une hypothèse erronée. |
| **Restrictions horaires** | « SEAL sait gérer des semaines types » | **Vrai en théorie, inutilisé en pratique** : il n'existe que **2 semaines types** — `Toujours` et `Jamais`. |

C'est la raison d'être de l'extraction : trois affirmations plausibles, trois
démentis. Le reste de la v1 est confirmé.

---

## Sommaire

1. [Architecture](#1-architecture)
2. [Le modèle du contrôle d'accès](#2-le-modèle-du-contrôle-daccès)
3. [Identités et badges](#3-identités-et-badges)
4. [Administration : comptes, profils, traçabilité](#4-administration--comptes-profils-traçabilité)
5. [Zones et topologie](#5-zones-et-topologie)
6. [Le second système d'accès : ENIQ / DOMBOX](#6-le-second-système-daccès--eniq--dombox)
7. [Le vocabulaire des événements](#7-le-vocabulaire-des-événements)
8. [Constats pour l'ISO 27001](#8-constats-pour-liso-27001)
9. [Ce qui reste à établir](#9-ce-qui-reste-à-établir)

---

## 1. Architecture

SEAL est l'hyperviseur de sûreté physique d'OMNITECH : contrôle d'accès (badges,
portes, lecteurs), détection d'intrusion (capteurs, secteurs, mise en service),
interface vidéo, et supervision du matériel.

**Deux instances**, bases SQL Server autonomes, sans référentiel commun :

| Site | Machine | Rôle |
|---|---|---|
| QA | `bx-qa-seal-vm` | recette |
| Production | `bx-seal-omega` | exploitation |

**Chaîne de terrain** : les **UTL/ULS** (unités de traitement locales) portent
l'intelligence : elles décident des accès localement, à partir d'une copie des
droits qui leur est descendue, et remontent leurs événements au serveur. Le
serveur SEAL n'est donc pas dans le chemin de décision — une porte continue de
fonctionner s'il tombe.

Cette architecture est visible dans le modèle : `AccessControl.Deployments` (40
déploiements), `dbo.ULS_STATS` (état, versions, clés, capacité), `dbo.ACTION`
(file d'actions à descendre), `dbo.ULS_KEYS` (9 clés cryptographiques), et
`dbo.DROITS_ATOMIQUES_EFFECTIFS` — la table des droits **calculés** qui alimente
les contrôleurs.

### Ordres de grandeur (production, 16/07/2026)

| Objet | Volume |
|---|--:|
| Objets physiques (`Objet_Fiche`) | **932** |
| Portes déployées (`AccessControl.DeployedDoors`) | **165** |
| Fiches / porteurs (`FICHE`) | **443** |
| Badges Millefeuille (`milf.BADGES`) | **443** |
| Droits saisis (`DROIT`) | **493** |
| Droits effectifs calculés (`DROITS_ATOMIQUES_EFFECTIFS`) | **1 903** |
| Conflits de droits (`DROITS_ATOMIQUES_CONFLITS`) | **32** |
| Groupes de badges (`GROUPEFICHE`) | **57** |
| Comptes console (`UTILISATEUR`) | **59** |
| Profils console (`T_PROFILS`) | **14** |
| Permissions DOMBOX (`ENIQ_INTERFACE_PERMISSIONS`) | **4 169** |
| Événements historisés (`EVENEMENTS_HIST`) | 504 792 |
| Alarmes historisées (`ALARMES_HIST`) | 285 598 |
| Passages (`T_PASSAGES`) | 45 623 |

---

## 2. Le modèle du contrôle d'accès

### 2.1 Le squelette réel

```
    FICHE (443)                                    Objet_Fiche (932)
   « le porteur »                                « portes, lecteurs, UTL… »
        │                                                │
        ├──── LIENFICHEGROUPE (608) ────► GROUPEFICHE (57)
        │     LIENFICHEGROUPE_ENABLE          « groupe de badges »
        │     (dates + heures d'activation)    porte les règles d'usage :
        │                                      maître-clés, immunités APB/APT,
        │                                      mode escorte, semaine type
        │                                                │
        └──────────────► DROIT (493) ◄──────────────────┘
                    fiche × porte × semaine type
                    × date début / date fin
                                │
                                ▼  (calcul)
              DROITS_ATOMIQUES_EFFECTIFS (1 903)
        le droit RÉEL, descendu dans les contrôleurs :
        FICH_ID, PORT_ID, SEM_TYPE_ID, NUMPHYS, JOURS_FERIES,
        MAITRE_CLES, IMMUN_DBLBDG, MODE_ESCORTE, IMMUN_APB,
        IMMUN_APT, VIP_OTIS, ENTREE, SORTIE, CODE_PIN_UTL
                                │
                    DROITS_ATOMIQUES_CONFLITS (32)
```

**Distinction essentielle pour la documentation** : SEAL sépare le droit **saisi**
(`DROIT`, ce qu'un gestionnaire a demandé) du droit **effectif**
(`DROITS_ATOMIQUES_EFFECTIFS`, ce que le contrôleur applique réellement, après
fusion des droits directs, des droits hérités des groupes, et arbitrage des
conflits). C'est le second qui fait foi. Une revue des droits ISO doit porter sur
lui — et sur les **32 conflits** détectés.

Le système matérialise même les conflits dans une table dédiée
(`DROITS_ATOMIQUES_CONFLITS`, avec les colonnes `ON_MAITRE_CLES`, `ON_IMMUN_APB`,
`ON_MODE_ESCORTE`…) : il sait dire *sur quel attribut* deux sources de droit se
contredisent. C'est un point fort à valoriser.

### 2.2 Les dimensions du droit

Chaque droit effectif porte :

| Dimension | Colonne | Enjeu ISO |
|---|---|---|
| Qui | `FICH_ID` / `NUMPHYS` | A.5.16 |
| Où | `PORT_ID` | A.5.15 |
| Quand (semaine) | `SEM_TYPE_ID` | A.5.15 |
| Quand (dates) | `DROI_APPLI_DATE_DEB/FIN`, `ENTREE`/`SORTIE` | A.5.18 |
| Jours fériés | `JOURS_FERIES` | A.5.15 |
| **Passe général** | `MAITRE_CLES` | **privilège élevé** |
| Anti-pass-back | `IMMUN_APB` | dérogation |
| Anti-timeback | `IMMUN_APT` | dérogation |
| Double badgeage | `IMMUN_DBLBDG` | dérogation |
| Mode escorte | `MODE_ESCORTE` | A.7.2 visiteurs |
| Code PIN | `CODE_PIN_UTL` | second facteur |

### 2.3 Le temps : une capacité réelle, non utilisée

```
dbo.SEMAINE_TYPE     →  2 lignes : « Toujours », « Jamais »
dbo.JOUR_TYPE        →  2 lignes : « Tout au long du jour », « A aucun moment »
dbo.TRANCHE_HORAIRE  →  8 lignes
```

SEAL sait modéliser des semaines types, des jours types et des tranches horaires.
**Aucune restriction horaire réelle n'est configurée** : les deux seules semaines
types sont les deux extrêmes. Un droit est donc « toujours valable » ou « jamais ».

Conséquence directe : **le contrôle d'accès d'OMNITECH n'applique aucune
restriction temporelle**. Le champ `off_hours` calculé dans le SIEM est une
information *observée* (l'accès a eu lieu hors heures ouvrées), pas une règle
*appliquée* par SEAL. C'est un écart à documenter — ou une décision à assumer
explicitement.

---

## 3. Identités et badges

### 3.1 Deux modules superposés

SEAL gère les porteurs à deux niveaux :

- **`dbo.FICHE` (443)** — le noyau : `FICH_NUM`, `FICH_STATUT` (VAL/ANN),
  `FICH_DATCREATION`, `IS_ANONYMOUS`, `MOTIF_ANNULATION`. Les attributs métier
  sont en champs personnalisables (`CHAMP_FICHE` 88 définitions →
  `DETAIL_FICHE` 18 605 valeurs, dont la photo `DFIC_VAL_PHOTO`).
- **`milf.BADGES` (443)** — le module **Millefeuille** : le badge « physique »
  et administratif, avec un modèle bien plus riche.

Les deux sont reliés par `milf.BADGES.SEAL_ID → dbo.FICHE.FICH_ID`.

### 3.2 `milf.BADGES` contient le matricule — correction majeure

`milf.BADGES` porte, entre autres :

```
MATRICULE varchar(32)        ← l'identifiant attendu
BADGE_NUMBER / PHYSICAL_NUMBER / SERIAL_NUMBER / ALTERNATE_BADGE_NUMBER
LAST_NAME / FIRST_NAME / BIRTH_DATE / PHOTO / QR_CODE
STATUS / ACCESS_FROM / ACCESS_TO / CANCELED / CANCELATION_REASON
CREATED / DELIVERED / PRINTED / ENCODED / RENEWED / RENEW_COUNTER
COMPANY / DEPARTMENT_SERVICE / USER_TYPE / USER_FUNCTION / CONTRACT_TYPE
MEDICAL_CHECKUP_EXPIRATION
SECURITY_TRAINING_VALIDITY_END
AUTHORIZATION_ATEX_EXPIRATION / _NH3_ / _ZSAR_ / _N1_N2_ / _HARBOUR_AGENT_
```

**Deux conséquences importantes.**

1. **Le pont badge → AD n'est ni impossible, ni cassé : le référentiel est à
   moitié rempli.** Mesuré le 16/07 sur `vw_SealIdentity_SIEM` :

   | Site | Porteurs | Avec `MATRICULE` | Avec `badge_number` |
   |------|---------:|-----------------:|--------------------:|
   | **OMEGA (production)** | 443 | **187 (42,2 %)** | 439 (99,1 %) |
   | QA | 98 | 19 (19,4 %) | 61 (62,2 %) |

   Deux conclusions antérieures étaient **fausses**, et il faut le dire :
   - « il manque un identifiant rattachable à l'annuaire, c'est de la
     gouvernance » → **faux** : `MATRICULE` existe sur 443 badges ;
   - « la vue exposée au SIEM ne va pas chercher le matricule » → **faux
     également** : `05_vw_SealIdentity_SIEM.sql` et `02_vw_SealEvents_SIEM.sql`
     font bien `b.MATRICULE AS identity_matricule`.

   Le fait réel : **le matricule n'est saisi que pour 42 % des porteurs** en
   production. Le pont fonctionne donc pour deux badges sur cinq. Ce n'est ni un
   correctif technique, ni une impossibilité — c'est un **remplissage de
   référentiel** (saisie), qui relève de la gestion des badges.

   Conséquence sur la détection : `EVT-002` (« badge inconnu ») se déclenchait sur
   les 58 % restants, tous légitimes — d'où son parcage et son remplacement par
   `DQ-001`, qui mesure et suit ce taux au lieu d'alerter dessus. Dès que le taux
   de remplissage sera significatif, `EVT-002` se réactive en une commande.

2. **SEAL porte des données d'habilitation métier** : visite médicale, formation
   sécurité, habilitations ATEX / NH3 / ZSAR / N1-N2, agent portuaire, avec leurs
   dates d'expiration. Ce n'est pas un simple contrôle d'accès : c'est un
   référentiel d'habilitations. À citer dans le périmètre du SMSI.

> `milf.LinkTagBadge` (lien badge ↔ tag) est **vide (0 ligne)**. Le lien entre les
> deux modules passe donc par `SEAL_ID`, pas par cette table.

### 3.3 Cycle de vie

`FICH_STATUT` : `VAL` (valide) / `ANN` (annulé), avec `MOTIF_ANNULATION` et
`DESCRIPTION_ANNULATION`. Côté Millefeuille : `CREATED` → `PRINTED` → `ENCODED` →
`DELIVERED` → `RENEWED` (avec `RENEW_COUNTER`) → `CANCELED`.

Le passage `ANN → VAL` (réactivation d'un badge retiré) est possible et surveillé
par le SIEM (détection ACC-004). La procédure devrait l'interdire.

### 3.4 La synchronisation LDAP existe et n'est pas utilisée

```
dbo.SYNCHRO_LDAP           → 0 ligne
dbo.SYNCHRO_LDAP_OBJET     → 0 ligne
dbo.SYNCHRO_LDAP_HISTORY   → 0 ligne
dbo.LDAP_PRE_SYNCHRO_TABLE → 0 ligne
```

Pourtant `CHAMP_FICHE` possède les colonnes `CFIC_LDAP_ATTRIBUT`,
`CFIC_LDAP_ATTRIBUT_WAY`, `CFIC_LDAP_MUST_CREATE`, et il existe un profil
« Profil par défaut import LDAP ». **La capacité de synchroniser SEAL avec
l'annuaire est installée mais inexploitée.** C'est probablement le vrai levier
pour fiabiliser le lien identité ↔ badge, et pour aligner les départs.

---

## 4. Administration : comptes, profils, traçabilité

### 4.1 Les 14 profils réels

| ID | Profil | Admin | Exclu Admin | Exclu Exploit. | Exclu API |
|---|---|---|---|---|---|
| 1 | **ADMINISTRATEURS** | **oui** | non | non | non |
| 3 | Opérateurs vidéo | non | non | non | oui |
| 4 | Relecteurs vidéo | non | non | non | oui |
| 5 | GESTIONNAIRES DE BADGES | non | oui | non | oui |
| 7 | UTILISATEUR STANDARD | non | oui | non | oui |
| 8 | CLÉS DES ULS | non | oui | non | **non** |
| 9 | OPERATEUR ALARME *(« En test »)* | non | oui | non | oui |
| 10 | Sonorisation | non | oui | oui | oui |
| 11 | DFS#TRS#GRP#MAGIC1 *(« DR Saran gestion badge »)* | non | oui | non | oui |
| 14 | Profil par défaut import LDAP | non | oui | oui | oui |
| 15 | UTILISATEUR AVEC API | non | oui | non | **non** |
| 16 | SEAL To Agrid | non | oui | oui | **non** |
| 17 | **TESTGBE** | non | oui | non | oui |
| 18 | **PGE Test droit sur éqpt** | non | oui | non | oui |

Trois observations pour la revue des droits (A.5.18) :

- **Deux profils de test en production** : `TESTGBE` (17) et `PGE Test droit sur
  éqpt` (18). Le second a été créé le 26/06/2026 et modifié cinq fois le jour même.
- Un profil au nom non parlant : `DFS#TRS#GRP#MAGIC1`.
- Un profil marqué « En test » : `OPERATEUR ALARME` (9).

Le modèle de droits console est : `UTILISATEUR` → `PRO_ID` (profil) →
`T_FONC_PROFIL` (105 associations) → `FONCTIONNALITES` (**219** fonctionnalités
atomiques). Des surcharges par utilisateur existent (`FONC_UTIL`, 404 lignes) —
donc **un compte peut avoir des droits hors de son profil** : la revue ne peut pas
se limiter aux profils.

`ALLOWED_PROFILE_SWITCHES` : 2 bascules autorisées (1 → 18, 8 → 9). Un
administrateur peut basculer vers le profil de test 18.

### 4.2 Le stockage des mots de passe console

`dbo.UTILISATEUR` (59 comptes) contient **à la fois** :

```
UTI_PASSW      varchar(50)  NOT NULL   ← champ mot de passe en clair (héritage)
UTI_SEED       varbinary(32)           ← sel
UTI_HASH_PASS  varbinary(32)           ← empreinte
PASS_HASH_ALGO varchar(50)
```

La colonne `UTI_PASSW` est **NOT NULL** : elle contient forcément quelque chose sur
les 59 comptes. C'est un héritage classique (ancienne authentification) qui devrait
être vide ou neutralisé. **Contenu non lu** (interdit par le contrat d'interface) —
mais l'existence même de cette colonne mérite une question à l'éditeur, et une
vérification. `UTILISATEUR_PASSWORD_HISTORY` (15 lignes) stocke, elle, sel + hash.

Le modèle gère par ailleurs correctement : `UTI_IS_LOCKEDOUT`,
`UTI_FAILED_PASSWORD_ATTEMPT_COUNT` (+ fenêtre), `UTI_MUST_RENEW_PWD`,
`UTI_LAST_PASSWORD_CHANGED_DATE`, `NO_PASSWORD_EXPIRATION`, `IS_WINDOWS_ACCOUNT`,
`DATE_DEBUT`/`DATE_FIN`. Les mécanismes attendus existent.

### 4.3 La traçabilité : native et granulaire

Le schéma `Audit` compte 15 tables de mouvements. Chacune conserve l'**avant et
l'après** (`*Old` / `New*`), le compte auteur, le canal et l'horodatage local + UTC.

`Audit.AccountsMovements` trace jusqu'aux bascules de privilège :
`OldIsAdmin`/`NewIsAdmin`, `OldCanAccessExternalApi`/`New…`,
`OldCanAccessSealAdministration`/`New…`, `OldCanAccessSealExploitation`/`New…`,
`OldIsLock`/`NewIsLock`, `OldMustRenewPassword`/`New…`.

`Audit.LogDownload` trace les **exports de journaux** (qui, quand, quel volume,
quelle borne temporelle) — rare, et précieux pour A.5.28.

`Audit.AccessControlPermissionMovements` (225) trace chaque changement de droit :
tag, groupe, porte, groupe de portes, dates avant/après, semaine type avant/après.

**C'est le point fort du système.** À valoriser tel quel dans le SMSI.

> Un second journal, `dbo.TRACES` (**499 971 lignes** : module, sous-module,
> utilisateur, description), existe et **n'est pas collecté par le SIEM**. À
> examiner : il peut contenir des actions non couvertes par le schéma `Audit`.

### 4.4 La main courante est vide

`dbo.MAIN_COURANTE` : **0 ligne**. `dbo.VACATIONS` : 1 178 vacations d'opérateur.

Les opérateurs ouvrent donc des vacations, mais **ne consignent rien**. Combiné à
l'acquittement d'alarme quasi inexistant (6 lignes sur 703 641), cela signifie :
**aucune trace de l'action humaine sur les événements de sûreté**. C'est l'écart le
plus structurant du dossier (A.5.24 / A.5.25).

---

## 5. Zones et topologie

### 5.1 La structure réelle (et pourquoi ma v1 se trompait)

```sql
Hypervision.ObjectsHierarchicalCatalog   -- 49 lignes
    NodeHierarchyId   hierarchyid   -- clé primaire : le CHEMIN dans l'arbre
    NodeId            bigint
    NodeObjectId      numeric       -- l'objet porté par le nœud
    NodeObjectType    varchar(50)   -- son type
```

Quatre colonnes. **Pas de `ParentNodeId`, pas de `NodeLabel`, pas de `NodeClass`.**
La hiérarchie est portée par le type `hierarchyid` de SQL Server : la parenté se
lit avec `.GetAncestor()`, `.IsDescendantOf()`, `.GetLevel()` — pas par une
jointure sur un identifiant parent.

C'est pourquoi ma vue `07_vw_SealZone_SIEM.sql` était bâtie sur du sable : elle
supposait un modèle parent/enfant classique. **Elle est à réécrire**, et le
garde-fou du lanceur (`<-- ajuster`) a joué son rôle : il vous a empêché de
déployer une vue fausse.

### 5.2 Les bonnes pistes

L'éditeur fournit ses propres outils, qu'il vaut mieux utiliser que réinventer :

| Objet | Ce qu'il donne |
|---|---|
| `Hypervision.fn_GetObjectsCatalogPath` | **le chemin d'un nœud** — exactement le `ZONE_PATH` recherché |
| `Hypervision.fn_GetObjectCatalogSubTree` | le sous-arbre d'un nœud |
| `Hypervision.View_ObjectsHierarchicalCatalogNodeDetails` | les détails d'un nœud (libellés) |
| `dbo.POS_OBJECTS_IN_ZONES_CACHE` (54) | **objet → zone**, déjà calculé (`SOURCE_ID` → `TARGET_ID`) |
| `dbo.POS_ZONES_IN_ZONES_CACHE` (1) | zone → sous-zone, avec niveau relatif |
| `dbo.MAP_ITEMS_FLAT` (149) | `OBJECT_ID` → `PARENT_ID` aplati |
| `dbo.ObjectsNodesTree` (16) | `NodeId`, `ParentNodeId`, `NodeName`, `SealObjectId` |
| `dbo.pk_GetZonesForObjectFromCache` | procédure éditeur : les zones d'un objet |

`POS_OBJECTS_IN_ZONES_CACHE` (54 lignes) est la piste la plus directe : c'est le
cache objet → zone que SEAL utilise déjà pour ses plans. À confronter aux **165
portes déployées** : 54 associations ne couvriront pas tout le parc.

### 5.3 Une autre voie, plus riche : `T_PASSAGES`

```
dbo.T_PASSAGES   -- 45 623 lignes
    PASS_ID, FICH_ID, NUM_PHYS, CONT_ID, PASS_DATE_PASSAGE,
    PASS_VALIDE, REFU_ID, ZONE_OBFI_ID, ZONE_IN_OUT, EVEN_ID, REEV_CODE
```

Cette table relie **le passage, la fiche (le porteur), la zone et le sens
(entrée/sortie)** — et fait le lien avec l'événement (`EVEN_ID`). C'est
structurellement une meilleure source que `EVENEMENTS` pour répondre à « qui est
allé où, dans quel sens » : l'identité et la zone y sont déjà résolues.

Elle n'est pas exposée au SIEM aujourd'hui. **C'est sans doute la piste la plus
rentable** — elle résout d'un coup le lien identité *et* le lien zone.

---

## 6. Le second système d'accès : ENIQ / DOMBOX

Le schéma `ENIQ` décrit un contrôle d'accès **parallèle**, à base de cylindres
électroniques autonomes (DOMBOX / OSS) :

| Table | Lignes |
|---|--:|
| `ENIQ_INTERFACE_PERMISSIONS` | **4 169** |
| `ENIQ_INTERFACE_DEVICES` | 42 |
| `ENIQ_INTERFACE_WEEKS` | 32 |
| `ENIQ_INTERFACE_HOLIDAYS` | 22 |
| `ENIQ_INTERFACE_DEVICES_COUPLED` | 63 |
| `ENIQ_INTERFACE_PERMISSIONS_OSS` | 0 |

**4 169 permissions** y sont définies — soit plus du double des 1 903 droits
effectifs du contrôle d'accès câblé. Ces cylindres fonctionnent **hors ligne** : ils
portent leurs droits en mémoire, sont synchronisés par lots, et leurs événements
ne remontent qu'à la synchronisation suivante (`LAST_EVENT_ID`,
`DOMBOX: Perte d'évènements`, `DOMBOX: décalage d'horloge` dans le référentiel).

**Ce périmètre n'est ni collecté par le SIEM, ni couvert par la documentation en
cours.** Il faut décider s'il entre dans le périmètre du SMSI. Les permissions
ENIQ portent d'ailleurs leurs propres conflits (`WEEK_TEMPLATE_CONFLICT`,
`HOLIDAYS_CONFLICT`, `MASTER_KEY_CONFLICT`, `HAS_CONFLICTS`).

À noter aussi : `dbo.TAG_KEYRING_ASSOCIATION` et `AGRID_*` (armoires à clés
Traka/Agrid) — encore un autre mode d'accès physique (clés mécaniques gérées).

---

## 7. Le vocabulaire des événements

`dbo.REF_EVENEMENT` : **150 codes sur OMEGA** (177 sur QA, **197 en union**). C'est
le dictionnaire complet de ce que SEAL sait dire.

La table est plus riche qu'un simple libellé — chaque code porte :

| Colonne | Rôle |
|---|---|
| `REEV_DFLT_SEVERITY` | sévérité par défaut (0 à 901) |
| `REEV_AL_USER_DESCRIPTION_PATTERN` | gabarit de la phrase d'alarme |
| `REEV_EVEN_USER_DESCRIPTION_PATTERN` / `_END` | gabarit début / fin d'événement |
| `REEV_INTEMPESTIVEOCCUR` / `MAXEVENT` / `PERIOD` | **seuils anti-flood par code** |
| `REEV_TRANSTYPE`, `REEV_DELAYTRANSFERT` | politique de transfert |

Les gabarits révèlent la sémantique : `Refus de [AccessBy] sur [OriginLabel], badge
interdit sur cette ULS. [UserComment]`. Les variables `[AccessBy]`, `[OriginLabel]`,
`[UserComment]` sont substituées à l'exécution — c'est ainsi que SEAL fabrique ses
descriptions lisibles.

**Le paramétrage anti-flood est uniforme** : presque tous les codes ont
`INTEMPESTIVEOCCUR = 60`, `MAXEVENT = 1000`, `PERIOD = 1` — c'est-à-dire les valeurs
par défaut. Seul `SEM542` (centrale intrusion déconnectée) est réglé finement
(10/10/6). Autrement dit : **la qualification « intempestive » n'est pas paramétrée
pour le parc**.

Répartition des 197 codes (union des deux sites) :

| Famille | Codes |
|---|--:|
| Matériel — lecteurs, modules, UTL, capteurs | 54 |
| Porte — état physique et commandes | 36 |
| Intrusion, sabotage, agression | 28 |
| Accès usager — autorisation et refus | 25 |
| Mise en service / hors service (secteurs) | 13 |
| Vidéo et détection | 5 |
| Véhicules et boucles | 2 |
| Console et administration | 2 |
| Système et supervision | 2 |
| Divers (boutons, DOMBOX, LoRa…) | 30 |

Les **25 codes de refus** décrivent toutes les conditions de la décision : badge
interdit sur l'ULS, hors semaine type (de l'usager *ou* de la porte), hors
calendrier, usager non valide à cette date, anti-pass-back, zone pleine (compteur
global ou individuel), code PIN incorrect, usager « brûlé » (trop d'essais), badge
représenté trop tôt, séquence de badgeage incorrecte, porte bloquée, jour férié.

Le référentiel complet (code → libellé) est fourni en CSV, annexable tel quel.

---

## 8. Constats pour l'ISO 27001

Chiffrés, vérifiables, classés par gravité.

### 8.1 Aucune trace de l'action humaine (A.5.24, A.5.25)

- Main courante : **0 ligne**.
- Acquittement d'alarme : **6 lignes sur 703 641**.
- Vacations ouvertes : 1 178.

Les opérateurs prennent leur poste mais ne consignent rien et n'acquittent rien.
**Il est impossible de démontrer qu'une alarme a été traitée, ni par qui.** Aucun
correctif technique ne comble cela : c'est une pratique d'exploitation.

### 8.2 Aucune restriction horaire (A.5.15)

2 semaines types : `Toujours`, `Jamais`. Le contrôle d'accès est binaire. À
documenter comme décision assumée, ou à corriger.

### 8.3 Un périmètre entier hors radar (A.5.15, A.8.16)

4 169 permissions sur cylindres DOMBOX/ENIQ, non supervisées, non documentées.
Décision de périmètre à prendre.

### 8.4 Des comptes et profils de test en production (A.5.18)

Profils `TESTGBE`, `PGE Test droit sur éqpt`, `OPERATEUR ALARME (En test)` ;
comptes `TESTGBE`, `seal_server_app_test`. Une revue s'impose.

### 8.5 Le lien identité ↔ badge n'est pas exploité (A.5.16, A.5.18)

Le matricule existe (`milf.BADGES.MATRICULE`, 443 badges) mais n'est pas exposé au
SIEM ; la synchronisation LDAP est installée mais vide. **Corrigeable** — voir §9.

### 8.6 `UTI_PASSW varchar(50) NOT NULL` (A.5.17)

Une colonne « mot de passe » en clair coexiste avec le sel et l'empreinte, sur
59 comptes. Contenu non lu. À éclaircir avec l'éditeur.

### 8.7 Ce qui fonctionne bien — à valoriser

- **Traçabilité d'administration native** : 15 tables de mouvements, avant/après
  sur chaque changement, imputable à un compte, une IP et un canal.
- **Modèle de droits complet** : validité, semaine type, anti-pass-back,
  anti-timeback, mode escorte, passes généraux, code PIN, jours fériés.
- **Détection native des conflits de droits** (32 conflits identifiés, avec
  l'attribut en cause).
- **Séparation droit saisi / droit effectif** : le système sait dire ce qui est
  réellement appliqué.
- **Export de journaux tracé** (`Audit.LogDownload`).
- **Référentiel d'habilitations métier** (médical, ATEX, NH3, ZSAR, formation).
- **Supervision externalisée** : le SIEM surveille en continu les gestes sensibles
  (passe général, réactivation de badge, inhibition d'alarme, export de journaux),
  ce qui apporte une **séparation des tâches** entre exploitant sûreté et SOC.

---

## 9. Ce qui reste à établir

Trois questions, une requête chacune. Script fourni : `06_recon_complements.sql`.

1. **Taux de remplissage du matricule** — décide si le pont badge → AD est
   immédiat ou s'il faut d'abord peupler la donnée.
   ```sql
   SELECT COUNT(*) AS badges, COUNT(MATRICULE) AS avec_matricule,
          COUNT(SEAL_ID) AS relies_a_une_fiche
   FROM milf.BADGES WHERE MILF_STATUS <> 'ANN';
   ```
2. **Couverture du cache de zones** — décide de la faisabilité du `seal_zone`.
   ```sql
   SELECT COUNT(*) AS objets_dans_une_zone,
          COUNT(DISTINCT TARGET_ID) AS zones
   FROM dbo.POS_OBJECTS_IN_ZONES_CACHE;
   ```
3. **`T_PASSAGES` : la piste courte** — si `ZONE_OBFI_ID` et `FICH_ID` sont bien
   remplis, cette table résout identité *et* zone d'un coup.
   ```sql
   SELECT COUNT(*) AS passages, COUNT(FICH_ID) AS avec_fiche,
          COUNT(ZONE_OBFI_ID) AS avec_zone, COUNT(NULLIF(ZONE_IN_OUT,'')) AS avec_sens
   FROM dbo.T_PASSAGES;
   ```

Utile en complément : la **documentation éditeur** (manuel d'administration), pour
confirmer la sémantique de `MODE_ESCORTE`, des immunités, et du lien
`milf.BADGES` ↔ `FICHE`.

---

## Annexe — traçabilité de l'analyse

Toutes les valeurs proviennent de `05_recon_fonctionnel.sql` exécuté sur
`BX-SEAL-OMEGA` le **16/07/2026 à 09:28** (métadonnées + tables de paramétrage
uniquement — aucune donnée personnelle lue), et des mesures SIEM du même jour.
La base est vivante : les volumes bougent, les ordres de grandeur et les ratios
non. Les chiffres SQL décrivent **OMEGA** ; les taux de remplissage cités en v1
décrivaient **QA** — les deux parcs diffèrent, ne pas les confondre.
