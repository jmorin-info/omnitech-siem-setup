# How SEAL works — physical security hypervisor

**OMNITECH SECURITY — technical analysis document**
**Version 2 — 16/07/2026** (v1 corrected: see [§0](#0-what-changes-since-v1))
Intended use: support for drafting the ISO 27001 documentation for access
control (A.5.15 access control, A.5.16 identity management, A.5.18 access
rights, A.7.1 to A.7.4 physical security).

Analysis basis: extraction of the **complete model of the production SEAL database**
(`BX-SEAL-OMEGA`, 16/07/2026) — **358 tables**, 1,255 views, relationships, volumes, and
the content of the configuration tables. Supplemented by 1.7 M events actually
collected in the SIEM.

---

## 0. What changes since v1

v1 had been written without access to the database (the service account only sees
5 views). The extraction of the real structure **contradicts three of its conclusions**.
They are corrected here.

| Point | v1 (inferred) | v2 (measured) |
|---|---|---|
| **Badge → AD bridge** | "the data does not exist, it is a governance debt" | **False.** `milf.BADGES` contains a `MATRICULE` column on **443 badges**, linked to the records by `SEAL_ID`. The data exists: it is simply not exposed to the SIEM. |
| **Zone topology** | "parent → child" hierarchy with label and class | **False.** The table has only 4 columns and uses a SQL Server `hierarchyid`. No label, no class. My zone view script was built on a wrong assumption. |
| **Time restrictions** | "SEAL can manage typical weeks" | **True in theory, unused in practice**: there are only **2 typical weeks** — `Toujours` and `Jamais`. |

This is the raison d'être of the extraction: three plausible assertions, three
refutations. The rest of v1 is confirmed.

---

## Contents

1. [Architecture](#1-architecture)
2. [The access control model](#2-the-access-control-model)
3. [Identities and badges](#3-identities-and-badges)
4. [Administration: accounts, profiles, traceability](#4-administration-accounts-profiles-traceability)
5. [Zones and topology](#5-zones-and-topology)
6. [The second access system: ENIQ / DOMBOX](#6-the-second-access-system-eniq--dombox)
7. [The event vocabulary](#7-the-event-vocabulary)
8. [Findings for ISO 27001](#8-findings-for-iso-27001)
9. [What remains to be established](#9-what-remains-to-be-established)

---

## 1. Architecture

SEAL is OMNITECH's physical security hypervisor: access control (badges,
doors, readers), intrusion detection (sensors, sectors, arming),
video interface, and hardware supervision.

**Two instances**, standalone SQL Server databases, without a common repository:

| Site | Machine | Role |
|---|---|---|
| QA | `bx-qa-seal-vm` | acceptance |
| Production | `bx-seal-omega` | operations |

**Field chain**: the **UTL/ULS** (local processing units) carry
the intelligence: they decide accesses locally, from a copy of the
rights pushed down to them, and report their events to the server. The
SEAL server is therefore not in the decision path — a door keeps
working if it goes down.

This architecture is visible in the model: `AccessControl.Deployments` (40
deployments), `dbo.ULS_STATS` (state, versions, keys, capacity), `dbo.ACTION`
(queue of actions to push down), `dbo.ULS_KEYS` (9 cryptographic keys), and
`dbo.DROITS_ATOMIQUES_EFFECTIFS` — the table of **computed** rights that feeds
the controllers.

### Orders of magnitude (production, 16/07/2026)

| Object | Volume |
|---|--:|
| Physical objects (`Objet_Fiche`) | **932** |
| Deployed doors (`AccessControl.DeployedDoors`) | **165** |
| Records / holders (`FICHE`) | **443** |
| Millefeuille badges (`milf.BADGES`) | **443** |
| Rights entered (`DROIT`) | **493** |
| Effective rights computed (`DROITS_ATOMIQUES_EFFECTIFS`) | **1,903** |
| Rights conflicts (`DROITS_ATOMIQUES_CONFLITS`) | **32** |
| Badge groups (`GROUPEFICHE`) | **57** |
| Console accounts (`UTILISATEUR`) | **59** |
| Console profiles (`T_PROFILS`) | **14** |
| DOMBOX permissions (`ENIQ_INTERFACE_PERMISSIONS`) | **4,169** |
| Historized events (`EVENEMENTS_HIST`) | 504,792 |
| Historized alarms (`ALARMES_HIST`) | 285,598 |
| Passages (`T_PASSAGES`) | 45,623 |

---

## 2. The access control model

### 2.1 The real skeleton

```
    FICHE (443)                                    Objet_Fiche (932)
   "the holder"                                 "doors, readers, UTL…"
        │                                                │
        ├──── LIENFICHEGROUPE (608) ────► GROUPEFICHE (57)
        │     LIENFICHEGROUPE_ENABLE          "badge group"
        │     (dates + activation hours)      carries the usage rules:
        │                                      master keys, APB/APT immunities,
        │                                      escort mode, typical week
        │                                                │
        └──────────────► DROIT (493) ◄──────────────────┘
                    record × door × typical week
                    × start date / end date
                                │
                                ▼  (computation)
              DROITS_ATOMIQUES_EFFECTIFS (1,903)
        the REAL right, pushed down into the controllers:
        FICH_ID, PORT_ID, SEM_TYPE_ID, NUMPHYS, JOURS_FERIES,
        MAITRE_CLES, IMMUN_DBLBDG, MODE_ESCORTE, IMMUN_APB,
        IMMUN_APT, VIP_OTIS, ENTREE, SORTIE, CODE_PIN_UTL
                                │
                    DROITS_ATOMIQUES_CONFLITS (32)
```

**Essential distinction for the documentation**: SEAL separates the **entered** right
(`DROIT`, what a manager requested) from the **effective** right
(`DROITS_ATOMIQUES_EFFECTIFS`, what the controller actually applies, after
merging direct rights, rights inherited from groups, and arbitration of
conflicts). It is the latter that is authoritative. An ISO rights review must focus on
it — and on the **32 conflicts** detected.

The system even materializes the conflicts in a dedicated table
(`DROITS_ATOMIQUES_CONFLITS`, with the columns `ON_MAITRE_CLES`, `ON_IMMUN_APB`,
`ON_MODE_ESCORTE`…): it can say *on which attribute* two sources of a right
contradict each other. This is a strength to highlight.

### 2.2 The dimensions of a right

Each effective right carries:

| Dimension | Column | ISO stake |
|---|---|---|
| Who | `FICH_ID` / `NUMPHYS` | A.5.16 |
| Where | `PORT_ID` | A.5.15 |
| When (week) | `SEM_TYPE_ID` | A.5.15 |
| When (dates) | `DROI_APPLI_DATE_DEB/FIN`, `ENTREE`/`SORTIE` | A.5.18 |
| Public holidays | `JOURS_FERIES` | A.5.15 |
| **Master pass** | `MAITRE_CLES` | **high privilege** |
| Anti-pass-back | `IMMUN_APB` | exception |
| Anti-timeback | `IMMUN_APT` | exception |
| Double badging | `IMMUN_DBLBDG` | exception |
| Escort mode | `MODE_ESCORTE` | A.7.2 visitors |
| PIN code | `CODE_PIN_UTL` | second factor |

### 2.3 Time: a real capability, unused

```
dbo.SEMAINE_TYPE     →  2 rows: "Toujours", "Jamais"
dbo.JOUR_TYPE        →  2 rows: "Tout au long du jour", "A aucun moment"
dbo.TRANCHE_HORAIRE  →  8 rows
```

SEAL can model typical weeks, typical days and time slots.
**No real time restriction is configured**: the only two typical
weeks are the two extremes. A right is therefore "always valid" or "never".

Direct consequence: **OMNITECH's access control applies no
time restriction**. The `off_hours` field computed in the SIEM is
*observed* information (the access occurred outside working hours), not a rule
*applied* by SEAL. This is a gap to document — or a decision to own
explicitly.

---

## 3. Identities and badges

### 3.1 Two superimposed modules

SEAL manages holders at two levels:

- **`dbo.FICHE` (443)** — the core: `FICH_NUM`, `FICH_STATUT` (VAL/ANN),
  `FICH_DATCREATION`, `IS_ANONYMOUS`, `MOTIF_ANNULATION`. The business attributes
  are in customizable fields (`CHAMP_FICHE` 88 definitions →
  `DETAIL_FICHE` 18,605 values, including the photo `DFIC_VAL_PHOTO`).
- **`milf.BADGES` (443)** — the **Millefeuille** module: the "physical"
  and administrative badge, with a much richer model.

The two are linked by `milf.BADGES.SEAL_ID → dbo.FICHE.FICH_ID`.

### 3.2 `milf.BADGES` contains the matricule — major correction

`milf.BADGES` carries, among others:

```
MATRICULE varchar(32)        ← the expected identifier
BADGE_NUMBER / PHYSICAL_NUMBER / SERIAL_NUMBER / ALTERNATE_BADGE_NUMBER
LAST_NAME / FIRST_NAME / BIRTH_DATE / PHOTO / QR_CODE
STATUS / ACCESS_FROM / ACCESS_TO / CANCELED / CANCELATION_REASON
CREATED / DELIVERED / PRINTED / ENCODED / RENEWED / RENEW_COUNTER
COMPANY / DEPARTMENT_SERVICE / USER_TYPE / USER_FUNCTION / CONTRACT_TYPE
MEDICAL_CHECKUP_EXPIRATION
SECURITY_TRAINING_VALIDITY_END
AUTHORIZATION_ATEX_EXPIRATION / _NH3_ / _ZSAR_ / _N1_N2_ / _HARBOUR_AGENT_
```

**Two important consequences.**

1. **The badge → AD bridge is neither impossible nor broken: the reference data is
   half filled.** Measured on 16/07 on `vw_SealIdentity_SIEM`:

   | Site | Holders | With `MATRICULE` | With `badge_number` |
   |------|---------:|-----------------:|--------------------:|
   | **OMEGA (production)** | 443 | **187 (42.2%)** | 439 (99.1%) |
   | QA | 98 | 19 (19.4%) | 61 (62.2%) |

   Two earlier conclusions were **false**, and it must be said:
   - "an identifier attachable to the directory is missing, it is a
     governance matter" → **false**: `MATRICULE` exists on 443 badges;
   - "the view exposed to the SIEM does not fetch the matricule" → **also
     false**: `05_vw_SealIdentity_SIEM.sql` and `02_vw_SealEvents_SIEM.sql`
     do perform `b.MATRICULE AS identity_matricule`.

   The real fact: **the matricule is only entered for 42% of the holders** in
   production. The bridge therefore works for two badges out of five. This is neither a
   technical fix nor an impossibility — it is a **reference-data
   fill** (data entry), which falls under badge management.

   Consequence for detection: `EVT-002` ("unknown badge") was triggering on
   the remaining 58%, all legitimate — hence its parking and its replacement by
   `DQ-001`, which measures and tracks this rate instead of alerting on it. As soon as the
   fill rate is significant, `EVT-002` is reactivated with a single command.

2. **SEAL carries business authorization data**: medical checkup, security
   training, ATEX / NH3 / ZSAR / N1-N2 authorizations, harbour agent, with their
   expiration dates. This is not a mere access control: it is an
   authorization repository. To be mentioned in the ISMS scope.

> `milf.LinkTagBadge` (badge ↔ tag link) is **empty (0 rows)**. The link between the
> two modules therefore goes through `SEAL_ID`, not through this table.

### 3.3 Life cycle

`FICH_STATUT`: `VAL` (valid) / `ANN` (canceled), with `MOTIF_ANNULATION` and
`DESCRIPTION_ANNULATION`. On the Millefeuille side: `CREATED` → `PRINTED` → `ENCODED` →
`DELIVERED` → `RENEWED` (with `RENEW_COUNTER`) → `CANCELED`.

The transition `ANN → VAL` (reactivation of a withdrawn badge) is possible and monitored
by the SIEM (detection ACC-004). The procedure should forbid it.

### 3.4 LDAP synchronization exists and is not used

```
dbo.SYNCHRO_LDAP           → 0 rows
dbo.SYNCHRO_LDAP_OBJET     → 0 rows
dbo.SYNCHRO_LDAP_HISTORY   → 0 rows
dbo.LDAP_PRE_SYNCHRO_TABLE → 0 rows
```

Yet `CHAMP_FICHE` has the columns `CFIC_LDAP_ATTRIBUT`,
`CFIC_LDAP_ATTRIBUT_WAY`, `CFIC_LDAP_MUST_CREATE`, and there is a
"Profil par défaut import LDAP" profile. **The capability to synchronize SEAL with
the directory is installed but unused.** It is probably the real lever
to make the identity ↔ badge link reliable, and to align departures.

---

## 4. Administration: accounts, profiles, traceability

### 4.1 The 14 real profiles

| ID | Profile | Admin | Admin excl. | Ops excl. | API excl. |
|---|---|---|---|---|---|
| 1 | **ADMINISTRATEURS** | **yes** | no | no | no |
| 3 | Opérateurs vidéo | no | no | no | yes |
| 4 | Relecteurs vidéo | no | no | no | yes |
| 5 | GESTIONNAIRES DE BADGES | no | yes | no | yes |
| 7 | UTILISATEUR STANDARD | no | yes | no | yes |
| 8 | CLÉS DES ULS | no | yes | no | **no** |
| 9 | OPERATEUR ALARME *("En test")* | no | yes | no | yes |
| 10 | Sonorisation | no | yes | yes | yes |
| 11 | DFS#TRS#GRP#MAGIC1 *("DR Saran gestion badge")* | no | yes | no | yes |
| 14 | Profil par défaut import LDAP | no | yes | yes | yes |
| 15 | UTILISATEUR AVEC API | no | yes | no | **no** |
| 16 | SEAL To Agrid | no | yes | yes | **no** |
| 17 | **TESTGBE** | no | yes | no | yes |
| 18 | **PGE Test droit sur éqpt** | no | yes | no | yes |

Three observations for the rights review (A.5.18):

- **Two test profiles in production**: `TESTGBE` (17) and `PGE Test droit sur
  éqpt` (18). The second was created on 26/06/2026 and modified five times the same day.
- A profile with an unclear name: `DFS#TRS#GRP#MAGIC1`.
- A profile marked "En test": `OPERATEUR ALARME` (9).

The console rights model is: `UTILISATEUR` → `PRO_ID` (profile) →
`T_FONC_PROFIL` (105 associations) → `FONCTIONNALITES` (**219** atomic
functionalities). Per-user overrides exist (`FONC_UTIL`, 404 rows) —
so **an account may have rights outside its profile**: the review cannot
be limited to the profiles.

`ALLOWED_PROFILE_SWITCHES`: 2 authorized switches (1 → 18, 8 → 9). An
administrator can switch to test profile 18.

### 4.2 Storage of console passwords

`dbo.UTILISATEUR` (59 accounts) contains **both**:

```
UTI_PASSW      varchar(50)  NOT NULL   ← cleartext password field (legacy)
UTI_SEED       varbinary(32)           ← salt
UTI_HASH_PASS  varbinary(32)           ← hash
PASS_HASH_ALGO varchar(50)
```

The `UTI_PASSW` column is **NOT NULL**: it necessarily contains something on
the 59 accounts. It is a classic legacy (old authentication) that should
be empty or neutralized. **Content not read** (forbidden by the interface contract) —
but the very existence of this column deserves a question to the vendor, and a
verification. `UTILISATEUR_PASSWORD_HISTORY` (15 rows) does store salt + hash.

The model also correctly handles: `UTI_IS_LOCKEDOUT`,
`UTI_FAILED_PASSWORD_ATTEMPT_COUNT` (+ window), `UTI_MUST_RENEW_PWD`,
`UTI_LAST_PASSWORD_CHANGED_DATE`, `NO_PASSWORD_EXPIRATION`, `IS_WINDOWS_ACCOUNT`,
`DATE_DEBUT`/`DATE_FIN`. The expected mechanisms exist.

### 4.3 Traceability: native and granular

The `Audit` schema has 15 movement tables. Each keeps the **before and
after** (`*Old` / `New*`), the authoring account, the channel and the local + UTC timestamp.

`Audit.AccountsMovements` traces down to the privilege switches:
`OldIsAdmin`/`NewIsAdmin`, `OldCanAccessExternalApi`/`New…`,
`OldCanAccessSealAdministration`/`New…`, `OldCanAccessSealExploitation`/`New…`,
`OldIsLock`/`NewIsLock`, `OldMustRenewPassword`/`New…`.

`Audit.LogDownload` traces the **log exports** (who, when, what volume,
what time bound) — rare, and valuable for A.5.28.

`Audit.AccessControlPermissionMovements` (225) traces each right change:
tag, group, door, door group, before/after dates, before/after typical week.

**This is the system's strength.** To be highlighted as-is in the ISMS.

> A second log, `dbo.TRACES` (**499,971 rows**: module, submodule,
> user, description), exists and is **not collected by the SIEM**. To
> be examined: it may contain actions not covered by the `Audit` schema.

### 4.4 The logbook is empty

`dbo.MAIN_COURANTE`: **0 rows**. `dbo.VACATIONS`: 1,178 operator shifts.

Operators therefore open shifts, but **record nothing**. Combined with
the almost nonexistent alarm acknowledgment (6 rows out of 703,641), this means:
**no trace of human action on the security events**. This is the most
structuring gap of the dossier (A.5.24 / A.5.25).

---

## 5. Zones and topology

### 5.1 The real structure (and why my v1 was wrong)

```sql
Hypervision.ObjectsHierarchicalCatalog   -- 49 rows
    NodeHierarchyId   hierarchyid   -- primary key: the PATH in the tree
    NodeId            bigint
    NodeObjectId      numeric       -- the object carried by the node
    NodeObjectType    varchar(50)   -- its type
```

Four columns. **No `ParentNodeId`, no `NodeLabel`, no `NodeClass`.**
The hierarchy is carried by SQL Server's `hierarchyid` type: the parentage is
read with `.GetAncestor()`, `.IsDescendantOf()`, `.GetLevel()` — not by a
join on a parent identifier.

This is why my `07_vw_SealZone_SIEM.sql` view was built on sand: it
assumed a classic parent/child model. **It must be rewritten**, and the
launcher's safeguard (`<-- adjust`) played its role: it prevented you from
deploying a wrong view.

### 5.2 The right leads

The vendor provides its own tools, which are better used than reinvented:

| Object | What it gives |
|---|---|
| `Hypervision.fn_GetObjectsCatalogPath` | **a node's path** — exactly the `ZONE_PATH` sought |
| `Hypervision.fn_GetObjectCatalogSubTree` | a node's subtree |
| `Hypervision.View_ObjectsHierarchicalCatalogNodeDetails` | a node's details (labels) |
| `dbo.POS_OBJECTS_IN_ZONES_CACHE` (54) | **object → zone**, already computed (`SOURCE_ID` → `TARGET_ID`) |
| `dbo.POS_ZONES_IN_ZONES_CACHE` (1) | zone → subzone, with relative level |
| `dbo.MAP_ITEMS_FLAT` (149) | `OBJECT_ID` → `PARENT_ID` flattened |
| `dbo.ObjectsNodesTree` (16) | `NodeId`, `ParentNodeId`, `NodeName`, `SealObjectId` |
| `dbo.pk_GetZonesForObjectFromCache` | vendor procedure: the zones of an object |

`POS_OBJECTS_IN_ZONES_CACHE` (54 rows) is the most direct lead: it is the
object → zone cache that SEAL already uses for its maps. To be compared to the **165
deployed doors**: 54 associations will not cover the whole fleet.

### 5.3 Another, richer path: `T_PASSAGES`

```
dbo.T_PASSAGES   -- 45,623 rows
    PASS_ID, FICH_ID, NUM_PHYS, CONT_ID, PASS_DATE_PASSAGE,
    PASS_VALIDE, REFU_ID, ZONE_OBFI_ID, ZONE_IN_OUT, EVEN_ID, REEV_CODE
```

This table links **the passage, the record (the holder), the zone and the direction
(entry/exit)** — and makes the link with the event (`EVEN_ID`). It is
structurally a better source than `EVENEMENTS` to answer "who went
where, in which direction": identity and zone are already resolved there.

It is not exposed to the SIEM today. **This is probably the most
profitable lead** — it resolves at once the identity link *and* the zone link.

---

## 6. The second access system: ENIQ / DOMBOX

The `ENIQ` schema describes a **parallel** access control, based on standalone
electronic cylinders (DOMBOX / OSS):

| Table | Rows |
|---|--:|
| `ENIQ_INTERFACE_PERMISSIONS` | **4,169** |
| `ENIQ_INTERFACE_DEVICES` | 42 |
| `ENIQ_INTERFACE_WEEKS` | 32 |
| `ENIQ_INTERFACE_HOLIDAYS` | 22 |
| `ENIQ_INTERFACE_DEVICES_COUPLED` | 63 |
| `ENIQ_INTERFACE_PERMISSIONS_OSS` | 0 |

**4,169 permissions** are defined there — more than double the 1,903 effective
rights of the wired access control. These cylinders operate **offline**: they
carry their rights in memory, are synchronized in batches, and their events
only report at the next synchronization (`LAST_EVENT_ID`,
`DOMBOX: Perte d'évènements`, `DOMBOX: décalage d'horloge` in the reference data).

**This perimeter is neither collected by the SIEM nor covered by the ongoing
documentation.** It must be decided whether it falls within the ISMS scope. The
ENIQ permissions moreover carry their own conflicts (`WEEK_TEMPLATE_CONFLICT`,
`HOLIDAYS_CONFLICT`, `MASTER_KEY_CONFLICT`, `HAS_CONFLICTS`).

Also of note: `dbo.TAG_KEYRING_ASSOCIATION` and `AGRID_*` (Traka/Agrid key
cabinets) — yet another physical access mode (managed mechanical keys).

---

## 7. The event vocabulary

`dbo.REF_EVENEMENT`: **150 codes on OMEGA** (177 on QA, **197 in union**). It is
the complete dictionary of what SEAL can say.

The table is richer than a simple label — each code carries:

| Column | Role |
|---|---|
| `REEV_DFLT_SEVERITY` | default severity (0 to 901) |
| `REEV_AL_USER_DESCRIPTION_PATTERN` | alarm sentence template |
| `REEV_EVEN_USER_DESCRIPTION_PATTERN` / `_END` | event start / end template |
| `REEV_INTEMPESTIVEOCCUR` / `MAXEVENT` / `PERIOD` | **anti-flood thresholds per code** |
| `REEV_TRANSTYPE`, `REEV_DELAYTRANSFERT` | transfer policy |

The templates reveal the semantics: `Refus de [AccessBy] sur [OriginLabel], badge
interdit sur cette ULS. [UserComment]`. The variables `[AccessBy]`, `[OriginLabel]`,
`[UserComment]` are substituted at runtime — this is how SEAL builds its
readable descriptions.

**The anti-flood configuration is uniform**: almost all the codes have
`INTEMPESTIVEOCCUR = 60`, `MAXEVENT = 1000`, `PERIOD = 1` — that is, the default
values. Only `SEM542` (intrusion panel disconnected) is finely tuned
(10/10/6). In other words: **the "spurious" qualification is not configured
for the fleet**.

Breakdown of the 197 codes (union of both sites):

| Family | Codes |
|---|--:|
| Hardware — readers, modules, UTL, sensors | 54 |
| Door — physical state and commands | 36 |
| Intrusion, sabotage, assault | 28 |
| User access — authorization and denial | 25 |
| Arming / disarming (sectors) | 13 |
| Video and detection | 5 |
| Vehicles and loops | 2 |
| Console and administration | 2 |
| System and supervision | 2 |
| Miscellaneous (buttons, DOMBOX, LoRa…) | 30 |

The **25 denial codes** describe all the conditions of the decision: badge
forbidden on the ULS, outside the typical week (of the user *or* of the door), outside
the calendar, user not valid on this date, anti-pass-back, zone full (global
counter or individual), incorrect PIN code, "burned" user (too many attempts), badge
re-presented too soon, incorrect badging sequence, blocked door, public holiday.

The complete reference data (code → label) is provided as CSV, attachable as-is.

---

## 8. Findings for ISO 27001

Quantified, verifiable, classified by severity.

### 8.1 No trace of human action (A.5.24, A.5.25)

- Logbook: **0 rows**.
- Alarm acknowledgment: **6 rows out of 703,641**.
- Shifts opened: 1,178.

Operators therefore take up their post but record nothing and acknowledge nothing.
**It is impossible to demonstrate that an alarm was handled, or by whom.** No
technical fix fills this gap: it is an operational practice.

### 8.2 No time restriction (A.5.15)

2 typical weeks: `Toujours`, `Jamais`. Access control is binary. To be
documented as an owned decision, or to be corrected.

### 8.3 An entire perimeter off the radar (A.5.15, A.8.16)

4,169 permissions on DOMBOX/ENIQ cylinders, unsupervised, undocumented.
A scope decision to be made.

### 8.4 Test accounts and profiles in production (A.5.18)

Profiles `TESTGBE`, `PGE Test droit sur éqpt`, `OPERATEUR ALARME (En test)`;
accounts `TESTGBE`, `seal_server_app_test`. A review is required.

### 8.5 The identity ↔ badge link is not exploited (A.5.16, A.5.18)

The matricule exists (`milf.BADGES.MATRICULE`, 443 badges) but is not exposed to the
SIEM; LDAP synchronization is installed but empty. **Fixable** — see §9.

### 8.6 `UTI_PASSW varchar(50) NOT NULL` (A.5.17)

A cleartext "password" column coexists with the salt and the hash, on
59 accounts. Content not read. To be clarified with the vendor.

### 8.7 What works well — to highlight

- **Native administration traceability**: 15 movement tables, before/after
  on each change, attributable to an account, an IP and a channel.
- **Complete rights model**: validity, typical week, anti-pass-back,
  anti-timeback, escort mode, master passes, PIN code, public holidays.
- **Native detection of rights conflicts** (32 conflicts identified, with
  the attribute at fault).
- **Separation of entered right / effective right**: the system can say what is
  actually applied.
- **Traced log export** (`Audit.LogDownload`).
- **Business authorization repository** (medical, ATEX, NH3, ZSAR, training).
- **Externalized supervision**: the SIEM continuously monitors the sensitive actions
  (master pass, badge reactivation, alarm inhibition, log export),
  which provides a **separation of duties** between the security operator and the SOC.

---

## 9. What remains to be established

Three questions, one query each. Script provided: `06_recon_complements.sql`.

1. **Matricule fill rate** — decides whether the badge → AD bridge is
   immediate or whether the data must first be populated.
   ```sql
   SELECT COUNT(*) AS badges, COUNT(MATRICULE) AS avec_matricule,
          COUNT(SEAL_ID) AS relies_a_une_fiche
   FROM milf.BADGES WHERE MILF_STATUS <> 'ANN';
   ```
2. **Zone cache coverage** — decides the feasibility of the `seal_zone`.
   ```sql
   SELECT COUNT(*) AS objets_dans_une_zone,
          COUNT(DISTINCT TARGET_ID) AS zones
   FROM dbo.POS_OBJECTS_IN_ZONES_CACHE;
   ```
3. **`T_PASSAGES`: the short lead** — if `ZONE_OBFI_ID` and `FICH_ID` are well
   filled, this table resolves identity *and* zone at once.
   ```sql
   SELECT COUNT(*) AS passages, COUNT(FICH_ID) AS avec_fiche,
          COUNT(ZONE_OBFI_ID) AS avec_zone, COUNT(NULLIF(ZONE_IN_OUT,'')) AS avec_sens
   FROM dbo.T_PASSAGES;
   ```

Useful as a complement: the **vendor documentation** (administration manual), to
confirm the semantics of `MODE_ESCORTE`, of the immunities, and of the
`milf.BADGES` ↔ `FICHE` link.

---

## Appendix — analysis traceability

All the values come from `05_recon_fonctionnel.sql` run on
`BX-SEAL-OMEGA` on **16/07/2026 at 09:28** (metadata + configuration tables
only — no personal data read), and from the SIEM measurements of the same day.
The database is live: the volumes move, the orders of magnitude and the ratios
do not. The SQL figures describe **OMEGA**; the fill rates cited in v1
described **QA** — the two sites differ, do not confuse them.
