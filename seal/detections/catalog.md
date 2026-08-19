# SEAL → Graylog — Detection catalog v1

> Authority: `seal/docs/CONTRACT.md` (normalized fields **D4**, decodings **D3**).
> Graylog **Open 7.1.3** edition → **Aggregation event definitions only**
> (no native Correlation event def, no JDBC lookup). The sequence
> correlation rules are marked **[SEQ]** and documented (approximation
> via pipeline state, or deferred to v2).
>
> **Threshold calibration**: RECON §9.5 volumetry — QA very lightly active
> (`EVENEMENTS` ≈ **158 events/24 h**, i.e. ≈ 6.6/h). The brute force /
> flood thresholds are therefore set well above the QA background noise (≥5–20 depending on the
> rule); to be re-calibrated on the **prod** volumetry before cutover.
>
> **Notification** (cf. `provision_detections.py`): a single
> `teams-notification-v2` notification (Teams webhook = HTTP notification carrying an
> **Adaptive Card**: rule, severity, actor/object, Graylog link).
> **Multi-site**: the card exposes `seal_site` per backlog line (`site:…`) to
> identify **which site** triggered, without modifying the `group_by`/the rules' key.
> **Critical/High = immediate** (attached Adaptive Card) ·
> **Medium/Info = digest** (no real-time push; visible in console + report).
>
> **Fields**: all the queries use **only** the normalized
> **D4** fields (`event_domain`, `event_action`, `event_outcome`, `operation_channel`,
> `actor_login`, `actor_usercode`, `src_ip`, `badge_number`, `target_object_label`,
> `door_id`, `seal_source_table`, `seal_payload`, …), never the raw SQL columns. The audit-specific
> details are exposed as `seal_<key>` fields (JSON exploded by Logstash); the alarm qualifiers (IS_INHIBITED...) are direct columns of the view.

## Conventions

- **Streams / index sets** (CONTRACT D0):
  `OMNI - SEAL Accès` (`omni-seal-access`) · `OMNI - SEAL Alarmes`
  (`omni-seal-alarm`) · `OMNI - SEAL Audit` (`omni-seal-audit`).
- **event_action** (D4) = `Operation` (audit) **or** `REEV_LIBELLE` **decoded**
  (access/alarm) via the `REEV_CODE→label` lookup. The detections rely on
  the **decoded REEV_CODE** (D0), not on the SEAL `severity_num` (unreliable).
- **Documented approximations**: the movement transitions (badge, permission,
  inhibition) do not yet have a dedicated D4 field → they are matched on
  `seal_source_table` + `seal_payload` (residual JSON D4). A dedicated normalized field
  is recommended in v2 ("Status" column = `[SEQ]` or *payload* note).
- **Window** noted `within / every` (minutes). `grace` = per-entity storm control.

## Status

| Code | Meaning |
|---|---|
| `active` | Aggregation event definition provisioned and **enabled**. |
| `[SEQ]-approx` | Sequence approximated by **pipeline state** (tag/flag set in the pipeline); provisioned, enabled, but depends on the pipeline deployment (Phase 3). |
| `[SEQ]-v2` | Sequence correlation not expressible in a simple aggregation → **deferred to v2** (`oms-xdr` service, multi-stream). Cataloged, **not** provisioned in Graylog. |
| `disabled (acceptance)` | Created **disabled** (dead-man switch) — activation **post-acceptance**, once the flow runs (cf. `provision_detections.py`). |

---

## 1. HYP — Hypervisor audit / SEAL consoles  (stream `OMNI - SEAL Audit`)

| ID | Title | Graylog query (D4) | group_by | Threshold | Window | Sev. | Technique | Notif. | Status |
|---|---|---|---|---|---|---|---|---|---|
| HYP-001 | Console brute force (authentication failures) | `event_domain:hypervisor_audit AND event_action:ConnectionFailure` | `actor_login` | `count() ≥ 5` | 10 / 1 | High | T1110 | immediate | active |
| HYP-002 | Brute force **followed by a success** (same account) | `event_domain:hypervisor_audit AND alert_tag:seal_bf_then_success` | `actor_login` | `count() ≥ 1` | 15 / 1 | High | T1110 / T1078 | immediate | [SEQ]-approx |
| HYP-003 | Administration console connection (`SealAdmin`) | `event_domain:hypervisor_audit AND event_action:Connection AND operation_channel:SealAdmin` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | Medium | T1078 | digest | active |
| HYP-004 | In-session profile change (`SwitchProfile`) | `event_domain:hypervisor_audit AND event_action:SwitchProfile` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | Medium | T1078 | digest | active |
| HYP-005 | Admin connection **outside working hours** | `event_domain:hypervisor_audit AND event_action:Connection AND operation_channel:SealAdmin AND off_hours:true` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | High | T1078 | immediate | [SEQ]-approx |
| HYP-006 | Export / download of audit logs | `event_domain:hypervisor_audit AND seal_source_table:LogDownload` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | Medium | T1005 | digest | active |
| HYP-007 | Account or role creation / modification | `event_domain:hypervisor_audit AND seal_source_table:(AccountsMovements OR AccountRolesMovements OR ProfilesMovements)` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | High | T1136 / T1098 | immediate | active |
| HYP-008 | Modification of profile authorizations | `event_domain:hypervisor_audit AND seal_source_table:(ProfileAuthorizedObjectsMovements OR ProfileAllowedSwitch OR ProfileRoleMovements)` | `actor_usercode` | `count() ≥ 1` | 10 / 5 | Medium | T1098 | digest | active |
| HYP-009 | Local unit migration (controller reconfig) | `event_domain:hypervisor_audit AND seal_source_table:LocalUnitMigrationMovements` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | Medium | T1565 | digest | active |
| HYP-010 | Physical object modification (door/command) | `event_domain:hypervisor_audit AND seal_source_table:(CommandObject OR ObjectDeclarationMovements)` | `actor_usercode` | `count() ≥ 1` | 15 / 5 | Medium | T1565.001 | digest | active |
| HYP-011 | Simultaneous multi-IP sessions (same account) | `event_domain:hypervisor_audit AND event_action:Connection` | `actor_login` | `card(src_ip) ≥ 2` | 10 / 5 | Medium | T1078 | digest | [SEQ]-approx |
| HYP-012 | **Console account active on several sites** (multi-site) | `event_domain:hypervisor_audit AND event_action:Connection` | `actor_login` | `card(seal_site) ≥ 2` | 30 / 10 | Medium | T1078 | digest | active |

*Note — HYP-012 (multi-site): the same console account connecting to **both**
SEAL sites (`bx-qa-seal-vm` **and** `bx-seal-omega`) within the window. A signal of
a shared account / cross-site lateral movement. Deliberately **Medium/digest**
(may be legitimate for a transversal admin → review, no Teams push: anti-flood).*

*Note — SEM759 ("User connection on the console") and SEM73 ("UTL
database modified") are normalized but not alerted in v1 (context /
correlation); v2 candidates. `off_hours` is a flag set in the pipeline (Phase 3).*

## 2. ACC — Access control administration / badges

| ID | Title | Graylog query (D4) | group_by | Threshold | Window | Sev. | Technique | Notif. | Status |
|---|---|---|---|---|---|---|---|---|---|
| ACC-001 | Assignment of a **master pass** (master key → 1) | `event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_MasterKeys:true AND seal_MasterKeysOld:false` | `actor_usercode` , `target_object_label` | `count() ≥ 1` | 10 / 5 | High | T1098 / T1078 | immediate | active |
| ACC-002 | Mass assignment of access rights | `event_domain:hypervisor_audit AND seal_source_table:AccessControlPermissionMovements` | `actor_usercode` | `count() ≥ 5` | 10 / 5 | Medium | T1098 | digest | active |
| ACC-003 | Badge creation (`∅→PRE`) | `event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_Status:PRE` | `actor_usercode` | `count() ≥ 1` | 15 / 10 | Info | T1136 | digest | active |
| ACC-004 | Badge **reactivation** (`Status ANN→VAL`) | `event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_StatusOld:ANN AND seal_Status:VAL` | `actor_usercode` , `target_login` | `count() ≥ 1` | 10 / 5 | High | T1078 | immediate | active |
| ACC-005 | Badge **disabled then used** (`VAL→ANN` → access) | *sequence TagMovements audit × EVENEMENTS access (same badge)* | `badge_number` | — | 24 h | High | T1078 | immediate | [SEQ]-v2 |
| ACC-006 | Repeated **denied** accesses on a door | `event_domain:access AND event_outcome:deny` | `target_object_label` | `count() ≥ 5` | 10 / 1 | Medium | T1110 | digest | active |
| ACC-007 | Access granted **outside time range** | `event_domain:access AND event_outcome:grant AND off_hours:true` | `badge_number` , `target_object_label` | `count() ≥ 1` | 15 / 5 | Medium | T1078 | digest | [SEQ]-approx |

*Note — `MasterKeys`, `Status/StatusOld` (badge transitions) are not yet dedicated
D4 fields → matched on `seal_payload` (JSON D4). A dedicated normalized field =
v2 task. Badge→matricule resolution rate ≈ 76.5% (RECON §9.3): `badge_number`
remains the reliable key in QA.*

## 3. ALM — Alarms  (stream `OMNI - SEAL Alarmes`)

| ID | Title | Graylog query (D4) | group_by | Threshold | Window | Sev. | Technique | Notif. | Status |
|---|---|---|---|---|---|---|---|---|---|
| ALM-001 | **Inhibition** of an alarm (`IS_INHIBITED→1`) | `event_domain:alarm AND IS_INHIBITED:true` | `target_object_label` | `count() ≥ 1` | 10 / 5 | High | T1562.001 | immediate | active |
| ALM-002 | Inhibition **followed by a break-in** (same point) | *sequence: ALM-001 → SEM113 on the same `target_object_label`* | `target_object_label` | — | 60 | High | T1562.001 | immediate | [SEQ]-v2 |
| ALM-003 | **Physical intrusion** (door break-in / panic button) | `event_domain:alarm AND event_action:("Effraction porte" OR "Déclencheur manuel percuté")` | `target_object_label` | `count() ≥ 1` | 5 / 1 | Critical | T1200 / physical | immediate | active |
| ALM-004 | **Spurious** alarm / sensor flood | `event_domain:alarm AND IS_INTEMPESTIVE:true` | `target_object_label` | `count() ≥ 20` | 10 / 5 | Medium | T1499 / T1562.001 | digest | active |

*Note — Decoded REEV_CODE (D3): `SEM113` = "Effraction porte", `SEM805` =
"Déclencheur manuel percuté" (panic button). The labels come from the
`REEV_CODE→REEV_LIBELLE` lookup (`dbo.REF_EVENEMENT`).*

## 4. EVT — Physical access events  (stream `OMNI - SEAL Accès`)

| ID | Title | Graylog query (D4) | group_by | Threshold | Window | Sev. | Technique | Notif. | Status |
|---|---|---|---|---|---|---|---|---|---|
| EVT-001 | User access **granted** (correlation base / hunting) | `event_domain:access AND event_outcome:grant` | `badge_number` | `count() ≥ 1` | 5 / 5 | Info | — | digest | active |
| EVT-002 | **Unknown / unenrolled badge** presented | `event_domain:access AND event_outcome:grant AND NOT _exists_:identity_matricule` | `badge_number` , `door_id` | `count() ≥ 1` | 10 / 5 | Medium | T1078 | digest | [SEQ]-approx |

*Note — EVT-001 (SEM138/SEM280 "user access / secondary reader") is the source
of granted access that feeds XCO; deliberately **Info/digest** (anti-firehose).
EVT-002: `badge_known` is set in the pipeline via `AcApi.TAG` (D0: the tag indicates
only that a badge is **known**, it does not carry a matricule).*

## 5. XCO — Cross-correlation physical ↔ digital  (multi-stream, **v2**)

Multi-source sequence correlations **not expressible** in Graylog Open
aggregation (cross-stream join + SIEM-side identity resolution). Cataloged;
implementation in **v2** in the `oms-xdr` service (OpenSearch read). **Not**
provisioned in Graylog.

| ID | Title | Logic | Correlates | Sev. | Technique | Status |
|---|---|---|---|---|---|---|
| XCO-001 | Impossible travel physical ↔ logon | Badge on site **and** remote Windows logon of the same matricule within an incompatible delay | `identity_matricule` (SEAL access) × 4624 Windows | High | T1078 | [SEQ]-v2 |
| XCO-002 | Badge access **without** correlated logon (tailgating / cloning) | Physical access granted without an expected Windows session on the same identity | SEAL access × Windows sessions | Medium | T1078 | [SEQ]-v2 |
| XCO-003 | Hypervisor reconfig **followed by** a break-in | Config change (HYP-009/010) then break-in (ALM-003) on the same object | SEAL audit × SEAL alarm | High | T1565 / T1562 | [SEQ]-v2 |

## 6. Dead-man switches — flow supervision (**created DISABLED**)

> **Do not enable** as long as the flow does not run: an absence rule
> triggers immediately when empty → permanent false positive. Created **disabled**,
> activation **post-acceptance** (`provision_detections.py` creates them with
> `?schedule=false`; manual activation in Graylog or re-run after validation
> of the flow). *Go-dark* pattern: **no `group_by`**, `count() < 1` (an empty aggregation
> without group_by correctly evaluates `count = 0`).

| ID | Title | Graylog query (D4) | group_by | Threshold | Window | Sev. | Ref. | Notif. | Status |
|---|---|---|---|---|---|---|---|---|---|
| DMS-001 | **Audit** flow interrupted (>15 min, all sites) | `event_source:seal AND event_domain:hypervisor_audit` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-002 | **Access** flow interrupted (>15 min, all sites) | `event_source:seal AND event_domain:access` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-003 | **Alarms** flow interrupted (>15 min, all sites) | `event_source:seal AND event_domain:alarm` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |

### 6.1 **Per-site** dead-man switches (multi-site) — created DISABLED

> **Rationale**: DMS-001/002/003 monitor the stopping of a **domain across all
> sites combined**; if a **single** site (`bx-qa-seal-vm` **or** `bx-seal-omega`) goes silent
> while the other keeps emitting, they stay **mute**. The variants below
> add a DMS per **(domain × site)** to detect that a specific site drops off.
> Same *go-dark* pattern (no `group_by`, `count() < 1`), **created `disabled`**
> (activation post-acceptance, cf. §5 points of attention). Generated by a loop in
> `provision_detections.py` (`SEAL_SITES × _DMS_SITE_DOMAINS`).

| ID | Title | Graylog query (D4) | group_by | Threshold | Window | Sev. | Ref. | Notif. | Status |
|---|---|---|---|---|---|---|---|---|---|
| DMS-004 | **Audit** flow interrupted — site `bx-qa-seal-vm` | `event_source:seal AND event_domain:hypervisor_audit AND seal_site:"bx-qa-seal-vm"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-005 | **Audit** flow interrupted — site `bx-seal-omega` | `event_source:seal AND event_domain:hypervisor_audit AND seal_site:"bx-seal-omega"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-006 | **Access** flow interrupted — site `bx-qa-seal-vm` | `event_source:seal AND event_domain:access AND seal_site:"bx-qa-seal-vm"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-007 | **Access** flow interrupted — site `bx-seal-omega` | `event_source:seal AND event_domain:access AND seal_site:"bx-seal-omega"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-008 | **Alarms** flow interrupted — site `bx-qa-seal-vm` | `event_source:seal AND event_domain:alarm AND seal_site:"bx-qa-seal-vm"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |
| DMS-009 | **Alarms** flow interrupted — site `bx-seal-omega` | `event_source:seal AND event_domain:alarm AND seal_site:"bx-seal-omega"` | — | `count() < 1` | 15 / 5 | High | A.8.16 | immediate | disabled (acceptance) |

> **Activation warning**: to be enabled (`--enable-deadman`) only **after** having
> confirmed that **each** site actually emits on **each** domain. A site that
> legitimately does not emit a domain (e.g. no alarm configured) would trigger a
> permanent FP → only enable the per-site DMS of the pairs actually fed.

---

## Recap

- **37 rules**: 12 HYP · 7 ACC · 4 ALM · 2 EVT · 3 XCO · 9 DMS (3 global + 6 per site).
- **Provisioned in Graylog** (`provision_detections.py`): **23 active aggregations**
  (including 4 `[SEQ]-approx` depending on a pipeline flag, + HYP-012 multi-site) +
  **9 disabled dead-man switches** (3 global DMS-001/002/003 + 6 per site
  DMS-004..009) = 32 event definitions.
- **Deferred to v2** (`oms-xdr`, not Graylog): ACC-005, ALM-002, XCO-001/002/003 = 5.
- **Immediate notification** (Teams Adaptive Card): Critical + High
  (HYP-001/002/005/007, ACC-001/004, ALM-001/003, + DMS on activation).
  **Digest** (Medium/Info, including HYP-012 multi-site): the rest.
  The card now carries `seal_site` per backlog line (**which site**).

## Points of attention

1. **Prerequisite streams**: the 3 SEAL streams (D0) must exist before
   provisioning; otherwise `provision_detections.py` skips the rule with a WARN.
2. **Pipeline dependencies**: `off_hours`, `badge_known`, `alert_tag:seal_bf_then_success`
   are set by the SEAL pipeline (Phase 3). As long as they do not exist, the
   `[SEQ]-approx` rules **match nothing** (silent, no FP) — to be verified in acceptance.
3. **`seal_payload` fields**: v1 approximation for the transitions (MasterKeys,
   badge Status, IS_INHIBITED, IS_INTEMPESTIVE). To be promoted to dedicated D4 fields in v2.
4. **QA→prod thresholds**: calibrated on QA (~158 ev/24 h). Re-calibrate before prod cutover.
5. **Dead-man switches**: remain **disabled** until the flow is stable (otherwise immediate FP).
   For the **per-site** DMS (§6.1), only enable the (domain × site) pairs
   actually fed (otherwise permanent FP on a domain legitimately mute on one site).
6. **Multi-site thresholds (review, to be decided before enabling per-entity aggregates)**:
   the burst/cardinality rules per **door / badge / account / IP** currently
   aggregate **all sites combined** (`group_by` without `seal_site`). Two effects to
   settle in prod acceptance:
   - **Cross-site label collision**: the same `target_object_label` (or
     `door_id`) may designate **two distinct physical doors** on `bx-qa-seal-vm`
     and `bx-seal-omega`. ACC-006 (denied accesses/door), ACC-007, EVT-002, ALM-001/003/004
     then mix two doors under a single key → threshold reached "straddling" or
     ambiguous attribution. **Recommendation**: add `seal_site` to the `group_by` of these rules
     (key = site + object) — **not applied in v1** so as not to change the behavior
     of the rules active in prod; to be validated then applied in a batch.
   - **Per-site vs cumulative thresholds**: brute force (HYP-001), repeated denials (ACC-006),
     sensor flood (ALM-004) — a global threshold may mask a localized attack on
     a single site (noise from the other) **or** wrongly accumulate. Decide per rule whether the
     threshold should be **per site** (via `seal_site` in the `group_by`) or stay cumulative.
   - **New multi-site avenue**: HYP-012 (console account on ≥2 sites) covers the
     shared / lateral account. A **cross-site badge** equivalent (same `badge_number`
     granted on both sites within an incompatible delay) is a matter of **sequence
     correlation** (multi-stream + delay) → **`oms-xdr` v2 candidate** (cf. XCO), not
     expressible in a simple aggregation here.
