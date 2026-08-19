# DATA_READINESS.md — Phase 6 entry checkpoint (SEAL Dashboards)

OMNITECH SECURITY · MISSION_SEAL_GRAYLOG Phase 6 · repo `omnitech-siem-setup/seal`
Control date: 2026-07-15.

> **STATUS: READY (updated 07/15 afternoon).** The real flow is running: DDL
> executed, Logstash collecting, **full backfill completed** (1.67 M rows,
> 0 errors). The 3 streams are populated with the normalized history. The Phase 6
> entry gate is cleared; the feasibility matrix (§2) remains the
> reference for the widgets to provision. **Remaining: operator validation of the
> matrix, then dashboard provisioning.**

---

## 1. Phase 6 prerequisites — verified state (blocking)

| Prerequisite | Expected | Observed (2026-07-15) | Verdict |
|---|---|---|---|
| Real events `event_domain:access` /24 h | > 0 | **0** | ❌ |
| Real events `event_domain:alarm` /24 h | > 0 | **0** | ❌ |
| Real events `event_domain:hypervisor_audit` /24 h | > 0 | **0** | ❌ |
| Synthetic `TEST_SIEM` injections (to ignore) | — | 6 (my Phase 3 E2E tests) | ℹ️ |
| Logstash installed + active (SIEM VM) | active | **inactive / not installed** | ❌ |
| `seal.conf` deployed | present | **absent** | ❌ |
| `vw_Seal*_SIEM` views created (Phase 1 DDL) | 4 views | **none** | ❌ |

**Conclusion: the collection chain is not yet established.** The widgets would
all measure zero → not verifiable. We stop here (consistent with the mission's
sequencing reminder).

### Critical path to clear the blocker (mandated order, operator side)
1. **SEAL DDL** (SSMS admin): `seal/sql/01_ → 05_ + 90_provision.sql`. Without the
   views, the JDBC inputs fail. Reminder: rowversion on `EVENEMENTS` =
   table rewrite → maintenance window (instantaneous in QA).
2. **Logstash base**: `install-logstash-siem.sh` (provided, ready, idempotent) on
   the SIEM VM → package + GELF/JDBC plugins + mssql-jdbc driver + keystore.
3. **Deploy** `seal/logstash/seal.conf` + `seal/logstash/sql/*.sql`, populate
   the keystore (Vaultwarden secrets), test `logstash -t`, start.
4. Let it run for **a few hours** (ideally 24 h including a business-hours window)
   for a representative sample, then **re-run this check**: the 3 volume
   lines must be > 0.

---

## 2. Widget feasibility matrix (derived from the CONTRACT, to be confirmed against data)

This matrix does not depend on volumes: it derives from the **field contract**
(`seal/docs/CONTRACT.md`) and the logic of the SQL views (which fields are populated
vs known empty). It makes it possible to know *in advance* which widgets will be
`FEASIBLE` and which are `[BLOCKED: depends on X]`, so as not to provision a
misleadingly empty panel.

### 2.1 Actual field population (by domain)

| Field (contract D4) | access | alarm | hypervisor_audit | Remark |
|---|---|---|---|---|
| `event_source`,`event_domain`,`timestamp` | ✅ | ✅ | ✅ | set by view/collector |
| `event_action` | ✅ (via correlated alarm) | ✅ REEV_LIBELLE | ✅ Operation | access: depends on the linked alarm |
| `event_outcome` (grant/deny/na) | ✅ | ✅ | ✅ (success/failure) | derived from REEV (144 deny/255 grant measured in database) |
| `severity_num` | — | ✅ EVEN_SEVERITE | ✅ mapping | — |
| `actor_usercode` | — | ✅ | ✅ | — |
| `actor_login` | — | — | ✅ (`seal_Login`) | console: UserConnections |
| `src_ip` | — | — | ✅ (`seal_IpAddress`) | — |
| `operation_channel` | — | — | ✅ | SealAdmin/Exploitation… |
| `badge_number` | ✅ | (if trigger) | ✅ (`seal_Number`) | — |
| `identity_matricule` | ⚠️ ~76.5% | — | — | badge→milf.BADGES ; ~23.5% unresolved |
| **`identity_upn`** | ❌ **empty** | ❌ **empty** | ❌ **empty** | unresolved in QA (SIEM-side, not wired) |
| `target_object_label/id/type` | ⚠️ ~62% | ✅ | ✅ (`seal_Object*`) | access: `RAW_ORIGIN_OBFI_ID` NULL ~38% |
| **`site`** | ❌ **NULL** | ❌ **NULL** | ❌ **NULL** | topology not mapped (NodeObjectId≠OBJ_ID) |
| **`door_id`** | ❌ absent | ❌ absent | ⚠️ audit only (`seal_DoorId`) | access: door = `target_object_label` |
| `off_hours` | ✅ | — | ✅ | local time 07–19 |
| `IS_INHIBITED`,`IS_INTEMPESTIVE`,`INTEMPESTIVE_COUNT` | — | ✅ | — | direct columns |
| `seal_source_table`,`seal_payload`,`seal_*` | — | — | ✅ | exploded JSON |

Legend: ✅ populated · ⚠️ partial · ❌ empty/blocked · — not applicable to the domain.

### 2.2 Widgets by view — feasible vs blocked

**View A — Operational SOC** (audience: operator; window 15 min–24 h)

| Widget | Query (SEAL streams) | Status |
|---|---|---|
| Access denials counter 1 h | `event_domain:access AND event_outcome:deny` | FEASIBLE |
| Failed console logins counter 1 h | `event_domain:hypervisor_audit AND event_action:ConnectionFailure` | FEASIBLE |
| Active alarms counter | `event_domain:alarm AND NOT _exists_:END_EVEN_ID` | FEASIBLE (to confirm) |
| Latest alarms feed (table) | `event_domain:alarm` → time, `severity_num`, `target_object_label`, `event_outcome` | FEASIBLE |
| Top 10 badges in denial /24 h | `event_domain:access AND event_outcome:deny` group by `badge_number` | FEASIBLE (badge fallback); **`identity_upn` [BLOCKED: identity_upn]** |
| Console: recent failures | `hypervisor_audit AND event_action:ConnectionFailure` → `actor_login`,`src_ip`,`operation_channel` | FEASIBLE |
| Denials by **door** | group by `target_object_label` (NOT `door_id` on access) | FEASIBLE ⚠️ ~62% objects resolved |
| Denials **by site** | group by `site` | **[BLOCKED: site]** |

**View B — Steering & audit evidence** (audience: CISO/Bureau Veritas; 7/30/90 d)

| Widget | Query | Status |
|---|---|---|
| Volume by `event_domain` over time (stacked) | `event_source:seal` group by `event_domain` histogram | FEASIBLE — **A.8.15 evidence** |
| Grant/deny distribution over time | `event_domain:access` group by `event_outcome` histogram | FEASIBLE |
| Rights movements (table) | `hypervisor_audit AND seal_source_table:(AccessControlPermissionMovements OR AccountsMovements OR ProfilesMovements OR ProfileRoleMovements OR TagMovements)` | FEASIBLE — **A.8.16 core** |
| Master key/immunity activations | `hypervisor_audit AND seal_source_table:TagMovements AND (seal_MasterKeys:true OR seal_ApbImmunity:true OR seal_AptImmunity:true OR seal_DoubleBadgedImmunity:true)` | FEASIBLE (to confirm `seal_*` names) |
| Operator account creations/elevations | `hypervisor_audit AND seal_source_table:AccountsMovements` | FEASIBLE |
| Top operator accounts by admin volume | `hypervisor_audit` group by `actor_usercode`/`actor_login` | FEASIBLE |
| Log exports over time | `hypervisor_audit AND seal_source_table:LogDownload` | FEASIBLE — meta-monitoring |
| Trend **by site** | group by `site` | **[BLOCKED: site]** |

**View C — Monitoring health** (audience: CISO/SOC)

| Widget | Query | Status |
|---|---|---|
| Freshness by domain (age of last event) | 3× `event_domain:X` → last `timestamp` | FEASIBLE |
| Throughput by domain (evt/hour) | `event_source:seal` group by `event_domain` histogram 1 h | FEASIBLE |
| State of the 3 dead man's switches | DMS-001/002/003 definitions (created disabled in Phase 4) | FEASIBLE once DMS enabled |
| Collection latency (gap timestamp vs reception) | requires a gap field | **[BLOCKED: latency field not normalized]** — see §4 |

---

## 3. Observed volumetry (to be filled once the flow is established)

| Domain | Total volume (backfill) | Populated fields | Ready for widgets? |
|---|---|---|---|
| access | **961,268** | event_action/outcome/off_hours/badge_number ; ~62% target_object ; ~76% identity_matricule | YES |
| alarm | **703,636** | event_action(REEV)/outcome/severity_num/IS_INHIBITED/IS_INTEMPESTIVE | YES |
| hypervisor_audit | **3,557** | Operation/actor_usercode ; actor_login/src_ip/target_* (console audit) | YES |

Observed orders of magnitude (30 d): access denials `event_outcome:deny` ≈ 147.
Blocked reminders (§2/§4) unchanged: `site`=NULL, `identity_upn` empty.
Incremental active: new events collected continuously (~30 s).

---

## 4. Evolution recommendations (out of Phase 6 scope — DO NOT fix here)

Reported as the mission requires (§5), without implementing them:
1. **`site` NULL**: establish the topology mapping with the operator
   (`ObjectsHierarchicalCatalog`: ID space distinct from `Objet_Fiche.OBJ_ID`).
   Unblocks all "by site" widgets (A and B).
2. **`identity_upn` empty in QA**: wire the matricule→AD/M365 resolution on the SIEM side
   (mirror rule `13-identity-mirror.rule`). Unblocks the identity pivot and the
   cross-correlation XCO. In the meantime, the widgets fall back on `badge_number`.
3. **Collection latency** (View C): no field carries the gap
   `event_timestamp` vs Graylog reception. Set a dedicated field in the
   pipeline (e.g. computed delta) if this widget is deemed a priority for the audit.
4. **`target_object_*` ~62% on access**: the 38% of events without
   `RAW_ORIGIN_OBFI_ID` have no target object → "by door" widgets on the access side
   undercount. To accept or to enrich upstream.

---

## 5. Decision requested (entry checkpoint)
1. Launch the critical path §1 (DDL → Logstash → collection) then let it run.
2. Validate the matrix §2 (feasible vs blocked widgets) — in particular: do we accept
   the `access` "by door" widgets at ~62%, and the `badge_number` fallback in
   the absence of `identity_upn`?
3. On confirmed real flow, I provision the 3 views (FEASIBLE widgets only)
   via idempotent `provision_dashboards.py`, then widget-by-widget acceptance testing.

**→ Stop at the Phase 6 entry checkpoint. Awaiting the establishment of the real flow
and the validation of this matrix before any provisioning.**
