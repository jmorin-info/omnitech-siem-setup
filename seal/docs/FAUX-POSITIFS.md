# SEAL — false positives and blind spots (review of 16/07/2026)

Review conducted on **7 days of real collection** (995 k accesses, 717 k alarms, 5.4 k audit)
and cross-checked in SQL against the source views. It revealed as many **false negatives**
(detections unable to trigger) as false positives.

## Summary

| Rule | Finding | Fix |
|-------|---------|-----------|
| **ALM-001** | **Dead**: `IS_INHIBITED` (bit) never reaches Graylog | SQL view in varchar + tolerant query |
| **ALM-004** | **Dead**: `IS_INTEMPESTIVE` is a *date*, not a boolean | `_exists_:IS_INTEMPESTIVE` |
| **ALM-001/003/004** | Grouping on `target_object_label` (100% empty in the index) | `trigger_code` (99.40%) + `seal_site` |
| **ACC-006** | Grouping on an empty field (0.00% in the index) → alert "denial on ONE door" triggered by 5 different doors | `target_object_id` (99.44%) + `seal_site` |
| **ACC-007** | Same + empty entity on the non-badge events | `+ _exists_:badge_number` |
| **EVT-002** | 76 alerts/7 d, **100% false positives** | **parked** + replaced by DQ-001 |

## The central pitfall: `bit` columns are lost

`IS_INHIBITED` is populated on **703,641 rows / 703,641** in the database. It is
present on **0 documents** in the index.

Cause: Logstash converts `bit` → boolean, and its GELF output **does not emit the
fields valued `false`**. The field never reaches Graylog. The ALM-001 detection
(alarm inhibition, T1562.001) was therefore querying `IS_INHIBITED:true` on a
nonexistent field: **structurally unable to trigger**, while
appearing green and active in the console. Same mechanism on `IS_PRIORITY`.

The `varchar` columns pass through — which is why `off_hours`, which holds the *string*
`'true'`/`'false'`, has worked from the start.

> **Rule to remember: never expose a `bit` column to a SIEM view.**
> Cast it to varchar (`'true'`/`'false'`). Verification:
> ```sql
> SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
> WHERE TABLE_NAME LIKE 'vw_Seal%' AND DATA_TYPE = 'bit';   -- must be empty
> ```

Fix: `/tmp/sql/01_fix_bit_columns.sql` (= `seal/sql/03_vw_SealAlarms_SIEM.sql`),
to be run on **QA and OMEGA**.

## The second pitfall: grouping on an unpopulated field

Graylog does not flag a `group_by` on an absent field: it puts everything into a
single **`(Empty Value)`** bucket. Visible in the real alerts:
`ACC-006 ... : (Empty Value)`.

Measured fill rates. **Two different populations**, not to be confused:
the SQL view describes the QA database; the index describes what is actually collected (very
largely OMEGA). A field may be populated in one and absent from
the other — this is the case of `target_object_label`.

| Field | SQL view (QA) | Index (all sites) | Verdict |
|-------|--------------|--------------------|---------|
| `target_object_label` | 8.5% (81,918 / 961,303) | **0.00%** (1 / 997,481) | unusable |
| `target_object_id` | 99.5% (956,154 / 961,303) | **99.44%** (991,930 / 997,481) | access key |
| `trigger_code` *(alarms)* | 100% (703,641 / 703,641) | **99.40%** (715,015 / 719,303) | alarm key, and **readable** |
| `badge_number` | 0.04% (399 / 961,303) | 0.13% (1,328 / 997,481) | mandatory `_exists_` guard |
| `identity_matricule` | 0.009% (87 / 961,303) | 0.01% (74 / 997,481) | badge→AD bridge empty |

> **Measurement pitfall** (encountered, fixed on 16/07): by default OpenSearch caps
> `hits.total` at **10,000**, whereas the aggregations count exactly. Comparing an
> `exists` against this capped total produces wrong percentages — even exceeding
> 100%. Always query with `"track_total_hits": true`.

### `seal_site`: sound for detection, misleading in history

| Window | Presence of `seal_site` (accesses) |
|---------|-------------------------------|
| Last 24 hours | **99.91%** |
| Last 7 days | 98.80% |
| All history | **3.63%** |

The field is set by Logstash (`add_field`): the historical backfill, being earlier,
does not carry it. The detections work on windows of 10 to 15 minutes,
therefore on a coverage close to 100% — grouping by `seal_site` is safe. On the
other hand, **any retrospective analysis by site over the history is skewed**:
96% of the old events have no site.

`trigger_code` carries the real labels: `ENTREE PRINCIPALE`, `LECT COURSIVE R+1`,
`PORTAIL OMEGA`. The alarm alerts now name the location.

Concrete consequence of ACC-006 before the fix: **all** the doors of **both**
sites fell into the same bucket. Five denials on five different doors
triggered "repeated denied accesses on *one* door" — and the alert did not say
which one. False positive both in substance *and* in form.

## EVT-002: the rule that measured something other than what it claimed

`EVT-002` ("unknown/unenrolled badge presented") tested
`NOT _exists_:identity_matricule`. But `identity_matricule` is only populated on
**87 rows / 961,303** (0.009%). The rule therefore did not measure the unknown status of a
badge but **the fill rate of the badge → AD bridge**: any legitimate badge came back
as "unknown". 76 alerts in 7 days on 39 badges, 100% false positives.

No threshold tuning corrects this. **But the cause is not the one I had
announced**: I first wrote that SEAL lacked an identifier
attachable to the directory, and that it was therefore a governance decision. That is
**false**. The `milf.BADGES.MATRICULE` column exists, and the views do retrieve it
correctly (`b.MATRICULE AS identity_matricule`). Measurement of 16/07 on
`vw_SealIdentity_SIEM`:

| Site | Holders | With matricule | With badge |
|------|---------:|---------------:|-----------:|
| **OMEGA (production)** | 443 | **187 (42.2%)** | 439 (99.1%) |
| QA | 98 | 19 (19.4%) | 61 (62.2%) |

The bridge therefore works for **two badges out of five** in production. `EVT-002`
was triggering on the remaining 58% — legitimate holders whose matricule
simply was not entered. This is a **reference-data fill issue**, not a technical
impossibility: the rate rises as soon as the entry is completed on the
badge management side.

Hence the choice: park `EVT-002` and **measure** the rate with `DQ-001` instead of
alerting on it.

Reactivation, once the bridge is populated:
```bash
seal/detections/provision_detections.py --apply --enable-parked
```

## Volumetry after fix (simulated on the 7 real days)

| Rule | Alerts / 7 d | Entities |
|-------|---------------|---------|
| ACC-006 | 10 | 2 doors |
| ACC-007 | 15 | 11 badges |
| ALM-003 | 0 | no break-in over the period |
| ALM-004 | 0 | no flood over the period |
| DQ-001 | 4 | 1 site |
| EVT-002 *(before)* | **203** | 43 badges |

## What remains an accepted blind spot

- **Alarm acknowledgment**: `ACK_EVEN_ID` is only populated on **6 rows /
  703,641**. The SLA therefore does not measure "unacknowledged alarm" but "alarm
  left *open*" (last status `LIV`). This is usable, but it must be
  stated: the acknowledgment dimension does not exist in the data.
- **Badge → AD bridge**: populated at **42% in production** (187/443 holders).
  Neither impossible nor broken: to be completed by data entry. See EVT-002.
- **`IS_INHIBITED` is `false` everywhere**: no alarm has ever been inhibited.
  The fix will therefore trigger nothing today — it guarantees that a
  **future** inhibition will be seen.
- **88% of the "access" flow is technical** (`SEM97`, reader connection loss,
  `event_outcome:na`): no impact on the detections (filtered on
  grant/deny), but it inflates the stream and the dashboards.
