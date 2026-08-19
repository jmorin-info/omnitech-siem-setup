# ACCEPTANCE TEST — SEAL → Graylog Integration (QA ONLY)

OMNITECH SECURITY · SIEM (`omnitech-siem-setup`) · MISSION_SEAL_GRAYLOG
Authority: `seal/docs/CONTRACT.md`. Scope: `bx-qa-seal-vm.omnitech.security`
(`10.33.120.2:1433`) — **never production**.

> This acceptance test validates the complete chain
> SEAL (SQL) → SIEM views → Logstash (JDBC, watermark) → GELF `10.33.220.10:12201`
> → Graylog streams/pipelines → detections → Teams notifications.
> It combines (A) manual actions in the SEAL QA UI, (B) a synthetic SQL
> injection tagged `TEST_SIEM` for cases not reproducible via the UI
> (`inject_synthetic.sql` / `cleanup.sql`), and (C) testing the 3 dead man's switches.

## Prerequisites before acceptance test

- [ ] DDL applied (`sql/01..05` + `90_provision.sql`): columns `EVEN_ROWVER`
      (EVENEMENTS) and `RowVer` (15 `Audit.*` tables) present, views
      `vw_SealEvents_SIEM` / `vw_SealAlarms_SIEM` / `vw_SealAudit_SIEM` /
      `vw_SealIdentity_SIEM` created, login `svc_graylog_seal` restricted to the views
      (cf. RECON §9.6).
- [ ] Logstash installed (`jdbc` plugin + `mssql-jdbc`), SEAL pipeline started,
      JDBC chain pinned to IP `10.33.120.2` + `hostNameInCertificate=<FQDN>`,
      `encrypt=true;trustServerCertificate=false`. Secret via Logstash keystore
      (never in cleartext).
- [ ] Graylog: 3 streams (`OMNI - SEAL Accès` / `Alarmes` / `Audit`), normalization
      pipelines (contract D4), CSV Data Adapter `REEV_CODE → REEV_LIBELLE`
      regenerated, Teams notification (`TEAMS_WEBHOOK_URL`) wired to the
      SEAL event definitions.
- [ ] Watermarks seeded to the current value (no historical backfill,
      cf. CONTRACT D5). Verify `MIN_ACTIVE_ROWVERSION()` is not blocked by an
      open transaction.
- [ ] Quiet QA time window (volume ~158 events/24 h) for clear reading.

For each test: record the **injection time**, the **arrival time** of the message
in Graylog (`Search` filtered on `event_source:seal`), and the observed **latency**.

---

## A. Assisted acceptance test — SEAL QA UI actions

Graylog search convention for each step:
`event_source:seal AND actor_usercode:TEST_SIEM*` (if injected scenario) or filter
on `actor_login` / `door_id` / `operation_channel` as applicable.

### A1. Login failure ×5 then success (console) — HYP-001 / HYP-002
- **UI action**: on `SEAL Exploitation` or the `SealAdmin` console, attempt 5
  logins with a wrong password for the same test account, then 1 successful
  login.
- **Source table**: `Audit.UserConnections` (`Operation` = `ConnectionFailure` ×5
  then `Connection`).
- **Expected checks**:
  1. Arrival: 6 messages `event_domain:hypervisor_audit`,
     `event_action:"Connection*"` within 1 watermark cycle (~30 s).
  2. Normalization (contract D4): `event_outcome=failure` on the 5 failures,
     `success` on the 6th; `actor_login`, `src_ip` (`IpAddress`), `user_agent`,
     `operation_channel` populated.
  3. Detection: **HYP-001** (≥5 `ConnectionFailure` / window / same login)
     fires. **HYP-002 [SEQ]** (repeated failures THEN success) fires if
     the pipeline-state approximation is active; otherwise record "deferred
     v2" (Open edition, cf. CONTRACT D0).
  4. Teams: notification received (title HYP-001, `actor_login`, failure count).

### A2. Reactivation of a test badge — ACC-004
- **UI action**: in SEAL Millefeuille, take a **cancelled** badge (`ANN`) and
  set it back to **valid** (`VAL`).
- **Source table**: `Audit.TagMovements` (transition `ANN → VAL`).
- **Checks**:
  1. Arrival: message `event_domain:hypervisor_audit`, `badge_number` = test
     badge number.
  2. Normalization: readable status transition (contract D3: `ANN→VAL =
     reactivation`); `identity_matricule` resolved if the badge is in `milf.BADGES`.
  3. Detection: **ACC-004** (badge reactivation) fires.
  4. Teams: notification received.

### A3. Privilege escalation of a test account (OldIsAdmin 0→1)
- **UI action**: on a test operator account, check the administrator role
  (`SealAdmin`).
- **Source table**: `Audit.AccountsMovements` (`OldIsAdmin=0 → NewIsAdmin=1`).
  See also `Audit.AccountRolesMovements` / `ProfileRoleMovements`.
- **Checks**:
  1. Arrival: audit message, `target_login` = modified account.
  2. Normalization: `event_action` reflects the admin right grant,
     `actor_usercode` = operator who made the change.
  3. Detection: "SEAL administrator privilege grant" rule fires
     (detection reference: *to be frozen in the Phase 4 backlog*; MITRE class
     Privilege Escalation).
  4. Teams: notification received.

### A4. Manual command on a test door — CommandObject
- **UI action**: from the operations wall, send a manual command
  (open/unlock) on a **test door**.
- **Source table**: `Audit.CommandObject` (`ObjectType` door, `ObjectId` /
  `ObjectLabel` of the test door).
- **Checks**:
  1. Arrival: audit message with `target_object_type`, `target_object_id`,
     `target_object_label`, `door_id` populated.
  2. Normalization: `event_action` = command, `actor_usercode` = operator;
     `site` resolved via `ObjectsHierarchicalCatalog` if mapped.
  3. Detection: "manual door command" rule fires (monitoring
     door openings outside the normal access flow).
  4. Teams: notification received.

### A5. Inhibition of a test alarm — ALM (inhibition)
- **UI action**: inhibit (`IS_INHIBITED`) an active test alarm in the
  supervision console.
- **Source table**: `dbo.ALARMES` (`IS_INHIBITED` toggles; rowversion `VERSION`
  re-emitted on lifecycle UPDATE).
- **Checks**:
  1. Arrival: message `event_domain:alarm` reflecting the inhibition.
  2. Normalization: `severity_num` = `EVEN_SEVERITE`, `event_action` =
     decoded `REEV_LIBELLE`, inhibition indicator present in `seal_payload`.
  3. Detection: "alarm inhibition" rule fires (potentially masking
     operator action — to be correlated).
  4. Teams: notification received.

### A6. Break-in / forced door test — ALM-003
- **UI action** (if the bench allows): force a test door contact
  (unauthorized physical opening) OR simulate via injection (see §B).
- **Source table**: `dbo.EVENEMENTS` / `dbo.ALARMES` (`REEV_CODE` = **SEM113**
  break-in, compl. SEM105 reported physical opening).
- **Checks**:
  1. Arrival: message `event_domain:alarm`, `event_action` = "Door break-in".
  2. Normalization: `SEM113 → REEV_LIBELLE` decoding via CSV lookup OK
     (no raw `SEM113` in `event_action`).
  3. Detection: **ALM-003** (forced door) fires.
  4. Teams: notification received (high priority).

### A7. Log export — LogDownload
- **UI action**: trigger a log export/download from the console.
- **Source table**: `Audit.LogDownload`.
- **Checks**:
  1. Arrival: audit message `event_domain:hypervisor_audit`.
  2. Normalization: `actor_usercode`, `operation_channel`, exported volume/object
     in `seal_payload`.
  3. Detection: "SEAL log export" rule fires (exfiltration monitoring
     / MITRE Collection).
  4. Teams: notification received.

### A8. Login to the administration console — HYP-003
- **UI action**: log in via the **`SealAdmin`** channel.
- **Source table**: `Audit.UserConnections` (`OperationChannel = SealAdmin`).
- **Checks**:
  1. Arrival: audit message, `operation_channel:SealAdmin`.
  2. Normalization compliant with D4.
  3. Detection: **HYP-003** (admin console access) fires.
  4. Teams: notification received.

### A9. Nominal badge access — EVT-001 / EVT-002
- **UI action**: swipe a **known** badge then an **unknown** badge on a
  test reader.
- **Source table**: `dbo.EVENEMENTS` (`REEV_CODE` SEM138/SEM280) + lookup
  `AcApi.TAG` / `milf.BADGES` for badge recognition.
- **Checks**:
  1. **EVT-001**: normalized user access (`event_outcome=grant`), matricule
     resolved (~76.5 % coverage expected, cf. RECON §9.3).
  2. **EVT-002**: **unknown** badge (absent from the badge tables) → alert.
  3. Teams: EVT-002 notification received for the unknown badge.

---

## B. Coverage table — rule by rule (to be filled in)

Latency = message arrival → notification. FP = false positive (Y/N + comment).
Fill in the "Script ref." column with the corresponding `seal/detections`
detection script once frozen in the Phase 4 backlog.

| Rule | Label | Source / condition | Fired (Y/N) | Latency | FP (Y/N) | Script ref. | Notes |
|---|---|---|---|---|---|---|---|
| EVT-001 | User access (known badge) | EVENEMENTS SEM138/SEM280 | | | | | |
| EVT-002 | Unknown badge | access with no known badge (AcApi.TAG/milf.BADGES) | | | | | |
| ACC-004 | Badge reactivation | TagMovements `ANN→VAL` | | | | | |
| ACC-PRIV* | SEAL admin grant | AccountsMovements `OldIsAdmin 0→1` | | | | | *code to be frozen |
| ACC-CMD* | Manual door command | CommandObject (door) | | | | | *code to be frozen |
| ALM-001 | Alarm lifecycle | ALARMES transitions (VERSION) | | | | | |
| ALM-002 [SEQ] | Unacknowledged alarm | absence of `ACK` within delay | | | | | pipeline-state approx. / v2 |
| ALM-003 | Break-in / forced door | REEV_CODE SEM113 (+SEM105) | | | | | |
| ALM-004 | Spurious alarm / flood | IS_INTEMPESTIVE / SEM287/193/187 | | | | | |
| ALM-INH* | Alarm inhibition | ALARMES `IS_INHIBITED` | | | | | *code to be frozen |
| HYP-001 | Console brute force | UserConnections ≥5 `ConnectionFailure` | | | | | |
| HYP-002 [SEQ] | Failures then success | 5 failures → 1 success (same login) | | | | | pipeline-state approx. / v2 |
| HYP-003 | Admin console access | OperationChannel `SealAdmin` | | | | | |
| AUD-LOGDL* | Log export | LogDownload | | | | | *code to be frozen |
| XCO-* | Cross-correlation badge↔Windows logon | SEAL ↔ Winlogbeat BX-QA-SEAL-VM | | | | | v2 / approx. Open |
| DMS-ACCESS | Dead man access | silence on `omni-seal-access` flow | | | | | cf. §C |
| DMS-ALARM | Dead man alarms | silence on `omni-seal-alarm` flow | | | | | cf. §C |
| DMS-AUDIT | Dead man audit | silence on `omni-seal-audit` flow | | | | | cf. §C |

---

## C. Testing the 3 dead man's switches (source silence)

Objective: prove that stopping the SEAL flow (dead agent, JDBC outage, log
disabled by an attacker) triggers a **silent source** alert per
stream. Reuses the SIEM watchdog pattern (`74-source-watchdog.sh`,
`alert_tag=source_silent`) extended to the 3 SEAL sources:
`seal_access`, `seal_alarm`, `seal_audit`.

Each flow feeds a distinct stream/index (CONTRACT D5: 3 views, 3
watermarks). The 3 DMS are therefore **independent**.

### Procedure
1. **Baseline**: verify that the 3 streams are receiving (freshness < threshold).
   Generate if needed 1 event per flow (§A or §B) to timestamp `last_seen`.
2. **Configure the DMS thresholds** for SEAL (file `/etc/default/omni-watchdog`):
   e.g. `seal_access:30,seal_alarm:30,seal_audit:30` (minutes) — adapt to the
   QA cadence. A threshold ≤ 20 min guarantees firing during the test window.
3. **Stop Logstash for 20 min** (stop the transport, not the database):
   `sudo systemctl stop logstash` (record the time). No DDL, no SQL write.
4. **Wait for the watchdog run** (15 min timer) beyond the threshold.
5. **Expected checks**:
   - 3 distinct `alert_tag=source_silent` alerts for `seal_access`,
     `seal_alarm`, `seal_audit`.
   - 3 distinct Teams notifications (one per stream).
   - No false alert on the other SIEM sources.
6. **Restore**: `sudo systemctl start logstash`. The watermark resumes at the last
   `sql_last_value` — verify it **catches up** on the events from the stop
   window (no loss) and that the 3 DMS **go back to green** on the next cycle.

### DMS grid (to be filled in)

| DMS | Stream / source | Threshold (min) | Logstash stop time | Alert time | Teams notif (Y/N) | Back to green (Y/N) | Catch-up OK (Y/N) |
|---|---|---|---|---|---|---|---|
| DMS-ACCESS | `omni-seal-access` / `seal_access` | | | | | | |
| DMS-ALARM | `omni-seal-alarm` / `seal_alarm` | | | | | | |
| DMS-AUDIT | `omni-seal-audit` / `seal_audit` | | | | | | |

> Additional note (outside DMS transport scope): the UTL heartbeat signal
> `SEM70/SEM71` (RECON §9.2) is a **sensor**-side dead-man on SEAL, distinct from the
> 3 transport DMS above. To be covered separately in the detection backlog.

---

## Cleanup

After the acceptance test: `cleanup.sql` (removes every `TEST_SIEM` marker). Messages
already ingested in Graylog remain in the SEAL indices (12/12/24-month retention) —
filter them by `actor_usercode:TEST_SIEM*` to distinguish them. Restart
Logstash if stopped for test C.

## Points of attention

- **Volume non-regression**: after the acceptance test, confirm that the SEAL throughput
  drops back to baseline (~158 events/24 h) — no watermark loop.
- **Open edition**: the `[SEQ]` rules (HYP-002, ALM-002, XCO-*) may be in
  pipeline-state approximation or deferred to v2; record the actual status
  observed, do not mark "failure" if the limitation is documented (CONTRACT D0).
- **GDPR**: verify that no SEAL message exposes a forbidden column
  (CONTRACT D1) — inspect a sample of each stream (no photo, name,
  password hash, etc.).
