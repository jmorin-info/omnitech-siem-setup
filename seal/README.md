# SEAL → Graylog — SIEM Integration (OMNITECH SECURITY)

Integration of the **SEAL** BMS/access-control system (SQL Server database) into the
`omnitech-siem-setup` Graylog SIEM. **Scope: QA only.**

> Single design authority: [`docs/CONTRACT.md`](docs/CONTRACT.md).
> Phase 0 reconnaissance: [`docs/RECON.md`](docs/RECON.md).
> Acceptance test: [`tests/RECETTE.md`](tests/RECETTE.md).

## 1. Architecture — end-to-end flow

```
                    bx-qa-seal-vm.omnitech.security  (SQL Server 2019 Std)
                    10.33.120.2:1433   —  SEAL database   (QA ONLY)
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Source tables                 SIEM views (GDPR-minimized, D1)         │
   │  dbo.EVENEMENTS  ───────────►  vw_SealEvents_SIEM   (wm: EVEN_ROWVER)  │
   │  dbo.ALARMES     ───────────►  vw_SealAlarms_SIEM   (wm: VERSION)      │
   │  Audit.* (15)    ───────────►  vw_SealAudit_SIEM    (wm: RowVer,UNION) │
   │  milf.BADGES/... ───────────►  vw_SealIdentity_SIEM (enrichment)       │
   └───────────────────────────────────┬──────────────────────────────────┘
        JDBC (mssql-jdbc)               │  encrypt=true; trustServerCertificate=false
        Server=10.33.120.2,1433         │  hostNameInCertificate=<FQDN>  (IP pinned)
        WHERE WatermarkBig > :sql_last_value
              AND WatermarkBig < MIN_ACTIVE_ROWVERSION()   (CONTRACT D5)
                                        ▼
                    ┌─────────────────────────────┐
                    │  Logstash (SIEM VM 10.33.220.10)
                    │  jdbc input (secret: keystore) │
                    │  gelf output → 12201           │
                    └───────────────┬────────────────┘
                                    │  GELF  10.33.220.10:12201
                                    ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Graylog 7.1.3 Open                                                    │
   │  Normalization pipelines (CONTRACT D4: event_source/domain/...)       │
   │  CSV lookup  REEV_CODE → REEV_LIBELLE  (Data Adapter regenerated/cron) │
   │  Identity enrichment: matricule (SQL) → UPN (SIEM-side, mirror)        │
   │  Streams / index sets:                                                │
   │    OMNI - SEAL Accès    (omni-seal-access, 12 months)                 │
   │    OMNI - SEAL Alarmes  (omni-seal-alarm,  12 months)                 │
   │    OMNI - SEAL Audit    (omni-seal-audit,  24 months)                 │
   └───────────────┬───────────────────────────────┬──────────────────────┘
        Detections │ (EVT/ACC/ALM/HYP/XCO)          │ Dead man's switches
                   ▼                                ▼  (74-source-watchdog:
             Event Definitions              seal_access/alarm/audit)
                   └──────────────┬─────────────────┘
                                  ▼
                        Teams notification  (TEAMS_WEBHOOK_URL)
```

Key details (see CONTRACT):
- **Time zone**: `timestamp` in UTC. EVENEMENTS/ALARMES converted with
  `AT TIME ZONE 'Romance Standard Time' AT TIME ZONE 'UTC'`; `Audit.*` uses
  `OperationDateUtc` (already UTC).
- **Identity**: `EVEN_PHYSICAL_NUMBER → milf.BADGES → MATRICULE` (~76.5% in QA);
  `identity_upn` resolved on the SIEM side (AD/M365), absent in QA.
- **Open edition**: no native Correlation event def → `[SEQ]` rules
  approximated via pipeline state or deferred to v2 (documented limitation).

## 2. Deliverable contents

| Path | Role |
|---|---|
| `docs/CONTRACT.md` | Integration contract (single authority) |
| `docs/RECON.md` | Phase 0 reconnaissance (read-only) |
| `sql/00_recon_queries.sql` | Discovery queries (read-only) |
| `sql/01..05_*.sql`, `sql/90_provision.sql` | **DDL**: rowversion columns, SIEM views, `svc_graylog_seal` login (to be written/validated in Phase 1) |
| `logstash/` | JDBC → GELF pipeline (Phase 2) |
| `graylog/pipelines/`, `lookups/`, `detections/` | Normalization, REEV lookup, rules (Phases 3-4) |
| `tests/RECETTE.md` | Assisted acceptance test + rule-by-rule table + DMS test |
| `tests/inject_synthetic.sql` | Synthetic `TEST_SIEM` injection (QA) |
| `tests/cleanup.sql` | Purge of `TEST_SIEM` markers (QA) |
| `../seal_graylog_setup.py` | Orchestrator (`--phase preflight/recon/plan-sql/apply-*`) |

## 3. Operation

- **Idempotent provisioning**: `NN-*.sh` bash scripts + `lib-graylog.sh`
  (search-by-title before creation, create-or-update). Re-runnable without
  side effects. SQL uses `CREATE OR ALTER`.
- **Dry-run by default**: any modifying code requires an explicit `--apply`.
- **Secrets**: never in plaintext. `00-vars.env` (gitignored) + env variables +
  Logstash keystore. The preflight report discloses only the *presence* of secrets.
- **Source monitoring**: the 3 SEAL feeds (`seal_access`, `seal_alarm`,
  `seal_audit`) are added to the watchdog (`74-source-watchdog.sh`,
  `alert_tag=source_silent`) → dead man's switch per stream (see RECETTE §C).
- **REEV lookup**: CSV Data Adapter regenerated by cron from `dbo.REF_EVENEMENT`
  (no native JDBC lookup in Open). Check the CSV freshness.
- **Watermark**: monotonic via rowversion + `MIN_ACTIVE_ROWVERSION()` bound. On a
  Logstash stop, resume from the last `sql_last_value` (no loss, see RECETTE §C6).

## 4. ROLLBACK

Complete removal, in this order (QA; in prod, under a maintenance window):

1. **Graylog**: stop the notifications, delete the SEAL Event Definitions,
   the SEAL pipelines/rules, the pipeline→stream connections, the REEV
   lookup/adapter, then the 3 streams and their index sets (`omni-seal-access/alarm/audit`).
   Ideally via the `NN-*.sh` scripts in deletion mode, otherwise via API
   (`ensure_*` searches by title → delete by id).
2. **Logstash**: stop and disable the SEAL pipeline; remove the keystore
   entry; remove the 3 sources from the watchdog (`/etc/default/omni-watchdog`).
3. **SQL — views**: `DROP VIEW vw_SealEvents_SIEM, vw_SealAlarms_SIEM,
   vw_SealAudit_SIEM, vw_SealIdentity_SIEM;`
4. **SQL — login/permissions**: revoke the GRANTs on the views, then
   `DROP USER svc_graylog_seal` (database) and `DROP LOGIN svc_graylog_seal` (server).
5. **SQL — added rowversion columns** (reversible):
   `ALTER TABLE dbo.EVENEMENTS DROP COLUMN EVEN_ROWVER;` (table rewrite →
   **maintenance window**) and `ALTER TABLE Audit.<t> DROP COLUMN RowVer;` on
   the 15 tables (instant). `dbo.ALARMES.VERSION` is **native**: DO NOT remove it.
6. **Acceptance-test data**: `tests/cleanup.sql` (purge `TEST_SIEM`).

> The SEAL indices already written into Graylog remain subject to their retention;
> delete them explicitly if an immediate purge is required.

## 5. PROD notes (before the non-QA cutover)

- **Maintenance window — EVENEMENTS rowversion**: `ALTER TABLE ADD
  EVEN_ROWVER` rewrites ~961k rows (RECON §9.4) → schedule a window.
  The 15 `Audit.*` and `dbo.ALARMES.VERSION` (native) do not require a window.
- **Service-account rotation**: the `svc_graylog_seal` password transited
  through a chat channel during setup → **renew it** before prod, store it only
  in a keystore/env variable, and remove the recon `db_datareader` grant in
  favor of a GRANT SELECT on the views only (RECON §9.6).
- **SQL driver + Logstash install**: the driver (`msodbcsql18`+`pyodbc` or
  `pymssql`) and Logstash (`jdbc` plugin + `mssql-jdbc`) are **absent** from the
  SIEM VM (RECON §4). To be installed (packages, modifying action, plan to confirm).
- **DNS double record**: `bx-qa-seal-vm` has 2 A records (`10.33.120.2` +
  `10.108.15.143`, filtered). **Pin the IP** `10.33.120.2` in the JDBC string +
  `hostNameInCertificate=<FQDN>` (strict cert validation preserved).
- **SQL server cert**: CN=`bx-qa-seal-vm.omnitech.security`, exp. 2028-07-09 —
  monitor the expiry.
- **Graylog edition**: actual instance 7.1.3 (the mission stated 6.x). No API
  impact; the `[SEQ]` rules remain limited (Open).
- **Volume / thresholds**: calibrated on QA (~158 events/24h) — recalibrate the
  detection thresholds and the Logstash schedule on prod volumes.

## 6. DPIA / GDPR checklist (referenced — out of scope for this deliverable)

Minimization is **imposed by the contract** (`docs/CONTRACT.md` **§D1**): the
SIEM views exclude passwords/hashes/seed, photos, civil status and contact
details; `milf.BADGES` is limited to `PHYSICAL_NUMBER/BADGE_NUMBER/MATRICULE/STATUS/USER_TYPE/
COMPANY/SITE`; `*_ANON` descriptions are preferred; `identity_upn` is not
extracted in QA. Formal compliance (**DPIA**, legal basis, retention periods vs
the 12/12/24-month retentions, notice to data subjects, register) falls to the DPO
and is **not** produced here — this deliverable provides the **technical proof of
minimization** (forbidden columns never exposed) to attach to the DPIA file.
Associated acceptance-test check: RECETTE.md "Points of attention → GDPR".

## 7. Exact deployment order

Driven by `seal_graylog_setup.py` (dry-run by default, `--apply` to modify):

| # | Step | Command / script | Modifying | Checkpoint |
|---|---|---|---|---|
| 1 | **Preflight** (network/DNS/TLS/edition/creds) | `./seal_graylog_setup.py --phase preflight` | no | — |
| 2 | **Recon** (read-only SELECT) | `./seal_graylog_setup.py --phase recon` | no | decodings validated (RECON §9) |
| 3 | **DDL** (rowversion + views + restricted login) | `--phase plan-sql` then `--phase apply-sql --apply` (`sql/01..05` + `90_provision.sql`) | **yes (SQL)** | validate the DDL BEFORE exec |
| 4 | **Graylog provisioning** (streams/index, REEV lookup, normalization pipelines) | SEAL `NN-*.sh` / dedicated `--apply` phase | yes (Graylog) | contract D4 respected |
| 5 | **Keystore + Logstash** (keystore secret, JDBC→GELF pipeline, watermark seed) | Logstash install + config | yes (SIEM VM) | GELF flow visible |
| 6 | **Detections + DMS + Teams** | `detections/` scripts + `74-source-watchdog.sh` (SEAL sources) | yes (Graylog) | rules wired |
| 7 | **Acceptance test** | `tests/RECETTE.md` (+ `inject_synthetic.sql`, DMS test), then `cleanup.sql` | yes (QA data) | rule-by-rule table filled |

## 8. The 2 remaining operator steps

These two actions are **not** performed by the deliverable (system installation /
privileged DDL) and must be carried out by the operator.

### 8.1 Admin DDL (Phase 3 of the plan) — privileged SQL login
Apply the DDL with a **temporary SQL admin** account (the service account does
not have DDL rights). No secret in the files; the admin password is passed via
an environment variable, **not stored**:
```bash
export SEAL_DB_ADMIN_USER='<temporary_sql_admin>'
read -rs SEAL_DB_ADMIN_PWD; export SEAL_DB_ADMIN_PWD   # masked input, out of history
./seal_graylog_setup.py --phase plan-sql                # DDL review (no exec)
./seal_graylog_setup.py --phase apply-sql --apply       # runs sql/01..05 + 90_provision.sql
unset SEAL_DB_ADMIN_PWD
```
Effect: adds `EVEN_ROWVER` (EVENEMENTS) and `RowVer` (15 `Audit.*`), creates the 4
SIEM views, creates `svc_graylog_seal` restricted to the views (removes `db_datareader`).

### 8.2 SQL driver + Logstash install (SIEM VM `10.33.220.10`)
```bash
# SQL driver (either option):
sudo apt-get install -y msodbcsql18 python3-pyodbc      # OR: pip install pymssql
# Logstash + JDBC plugins:
sudo apt-get install -y logstash
sudo /usr/share/logstash/bin/logstash-plugin install logstash-integration-jdbc
# mssql-jdbc driver dropped into the SEAL pipeline directory (see logstash/)
# Secret out of plaintext — via Logstash keystore:
sudo /usr/share/logstash/bin/logstash-keystore add SEAL_DB_SVC_PWD
```
Then start the SEAL pipeline and **seed the watermarks** to the current value
(no historical backfill, CONTRACT D5). Verify the GELF arrival on
`10.33.220.10:12201`.

---

## Deployment status (2026-07-15)

**On the SIEM VM (10.33.220.10) — DONE and verified:**
- Logstash 8.19 installed (`seal/logstash/install-logstash-siem.sh`), mssql-jdbc
  12.8.1 driver, gelf/jdbc plugins.
- `seal.conf` deployed (`/etc/logstash/conf.d/`), SQL queries (`/etc/logstash/sql/`),
  watermark directory (`/var/lib/logstash/seal/`).
- Logstash keystore populated (`SEAL_DB_SVC_USER/PWD`) — generated passphrase
  supplied to the service via a systemd drop-in `EnvironmentFile=/etc/logstash/keystore.env`
  (0640, outside the repo). **`logstash -t` = Configuration OK.**
- **Dedicated SEAL GELF UDP input `OMNI - SEAL (GELF UDP 12202)`** (127.0.0.1) — the
  `gelf` (UDP) output could not target the GELF *HTTP* input 12201; validated E2E.
- `logstash` service **enabled but NOT started** (waiting on the views).

**Configuration fixes applied:** GELF output (UDP→dedicated 12202 input);
driver/SQL paths realigned; `vw_SealReev_SIEM` view (06) + grant so the
REEV lookup regeneration survives the `90_provision` lockdown.

**Remaining operator step (blocking) — DDL on SEAL:** my service account is
read-only (`db_datareader`), it cannot create the views. Package
ready: **`/tmp/seal-sql-package/`** (+ `.tgz`) — `Run-SealDDL.ps1` / `run-ddl.bat`
+ `sql/` (01→06, 90_provision) + README. To run on BX-QA-SEAL-VM with an
SQL admin login (e.g. `sa`).

**Commissioning order:** (1) DDL on SEAL → (2) `systemctl start logstash`
→ (3) verify arrival in the 3 streams → (4) turn
`seal/dashboards/DATA_READINESS.md` back to green → (5) Phase 6 dashboards.
