# Adding the 2nd SEAL — BX-SEAL-OMEGA (10.33.140.1) — PRODUCTION

Onboarding a second SEAL in multi-site. The site is distinguished by the
`seal_site` field (`bx-qa-seal-vm` for the current one, `bx-seal-omega` for this server).
The existing SEAL streams, pipelines, dashboards and detections cover BOTH
sites without modification. QA → PROD: reinforced precautions below.

Verified facts: `10.33.140.1:1433` open from the SIEM; host =
`BX-SEAL-OMEGA.omnitech.security`; OMNITECH root CA already in the truststore.

---

## 0. PRODUCTION — precautions (read before starting)

- **Collection = read-only** (service account on views): low risk.
- **The sensitive point = adding the rowversion on `dbo.EVENEMENTS`** (watermark):
  `ALTER TABLE ADD <rowversion>` **rewrites the entire table**. On a production
  EVENEMENTS (potentially several million rows) → **maintenance window
  + CISO approval**. Two options:
  - **Option A (recommended if the window is possible)**: apply the DDL as
    is (like QA). `ALARMES.VERSION` is already a native rowversion (no
    ALTER); the 15 `Audit.*` tables are small (instant ALTER); only
    `EVENEMENTS` requires the window.
  - **Option B (no table rewrite)**: do NOT add a rowversion on
    EVENEMENTS; use `EVEN_STORAGE_TIMESTAMP` (NOT NULL, server timestamp)
    as the watermark. Requires a variant of the `vw_SealEvents_SIEM` view
    exposing `EVEN_STORAGE_TIMESTAMP AS WatermarkTs` and a Logstash input with
    `tracking_column_type => "timestamp"` (instead of numeric) with a slight
    overlap (`>=` + dedup) since a datetime is not strictly monotonic.
    Ask me to generate the variant if you choose B.
- **Do NOT run `inject_synthetic.sql` / `cleanup.sql` on prod** (QA
  only; the `BX-QA-SEAL%` guardrail blocks them anyway).

## 1. On BX-SEAL-OMEGA (SQL, admin) — DDL

Same package as QA (`1-sql-sur-SEAL/`). The service account is **dedicated to this
server** (distinct credentials):

```sql
CREATE LOGIN [svc_graylog_seal] WITH PASSWORD = '<strong DEDICATED omega password>', CHECK_POLICY = ON;
USE [SEAL]; CREATE USER [svc_graylog_seal] FOR LOGIN [svc_graylog_seal];
```

Then (maintenance window for step 01):
```powershell
powershell -ExecutionPolicy Bypass -File .\Run-SealDDL.ps1 -SqlUser sa
```
The DDL has no machine guardrail (it targets `-d SEAL` on the current server):
nothing to lift for the DDL. Verify at the end of the run: 5 views created, account locked.

## 2. On the SIEM — keystore (OMEGA credentials)

```bash
KS=/usr/share/logstash/bin/logstash-keystore
KP=$(grep -oP 'LOGSTASH_KEYSTORE_PASS=\K.*' /etc/logstash/keystore.env)
printf '%s' 'svc_graylog_seal'        | LOGSTASH_KEYSTORE_PASS="$KP" $KS --path.settings /etc/logstash add SEAL2_DB_SVC_USER --stdin
printf '%s' '<omega svc pwd (Vault)>' | LOGSTASH_KEYSTORE_PASS="$KP" $KS --path.settings /etc/logstash add SEAL2_DB_SVC_PWD  --stdin
```

## 3. On the SIEM — deploy the OMEGA inputs

```bash
sudo install -m0640 -o root -g logstash seal/logstash/seal-omega.conf /etc/logstash/conf.d/seal-omega.conf
# seed the watermarks (choose):
#   - no backfill (recommended in prod at startup): current
#     @@DBTS value of BX-SEAL-OMEGA (SELECT CONVERT(BIGINT,@@DBTS) on this server)
#   - full backfill: '--- 0'
for f in events alarms audit; do printf -- '--- <SEED>\n' > /var/lib/logstash/seal/.omega_${f}_last_run; \
  chown logstash:logstash /var/lib/logstash/seal/.omega_${f}_last_run; chmod 0640 /var/lib/logstash/seal/.omega_${f}_last_run; done
sudo -u logstash env LOGSTASH_KEYSTORE_PASS="$KP" /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
systemctl restart logstash && journalctl -u logstash -f
```
Note: `seal-omega.conf` contains ONLY the inputs; the filter and GELF output
of `seal.conf` apply (merged pipeline). Do not redefine filter/output there.

## 4. Verification

```
# OMEGA events must arrive, tagged seal_site=bx-seal-omega:
#   event_source:seal AND seal_site:bx-seal-omega
# Breakdown by site (to add to the dashboards if needed): pivot on seal_site.
# Detections/correlation cover OMEGA automatically (routing by domain).
```

## 5. Reminders
- Rotate the OMEGA service account password after go-live.
- `seal_site` is present only on events ingested AFTER this deployment
  (the already-ingested QA history has no such field; filter `NOT seal_site:bx-seal-omega`
  to isolate QA if needed).
- Scope unchanged: no `VDO_*` video stream, no `UserData.SearchHistory`.
