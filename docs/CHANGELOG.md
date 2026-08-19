# Changelog — SIEM OMNITECH

All notable changes to the platform. Format: date — change.
*Last review: 2026-06-22.*

## 2026-06-22 (ML layer, enriched console, quality)

### `oms-ml` learning layer
- **Unsupervised anomaly detection** (IsolationForest, log1p + StandardScaler)
  per entity (host/account) — explainable 0-100 score (z-score), re-injected as GELF
  (`event_source=ml_anomaly`). Deployed (`77-ml-scoring.sh`, timers).
- **Supervised false-positive reduction**: labels = **True/False positive
  disposition** set at case closure in the console (closed loop); trains
  from ~30 qualified cases onward.
- **`79-interne-indexset.sh`**: dedicated `omni-interne` index set for the internal
  stream — fixes a blind spot: `ueba_score` (74 k), `collecte_sla`, `siem_health`,
  `xdr_incident`, `ml_anomaly` were being written to `graylog_0`, invisible to the console.

### SOC console — premium visual redesign + enrichments
- Premium interface (glassmorphism, glow, tinted metallic KPIs, micro-interactions).
- **Overview**: **ML Anomalies** + **UEBA Risk** cards (real scores),
  **KPI trends** (▲/▼ % vs previous period).
- **Detections**: free-text search + CSV export + **real severity** (`risk_severity`
  instead of `priority`, which is absent) + risk score.
- **⌘K palette**: live entity search → Entity-360.
- **Incidents**: TP/FP disposition (feeds the ML) + `cases.json` lock (race).
- **Health**: self-supervision robots (X/Y), collection coverage (SLA),
  list of go-dark hosts.
- **Attack graph**, filterable (tactic / volume / entity centering).
- **Entity-360**: ML + UEBA score + event pagination.
- **Leaks & Dark Web**: summary by category + reassuring "no leak" state.
- **Executive report** enriched (operational posture, ML/UEBA at-risk entities).

### Ergonomics / UX / mobile
- Keyboard accessibility (visible focus, focus-trap, ARIA), feedback **toasts**,
  loading skeletons, adjustable **refresh cadence**, **help panel
  (?)** + **density toggle**.
- **Mobile PWA**: **Threat** tab (console parity: threat, KPI, ML/UEBA, detections).

### Quality / performance / audit fixes
- **TTL in-memory cache** on heavy aggregations (ATT&CK matrix ~783→7 ms,
  report ~811→3 ms).
- **Offline test suite** (`run-tests.sh`, 23 tests: redaction + oms-ml).
- **Redaction mode** (`MOBILE_REDACT`) for anonymized screenshots.
- Multi-agent audit fixes: supervision robots **versioned**
  (`61-supervision-robots.sh`), `ensure_lookup` **centralized** in `lib-graylog.sh`
  (fixes the silent failure of the m365 lookup), **`service_stop_securite`** alert
  (T1489, ransomware precursor) wired (`78`), integrity-doc honesty
  (HMAC key co-located).

### Detections ready to deploy (NOT deployed — `80-detection-extra2.sh`)
3 zero-false-positive tripwires validated by OpenSearch survey (30 d): `defender_tamper`
(T1562.001), `schtask_payload` (T1053.005), `amsi_bypass` (T1562.001). To deploy
after review (then re-run `57` followed by `14`).

### Graylog hardening (streams / index / dashboards / correlation / FP)
- **False-positive reduction (`81-fp-allowlist.sh`, deployed)**: "OMNI - Allowlist FP"
  pipeline (stage 25) — for **measured** benign patterns
  (scheduled_task 97% FP, service_install 86% FP, including our own
  winlogbeat/Sysmon agents), sets `fp_allowlist=true` and **removes `alert_tag`** (the alert
  no longer fires; the event stays indexed). Reversible (lookup `fp-allowlist.csv`).
- **"OMNI - Analytics" dashboard (`82-...`, deployed)**: 5 tabs — overview,
  ML anomalies, UEBA, coverage & health, noise/FP.
- **Kill-chain correlation (`oms-xdr/rules.yaml`)**: 4 multi-signal rules
  (LSASS theft→persistence, offensive PowerShell→persistence, cred usage→admin
  share, LSASS→lateral 6 h) + 6 signals + per-signal window. Additive, dry-run
  response preserved; live at the next `oms-xdr` timer cycle.
- **Consolidated retention (`83-...`, dry-run by default)**: single source of
  truth (values = `POLITIQUE-RETENTION.md`); fixes the
  `OMNI - FortiManager` routing (graylog_0 → `omni-fortimanager`). `APPLY=1` to apply
  (0 immediate deletion; auto-purge beyond thresholds thereafter).
- **Kerberos alert consolidation (`84-kerberoast-dedup.sh`, dry-run by default)**:
  kerberoasting/RC4 ×3 and AS-REP ×2 on the same event → **5 alerts → 2**
  (canonical source = `73`), coverage-loss safeguard. AES posture
  confirmed (zero RC4/0x17 in 90 d → latent noise). `APPLY=1` to consolidate.

## 2026-06-14 (consistency audit & new sources)

### New sources integrated (`52-new-sources.sh`)
- **ESET PROTECT** (10.33.50.20): Syslog TCP 1515 input (514 redirected by the
  firewall), "OMNI - ESET" stream, `event_source=eset` (+ threat tag). Dedicated
  `omni-eset` index set (365 d retention). "ESET: detection" alert (mail route).
- **BunkerWeb WAF** (10.33.70.1): Filebeat → Beats 5044, "OMNI - BunkerWeb" stream
  (routing by `event_source=bunkerweb` set by Filebeat), WAF tag, `http_*`/`waf_*` fields.
  Dedicated `omni-bunkerweb` index set (90 d retention), "WAF BunkerWeb" dashboard page.
- **NPS** (10.33.50.247): already mapped on the SIEM side (lookup `win-events.csv` 6272/6273/6274
  + alert added in 13). Winlogbeat still to be deployed server-side — **not yet
  reporting on the client side**.

### Bugs fixed (consistency audit 2026-06-14)
- **FortiGate timestamp**: sets `timestamp` from `eventtime` (epoch
  nanoseconds) — rule `omni-forti-05-eventtime`, compliant with A.8.17 (time sync).
- **Brute-force false positives**: exclusion of machine accounts (`*$`) and noisy
  service accounts (`ninjaone`, `ADSyncMSA_*`) that fail in a loop.
- **PowerShell**: exclusion of `wakeup-ssrs.ps1` (legitimate recurring task).
- **vSphere brute-force**: exclusion of `vpxuser` / `dcui` / `localhost`; **(2026-06-15)** exclusion of the **ESXi cluster service noise** (`clusterAgent`/gRPC "authentication handshake failed", expired **SAML token**) that was mis-tagged `auth_echec` (empty user/src_ip) → generated **false brute-force** (per ESXi node IP and "(Empty Value)") and false **"At-risk host" UEBA** on the infrastructure. Fixed at the root (`19-vsphere.sh`, rule `omni-vsphere-10-auth-fail`).
- **Incident deduplication**: `event_source=incident` routed to "OMNI - Interne
  SIEM" with symmetric exclusion on the M365 side (anti-dup) — `44-incidents.sh`.
- **cert-check** switched to permanent telemetry.

### Architecture & retention
- **Dedicated index sets** for ESET and BunkerWeb (separation of streams and retention).
- Current retention: **FortiGate = 180 d**; Windows/Sysmon/vSphere/M365/ESET = 365 d;
  **BunkerWeb = 90 d**. `/data` disk: 7.3 TB.
- FortiGate: `source` = device name (host).

### Alert routing (2 tiers — `22-alert-routing.sh`)
- **Teams = firehose**: all alerts.
- **Mail = critical "wake me up"** only (confirmed compromise + SIEM
  health), 26 alerts. Grace period for recurring mail alerts raised to ≥ 60 min.
- Enriched, *source-aware* mail/Teams templates (script 13).

### Purge tooling
- `53-purge-clean.sh`: purges **data** (logs + alert history) while
  preserving **the entire configuration** (method: deflector cycle + deletion of
  old indices via the API). Chains into `54-post-purge-repopulate.sh` (rebuild
  of ranges, M365 re-fetch, restart of analysis robots).

### Verifications (live)
- Single **"OMNI - SOC" dashboard with 24 pages**, `requires={}` (100% OSS, no
  Enterprise).
- 144 pipeline rules, 88 event definitions, 13 active streams (including
  ESET, BunkerWeb, FortiGate).

### Sources & enrichments added (rest of the day)
- **Vaultwarden** (BX-VAULTWARDEN, Docker → Filebeat): dedicated stream + pipeline
  (`55-vaultwarden.sh`), **dedicated `omni-vaultwarden` index set** (90 d) — avoids
  eviction of the SIEM's internal events. Client kit `/kit/vw-filebeat.sh`
  (anti-replay: `ignore_older 72h` + persistent registry). Vault detections:
  `vault_auth_fail` (brute-force with src_ip/account), MITRE T1555.
- **FortiGate DHCP attribution** (`56-fortidhcp.sh`): REST API collector
  (read-only token) → lookup `omni-dhcp-attribution` (ip→hostname/MAC), 15 min timer.
  The FortiGate pipeline sets `src_hostname`/`dest_hostname` on internal
  IPs (rules `omni-forti-06-dhcp-src/dest`) → "who is behind 10.33.x.x".
- **Unified identity** (`58-identity-correlation.sh`): `identity`
  (canonical account: no domain/upn, lowercase) + `identity_human` (groups
  `adm-X`/`svc-X` under the person) fields on winsec/sysmon/winother/M365/FortiGate/vSphere.
  **"Identity"** dashboard page (pivot 1 person, all sources). Already correlates
  jmorin/adm-jmorin on FortiGate+AD+Sysmon.
- **M365 / Entra ID Protection**: ingestion of `riskDetections` (permission
  `IdentityRiskEvent.Read.All`) → `m365_type:risk`, tag `m365_risque` (atRisk),
  mail alert. Revealed the **jaubert** account flagged atRisk (foreign cloud attack).
  Detection `m365_brute_externe` (M365 failures outside FR, T1110).

### Detection — MITRE coverage & new rules
- **MITRE ATT&CK coverage map** (`57-mitre-coverage.sh`): layer
  `docs/mitre-navigator-layer.json` (to load into ATT&CK Navigator) + report.
  **58 detections / 44 techniques / 12-14 tactics** (cf. COUVERTURE-MITRE-ATTACK.md).
- **Privilege Escalation filled** (`47-detections-extra.sh`): `uac_bypass`
  (T1548.002), `scheduled_task` (T1053.005), `service_install` (T1543.003). +
  `remote_discovery` (T1018), `service_stop_securite` (T1489).
- **Sensitive file audit** (`59-file-audit.sh`): parses 4663/5145, tags
  `file_sensitive_access` (T1039) / `file_delete_sensible` (T1485), mass access/
  deletion alerts (exfil/ransomware). *Armed* — requires SACLs on the servers.

### Integrity & encryption (ISO pillars)
- **Log integrity** (`60-integrity.sh`, A.8.15): daily **hash-chained + HMAC-signed**
  register of the corpus state, off-SIEM copy (SMB),
  `omni-integrity --verify` (weekly + mail alert if the chain is broken — tested: a
  tampering is detected). **Graylog role "OMNI - Analyst (read-only)"**
  (least privilege, A.8.2).
- **Encryption at rest** of `/data` (A.8.24/A.5.33) **completed on 2026-06-14**:
  **LUKS2 (inline header, aes-xts 512 bits) + TPM2/PCR7 unlock**. Fresh encrypted
  reformat (config outside `/data` preserved, logs repopulated). See PROCEDURE-CHIFFREMENT-REPOS.md.
- **Encryption supervision**: `omni-self-health` now verifies that `/data`
  (encrypted) is indeed open + mounted (alert if the TPM fails at boot or if the volume
  is unmounted); the **LUKS header is included in the daily config backup**
  (encrypted, out-of-band `/SIEM/luks/`) → recovery always up to date.
- **Advanced SOAR**: playbook scoping (isolate host / disable account /
  ticket) pending the NinjaOne API. See SOAR-PLAYBOOKS.md.

### Multi-agent audit & fixes (consistency)
- **Pipeline halt-traps fixed** (a "match either" stage with no satisfied rule
  stops the pipeline): Network exposure (privflags + 4th direction
  `transit`), External sources (pass-through rule), Identity (pass-through/stage).
- **Veeam**: `veeam_job_echec` = **final** job failure (eid 190) only;
  transient retries (eid 450, "restore point locked") → `veeam_job_warn`
  (view, no alert). No more false "backup failed".
- **SOAR reconnected and made permanent** (the sync in 13 now preserved it),
  **ESET fields** fixed (`eset_action`), **Vaultwarden loop** dropped
  (~9k/day of noise), **`vw_level`** unified, false **"robot down"**
  (omni-self-health: robust age calculation) removed. New supervised robots.
- **Anti-spam mail**: 26 critical alerts by mail ("wake me up" tier),
  everything else in Teams (firehose). Added "Audit sabotage" to mail.

### Data hygiene
- **Vaultwarden replay purge**: Filebeat had replayed the entire container
  history (2023→2026). ~23 M backdated docs purged from the Default `graylog_*` index
  **and** ~23 M from the Windows `omni-winother_*` index (double routing fixed). Real
  internal/Windows events are preserved.

## 2026-06-12 (afternoon — fixes, audit & optimizations)

### Bugs fixed (consistency audit)
- **vSphere parsed nothing**: stage 0 of the pipeline contained only the
  "drop noise" rule in *match either* — any non-noise message was blocked
  before normalization (0 host/event_action on 44k logs/15 min). Fixed.
- **M365 Activity collector crashed** (naive vs aware datetime): crashed on
  every run after the first → empty M365 Activity page. Fixed +
  cursor reset → 53,000+ M365 events (Exchange/SharePoint/OneDrive/Teams).
- Fix applied to the binary **and** the source script (anti-regression).

### Optimizations
- **vSphere −87%**: filtering of ESXi storage noise (vSAN traces, osfsd,
  envoy-access, vmkwarning; empty application_name on ESXi → filter on
  content). 26k → 3.4k logs/5 min, security events preserved.
- **SOAR whitelist** populated (legitimate France VPN IPs + Ivry site IPs),
  tested. To be completed with the public IPs of the Bordeaux/PACA sites.

### Verifications
- Full audit: 56 pipeline rules (0 errors), 0 indexing failures, all
  services/timers OK, 43 definitions, nominal throughput.
- Veeam confirmed functional ("Veeam Backup" channel + active failure alert).
- Log purge (clean base): real-time collection verified on all streams.

## 2026-06-12 (consolidation)

### Security / detection
- **SOAR-light**: automatic blocking of attacking IPs (VPN/spraying alerts)
  via a threat feed read by the FortiGate. Safeguards: never an internal IP/whitelist,
  threshold, ceiling, 24 h expiry, traceability.
- **AD canary account**: internal intrusion detection (lookup + rule + alert
  + creation script `New-OmniCanary.ps1` with a Kerberoasting-bait SPN).
- FortiGate VPN hardening (FR geo-restriction) — spraying campaign stopped.
- Full FortiGate UTM enabled on the 3 clusters (AV/IPS/web/DNS/app-control).

### Resilience / compliance
- Daily encrypted (AES-256) configuration backup externalized to SMB,
  14 d retention, self-monitored + **DRP** (rebuild plan) + RESTORE.md.
- ISO-aligned retention (365 d identity/cloud, 180 d network/endpoint) + disk
  safeguard (alert at 80%, emergency purge at 88%).
- **Automatic weekly report** (Monday 08:00) — review evidence.
- **ISO 27001 documentation set**: policy, standard, procedure, architecture
  dossier, compliance register, DRP, LDAPS, executive summary.
- Console authentication by **LDAPS** restricted to Domain Admins.

### Operations
- **Veeam** integration (Windows channel) — revealed a critical job in failure.
- Single Windows enrollment script `Install-OmniSiem-NinjaOne.ps1`.
- Alert-storm fix (grace periods/keys, service account detection).
- **Log purge** (clean base) after the build/test phase.

## 2026-06-13 (UEBA/NDR, MITRE ATT&CK & incident correlation)

### Advanced detection (beyond Graylog)
- **UEBA / NDR layer** (`40-ueba-ndr.sh`): collectors `omni-ueba-volume`
  (volume anomaly per source, same-hour-of-day z-score), score, geo, and
  new country — autonomous robots feeding the internal SIEM stream.
- **Network NDR**: internal scan detection (`48-ndr-scan.sh`, T1046),
  DNS exfiltration/tunneling (`43-ndr-dns.sh`, T1071.004), beaconing, lateral
  movement and exfiltration.
- **LDAP / directory reconnaissance** (`49-ldap-recon.sh`): detection of
  BloodHound / SharpHound via the `omni-ldap-recon` collector.
- **Attack-chain correlation → incidents** (`44-incidents.sh`): the `omni-incident-correlate`
  correlator aggregates the detections of a single entity into scored
  incidents (`incident_score`), routed to "OMNI - Interne SIEM".
- **Complementary detections** (`47-detections-extra.sh`): 5 rules from the
  multi-agent review, in a dedicated pipeline.

### Mapping & MITRE
- **MITRE ATT&CK mapping + risk score** (`37-mitre-attack.sh`):
  `alert_tag` → technique (Txxxx) / tactic / severity / score, via a CSV lookup.
- **Real-time cyber map** (`42-carte-cyber.sh`): animated flow arcs generated
  outside Graylog (`omni-geo-flux` → `flux.json`).
- **Internet exposure & at-risk port class** (`49-expo-port-class.sh`):
  enrichment of FortiGate flows.

### Operations & supervision
- **Robot self-supervision** (`46-self-health.sh`): `omni-self-health`
  routes `event_source=siem_health` → INT, 30 min timer ("Analysis robot
  down" alert).
- **Monthly executive report** (`45-monthly-report.sh`): HTML + PDF (weasyprint),
  sent on the 1st of the month at 06:00, archived under `/var/www/siem-kit/rapports/`.
- **Breakdown of M365 failures by Azure AD code** (`48-m365-fail-codes.sh`).

## 2026-06-11 (initial production release)
- SIEM build: model (index/streams/inputs), 55 pipeline rules,
  detections, 24-page dashboard, end-to-end TLS, M365 collection, FortiAnalyzer,
  vSphere, Windows agent deployment (NinjaOne + GPO).

---
*Keep up to date with every change. Detailed technical reference: `CONTEXT.md`
(repo root). See also `INTEGRATION-SOURCES.md`, `INVENTAIRE-SOURCES.md`,
`POLITIQUE-RETENTION.md` and `REPONSE-AUTOMATISEE.md` in `docs/`.*
