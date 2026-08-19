# DOS — SIEM Architecture and Operations Dossier

*Version 1.1 — 14/06/2026 — Classification: internal*
*Initial production release: 11/06/2026 — consolidation: 12/06/2026 — review: 14/06/2026*

## 0. Architecture diagram

```
 SOURCES                         COLLECTION / TRANSPORT        SIEM  bx-it-graylog-vm (10.33.220.10)
 ───────────────────────         ────────────────────         ─────────────────────────────────────
 DC · Servers · Endpoints ─────> Winlogbeat TLS  :5044 ─┐
   Security, Sysmon,                                     │
   PowerShell, Defender,                                 │      ┌──────────────────────────────────┐
   Veeam Backup, (NPS*)                                  │      │ INPUTS(7) ─> STREAMS(13) ─>       │
 BunkerWeb WAF ──> Filebeat TLS  :5044 ─────────────────┤      │ PIPELINES (20 / 144 rules)       │
   http_* / waf_*                                        │      │  · normalization                 │
                                                         ├────> │  · GeoIP/lookup enrichment       │
 FortiGate x3 ─> FortiAnalyzer ─> syslog     :1514 ─────┤      │  · detections (alert_tag)        │
   traffic, UTM, VPN                                     │      │  · ATT&CK / off-hours / accounts │
                                                         │      │ INDEX OpenSearch  omni-*         │
 ESET PROTECT ────────────────> syslog JSON  :1515 ─────┤      │  (ISO rotation/retention)        │
   eset_* (AV/HIPS threats)                              │      └───────────────┬──────────────────┘
                                                         │                      │
 ESXi x4 · vCenter ────────────> syslog      :1516 ─────┤              EVENT DEFINITIONS
                                                         │                (88 definitions)
 Microsoft 365 ─> API collectors ─> GELF     :12201 ────┤                      │
   Graph + O365 Mgmt Activity                            │      ┌───────────────┼─────────────────┐
                                                         │    MAIL             TEAMS          AUTO RESPONSE
 Self-monitoring ───────────────> GELF       :12201 ────┘  (26 critical)    (firehose 87)     SOAR ─> feed
   backup · disk · SOAR · cert · health · UEBA/NDR         IT team          SOC channel      ─> FortiGate
                                                                                            (IP blocking)

 * NPS: mapped (lookup 6272/6273/6274) but not yet forwarded on the client side (Winlogbeat to be deployed).

 CONSOLE  https://bx-it-graylog-vm.omnitech.security  (AD / LDAPS auth, domain admins)
 BACKUP  daily encrypted config ─> \\10.33.50.5\Public\SIEM   |   dedicated /data 7.3 TB
```

## 1. Platform

| Item | Value |
|---|---|
| VM | `bx-it-graylog-vm` — **10.33.220.10** — VLAN 220 ("ELK Network"), BX site |
| OS | Debian (kernel 6.12), nftables host firewall |
| Disks | system 931 GB (/, /var, /home); **data 7.3 TB mounted on `/data`** (≈147 GB used at review) |
| Data | OpenSearch: `/data/opensearch` — Graylog journal: `/data/graylog-journal` |

## 2. Software components

| Component | Version | Role |
|---|---|---|
| Graylog Server | **7.1.3** | ingestion, pipelines, alerting, dashboards (HTTPS API :9000) |
| OpenSearch | **2.19.5** | storage/indexing (localhost:9200) |
| MongoDB | **8.0.24** | Graylog configuration (authenticated) |
| nginx | **1.26.3** | reverse proxy HTTPS console :443 + hosting of the `/kit` kit |
| Java/JVM | truststore `cacerts-omni.jks` (OMNITECH Root CA) — full internal TLS |

TLS specificity: `http_publish_uri` = FQDN resolved to 127.0.0.1 via
`/etc/hosts`; all API calls go through
`https://bx-it-graylog-vm.omnitech.security:9000/api` + internal CA.

## 3. Network flows

### Inbound (collection)
| Port | Proto | Source | Content |
|---|---|---|---|
| 5044 | TCP/TLS | all 10.33.0.0/16 (Winlogbeat agents) + **BunkerWeb (Filebeat)** | Windows logs + Veeam + **WAF** |
| 1514 | TCP **and** UDP | FortiAnalyzer (10.33.80.253) | logs of the 3 FortiGate clusters |
| 1515 | TCP | **ESET PROTECT** (10.33.50.20) | syslog JSON AV/HIPS threats (514 redirected by the firewall) |
| 1516 | TCP **and** UDP | ESXi ×4 + vCenter | vSphere syslog |
| 12201 | HTTP (localhost) | M365 collectors + internal scripts | GELF |
| 443 | HTTPS | LAN | web console |

> The same Beats input :5044 receives Winlogbeat **and** Filebeat (BunkerWeb).
> Routing of BunkerWeb messages to their stream is done on the field
> `filebeat_event_source = bunkerweb` (set by Filebeat), with symmetric
> exclusion on the "OMNI - Windows autres" stream.

### Outbound
| Destination | Port | Usage |
|---|---|---|
| Microsoft (Graph, O365 Mgmt API) | 443 | M365 collectors (timers) |
| DB-IP / abuse feeds | 443 | GeoIP / threat intel updates |
| 10.33.50.5 (Files) | 445 | daily backup deposit (`svc_siem` account) |
| smtp-internal.omnitech-security.fr | 25 | email notifications |
| Power Automate (M365) | 443 | Teams notifications |

Dedicated FortiGate rules: log flows (1339 fixed, 1340, 1424…), console
access (1335), SMB backup (Graylog_Backup rule created on 12/06),
514→1515 redirection for ESET.

## 4. Processing chain

**7 inputs** → **13 streams** (Windows Security / Sysmon / Windows autres /
FortiGate / vSphere / M365 / **ESET** / **BunkerWeb** / Interne SIEM, plus the
system Default Stream) → **20 pipelines, 144 rules**:

- **normalization/detection** pipelines per source: Windows Security, Sysmon,
  Windows autres, FortiGate, M365, M365 Activité, vSphere, **Sources externes**
  (ESET + BunkerWeb);
- **cross-cutting enrichment** pipelines: ATT&CK enrichment,
  off-hours enrichment, account enrichment, M365 enrichment,
  Network exposure;
- **additional detection** pipelines: Détections complémentaires,
  Détections Lot3, Détections Lot4;
- **volume-reduction** pipeline: Réduction volume (ISO) — drops applicative
  vCenter and **ESXi/vSAN storage noise (−87% vSphere)**, Veeam/snapshot
  exclusions, dwm/winlogon, Azure AD Sync…

Output → `omni-*` index (daily rotation, retentions POL §5).

> **Pipeline pitfall to know**: a `match either` stage containing only one
> conditional rule (drop/tag) blocks any message that does not match it. Always
> pair it with a rule that always matches (normalization).

> **Graylog 7.x API pitfalls**: no ternary in a pipeline, `contains()` takes
> 2 arguments, definition POSTs expect the `{entity}` envelope, and the
> deflector cycle is done via `POST /system/deflector/{id}/cycle`.

## 5. Indexes and retention (applied by `41-retention-iso.sh`)

**Daily** rotation (TimeBasedRotationStrategy P1D), retention by number
of indexes kept (= number of days).

| Index set | Content | Retention | Nominal volume |
|---|---|---|---|
| omni-winsec | Windows Security | **365 d** | ~5.5 GB/d |
| omni-winother | System/PowerShell/Defender/RDP/**Veeam**/**NPS** | **365 d** | ~2.7 GB/d |
| omni-m365 | Microsoft 365 | **365 d** | <0.1 GB/d |
| omni-sysmon | Sysmon | **365 d** | ~1.8 GB/d |
| omni-vsphere | vSphere (ESXi/vSAN noise filtered, −87%) | **365 d** | ~0.3 GB/d |
| omni-eset | **ESET PROTECT** (AV/HIPS threats) | **365 d** | <0.1 GB/d |
| omni-fortigate | FortiGate (traffic+UTM+VPN) | **180 d** | ~11 GB/d |
| omni-bunkerweb | **BunkerWeb WAF** (http_*/waf_*) | **90 d** | web volume |

> Retention choice: 365 d (forensics / compliance) on the identity and
> endpoint sources; 180 d on FortiGate (highest volume); 90 d on the WAF
> (web volume, short forensic value). A disk safeguard (§8) protects `/data`.

## 6. Detections (88 active definitions)

**2-tier** routing (script `22-alert-routing.sh`): **Teams = firehose** (87
definitions, SOC channel); **MAIL = 26 critical "wake-me-up" alerts**
(confirmed compromise + SIEM health). Legend below: **MT** = mail+Teams ·
**T** = Teams only.

### Alerts routed to MAIL (26 critical)
- Critical incident (correlated kill-chain)
- Ransomware indicator (shadow copy deletion)
- Brute force FOLLOWED by a success (same account)
- Successful lateral movement (1 account → N hosts)
- Suspicious DCSync
- CANARY ACCOUNT touched (probable AD intrusion)
- Impossible travel (multi-located account)
- M365 mail forwarding to external domain
- ESET: antivirus detection / threat
- Veeam: failed job or warning
- Winlogbeat silence (0 Windows logs / 15 min)
- Analysis robot down (self-monitoring)
- SIEM disk >80% (/data)
- EMERGENCY retention PURGE (disk almost full)
- SIEM config backup failed
- SIEM config backup missing (>26 h)
- SIEM certificate expiring soon (<45 d)
- Estate certificate expiring soon
- Weekly report failed

### Main detections (representative excerpt)

| Detection | Level |
|---|---|
| Brute force (≥10 failures/account/10 min, key by account; excludes machine accounts `*$` + service accounts ninjaone/ADSyncMSA) | T |
| Brute force FOLLOWED by a success (same account) | MT |
| Password spraying (≥8 accounts/IP, key by IP) | T |
| VPN portal brute force (≥30 failures/IP/h) | T |
| VPN mounted from abroad | T |
| Locked account (4740) | T |
| Attempt on a disabled account | T |
| Account created in the domain (4720) | T |
| Modification of a privileged group | T |
| Suspicious DCSync | MT |
| Suspicious Kerberoasting (≥5 SPN/account) | T |
| Successful lateral movement (1 account → N hosts) | MT |
| AD failures + foreign M365 login (correlation) | T |
| Audit tampering (1102/4719/4794/104) | T |
| Winlogbeat silence (0 Windows logs/15 min) | MT |
| Service/batch logon failure (broken service account) | T |
| Admin share sweep (≥3 hosts/account) | T |
| LSASS memory access | T |
| Process injection (Sysmon 8/25) | T |
| Suspicious PowerShell (encoded/download/mimikatz; excludes wakeup-ssrs.ps1) | T |
| Ransomware indicator (shadow copies) | MT |
| New service installed (7045) | T |
| Scheduled task created (4698) | T |
| Defender: detection or disabling | T |
| FortiGate: virus / IPS | T |
| Malicious IP (Tor/Spamhaus) | T |
| M365 brute force / at-risk account / login outside France | T |
| M365 privileged role / mailbox delegation / external forwarding / external sharing | MT (forwarding) / T |
| Impossible travel (multi-located account) | MT |
| vSphere: brute force (excludes vpxuser/dcui/localhost) / ESXi SSH-shell / VM deletion | T |
| **ESET: antivirus detection / threat** (Threat_Event / HipsAggregated_Event) | MT |
| **BunkerWeb / WAF**: blocked requests, scans, web attacks | T |
| Veeam: failed job or warning | MT |
| SIEM config backup failed / missing >26 h | MT |
| SIEM disk >80% / EMERGENCY retention PURGE | MT |
| SIEM / estate certificate expiring soon | MT |
| Weekly report failed | MT |
| Critical incident (correlated kill-chain, built-in deduplication) | MT |
| **CANARY ACCOUNT touched** (AD intrusion) | MT |
| **SOAR: IP automatically blocked** | T |
| UEBA / NDR: volume spikes, new country, beaconing, DNS exfiltration, sweep | T |

> The complete list of the 88 definitions and their exact routing is generated/controlled
> via `13-graylog-alerts.sh`, `21-alert-hygiene.sh`, the additional detection
> scripts (47/48/50/51) and `22-alert-routing.sh`. See also
> `docs/REGISTRE-DETECTIONS.md`.

## 7. "OMNI - SOC" dashboard (24 pages)

Single dashboard `requires={}` → 100% OSS (no Enterprise required).

| Page | What it is for |
|---|---|
| **Direction** | Overview: volumes, current detections, overall status |
| **Alertes** | History of triggered alerts (by priority) |
| **Incidents** | Correlated incidents (kill-chain) emitted by the incident robot |
| **ATT&CK** | MITRE ATT&CK coverage (observed tactics/techniques) |
| **UEBA / NDR** | Abnormal behavior: user scoring, new country, beaconing, exfil |
| **Santé collecte** | Which hosts/sources are reporting — spot a blind spot (includes ESET/BunkerWeb) |
| **Identité AD** | Authentications, failures, lockouts, logon types |
| **Comptes à privilèges** | Activity of `adm-*` accounts, special privileges |
| **Comptes & conformité** | Account lifecycle, privileged groups, PKI, NPS |
| **M365** | Cloud logins, countries, applications, at-risk accounts |
| **M365 Activité** | Exchange / SharePoint / OneDrive: shares, mailbox access |
| **Endpoint** | Sysmon: processes, network, DNS, endpoint detections |
| **Hunting** | Proactive search: LSASS, Office→shell, persistence, pipes |
| **Réseau** | FortiGate: traffic, UTM (virus/IPS), malicious IPs |
| **VPN & Exposition** | Portal attacks, targeted IPs/accounts, legitimate tunnels |
| **Sources externes** | ESET (AV/HIPS threats) and associated endpoint correlations |
| **WAF BunkerWeb** | Web traffic, blocked requests, scans, application attacks |
| **Cartographie** | M365/VPN connections worldwide (GeoIP) |
| **vSphere** | ESXi/vCenter: access, SSH, VM lifecycle |
| **Sauvegardes** | Veeam jobs, snapshots, SIEM config backup, disk safeguard |
| **Certificats** | SIEM + estate certificate expiration (permanent telemetry) |
| **Vulnérabilités** | Inventory of reported vulnerabilities (daily client scan) |
| **Investigation** | Cross-cutting multi-stream page to pivot during an investigation |

## 8. SIEM backup (detail)

- `30-backup-config.sh` + timer **03:15** (Persistent): mongodump (authenticated
  URI) + /etc (graylog, opensearch, nginx, systemd) +
  /usr/local/sbin + kit + IaC → tar.gz → **AES-256-CBC (PBKDF2 200k)** →
  local copy `/var/backups/siem` + deposit `\\10.33.50.5\Public\SIEM`
  (`svc_siem` account, cred 600) — 14-day retention on both sides.
- GELF status → "OMNI - Interne SIEM" stream → failure/absence alerts (mail).
- `32-disk-guard.sh` + 6 h timer: 80% alert, emergency purge 88%→82%.
- Restore: `RESTORE.md` / `PRA-RECONSTRUCTION-SIEM.md` (quarterly test — see PRO §2).

## 9. Infrastructure as Code (reference = these scripts, not the console)

| Script | Role |
|---|---|
| `00-vars.env` (600) | secrets and parameters |
| `lib-graylog.sh` | API helpers (TLS, entity envelope, ensure_*) |
| `06-firewall.sh` | nftables + redirections (514→1515 ESET) |
| `07-inputs.sh` | Graylog inputs (Beats, Syslog, GELF) |
| `10-graylog-model.sh` | index sets, streams, inputs |
| `11-graylog-enrichment.sh` | CSV lookups (GeoIP, threat intel, win-events…) |
| `12-graylog-pipelines.sh` | base rules + pipelines (normalization/detection) |
| `13-graylog-alerts.sh` | notifications (ASCII mail, Teams card, SOAR HTTP) + base definitions, source-aware templates |
| `14-graylog-dashboards.sh` | "OMNI - SOC" dashboard 24 pages (generated, `requires={}`) |
| `16/17/18-m365-*.sh` + `/usr/local/sbin/omni-m365-*` | GELF input + cloud collectors + timers |
| `19-vsphere.sh` | vSphere module |
| `21-alert-hygiene.sh` | **mandatory overlay after 13**: graces/keys, svc/Veeam/backup/disk/report alerts, "OMNI - Interne SIEM" stream |
| `22-alert-routing.sh` | **2-tier routing** (Teams firehose / mail 26 critical), mail grace ≥60 min |
| `30/32-*.sh` | config backup, disk safeguard |
| `41-retention-iso.sh` | ISO retentions per index set (replaces the old 31) |
| `33-ldaps-auth.sh` | AD authentication (LDAPS) on the console |
| `34-weekly-report.sh` + `/usr/local/sbin/omni-weekly-report` | weekly report (HTML mail + local copy) |
| `45-monthly-report.sh` + `/usr/local/sbin/omni-monthly-report` | monthly report |
| `35-canary.sh` + `windows/New-OmniCanary.ps1` | AD canary account (lookup + alert + creation script) |
| `36-soar.sh` + `/usr/local/sbin/omni-soar` | SOAR-light: automatic IP blocking (FortiGate feed, webhook 127.0.0.1:8088) |
| `37-mitre-attack.sh` | MITRE ATT&CK enrichment / coverage |
| `38-vuln-scan.sh` + `/usr/local/sbin/omni-vuln-scan` | estate vulnerability scan |
| `39-collect-health.sh` + `/usr/local/sbin/omni-collect-health` | collection health |
| `40-ueba-ndr.sh` + `/usr/local/sbin/omni-ueba-*` + `omni-ndr-*` | UEBA (scoring, geo, volume) and NDR (beacon, DNS, exfil, lateral, scan) |
| `42-carte-cyber.sh` + `/usr/local/sbin/omni-geo-flux` | mapping / geographic flows |
| `43-ndr-dns.sh`, `48-ndr-scan.sh` | additional NDR detections |
| `44-incidents.sh` + `/usr/local/sbin/omni-incident-correlate` | incident correlation (kill-chain, deduplication) |
| `46-self-health.sh` + `/usr/local/sbin/omni-self-health` | SIEM self-monitoring (robots down) |
| `47-detections-extra.sh`, `48-m365-fail-codes.sh`, `49-*`, `50-enrich-lot3.sh`, `51-enrich-lot4.sh` | additional detections and enrichments (Lot3/Lot4, network exposure, LDAP recon, M365 fail codes) |
| `52-new-sources.sh` | **ESET integration (1515) + BunkerWeb (Filebeat) + NPS mapping** |
| `/usr/local/sbin/omni-cert-check`, `omni-cert-renew` | certificate monitoring/renewal (permanent telemetry) |
| `40-purge-logs.sh` | manual history maintenance (CONFIRM=OUI) — replaced by 53/54 |
| `53-purge-clean.sh` | **data purge** (deflector cycle + index deletion), keeps ALL config; `gl-system-events` preserved |
| `54-post-purge-repopulate.sh` | post-purge repopulation (index ranges, M365 re-fetch, robot restart) |
| `55-vaultwarden.sh` | Vaultwarden source (stream + **dedicated index set `omni-vaultwarden`** + pipeline `omni-vw-*` + vault detections); kit `/kit/vw-filebeat.sh` |
| `56-fortidhcp.sh` | FortiGate DHCP attribution (`omni-fortidhcp-fetch`, 15 min timer, lookup `omni-dhcp-attribution` → `src_hostname`/`dest_hostname`) |
| `57-mitre-coverage.sh` | MITRE ATT&CK coverage map → `docs/mitre-navigator-layer.json` (Navigator layer) + summary |
| `58-identity-correlation.sh` | unified identity (`identity`/`identity_human`) + "Identité" dashboard page |
| `59-file-audit.sh` | sensitive file access audit (4663/5145 → `file_sensitive_access`/`file_delete_sensible`) |
| `60-integrity.sh` | log integrity (hashed-signed register `omni-integrity` + `--verify` + off-SIEM copy) + read-only Graylog role |
| `windows/`, `fortigate/`, `lookups/` | agent kit, FortiGate config, CSV |
| `docs/` | ISO dossier (POL, STD, PRO, DOS, REGISTRE, PRA, LDAPS, INTEGRATION-SOURCES…) |

Base (re)deployment order: `10 → 11 → 12 → 13 → 14` then **21** then
**22** then **41**. The source/detection/analytics modules (16-19, 35-52) are
replayed afterward (idempotent). Controlled purge: `53` then `54`.

## 10. Scheduled tasks

`systemctl list-timers 'omni-*'` (24 timers at review). Main ones:

- M365 collectors: `omni-m365-fetch`, `omni-m365-activity`;
- backup: `omni-backup-config` (03:15), safeguard `omni-disk-guard` (6 h);
- reports: `omni-weekly-report` (Monday 08:00), `omni-monthly-report` (1st of the month);
- certificates: `omni-cert-renew`, `omni-cert-check` (weekly);
- vulnerabilities: `omni-vuln-scan` (daily);
- health: `omni-collect-health`, `omni-self-health`;
- UEBA: `omni-ueba-geo`, `omni-ueba-geo-newcountry`, `omni-ueba-score`, `omni-ueba-volume`;
- NDR: `omni-ndr-dns`, `omni-ndr-scan`, `omni-ndr-beacon`, `omni-ndr-exfil`, `omni-ndr-lateral`;
- correlation / misc: `omni-incident-correlate`, `omni-ldap-recon`, `omni-geo-flux`, `omni-soar-expire` (hourly).

Permanent service: `omni-soar.service` (IP blocking webhook, 127.0.0.1:8088).
Estate side: daily NinjaOne policy `Install-OmniSiem-NinjaOne.ps1`.

## 11. Production release history

| Date | Step |
|---|---|
| 11/06 | Initial build: model, pipelines, alerts, dashboards, M365, end-to-end TLS, FAZ, vSphere; agent deployment (NinjaOne + GPO) |
| 11→12/06 night | Founding incident: brute-force storm (FSSO service on AD02) → anti-storm redesign (graces/keys), service account detection |
| 12/06 morning | VPN hardening (geo-FR — spraying stopped), full UTM on 3 clusters, FSSO restored, single enrollment script, Veeam integrated (+ discovery of the failed Vaultwarden job) |
| 12/06 midday | Resilience: externalized encrypted backup + ISO retentions + safeguards + this documentation dossier |
| 13/06 | Analytics extension: MITRE ATT&CK, UEBA/NDR, vulnerability scan, incident correlation, monthly reports, enrichment/detection batches (Lot3/Lot4), 2-tier alert routing |
| 14/06 | New sources: **ESET PROTECT** (1515), **BunkerWeb WAF** (Filebeat), **NPS** mapping; audit fixes (FortiGate `eventtime` timestamp, brute-force exclusions for machine/service accounts, PowerShell wakeup-ssrs, incident dedup, vSphere brute-force vpxuser/dcui/localhost, cert-check as permanent telemetry, dedicated ESET/BunkerWeb index sets); purge tooling 53/54; dashboard extended to 24 pages |

## 12. Known limitations and backlog

- LDAP group-sync (automatic roles per AD group) = Enterprise feature;
  in Open Source, console role assignment is manual (cf. LDAPS.md).
- M365 riskDetections: **ingested** (`m365_type:risk`, tag `m365_risque`) via the
  Graph permission `IdentityRiskEvent.Read.All` (Entra ID **P1**: risk events
  visible, level masked `hidden`; the detailed level + `riskyUsers`
  would require **P2**). `SecurityAlert.Read.All` granted but inoperative (tenant
  without a Microsoft Defender XDR backend → 403 "not provisioned").
- **NPS**: mapped on the SIEM side (lookup `win-events.csv` 6272/6273/6274) but not
  yet forwarded — deploy Winlogbeat on 10.33.50.247.
- Restore test to be performed (quarterly PRO / PRA).
- Security backlog: Wazuh integration, deep inspection (AD CS SubCA),
  remaining Windows servers in NinjaOne, host `DESKTOP-GASTH3T` to be identified.
