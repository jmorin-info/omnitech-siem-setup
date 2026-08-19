<div align="center">

<img src="docs/captures/01-overview.png" alt="OMNI SOC — overview console" width="94%">

# OMNI SIEM — Detection &amp; Response Platform

**A self-hosted, on-premise SIEM/SOC platform for OMNITECH Security**
Built on Graylog · OpenSearch · MongoDB, extended with a custom detection engine,
an AI-assisted alert-triage service, automated response (SOAR), a purpose-built SOC
console, and full physical-access-control (SEAL) correlation.

`~20 log sources` · `197 detections` · `250 pipeline rules` · `40 pipelines` · `22 streams` · `MITRE ATT&CK-mapped` · `ISO 27001-aligned`

</div>

---

## Table of contents

1. [What this is](#1-what-this-is)
2. [Key capabilities](#2-key-capabilities)
3. [Architecture](#3-architecture)
4. [Data sources](#4-data-sources)
5. [Detection engine](#5-detection-engine)
6. [Alert triage &amp; notifications](#6-alert-triage--notifications)
7. [Automated response (SOAR)](#7-automated-response-soar)
8. [The SOC console](#8-the-soc-console)
9. [Physical security correlation (SEAL)](#9-physical-security-correlation-seal)
10. [Deployment](#10-deployment)
11. [Operations &amp; resilience](#11-operations--resilience)
12. [Compliance (ISO/IEC 27001)](#12-compliance-isoiec-27001)
13. [Repository layout](#13-repository-layout)
14. [Documentation index](#14-documentation-index)

---

## 1. What this is

OMNI SIEM is a **production security-monitoring platform** that ingests logs from the
whole OMNITECH estate — Windows domain, FortiGate firewalls (multi-site), Microsoft 365 /
Entra ID, VMware vSphere, endpoint AV/EDR, a WAF, the physical access-control system, and
more — normalises them, runs **197 detections** mapped to MITRE ATT&CK, correlates them
into incidents, decides which alerts truly deserve a human's attention, and drives both a
real-time SOC console and automated response.

It is **not** a vanilla Graylog install. On top of the ingest/search core it adds:

- a **custom detection library** (Graylog event definitions + pipeline enrichment) covering
  initial access, credential theft, lateral movement, persistence, defence evasion,
  exfiltration, ransomware precursors, and physical intrusion;
- an **alert-triage micro-service** (`omni-alert-triage`) that scores every alert, correlates
  kill-chains across sources, suppresses noise, and — for the grey zone — asks an LLM judge
  whether the alert warrants an e-mail, then renders a clean, professional notification;
- a fleet of **~39 analytics robots** (UEBA geo-velocity, beaconing/C2, DNS tunnelling,
  volume exfiltration, lateral-movement, source-freshness watchdog, backup/health, …);
- **SOAR-light** automated IP blocking wired back into the FortiGate;
- a **purpose-built SOC console** (`/soc/`) and a **mobile PWA**;
- everything provisioned **idempotently** by ~104 versioned shell scripts, so the entire
  platform can be rebuilt from source.

---

## 2. Key capabilities

| Area | Capability |
|---|---|
| **Ingestion** | 15 Graylog inputs (Beats/TLS, Syslog TCP/UDP, GELF) across ~20 logical sources |
| **Normalisation** | 40 pipelines / 250 rules — every source normalised to a common schema (`event_source`, `event_action`, `alert_tag`, `src_ip`, `user`, `host`, MITRE fields…) |
| **Detection** | 197 event definitions (192 enabled), each mapped to a MITRE ATT&CK technique/tactic |
| **Correlation** | Cross-source kill-chain correlation on canonical identity/host/IP keys → incidents |
| **Triage** | Tiered decisioning (Critical / grey zone / noise) + LLM judge for the grey zone + learned false-positive suppression |
| **Notifications** | One clean, sober HTML e-mail per real alert, with facts, ATT&CK badge, an action playbook, and one-click console / block / false-positive links |
| **Response** | SOAR-light auto-block of attacking public IPs (FortiGate address-group feed), reversible, whitelisted |
| **UEBA / NDR** | Geo-velocity ("impossible travel" / new-country), beaconing/C2, DNS anomalies, volume exfiltration, lateral movement, per-entity risk scoring |
| **Physical** | SEAL access-control events correlated with the cyber timeline (badge, door, intrusion, dead-man switches) |
| **Visualisation** | Native Graylog dashboards + a bespoke real-time SOC console + mobile PWA |
| **Resilience** | Nightly application backups, ISO retention tiers, source-freshness watchdog, self-health checks, drift detection |
| **Compliance** | ISO/IEC 27001 control mapping and evidence generation |

---

## 3. Architecture

```
                         ┌──────────────────────────────────────────────────────┐
   Log sources           │                    bx-it-graylog-vm                    │
 ─────────────           │                                                        │
  Winlogbeat  ──TLS 5044─▶│  Graylog inputs ─▶ pipelines (40) ─▶ streams (22)      │
  FortiGate   ──Syslog───▶│      │              normalise/enrich       │           │
  (via FAZ)               │      │              tag MITRE / alert_tag  │           │
  M365/Entra  ──GELF─────▶│      ▼                                     ▼           │
  vSphere     ──Syslog───▶│  OpenSearch (indices on /data, 7.3 TB) ◀── event       │
  ESET / EMS  ──Syslog───▶│      ▲                                   definitions   │
  Aruba/Linux ──Syslog───▶│      │                                    (197)        │
  Vaultwarden ──GELF─────▶│      │                                     │           │
  SEAL (phys) ──GELF─────▶│      │                                     ▼           │
  …                       │  analytics robots (39) ──GELF re-inject──▶ alerts       │
                          │  (UEBA, NDR, watchdog, health)             │           │
                          │                                            ▼           │
                          │                                   ┌─────────────────┐  │
                          │                          Teams ◀──│ notifications   │  │
                          │                          SOAR ◀──│ (Teams / SOAR / │  │
                          │                                   │  Triage webhook)│  │
                          │                                   └────────┬────────┘  │
                          │                                            ▼           │
                          │                             omni-alert-triage (:8089)  │
                          │                             score · correlate · LLM    │
                          │                             judge · dedup · render     │
                          │                                            │           │
                          │   /soc/ console  ·  mobile PWA  ·  e-mail ◀─┘           │
                          └──────────────────────────────────────────────────────┘
```

**Core stack**

- **Graylog** — ingestion, pipelines, streams, event definitions, dashboards, notifications.
- **OpenSearch** — the search/analytics backend; indices live on a dedicated encrypted
  volume (`/data`, LUKS). Snapshots for DR.
- **MongoDB** — Graylog configuration store (backed up nightly).
- **NGINX + TLS** — reverse proxy fronting the Graylog UI and the SOC console.
- **systemd** — every robot and service runs as a hardened unit with timers.

**Custom services (Python, stdlib-only, systemd units)**

| Service | Port | Role |
|---|---|---|
| `omni-alert-triage` | 8089 | Alert scoring, correlation, LLM grey-zone judge, e-mail rendering |
| `omni-soar` | 8088 | Auto-block webhook → FortiGate address group |
| `omni-mobile-api` | — | Backend for the mobile PWA and the `/soc/` console |
| `omni-source-watchdog` | — (timer) | Per-source freshness monitoring (silent-source detection) |
| ~35 analytics robots | — (timers) | UEBA / NDR / health / enrichment |

---

## 4. Data sources

Roughly twenty logical sources feed the platform. Each is normalised to a common schema and
watched for silence by the source-freshness watchdog.

| Source | Transport | `event_source` | What it brings |
|---|---|---|---|
| Windows Security | Winlogbeat / Beats TLS | `windows_security` | Auth, privilege, account & GPO changes, Kerberos |
| Sysmon | Winlogbeat | `sysmon` | Process/network/registry telemetry (EDR-grade) |
| Windows (other) | Winlogbeat | `windows` | Services, tasks, PowerShell, DNS-server audit |
| FortiGate (multi-site) | Syslog via FortiAnalyzer | `fortigate` | Traffic, UTM, IPS, virus, VPN, DoS |
| FortiManager | Syslog | `fortimanager` | Admin logins, config changes |
| FortiGate DHCP | API feeder | `forti_dhcp` | Lease/identity mapping |
| FortiClient EMS | Syslog TLS | `fortiems` | Endpoint AV, vulnerabilities, protection state |
| Microsoft 365 / Entra ID | GELF (fetcher) | `m365` | Sign-ins, MFA/device registration, mail forwarding, role changes, Identity Protection |
| VMware vSphere | Syslog | `vsphere` | Host/VM lifecycle, auth, snapshots |
| ESET | Syslog | `eset` | Endpoint AV detections |
| Aruba | Syslog TCP/UDP | `aruba` | Switch/AP auth, port-security, STP |
| Linux | Syslog | `linux` | Host auth and system logs |
| BunkerWeb (WAF) | — | `bunkerweb` | Application firewall blocks and scans |
| Vaultwarden | Filebeat/GELF | `vaultwarden` | Password-vault access and brute force |
| NinjaOne (inventory) | — | `inventory` | Asset inventory |
| Veeam | Winlogbeat ("Veeam Backup" channel) | `veeam` | Backup job success / warning / failure |
| ADCS | — | `adcs` | Certificate-services abuse (ESC1–ESC8) |
| Certificate parc | GELF UDP | `cert_parc` | Certificate-orchestrator inventory & expiry |
| Windows DNS | Winlogbeat (DNSServer/Audit) | `dns` | DNS record changes, cache flush, sensitive zones |
| **SEAL** (physical) | GELF TCP | `seal` | Badge access, doors, alarms, intrusion, dead-man switches |

> Internal, derived sources (`alert_triage`, `alert_correlation`, `ueba_geo`, `ndr_*`,
> `siem_*`) are re-injected by the robots and the triage service so that every decision is
> itself searchable and dashboarded.

---

## 5. Detection engine

**197 event definitions** (192 enabled), each tagged with a MITRE ATT&CK technique and
tactic. Detections are grouped by kill-chain phase:

- **Initial access** — malicious-IP VPN logins, M365 legacy-auth (MFA bypass), foreign M365
  sign-ins, anomalous geographic logins (new country / impossible travel).
- **Execution** — Office → interpreter, WMI process-create, InstallUtil / certutil LOLBins,
  service-launched shells, malware on endpoint (ESET / FortiClient).
- **Credential access** — LSASS memory access, NTDS.dit extraction, DCSync, Kerberoasting,
  AS-REP roasting, SAM/SYSTEM hive theft, GPP/SYSVOL credentials, Vaultwarden brute force.
- **Persistence / privilege** — AdminSDHolder, RBCD, Shadow Credentials, autorun/Run keys,
  scheduled tasks, IFEO hijack, privileged-group changes, Zerologon.
- **Defence evasion** — Defender tampering, AMSI bypass, event-log clearing, USN-journal
  deletion, audit sabotage, **silent-source detection** (a blinded collector is itself an alert).
- **Discovery / lateral movement** — AD recon (LDAP/nltest), internal scan, admin-share
  sweeps, WinRM lateral movement, RunAs credential use.
- **Collection / exfiltration** — sensitive-file mass access, volume-based exfiltration
  (with legitimate-egress allow-listing, e.g. offsite backup targets).
- **Impact** — ransomware precursors (shadow-copy deletion, backup destruction, mass file
  deletion), extortion-site mentions, dark-web leaks.
- **Health / assurance** — backup failure/absence, disk pressure, certificate expiry,
  robot self-supervision, repo/production drift, log-integrity chain.

Normalisation and enrichment run in **40 pipelines / 250 rules**: GeoIP, threat-intel
(Tor/Spamhaus/URLhaus/abuse.ch), MITRE lookup by `alert_tag`, per-source field mapping, and
noise/false-positive allow-lists learned over time.

<div align="center"><img src="docs/captures/04-detections.png" alt="Detections view" width="90%"></div>

*ATT&CK coverage and the live detection catalogue are documented in
[`docs/COUVERTURE-MITRE-ATTACK.md`](docs/COUVERTURE-MITRE-ATTACK.md) and
[`docs/REGISTRE-DETECTIONS.md`](docs/REGISTRE-DETECTIONS.md).*

<div align="center"><img src="docs/captures/06-attack.png" alt="ATT&CK matrix" width="90%"></div>

---

## 6. Alert triage &amp; notifications

Raw detections are firehosed to Teams and the console, but **only qualified, actionable
alerts reach the security mailbox**. That decision is made by the `omni-alert-triage`
micro-service, to which every mailing detection is wired (a single HTTP notification).

**How a decision is made**

1. **Classify** the alert into a tier — *Critical*, *grey zone*, or *noise* — from the title.
2. **Score** it on multiple signals: priority, critical-asset match, threat-intel, off-hours,
   and **kill-chain velocity** (how many *distinct* detection types hit the same entity in
   the window, across sources — a lateral-moving attacker lights up several).
3. **Correlate** across sources on canonical keys (identity / host / IP / badge), so that a
   SEAL console login and a Windows brute-force on the same account join up.
4. **Grey zone → LLM judge.** For ambiguous alerts, a Claude (Haiku) judge is asked, over a
   **redacted** context, whether the alert deserves an immediate e-mail. Critical alerts are
   never suppressed; noise is dropped unless it escalates by score.
5. **De-duplicate** and honour **learned false-positive rules** (analysts flag FPs from the
   console; rules are scoped, time-boxed, and never silence a Critical).

**The notification.** Each e-mail is a single, sober, professional HTML message: a colour
accent by severity, a calm facts table (who / where / how many), the ATT&CK technique as a
clickable badge, a four-part **action playbook** (what it is / what to check / remediation /
durable fix), the triggering raw events, correlated alerts on the same entity, and one-click
buttons (open in console, view logs, block IP, mark false-positive). Physical-security
alerts additionally carry site / zone / door / badge.

---

## 7. Automated response (SOAR)

`omni-soar` exposes a webhook that the platform calls when an attacking **public** IP is
confirmed (brute force, scanning, WAF attacker). It pushes the IP into a FortiGate address
group consumed by a block policy. The action is:

- **guarded** — public IPs only, with a whitelist (never blocks internal or partner ranges);
- **reversible** — entries carry a TTL (24 h) and can be cleared;
- **auditable** — every block is re-injected as an event and shown on the console.

A **manual block** path lets an analyst block an IP straight from an alert e-mail via an
HMAC-signed, time-boxed link.

---

## 8. Visualisation — Graylog dashboards &amp; SOC console

### Native Graylog dashboards

The platform ships purpose-built Graylog dashboards over the normalised data — a security
overview, an analytics view (collection coverage, robot health, UEBA/ML, geo-anomalies), a
triage &amp; multi-site view, a sources view, and five SEAL physical-security dashboards. These
are live captures of the Graylog web UI.

<div align="center"><img src="docs/captures/graylog/graylog-01-soc.png" alt="Graylog — OMNI SOC dashboard" width="90%"></div>

*`OMNI - SOC` — the security overview dashboard.*

<div align="center"><img src="docs/captures/graylog/graylog-02-analytics.png" alt="Graylog — OMNI Analytics dashboard" width="90%"></div>

*`OMNI - Analytics` — collection coverage, analytics-robot telemetry, ML/UEBA anomalies, impossible-travel.*

| | |
|---|---|
| ![Triage & multi-site](docs/captures/graylog/graylog-03-triage-multisite.png) | ![Sources](docs/captures/graylog/graylog-04-sources.png) |
| `OMNI - Triage & Multi-site` — mail-vs-drop, per-site FortiGate | `Sources` — ingest volume by source |
| ![SEAL SOC](docs/captures/graylog/graylog-05-seal-soc.png) | ![SEAL multi-site](docs/captures/graylog/graylog-06-seal-multisite.png) |
| `SEAL - SOC opérationnel` — physical access, live | `SEAL - Vue multi-site` — access across sites |
| ![Inputs](docs/captures/graylog/graylog-07-inputs.png) | ![Pipelines](docs/captures/graylog/graylog-08-pipelines.png) |
| Ingest inputs (Beats / Syslog / GELF) | Processing pipelines |

### The SOC console

A bespoke, real-time console (`/soc/`) sits on top of the OpenSearch backend. It is the
day-to-day analyst surface: posture at a glance, incidents, the detection catalogue, entity
360° dossiers, the ATT&CK matrix, an attack graph, dark-web leaks, collection health, and
playbooks. A companion **mobile PWA** brings the essentials and push notifications to a phone.

| | |
|---|---|
| ![Incidents](docs/captures/03-incidents.png) | ![Entities](docs/captures/02-entites.png) |
| **Incidents** — correlated kill-chains, ranked | **Entities** — accounts / hosts / IPs at risk |
| ![Playbooks](docs/captures/05-playbooks.png) | ![Attack graph](docs/captures/07-graphe.png) |
| **Playbooks** — response guidance per detection | **Attack graph** — lateral-movement paths |
| ![Health](docs/captures/08-sante.png) | ![Leaks](docs/captures/09-fuites.png) |
| **Health &amp; collection** — source freshness, cluster | **Leaks &amp; dark web** — exposed credentials / ransomware mentions |
| ![Entity dossier](docs/captures/10-dossier360.png) | ![Timeline](docs/captures/10b-timeline.png) |
| **360° dossier** — everything known about an entity | **Timeline** — unified cyber + physical timeline |
| ![English UI](docs/captures/11-overview-en.png) | ![Mobile PWA](docs/captures/12-pwa-mobile.png) |
| **Bilingual UI** (FR / EN) | **Mobile PWA** — SOC in your pocket |

> Console details: [`docs/CONSOLE-SOC.md`](docs/CONSOLE-SOC.md).

---

## 9. Physical security correlation (SEAL)

The SEAL access-control system is a first-class log source. Badge reads, door states,
alarms, and operator actions are normalised (`event_source:seal`) and correlated on the same
timeline as cyber events, so a physical intrusion and a suspicious login on the same site or
account can be seen together. Dead-man switches watch each site's audit / access / alarm
streams and alert if a flow goes silent. A dedicated Teams channel carries physical alerts.

*See [`docs/captures/10b-timeline.png`](docs/captures/10b-timeline.png) for the unified
timeline, and the SEAL integration notes under `docs/`.*

---

## 10. Deployment

The whole platform is provisioned by **~104 idempotent shell scripts** (`00-preflight.sh` …
`99-cert-orchestrator.sh`), each responsible for one concern and safe to re-run. A Docker
variant exists for DR / staging.

**High-level order**

```
00–09   preflight · base · MongoDB · OpenSearch · Graylog · NGINX/TLS · firewall · inputs · backup
10–14   data model · enrichment · pipelines · detections · dashboards
15–22   reports · M365 · vSphere · alert hygiene · routing
27–49   hardening · VPN/TI · drift · retention · disk guard · LDAPS · canary · SOAR · MITRE · triage · UEBA/NDR
50–79   enrichment lots · new sources · Vaultwarden · FortiDHCP · identity correlation · file audit ·
        integrity · robot supervision · auto-updates · FortiManager · mobile PWA · threat-intel ·
        leaks (GitHub / dark web) · SOC console · detection tuning · ML scoring · internal index set
80–99   analytics dashboards · retention consolidation · detections backlog · services versioning ·
        deception/honeytokens · attack graph · FortiClient EMS · DNS · Linux · Aruba · Entra ·
        correlation · multi-site SOAR · index templates · cert orchestrator
```

Prerequisites, variables, and secrets are described in `docs/` and `SECRETS.example.md`
(no secret is committed). See [`docs/PRA-RECONSTRUCTION-SIEM.md`](docs/PRA-RECONSTRUCTION-SIEM.md)
for a full rebuild procedure and [`docs/PROCEDURE-EXPLOITATION-SIEM.md`](docs/PROCEDURE-EXPLOITATION-SIEM.md)
for operations.

---

## 11. Operations &amp; resilience

- **Backups** — nightly application backup (MongoDB dump + OpenSearch snapshot + configs),
  restore procedure validated ([`RESTORE.md`](RESTORE.md)).
- **Retention** — ISO-aligned per-source retention tiers (e.g. FortiGate/Sysmon 90 d,
  Windows Security / vSphere / ESET 180 d, M365 365 d) — see
  [`docs/POLITIQUE-RETENTION.md`](docs/POLITIQUE-RETENTION.md).
- **Source watchdog** — every monitored source has a silence threshold; a blinded collector
  raises a `source_silent` alert (this is how a stalled DNS-audit or Veeam feed is caught).
- **Self-health &amp; drift** — periodic self-checks and repo-vs-production drift detection.
- **Encryption** — the data volume is LUKS-encrypted; TLS everywhere; SSH locked down.
- **Alerting hygiene** — one clean mail per real alert; the triage service is the single mail
  path (no legacy double-notifications).

---

## 12. Compliance (ISO/IEC 27001)

Detections, retention, logging policy, incident procedure, and evidence generation are mapped
to ISO/IEC 27001 controls (notably A.8.15 logging, A.8.16 monitoring, A.5.x incident
management). See [`docs/ISO27001-MAPPING.md`](docs/ISO27001-MAPPING.md),
[`docs/REGISTRE-CONFORMITE-ISO27001.md`](docs/REGISTRE-CONFORMITE-ISO27001.md), and the
`docs/EVIDENCE-AUDIT-*.md` evidence packs.

---

## 13. Repository layout

```
.
├── 00-preflight.sh … 99-cert-orchestrator.sh   # ~104 idempotent provisioning scripts
├── lib-graylog.sh                              # shared Graylog API helpers (paginated, idempotent)
├── triage/omni-alert-triage                    # alert-triage micro-service (+ .env template)
├── oms-xdr / oms-ml / oms-graph                # correlation, ML scoring, attack graph add-ons
├── seal/                                        # SEAL physical-access integration & detections
├── mobile/  (soc/, pwa)                         # SOC console + mobile PWA frontends
├── lookups/                                     # 20 lookup tables (guidance, MITRE, allow-lists…)
├── kit/  windows/  fortigate/                   # collector kits & source configs
├── docker/                                      # Docker variant (DR / staging)
├── tests/  run-tests.sh                         # test harness
└── docs/                                        # full documentation set (see below)
```

---

## 14. Documentation index

The complete documentation set lives under [`docs/`](docs/) — start at
[`docs/00-INDEX.md`](docs/00-INDEX.md).

**Core documentation (English):**

| Document | Covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, data flow, storage, services, network |
| [`docs/DATA-SOURCES.md`](docs/DATA-SOURCES.md) | Every source, transport, normalised schema, freshness monitoring |
| [`docs/DETECTIONS.md`](docs/DETECTIONS.md) | Detection engine, MITRE coverage, enrichment, UEBA/NDR, correlation |
| [`docs/ALERTING-AND-TRIAGE.md`](docs/ALERTING-AND-TRIAGE.md) | Triage service, scoring, LLM judge, notification design, SOAR |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Health, watchdog, backup/DR, retention, runbook |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Prerequisites, provisioning order, rebuild procedure |

**Reference documentation (original, French — authoritative for audit):**

| Topic | Document |
|---|---|
| Architecture dossier | [`docs/DOSSIER-ARCHITECTURE-SIEM.md`](docs/DOSSIER-ARCHITECTURE-SIEM.md) |
| Source integration &amp; inventory | [`docs/INTEGRATION-SOURCES.md`](docs/INTEGRATION-SOURCES.md) · [`docs/INVENTAIRE-SOURCES.md`](docs/INVENTAIRE-SOURCES.md) |
| Detection registry | [`docs/REGISTRE-DETECTIONS.md`](docs/REGISTRE-DETECTIONS.md) |
| MITRE ATT&CK coverage | [`docs/COUVERTURE-MITRE-ATTACK.md`](docs/COUVERTURE-MITRE-ATTACK.md) |
| SOC console | [`docs/CONSOLE-SOC.md`](docs/CONSOLE-SOC.md) |
| Automated response &amp; playbooks | [`docs/REPONSE-AUTOMATISEE.md`](docs/REPONSE-AUTOMATISEE.md) · [`docs/SOAR-PLAYBOOKS.md`](docs/SOAR-PLAYBOOKS.md) |
| Operations runbook | [`docs/PROCEDURE-EXPLOITATION-SIEM.md`](docs/PROCEDURE-EXPLOITATION-SIEM.md) |
| Incident procedure | [`docs/PROCEDURE-INCIDENT.md`](docs/PROCEDURE-INCIDENT.md) |
| Disaster recovery / rebuild | [`docs/PRA-RECONSTRUCTION-SIEM.md`](docs/PRA-RECONSTRUCTION-SIEM.md) |
| Retention policy | [`docs/POLITIQUE-RETENTION.md`](docs/POLITIQUE-RETENTION.md) |
| Troubleshooting | [`docs/GUIDE-DEPANNAGE.md`](docs/GUIDE-DEPANNAGE.md) |
| Glossary | [`docs/GLOSSAIRE.md`](docs/GLOSSAIRE.md) |
| ISO 27001 mapping &amp; evidence | [`docs/ISO27001-MAPPING.md`](docs/ISO27001-MAPPING.md) · `docs/EVIDENCE-AUDIT-*.md` |
| Executive summary | [`docs/SYNTHESE-EXECUTIVE.md`](docs/SYNTHESE-EXECUTIVE.md) |

> Source-specific integration notes (kept from the original French documentation):
> [`VEEAM.md`](VEEAM.md), [`M365.md`](M365.md),
> [`VSPHERE.md`](VSPHERE.md), [`FORTIANALYZER.md`](FORTIANALYZER.md),
> [`GUIDE.md`](GUIDE.md), [`CONTEXT.md`](CONTEXT.md).

---

<div align="center">
<sub>OMNI SIEM · OMNITECH Security · self-hosted detection &amp; response · Graylog + OpenSearch + custom detection/triage/response tier</sub>
</div>
