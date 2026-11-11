<div align="center">

<img src="docs/captures/01-overview.png" alt="OMNI SOC — overview console" width="94%">

# OMNI SIEM — Detection &amp; Response Platform

**A self-hosted, on-premise SIEM/SOC platform for OMNITECH Security**
Built on Graylog · OpenSearch · MongoDB, extended with a custom detection engine,
a scoring-based alert-triage service, automated response (SOAR), a purpose-built SOC
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

Everything runs on a single hardened Debian 13 server (a physical box; the
`bx-it-graylog-vm` hostname is a leftover from an earlier virtualised version).

```mermaid
flowchart LR
  subgraph Sources
    WIN[Windows / Sysmon<br/>Winlogbeat TLS]
    FGT[FortiGate x3<br/>via FortiAnalyzer]
    M365[Microsoft 365 / Entra ID]
    OTH[vSphere · ESET · EMS · Aruba<br/>Linux · WAF · Vaultwarden]
    SEAL[SEAL access control<br/>SQL via Logstash]
  end
  subgraph SIEM[SIEM server]
    IN[Graylog inputs] --> PIPE[Pipelines<br/>normalise · enrich · tag]
    PIPE --> OS[(OpenSearch<br/>encrypted /data)]
    PIPE --> DEF[Event definitions<br/>MITRE-mapped]
    ROB[Analytics robots<br/>UEBA · NDR · health] -->|GELF| IN
    DEF --> TRI[omni-alert-triage<br/>score · correlate · dedup]
    DEF --> SOAR[omni-soar<br/>IP blocklist]
    MDB[(MongoDB<br/>configuration)]
  end
  WIN --> IN
  FGT --> IN
  M365 --> IN
  OTH --> IN
  SEAL --> IN
  TRI --> MAIL[E-mail · Teams]
  TRI --> CON[SOC console · mobile PWA]
  SOAR -->|threat feed| FW[FortiGate WAN block]
```

The detailed view:

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
4. **Grey zone → LLM judge.** For ambiguous alerts, a small hosted LLM is asked, over a
   **redacted** context, whether the alert deserves an immediate e-mail. If the judge is
   unreachable it backs off for an hour and the alert is sent "as a precaution", clearly
   labelled as such. Critical alerts are
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
confirmed (brute force, scanning, WAF attacker). It publishes the IP in a threat feed that
the FortiGate of each site pulls every two minutes and drops at the WAN edge. The action is:

- **guarded** — public IPs only. An IP that has authenticated successfully in the last 90
  days (VPN, Microsoft 365) is never blocked, nor are site and partner ranges, and a single
  failure is never enough. This is what keeps an employee's home IP from being locked out
  after a typo;
- **reversible** — entries carry a TTL (24 h) and expire on their own;
- **auditable** — every block is re-injected as an event, shown on the console and
  summarised in a morning digest.

To lift a block by hand (effective within two minutes): `sudo omni-soar-debloquer <ip>`,
optionally with `--exclure "reason"` to make the exclusion permanent.

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

### Prerequisites

Checked by `./00-preflight.sh`, which prints a PASS / WARN / FAIL report:

- Debian 13, root access, reachable apt mirrors;
- a CPU with **AVX** (required by MongoDB 8);
- at least 30 GB of RAM (OpenSearch and Graylog heaps are sized in `00-vars.env`);
- a dedicated data disk for `/data`, encrypted with LUKS2 and unlocked by the TPM;
- a resolvable FQDN and free input ports (443, 5044, 1514–1520, 12201).

### Quick start

```bash
git clone https://github.com/jmorin-info/omnitech-siem-setup.git
cd omnitech-siem-setup && chmod +x *.sh

cp 00-vars.env.example 00-vars.env && chmod 600 00-vars.env
$EDITOR 00-vars.env              # replace every CHANGEME, check every "A VERIFIER" line

./00-preflight.sh --gen-vars     # host checks + suggested values
./01-base.sh && ./02-mongodb.sh && ./03-opensearch.sh && ./04-graylog.sh
./05-nginx-tls.sh && ./06-firewall.sh && ./07-inputs.sh && ./08-backup.sh
./10-graylog-model.sh && ./11-graylog-enrichment.sh && ./12-graylog-pipelines.sh
./13-graylog-alerts.sh && ./21-alert-hygiene.sh && ./14-graylog-dashboards.sh
```

Then run the functional groups (detections, UEBA/NDR, SOAR, triage, reports, extra
sources). A few numbers are shared by two scripts (38, 40, 48, 49, 84, 85, 97): always go by
the full script name and its header. The French README has the exact order.

### Configuration

All settings live in a single file, `00-vars.env`, which is never committed. Start from the
commented template `00-vars.env.example`. Keep comments on their own lines: some Python
collectors read this file and do not strip trailing comments. Every script sources
`00-vars.env` first, then `lib-graylog.sh`. In the other order the API URL is empty and calls
fail silently.

Service secrets (webhooks, API keys, service accounts) are listed in `SECRETS.example.md`;
the real `SECRETS.md` is git-ignored. See [`docs/PRA-RECONSTRUCTION-SIEM.md`](docs/PRA-RECONSTRUCTION-SIEM.md)
for a full rebuild procedure and [`docs/PROCEDURE-EXPLOITATION-SIEM.md`](docs/PROCEDURE-EXPLOITATION-SIEM.md)
for operations.

---

## 11. Operations &amp; resilience

- **Backups** — a nightly encrypted archive of the full configuration (MongoDB dump, configs,
  robots, systemd units, this repository), checked for restorability on every run and copied
  off the host. Indexed logs are covered by **selective, incremental OpenSearch snapshots**
  (`oms-snap-siem`, 01:30): rolling windows for the big indices, small ones in full, plus a
  weekly test restore. Restore with `include_aliases=false` so the Graylog write alias is
  never moved. Full procedure: [`RESTORE.md`](RESTORE.md).
- **Automatic updates** — Debian security fixes through `unattended-upgrades`. The SIEM stack
  is handled by `oms-maj-siem` every Sunday at 04:30:
  1. pre-checks (`/data` mounted, OpenSearch green, Graylog API up, free space);
  2. backup;
  3. upgrade;
  4. known fixes re-applied;
  5. reboot if the kernel asks for it, with a full post-boot check;
  6. an e-mail report.

  Upgrades stay inside pinned series (Graylog 7.1, OpenSearch 2.19, MongoDB 8.0,
  Logstash 8.19, see `/etc/apt/preferences.d/oms-siem-series`). Moving to a new major series
  is a deliberate, manual decision. Dry run: `oms-maj-siem --simuler`.
- **Retention** — ISO-aligned per-source retention tiers (e.g. FortiGate/Sysmon 90 d,
  Windows Security / vSphere / ESET 180 d, M365 365 d) — see
  [`docs/POLITIQUE-RETENTION.md`](docs/POLITIQUE-RETENTION.md).
- **Source watchdog** — every monitored source has a silence threshold; a blinded collector
  raises a `source_silent` alert (this is how a stalled DNS-audit or Veeam feed is caught).
- **Self-health &amp; drift** — periodic self-checks and repo-vs-production drift detection.
- **Encryption** — the data volume is LUKS-encrypted; TLS everywhere; SSH locked down.
- **Alerting hygiene** — one clean mail per real alert; the triage service is the single mail
  path (no legacy double-notifications).

### Troubleshooting — the ones that bite

| Symptom | Cause and fix |
|---|---|
| Console login returns **503 "Authentication service unavailable"** for everyone | Graylog's AD backend (LDAPS with certificate checks) does not trust the CA that now signs the domain controllers' certificates, typically after a CA renewal. Import the new root into the Java truststore set in `GRAYLOG_SERVER_JAVA_OPTS`, then restart `graylog-server`. While the backend fails, even local accounts are refused |
| **Logstash restarts in a loop** after a package upgrade | The upgrade removes the hand-installed `logstash-output-gelf` plugin. Reinstall it with `JRUBY_OPTS="-J-Xmx2g" logstash-plugin install logstash-output-gelf`; without the memory flag the installer runs out of heap. `oms-maj-siem` does it for you |
| Logstash **TLS errors to SQL Server** | Logstash ships its own JVM, which does not know the internal CA: use a truststore outside the package (`/etc/logstash/cacerts-omni.jks`, referenced in `jvm.options`). On the SQL side, check the instance is bound to the *current* machine certificate; after auto-renewal it keeps the old thumbprint |
| **OpenSearch red** right after a reboot | Expected for a few minutes while 1,200+ shards are reallocated. Graylog migrations running in that window may log rotation errors; they are harmless as long as `index_failures` stays empty. Wait for green before digging |
| Snapshots silently stopped | The `graylog_fs` repository registration lives in the cluster state and is lost if `path.data` is migrated or wiped. Re-register it |

More in [`docs/GUIDE-DEPANNAGE.md`](docs/GUIDE-DEPANNAGE.md) and the French README.

### Security & secrets

- No secret is committed. `.gitignore` excludes `00-vars.env`, `SECRETS.md`, keys,
  certificates and credential files; only `*.example` templates are versioned.
- Internal services (OpenSearch, MongoDB, the Graylog API, the console backend) listen on
  `127.0.0.1` only. Nginx (443) and the inputs are the only exposed ports, behind nftables
  and the perimeter firewall.
- Production robots that are patched in place are copied back into `deploye/` with
  `sync-deploye.sh`. It strips credentials from URLs, runs a secret scan and refuses to
  commit if anything shows up.

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
├── deploye/  sync-deploye.sh                    # production state of robots, units, APT pins (copied back from the server)
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

> Version française opérationnelle : [README.fr.md](README.fr.md). Les documents détaillés existent en français (`*.md`) et en anglais (`*.en.md`).
