# STD — Technical Logging Standard

*Version 1.0 — 12/06/2026 — implements POL-SUPERVISION-JOURNALISATION — Classification: internal*

This standard sets the MANDATORY technical rules. Any deviation is a
non-conformity to be corrected or documented (IT department waiver).

## 1. Mandatory sources and collected channels

| Source | Mechanism | Channels / contents | SIEM stream |
|---|---|---|---|
| AD controllers (BX-AD-01, BX-AD02 + site DCs) | Winlogbeat 8.17.4 OSS (TLS 5044) | Security (EventID **in ranges**: 1100-1104, 4624-4799, 4886-4889, 5136-5145, 6272-6274, 7045), Sysmon, PowerShell 4104, Defender, System, RDP, NTLM | OMNI - Windows Security / Sysmon / Windows autres |
| Windows servers and workstations | idem (NinjaOne deployment `Install-OmniSiem-NinjaOne.ps1`, daily) | idem + **"Veeam Backup"** channel auto-detected on the Veeam server | idem |
| FortiGate (3 clusters: OMNITECH-BDX_FG120G, FGFW-IV, HA-LC) | FortiAnalyzer → syslog forwarding (TCP 1514) | traffic, event (VPN), **utm** (virus/IPS/webfilter/DNS/app-ctrl) | OMNI - FortiGate |
| vSphere (4 ESXi + vCenter 8) | syslog TCP/UDP 1516 | auth, shell/SSH, VM lifecycle, snapshots | OMNI - vSphere |
| Microsoft 365 / Entra ID | API collectors (Graph + O365 Management Activity) → GELF HTTP 12201 | sign-ins, Entra audit, Exchange, SharePoint/OneDrive | OMNI - M365 |
| SIEM itself | GELF 12201 (event_source=siem_*) | config backup status, disk guard | OMNI - Interne SIEM |

**Imperative rules:**
- Security channel: **never a flat list of EventIDs** (Windows API limit
  ≈ 23 expressions → silent channel). Always ranges.
- Every new server/workstation is enrolled by the single script
  `Install-OmniSiem-NinjaOne.ps1` (CA, audit, Sysmon, Winlogbeat, 5044 check).
- Windows audit policy: `audit-baseline.csv` baseline (auditpol),
  command line in 4688 events, ScriptBlockLogging, Security ≥ 2 GB.

## 2. Transport, network and collection security

| Flow | Port | Security |
|---|---|---|
| Winlogbeat → SIEM | TCP 5044 | TLS, OMNITECH root CA (PKI AD CS) |
| FAZ → SIEM | TCP 1514 | management VLAN, dedicated FW rule |
| vSphere → SIEM | TCP/UDP 1516 | management VLAN, dedicated FW rule |
| M365 collectors (localhost) | HTTP 12201 | local only |
| Web console | HTTPS 443 (nginx) | internal PKI certificate |
| Graylog API | HTTPS 9000 (localhost + FQDN) | TLS, internal CA |
| SIEM → backup share | TCP 445 | dedicated account `svc_siem`, encrypted archive |

Host firewall (nftables): 80/443/5044 restricted to 10.33.0.0/16; 1514/1516
restricted to legitimate emitters. Dedicated FortiGate rules per flow ("Réseau
ELK" zone).

## 3. Normalization (pivot fields)

The pipeline (144 rules) guarantees the following common fields — any
new source MUST populate them:

| Field | Content | Example |
|---|---|---|
| `event_source` | source family | windows_security, fortigate, veeam, m365 |
| `event_action` | normalized action (fr, snake_case, ASCII) | echec_connexion, vm_supprimee |
| `user` | account concerned (without domain) | jmorin, adm-jmorin |
| `src_ip` / `dest_ip` | **validated** IPs (never "N/A", "x.x", ip:port) | 10.33.20.4 |
| `host` / `source` | emitting machine | bx-veeam-it-sv |
| `alert_tag` | detection marker for alert rules | dcsync, veeam_job_echec |
| `failure_reason` | translated failure cause (lookup) | mot_de_passe_errone |

Conventions: prefix **OMNI -** for every Graylog object (streams, alerts,
dashboard); index **omni-***; daily rotation; ASCII without accents
in any content pushed to Windows/emails.

## 3bis. Matrix of monitored Windows events

Reference of the collected EventIDs (Security channel in **ranges**, cf. §1) and
their detection usage:

| EventID | Meaning | SIEM usage |
|---|---|---|
| 4624 / 4625 | Successful / failed logon | Brute force, spraying, success tracking, logon types |
| 4634 / 4647 | Logoff | Session correlation |
| 4648 | Logon with explicit credentials | Lateral movement |
| 4662 | Operation on an AD object | **DCSync** (replication GUID) |
| 4670 | Permissions modified | Elevation, persistence |
| 4672 | Special privileges at logon | Privileged account tracking |
| 4688 | Process creation (+ command line) | Endpoint, LOLBins |
| 4697 / 7045 | Service installed | Persistence |
| 4698 / 4699 | Scheduled task created / deleted | Persistence |
| 4720/4722/4725/4726 | Account created/enabled/disabled/deleted | Account lifecycle |
| 4724/4723 | Password reset / change | Account takeover |
| 4727-4737 / 4754-4758 | Group management (creation, member addition) | **Privileged groups** |
| 4732 / 4728 / 4756 | Addition to a sensitive local/global/universal group | Elevation |
| 4740 | Account locked out | Effect of brute force / DoS |
| 4767 | Account unlocked | Tracking |
| 4768 / 4769 / 4771 | Kerberos (TGT, TGS, pre-auth) | **Kerberoasting** (4769 RC4) |
| 4776 | NTLM validation | Legacy authentication failures |
| 4778 / 4779 | Session reconnected / disconnected (RDP) | Remote access |
| 4794 | DSRM attempt | DC compromise |
| 5136 / 5137 / 5141 | AD object modification / creation / deletion | Directory changes |
| 5140 / 5145 | Network share access | **Admin share sweeping** (ADMIN$, C$) |
| 1102 / 1100 | Audit log cleared / stopped | **Audit sabotage** |
| 6272-6274 | NPS (RADIUS) | Network access (802.1X) |
| 4886-4889 | AD CS (certificates) | PKI activity |

Complementary sources: **Sysmon** (1 process, 3 network, 8/25 injection,
10 LSASS access, 11 file, 13 registry Run, 17/18 named pipes, 22 DNS),
**PowerShell** 4104 (ScriptBlock), **Defender** (1006/1116/5001/5007…),
**System** (104, 7045, 7036, 6005/6006/6008).

## 4. Severities and notifications

| Level | Usage | Notification | Anti-storm grace |
|---|---|---|---|
| **P3** | Action required (attack, sabotage, backup KO) | Email IT team + Teams SOC | 10 min to 4 h depending on the rule, **per key** (account/IP) when relevant |
| **P2** | To be aware of (weak signal, hygiene) | Teams SOC | 30 min to 4 h |

Rules: **service/batch type (4/5)** logon failures never feed
brute-force detections (dedicated hygiene alert). Any "persistent state"
alert has a grace ≥ 30 min. Every email is in ASCII, without a link
to the console.

## 5. Retention, capacity, integrity

- Retentions per index: cf. POL §4 — applied by `41-retention-iso.sh`
  (to re-run after any re-provisioning of the model).
- Capacity: nominal volume ≈ **25 GB/day**; projected ceiling ≈ 5.6 TB /
  7.3 TB (77%). **Monthly review** of the GB/day (procedure PRO §4).
- Guard: `32-disk-guard.sh` (every 6 h) — alert ≥ 80%, emergency purge
  ≥ 88% (oldest indices first, never an active index),
  every purge is alerted.
- Indexing failures: 0 tolerated in nominal operation (System → Indexer
  failures); any non-conforming value is corrected **at the source or the
  pipeline** (never by loosening the mapping).

## 6. Accounts and secrets

| Account/secret | Usage | Rule |
|---|---|---|
| `admin` (local Graylog) | console administration | strong password in the vault; target: named accounts via LDAPS |
| `svc_siem` (AD) | SMB backup repository | rights limited to `Public\SIEM`, never interactive |
| `BACKUP_PASSPHRASE` | archive decryption | vault mandatory |
| Entra app (M365) | cloud log reading | read-only rights (Reports/AuditLog) |
| `00-vars.env` | provisioning secrets | chmod 600, included in the encrypted backup |

General prohibition: no collection service under a named account or a
member of an administration group.

## 7. Time synchronization (mandatory)

Multi-source event correlation requires a common clock:
- All sources (DC, servers, workstations, FortiGate, ESXi) are
  NTP-synchronized on the same reference (domain PDC emulator).
- The SIEM stores in **UTC** and displays in **Europe/Paris**.
- Any clock drift > a few seconds is treated as an anomaly
  (skews the alerts' sliding windows and the investigations).

## 8. Hardening and SIEM protection

| Measure | Status |
|---|---|
| Console and API over HTTPS only (TLS, internal CA) | ✅ |
| nftables host firewall (ingestion ports restricted by CIDR/source) | ✅ |
| Console accounts: target LDAPS + "Admins du domaine" group (cf. LDAPS.md), local `admin` fallback in the vault | in progress |
| No direct OpenSearch/MongoDB access outside localhost | ✅ |
| Secrets (`00-vars.env`, `.smb-siem.cred`) in chmod 600 | ✅ |
| AES-256 encrypted backups, passphrase in the vault | ✅ |
| Source sabotage detection (1102/104, audit stop, agent silence) | ✅ |
| Self-monitoring (silent collection, backup KO, disk) | ✅ |

## 9. Integrity and evidential value

- Indices are under controlled rotation/retention; **no deletion
  outside retention** without administration rights, and any emergency purge
  (disk guard) is **alerted and traced**.
- To build evidence: export the relevant subset (Graylog search
  → export), timestamped, and keep it outside rotation (documented manual
  freeze, IT department).
- The SIEM is backed up daily (config); the logs themselves
  are not backed up but are protected by their retention period.

## 10. Naming conventions (recap)

| Element | Convention | Example |
|---|---|---|
| Graylog objects | prefix `OMNI - ` | `OMNI - Windows Security` |
| Index sets | `omni-<flux>` | `omni-fortigate` |
| Detection tags | `alert_tag` snake_case ASCII | `dcsync`, `veeam_job_echec` |
| Normalized actions | `event_action` French snake_case without accent | `echec_connexion` |
| IaC scripts | `NN-object.sh` numbered by execution order | `12-graylog-pipelines.sh` |
| Hosts | existing AD nomenclature | `bx-veeam-it-sv` |
