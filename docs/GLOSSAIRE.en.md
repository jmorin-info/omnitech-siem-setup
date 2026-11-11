# Glossary — SIEM OMNITECH

*Terms used across the documentation set, for non-specialist readers
(management, audit, newcomers).*

> Review date: 2026-06-14.

## General concepts

| Term | Definition |
|---|---|
| **SIEM** | *Security Information and Event Management*. A system that centralizes the logs of the entire IS, correlates them, detects threats and alerts. Here: Graylog. |
| **SOC** | *Security Operations Center*. The security supervision function (at OMNITECH: the IT team, tooled by the SIEM). |
| **Journal / log** | Timestamped trace of an event (logon, access, action). The SIEM's raw material. |
| **Graylog** | The (open source) SIEM software that ingests, processes and presents the logs. |
| **OpenSearch** | The database that stores and indexes the logs (search engine). |
| **Input** | Entry point for logs into Graylog (a port + a protocol). |
| **Stream** | Named flow that groups the messages from a single source (e.g. "Windows Security"). |
| **Pipeline / rule** | Processing applied to messages: normalization, enrichment, tagging. |
| **Index / retention** | Storage by period; retention is the keeping duration before automatic deletion. |
| **Detection / alert** | A rule that watches a pattern (e.g. 10 failed logons) and notifies when it occurs. |
| **Dashboard** | Visual dashboard (here "OMNI - SOC", a single 24-page dashboard, 100% open source — no Enterprise license required). |
| **GeoIP** | Enrichment that maps an IP to a country/city (for the cartography). |
| **Lookup** | Correspondence table (e.g. event code → readable label, canary IP → account). |

## Log sources and collectors

| Term | Definition |
|---|---|
| **AD (Active Directory)** | Microsoft directory that manages the domain's accounts, workstations and authentications; the main source of security events. |
| **Winlogbeat** | Agent installed on Windows machines (AD, servers) that sends their logs to the SIEM, encrypted (Beats on port 5044, TLS). |
| **Sysmon** | Microsoft tool that produces detailed workstation telemetry (processes, network, file creation…); 365-d retention. |
| **FortiGate** | OMNITECH's Fortinet firewall; its logs (traffic + UTM) are voluminous, hence a dedicated 180-d retention. The `source` field carries the device name. |
| **FortiAnalyzer (FAZ)** | Fortinet collector that centralizes the logs of the FortiGate firewalls and forwards them to the SIEM (syslog, port 1514). |
| **UTM** | *Unified Threat Management*: firewall security functions (antivirus, IPS, web/DNS filtering). |
| **M365 (Microsoft 365)** | Microsoft cloud suite (mail, OneDrive…); the audit activity is retrieved by a collector then injected in GELF. |
| **GELF** | *Graylog Extended Log Format*: structured log format used for the M365 collectors and the SIEM's self-monitoring. |
| **vSphere / vCenter** | VMware virtualization platform; the ESXi hosts and the vCenter send their logs in syslog (port 1516). |
| **Veeam** | Backup solution; its logs feed the backup-related detection (deletion, failures). |
| **ESET PROTECT** | ESET antivirus/EDR console; sends its detections in syslog JSON (port 1515) to the "OMNI - ESET" stream (`eset_*` fields), 365-d retention. |
| **BunkerWeb** | Web application firewall (WAF) protecting the exposed services; its logs are forwarded by Filebeat to the Beats input (5044) → "OMNI - BunkerWeb" stream (`http_*` / `waf_*` fields), 90-d retention. |
| **WAF** | *Web Application Firewall*: filters malicious HTTP requests (injections, scans…); here provided by BunkerWeb. |
| **Filebeat** | Lightweight agent that reads log files (e.g. BunkerWeb) and ships them to the SIEM via the Beats input. |
| **NPS** | *Network Policy Server* (Microsoft RADIUS server); mapped in the documentation but not yet forwarded on the client side. |

## Threats and attack techniques

| Term | Definition |
|---|---|
| **DCSync** | Attack technique: impersonating a domain controller to steal the AD passwords. |
| **Kerberoasting** | Attack that extracts Kerberos tickets to crack the passwords of service accounts. |
| **Brute force / spraying** | Massive password attempts (brute force = one account; spraying = one password against many accounts). |
| **Ransomware** | Software that encrypts data for extortion; detected here via the deletion of backups (shadow copies). |
| **LSASS** | Windows process that holds credentials in memory; a classic target for password theft. |
| **Canary account** | Decoy account never used; any activity involving it signals an intrusion (lookup `omni-canary`, critical alert email + Teams). |

## Detection, response and alerting

| Term | Definition |
|---|---|
| **MITRE ATT&CK** | Public reference of attack tactics and techniques; the SIEM correlates the detections by tactic to spot attack chains. |
| **UEBA** | *User and Entity Behavior Analytics*: behavioral risk score per host/account (detections + vulnerabilities + anomalies merged). |
| **NDR** | *Network Detection and Response*: detection of suspicious network behaviors (scans, DNS exfiltration…). |
| **SOAR** | *Security Orchestration, Automation and Response*: automated response (here, blocking attacking IPs on the firewall). |
| **Threat feed** | List of malicious IPs/domains that a firewall reads to block; the SIEM dynamically feeds one. |
| **LDAPS** | Secure (encrypted) LDAP: authentication protocol for AD accounts on the console. |
| **P2 / P3** | Alert priority levels (P3 = critical; P2 = important). The "wake-me-up" P3 goes by email; all priorities combined also go to Teams. |
| **2-tier routing (email / Teams)** | Notification routing: **Teams = firehose** (all alerts); **email = 26 critical alerts** only (confirmed compromise + SIEM health). Avoids spamming the mailbox (script `22-alert-routing.sh`). |
| **Grace (anti-storm)** | Delay during which the same alert does not re-notify, to avoid spam (≥ 60 min on recurring email alerts). |

## Governance and operations

| Term | Definition |
|---|---|
| **RTO / RPO** | Continuity objectives: recovery time (RTO) and maximum data loss (RPO). |
| **IaC** | *Infrastructure as Code*: the entire configuration is in reproducible scripts, not done "by hand". |
| **Purge / repopulation** | Operational procedure: `53-purge-clean.sh` wipes the data while preserving the configuration, then `54-post-purge-repopulate.sh` re-primes the flows. |
| **ISO 27001** | International standard for information security management; this documentation set covers its logging/monitoring measures. |

## Advanced detection, integrity & encryption

| Term | Definition |
|---|---|
| **MITRE ATT&CK** | Worldwide reference of attack techniques (T####). Every detection is mapped to it; the coverage (44 techniques) is visualized by loading the `mitre-navigator-layer.json` layer into ATT&CK Navigator. |
| **KEV** | *Known Exploited Vulnerabilities* (CISA catalog): flaws **actively exploited** in the wild → absolute remediation priority. |
| **Integrity / tamper-evidence** | Daily register **hash-chained and signed** of the logs' state, copied off-SIEM: makes any retroactive deletion/tampering **provable** (audit evidential value). |
| **Unified identity (`identity`)** | Canonical account (without domain or `@upn`) correlating the same person across AD, M365, VPN, endpoint; `identity_human` groups the `adm-`/`svc-` accounts under the person. |
| **DHCP attribution (`src_hostname`)** | IP→machine correlation via the FortiGate's DHCP leases: answers "who is behind 10.33.x.x" during an investigation. |
| **SOAR** | *Security Orchestration, Automation & Response*: reflex response (e.g. blocking an attacking IP), with guards (never an internal or allowlisted IP). |
| **TPM2 / LUKS** | Encryption of the `/data` data disk: LUKS2 encrypts, the **TPM2** (motherboard chip) unlocks it automatically at boot — the disk stays unreadable if stolen/extracted. |
| **Entra ID Protection** | Microsoft's risk engine (ML) on the M365 tenant: flags "at-risk" accounts (impossible travel, leaked credentials…) — ingested into the SIEM (`m365_type:risk`). |
