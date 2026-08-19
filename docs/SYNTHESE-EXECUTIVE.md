# Executive summary — OMNITECH Security SIEM

*1-page document for management / IT department — 06/12/2026 — Classification: internal*

## In one sentence

OMNITECH Security operates an **operational SIEM (security operations center)**
that collects, correlates and monitors in real time the logs of the
entire information system, automatically detects attacks and
failures, and alerts the IT team — all documented and aligned with ISO 27001.

## What is covered

| Domain | Monitored |
|---|---|
| **Active Directory / Windows** | authentications, accounts, privileges, executions (servers + workstations) |
| **Microsoft 365 / Entra** | sign-ins, shares, mail forwarding, roles, **risky accounts (Entra ID Protection)** |
| **Network (FortiGate ×3)** | traffic, antivirus/IPS, web, VPN, **IP→machine attribution (DHCP)** |
| **Endpoint / EDR (ESET)** | workstation & server antivirus detections |
| **Application WAF (BunkerWeb)** | HTTP filtering, blocks, application scans |
| **Password vault (Vaultwarden)** | auth failures, admin access |
| **Virtualization (vSphere)** | access, machine lifecycle |
| **Backups (Veeam)** | job success / failure |
| **The SIEM itself** | collection, backup, capacity, **provable log integrity** (self-monitoring) |

## Demonstrated value (first week)

- **VPN attack blocked**: a password attack campaign from
  the Internet (10,000+ attempts, account lockouts) was detected and
  stopped by hardening, with no impact on users.
- **Critical backup failure revealed**: the password vault
  had not been backed up for 3 days — invisible until the SIEM.
- **Failing service account identified** (cause of an alert storm).

## Setup

- **88 definitions** (87 detections + 1 system), automatic (identity attacks, ransomware,
  cloud, network, internal intrusion) + **automated response** (IP blocking).
- **Notifications** by email + Microsoft Teams, with a handling commitment.
- **Single dashboard** across 24 pages for oversight.
- **Resilience**: daily encrypted and offsite backup, rebuild
  plan (recovery ≤ 4 h), capacity guardrails.
- **Authentication** of administrators via named AD accounts (LDAPS).

## ISO 27001:2022 compliance

Covers the measures A.8.15 (logging **+ provable log integrity**),
A.8.16 (monitoring), A.5.25 (assessment of events), A.8.13 (backup),
A.5.33 (protection of records), A.5.28 (evidence / evidential value),
A.8.9 (configuration management), **A.8.2 (privileged access — read-only role),
A.8.24 (encryption at rest — **completed**), A.5.7 (threat intelligence —
MITRE ATT&CK coverage 44 techniques)**.
Complete documentary set: policy, standard, procedure, architecture
dossier, compliance register, continuity plan.

## Points for the IT department's attention

1. **Validate and sign** the monitoring policy (POL).
2. Schedule the **annual restore test** (A.8.13 requirement).
3. Fix the backup of the vault server (technical action in progress).

## Cost / upkeep

**Open source** solution (Graylog/OpenSearch), fully scripted
(reproducible), operated by the IT team via documented daily,
weekly and monthly reviews. No license cost.
