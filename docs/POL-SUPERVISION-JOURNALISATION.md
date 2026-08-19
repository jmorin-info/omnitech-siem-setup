# POL — Monitoring and Logging Policy

| | |
|---|---|
| **Version** | 1.0 — 12/06/2026 |
| **Owner** | OMNITECH Security IT Department |
| **Approval** | Pending IT Department validation (date/signature: ____________) |
| **Classification** | Internal |
| **Review** | Annual, or after a major incident / regulatory change |
| **ISO 27001:2022 refs** | A.8.15, A.8.16, A.5.25, A.5.33, A.5.28, A.8.13 |

## 0. Normative and regulatory framework

This policy is part of OMNITECH Security's Information Security Management
System (ISMS) and addresses the following requirements:

| Framework | Requirements covered |
|---|---|
| **ISO/IEC 27001:2022** (Annex A) | 8.15 Logging · 8.16 Monitoring · 5.25 Assessment of events · 8.13 Backup · 5.33 Protection of records · 5.28 Collection of evidence · 8.9 Configuration management · 8.6 Capacity |
| **GDPR** (EU 2016/679) | Art. 5 (minimisation, storage limitation), Art. 32 (security of processing) |
| **ANSSI recommendations** | "Logging" guide (6-12 month retention periods), Active Directory recommendations |
| **CNIL framework** | Log retention periods, traceability |

This policy is broken down into subordinate documents: **STD-JOURNALISATION**
(technical rules), **PRO-EXPLOITATION-SIEM** (operational procedures),
**DOSSIER-ARCHITECTURE-SIEM** (design). In the event of a contradiction, the
hierarchy is: Policy > Standard > Procedure.

## 1. Purpose and scope

This policy defines OMNITECH Security's commitments regarding
**logging** (collection and retention of traces) and
**security monitoring** (detection and handling of events).

Scope: the entire information system — the BX (Bordeaux), IV
(Ivry) and LC/PACA sites — including: Active Directory and Windows servers,
workstations, FortiGate firewalls (3 clusters), the vSphere virtualisation
infrastructure, Microsoft 365, Veeam backups, and the SIEM itself.

## 2. Responsibilities

| Role | Responsibility |
|---|---|
| **IT Department** | Validates the policy, arbitrates retention periods, receives reporting |
| **SIEM Administrator** (IT team) | Day-to-day operations, alert triage, upkeep (PRO) |
| **System/network administrators** | Maintenance of log sources (agents, audit policy, forwarding) |
| **Every employee** | Informed that IS usage is logged (acceptable use policy) |

## 3. Logging principles

1. **Targeted completeness**: security events are logged as a priority
   (authentication, account and privilege management, process execution,
   network and UTM traffic, cloud access, backups) — not the systematic
   capture of content.
2. **Centralisation**: all sources converge on the Graylog SIEM
   (`bx-it-graylog-vm`, dedicated VLAN 220), the single point for search,
   correlation and alerting.
3. **Secure transport**: TLS for agents (port 5044, internal PKI); internal
   syslog flows confined to the administration VLANs by dedicated firewall
   rules.
4. **Reliable timestamping**: all sources are NTP-synchronised; timestamps
   stored in UTC in the SIEM, displayed in Europe/Paris.
5. **Dedicated service accounts**: no collection service runs under a named
   or administrative account (the 12/06/2026 incident — FSSO service —
   established as a rule).

## 4. Log retention

Periods validated against CNIL/ANSSI recommendations (6 months to 1 year for
security logs) and dedicated capacity (7.3 TB):

| Category | Flow | Retention |
|---|---|---|
| Identity and authentication | Windows Security (AD), accounts, Kerberos | **365 days** |
| Systems and applications | Windows System/PowerShell/Defender, **Veeam** | **365 days** |
| Cloud | Microsoft 365 (sign-ins, audit, Exchange/SharePoint) | **365 days** |
| Endpoint telemetry | Sysmon (processes, network, DNS) | **180 days** |
| Network | FortiGate (traffic, UTM, VPN) | **180 days** |
| Virtualisation | vSphere (ESXi, vCenter) | **180 days** |
| SIEM configuration | Daily encrypted backup | **14 days** |

Deletion at expiry is **automatic** (daily index rotation). Any request for
extended retention (litigation, investigation) is subject to a manual hold
documented by the IT Department.

## 5. Monitoring and alerting

- **88 definitions** (87 detections + 1 system) active, covering: identity
  attacks (brute force, spraying, Kerberoasting, DCSync), endpoint
  (ransomware, injection, offensive PowerShell, LSASS), network (UTM,
  malicious IPs, VPN), M365 cloud, virtualisation, backups, and SIEM
  self-monitoring (silent collection, backup failure, disk).
- **Two notification levels**: P3 (critical) = IT team e-mail +
  Teams; P2 (important) = SOC Teams channel. Anti-storm: grace period
  per alert (and per account/IP for keyed alerts).
- **Handling commitment**: every P3 alert is qualified **on the same
  business day**; P2 alerts are reviewed daily (see PRO §2).
- Detection coverage is reviewed at each IS change and at least
  **quarterly**.

## 6. SIEM backup and continuity

- Full configuration backed up **every night (03:15)**, AES-256 encrypted,
  offloaded outside the VM (`\\10.33.50.5\Public\SIEM`),
  14-day retention, **automatic alert on failure or absence**.
- Rebuild procedure documented and tested (`RESTORE.md`); target for
  resuming collection: **≤ 4 h** after a replacement VM is made available
  (historical logs are not restored).
- Capacity safeguards: alert at 80% of data volume, automatic emergency
  purge of the oldest logs at 88% (the day's collection takes precedence
  over history).

## 7. Protection and evidence

- Access to the SIEM console is restricted (dedicated administrative account;
  target: AD authentication via LDAPS, see LDAPS.md) and logged.
- SIEM logs constitute an element of evidence: their integrity is
  protected (deletion impossible outside retention without administrative
  rights; any emergency purge is alerted and logged).
- Sabotage of logging **at the sources** is itself detected
  (Windows log clearing 1102/104, audit stop 4719, silence of an
  agent).

## 8. Compliance and personal data

Logs contain personal data (usernames, IPs). Their processing is based on the
legitimate interest of securing the IS, is proportionate (security purpose
exclusively), time-limited (§4) and restricted to authorised personnel.
Recorded in the register of processing activities.

- **Exclusive purpose**: IS security and incident investigation. Any use
  for other purposes (individual monitoring of employee activity) is
  prohibited.
- **Information**: employees are informed of the existence of logging via
  the acceptable use policy (works council consultation possible).
- **Access**: only authorised SIEM administrators consult the nominative
  logs; console access is itself logged.

## 9. Steering indicators (KPI)

Tracked by the SIEM administrator and presented in the management review:

| Indicator | Target | Source |
|---|---|---|
| Monitored hosts / estate ratio | ≥ 95% | Collection Health dashboard |
| Sources silent > 24 h | 0 | "Winlogbeat Silence" alert + review |
| Indexing failures (per week) | 0 | System → Indexer failures |
| P3 alert qualification time | ≤ 1 business day | Handling register |
| Successful config backups / 14 d | 14/14 | Backups page |
| Untreated failed Veeam backups | 0 | Veeam alert |
| /data fill level | < 80% | Disk safeguard |
| Restoration test | ≥ 1 / year, successful | PRO §2 |

## 10. Exception management

Any deviation from this policy or the standard (e.g. an unlogged source,
reduced retention, a service under a non-dedicated account) must be:
**documented**, **justified** (technical/business constraint), **dated**,
**approved by the IT Department**, accompanied by a **review deadline**, and
recorded in a register of deviations. A deviation without a deadline is
prohibited.

## 11. Awareness and continuous improvement

- System/network administrators are made aware of logging requirements
  (upkeep of the audit policy, agents, forwarding).
- Any security or SIEM operational incident feeds a lessons-learned entry
  recorded in `CONTEXT.md` (pitfalls and resolutions) and, where relevant,
  drives an evolution of this policy or the standard.
- **Review**: annual at a minimum, and after any major incident, significant
  architecture change or regulatory change.

## 12. Validation

| Role | Name | Date | Signature |
|---|---|---|---|
| Author (SIEM Admin) | J. Morin | 12/06/2026 | |
| Approver (IT Department) | | | |

*History: v1.0 — 12/06/2026 — creation.*
