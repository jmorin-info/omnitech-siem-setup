# SIEM ↔ ISO/IEC 27001:2022 mapping (Annex A)

> **Purpose.** This document bridges the technical capabilities of the OMNITECH
> SIEM and the controls of Annex A of ISO/IEC 27001:2022. For each
> relevant control: what the SIEM provides, and **where the evidence is**
> (documented information) for the auditor. It serves as a basis for drafting the
> formal ISMS documents (policies, procedures, records).
>
> **Status:** technical support to the ISMS — to be validated/approved by the CISO.
> **Scope:** Graylog SIEM (collection, detection, correlation, monitoring)
> of the OMNITECH Security information system.

## 1. Correspondence table (control → SIEM contribution → evidence)

| Annex A control (2022) | Title | SIEM contribution | Evidence / location |
|--------------------------|----------|----------------|----------------------|
| **A.8.15** | Logging | Centralized and tamper-proof collection of the logs of all the sources (AD/Sysmon, FortiGate, Microsoft 365/Entra, vSphere, Veeam, **ESET PROTECT**, **BunkerWeb WAF**, internal SIEM telemetry); timestamping; write-only protection | Graylog streams (13 streams); `docs/POLITIQUE-RETENTION.md`; `docs/INVENTAIRE-SOURCES.md` |
| **A.8.16** | Monitoring activities | 88 definitions (87 detections + 1 system) active, real-time dashboards ("OMNI - SOC", 24 pages), behavioral anomalies (UEBA), network monitoring (NDR) | "OMNI - SOC" dashboard; `docs/REGISTRE-DETECTIONS.md`; Graylog alerts |
| **A.8.17** | Clock synchronization | All hosts and the SIEM NTP-synchronized on the PDC; consistent event timestamping | NTP conf (`00-vars.env` NTP1/NTP2); `timestamp` field |
| **A.5.7** | Threat intelligence | Threat intel (Tor/Spamhaus), CISA KEV (exploited vulnerabilities), ESET PROTECT detections (endpoint threats/IoC), MITRE ATT&CK mapping | "ATT&CK", "Vulnerabilities", "External sources" pages; threat-intel lookup; `lookups/mitre-attack.csv` |
| **A.5.24** | Incident management planning | Automatic correlation of detections into timestamped **incidents** (kill-chain), P2/P3 prioritization, notifications | "Incidents" page; `docs/PROCEDURE-INCIDENT.md`; `omni-incident-correlate` |
| **A.5.25** | Assessment and decision on events | Risk scoring (MITRE + UEBA 0-100), severity, triage queue | "Critical incidents", "At-risk entities" KPIs; UEBA score |
| **A.5.26** | Incident response | Routing of notifications in **2 tiers**: Teams = firehose (all alerts), email = 26 critical "wake me up" alerts (confirmed compromise + SIEM health); SOAR-light (auto blocking of attacking IPs via FortiGate threat-feed) | Graylog notifications; `22-alert-routing.sh`; `omni-soar`; `docs/PROCEDURE-INCIDENT.md`; `docs/REPONSE-AUTOMATISEE.md` |
| **A.5.27** | Learning from incidents | Weekly report + monthly executive report (trends, top risks); queryable history | `omni-weekly-report`, `omni-monthly-report`; archive `/kit/rapports/` |
| **A.5.28** | Collection of evidence | Logs retained (security dossier **365 d**; FortiGate **180 d**; BunkerWeb **90 d**), timestamped, tamper-proof; raw message retained for forensics | OpenSearch index; `docs/POLITIQUE-RETENTION.md` |
| **A.8.7** | Protection against malware | Microsoft Defender detection (detection/disabling), **ESET PROTECT EDR/antivirus** (threats, HIPS events), FortiGate UTM (virus/IPS), ransomware indicators | "Defender", "ESET: detection", "FortiGate virus/IPS", "Ransomware indicator" alerts; "External sources" page |
| **A.8.8** | Management of technical vulnerabilities | Cross-referencing software inventory × CISA KEV (exploited CVEs) + patch age | "Vulnerabilities" page; `omni-vuln-scan` |
| **A.8.12** | Data leakage prevention | Exfiltration detection: DNS tunneling (entropy), M365 external shares, external mail forwards, outbound volume spikes | "DNS tunneling", "M365 external share / mail forward" alerts; UEBA/NDR page |
| **A.8.13** | Information backup | Monitoring of Veeam backups (failures/warnings), snapshots | "Backups" page; "Veeam job failed" alert |
| **A.8.9** | Configuration management | Daily backup of the SIEM configuration + disk safeguard | "Backup config", "Disk >80%" alerts |
| **A.5.23** | Cloud services security | Microsoft 365 / Entra monitoring: sign-ins, countries, roles, shares, OAuth | "M365", "M365 Activity" pages; M365 alerts |
| **A.8.2 / A.8.3 / A.5.18** | Privileged access / access rights | Reinforced monitoring of admin accounts (adm-*), privileged groups, special privileges | "Privileged accounts" page; "Privileged group", "DCSync", "Kerberoasting" alerts |
| **A.8.20 / A.8.21 / A.8.22** | Network security | Firewall traffic, denials, geolocation, segmentation, C2 beaconing; **BunkerWeb WAF** (HTTP application filtering, `http_*`/`waf_*` events) protecting the exposed services | "Network", "VPN & Exposure", "Mapping", "BunkerWeb WAF" pages; real-time cyber map; classification of exposed ports |
| **A.8.16 (go-dark)** | Monitoring — collection continuity | Detection of hosts that stop emitting (failure or sabotage) + SLA coverage; self-supervision of the analysis robots | "Collection health" page; `omni-collect-health`, `omni-self-health` |
| **A.5.10 / A.8.10** | Acceptable use / information deletion | Canary detection (decoy account/file), VM deletion, audit log sabotage | "Canary account", "Audit sabotage", "vSphere VM deletion" alerts |

## 2. Log integrity and protection (cross-cutting requirement A.8.15)

- **Tamper-proofing / evidentiary value**: write-only OpenSearch index **+
  HMAC-signed hash-chained integrity register** (`60-integrity.sh` →
  `omni-integrity`): daily fingerprint of the corpus state, **out-of-band copy
  (SMB share)**, weekly verification (`--verify`) and **alert if the chain
  is broken** → any retroactive deletion/alteration becomes **provable**
  (tamper-evidence). Cf. `docs/PROCEDURE-INTEGRITE-PREUVE.md` (A.8.15 / A.5.28).
- **Least privilege (A.8.2 / A.8.3)**: Graylog role "OMNI - Analyst (read-only)"
  for the analysts; admin account (the only one authorized to delete) reserved
  for **break-glass** (password in the vault).
- **Encryption at rest (A.8.24 / A.5.33)**: `/data` volume encrypted **LUKS2 +
  TPM2 unlock** (inline header, `aes-xts` 512 bits) — **done on 2026-06-14**,
  cf. `docs/PROCEDURE-CHIFFREMENT-REPOS.md`.
- **Alteration detection**: "Audit sabotage" rule (Event ID
  1102/4719/4794/104) in P3 + **"Log integrity COMPROMISED" alert** → immediate
  alert (email) if someone clears/disables logging or breaks the chain.
- **Access control**: SIEM console restricted by LDAPS + dedicated AD group;
  OpenSearch listening on localhost only.
- **Availability**: Graylog buffer journal (if OpenSearch unavailable);
  disk safeguard (controlled purge at 80%, never saturation — dedicated `/data`
  disk of 7.3 TB).
- **Backup**: SIEM configuration backed up daily (encrypted).
- **Dedicated index sets**: each source has its own index set with
  differentiated retention (security 365 d; FortiGate 180 d; BunkerWeb 90 d),
  guaranteeing compartmentalization and an explicit retention policy.

## 3. Formal ISO documents to derive (to be generated next)

This technical corpus makes it possible to draft the following normative documents:

1. **Logging and monitoring policy** ← `POLITIQUE-RETENTION.md`
   + this mapping (A.8.15/8.16/8.17).
2. **Incident management procedure** ← `PROCEDURE-INCIDENT.md`
   (A.5.24–5.28).
3. **SIEM operating procedure** ← `PROCEDURE-EXPLOITATION-SIEM.md`.
4. **Register of monitored assets / sources** ← `INVENTAIRE-SOURCES.md`
   (feeds the asset inventory A.5.9).
5. **Register of detection rules** ← `REGISTRE-DETECTIONS.md`.
6. **Evidence records**: archived monthly/weekly reports,
   alert history, dashboards (A.5.28).

## 4. Statement of Applicability (SoA) — note

The above controls are **implemented** (at least partially) by the
SIEM. The ISMS SoA must reference the SIEM as the means of implementation for
these controls, and this document as evidence of coverage.

---
*Technical support to the OMNITECH ISMS — to be validated and dated by the CISO.
Last review: **2026-06-14**. See also `GUIDE.md` (overview),
`CONTEXT.md` (implementation detail), `INVENTAIRE-SOURCES.md` (assets A.5.9),
`REGISTRE-DETECTIONS.md` (rules A.8.16) and `POLITIQUE-RETENTION.md` (durations).*
