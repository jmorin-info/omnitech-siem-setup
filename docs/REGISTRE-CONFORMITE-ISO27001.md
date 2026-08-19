# ISO/IEC 27001:2022 compliance register — OMNITECH SIEM

*Version 1.0 — 12/06/2026 — Scope: monitoring, logging and
detection provided by the Graylog SIEM `bx-it-graylog-vm`. Classification: internal.*

Status legend: ✅ Compliant · 🟡 Partial (action in progress) · ⬜ To be addressed.

## 1. Organizational controls (A.5)

| A.5 control | Requirement | Implementation (evidence) | Status |
|---|---|---|---|
| 5.7 Threat intelligence | Threat intelligence | Tor/Spamhaus, GeoIP lookups, `threat_intel` rules | ✅ |
| 5.15 Access control | Restrict access | Console restricted to "Domain Admins" via LDAPS (LDAPS.md), host firewall | ✅ |
| 5.16 Identity management | Traceable identities | Nominative AD auth on the console (LDAPS backend) | ✅ |
| 5.17 Authentication | Managed secrets | LDAPS + local backup `admin` in the vault; secrets chmod 600 | ✅ |
| 5.18 Access rights | Least privilege | Dedicated service accounts (svc_siem), no collection under an admin account | ✅ |
| 5.23 Cloud services security | Cloud monitoring | M365 collection (sign-ins, audit, Exchange/SharePoint) | ✅ |
| 5.25 Assessment of events | Qualify/classify | Triage PRO §3, classification PRO §7, 88 prioritized definitions | ✅ |
| 5.26 Incident response | Procedure + response | Playbooks PRO §6, RACI matrix §8, **SOAR-light** (auto blocking of attacking IPs via FortiGate feed) | ✅ |
| 8.16 (internal detection) | Detect intrusion | **AD canary account** (decoy, ~zero false positives) | ✅ |
| 5.28 Collection of evidence | Usable evidence | UTC-timestamped logs, Graylog export, controlled retention (STD §9) | ✅ |
| 5.33 Protection of records | Log integrity | Automatic retention, out-of-retention deletion impossible without rights, traced purge | ✅ |
| 5.36 Compliance with policies | Regular review | PRO §2 reviews + **automatic weekly report** (evidence) | ✅ |

## 2. People controls (A.6)

| Control | Requirement | Implementation | Status |
|---|---|---|---|
| 6.3 Awareness | Information | IT charter (logging), POL §11 | 🟡 (charter outside the SIEM) |
| 6.8 Event reporting | Escalation | Email + Teams SOC notifications to the IT team | ✅ |

## 3. Physical controls (A.7)

| Control | Requirement | Implementation | Status |
|---|---|---|---|
| 7.4 Physical monitoring | — | Outside the SIEM scope (access control/NVR logs collected via FortiGate) | 🟡 |

## 4. Technological controls (A.8) — core of the setup

| A.8 control | Requirement | Implementation (evidence) | Status |
|---|---|---|---|
| 8.5 Secure authentication | Robust console auth | LDAPS/TLS, cert verified by Root CA, access limited to admins | ✅ |
| 8.6 Capacity management | Size/monitor | Capacity plan (STD §5), disk safeguard `32`, weekly KPIs | ✅ |
| 8.7 Protection against malware | Detect | FortiGate UTM (AV/IPS), Defender, ransomware/PowerShell/LSASS rules | ✅ |
| 8.8 Management of technical vulnerabilities | — | OpenVAS (logs collected); patching outside the SIEM | 🟡 |
| 8.9 Configuration management | Controlled config | **IaC**: scripts 10→34 idempotent, daily config backup | ✅ |
| 8.10 Information deletion | Deletion in due course | Automatic per-index retention (POL §4, `31`) | ✅ |
| 8.12 Data leakage prevention | Detect exfiltration | M365 (external share, mail forward), FortiGate (outbound threat intel) | ✅ |
| 8.13 Backup | Back up/test | Externalized encrypted config backup (`30`), DRP, **test to be performed** | 🟡 |
| 8.15 Logging | Produce/protect logs | 7 inputs, 13 streams, 144 pipeline rules, retention POL §4, complete STD | ✅ |
| 8.16 Monitoring activities | Monitor/alert | **88 definitions** (87 detections + 1 system), 24-page dashboard, notifications, self-monitoring | ✅ |
| 8.17 Clock synchronization | Common clock | NTP on all sources, UTC in the SIEM (STD §7) | ✅ |
| 8.20 Network security | Segment | Dedicated VLAN 220, FortiGate rules per flow, host firewall | ✅ |
| 8.23 Web filtering | — | FortiGate webfilter/DNS filter (logs collected) | ✅ |
| 8.28 Secure coding | — | Outside scope (CI/CD logs not covered) | ⬜ |

## 5. Summary of open actions

| # | Action | Ref | Owner | Deadline |
|---|---|---|---|---|
| 1 | Have the POL signed by IT management | POL §12 | IT management | — |
| 2 | Perform the restore test (DRP) | DRP, A.8.13 | SIEM admin | Current quarter |
| 3 | Shift the Veeam *Backup Copy* job (restore-point lock contention; the backup **succeeds on retry**, not a DRP gap) | Veeam detection | Sys admin | — |
| 4 | Extend collection to the remaining Windows servers + enable file audit SACLs on the sensitive folders | STD §1 / `59` | Sys admin | — |
| 5 | Encryption at rest for `/data` (LUKS2/TPM2) | A.8.24, PROCEDURE-CHIFFREMENT | SIEM admin | ✅ **Done on 2026-06-14** |
| 6 | Assign the analyst accounts to the Graylog "read-only" role (created) | A.8.2 | SIEM admin | — |
| 7 | Enable the NinjaOne API → advanced SOAR (host isolation / account disabling) | SOAR-PLAYBOOKS | SIEM admin | — |
| 8 | Link the IT charter (awareness 6.3) | A.6.3 | IT management | — |

> *Closed 2026-06-14*: AD canary account (in production, cf. §1 A.8.16 + REPONSE-AUTOMATISEE); creation of the Graylog read-only role (action #6 = assigning the accounts remains); log integrity/evidentiary value (hashed-signed register); **encryption at rest for `/data` (LUKS2 + TPM2 unlock) done**.

## 6. Evidence method for the auditor

| Typical auditor question | Where to show the evidence |
|---|---|
| "What do you log?" | STD §1 + §3bis (EventID matrix) |
| "For how long? Why?" | POL §4 (retentions justified CNIL/ANSSI) |
| "How do you detect?" | DOSSIER §6 (88 definitions) + live dashboard |
| "Who handles, in how much time?" | PRO §2/§3/§7 + processing register |
| "Prove the regular review" | Weekly report (email + copy `/var/backups/siem/`) |
| "And if the SIEM goes down?" | DRP + daily backup + absence alert |
| "Who accesses the SIEM?" | LDAPS.md (admin restriction) + console access logs |
| "Evidence integrity?" | STD §9 + traced/alerted purge |

*Review of this register: at each internal audit and at least annually.*

## 7. Maintenance log (operational evidence A.8.15 / A.8.16 / A.8.17)

| Date | Action | Justification / scope | Control |
|---|---|---|---|
| 2026-06-14 | **Purge of the log indices** (data + alert history; **configuration preserved**) | **Planned maintenance** action: reset after anti-false-positive tuning (the initial dataset was polluted by FPs from service/machine accounts and legitimate internal scripts). Clean reconstitution via `54-post-purge-repopulate.sh`. Collection outage: none (ingestion resumed immediately into empty indices). | A.8.15 (traced and justified audit-trail break) |
| 2026-06-14 | **FortiGate timestamp fix**: `timestamp` set from `eventtime` (epoch ns) | Before: Graylog fell back to the reception time (+ ~14k errors/day). After: **exact event time** (residual gap 0.2 s); errors removed. | A.8.17 (clock synchronization / timestamp accuracy) |
| 2026-06-14 | **Inter-source clock drift audit** (read-only) | Event-time / reception-time gap measured per source: FortiGate 0.2 s, vSphere 1 s, Windows/Sysmon 5-7 s, BunkerWeb 7.6 s — **all < 8 s** (threshold 60 s). SIEM: NTP active/synchronized. **No significant drift.** | A.8.17 |
| 2026-06-14 | **False positive reduction** (multi-agent audit) + **2-tier alert routing** (email = critical only, Teams = firehose) | Improves detection relevance (A.8.16) and ensures that critical alerts are not drowned out (usable review evidence). | A.8.16 / A.5.25 |
| 2026-06-14 | **Log integrity / evidentiary value**: HMAC-signed hash-chained register (`60-integrity.sh`), out-of-band SMB copy, weekly verification + alert on chain break; **Graylog read-only role** (least privilege) | Raises log protection from "write-only" to **provable inalterability** (tamper-evidence); reduces the surface for manipulation by privileged accounts. | A.8.15 / A.8.2 / A.5.28 |
| 2026-06-14 | **MITRE ATT&CK coverage mapped** (44 techniques / 12 tactics out of 14) + new detections (privilege escalation, M365 risk/brute, file audit 4663/5145, integrity, Internet exposure) | Explicit measurement and extension of detection coverage; helps prioritization. | A.8.16 / A.5.7 |
| 2026-06-14 | **Vaultwarden hygiene purge**: ~46 M misrouted replay documents deleted (Filebeat was replaying the container's 2023→2026 history); drop rule added + **dedicated index set** | Restores the quality of the detection aggregates; the real internal/Windows events are preserved; audit-trail break traced and justified. | A.8.15 |
| 2026-06-14 | **Encryption at rest for `/data` DONE** (inline LUKS2, aes-xts 512 bits + TPM2/PCR7 unlock). Method: fresh encrypted reformat — the indexed logs were re-purged then repopulated (live ingestion + `54`), all the config (MongoDB, scripts, lookups) being outside `/data` is fully preserved. Header backed up encrypted out-of-band (SMB `/SIEM/luks/`), backup passphrase in the vault, TPM2 auto-unlock. | Protects the data at rest against disk theft / disposal / RMA / theft of the powered-off server. | A.8.24 / A.5.33 |

*Known limitations (hardening backlog): ESET/vSphere/FortiGate syslog flows in clear text on the isolated SIEM VLAN (syslog-over-TLS migration to be studied); advanced SOAR (host isolation / account disabling) pending the NinjaOne API; TPM in the PCR SHA-1 bank (enable the SHA-256 bank in the BIOS to harden the sealing — non-blocking).*
