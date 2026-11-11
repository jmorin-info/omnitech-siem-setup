# Evidence dossier — ISO/IEC 27001:2022 audit (generated on 2026-07-01)

Document **automatically generated** from the production SIEM/XDR platform
(`68-iso-evidence.sh`). **Dated and reproducible** evidence for Stage 2 (Nov. 2026).
Each section references the Annex A control(s) it attests to.

## A.8.15 — Logging (centralized and tamper-proof collection)
- Active OMNI streams: **15**. OpenSearch cluster: **green**. Indexing failures: **23**.
- Sources emitting over 24 h: fortigate(14988105), sysmon(5745601), windows_security(5623461), windows(2092426), vsphere(1046928), bunkerweb(232895), m365(114762), vaultwarden(55388), inventory(32766), forti_dhcp(18896), vuln(1035), alert_triage(793), aruba(761), ml_anomaly(720), fortimanager(578), dns(522), ndr_scan(490), veeam(417), siem_health(145), ndr_exfil(95)
- Tiered retention documented (`docs/POLITIQUE-RETENTION.md`); integrity via HMAC chain (`omni-integrity`, `docs/PROCEDURE-INTEGRITE-PREUVE.md`).

## A.8.16 — Monitoring of activities
- Active event definitions (detections): **142**.
- Distinct detection tags: **127**, mapped to MITRE ATT&CK.
- Detection volume: **42125** over 7 d, **42125** over 30 d.
- Correlated incidents (oms-xdr) over 30 d: **31**.
- Real-time "OMNI - SOC" dashboard + "OMS-XDR" page; behavioral UEBA/NDR.

## A.5.7 — Threat intelligence
- MITRE ATT&CK coverage: **74 techniques** across **19 tactics** (`docs/mitre-navigator-layer.json` layer).
- Threat intel IOC (abuse.ch, daily refresh): **5 C2 IPs** (Feodo), **2185 malicious domains** (URLhaus); + Tor/Spamhaus, CISA KEV.

## A.5.24 / A.5.25 / A.5.26 — Incident management, assessment and response
- Kill-chain correlation (oms-xdr) + risk scoring (MITRE + UEBA 0-100).
- Response: SOAR-light (IP blocking via FortiGate feed, no creds); ESET/AD actuators in dry-run (human-in-the-loop); 2-tier notification + **PWA mobile app** (alerts/push, VPN-only).
- Procedures: `docs/PROCEDURE-INCIDENT.md`, `docs/REPONSE-AUTOMATISEE.md`.

## A.8.32 — Change management / A.5.37 — Operating procedures
- All provisioning under Git (private repo); idempotent scripts; procedures `docs/PRO-EXPLOITATION-SIEM.md`.
- **Clause 10**: dated & verified continual improvement register — `docs/REGISTRE-AMELIORATION-CONTINUE.md`.

## A.8.13 — Backup / A.8.8 — Vulnerabilities
- Daily encrypted config backup + NAS export (`30-backup-config.sh`), DRP `docs/PRA-RECONSTRUCTION-SIEM.md`.
- Vulnerabilities: CISA KEV correlation + patch age (`38-vuln-scan.sh`).

---
*Active continuous monitoring services: active
active. To regenerate: `bash 68-iso-evidence.sh`.*
