# Evidence dossier — ISO/IEC 27001:2022 audit (generated on 2026-08-01)

Document **automatically generated** from the production SIEM/XDR platform
(`68-iso-evidence.sh`). **Dated and reproducible** evidence for Stage 2 (Nov. 2026).
Each section references the Annex A control(s) it attests.

## A.8.15 — Logging (centralized and tamper-proof collection)
- Active OMNI streams: **19**. OpenSearch cluster: **green**. Indexing failures: **23**.
- Sources emitting over 24 h: fortigate(10561878), sysmon(5817992), windows_security(5725726), windows(1065212), vsphere(966111), bunkerweb(164202), m365(87133), vaultwarden(55142), ueba_score(16450), forti_dhcp(13619), seal(12853), ueba_geo(1905), alert_triage(1356), ml_anomaly(720), fortimanager(699), aruba(626), collecte_sla(519), inventory(312), veeam(159), vuln(149)
- Tiered retention documented (`docs/POLITIQUE-RETENTION.md`); integrity via HMAC chain (`omni-integrity`, `docs/PROCEDURE-INTEGRITE-PREUVE.md`).

## A.8.16 — Monitoring activities
- Active event definitions (detections): **197**.
- Distinct detection tags: **134**, mapped to MITRE ATT&CK.
- Detection volume: **154448** over 7 d, **575771** over 30 d.
- Correlated incidents (oms-xdr) over 30 d: **1111**.
- Real-time "OMNI - SOC" dashboard + "OMS-XDR" page; behavioral UEBA/NDR.

## A.5.7 — Threat intelligence
- MITRE ATT&CK coverage: **77 techniques** across **19 tactics** (layer `docs/mitre-navigator-layer.json`).
- IOC threat intel (abuse.ch, daily refresh): **5 C2 IPs** (Feodo), **2137 malicious domains** (URLhaus); + Tor/Spamhaus, CISA KEV.

## A.5.24 / A.5.25 / A.5.26 — Incident management, assessment and response
- Kill-chain correlation (oms-xdr) + risk scoring (MITRE + UEBA 0-100).
- Response: SOAR-light (IP blocking via FortiGate feed, no creds); ESET/AD actuators in dry-run (human-in-the-loop); 2-tier notification + **PWA mobile app** (alerts/push, VPN-only).
- Procedures: `docs/PROCEDURE-INCIDENT.md`, `docs/REPONSE-AUTOMATISEE.md`.

## A.8.32 — Change management / A.5.37 — Operating procedures
- All provisioning under Git (private repository); idempotent scripts; procedures `docs/PRO-EXPLOITATION-SIEM.md`.
- **Clause 10**: dated & verified continual improvement register — `docs/REGISTRE-AMELIORATION-CONTINUE.md`.

## A.8.13 — Backup / A.8.8 — Vulnerabilities
- Daily encrypted config backup + NAS export (`30-backup-config.sh`), DRP `docs/PRA-RECONSTRUCTION-SIEM.md`.
- Vulnerabilities: CISA KEV correlation + patch age (`38-vuln-scan.sh`).

---
*Continuous supervision services active: active
active. To regenerate: `bash 68-iso-evidence.sh`.*
