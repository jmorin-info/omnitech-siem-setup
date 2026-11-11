# Evidence file — ISO/IEC 27001:2022 audit (generated on 2026-06-18)

Document **generated automatically** from the SIEM/XDR platform in production
(`68-iso-evidence.sh`). **Dated and reproducible** evidence for Stage 2 (Nov. 2026).
Each section references the Annex A control(s) it attests.

## A.8.15 — Logging (centralized and tamper-proof collection)
- Active OMNI streams: **11**. OpenSearch cluster: **green**. Indexing failures: **20**.
- Sources emitting over 24 h: fortigate(12126308), windows_security(4731742), sysmon(4549619), windows(1183827), vsphere(955081), bunkerweb(96579), m365(71688), vaultwarden(55865), inventory(30384), forti_dhcp(19164), veeam(415), eset(85), cert_parc(56), adcs(30), xdr_incident(7), siem_integrity(1)
- Tiered retention documented (`docs/POLITIQUE-RETENTION.md`); integrity via HMAC chain (`omni-integrity`, `docs/PROCEDURE-INTEGRITE-PREUVE.md`).

## A.8.16 — Monitoring activities
- Active event definitions (detections): **101**.
- Distinct detection tags: **69**, mapped to MITRE ATT&CK.
- Detection volume: **38800** over 7 d, **38800** over 30 d.
- Correlated incidents (oms-xdr) over 30 d: **7**.
- Real-time dashboard "OMNI - SOC" + "OMS-XDR" page; behavioral UEBA/NDR.

## A.5.7 — Threat intelligence
- MITRE ATT&CK coverage: **48 techniques** across **12 tactics** (layer `docs/mitre-navigator-layer.json`).
- Threat intel IOC (abuse.ch, daily refresh): **5 C2 IPs** (Feodo), **2504 malicious domains** (URLhaus); + Tor/Spamhaus, CISA KEV.

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
