# Evidence file — ISO/IEC 27001:2022 audit (generated on 2026-07-02)

Document **generated automatically** from the SIEM/XDR platform in production
(`68-iso-evidence.sh`). **Dated and reproducible** evidence for Stage 2 (Nov. 2026).
Each section references the Annex A control(s) it attests.

## A.8.15 — Logging (centralized and tamper-proof collection)
- Active OMNI streams: **16**. OpenSearch cluster: **green**. Indexing failures: **23**.
- Sources emitting over 24 h: fortigate(14693860), windows_security(5791474), sysmon(5380797), windows(1392892), vsphere(1101882), m365(311393), bunkerweb(214370), vaultwarden(55265), inventory(32946), forti_dhcp(19743), vuln(2004), ueba_score(1446), alert_triage(944), fortimanager(857), aruba(842), ml_anomaly(720), veeam(561), ndr_scan(316), dns(277), collecte_sla(185)
- Tiered retention documented (`docs/POLITIQUE-RETENTION.md`); integrity via HMAC chain (`omni-integrity`, `docs/PROCEDURE-INTEGRITE-PREUVE.md`).

## A.8.16 — Monitoring activities
- Active event definitions (detections): **145**.
- Distinct detection tags: **127**, mapped to MITRE ATT&CK.
- Detection volume: **96397** over 7 d, **96402** over 30 d.
- Correlated incidents (oms-xdr) over 30 d: **54**.
- Real-time dashboard "OMNI - SOC" + "OMS-XDR" page; behavioral UEBA/NDR.

## A.5.7 — Threat intelligence
- MITRE ATT&CK coverage: **74 techniques** across **19 tactics** (layer `docs/mitre-navigator-layer.json`).
- Threat intel IOC (abuse.ch, daily refresh): **5 C2 IPs** (Feodo), **2205 malicious domains** (URLhaus); + Tor/Spamhaus, CISA KEV.

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
