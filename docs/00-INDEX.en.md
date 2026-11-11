# OMNI SIEM — Documentation

Complete documentation for the OMNI SIEM / SOC platform. Start with the
[project README](../README.md) for the high-level tour, then use the map below.

## Core documentation (English)

| # | Document | What it covers |
|---|---|---|
| 1 | [ARCHITECTURE.md](ARCHITECTURE.md) | Components, data flow, storage, services, network |
| 2 | [DATA-SOURCES.md](DATA-SOURCES.md) | Every log source, transport, normalised schema |
| 3 | [DETECTIONS.md](DETECTIONS.md) | Detection engine, MITRE ATT&CK coverage, pipeline enrichment |
| 4 | [ALERTING-AND-TRIAGE.md](ALERTING-AND-TRIAGE.md) | Triage service, scoring, LLM judge, notifications, SOAR |
| 5 | [OPERATIONS.md](OPERATIONS.md) | Backups, retention, watchdog, health, day-to-day runbook |
| 6 | [DEPLOYMENT.md](DEPLOYMENT.md) | Prerequisites, provisioning scripts, rebuild procedure |

## Screenshots

- `captures/graylog/` — live captures of the Graylog web UI (dashboards, inputs, pipelines).
- `captures/` — the bespoke SOC console and mobile PWA.

## Reference documentation (original, French)

The platform's detailed operational and compliance documentation is retained verbatim for
traceability. It is authoritative for audit purposes.

**Architecture &amp; sources**
- [DOSSIER-ARCHITECTURE-SIEM.md](DOSSIER-ARCHITECTURE-SIEM.md) — full architecture dossier
- [INTEGRATION-SOURCES.md](INTEGRATION-SOURCES.md) · [INVENTAIRE-SOURCES.md](INVENTAIRE-SOURCES.md) — source integration &amp; inventory
- [../CONTEXT.md](../CONTEXT.md) — project context &amp; history

**Detection &amp; response**
- [REGISTRE-DETECTIONS.md](REGISTRE-DETECTIONS.md) — detection registry
- [COUVERTURE-MITRE-ATTACK.md](COUVERTURE-MITRE-ATTACK.md) — ATT&CK coverage
- [REPONSE-AUTOMATISEE.md](REPONSE-AUTOMATISEE.md) · [SOAR-PLAYBOOKS.md](SOAR-PLAYBOOKS.md) — automated response &amp; playbooks
- [CONSOLE-SOC.md](CONSOLE-SOC.md) — SOC console
- [DECEPTION-PLAN.md](DECEPTION-PLAN.md) — deception / honeytokens

**Operations &amp; resilience**
- [PROCEDURE-EXPLOITATION-SIEM.md](PROCEDURE-EXPLOITATION-SIEM.md) · [PRO-EXPLOITATION-SIEM.md](PRO-EXPLOITATION-SIEM.md) — operations
- [PROCEDURE-INCIDENT.md](PROCEDURE-INCIDENT.md) — incident response
- [PRA-RECONSTRUCTION-SIEM.md](PRA-RECONSTRUCTION-SIEM.md) — disaster recovery / rebuild
- [POLITIQUE-RETENTION.md](POLITIQUE-RETENTION.md) — retention policy
- [GUIDE-DEPANNAGE.md](GUIDE-DEPANNAGE.md) — troubleshooting
- [PROCEDURE-CHIFFREMENT-REPOS.md](PROCEDURE-CHIFFREMENT-REPOS.md) — volume encryption
- [../RESTORE.md](../RESTORE.md) — restore procedure

**Compliance &amp; governance (ISO/IEC 27001)**
- [ISO27001-MAPPING.md](ISO27001-MAPPING.md) · [REGISTRE-CONFORMITE-ISO27001.md](REGISTRE-CONFORMITE-ISO27001.md) — control mapping &amp; register
- [ISO27001-preuves.md](ISO27001-preuves.md) — evidence
- [STD-JOURNALISATION.md](STD-JOURNALISATION.md) · [POL-SUPERVISION-JOURNALISATION.md](POL-SUPERVISION-JOURNALISATION.md) — logging standard &amp; policy
- [PROCEDURE-INTEGRITE-PREUVE.md](PROCEDURE-INTEGRITE-PREUVE.md) — evidence integrity
- [REGISTRE-AMELIORATION-CONTINUE.md](REGISTRE-AMELIORATION-CONTINUE.md) — continuous-improvement register
- `EVIDENCE-AUDIT-*.md` — dated audit evidence packs

**Source-specific integration notes**
- [../VEEAM.md](../VEEAM.md) · [../M365.md](../M365.md) · [../VSPHERE.md](../VSPHERE.md) · [../FORTIANALYZER.md](../FORTIANALYZER.md) · [ENTRA-SETUP.md](ENTRA-SETUP.md) · [LDAPS.md](LDAPS.md)

**Governance &amp; misc**
- [SYNTHESE-EXECUTIVE.md](SYNTHESE-EXECUTIVE.md) — executive summary
- [GLOSSAIRE.md](GLOSSAIRE.md) — glossary
- [CHANGELOG.md](CHANGELOG.md) — change log
- [MDR-CO-MANAGE-CHIFFRAGE-2026-06-18.md](MDR-CO-MANAGE-CHIFFRAGE-2026-06-18.md) — co-managed MDR costing
