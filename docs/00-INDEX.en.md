# OMNI SIEM — Documentation

## Installation and maintenance

- [SSH terminal administration menus](INTERFACE-ADMINISTRATION.md)
- [Installation neuve et périmètre des composants](INSTALLATION.md)
- [Mises à jour, conservation de la configuration et retour arrière](UPDATES.md)
- [Modules WatchGuard, UniFi et Palo Alto](INTEGRATIONS-MODULAIRES.md)
- [Console `/soc/` : déploiement et diagnostic 404/502](CONSOLE-DEPLOIEMENT.md)
- [Audit de portabilité daté](AUDIT-PORTABILITE-2026-11-19.md)

Complete documentation for the OMNI SIEM / SOC platform. Start with the
[project README](../README.md) for the high-level tour, then use the map below.

## Core documentation (English)

| # | Document | What it covers |
|---|---|---|
| 1 | [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) | Components, data flow, storage, services, network |
| 2 | [DATA-SOURCES.md](DATA-SOURCES.md) | Every log source, transport, normalised schema |
| 3 | [detection/DETECTIONS.md](detection/DETECTIONS.md) | Detection engine, MITRE ATT&CK coverage, pipeline enrichment |
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
- [architecture/DOSSIER-ARCHITECTURE-SIEM.md](architecture/DOSSIER-ARCHITECTURE-SIEM.md) — full architecture dossier
- [sources/INTEGRATION-SOURCES.md](sources/INTEGRATION-SOURCES.md) · [sources/INVENTAIRE-SOURCES.md](sources/INVENTAIRE-SOURCES.md) — source integration &amp; inventory
- [reference/CONTEXT.md](reference/CONTEXT.md) — project context &amp; history

**Detection &amp; response**
- [detection/REGISTRE-DETECTIONS.md](detection/REGISTRE-DETECTIONS.md) — detection registry
- [detection/COUVERTURE-MITRE-ATTACK.md](detection/COUVERTURE-MITRE-ATTACK.md) — ATT&CK coverage
- [exploitation/REPONSE-AUTOMATISEE.md](exploitation/REPONSE-AUTOMATISEE.md) · [exploitation/SOAR-PLAYBOOKS.md](exploitation/SOAR-PLAYBOOKS.md) — automated response &amp; playbooks
- [CONSOLE-SOC.md](CONSOLE-SOC.md) — SOC console
- [detection/DECEPTION-PLAN.md](detection/DECEPTION-PLAN.md) — deception / honeytokens

**Operations &amp; resilience**
- [exploitation/PROCEDURE-EXPLOITATION-SIEM.md](exploitation/PROCEDURE-EXPLOITATION-SIEM.md) · [securite-conformite/PRO-EXPLOITATION-SIEM.md](securite-conformite/PRO-EXPLOITATION-SIEM.md) — operations
- [exploitation/PROCEDURE-INCIDENT.md](exploitation/PROCEDURE-INCIDENT.md) — incident response
- [exploitation/PRA-RECONSTRUCTION-SIEM.md](exploitation/PRA-RECONSTRUCTION-SIEM.md) — disaster recovery / rebuild
- [securite-conformite/POLITIQUE-RETENTION.md](securite-conformite/POLITIQUE-RETENTION.md) — retention policy
- [exploitation/GUIDE-DEPANNAGE.md](exploitation/GUIDE-DEPANNAGE.md) — troubleshooting
- [securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md](securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md) — volume encryption
- [exploitation/RESTORE.md](exploitation/RESTORE.md) — restore procedure
- [../README.md](../README.md) §11 — automatic updates (`oms-maj-siem`), selective snapshots, SOAR unblocking, common pitfalls

**Compliance &amp; governance (ISO/IEC 27001)**
- [securite-conformite/ISO27001-MAPPING.md](securite-conformite/ISO27001-MAPPING.md) · [securite-conformite/REGISTRE-CONFORMITE-ISO27001.md](securite-conformite/REGISTRE-CONFORMITE-ISO27001.md) — control mapping &amp; register
- [securite-conformite/ISO27001-preuves.md](securite-conformite/ISO27001-preuves.md) — evidence
- [securite-conformite/STD-JOURNALISATION.md](securite-conformite/STD-JOURNALISATION.md) · [securite-conformite/POL-SUPERVISION-JOURNALISATION.md](securite-conformite/POL-SUPERVISION-JOURNALISATION.md) — logging standard &amp; policy
- [securite-conformite/PROCEDURE-INTEGRITE-PREUVE.md](securite-conformite/PROCEDURE-INTEGRITE-PREUVE.md) — evidence integrity
- [securite-conformite/REGISTRE-AMELIORATION-CONTINUE.md](securite-conformite/REGISTRE-AMELIORATION-CONTINUE.md) — continuous-improvement register
- `EVIDENCE-AUDIT-*.md` — dated audit evidence packs

**Source-specific integration notes**
- [sources/VEEAM.md](sources/VEEAM.md) · [sources/M365.md](sources/M365.md) · [sources/VSPHERE.md](sources/VSPHERE.md) · [sources/FORTIANALYZER.md](sources/FORTIANALYZER.md) · [sources/ENTRA-SETUP.md](sources/ENTRA-SETUP.md) · [sources/LDAPS.md](sources/LDAPS.md)

**Governance &amp; misc**
- [demarrage/SYNTHESE-EXECUTIVE.md](demarrage/SYNTHESE-EXECUTIVE.md) — executive summary
- [reference/GLOSSAIRE.md](reference/GLOSSAIRE.md) — glossary
- [CHANGELOG.md](CHANGELOG.md) — change log
- [archives/MDR-CO-MANAGE-CHIFFRAGE-2026-06-18.md](archives/MDR-CO-MANAGE-CHIFFRAGE-2026-06-18.md) — co-managed MDR costing

## Recently updated (November 2026)

- [ALERTING-AND-TRIAGE.md](ALERTING-AND-TRIAGE.md) — noise control, hourly grouping, daily digest
- [detection/DETECTIONS.md](detection/DETECTIONS.md) — correlation layer v3
- [CONSOLE-SOC.en.md](CONSOLE-SOC.en.md) — "Action needed" band, SOAR unblock, operations page
- [SOAR-PLAYBOOKS.en.md](SOAR-PLAYBOOKS.en.md) — external threat feed and guardrails
- [CHANGELOG.en.md](CHANGELOG.en.md) — dated changes
