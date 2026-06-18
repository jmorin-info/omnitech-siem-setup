# Dossier documentaire SIEM OMNITECH — Index

| Réf | Document | Type ISO | Objet |
|---|---|---|---|
| POL | [POL-SUPERVISION-JOURNALISATION.md](POL-SUPERVISION-JOURNALISATION.md) | **Politique** | Engagements, périmètre, responsabilités, rétention — validée DSI |
| STD | [STD-JOURNALISATION.md](STD-JOURNALISATION.md) | **Standard** | Règles techniques : sources, transport, champs, seuils, conventions |
| PRO | [PRO-EXPLOITATION-SIEM.md](PRO-EXPLOITATION-SIEM.md) | **Procédure** | Exploitation au quotidien : revues, triage, enrôlement, relances |
| DOS | [DOSSIER-ARCHITECTURE-SIEM.md](DOSSIER-ARCHITECTURE-SIEM.md) | **Dossier d'exploitation** | Architecture, composants, flux, MEP, secrets, sauvegarde |
| REG | [REGISTRE-CONFORMITE-ISO27001.md](REGISTRE-CONFORMITE-ISO27001.md) | **Registre de conformité** | Mapping Annexe A ↔ preuves, actions ouvertes, méthode auditeur |
| PRA | [PRA-RECONSTRUCTION-SIEM.md](PRA-RECONSTRUCTION-SIEM.md) | **Plan de continuité** | Reconstruction sur nouveau serveur : RTO/RPO, scénarios, validation |
| — | [LDAPS.md](LDAPS.md) | Procédure | Authentification AD (LDAPS) sur la console Graylog |
| — | [REPONSE-AUTOMATISEE.md](REPONSE-AUTOMATISEE.md) | Procédure | Compte canari AD + SOAR (détection avancée & réponse auto) |
| — | [GUIDE-DEPANNAGE.md](GUIDE-DEPANNAGE.md) | Exploitation | Dépannage : symptôme → cause → solution |
| — | [SYNTHESE-EXECUTIVE.md](SYNTHESE-EXECUTIVE.md) | Direction | Synthèse 1 page pour la DSI / comité |
| — | [GLOSSAIRE.md](GLOSSAIRE.md) | Référence | Termes techniques pour lecteurs non spécialistes |
| — | [CHANGELOG.md](CHANGELOG.md) | Référence | Journal des évolutions daté |

## Documents support SMSI / opérationnels (mêmes dossier `docs/`)

> Documents factuels complémentaires, support à l'audit ISO et à l'exploitation.
> L'index alternatif [INDEX-DOCUMENTATION.md](INDEX-DOCUMENTATION.md) en donne une lecture par niveau (fonctionnel vs SMSI).

| Document | Objet |
|---|---|
| [ISO27001-MAPPING.md](ISO27001-MAPPING.md) | Document-pont : capacités SIEM ↔ contrôles Annexe A + preuves |
| [REGISTRE-DETECTIONS.md](REGISTRE-DETECTIONS.md) | Catalogue des règles de détection actives (alertes Graylog) |
| [INVENTAIRE-SOURCES.md](INVENTAIRE-SOURCES.md) | Inventaire des sources/actifs supervisés (AD/Sysmon, FortiGate, M365, vSphere, Veeam, ESET, BunkerWeb, NPS) |
| [INTEGRATION-SOURCES.md](INTEGRATION-SOURCES.md) | Procédure d'intégration des nouvelles sources (ESET PROTECT, NPS, BunkerWeb WAF) |
| [POLITIQUE-RETENTION.md](POLITIQUE-RETENTION.md) | Politique de rétention différenciée par source (preuve A.8.15) |
| [PROCEDURE-INCIDENT.md](PROCEDURE-INCIDENT.md) | Détection → évaluation → réponse → clôture des incidents |
| [PROCEDURE-EXPLOITATION-SIEM.md](PROCEDURE-EXPLOITATION-SIEM.md) | Exploitation courante, maintenance, contrôle du bon fonctionnement |
| [COUVERTURE-MITRE-ATTACK.md](COUVERTURE-MITRE-ATTACK.md) | Carte de couverture MITRE ATT&CK (+ calque `mitre-navigator-layer.json`) + plan de validation purple-team |
| [SOAR-PLAYBOOKS.md](SOAR-PLAYBOOKS.md) | Réponse automatisée (SOAR) : catalogue de playbooks PB-01→05, garde-fous |
| [PROCEDURE-INTEGRITE-PREUVE.md](PROCEDURE-INTEGRITE-PREUVE.md) | Intégrité & valeur probante des journaux (registre haché-signé) + forensique (A.8.15/5.28) |
| [PROCEDURE-CHIFFREMENT-REPOS.md](PROCEDURE-CHIFFREMENT-REPOS.md) | Chiffrement des données au repos `/data` (LUKS2 + TPM2) (A.8.24/5.33) |
| [AUDIT-DASHBOARD-2026-06-14.md](AUDIT-DASHBOARD-2026-06-14.md) | Audit senior-SoC des dashboards + plan d'amélioration (suivi des lots) |

## Documents techniques associés (racine `~/omnitech-siem-setup/`)

| Document | Objet |
|---|---|
| `GUIDE.md` | « Comprendre le SIEM en 15 min » : schéma de flux, rôle des pages, analyses expliquées |
| `CONTEXT.md` | Mémoire technique complète : historique, pièges connus (API 7.x), incidents résolus |
| `RESTORE.md` | Restauration complète du SIEM depuis une sauvegarde config |
| `VEEAM.md` | Intégration Veeam Backup & Replication |
| `VSPHERE.md` | Intégration ESXi / vCenter |
| `windows/README-WINDOWS.md` | Volet Windows/AD : agents, GPO, NinjaOne |
| `fortigate/0*.conf` | Configurations FortiGate (UTM, VPN, proxy, policies) |

## Correspondance ISO 27001:2022 (Annexe A)

| Mesure | Couverte par |
|---|---|
| 8.15 Journalisation | POL §3-4, STD §2-3 |
| 8.16 Activités de surveillance | POL §5, PRO §2-3, règles de détection (REGISTRE-DETECTIONS) + UEBA/NDR (DOS §6) |
| 5.25 Évaluation des événements de sécurité | PRO §3 (triage) |
| 8.13 Sauvegarde de l'information | POL §6, DOS §8, RESTORE.md |
| 5.33 Protection des enregistrements | POL §4 (rétention), STD §5 (intégrité) |
| 5.28 Collecte de preuves | POL §7 |
| 5.36 / 8.16 Revue régulière | Rapport hebdo (`34-weekly-report.sh`) |
| 8.13 / 5.30 Continuité | PRA-RECONSTRUCTION-SIEM, RESTORE.md |
| 5.26 Réponse aux incidents | REPONSE-AUTOMATISEE (canari + SOAR), PRO §6 |
| 8.9 Gestion de configuration | DOS (IaC scripts `10-*` → `54-*` + collecteurs `/usr/local/sbin/omni-*`) |
| (Vue complète Annexe A) | **REGISTRE-CONFORMITE-ISO27001** |

> Tout ce dossier est inclus dans la sauvegarde quotidienne chiffrée
> (`30-backup-config.sh` → `\\10.33.50.5\Public\SIEM`).

*Version 1.1 — Revue : 14/06/2026 — Rédaction : équipe IT (J. Morin) — Classification : interne*
