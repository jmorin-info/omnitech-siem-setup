# Dossier documentaire SIEM OMNITECH — Index

**Première visite : [Commencer avec OMNI SIEM](DEMARRER.md).** Choisir d'abord
installation neuve, mise à jour ou ajout d'une source. Les documents ISO et
les références de l'installation historique figurent plus bas.

## Parcours installation et maintenance

- [Interface d'administration dans le terminal SSH](INTERFACE-ADMINISTRATION.md)
- [Installation neuve et périmètre des composants](INSTALLATION.md)
- [Ubuntu : installation ligne par ligne et essai Ubuntu 26.04](UBUNTU-DEMARRAGE.md)
- [Qualification Ubuntu 26.04 sur VM isolée et rapports](QUALIFICATION-UBUNTU2604.md)
- [Mises à jour, conservation de la configuration et retour arrière](UPDATES.md)
- [Modules WatchGuard, UniFi et Palo Alto](INTEGRATIONS-MODULAIRES.md)
- [Console `/soc/` : déploiement et diagnostic 404/502](CONSOLE-DEPLOIEMENT.md)
- [Audit de portabilité daté](AUDIT-PORTABILITE-2026-11-19.md)

| Réf | Document | Type ISO | Objet |
|---|---|---|---|
| POL | [securite-conformite/POL-SUPERVISION-JOURNALISATION.md](securite-conformite/POL-SUPERVISION-JOURNALISATION.md) | **Politique** | Engagements, périmètre, responsabilités, rétention — validée DSI |
| STD | [securite-conformite/STD-JOURNALISATION.md](securite-conformite/STD-JOURNALISATION.md) | **Standard** | Règles techniques : sources, transport, champs, seuils, conventions |
| PRO | [securite-conformite/PRO-EXPLOITATION-SIEM.md](securite-conformite/PRO-EXPLOITATION-SIEM.md) | **Procédure** | Exploitation au quotidien : revues, triage, enrôlement, relances |
| DOS | [architecture/DOSSIER-ARCHITECTURE-SIEM.md](architecture/DOSSIER-ARCHITECTURE-SIEM.md) | **Dossier d'exploitation** | Architecture, composants, flux, MEP, secrets, sauvegarde |
| REG | [securite-conformite/REGISTRE-CONFORMITE-ISO27001.md](securite-conformite/REGISTRE-CONFORMITE-ISO27001.md) | **Registre de conformité** | Mapping Annexe A ↔ preuves, actions ouvertes, méthode auditeur |
| PRA | [exploitation/PRA-RECONSTRUCTION-SIEM.md](exploitation/PRA-RECONSTRUCTION-SIEM.md) | **Plan de continuité** | Reconstruction sur nouveau serveur : RTO/RPO, scénarios, validation |
| — | [sources/LDAPS.md](sources/LDAPS.md) | Procédure | Authentification AD (LDAPS) sur la console Graylog |
| — | [exploitation/REPONSE-AUTOMATISEE.md](exploitation/REPONSE-AUTOMATISEE.md) | Procédure | Compte canari AD + SOAR (détection avancée & réponse auto) |
| — | [exploitation/GUIDE-DEPANNAGE.md](exploitation/GUIDE-DEPANNAGE.md) | Exploitation | Dépannage : symptôme → cause → solution |
| — | [demarrage/SYNTHESE-EXECUTIVE.md](demarrage/SYNTHESE-EXECUTIVE.md) | Direction | Synthèse 1 page pour la DSI / comité |
| — | [reference/GLOSSAIRE.md](reference/GLOSSAIRE.md) | Référence | Termes techniques pour lecteurs non spécialistes |
| — | [../CHANGELOG.md](../CHANGELOG.md) | Référence | Journal des évolutions daté |
| — | [CONSOLE-SOC.md](CONSOLE-SOC.md) | Exploitation | Console SOC : vues, bande « À traiter », SOAR et déblocage, page Exploitation |
| — | [exploitation/SOAR-PLAYBOOKS.md](exploitation/SOAR-PLAYBOOKS.md) | Procédure | Réponse automatisée, garde-fous et déblocage |

## Documents support SMSI / opérationnels (mêmes dossier `docs/`)

> Documents factuels complémentaires, support à l'audit ISO et à l'exploitation.
> Les anciens liens vers [INDEX-DOCUMENTATION.md](INDEX-DOCUMENTATION.md) redirigent vers cet index unique.

| Document | Objet |
|---|---|
| [securite-conformite/ISO27001-MAPPING.md](securite-conformite/ISO27001-MAPPING.md) | Document-pont : capacités SIEM ↔ contrôles Annexe A + preuves |
| [detection/REGISTRE-DETECTIONS.md](detection/REGISTRE-DETECTIONS.md) | Catalogue des règles de détection actives (alertes Graylog) |
| [sources/INVENTAIRE-SOURCES.md](sources/INVENTAIRE-SOURCES.md) | Inventaire des sources/actifs supervisés (AD/Sysmon, FortiGate, M365, vSphere, Veeam, ESET, BunkerWeb, NPS) |
| [sources/INTEGRATION-SOURCES.md](sources/INTEGRATION-SOURCES.md) | Procédure d'intégration des nouvelles sources (ESET PROTECT, NPS, BunkerWeb WAF) |
| [securite-conformite/POLITIQUE-RETENTION.md](securite-conformite/POLITIQUE-RETENTION.md) | Politique de rétention différenciée par source (preuve A.8.15) |
| [exploitation/PROCEDURE-INCIDENT.md](exploitation/PROCEDURE-INCIDENT.md) | Détection → évaluation → réponse → clôture des incidents |
| [exploitation/PROCEDURE-EXPLOITATION-SIEM.md](exploitation/PROCEDURE-EXPLOITATION-SIEM.md) | Exploitation courante, maintenance, contrôle du bon fonctionnement |
| [detection/COUVERTURE-MITRE-ATTACK.md](detection/COUVERTURE-MITRE-ATTACK.md) | Carte de couverture MITRE ATT&CK (+ calque `mitre-navigator-layer.json`) + plan de validation purple-team |
| [exploitation/SOAR-PLAYBOOKS.md](exploitation/SOAR-PLAYBOOKS.md) | Réponse automatisée (SOAR) : catalogue de playbooks PB-01→05, garde-fous |
| [securite-conformite/PROCEDURE-INTEGRITE-PREUVE.md](securite-conformite/PROCEDURE-INTEGRITE-PREUVE.md) | Intégrité & valeur probante des journaux (registre haché-signé) + forensique (A.8.15/5.28) |
| [securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md](securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md) | Chiffrement des données au repos `/data` (LUKS2 + TPM2) (A.8.24/5.33) |
| [archives/AUDIT-DASHBOARD-2026-06-14.md](archives/AUDIT-DASHBOARD-2026-06-14.md) | Audit senior-SoC des dashboards + plan d'amélioration (suivi des lots) |

## Documents techniques associés (racine `~/omnitech-siem-setup/`)

| Document | Objet |
|---|---|
| `docs/demarrage/GUIDE.md` | « Comprendre le SIEM en 15 min » : schéma de flux, rôle des pages, analyses expliquées |
| `docs/reference/CONTEXT.md` | Mémoire technique complète : historique, pièges connus (API 7.x), incidents résolus |
| `docs/exploitation/RESTORE.md` | Restauration complète du SIEM depuis une sauvegarde config |
| `README.fr.md` § Exploitation courante | Mises à jour automatiques (`oms-maj-siem`), snapshots sélectifs (`oms-snap-siem`), SOAR et déblocage d'une IP, synchronisation `deploye/` |
| `docs/sources/VEEAM.md` | Intégration Veeam Backup & Replication |
| `docs/sources/VSPHERE.md` | Intégration ESXi / vCenter |
| `windows/README-WINDOWS.md` | Volet Windows/AD : agents, GPO, NinjaOne |
| `fortigate/0*.conf` | Configurations FortiGate (UTM, VPN, proxy, policies) |

## Documentation de présentation en anglais

Pour un lecteur extérieur, la même plateforme est décrite en anglais par [00-INDEX.en.md](00-INDEX.en.md) : [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md), [DATA-SOURCES.md](DATA-SOURCES.md), [detection/DETECTIONS.md](detection/DETECTIONS.md), [ALERTING-AND-TRIAGE.md](ALERTING-AND-TRIAGE.md), [OPERATIONS.md](OPERATIONS.md) et [DEPLOYMENT.md](DEPLOYMENT.md). Les documents français ci-dessus restent la référence pour l'audit.

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
