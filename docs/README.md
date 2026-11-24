# Documentation OMNI SIEM

Index unique de la documentation du dépôt. Il remplace les anciens index
(`00-INDEX.md`, `DEMARRER.md`, `INDEX-DOCUMENTATION.md`), conservés sous forme
de redirections lorsque des liens externes y pointent encore.

La documentation est organisée **par parcours** ci-dessous, puis
[par dossier](#organisation-des-dossiers). Le français est la langue de
référence (voir la [politique linguistique](#politique-linguistique)).

Les documents décrivent l'installation de référence d'OMNITECH SECURITY avec
ses extensions. Une installation neuve n'active que le socle : le périmètre
exact figure dans [INSTALLATION.md](INSTALLATION.md).

## Découvrir

| Document | Objet |
|---|---|
| [README du dépôt](../README.fr.md) | Présentation, capacités en service, architecture, limites |
| [Comprendre le SIEM en 15 minutes](demarrage/GUIDE.md) | Explication en langage simple des flux, des écrans et des analyses |
| [Aperçu visuel](demarrage/APERCU-VISUEL.md) | Captures de la console SOC, de la PWA et des tableaux de bord Graylog |
| [Synthèse exécutive](demarrage/SYNTHESE-EXECUTIVE.md) | Une page pour la direction (rédigée le 12/06/2026) |
| [Architecture](architecture/ARCHITECTURE.md) | Composants, flux et choix techniques (en anglais) |
| [Dossier d'architecture et d'exploitation](architecture/DOSSIER-ARCHITECTURE-SIEM.md) | Document « DOS » du corpus ISO : composants, flux, mise en production, sauvegarde |
| [Sources de données](DATA-SOURCES.md) | Sources collectées, transports et champs (en anglais) |
| [Feuille de route](ROADMAP.md) | Axes d'amélioration, état fait / en cours / à faire |
| [Glossaire](reference/GLOSSAIRE.md) | Termes techniques pour lecteurs non spécialistes |

## Installer

| Document | Objet |
|---|---|
| [Installation et périmètre du socle](INSTALLATION.md) | Prérequis, phases, composants installés, contrôles de réception |
| [Installation Ubuntu ligne par ligne](UBUNTU-DEMARRAGE.md) | Parcours pas à pas sur une machine neuve |
| [Qualification Ubuntu 26.04](QUALIFICATION-UBUNTU2604.md) | Recette sur VM isolée et rapports |
| [Déploiement](DEPLOYMENT.md) | Vue d'ensemble installation, mises à jour, reprise |
| [Interface d'administration SSH](INTERFACE-ADMINISTRATION.md) | Gestionnaire en terminal : configuration, installation, modules |
| [Console SOC : déploiement et diagnostic](CONSOLE-DEPLOIEMENT.md) | Publication de `/soc/`, erreurs 404 et 502 |
| [Console SOC : pages et widgets](CONSOLE-MODULES.md) | Pages adaptées aux streams du site, droits, nouvelles machines et conservation des réglages |
| [Modules WatchGuard, UniFi, Palo Alto](INTEGRATIONS-MODULAIRES.md) | Content Packs, tableaux de bord, limites de formats |
| [Gabarit des secrets](securite-conformite/SECRETS.example.md) | Liste des secrets à définir localement (jamais versionnés) |
| [Scripts de provisioning](reference/SCRIPTS-PROVISIONING.md) | Rôle, statut et dépendances des scripts numérotés |

## Exploiter au quotidien

| Document | Objet |
|---|---|
| [Guide d'exploitation de l'installation de référence](exploitation/GUIDE-EXPLOITATION.md) | Configuration, enrôlement des hôtes, Fortinet, TLS, validation, sauvegardes, dépannage, supervision |
| [Utiliser la console SOC](CONSOLE-SOC.md) | Vues, file « À traiter », SOAR et déblocage |
| [Procédure d'exploitation](exploitation/PROCEDURE-EXPLOITATION-SIEM.md) | Contrôles quotidiens et périodiques, maintenance, capacité |
| [Exploitation et résilience](OPERATIONS.md) | Robots, supervision, sauvegardes (en anglais) |
| [Alerting et triage](ALERTING-AND-TRIAGE.md) | Chaîne de notification et triage des alertes (en anglais) |
| [Guide de dépannage](exploitation/GUIDE-DEPANNAGE.md) | Symptôme, cause, solution |
| [Intégration de nouvelles sources](sources/INTEGRATION-SOURCES.md) | ESET PROTECT, NPS, BunkerWeb |
| [Inventaire des sources](sources/INVENTAIRE-SOURCES.md) | Sources surveillées, volumes, criticité |
| Intégrations par source | [FortiAnalyzer](sources/FORTIANALYZER.md), [Microsoft 365](sources/M365.md), [Entra ID](sources/ENTRA-SETUP.md), [vSphere](sources/VSPHERE.md), [Veeam](sources/VEEAM.md), [LDAPS](sources/LDAPS.md), [Windows et AD](../windows/README-WINDOWS.md), [SEAL](../seal/README.md) |

## Réagir à un incident

| Document | Objet |
|---|---|
| [Procédure de gestion des incidents](exploitation/PROCEDURE-INCIDENT.md) | Détection, évaluation, réponse, clôture |
| [Playbooks SOAR](exploitation/SOAR-PLAYBOOKS.md) | Réponse automatisée, garde-fous, déblocage |
| [Indicateurs SOC](exploitation/INDICATEURS-SOC.md) | Volume d'alertes, MTTD, MTTR, faux positifs, couverture ATT&CK : définitions, outil, page de la console, lacunes |
| [Détection avancée et réponse automatisée](exploitation/REPONSE-AUTOMATISEE.md) | Compte canari AD et SOAR |
| [Restauration depuis une sauvegarde](exploitation/RESTORE.md) | Restauration complète de la configuration |
| [Plan de reconstruction (PRA)](exploitation/PRA-RECONSTRUCTION-SIEM.md) | RTO/RPO, scénarios, validation, journal des tests |
| [Restauration complète chronométrée](exploitation/RESTAURATION-COMPLETE.md) | Couverture des sauvegardes, intrants mesurés, objectifs RTO/RPO, exercice sur VM isolée |
| [Intégrité et valeur probante des journaux](securite-conformite/PROCEDURE-INTEGRITE-PREUVE.md) | Registre chaîné, conservation des preuves |
| [Incident du 21/11/2026 : tests de la console en production](archives/INCIDENT-CONSOLE-2026-11-21.md) | Indisponibilité du backend, restauration, message de test conservé dans Graylog |

## Mettre à jour

| Document | Objet |
|---|---|
| [Mises à jour du code](UPDATES.md) | Révision figée, préparation, sauvegarde, retour arrière |
| [Journal des modifications](../CHANGELOG.md) | Évolutions datées du dépôt et de la plateforme |
| [Scripts ponctuels](../tools/ponctuel/README.md) | Correctifs et migrations datés, conservés pour traçabilité |
| [Contribuer](../CONTRIBUTING.md) | Conventions de développement, tests, commits |

## Conformité ISO 27001

Corpus documentaire du SMSI pour le périmètre SIEM (référentiel ISO/IEC
27001:2022, Annexe A).

| Réf. | Document | Type | Objet |
|---|---|---|---|
| POL | [Politique de supervision et de journalisation](securite-conformite/POL-SUPERVISION-JOURNALISATION.md) | Politique | Engagements, périmètre, responsabilités, rétention |
| STD | [Standard technique de journalisation](securite-conformite/STD-JOURNALISATION.md) | Standard | Sources, transport, champs, seuils, conventions |
| PRO | [Procédure d'exploitation du SIEM](securite-conformite/PRO-EXPLOITATION-SIEM.md) | Procédure | Traitement des alertes, classification, escalade, RACI |
| DOS | [Dossier d'architecture](architecture/DOSSIER-ARCHITECTURE-SIEM.md) | Dossier | Architecture, composants, flux, secrets, sauvegarde |
| REG | [Registre de conformité](securite-conformite/REGISTRE-CONFORMITE-ISO27001.md) | Registre | Correspondance Annexe A et preuves, actions ouvertes |
| PRA | [Plan de reconstruction](exploitation/PRA-RECONSTRUCTION-SIEM.md) | Continuité | Reconstruction sur nouveau serveur |
| — | [Registre d'amélioration continue](securite-conformite/REGISTRE-AMELIORATION-CONTINUE.md) | Registre | Clause 10 : améliorations datées et vérifiées |
| — | [Registre des détections](detection/REGISTRE-DETECTIONS.md) | Registre | Catalogue des règles de détection |
| — | [Cartographie SIEM et Annexe A](securite-conformite/ISO27001-MAPPING.md) | Référence | Capacités du SIEM rapprochées des mesures |
| — | [Production des preuves](securite-conformite/ISO27001-preuves.md) | Procédure | Commandes et méthode de production des preuves |
| — | [Politique de rétention](securite-conformite/POLITIQUE-RETENTION.md) | Politique | Rétention différenciée par source |
| — | [Chiffrement des données au repos](securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md) | Procédure | `/data` en LUKS2 et TPM2 |
| — | [Auto-évaluation initiale](securite-conformite/ISO27001.md) | Évaluation | État et écarts au 11/06/2026 ; l'état courant est dans le registre de conformité |
| — | [Dossiers de preuves mensuels](archives/preuves-iso/) | Preuves | Générés par `68-iso-evidence.sh` |

## Détection

| Document | Objet |
|---|---|
| [Moteur de détection](detection/DETECTIONS.md) | Fonctionnement des détections (en anglais) |
| [Couverture MITRE ATT&CK](detection/COUVERTURE-MITRE-ATTACK.md) | Carte de couverture, plan de validation par technique |
| [Backlog de détection](detection/DETECTION-BACKLOG.md) | Lacunes ATT&CK identifiées et propositions |
| [Validation continue des détections](detection/VALIDATION-DETECTIONS.md) | Contrôle hebdomadaire en lecture seule des définitions actives, fixtures, vivacité |
| [OMNI Sentinel](architecture/OMNI-SENTINEL.md) | Défense proactive : architecture et gouvernance |
| [Plan de leurres](detection/DECEPTION-PLAN.md) | Semis des honeytokens |
| [Calque ATT&CK Navigator](detection/mitre-navigator-layer.json) | Fichier généré par `57-mitre-coverage.sh` |

## Référence

| Document | Objet |
|---|---|
| [Scripts de provisioning](reference/SCRIPTS-PROVISIONING.md) | Inventaire, numéros en double, plan de renumérotation |
| [Glossaire](reference/GLOSSAIRE.md) | Définitions |
| [Audit de portabilité du 19/11/2026](AUDIT-PORTABILITE-2026-11-19.md) | Reproductibilité de l'installation (état daté) |
| [Sécurité du dépôt](../SECURITY.md) | Signalement de vulnérabilité, gestion des secrets |

Documentation des sous-projets : [oms-xdr](../oms-xdr/README.md),
[oms-ml](../oms-ml/README.md), [oms-graph](../oms-graph/README.md),
[SEAL](../seal/README.md), [modules d'intégration](../integrations/README.md),
[Docker](../docker/README-DOCKER.md), [Windows](../windows/README-WINDOWS.md).

## Organisation des dossiers

```
docs/
  README.md                index unique (ce document)
  ROADMAP.md               feuille de route
  *.md                     documents d'installation, de déploiement et de la console,
                           et documents cités par l'outillage (voir ci-dessous)
  demarrage/               découverte et synthèse
  architecture/            architecture et dossier d'exploitation
  exploitation/            procédures quotidiennes, incident, restauration, PRA
  securite-conformite/     corpus ISO 27001 (POL, STD, PRO, registres, preuves)
  sources/                 intégration par source de journaux
  detection/               détections, couverture ATT&CK, leurres
  reference/               inventaires et glossaire
  archives/                documents datés non maintenus
    preuves-iso/           dossiers de preuves mensuels
    en/                    traductions anglaises non maintenues
  captures/                captures d'écran
```

Certains documents restent à la racine de `docs/` parce que l'outillage ou
d'autres documents les citent par leur chemin : le gestionnaire SSH
(`manager/inventory.py`) référence `INSTALLATION.md`, `CONSOLE-DEPLOIEMENT.md`,
`INTEGRATIONS-MODULAIRES.md`, `UPDATES.md`, `ALERTING-AND-TRIAGE.md`,
`DATA-SOURCES.md`, `OPERATIONS.md`, `AUDIT-PORTABILITE-2026-11-19.md` et
`00-INDEX.md`. Les fichiers `00-INDEX.md`, `DEMARRER.md`,
`PRA-RECONSTRUCTION-SIEM.md` (dans `docs/`) et `RESTORE.md` (à la racine du
dépôt) sont de simples redirections.

## Archives

Le dossier [archives/](archives/README.md) conserve les documents datés :
audits, évaluations, chiffrages, revue critique, contexte technique de juin
2026, dossiers de preuves mensuels et traductions anglaises. Ils décrivent
l'état observé à leur date et ne sont pas mis à jour.

## Politique linguistique

- **Le français est la langue de référence** du dépôt : documentation,
  procédures, messages de commit, commentaires des nouveaux scripts.
- **L'anglais est maintenu pour** le `README.md` racine (vitrine du dépôt) et
  les documents de présentation rédigés directement en anglais :
  [ARCHITECTURE.md](architecture/ARCHITECTURE.md),
  [DATA-SOURCES.md](DATA-SOURCES.md), [DETECTIONS.md](detection/DETECTIONS.md),
  [ALERTING-AND-TRIAGE.md](ALERTING-AND-TRIAGE.md),
  [OPERATIONS.md](OPERATIONS.md), [DEPLOYMENT.md](DEPLOYMENT.md) et le guide
  anglais de la console ([CONSOLE-SOC.en.md](CONSOLE-SOC.en.md)).
- **Les traductions anglaises des documents français ne sont plus
  maintenues** : elles sont archivées dans [archives/en/](archives/en/README.md).
- Les sous-projets (`seal/`, `oms-*`, `docker/`, `windows/`) conservent leurs
  fichiers `*.en.md` ; en cas d'écart, la version française fait foi.
- Un document anglais maintenu qui diverge de la version française est mis à
  jour dans la même modification, ou signalé comme non maintenu.
