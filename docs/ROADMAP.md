# Feuille de route

Ce document décrit les axes d'amélioration de la plateforme et leur état
réel. Il part d'un constat partagé avec une revue externe du dépôt (novembre
2026) : la richesse fonctionnelle est importante ; le défi principal est
désormais de **démontrer** que la plateforme est fiable, testable,
maintenable et récupérable après incident, plutôt que d'ajouter des
fonctionnalités.

Chaque élément est classé :

- **Fait** : présent dans le dépôt ou constaté en production, avec sa référence ;
- **En cours** : amorcé mais incomplet, ou en observation ;
- **À faire** : non commencé.

État au 22/11/2026. Mettre à jour ce document à chaque livraison concernée
et consigner le changement dans le [journal des modifications](../CHANGELOG.md).

## 1. Validation continue des détections

Objectif : savoir ce que la plateforme détecte réellement, mesuré par
scénario (rappel, précision, faux positifs, délai de détection), et non par
nombre de règles.

| État | Élément | Référence |
|---|---|---|
| Fait | Tests hors ligne des dépendances de détection et des processeurs de pipeline | `tests/test_detection_dependencies.py`, `tests/test_pipeline_processors.py` |
| Fait | Test hors ligne du calcul de dérive des définitions d'événements | `tools/test-converge-diff.sh` |
| Fait | Tests unitaires des moteurs de corrélation, ML et graphe | `oms-xdr/tests`, `oms-ml/tests`, `oms-graph/tests` |
| Fait | Plan de validation par technique (test Atomic Red Team et `alert_tag` attendu pour onze techniques) | [COUVERTURE-MITRE-ATTACK.md](detection/COUVERTURE-MITRE-ATTACK.md) |
| Fait | Rejeu sur 30 jours des règles de la couche de corrélation v3 avant mise en production | [journal des modifications](../CHANGELOG.md), `tools/omni-v3/` |
| À faire | Jeux d'événements de référence versionnés par détection (positif attendu, négatif attendu) rejoués automatiquement contre les pipelines | |
| À faire | Exécution planifiée de scénarios contrôlés sur un poste de test et journal des campagnes (technique, détecté oui/non, délai) | |
| À faire | Mesure des faux négatifs du triage (alertes écartées qui auraient dû être remontées) et de la résistance aux contenus de journaux hostiles soumis à la couche LLM | |
| À faire | Fiche de détection versionnée (technique, prérequis de télémétrie, données de test, propriétaire) ; expression en Sigma lorsque pertinent | |

## 2. Industrialisation des déploiements

| État | Élément | Référence |
|---|---|---|
| Fait | Installation neuve par phases explicites, plan en lecture seule par défaut | `install.sh`, [INSTALLATION.md](INSTALLATION.md) |
| Fait | Intégration continue : suites hors ligne et inventaire de portabilité à chaque poussée | `.github/workflows/check.yml` |
| Fait | Recette d'installation sur VM Ubuntu 26.04 isolée (workflow dédié et script local) | `.github/workflows/ubuntu-vm.yml`, [QUALIFICATION-UBUNTU2604.md](QUALIFICATION-UBUNTU2604.md) |
| Fait | Blocage local des secrets et des mentions d'outillage avant commit | `scan-depot.sh --installer` |
| Fait | Mises à jour du code à révision figée, avec sauvegarde et retour arrière ; tests de l'outil | [UPDATES.md](UPDATES.md), `tests/test_updater.py` |
| Fait | Contrôle des liens internes de la documentation dans les tests | `tools/check-doc-links.py` |
| Fait | Analyse statique dans l'intégration continue : ShellCheck (scripts Bash), Ruff (Python) | `tools/ci-lint.sh`, `.github/workflows/check.yml` |
| Fait | Détection de secrets côté serveur (intégration continue), en complément du crochet local | `scan-depot.sh --arbre`, `.github/workflows/check.yml` |
| Fait | Tests de non-régression de la récupération Git (`git fetch`) de l'outil de mise à jour dans des conditions dégradées | `tests/test_updater_fetch.py` |
| À faire | Manifeste d'ordre d'exécution des scripts de provisioning et renumérotation par domaine | [SCRIPTS-PROVISIONING.md](reference/SCRIPTS-PROVISIONING.md#plan-de-renumérotation-et-de-regroupement-proposition-non-appliquée) |
| En cours | Migration vers un emplacement unique : outil et drop-ins disponibles, bascule des services de production encore à effectuer | `tools/migrer-chemin-canonique.sh`, [audit de cohérence](AUDIT-COHERENCE-2026-11-21.md) |

## 3. Réponse automatisée sûre

Principe : une action destructrice ou bloquante n'est jamais déclenchée par la
seule couche LLM ; les actions à fort impact passent par des seuils, un mode
simulation et une validation humaine.

| État | Élément | Référence |
|---|---|---|
| Fait | SOAR FortiGate : blocage déclenché par des détections à seuil (Graylog), durée limitée (24 h), exclusions fixes et dynamiques, déblocage outillé | [SOAR-PLAYBOOKS.md](exploitation/SOAR-PLAYBOOKS.md), `soar-v2/` |
| Fait | Mode simulation global (`SOAR_MODE`) et par détection (`SOAR_DETECTIONS_SIMULATION`), rejeu rétroactif des décisions | `soar-v2/omni-soar`, `soar-v2/omni-soar-simulation` |
| Fait | Le triage LLM décide de l'acheminement des notifications ; le blocage depuis un courriel passe par un lien signé, à durée limitée, cliqué par un analyste | `triage/omni-alert-triage` |
| Fait | Actionneurs `oms-xdr` (blocage, désactivation de compte, isolement) en recommandation par défaut, double verrou ; les actions non implémentées le signalent au lieu de simuler un succès | `oms-xdr/oms_xdr/responder.py` ; configuration en production : `dry_run: true` |
| Fait | Désactivation de compte AD outillée avec garde-fous, en simulation par défaut | `69-ad-response.sh` |
| En cours | Rétablir la couche LLM du triage, hors service au 21/11/2026 (appels à l'API refusés, repli par règles) | journal du service `omni-alert-triage` |
| En cours | Détection « balayage IKE » branchée sur le SOAR en observation uniquement | [journal des modifications](../CHANGELOG.md) (12/11/2026) |
| À faire | Seuils de confiance explicites par action et circuit d'approbation tracé (qui a validé, quand) pour les actions hors blocage d'IP | |
| À faire | Journal d'audit infalsifiable des actions de réponse, distinct des journaux applicatifs | |

## 4. Résilience et reprise (RTO/RPO)

| État | Élément | Référence |
|---|---|---|
| Fait | Objectifs formalisés : RTO de reprise de collecte ≤ 4 h, RPO configuration ≤ 24 h ; journaux non sauvegardés intégralement (choix assumé) | [PRA-RECONSTRUCTION-SIEM.md](exploitation/PRA-RECONSTRUCTION-SIEM.md) |
| Fait | Sauvegarde chiffrée quotidienne de la configuration, test de restaurabilité à chaque exécution, alerte en cas d'échec ou d'absence | `30-backup-config.sh` |
| Fait | Snapshots OpenSearch sélectifs quotidiens et test hebdomadaire de restauration dans un index temporaire | minuteries `oms-snap-siem` et `oms-snap-siem-test` |
| Fait | Test de restaurabilité de l'archive de configuration (22/06/2026) | journal des tests du PRA |
| Fait | Pile Docker distincte pour un environnement de préproduction ou de secours | [docker/README-DOCKER.md](../docker/README-DOCKER.md) |
| Fait | Intrants RPO/RTO mesurés en lecture seule, objectifs révisés et proposés (22/11/2026) ; exercice de restauration complète outillé avec garde anti-production | [RESTAURATION-COMPLETE.md](exploitation/RESTAURATION-COMPLETE.md) |
| À faire | Exécuter la reconstruction complète chronométrée sur VM isolée et consigner le RTO mesuré (exigence annuelle du PRA, non réalisée à ce jour) | `tools/omni-restore-drill.py` |
| À faire | Copie hors serveur du dépôt de snapshots `graylog_fs` (aujourd'hui sur le même serveur que les index) | [RESTAURATION-COMPLETE.md](exploitation/RESTAURATION-COMPLETE.md) §7 |
| À faire | Scénarios documentés d'indisponibilité : serveur SIEM, stockage `/data`, flux réseau des sources | |
| À faire | Réduction du point de défaillance unique (architecture mono-serveur) : au minimum un nœud de secours tiède restaurable dans le RTO | |

## 5. Indicateurs du SOC

| État | Élément | Référence |
|---|---|---|
| Fait | Supervision de la collecte, des sources silencieuses et des robots d'analyse | `39-collect-health.sh`, `74-source-watchdog.sh`, `46-self-health.sh` |
| Fait | Tableaux de bord « OMNI - Analytics » et « OMNI - Triage & Multi-site » ; rapports hebdomadaire et mensuel | `82-graylog-analytics-dashboard.sh`, `84-dashboards-triage-site.sh`, `34-weekly-report.sh`, `45-monthly-report.sh` |
| Fait | Couverture ATT&CK calculée depuis la table de correspondance | `57-mitre-coverage.sh` |
| À faire | MTTD et MTTR mesurés (horodatage de l'événement, de l'alerte, de la prise en charge et de la clôture) | |
| À faire | Taux d'alertes utiles et de faux positifs par détection, à partir des décisions d'analyste | |
| À faire | Disponibilité des robots et couverture des sources exprimées en indicateurs suivis dans le temps | |

## 6. Modèle de données commun

Vision : faire converger les moteurs (corrélation, graphe, ML, réponse) sur
des objets communs (Event, Entity, Finding, Incident, Evidence, Action), en
s'inspirant d'OCSF pour les événements et de MITRE ATT&CK pour les techniques,
sans repartir de zéro.

| État | Élément | Référence |
|---|---|---|
| Fait | Schéma de champs normalisé commun à toutes les sources (`event_source`, `event_action`, `user`, `host`, `src_ip`...) | `12-graylog-pipelines.sh`, [STD-JOURNALISATION.md](securite-conformite/STD-JOURNALISATION.md) |
| Fait | Identité canonique inter-sources (`identity`) | `58-identity-correlation.sh` |
| Fait | Correspondance des détections vers ATT&CK (table `lookups/mitre-attack.csv`) | `37-mitre-attack.sh` |
| Fait | Incidents corrélés réinjectés comme événements (`event_source=xdr_incident`) | `oms-xdr` |
| À faire | Table de correspondance entre le schéma OMNI et les classes OCSF | |
| À faire | Définition et versionnement des objets Finding, Incident, Evidence et Action partagés par les moteurs | |
| À faire | Identifiants stables d'entités (utilisateur, hôte, adresse, session) portés par chaque événement | |

## 7. Maintenabilité du dépôt

| État | Élément | Référence |
|---|---|---|
| Fait | Documentation rangée par usage, index unique, politique linguistique | [docs/README.md](README.md) |
| Fait | Scripts ponctuels séparés des scripts de provisioning, avec statut | [tools/ponctuel/](../tools/ponctuel/README.md) |
| Fait | Inventaire des scripts de provisioning et des numéros en double | [SCRIPTS-PROVISIONING.md](reference/SCRIPTS-PROVISIONING.md) |
| Fait | `83-retention-consolidee.sh` révisé : seul le compteur de rétention peut augmenter ; période et stratégie conservées, état relu avant écriture | [SCRIPTS-PROVISIONING.md](reference/SCRIPTS-PROVISIONING.md#note-sur-le-script-83) |
| Fait | Scripts retirés 15, 22, 31, 44 et ancien outil de synchronisation archivés | `tools/ponctuel/README.md` |
| En cours | Source Cert Orchestrator réinstallée le 22/11/2026 ; réception et normalisation des premiers journaux encore à vérifier | `99-cert-orchestrator.sh` |
