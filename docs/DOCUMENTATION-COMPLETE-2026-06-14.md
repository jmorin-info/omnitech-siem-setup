# 📚 Documentation complète — SIEM OMNITECH

> **Compilation de l'ensemble du dossier documentaire en un seul fichier.**
> Généré le **2026-06-14**. En cas de doute, les fichiers individuels de `docs/` font foi.
> (Le calque MITRE `mitre-navigator-layer.json` est un artefact JSON, fourni à part.)

## Sommaire

1. [Synthèse exécutive — SIEM OMNITECH Security](#doc-1) — `SYNTHESE-EXECUTIVE.md`
2. [Dossier documentaire SIEM OMNITECH — Index](#doc-2) — `00-INDEX.md`
3. [POL — Politique de supervision et de journalisation](#doc-3) — `POL-SUPERVISION-JOURNALISATION.md`
4. [STD — Standard technique de journalisation](#doc-4) — `STD-JOURNALISATION.md`
5. [PRO — Procédure d'exploitation du SIEM](#doc-5) — `PRO-EXPLOITATION-SIEM.md`
6. [DOS — Dossier d'architecture et d'exploitation du SIEM](#doc-6) — `DOSSIER-ARCHITECTURE-SIEM.md`
7. [Registre de conformité ISO/IEC 27001:2022 — SIEM OMNITECH](#doc-7) — `REGISTRE-CONFORMITE-ISO27001.md`
8. [PRA — Plan de reconstruction du SIEM sur un nouveau serveur](#doc-8) — `PRA-RECONSTRUCTION-SIEM.md`
9. [Cartographie SIEM ↔ ISO/IEC 27001:2022 (Annexe A)](#doc-9) — `ISO27001-MAPPING.md`
10. [Registre des règles de détection — SIEM OMNITECH](#doc-10) — `REGISTRE-DETECTIONS.md`
11. [Couverture MITRE ATT&CK — SIEM OMNITECH](#doc-11) — `COUVERTURE-MITRE-ATTACK.md`
12. [Inventaire des sources surveillées — SIEM OMNITECH](#doc-12) — `INVENTAIRE-SOURCES.md`
13. [Intégration de nouvelles sources — ESET / NPS / BunkerWeb](#doc-13) — `INTEGRATION-SOURCES.md`
14. [Politique de rétention des journaux - OMNITECH Security (SIEM Graylog)](#doc-14) — `POLITIQUE-RETENTION.md`
15. [Procédure de détection et de réponse aux incidents de sécurité](#doc-15) — `PROCEDURE-INCIDENT.md`
16. [Procédure d'exploitation du SIEM OMNITECH](#doc-16) — `PROCEDURE-EXPLOITATION-SIEM.md`
17. [Intégrité & valeur probante des journaux — OMNITECH SIEM](#doc-17) — `PROCEDURE-INTEGRITE-PREUVE.md`
18. [Chiffrement des données au repos — /data (OpenSearch) · OMNITECH SIEM](#doc-18) — `PROCEDURE-CHIFFREMENT-REPOS.md`
19. [SOAR — Playbooks de réponse automatisée (OMNITECH SIEM)](#doc-19) — `SOAR-PLAYBOOKS.md`
20. [Détection avancée & réponse automatisée — Canari AD + SOAR](#doc-20) — `REPONSE-AUTOMATISEE.md`
21. [LDAPS — Authentification Active Directory sur la console Graylog](#doc-21) — `LDAPS.md`
22. [Guide de dépannage — SIEM OMNITECH](#doc-22) — `GUIDE-DEPANNAGE.md`
23. [Glossaire — SIEM OMNITECH](#doc-23) — `GLOSSAIRE.md`
24. [Journal des modifications — SIEM OMNITECH](#doc-24) — `CHANGELOG.md`
25. [Audit dashboards SIEM — feuille de route (senior SoC)](#doc-25) — `AUDIT-DASHBOARD-2026-06-14.md`


<a id="doc-1"></a>

---

<!-- ============================== SYNTHESE-EXECUTIVE.md ============================== -->

# Synthèse exécutive — SIEM OMNITECH Security

*Document d'1 page pour la direction / DSI — 12/06/2026 — Classification : interne*

## En une phrase

OMNITECH Security dispose d'un **SIEM (centre de supervision de sécurité)**
opérationnel qui collecte, corrèle et surveille en temps réel les journaux de
l'ensemble du système d'information, détecte automatiquement les attaques et
les pannes, et alerte l'équipe IT — le tout documenté et aligné ISO 27001.

## Ce qui est couvert

| Domaine | Surveillé |
|---|---|
| **Active Directory / Windows** | authentifications, comptes, privilèges, exécutions (serveurs + postes) |
| **Microsoft 365 / Entra** | connexions, partages, transferts mail, rôles, **comptes à risque (Entra ID Protection)** |
| **Réseau (FortiGate ×3)** | trafic, antivirus/IPS, web, VPN, **attribution IP→machine (DHCP)** |
| **Endpoint / EDR (ESET)** | détections antivirus poste & serveur |
| **WAF applicatif (BunkerWeb)** | filtrage HTTP, blocages, scans applicatifs |
| **Coffre de mots de passe (Vaultwarden)** | échecs d'auth, accès admin |
| **Virtualisation (vSphere)** | accès, cycle de vie des machines |
| **Sauvegardes (Veeam)** | succès / échecs des jobs |
| **Le SIEM lui-même** | collecte, sauvegarde, capacité, **intégrité prouvable des journaux** (auto-surveillance) |

## Valeur démontrée (première semaine)

- **Attaque VPN bloquée** : une campagne d'attaque par mot de passe depuis
  Internet (10 000+ tentatives, verrouillage de comptes) a été détectée et
  stoppée par durcissement, sans impact sur les utilisateurs.
- **Panne de sauvegarde critique révélée** : le coffre-fort de mots de passe
  n'était plus sauvegardé depuis 3 jours — invisible jusqu'au SIEM.
- **Compte de service défaillant identifié** (cause d'une tempête d'alertes).

## Dispositif

- **88 définitions** (87 détections + 1 système) automatiques (attaques identité, ransomware,
  cloud, réseau, intrusion interne) + **réponse automatisée** (blocage d'IP).
- **Notifications** mail + Microsoft Teams, avec engagement de traitement.
- **Tableau de bord** unique en 24 pages pour le pilotage.
- **Résilience** : sauvegarde quotidienne chiffrée et externalisée, plan de
  reconstruction (reprise ≤ 4 h), garde-fous de capacité.
- **Authentification** des administrateurs par compte AD nominatif (LDAPS).

## Conformité ISO 27001:2022

Couvre les mesures A.8.15 (journalisation **+ intégrité prouvable des journaux**),
A.8.16 (surveillance), A.5.25 (évaluation des événements), A.8.13 (sauvegarde),
A.5.33 (protection des enregistrements), A.5.28 (preuves / valeur probante),
A.8.9 (gestion de configuration), **A.8.2 (accès privilégiés — rôle lecture seule),
A.8.24 (chiffrement au repos — **réalisé**), A.5.7 (renseignement sur les menaces —
couverture MITRE ATT&CK 44 techniques)**.
Dossier documentaire complet : politique, standard, procédure, dossier
d'architecture, registre de conformité, plan de continuité.

## Points d'attention soumis à la DSI

1. **Valider et signer** la politique de supervision (POL).
2. Planifier le **test annuel de restauration** (exigence A.8.13).
3. Réparer la sauvegarde du serveur de coffre-fort (action technique en cours).

## Coût / maintien

Solution **open source** (Graylog/OpenSearch), entièrement scriptée
(reproductible), exploitée par l'équipe IT via des revues quotidiennes,
hebdomadaires et mensuelles documentées. Aucun coût de licence.


<a id="doc-2"></a>

---

<!-- ============================== 00-INDEX.md ============================== -->

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


<a id="doc-3"></a>

---

<!-- ============================== POL-SUPERVISION-JOURNALISATION.md ============================== -->

# POL — Politique de supervision et de journalisation

| | |
|---|---|
| **Version** | 1.0 — 12/06/2026 |
| **Propriétaire** | DSI OMNITECH Security |
| **Approbation** | À valider DSI (date/visa : ____________) |
| **Classification** | Interne |
| **Révision** | Annuelle, ou après incident majeur / évolution réglementaire |
| **Réfs ISO 27001:2022** | A.8.15, A.8.16, A.5.25, A.5.33, A.5.28, A.8.13 |

## 0. Cadre normatif et réglementaire

La présente politique s'inscrit dans le Système de Management de la Sécurité
de l'Information (SMSI) d'OMNITECH Security et répond aux exigences suivantes :

| Référentiel | Exigences couvertes |
|---|---|
| **ISO/IEC 27001:2022** (Annexe A) | 8.15 Journalisation · 8.16 Surveillance · 5.25 Évaluation des événements · 8.13 Sauvegarde · 5.33 Protection des enregistrements · 5.28 Collecte de preuves · 8.9 Gestion de configuration · 8.6 Capacité |
| **RGPD** (UE 2016/679) | Art. 5 (minimisation, limitation de conservation), Art. 32 (sécurité du traitement) |
| **Recommandations ANSSI** | Guide « Journalisation » (durées 6-12 mois), recommandations Active Directory |
| **Référentiel CNIL** | Durées de conservation des journaux, traçabilité |

Cette politique se décline en documents subordonnés : **STD-JOURNALISATION**
(règles techniques), **PRO-EXPLOITATION-SIEM** (procédures opérationnelles),
**DOSSIER-ARCHITECTURE-SIEM** (conception). En cas de contradiction, la
hiérarchie est : Politique > Standard > Procédure.

## 1. Objet et périmètre

La présente politique définit les engagements d'OMNITECH Security en matière
de **journalisation** (collecte et conservation des traces) et de
**supervision de sécurité** (détection et traitement des événements).

Périmètre : l'ensemble du système d'information — sites BX (Bordeaux), IV
(Ivry), LC/PACA — incluant : Active Directory et serveurs Windows, postes de
travail, pare-feu FortiGate (3 clusters), infrastructure de virtualisation
vSphere, Microsoft 365, sauvegardes Veeam, et le SIEM lui-même.

## 2. Responsabilités

| Rôle | Responsabilité |
|---|---|
| **DSI** | Valide la politique, arbitre les rétentions, reçoit le reporting |
| **Administrateur SIEM** (équipe IT) | Exploitation quotidienne, triage des alertes, maintien en condition (PRO) |
| **Administrateurs systèmes/réseau** | Maintien des sources de logs (agents, audit policy, forwarding) |
| **Tout collaborateur** | Informé que l'usage du SI est journalisé (charte informatique) |

## 3. Principes de journalisation

1. **Exhaustivité ciblée** : sont journalisés en priorité les événements de
   sécurité (authentification, gestion des comptes et privilèges, exécution
   de processus, trafic réseau et UTM, accès cloud, sauvegardes) — pas la
   captation systématique de contenus.
2. **Centralisation** : toutes les sources convergent vers le SIEM Graylog
   (`bx-it-graylog-vm`, VLAN dédié 220), point unique de recherche,
   corrélation et alerte.
3. **Transport sécurisé** : TLS pour les agents (port 5044, PKI interne) ;
   flux syslog internes cantonnés aux VLAN d'administration par règles
   pare-feu dédiées.
4. **Horodatage fiable** : toutes les sources sont synchronisées NTP ;
   horodatage conservé en UTC dans le SIEM, affiché Europe/Paris.
5. **Comptes techniques dédiés** : aucun service de collecte ne s'exécute
   sous un compte nominatif ou d'administration (incident du 12/06/2026 —
   service FSSO — érigé en règle).

## 4. Rétention des journaux

Durées validées au regard des recommandations CNIL/ANSSI (6 mois à 1 an pour
les journaux de sécurité) et de la capacité dédiée (7,3 To) :

| Catégorie | Flux | Rétention |
|---|---|---|
| Identité et authentification | Windows Security (AD), comptes, Kerberos | **365 jours** |
| Systèmes et applications | Windows System/PowerShell/Defender, **Veeam** | **365 jours** |
| Cloud | Microsoft 365 (connexions, audit, Exchange/SharePoint) | **365 jours** |
| Télémétrie endpoint | Sysmon (processus, réseau, DNS) | **180 jours** |
| Réseau | FortiGate (trafic, UTM, VPN) | **180 jours** |
| Virtualisation | vSphere (ESXi, vCenter) | **180 jours** |
| Configuration du SIEM | Sauvegarde quotidienne chiffrée | **14 jours** |

La suppression à échéance est **automatique** (rotation quotidienne des
index). Toute demande de conservation prolongée (contentieux, enquête) fait
l'objet d'un gel manuel documenté par la DSI.

## 5. Supervision et alerte

- **88 définitions** (87 détections + 1 système) actives couvrant : attaques sur l'identité
  (force brute, spraying, Kerberoasting, DCSync), endpoint (ransomware,
  injection, PowerShell offensif, LSASS), réseau (UTM, IP malveillantes,
  VPN), cloud M365, virtualisation, sauvegardes, et auto-surveillance du
  SIEM (collecte muette, sauvegarde en échec, disque).
- **Deux niveaux de notification** : P3 (critique) = e-mail équipe IT +
  Teams ; P2 (important) = canal Teams SOC. Anti-tempête : période de grâce
  par alerte (et par compte/IP pour les alertes à clé).
- **Engagement de traitement** : toute alerte P3 est qualifiée **le jour
  ouvré même** ; les P2 sont revues quotidiennement (cf. PRO §2).
- La couverture de détection est revue à chaque évolution du SI et au
  minimum **trimestriellement**.

## 6. Sauvegarde et continuité du SIEM

- Configuration complète sauvegardée **chaque nuit (03:15)**, chiffrée
  AES-256, externalisée hors de la VM (`\\10.33.50.5\Public\SIEM`),
  rétention 14 jours, **alerte automatique en cas d'échec ou d'absence**.
- Procédure de reconstruction documentée et testée (`RESTORE.md`) ;
  objectif de reprise de la collecte : **≤ 4 h** après mise à disposition
  d'une VM de remplacement (les journaux historiques ne sont pas restaurés).
- Garde-fous capacité : alerte à 80 % du volume de données, purge d'urgence
  automatique des journaux les plus anciens à 88 % (la collecte du jour
  prime sur l'historique).

## 7. Protection et preuve

- Accès à la console SIEM restreint (compte d'administration dédié ; cible :
  authentification AD via LDAPS, cf. LDAPS.md) et tracé.
- Les journaux du SIEM constituent un élément de preuve : leur intégrité est
  protégée (suppression impossible hors rétention sans droits
  d'administration ; toute purge d'urgence est alertée et tracée).
- Le sabotage de la journalisation **sur les sources** est lui-même détecté
  (effacement de journal Windows 1102/104, arrêt d'audit 4719, silence d'un
  agent).

## 8. Conformité et données personnelles

Les journaux contiennent des données personnelles (identifiants, IP). Leur
traitement est fondé sur l'intérêt légitime de sécurisation du SI, est
proportionné (finalité sécurité exclusivement), limité dans le temps (§4) et
restreint aux personnes habilitées. Mention au registre des traitements.

- **Finalité exclusive** : sécurité du SI et investigation d'incidents. Tout
  usage à d'autres fins (contrôle individuel de l'activité des salariés) est
  proscrit.
- **Information** : les collaborateurs sont informés de l'existence de la
  journalisation via la charte informatique (consultation possible des CSE).
- **Accès** : seuls les administrateurs SIEM habilités consultent les
  journaux nominatifs ; les accès à la console sont eux-mêmes tracés.

## 9. Indicateurs de pilotage (KPI)

Suivis par l'administrateur SIEM et présentés en revue de direction :

| Indicateur | Cible | Source |
|---|---|---|
| Taux d'hôtes supervisés / parc | ≥ 95 % | Dashboard Santé collecte |
| Sources en silence > 24 h | 0 | Alerte « Silence Winlogbeat » + revue |
| Échecs d'indexation (par semaine) | 0 | System → Indexer failures |
| Délai de qualification d'une alerte P3 | ≤ 1 jour ouvré | Registre de traitement |
| Sauvegardes config réussies / 14 j | 14/14 | Page Sauvegardes |
| Sauvegardes Veeam en échec non traitées | 0 | Alerte Veeam |
| Remplissage /data | < 80 % | Garde-fou disque |
| Test de restauration | ≥ 1 / an, réussi | PRO §2 |

## 10. Gestion des exceptions

Toute dérogation à la présente politique ou au standard (ex. source non
journalisée, rétention réduite, service sous compte non dédié) doit être :
**documentée**, **justifiée** (contrainte technique/métier), **datée**,
**approuvée par la DSI**, assortie d'une **échéance de revue**, et consignée
dans un registre des dérogations. Une dérogation sans échéance est interdite.

## 11. Sensibilisation et amélioration continue

- Les administrateurs systèmes/réseau sont sensibilisés aux exigences de
  journalisation (maintien de l'audit policy, des agents, du forwarding).
- Tout incident de sécurité ou d'exploitation du SIEM alimente un retour
  d'expérience consigné dans `CONTEXT.md` (pièges et résolutions) et, si
  pertinent, fait évoluer cette politique ou le standard.
- **Revue** : annuelle a minima, et après tout incident majeur, changement
  d'architecture significatif ou évolution réglementaire.

## 12. Validation

| Rôle | Nom | Date | Visa |
|---|---|---|---|
| Rédacteur (Admin SIEM) | J. Morin | 12/06/2026 | |
| Approbateur (DSI) | | | |

*Historique : v1.0 — 12/06/2026 — création.*


<a id="doc-4"></a>

---

<!-- ============================== STD-JOURNALISATION.md ============================== -->

# STD — Standard technique de journalisation

*Version 1.0 — 12/06/2026 — applique la POL-SUPERVISION-JOURNALISATION — Classification : interne*

Ce standard fixe les règles techniques OBLIGATOIRES. Tout écart est une
non-conformité à corriger ou à documenter (dérogation DSI).

## 1. Sources obligatoires et canaux collectés

| Source | Mécanisme | Canaux / contenus | Stream SIEM |
|---|---|---|---|
| Contrôleurs AD (BX-AD-01, BX-AD02 + DC sites) | Winlogbeat 8.17.4 OSS (TLS 5044) | Security (EventID **en plages** : 1100-1104, 4624-4799, 4886-4889, 5136-5145, 6272-6274, 7045), Sysmon, PowerShell 4104, Defender, System, RDP, NTLM | OMNI - Windows Security / Sysmon / Windows autres |
| Serveurs Windows et postes | idem (déploiement NinjaOne `Install-OmniSiem-NinjaOne.ps1`, quotidien) | idem + canal **« Veeam Backup »** auto-détecté sur le serveur Veeam | idem |
| FortiGate (3 clusters : OMNITECH-BDX_FG120G, FGFW-IV, HA-LC) | FortiAnalyzer → forwarding syslog (TCP 1514) | traffic, event (VPN), **utm** (virus/IPS/webfilter/DNS/app-ctrl) | OMNI - FortiGate |
| vSphere (4 ESXi + vCenter 8) | syslog TCP/UDP 1516 | auth, shell/SSH, cycle de vie VM, snapshots | OMNI - vSphere |
| Microsoft 365 / Entra ID | Collecteurs API (Graph + O365 Management Activity) → GELF HTTP 12201 | connexions, audit Entra, Exchange, SharePoint/OneDrive | OMNI - M365 |
| SIEM lui-même | GELF 12201 (event_source=siem_*) | statut sauvegarde config, garde-fou disque | OMNI - Interne SIEM |

**Règles impératives :**
- Canal Security : **jamais de liste plate d'EventID** (limite de l'API
  Windows ≈ 23 expressions → canal muet). Toujours des plages.
- Tout nouveau serveur/poste est enrôlé par le script unique
  `Install-OmniSiem-NinjaOne.ps1` (CA, audit, Sysmon, Winlogbeat, vérif 5044).
- Politique d'audit Windows : baseline `audit-baseline.csv` (auditpol),
  ligne de commande dans les 4688, ScriptBlockLogging, Security ≥ 2 Go.

## 2. Transport, réseau et sécurité de la collecte

| Flux | Port | Sécurité |
|---|---|---|
| Winlogbeat → SIEM | TCP 5044 | TLS, CA racine OMNITECH (PKI AD CS) |
| FAZ → SIEM | TCP 1514 | VLAN management, règle FW dédiée |
| vSphere → SIEM | TCP/UDP 1516 | VLAN management, règle FW dédiée |
| Collecteurs M365 (localhost) | HTTP 12201 | local uniquement |
| Console web | HTTPS 443 (nginx) | certificat PKI interne |
| API Graylog | HTTPS 9000 (localhost + FQDN) | TLS, CA interne |
| SIEM → partage sauvegarde | TCP 445 | compte dédié `svc_siem`, archive chiffrée |

Pare-feu hôte (nftables) : 80/443/5044 limités à 10.33.0.0/16 ; 1514/1516
limités aux émetteurs légitimes. Règles FortiGate dédiées par flux (zone
« Réseau ELK »).

## 3. Normalisation (champs pivots)

Le pipeline (144 règles) garantit les champs communs suivants — toute
nouvelle source DOIT les alimenter :

| Champ | Contenu | Exemple |
|---|---|---|
| `event_source` | famille de la source | windows_security, fortigate, veeam, m365 |
| `event_action` | action normalisée (fr, snake_case, ASCII) | echec_connexion, vm_supprimee |
| `user` | compte concerné (sans domaine) | jmorin, adm-jmorin |
| `src_ip` / `dest_ip` | IP **validées** (jamais «N/A», «x.x», ip:port) | 10.33.20.4 |
| `host` / `source` | machine émettrice | bx-veeam-it-sv |
| `alert_tag` | marqueur de détection pour les règles d'alerte | dcsync, veeam_job_echec |
| `failure_reason` | cause d'échec traduite (lookup) | mot_de_passe_errone |

Conventions : préfixe **OMNI -** pour tout objet Graylog (streams, alertes,
dashboard) ; index **omni-*** ; rotation quotidienne ; ASCII sans accents
dans tout contenu poussé vers Windows/mails.

## 3bis. Matrice des événements Windows surveillés

Référence des EventID collectés (canal Security en **plages**, cf. §1) et de
leur usage en détection :

| EventID | Signification | Usage SIEM |
|---|---|---|
| 4624 / 4625 | Connexion réussie / échouée | Force brute, spraying, suivi succès, types de logon |
| 4634 / 4647 | Déconnexion | Corrélation de session |
| 4648 | Logon avec identifiants explicites | Mouvement latéral |
| 4662 | Opération sur objet AD | **DCSync** (GUID réplication) |
| 4670 | Permissions modifiées | Élévation, persistance |
| 4672 | Privilèges spéciaux à la connexion | Suivi des comptes à privilèges |
| 4688 | Création de processus (+ ligne de commande) | Endpoint, LOLBins |
| 4697 / 7045 | Service installé | Persistance |
| 4698 / 4699 | Tâche planifiée créée / supprimée | Persistance |
| 4720/4722/4725/4726 | Compte créé/activé/désactivé/supprimé | Cycle de vie des comptes |
| 4724/4723 | Réinitialisation / changement de mot de passe | Prise de contrôle de compte |
| 4727-4737 / 4754-4758 | Gestion des groupes (création, ajout membre) | **Groupes privilégiés** |
| 4732 / 4728 / 4756 | Ajout à un groupe local/global/universel sensible | Élévation |
| 4740 | Compte verrouillé | Effet du brute force / DoS |
| 4767 | Compte déverrouillé | Suivi |
| 4768 / 4769 / 4771 | Kerberos (TGT, TGS, pré-auth) | **Kerberoasting** (4769 RC4) |
| 4776 | Validation NTLM | Échecs d'authentification legacy |
| 4778 / 4779 | Session reconnectée / déconnectée (RDP) | Accès distant |
| 4794 | Tentative DSRM | Compromission DC |
| 5136 / 5137 / 5141 | Modification / création / suppression objet AD | Changements annuaire |
| 5140 / 5145 | Accès partage réseau | **Balayage de partages admin** (ADMIN$, C$) |
| 1102 / 1100 | Effacement / arrêt du journal d'audit | **Sabotage de l'audit** |
| 6272-6274 | NPS (RADIUS) | Accès réseau (802.1X) |
| 4886-4889 | AD CS (certificats) | Activité PKI |

Sources complémentaires : **Sysmon** (1 process, 3 réseau, 8/25 injection,
10 accès LSASS, 11 fichier, 13 registre Run, 17/18 named pipes, 22 DNS),
**PowerShell** 4104 (ScriptBlock), **Defender** (1006/1116/5001/5007…),
**System** (104, 7045, 7036, 6005/6006/6008).

## 4. Sévérités et notifications

| Niveau | Usage | Notification | Grâce anti-tempête |
|---|---|---|---|
| **P3** | Action requise (attaque, sabotage, sauvegarde KO) | E-mail équipe IT + Teams SOC | 10 min à 4 h selon la règle, **par clé** (compte/IP) quand pertinent |
| **P2** | À connaître (signal faible, hygiène) | Teams SOC | 30 min à 4 h |

Règles : les échecs de logon **type service/batch (4/5)** ne nourrissent
jamais les détections de force brute (alerte d'hygiène dédiée). Toute alerte
« état persistant » a une grâce ≥ 30 min. Tout mail est en ASCII, sans lien
vers la console.

## 5. Rétention, capacité, intégrité

- Rétentions par index : cf. POL §4 — appliquées par `41-retention-iso.sh`
  (à relancer après tout re-provisionnement du modèle).
- Capacité : volume nominal ≈ **25 Go/jour** ; plafond projeté ≈ 5,6 To /
  7,3 To (77 %). **Revue mensuelle** du Go/jour (procédure PRO §4).
- Garde-fou : `32-disk-guard.sh` (toutes les 6 h) — alerte ≥ 80 %, purge
  d'urgence ≥ 88 % (plus anciens index d'abord, jamais un index actif),
  chaque purge est alertée.
- Échecs d'indexation : 0 toléré en régime nominal (System → Indexer
  failures) ; toute valeur non conforme est corrigée **à la source ou au
  pipeline** (jamais en assouplissant le mapping).

## 6. Comptes et secrets

| Compte/secret | Usage | Règle |
|---|---|---|
| `admin` (local Graylog) | administration console | mot de passe fort dans le coffre ; cible : comptes nominatifs via LDAPS |
| `svc_siem` (AD) | dépôt SMB des sauvegardes | droits limités à `Public\SIEM`, jamais interactif |
| `BACKUP_PASSPHRASE` | déchiffrement des archives | coffre-fort obligatoire |
| App Entra (M365) | lecture des logs cloud | droits lecture seule (Reports/AuditLog) |
| `00-vars.env` | secrets de provisionnement | chmod 600, inclus dans la sauvegarde chiffrée |

Interdiction générale : aucun service de collecte sous compte nominatif ou
membre d'un groupe d'administration.

## 7. Synchronisation horaire (obligatoire)

La corrélation d'événements multi-sources exige une horloge commune :
- Toutes les sources (DC, serveurs, postes, FortiGate, ESXi) sont
  synchronisées NTP sur la même référence (PDC émulateur du domaine).
- Le SIEM stocke en **UTC** et affiche en **Europe/Paris**.
- Tout écart d'horloge > quelques secondes est traité comme une anomalie
  (fausse les fenêtres glissantes des alertes et les investigations).

## 8. Durcissement et protection du SIEM

| Mesure | État |
|---|---|
| Console et API en HTTPS uniquement (TLS, CA interne) | ✅ |
| Pare-feu hôte nftables (ports d'ingestion limités par CIDR/source) | ✅ |
| Comptes console : cible LDAPS + groupe « Admins du domaine » (cf. LDAPS.md), `admin` local de secours au coffre | en cours |
| Aucun accès direct OpenSearch/MongoDB hors localhost | ✅ |
| Secrets (`00-vars.env`, `.smb-siem.cred`) en chmod 600 | ✅ |
| Sauvegardes chiffrées AES-256, passphrase au coffre | ✅ |
| Détection du sabotage des sources (1102/104, arrêt audit, silence agent) | ✅ |
| Auto-surveillance (collecte muette, backup KO, disque) | ✅ |

## 9. Intégrité et valeur probante

- Les index sont en rotation/rétention contrôlée ; **aucune suppression
  hors rétention** sans droits d'administration, et toute purge d'urgence
  (garde-fou disque) est **alertée et tracée**.
- Pour constituer une preuve : exporter le sous-ensemble concerné (recherche
  Graylog → export), horodaté, et le conserver hors rotation (gel manuel
  documenté DSI).
- Le SIEM est sauvegardé quotidiennement (config) ; les journaux eux-mêmes
  ne sont pas sauvegardés mais protégés par leur durée de rétention.

## 10. Conventions de nommage (récapitulatif)

| Élément | Convention | Exemple |
|---|---|---|
| Objets Graylog | préfixe `OMNI - ` | `OMNI - Windows Security` |
| Index sets | `omni-<flux>` | `omni-fortigate` |
| Tags de détection | `alert_tag` snake_case ASCII | `dcsync`, `veeam_job_echec` |
| Actions normalisées | `event_action` français snake_case sans accent | `echec_connexion` |
| Scripts IaC | `NN-objet.sh` numérotés par ordre d'exécution | `12-graylog-pipelines.sh` |
| Hôtes | nomenclature AD existante | `bx-veeam-it-sv` |


<a id="doc-5"></a>

---

<!-- ============================== PRO-EXPLOITATION-SIEM.md ============================== -->

# PRO — Procédure d'exploitation du SIEM

*Version 1.0 — 12/06/2026 — applique POL + STD — Classification : interne*

Console : `https://bx-it-graylog-vm.omnitech.security` → Dashboards →
**OMNI - SOC** (24 pages). Notifications : mails `[SIEM]` + canal Teams SOC.

## 1. Vue d'ensemble du fonctionnement

Sources → (TLS/syslog/API) → **Inputs** Graylog → **Streams** (routage par
source) → **Pipelines** (normalisation, enrichissement GeoIP/lookups,
détections `alert_tag`) → **Index** OpenSearch (rotation quotidienne,
rétention POL §4) → **Définitions d'événements** (88) → notifications
mail/Teams → triage humain (la présente procédure).

## 2. Revues périodiques

### Quotidienne (~10 min, matin)
1. **Teams SOC + boîte mail** : traiter les alertes de la nuit (cf. §3).
2. Dashboard **Synthèse** : volumes anormaux ? détections en attente ?
3. Dashboard **Santé collecte** : chaque famille d'hôtes remonte-t-elle ?
   (un serveur muet = angle mort). L'alerte « Silence Winlogbeat » couvre
   l'arrêt global, pas un hôte isolé.
4. Page **Sauvegardes** : backup config OK cette nuit ; jobs Veeam en échec.

### Hebdomadaire (~20 min)
1. System → **Indexer failures** : doit rester à zéro (sinon : corriger la
   source/pipeline, cf. CONTEXT.md pièges).
2. Page **VPN & Exposition** : IP attaquantes, comptes visés, géo.
3. Page **Comptes & conformité** : créations/suppressions de comptes,
   groupes privilégiés, services installés — tout doit être justifiable.
4. Revue des hôtes : nouveaux postes enrôlés ? serveurs manquants ?
   (NinjaOne : résultat du script quotidien Install-OmniSiem.)

### Mensuelle (~30 min)
1. **Capacité** : `df -h /data` + taille des index du jour
   (`curl -s 127.0.0.1:9200/_cat/indices/omni-*?h=index,store.size&s=index`)
   → comparer au nominal (~25 Go/j). Dérive > +30 % : analyser, ajuster
   (STD §5, options fortigate 120 j / split traffic-UTM).
2. **Test du circuit d'alerte** : déclencher un test (notification → mail +
   Teams reçus).
3. Revue des règles : faux positifs récurrents → affiner (exclusions
   pipeline), détections manquantes → ajouter.
4. Vérifier la présence des 14 archives de sauvegarde sur le partage.

### Trimestrielle
- Revue de couverture détection (nouvelles menaces, nouveaux systèmes).
- **Test de restauration** (RESTORE.md) sur VM jetable — au moins 1×/an.
- Revue des comptes/accès console et des secrets (STD §6).

## 3. Traitement d'une alerte

1. **Qualifier** : ouvrir la page dashboard correspondante (Identité AD,
   VPN & Exposition, Endpoint, M365, Sauvegardes…) ; replacer l'alerte dans
   son contexte (volumes, récurrence, autres signaux du même compte/hôte/IP).
2. **Vrai positif sécurité** → réponse : isoler le poste (NinjaOne/EDR),
   désactiver/réinitialiser le compte (AD + révocation sessions M365),
   bloquer l'IP (FortiGate), préserver les preuves (exports SIEM). Ouvrir
   une fiche incident.
3. **Problème d'exploitation** (compte de service cassé, job Veeam KO,
   backup config KO) → ticket vers l'équipe concernée ; l'alerte rappelle
   (grâce 4 h) tant que non corrigé.
4. **Faux positif** → ne PAS ignorer : exclusion ciblée au pipeline ou
   ajustement de seuil (modifier le script 12/13/21 puis rejouer — jamais de
   modif console seule, l'IaC est la référence).
5. Tracer la décision (ticket/registre) — exigence A.5.25.

## 4. Gestes d'exploitation courants

| Geste | Commande / action |
|---|---|
| Enrôler une machine Windows | NinjaOne → `Install-OmniSiem-NinjaOne.ps1` (ou manuel : iwr depuis `/kit`, cf. README-WINDOWS) |
| Vérifier un hôte côté SIEM | recherche `source:<hostname>` sur 15 min |
| Rejouer le provisionnement | scripts dans l'ordre : `10 → 11 → 12 → 13 → 14` puis **toujours** `21` (tuning alertes) et `31` (rétentions) |
| Sauvegarde manuelle | `bash 30-backup-config.sh` |
| Restauration | `RESTORE.md` |
| État services | `systemctl status graylog-server opensearch mongod nginx` ; timers : `systemctl list-timers omni-*` |
| Santé indexation | console System→Overview + Indexer failures |
| Ajouter une source syslog | nouvel input + stream + règle pipeline de normalisation (STD §3) + retention + page dashboard — via nouveaux scripts IaC |

## 5. Incidents connus et résolutions (mémo)

Voir `CONTEXT.md` (sections « PIÈGE À RETENIR ») — notamment : listes
EventID trop longues (canal Security muet), tempête d'alertes / grâces,
panne silencieuse Teams (Power Automate), stream M365 qui avale le GELF,
locale FR (`auditpol` « Réussite »), TLS 1.2 obligatoire (Server 2016),
règle FW 1339 (srcintf), `key_spec`/`field_spec` API Graylog.

## 6. Playbooks de réponse (par scénario)

Chaque playbook suit la trame : **Confirmer → Contenir → Éradiquer →
Rétablir → Capitaliser**. Le SIEM sert au confirmer et au capitaliser.

### P-1 — Force brute / spraying sur compte AD
1. **Confirmer** : page *VPN & Exposition* / *Identité AD* — IP source,
   comptes visés, succès consécutif éventuel.
2. **Contenir** : si IP externe → bloquer sur FortiGate ; si succès obtenu →
   désactiver le compte, forcer le changement de mot de passe, révoquer les
   sessions. Vérifier les verrouillages (4740) collatéraux.
3. **Éradiquer/Rétablir** : déverrouiller les comptes légitimes
   (`Search-ADAccount -LockedOut | Unlock-ADAccount`), renforcer (MFA VPN).
4. **Capitaliser** : si exposition portail → durcissement (géo, MFA).

### P-2 — Ransomware / indicateur de chiffrement
1. **Confirmer** : alerte « Indicateur de ransomware » (suppression shadow
   copies) ou pic de modifications — identifier l'hôte et le compte.
2. **Contenir IMMÉDIATEMENT** : isoler l'hôte (NinjaOne/EDR/port réseau),
   suspendre le compte. Ne pas éteindre (préserver la RAM si forensic).
3. **Éradiquer** : analyse EDR, recherche de propagation (partages admin,
   mouvement latéral via 4624 type 3).
4. **Rétablir** : restauration depuis Veeam (vérifier que les sauvegardes
   de la cible sont saines — cf. page Sauvegardes).

### P-3 — Compte M365 compromis
1. **Confirmer** : *M365* / *Cartographie* — connexion hors France, compte à
   risque, transfert mail externe, délégation de boîte.
2. **Contenir** : révoquer les sessions (Entra), réinitialiser le mot de
   passe, désactiver les règles de transfert créées, vérifier les
   inscriptions MFA frauduleuses.
3. **Éradiquer** : auditer les partages/délégations récents du compte.
4. **Capitaliser** : Conditional Access, blocage legacy auth.

### P-4 — Activité sur l'AD (DCSync, Kerberoasting, groupe privilégié)
1. **Confirmer** : *Comptes à privilèges* — auteur, compte cible, horodatage.
2. **Contenir** : si non légitime → suspendre le compte auteur, rotation des
   secrets concernés (krbtgt si DCSync confirmé, comptes de service si
   Kerberoasting), retrait de l'ajout au groupe.
3. **Capitaliser** : revue des délégations AD, tiering administratif.

### P-5 — Exploitation : compte de service / sauvegarde en échec
1. **Confirmer** : alerte dédiée (Échec logon service, Veeam, Backup config).
2. **Traiter** : ticket à l'équipe concernée ; corriger la cause
   (credentials, droit « log on as a service », cible de dépôt…).
3. L'alerte rappelle (grâce 4 h) jusqu'à résolution → ne pas la désactiver,
   la résoudre.

## 7. Classification des incidents

| Niveau | Critère | Délai de prise en charge |
|---|---|---|
| **Critique** | Compromission active, ransomware, exfiltration, DC menacé | Immédiat |
| **Majeur** | Compte privilégié/M365 compromis, intrusion confirmée | ≤ 2 h |
| **Mineur** | Tentative bloquée, signal isolé à qualifier | ≤ 1 j ouvré |
| **Exploitation** | Panne de collecte, backup/service KO | ≤ 1 j ouvré |

## 8. Matrice RACI

| Activité | Admin SIEM | Admin Sys/Rés | DSI |
|---|---|---|---|
| Revues quotidiennes/hebdo | **R/A** | C | I |
| Maintien des sources (audit, agents, forwarding) | C | **R/A** | I |
| Triage et qualification des alertes | **R/A** | C | I |
| Réponse à incident critique | **R** | C | **A** |
| Évolution des règles de détection | **R/A** | C | I |
| Validation politique / dérogations | C | I | **R/A** |
| Test de restauration | **R/A** | C | I |

(R=Réalise, A=Approuve/responsable, C=Consulté, I=Informé)

## 9. Contacts et escalade

| Sujet | Contact |
|---|---|
| Exploitation SIEM / triage | Équipe IT (J. Morin) |
| Incident de sécurité avéré | DSI + (si besoin) prestataire réponse à incident |
| Fournisseurs | FortiGate/FAZ : support Fortinet ; M365 : support Microsoft |


<a id="doc-6"></a>

---

<!-- ============================== DOSSIER-ARCHITECTURE-SIEM.md ============================== -->

# DOS — Dossier d'architecture et d'exploitation du SIEM

*Version 1.1 — 14/06/2026 — Classification : interne*
*Mise en production initiale : 11/06/2026 — consolidation : 12/06/2026 — revue : 14/06/2026*

## 0. Schéma d'architecture

```
 SOURCES                         COLLECTE / TRANSPORT          SIEM  bx-it-graylog-vm (10.33.220.10)
 ───────────────────────         ────────────────────         ─────────────────────────────────────
 DC · Serveurs · Postes  ──────> Winlogbeat TLS  :5044 ─┐
   Security, Sysmon,                                     │
   PowerShell, Defender,                                 │      ┌──────────────────────────────────┐
   Veeam Backup, (NPS*)                                  │      │ INPUTS(7) ─> STREAMS(13) ─>       │
 BunkerWeb WAF ──> Filebeat TLS  :5044 ─────────────────┤      │ PIPELINES (20 / 144 règles)      │
   http_* / waf_*                                        │      │  · normalisation                 │
                                                         ├────> │  · enrichissement GeoIP/lookups  │
 FortiGate x3 ─> FortiAnalyzer ─> syslog     :1514 ─────┤      │  · détections (alert_tag)        │
   trafic, UTM, VPN                                      │      │  · ATT&CK / off-hours / comptes  │
                                                         │      │ INDEX OpenSearch  omni-*         │
 ESET PROTECT ────────────────> syslog JSON  :1515 ─────┤      │  (rotation/rétention ISO)        │
   eset_* (menaces AV/HIPS)                              │      └───────────────┬──────────────────┘
                                                         │                      │
 ESXi x4 · vCenter ────────────> syslog      :1516 ─────┤              DÉFINITIONS D'ÉVÉNEMENTS
                                                         │                (88 définitions)
 Microsoft 365 ─> collecteurs API ─> GELF    :12201 ────┤                      │
   Graph + O365 Mgmt Activity                            │      ┌───────────────┼─────────────────┐
                                                         │    MAIL             TEAMS          RÉPONSE AUTO
 Auto-surveillance ─────────────> GELF       :12201 ────┘  (26 critiques)   (firehose 87)     SOAR ─> feed
   backup · disque · SOAR · cert · santé · UEBA/NDR        équipe IT        canal SOC        ─> FortiGate
                                                                                            (blocage IP)

 * NPS : mappé (lookup 6272/6273/6274) mais pas encore remonté côté client (Winlogbeat à déployer).

 CONSOLE  https://bx-it-graylog-vm.omnitech.security  (auth AD / LDAPS, admins du domaine)
 SAUVEGARDE  config chiffrée quotidienne ─> \\10.33.50.5\Public\SIEM   |   /data dédié 7,3 To
```

## 1. Plateforme

| Élément | Valeur |
|---|---|
| VM | `bx-it-graylog-vm` — **10.33.220.10** — VLAN 220 (« Réseau ELK »), site BX |
| OS | Debian (noyau 6.12), pare-feu hôte nftables |
| Disques | système 931 Go (/, /var, /home) ; **données 7,3 To monté sur `/data`** (≈147 Go utilisés à la revue) |
| Données | OpenSearch : `/data/opensearch` — journal Graylog : `/data/graylog-journal` |

## 2. Composants logiciels

| Composant | Version | Rôle |
|---|---|---|
| Graylog Server | **7.1.3** | ingestion, pipelines, alerting, dashboards (API HTTPS :9000) |
| OpenSearch | **2.19.5** | stockage/indexation (localhost:9200) |
| MongoDB | **8.0.24** | configuration Graylog (authentifié) |
| nginx | **1.26.3** | reverse proxy console HTTPS :443 + hébergement kit `/kit` |
| Java/JVM | truststore `cacerts-omni.jks` (Root CA OMNITECH) — TLS interne complet |

Particularité TLS : `http_publish_uri` = FQDN résolu en 127.0.0.1 via
`/etc/hosts` ; tous les appels API passent par
`https://bx-it-graylog-vm.omnitech.security:9000/api` + CA interne.

## 3. Flux réseau

### Entrants (collecte)
| Port | Proto | Source | Contenu |
|---|---|---|---|
| 5044 | TCP/TLS | tout 10.33.0.0/16 (agents Winlogbeat) + **BunkerWeb (Filebeat)** | logs Windows + Veeam + **WAF** |
| 1514 | TCP **et** UDP | FortiAnalyzer (10.33.80.253) | logs des 3 clusters FortiGate |
| 1515 | TCP | **ESET PROTECT** (10.33.50.20) | syslog JSON menaces AV/HIPS (514 redirigé par le pare-feu) |
| 1516 | TCP **et** UDP | ESXi ×4 + vCenter | syslog vSphere |
| 12201 | HTTP (localhost) | collecteurs M365 + scripts internes | GELF |
| 443 | HTTPS | LAN | console web |

> Le même input Beats :5044 reçoit Winlogbeat **et** Filebeat (BunkerWeb).
> Le routage des messages BunkerWeb vers leur stream se fait sur le champ
> `filebeat_event_source = bunkerweb` (posé par Filebeat), avec exclusion
> symétrique sur le stream « OMNI - Windows autres ».

### Sortants
| Destination | Port | Usage |
|---|---|---|
| Microsoft (Graph, O365 Mgmt API) | 443 | collecteurs M365 (timers) |
| DB-IP / abuse feeds | 443 | mises à jour GeoIP / threat intel |
| 10.33.50.5 (Files) | 445 | dépôt sauvegarde quotidienne (compte `svc_siem`) |
| smtp-internal.omnitech-security.fr | 25 | notifications mail |
| Power Automate (M365) | 443 | notifications Teams |

Règles FortiGate dédiées : flux logs (1339 corrigée, 1340, 1424…), accès
console (1335), sauvegarde SMB (règle Graylog_Backup créée le 12/06),
redirection 514→1515 pour ESET.

## 4. Chaîne de traitement

**7 inputs** → **13 streams** (Windows Security / Sysmon / Windows autres /
FortiGate / vSphere / M365 / **ESET** / **BunkerWeb** / Interne SIEM, plus le
Default Stream système) → **20 pipelines, 144 règles** :

- pipelines de **normalisation/détection** par source : Windows Security, Sysmon,
  Windows autres, FortiGate, M365, M365 Activité, vSphere, **Sources externes**
  (ESET + BunkerWeb) ;
- pipelines d'**enrichissement transverse** : Enrichissement ATT&CK,
  Enrichissement off-hours, Enrichissement comptes, Enrichissement M365,
  Exposition réseau ;
- pipelines de **détections additionnelles** : Détections complémentaires,
  Détections Lot3, Détections Lot4 ;
- pipeline de **réduction de volume** : Réduction volume (ISO) — drop vCenter
  applicatif et **bruit stockage ESXi/vSAN (−87 % vSphere)**, exclusions
  Veeam/snapshots, dwm/winlogon, Azure AD Sync…

Sortie → index `omni-*` (rotation quotidienne, rétentions POL §5).

> **Piège pipeline à connaître** : un stage `match either` ne contenant qu'une
> règle conditionnelle (drop/tag) bloque tout message qui ne la matche pas. Y
> adjoindre toujours une règle qui matche systématiquement (normalisation).

> **Pièges API Graylog 7.x** : pas de ternaire en pipeline, `contains()` prend
> 2 arguments, les POST de définitions attendent l'enveloppe `{entity}`, et le
> cycle du deflector se fait par `POST /system/deflector/{id}/cycle`.

## 5. Index et rétention (appliqué par `41-retention-iso.sh`)

Rotation **quotidienne** (TimeBasedRotationStrategy P1D), rétention par nombre
d'index conservés (= nombre de jours).

| Index set | Contenu | Rétention | Volume nominal |
|---|---|---|---|
| omni-winsec | Windows Security | **365 j** | ~5,5 Go/j |
| omni-winother | System/PowerShell/Defender/RDP/**Veeam**/**NPS** | **365 j** | ~2,7 Go/j |
| omni-m365 | Microsoft 365 | **365 j** | <0,1 Go/j |
| omni-sysmon | Sysmon | **365 j** | ~1,8 Go/j |
| omni-vsphere | vSphere (bruit ESXi/vSAN filtré, −87 %) | **365 j** | ~0,3 Go/j |
| omni-eset | **ESET PROTECT** (menaces AV/HIPS) | **365 j** | <0,1 Go/j |
| omni-fortigate | FortiGate (traffic+UTM+VPN) | **180 j** | ~11 Go/j |
| omni-bunkerweb | **BunkerWeb WAF** (http_*/waf_*) | **90 j** | volume web |

> Choix de rétention : 365 j (forensique / conformité) sur les sources d'identité
> et endpoint ; 180 j sur FortiGate (volume le plus élevé) ; 90 j sur le WAF
> (volume web, valeur forensique courte). Un garde-fou disque (§8) protège `/data`.

## 6. Détections (88 définitions actives)

Routage **2 tiers** (script `22-alert-routing.sh`) : **Teams = firehose** (87
définitions, canal SOC) ; **MAIL = 26 alertes critiques « réveille-moi »**
(compromission confirmée + santé du SIEM). Légende ci-dessous : **MT** = mail+Teams ·
**T** = Teams seul.

### Alertes routées vers le MAIL (26 critiques)
- Incident critique (kill-chain corrélée)
- Indicateur de ransomware (suppression shadow copies)
- Force brute SUIVIE d'un succès (même compte)
- Mouvement latéral réussi (1 compte → N hôtes)
- DCSync suspect
- COMPTE CANARI touché (intrusion AD probable)
- Impossible travel (compte multi-localisé)
- M365 transfert mail vers domaine externe
- ESET : détection / menace antivirus
- Veeam : job en échec ou avertissement
- Silence Winlogbeat (0 log Windows / 15 min)
- Robot d'analyse en panne (auto-supervision)
- Disque SIEM >80 % (/data)
- PURGE D'URGENCE rétention (disque presque plein)
- Backup config SIEM en échec
- Backup config SIEM absent (>26 h)
- Certificat SIEM expire bientôt (<45 j)
- Certificat du parc expire bientôt
- Rapport hebdomadaire en échec

### Principales détections (extrait représentatif)

| Détection | Niveau |
|---|---|
| Force brute (≥10 échecs/compte/10 min, clé par compte ; exclut comptes machine `*$` + service ninjaone/ADSyncMSA) | T |
| Force brute SUIVIE d'un succès (même compte) | MT |
| Password spraying (≥8 comptes/IP, clé par IP) | T |
| Force brute portail VPN (≥30 échecs/IP/h) | T |
| VPN monté depuis l'étranger | T |
| Compte verrouillé (4740) | T |
| Tentative sur compte désactivé | T |
| Compte créé dans le domaine (4720) | T |
| Modification d'un groupe privilégié | T |
| DCSync suspect | MT |
| Kerberoasting suspect (≥5 SPN/compte) | T |
| Mouvement latéral réussi (1 compte → N hôtes) | MT |
| Échecs AD + connexion M365 étrangère (corrélation) | T |
| Sabotage de l'audit (1102/4719/4794/104) | T |
| Silence Winlogbeat (0 log Windows/15 min) | MT |
| Échec logon service/batch (compte de service cassé) | T |
| Balayage de partages admin (≥3 hôtes/compte) | T |
| Accès mémoire LSASS | T |
| Injection de processus (Sysmon 8/25) | T |
| PowerShell suspect (encodé/download/mimikatz ; exclut wakeup-ssrs.ps1) | T |
| Indicateur de ransomware (shadow copies) | MT |
| Nouveau service installé (7045) | T |
| Tâche planifiée créée (4698) | T |
| Defender : détection ou désactivation | T |
| FortiGate : virus / IPS | T |
| IP malveillante (Tor/Spamhaus) | T |
| M365 force brute / compte à risque / connexion hors France | T |
| M365 rôle privilégié / délégation boîte / transfert externe / partage externe | MT (transfert) / T |
| Impossible travel (compte multi-localisé) | MT |
| vSphere : brute force (exclut vpxuser/dcui/localhost) / SSH-shell ESXi / suppression de VM | T |
| **ESET : détection / menace antivirus** (Threat_Event / HipsAggregated_Event) | MT |
| **BunkerWeb / WAF** : requêtes bloquées, scans, attaques web | T |
| Veeam : job en échec ou avertissement | MT |
| Backup config SIEM en échec / absent >26 h | MT |
| Disque SIEM >80 % / PURGE D'URGENCE rétention | MT |
| Certificat SIEM / parc expire bientôt | MT |
| Rapport hebdomadaire en échec | MT |
| Incident critique (kill-chain corrélée, déduplication intégrée) | MT |
| **COMPTE CANARI touché** (intrusion AD) | MT |
| **SOAR : IP bloquée automatiquement** | T |
| UEBA / NDR : pics de volume, nouveau pays, beaconing, exfiltration DNS, balayage | T |

> La liste complète des 88 définitions et de leur routage exact se génère/contrôle
> via `13-graylog-alerts.sh`, `21-alert-hygiene.sh`, les scripts de détections
> additionnelles (47/48/50/51) et `22-alert-routing.sh`. Voir aussi
> `docs/REGISTRE-DETECTIONS.md`.

## 7. Dashboard « OMNI - SOC » (24 pages)

Dashboard unique `requires={}` → 100 % OSS (pas d'Enterprise requis).

| Page | À quoi elle sert |
|---|---|
| **Direction** | Vue d'ensemble : volumes, détections du moment, état global |
| **Alertes** | Historique des alertes déclenchées (par priorité) |
| **Incidents** | Incidents corrélés (kill-chain) émis par le robot d'incidents |
| **ATT&CK** | Couverture MITRE ATT&CK (tactiques/techniques observées) |
| **UEBA / NDR** | Comportement anormal : scoring utilisateurs, nouveau pays, beaconing, exfil |
| **Santé collecte** | Quels hôtes/sources remontent — repérer un angle mort (inclut ESET/BunkerWeb) |
| **Identité AD** | Authentifications, échecs, verrouillages, types de logon |
| **Comptes à privilèges** | Activité des comptes `adm-*`, privilèges spéciaux |
| **Comptes & conformité** | Cycle de vie comptes, groupes privilégiés, PKI, NPS |
| **M365** | Connexions cloud, pays, applications, comptes à risque |
| **M365 Activité** | Exchange / SharePoint / OneDrive : partages, accès boîtes |
| **Endpoint** | Sysmon : processus, réseau, DNS, détections poste |
| **Hunting** | Recherche proactive : LSASS, Office→shell, persistance, pipes |
| **Réseau** | FortiGate : trafic, UTM (virus/IPS), IP malveillantes |
| **VPN & Exposition** | Attaques portail, IP/comptes visés, tunnels légitimes |
| **Sources externes** | ESET (menaces AV/HIPS) et corrélations endpoint associées |
| **WAF BunkerWeb** | Trafic web, requêtes bloquées, scans, attaques applicatives |
| **Cartographie** | Connexions M365/VPN dans le monde (GeoIP) |
| **vSphere** | ESXi/vCenter : accès, SSH, cycle de vie des VM |
| **Sauvegardes** | Jobs Veeam, snapshots, backup config SIEM, garde-fou disque |
| **Certificats** | Expiration certificats SIEM + parc (télémétrie permanente) |
| **Vulnérabilités** | Inventaire des vulnérabilités remontées (scan client quotidien) |
| **Investigation** | Page transverse multi-streams pour pivoter lors d'une enquête |

## 8. Sauvegarde du SIEM (détail)

- `30-backup-config.sh` + timer **03:15** (Persistent) : mongodump (URI
  authentifiée) + /etc (graylog, opensearch, nginx, systemd) +
  /usr/local/sbin + kit + IaC → tar.gz → **AES-256-CBC (PBKDF2 200k)** →
  copie locale `/var/backups/siem` + dépôt `\\10.33.50.5\Public\SIEM`
  (compte `svc_siem`, cred 600) — rétention 14 j des deux côtés.
- Statut GELF → stream « OMNI - Interne SIEM » → alertes échec/absence (mail).
- `32-disk-guard.sh` + timer 6 h : alerte 80 %, purge d'urgence 88 %→82 %.
- Restauration : `RESTORE.md` / `PRA-RECONSTRUCTION-SIEM.md` (test trimestriel — voir PRO §2).

## 9. Infrastructure as Code (référence = ces scripts, pas la console)

| Script | Rôle |
|---|---|
| `00-vars.env` (600) | secrets et paramètres |
| `lib-graylog.sh` | helpers API (TLS, enveloppe entity, ensure_*) |
| `06-firewall.sh` | nftables + redirections (514→1515 ESET) |
| `07-inputs.sh` | inputs Graylog (Beats, Syslog, GELF) |
| `10-graylog-model.sh` | index sets, streams, inputs |
| `11-graylog-enrichment.sh` | lookups CSV (GeoIP, threat intel, win-events…) |
| `12-graylog-pipelines.sh` | règles + pipelines de base (normalisation/détection) |
| `13-graylog-alerts.sh` | notifications (mail ASCII, Teams card, SOAR HTTP) + définitions de base, templates source-aware |
| `14-graylog-dashboards.sh` | dashboard « OMNI - SOC » 24 pages (généré, `requires={}`) |
| `16/17/18-m365-*.sh` + `/usr/local/sbin/omni-m365-*` | input GELF + collecteurs cloud + timers |
| `19-vsphere.sh` | volet vSphere |
| `21-alert-hygiene.sh` | **surcouche obligatoire après 13** : grâces/clés, alertes svc/Veeam/backup/disque/rapport, stream « OMNI - Interne SIEM » |
| `22-alert-routing.sh` | **routage 2 tiers** (Teams firehose / mail 26 critiques), grâce mail ≥60 min |
| `30/32-*.sh` | sauvegarde config, garde-fou disque |
| `41-retention-iso.sh` | rétentions ISO par index set (remplace l'ancien 31) |
| `33-ldaps-auth.sh` | authentification AD (LDAPS) sur la console |
| `34-weekly-report.sh` + `/usr/local/sbin/omni-weekly-report` | rapport hebdomadaire (mail HTML + copie locale) |
| `45-monthly-report.sh` + `/usr/local/sbin/omni-monthly-report` | rapport mensuel |
| `35-canary.sh` + `windows/New-OmniCanary.ps1` | compte canari AD (lookup + alerte + script de création) |
| `36-soar.sh` + `/usr/local/sbin/omni-soar` | SOAR-light : blocage auto d'IP (feed FortiGate, webhook 127.0.0.1:8088) |
| `37-mitre-attack.sh` | enrichissement / couverture MITRE ATT&CK |
| `38-vuln-scan.sh` + `/usr/local/sbin/omni-vuln-scan` | scan de vulnérabilités du parc |
| `39-collect-health.sh` + `/usr/local/sbin/omni-collect-health` | santé de la collecte |
| `40-ueba-ndr.sh` + `/usr/local/sbin/omni-ueba-*` + `omni-ndr-*` | UEBA (scoring, géo, volume) et NDR (beacon, DNS, exfil, latéral, scan) |
| `42-carte-cyber.sh` + `/usr/local/sbin/omni-geo-flux` | cartographie / flux géographiques |
| `43-ndr-dns.sh`, `48-ndr-scan.sh` | détections NDR additionnelles |
| `44-incidents.sh` + `/usr/local/sbin/omni-incident-correlate` | corrélation d'incidents (kill-chain, déduplication) |
| `46-self-health.sh` + `/usr/local/sbin/omni-self-health` | auto-supervision du SIEM (robots en panne) |
| `47-detections-extra.sh`, `48-m365-fail-codes.sh`, `49-*`, `50-enrich-lot3.sh`, `51-enrich-lot4.sh` | détections et enrichissements complémentaires (Lot3/Lot4, exposition réseau, recon LDAP, M365 fail codes) |
| `52-new-sources.sh` | **intégration ESET (1515) + BunkerWeb (Filebeat) + mapping NPS** |
| `/usr/local/sbin/omni-cert-check`, `omni-cert-renew` | surveillance/renouvellement certificats (télémétrie permanente) |
| `40-purge-logs.sh` | maintenance manuelle historique (CONFIRM=OUI) — remplacée par 53/54 |
| `53-purge-clean.sh` | **purge des données** (cycle deflector + suppression index), garde TOUTE la config ; `gl-system-events` conservé |
| `54-post-purge-repopulate.sh` | repopulation post-purge (index ranges, re-fetch M365, relance des robots) |
| `55-vaultwarden.sh` | source Vaultwarden (stream + **index set dédié `omni-vaultwarden`** + pipeline `omni-vw-*` + détections coffre) ; kit `/kit/vw-filebeat.sh` |
| `56-fortidhcp.sh` | attribution DHCP FortiGate (`omni-fortidhcp-fetch`, timer 15 min, lookup `omni-dhcp-attribution` → `src_hostname`/`dest_hostname`) |
| `57-mitre-coverage.sh` | carte de couverture MITRE ATT&CK → `docs/mitre-navigator-layer.json` (calque Navigator) + bilan |
| `58-identity-correlation.sh` | identité unifiée (`identity`/`identity_human`) + page dashboard « Identité » |
| `59-file-audit.sh` | audit d'accès fichiers sensibles (4663/5145 → `file_sensitive_access`/`file_delete_sensible`) |
| `60-integrity.sh` | intégrité des logs (registre haché-signé `omni-integrity` + `--verify` + copie hors-SIEM) + rôle Graylog lecture seule |
| `windows/`, `fortigate/`, `lookups/` | kit agents, conf FortiGate, CSV |
| `docs/` | dossier ISO (POL, STD, PRO, DOS, REGISTRE, PRA, LDAPS, INTEGRATION-SOURCES…) |

Ordre de (re)déploiement de base : `10 → 11 → 12 → 13 → 14` puis **21** puis
**22** puis **41**. Les volets sources/détections/analytics (16-19, 35-52) se
rejouent ensuite (idempotents). Purge contrôlée : `53` puis `54`.

## 10. Tâches planifiées

`systemctl list-timers 'omni-*'` (24 timers à la revue). Principaux :

- collecteurs M365 : `omni-m365-fetch`, `omni-m365-activity` ;
- sauvegarde : `omni-backup-config` (03:15), garde-fou `omni-disk-guard` (6 h) ;
- rapports : `omni-weekly-report` (lundi 08:00), `omni-monthly-report` (1er du mois) ;
- certificats : `omni-cert-renew`, `omni-cert-check` (hebdo) ;
- vulnérabilités : `omni-vuln-scan` (quotidien) ;
- santé : `omni-collect-health`, `omni-self-health` ;
- UEBA : `omni-ueba-geo`, `omni-ueba-geo-newcountry`, `omni-ueba-score`, `omni-ueba-volume` ;
- NDR : `omni-ndr-dns`, `omni-ndr-scan`, `omni-ndr-beacon`, `omni-ndr-exfil`, `omni-ndr-lateral` ;
- corrélation / divers : `omni-incident-correlate`, `omni-ldap-recon`, `omni-geo-flux`, `omni-soar-expire` (horaire).

Service permanent : `omni-soar.service` (webhook blocage IP, 127.0.0.1:8088).
Côté parc : politique NinjaOne quotidienne `Install-OmniSiem-NinjaOne.ps1`.

## 11. Historique de mise en production

| Date | Étape |
|---|---|
| 11/06 | Build initial : modèle, pipelines, alertes, dashboards, M365, TLS bout-en-bout, FAZ, vSphere ; déploiement agents (NinjaOne + GPO) |
| 11→12/06 nuit | Incident fondateur : tempête force brute (service FSSO sur AD02) → refonte anti-tempête (grâces/clés), détection comptes de service |
| 12/06 matin | Durcissement VPN (géo-FR — spraying stoppé), UTM complet 3 clusters, FSSO rétabli, script d'enrôlement unique, Veeam intégré (+ découverte job Vaultwarden KO) |
| 12/06 midi | Résilience : sauvegarde chiffrée externalisée + rétentions ISO + garde-fous + ce dossier documentaire |
| 13/06 | Extension analytics : MITRE ATT&CK, UEBA/NDR, scan de vulnérabilités, corrélation d'incidents, rapports mensuels, lots d'enrichissement/détection (Lot3/Lot4), routage alertes 2 tiers |
| 14/06 | Nouvelles sources : **ESET PROTECT** (1515), **BunkerWeb WAF** (Filebeat), mapping **NPS** ; audit correctifs (timestamp FortiGate `eventtime`, exclusions brute-force comptes machine/service, PowerShell wakeup-ssrs, dédup incidents, brute-force vSphere vpxuser/dcui/localhost, cert-check en télémétrie permanente, index sets dédiés ESET/BunkerWeb) ; outillage purge 53/54 ; dashboard porté à 24 pages |

## 12. Limites connues et backlog

- Group-sync LDAP (rôles auto par groupe AD) = fonctionnalité Enterprise ;
  en Open Source l'attribution de rôles console est manuelle (cf. LDAPS.md).
- M365 riskDetections : **ingéré** (`m365_type:risk`, tag `m365_risque`) via la
  permission Graph `IdentityRiskEvent.Read.All` (Entra ID **P1** : événements de
  risque visibles, niveau masqué `hidden` ; le niveau détaillé + `riskyUsers`
  nécessiteraient **P2**). `SecurityAlert.Read.All` accordée mais inopérante (tenant
  sans backend Microsoft Defender XDR → 403 « not provisioned »).
- **NPS** : mappé côté SIEM (lookup `win-events.csv` 6272/6273/6274) mais pas
  encore remonté — déployer Winlogbeat sur 10.33.50.247.
- Test de restauration à réaliser (trimestriel PRO / PRA).
- Backlog sécurité : intégration Wazuh, deep inspection (SubCA AD CS),
  serveurs Windows restants dans NinjaOne, hôte `DESKTOP-GASTH3T` à identifier.


<a id="doc-7"></a>

---

<!-- ============================== REGISTRE-CONFORMITE-ISO27001.md ============================== -->

# Registre de conformité ISO/IEC 27001:2022 — SIEM OMNITECH

*Version 1.0 — 12/06/2026 — Périmètre : supervision, journalisation et
détection assurées par le SIEM Graylog `bx-it-graylog-vm`. Classification : interne.*

Légende statut : ✅ Conforme · 🟡 Partiel (action en cours) · ⬜ À traiter.

## 1. Mesures organisationnelles (A.5)

| Mesure A.5 | Exigence | Mise en œuvre (preuve) | Statut |
|---|---|---|---|
| 5.7 Renseignement sur les menaces | Threat intelligence | Lookups Tor/Spamhaus, GeoIP, règles `threat_intel` | ✅ |
| 5.15 Contrôle d'accès | Restreindre l'accès | Console restreinte « Admins du domaine » via LDAPS (LDAPS.md), pare-feu hôte | ✅ |
| 5.16 Gestion des identités | Identités traçables | Auth AD nominative sur la console (backend LDAPS) | ✅ |
| 5.17 Authentification | Secrets gérés | LDAPS + `admin` local de secours au coffre ; secrets chmod 600 | ✅ |
| 5.18 Droits d'accès | Moindre privilège | Comptes de service dédiés (svc_siem), pas de collecte sous compte admin | ✅ |
| 5.23 Sécurité des services cloud | Surveillance du cloud | Collecte M365 (connexions, audit, Exchange/SharePoint) | ✅ |
| 5.25 Appréciation des événements | Qualifier/classer | Triage PRO §3, classification PRO §7, 88 définitions priorisées | ✅ |
| 5.26 Réponse aux incidents | Procédure + réponse | Playbooks PRO §6, matrice RACI §8, **SOAR-light** (blocage auto IP attaquantes via feed FortiGate) | ✅ |
| 8.16 (détection interne) | Détecter l'intrusion | **Compte canari AD** (leurre, faux positifs ~nuls) | ✅ |
| 5.28 Collecte de preuves | Preuves exploitables | Journaux horodatés UTC, export Graylog, rétention contrôlée (STD §9) | ✅ |
| 5.33 Protection des enregistrements | Intégrité des logs | Rétention auto, suppression hors-rétention impossible sans droits, purge tracée | ✅ |
| 5.36 Conformité aux politiques | Revue régulière | Revues PRO §2 + **rapport hebdomadaire automatique** (preuve) | ✅ |

## 2. Mesures liées aux personnes (A.6)

| Mesure | Exigence | Mise en œuvre | Statut |
|---|---|---|---|
| 6.3 Sensibilisation | Information | Charte informatique (journalisation), POL §11 | 🟡 (charte hors SIEM) |
| 6.8 Signalement d'événements | Remontée | Notifications mail + Teams SOC vers l'équipe IT | ✅ |

## 3. Mesures physiques (A.7)

| Mesure | Exigence | Mise en œuvre | Statut |
|---|---|---|---|
| 7.4 Surveillance physique | — | Hors périmètre SIEM (logs contrôle d'accès/NVR collectés via FortiGate) | 🟡 |

## 4. Mesures technologiques (A.8) — cœur du dispositif

| Mesure A.8 | Exigence | Mise en œuvre (preuve) | Statut |
|---|---|---|---|
| 8.5 Authentification sécurisée | Auth robuste console | LDAPS/TLS, cert vérifié par Root CA, accès limité aux admins | ✅ |
| 8.6 Gestion des capacités | Dimensionner/surveiller | Plan de capacité (STD §5), garde-fou disque `32`, KPI hebdo | ✅ |
| 8.7 Protection contre les codes malveillants | Détecter | FortiGate UTM (AV/IPS), Defender, règles ransomware/PowerShell/LSASS | ✅ |
| 8.8 Gestion des vulnérabilités techniques | — | OpenVAS (logs collectés) ; patching hors SIEM | 🟡 |
| 8.9 Gestion de configuration | Config maîtrisée | **IaC** : scripts 10→34 idempotents, sauvegarde de config quotidienne | ✅ |
| 8.10 Suppression d'informations | Effacement à terme | Rétention automatique par index (POL §4, `31`) | ✅ |
| 8.12 Prévention fuite de données | Détecter exfiltration | M365 (partage externe, transfert mail), FortiGate (threat intel sortant) | ✅ |
| 8.13 Sauvegarde | Sauvegarder/tester | Sauvegarde config chiffrée externalisée (`30`), PRA, **test à réaliser** | 🟡 |
| 8.15 Journalisation | Produire/protéger les logs | 7 inputs, 13 streams, 144 règles de pipeline, rétention POL §4, STD complet | ✅ |
| 8.16 Activités de surveillance | Surveiller/alerter | **88 définitions** (87 détections + 1 système), dashboard 24 pages, notifications, auto-surveillance | ✅ |
| 8.17 Synchronisation des horloges | Horloge commune | NTP sur toutes les sources, UTC dans le SIEM (STD §7) | ✅ |
| 8.20 Sécurité des réseaux | Cloisonner | VLAN 220 dédié, règles FortiGate par flux, pare-feu hôte | ✅ |
| 8.23 Filtrage web | — | FortiGate webfilter/DNS filter (logs collectés) | ✅ |
| 8.28 Codage sécurisé | — | Hors périmètre (logs CI/CD non couverts) | ⬜ |

## 5. Synthèse des actions ouvertes

| # | Action | Réf | Responsable | Échéance |
|---|---|---|---|---|
| 1 | Faire signer la POL par la DSI | POL §12 | DSI | — |
| 2 | Réaliser le test de restauration (PRA) | PRA, A.8.13 | Admin SIEM | Trimestre en cours |
| 3 | Décaler le job Veeam *Backup Copy* (contention de verrou de point de restauration ; la sauvegarde **aboutit au retry**, pas un trou de PRA) | Détection Veeam | Admin Sys | — |
| 4 | Étendre la collecte aux serveurs Windows restants + activer les SACL d'audit fichier sur les dossiers sensibles | STD §1 / `59` | Admin Sys | — |
| 5 | Chiffrement au repos `/data` (LUKS2/TPM2) | A.8.24, PROCEDURE-CHIFFREMENT | Admin SIEM | ✅ **Fait le 2026-06-14** |
| 6 | Affecter les comptes analystes au rôle Graylog « lecture seule » (créé) | A.8.2 | Admin SIEM | — |
| 7 | Activer l'API NinjaOne → SOAR avancé (isolation hôte / désactivation compte) | SOAR-PLAYBOOKS | Admin SIEM | — |
| 8 | Lier la charte informatique (sensibilisation 6.3) | A.6.3 | DSI | — |

> *Clôturé 2026-06-14* : Compte canari AD (en production, cf. §1 A.8.16 + REPONSE-AUTOMATISEE) ; création du rôle Graylog lecture seule (action #6 = affectation des comptes restante) ; intégrité/valeur probante des journaux (registre haché-signé).

## 6. Méthode de preuve pour l'auditeur

| Question type auditeur | Où montrer la preuve |
|---|---|
| « Que journalisez-vous ? » | STD §1 + §3bis (matrice EventID) |
| « Combien de temps ? Pourquoi ? » | POL §4 (rétentions justifiées CNIL/ANSSI) |
| « Comment détectez-vous ? » | DOSSIER §6 (88 définitions) + dashboard live |
| « Qui traite, en combien de temps ? » | PRO §2/§3/§7 + registre de traitement |
| « Prouvez la revue régulière » | Rapport hebdo (mail + copie `/var/backups/siem/`) |
| « Et si le SIEM tombe ? » | PRA + sauvegarde quotidienne + alerte d'absence |
| « Qui accède au SIEM ? » | LDAPS.md (restriction admins) + logs d'accès console |
| « Intégrité des preuves ? » | STD §9 + purge tracée/alertée |

*Revue de ce registre : à chaque audit interne et au minimum annuellement.*

## 7. Journal de maintenance (preuves d'exploitation A.8.15 / A.8.16 / A.8.17)

| Date | Action | Justification / portée | Contrôle |
|---|---|---|---|
| 2026-06-14 | **Purge des index de logs** (données + historique d'alertes ; **configuration conservée**) | Action de **maintenance planifiée** : remise à zéro après tuning anti-faux-positifs (le jeu de données initial était pollué par des FP de comptes de service/machine et des scripts internes légitimes). Reconstitution propre via `54-post-purge-repopulate.sh`. Coupure de collecte : nulle (ingestion reprise immédiatement dans des index vides). | A.8.15 (rupture d'audit-trail tracée et justifiée) |
| 2026-06-14 | **Correctif horodatage FortiGate** : `timestamp` posé depuis `eventtime` (epoch ns) | Avant : Graylog repliait sur l'heure de réception (+ ~14k erreurs/j). Après : **heure d'événement exacte** (écart résiduel 0,2 s) ; erreurs supprimées. | A.8.17 (synchronisation horaire / exactitude des horodatages) |
| 2026-06-14 | **Audit de dérive d'horloge inter-sources** (read-only) | Écart heure-événement / heure-réception mesuré par source : FortiGate 0,2 s, vSphere 1 s, Windows/Sysmon 5-7 s, BunkerWeb 7,6 s — **toutes < 8 s** (seuil 60 s). SIEM : NTP actif/synchronisé. **Aucune dérive significative.** | A.8.17 |
| 2026-06-14 | **Réduction des faux positifs** (audit multi-agent) + **routage 2-tiers des alertes** (mail = critique only, Teams = firehose) | Améliore la pertinence de la détection (A.8.16) et garantit que les alertes critiques ne sont pas noyées (preuve de revue exploitable). | A.8.16 / A.5.25 |
| 2026-06-14 | **Intégrité / valeur probante des journaux** : registre haché-en-chaîne signé HMAC (`60-integrity.sh`), copie hors-bande SMB, vérification hebdo + alerte sur rupture de chaîne ; **rôle Graylog lecture seule** (moindre privilège) | Fait passer la protection des journaux de « écriture seule » à **inaltérabilité prouvable** (tamper-evidence) ; réduit la surface de manipulation par les comptes privilégiés. | A.8.15 / A.8.2 / A.5.28 |
| 2026-06-14 | **Couverture MITRE ATT&CK cartographiée** (44 techniques / 12 tactiques sur 14) + nouvelles détections (privilege escalation, M365 risk/brute, audit fichiers 4663/5145, intégrité, exposition Internet) | Mesure et extension explicites de la couverture de détection ; aide à la priorisation. | A.8.16 / A.5.7 |
| 2026-06-14 | **Purge d'hygiène Vaultwarden** : ~46 M documents de rejeu mal routés supprimés (Filebeat rejouait l'historique du conteneur 2023→2026) ; règle de drop ajoutée + **index set dédié** | Restaure la qualité des agrégats de détection ; les événements internes/Windows réels sont préservés ; rupture d'audit-trail tracée et justifiée. | A.8.15 |
| 2026-06-14 | **Chiffrement au repos `/data` RÉALISÉ** (LUKS2 inline, aes-xts 512 bits + déverrouillage TPM2/PCR7). Méthode : reformatage chiffré à neuf — les logs indexés ont été repurgés puis repeuplés (ingestion live + `54`), toute la config (MongoDB, scripts, lookups) étant hors `/data` est intégralement préservée. Header sauvegardé chiffré hors-bande (SMB `/SIEM/luks/`), passphrase de secours au coffre, déverrouillage auto TPM2. | Protège les données au repos contre le vol de disque / mise au rebut / SAV / vol du serveur éteint. | A.8.24 / A.5.33 |

*Limites connues (backlog durcissement) : **chiffrement au repos `/data` — réalisé le 2026-06-14** (procédure validée) ; flux syslog ESET/vSphere/FortiGate en clair sur le VLAN SIEM isolé (migration syslog-over-TLS à étudier) ; SOAR avancé (isolation hôte / désactivation compte) en attente de l'API NinjaOne.*


<a id="doc-8"></a>

---

<!-- ============================== PRA-RECONSTRUCTION-SIEM.md ============================== -->

# PRA — Plan de reconstruction du SIEM sur un nouveau serveur

*Version 1.0 — 12/06/2026 — Classification : interne — Réf ISO A.8.13, A.5.30*

Ce document décrit la **remise en service du SIEM sur un serveur de
remplacement** en cas de perte de la VM `bx-it-graylog-vm`. Il complète la
procédure technique détaillée `RESTORE.md` (commandes exactes) par le cadre
de continuité : objectifs, scénarios, rôles, validation.

## 1. Objectifs de continuité

| Indicateur | Valeur cible | Justification |
|---|---|---|
| **RTO** (reprise de la collecte) | ≤ 4 h | après mise à disposition d'une VM conforme |
| **RPO config** (perte de configuration) | ≤ 24 h | sauvegarde quotidienne 03:15 |
| **RPO logs** (perte d'historique) | jusqu'à la dernière rétention | les **journaux ne sont pas sauvegardés** (choix assumé : volume) — seule la configuration l'est |

**Conséquence clé** : après reconstruction, toute la chaîne de collecte, les
détections, dashboards et alertes reprennent à l'identique ; l'historique des
logs antérieurs est perdu mais la collecte temps réel redémarre immédiatement
(les agents/forwarders pointent sur le même FQDN/IP).

## 2. Pré-requis disponibles en permanence (à vérifier maintenant)

| Élément | Emplacement | Vérifié |
|---|---|---|
| Archives de config chiffrées (14 j) | `\\10.33.50.5\Public\SIEM\omni-siem-config_*.tar.gz.enc` | rotation OK |
| **Passphrase de déchiffrement** | Coffre-fort (`BACKUP_PASSPHRASE`) | ⚠️ À DÉPOSER AU COFFRE |
| Mot de passe `admin` local de secours | Coffre-fort | ✅ |
| Identifiants `svc_siem` (SMB) | Coffre-fort | ✅ |
| Procédure technique | `RESTORE.md` (inclus dans l'archive) | ✅ |
| Réservation IP/DNS `10.33.220.10` / FQDN | DNS interne + /etc/hosts | ✅ |
| **Clé HMAC d'intégrité** `/etc/graylog/omni-integrity.key` | Coffre-fort + hors-bande | ⚠️ sans elle, la chaîne d'intégrité passée n'est plus **vérifiable** (perte de valeur probante) |
| **Passphrase de secours LUKS `/data`** + **sauvegarde chiffrée du header** (header **inline** ; `omni-luks-header-*.img.enc`) | Passphrase → Coffre-fort ; header → SMB `/SIEM/luks/` (+ inclus dans le backup config chiffré quotidien) | ⚠️ sans la **passphrase**, `/data` est irrécupérable si le TPM/carte mère change ; le header inline est **sauvegardé/restaurable** (`luksHeaderRestore`) |

> Sans la passphrase de sauvegarde, les archives sont **irrécupérables**.
> Idem pour la **clé HMAC d'intégrité** (vérification de l'audit-trail) et la
> **passphrase/header LUKS** (déchiffrement de `/data` sur nouveau matériel — le
> TPM est lié à la carte mère, ré-enrôlement requis au remplacement). Ces 4 secrets
> sont les points de défaillance unique du PRA : présence au coffre vérifiée à
> chaque revue trimestrielle.

## 3. Scénarios et déclenchement

| Scénario | Réponse |
|---|---|
| VM corrompue / disque système perdu, `/data` intact | Reconstruire l'OS + pile, restaurer la config, **re-pointer `/data`** (logs conservés) |
| Perte totale (VM + données) | Reconstruction complète, logs repartent de zéro |
| Indisponibilité temporaire (service planté) | Pas de PRA : `systemctl restart` ; cf. PRO §4 |

Déclenchement : décision de l'**Admin SIEM** (incident d'exploitation) ou de
la **DSI** (sinistre majeur). Prévenir l'équipe IT (les alertes vont cesser
pendant la bascule).

## 4. Procédure de reconstruction (résumé — détail dans RESTORE.md)

1. **Provisionner** une VM Debian 12+, **même hostname/IP** (`bx-it-graylog-vm`
   / 10.33.220.10), VLAN 220, disque data sur `/data`.
2. **Installer la pile** aux versions de référence (DOSSIER §2 : Graylog
   7.1.3, OpenSearch 2.19.5, MongoDB 8.0.24, nginx) + `cifs-utils`.
3. **Récupérer et déchiffrer** la dernière archive depuis le partage SMB
   (compte `svc_siem`, passphrase du coffre).
4. **Restaurer** : fichiers `/etc` (graylog, opensearch, nginx, systemd),
   `/usr/local/sbin`, kit `/kit`, IaC `~/omnitech-siem-setup`, puis
   `mongorestore` de la base `graylog` (gestion de l'auth Mongo : RESTORE §4).
5. **Démarrer** mongod → opensearch → graylog-server → nginx ; réactiver les
   timers `omni-*`.
6. **Vérifier** (cf. §5).

## 5. Validation post-reconstruction (checklist)

- [ ] Console accessible en HTTPS, login AD (LDAPS) **et** `admin` local OK.
- [ ] Inputs à l'écoute : `ss -tlnp | grep -E "5044|1514|1516|12201"`.
- [ ] Les agents Winlogbeat se reconnectent (recherche `source:*` < 5 min).
- [ ] FAZ et vSphere émettent (streams FortiGate / vSphere alimentés).
- [ ] Collecteurs M365 : timers actifs, dernier run OK.
- [ ] 88 définitions d'événements présentes et **activées**.
- [ ] Dashboard « OMNI - SOC » s'affiche (24 pages).
- [ ] Sauvegarde : `bash 30-backup-config.sh` réussit (dépôt SMB).
- [ ] Une notification de test arrive par mail **et** Teams.
- [ ] `/data` : indices présents (si conservés) ou recréés ; rétentions OK.

## 6. Bascule et communication

- Pendant la reconstruction, **aucune alerte n'est émise** : surveiller
  manuellement les points critiques (AD, VPN) via les consoles natives
  (FortiGate, Entra) jusqu'au rétablissement.
- À la fin : informer l'équipe IT du rétablissement ; consigner l'incident
  et le temps de reprise réel (mesure du RTO) dans le registre d'incidents.

## 7. Maintien en condition du PRA

| Action | Fréquence |
|---|---|
| Vérifier la présence des 14 archives sur le partage | Mensuelle (PRO §2) |
| Vérifier la passphrase et les secrets au coffre | Trimestrielle |
| **Test de restauration réel sur VM jetable** | ≥ 1×/an (exigence A.8.13) |
| Mettre à jour les versions de référence (DOSSIER §2) | À chaque montée de version |

Un PRA non testé n'est pas un PRA : le test annuel est **obligatoire** et son
compte-rendu est conservé comme preuve d'audit.


<a id="doc-9"></a>

---

<!-- ============================== ISO27001-MAPPING.md ============================== -->

# Cartographie SIEM ↔ ISO/IEC 27001:2022 (Annexe A)

> **Objet.** Ce document fait le pont entre les capacités techniques du SIEM
> OMNITECH et les contrôles de l'Annexe A d'ISO/IEC 27001:2022. Pour chaque
> contrôle pertinent : ce que le SIEM apporte, et **où se trouve la preuve**
> (documented information) pour l'auditeur. Il sert de base à la rédaction des
> documents formels du SMSI (politiques, procédures, enregistrements).
>
> **Statut :** support technique au SMSI — à valider/approuver par le RSSI.
> **Périmètre :** SIEM Graylog (collecte, détection, corrélation, supervision)
> du système d'information OMNITECH Security.

## 1. Tableau de correspondance (contrôle → apport SIEM → preuve)

| Contrôle Annexe A (2022) | Intitulé | Apport du SIEM | Preuve / emplacement |
|--------------------------|----------|----------------|----------------------|
| **A.8.15** | Journalisation | Collecte centralisée et inviolable des journaux de l'ensemble des sources (AD/Sysmon, FortiGate, Microsoft 365/Entra, vSphere, Veeam, **ESET PROTECT**, **WAF BunkerWeb**, télémétrie interne SIEM) ; horodatage ; protection en écriture seule | Streams Graylog (13 streams) ; `docs/POLITIQUE-RETENTION.md` ; `docs/INVENTAIRE-SOURCES.md` |
| **A.8.16** | Surveillance des activités | 88 définitions (87 détections + 1 système) actives, tableaux de bord temps réel (« OMNI - SOC », 24 pages), anomalies comportementales (UEBA), surveillance réseau (NDR) | Dashboard « OMNI - SOC » ; `docs/REGISTRE-DETECTIONS.md` ; alertes Graylog |
| **A.8.17** | Synchronisation des horloges | Tous les hôtes et le SIEM synchronisés NTP sur le PDC ; horodatage cohérent des événements | Conf NTP (`00-vars.env` NTP1/NTP2) ; champ `timestamp` |
| **A.5.7** | Renseignement sur les menaces | Threat intel (Tor/Spamhaus), CISA KEV (vulnérabilités exploitées), détections ESET PROTECT (menaces/IoC endpoint), mapping MITRE ATT&CK | Pages « ATT&CK », « Vulnérabilités », « Sources externes » ; lookup threat-intel ; `lookups/mitre-attack.csv` |
| **A.5.24** | Préparation à la gestion des incidents | Corrélation automatique des détections en **incidents** horodatés (kill-chain), priorisation P2/P3, notifications | Page « Incidents » ; `docs/PROCEDURE-INCIDENT.md` ; `omni-incident-correlate` |
| **A.5.25** | Évaluation et décision sur les événements | Scoring de risque (MITRE + UEBA 0-100), sévérité, file de triage | KPIs « Incidents critiques », « Entités à risque » ; score UEBA |
| **A.5.26** | Réponse aux incidents | Routage des notifications en **2 tiers** : Teams = firehose (toutes les alertes), e-mail = 26 alertes critiques « réveille-moi » (compromission confirmée + santé SIEM) ; SOAR-light (blocage auto d'IP attaquantes via threat-feed FortiGate) | Notifications Graylog ; `22-alert-routing.sh` ; `omni-soar` ; `docs/PROCEDURE-INCIDENT.md` ; `docs/REPONSE-AUTOMATISEE.md` |
| **A.5.27** | Tirer des enseignements des incidents | Rapport hebdo + rapport exécutif mensuel (tendances, top risques) ; historique requêtable | `omni-weekly-report`, `omni-monthly-report` ; archive `/kit/rapports/` |
| **A.5.28** | Collecte de preuves | Journaux conservés (dossier sécurité **365 j** ; FortiGate **180 j** ; BunkerWeb **90 j**), horodatés, inviolables ; message brut conservé pour le forensic | Index OpenSearch ; `docs/POLITIQUE-RETENTION.md` |
| **A.8.7** | Protection contre les logiciels malveillants | Détection Microsoft Defender (détection/désactivation), **EDR/antivirus ESET PROTECT** (menaces, événements HIPS), UTM FortiGate (virus/IPS), indicateurs ransomware | Alertes « Defender », « ESET : détection », « FortiGate virus/IPS », « Indicateur de ransomware » ; page « Sources externes » |
| **A.8.8** | Gestion des vulnérabilités techniques | Croisement inventaire logiciel × CISA KEV (CVE exploitées) + ancienneté des correctifs | Page « Vulnérabilités » ; `omni-vuln-scan` |
| **A.8.12** | Prévention de la fuite de données | Détection d'exfiltration : tunneling DNS (entropie), partages externes M365, transferts mail externes, pics de volume sortant | Alertes « Tunneling DNS », « M365 partage externe / transfert mail » ; page UEBA/NDR |
| **A.8.13** | Sauvegarde des informations | Supervision des sauvegardes Veeam (échecs/avertissements), snapshots | Page « Sauvegardes » ; alerte « Veeam job en échec » |
| **A.8.9** | Gestion des configurations | Sauvegarde quotidienne de la configuration du SIEM + garde-fou disque | Alertes « Backup config », « Disque >80% » |
| **A.5.23** | Sécurité des services cloud | Surveillance Microsoft 365 / Entra : connexions, pays, rôles, partages, OAuth | Pages « M365 », « M365 Activité » ; alertes M365 |
| **A.8.2 / A.8.3 / A.5.18** | Accès à privilèges / droits d'accès | Surveillance renforcée des comptes admin (adm-*), groupes privilégiés, privilèges spéciaux | Page « Comptes à privilèges » ; alertes « Groupe privilégié », « DCSync », « Kerberoasting » |
| **A.8.20 / A.8.21 / A.8.22** | Sécurité des réseaux | Trafic pare-feu, refus, géolocalisation, segmentation, beaconing C2 ; **WAF BunkerWeb** (filtrage applicatif HTTP, événements `http_*`/`waf_*`) en protection des services exposés | Pages « Réseau », « VPN & Exposition », « Cartographie », « WAF BunkerWeb » ; carte cyber temps réel ; classification des ports exposés |
| **A.8.16 (go-dark)** | Surveillance — continuité de la collecte | Détection des hôtes qui cessent d'émettre (panne ou sabotage) + couverture SLA ; auto-supervision des robots d'analyse | Page « Santé collecte » ; `omni-collect-health`, `omni-self-health` |
| **A.5.10 / A.8.10** | Usage acceptable / suppression d'information | Détection canari (compte/fichier leurre), suppression de VM, sabotage des journaux d'audit | Alertes « Compte canari », « Sabotage de l'audit », « vSphere suppression VM » |

## 2. Intégrité et protection des journaux (exigence transverse A.8.15)

- **Inviolabilité / valeur probante** : index OpenSearch en écriture seule **+
  registre d'intégrité haché-en-chaîne signé HMAC** (`60-integrity.sh` →
  `omni-integrity`) : empreinte quotidienne de l'état du corpus, **copie hors-bande
  (partage SMB)**, vérification hebdomadaire (`--verify`) et **alerte si la chaîne
  est rompue** → toute suppression/altération rétroactive devient **prouvable**
  (tamper-evidence). Cf. `docs/PROCEDURE-INTEGRITE-PREUVE.md` (A.8.15 / A.5.28).
- **Moindre privilège (A.8.2 / A.8.3)** : rôle Graylog « OMNI - Analyste (lecture
  seule) » pour les analystes ; compte admin (seul habilité à supprimer) réservé
  en **break-glass** (MDP au coffre).
- **Chiffrement au repos (A.8.24 / A.5.33)** : volume `/data` chiffré **LUKS2 +
  déverrouillage TPM2** (header inline, `aes-xts` 512 bits) — **réalisé le 2026-06-14**,
  cf. `docs/PROCEDURE-CHIFFREMENT-REPOS.md`.
- **Détection de l'altération** : règle « Sabotage de l'audit » (Event ID
  1102/4719/4794/104) en P3 + **alerte « Intégrité des logs COMPROMISE »** → alerte
  immédiate (mail) si quelqu'un efface/désactive la journalisation ou rompt la chaîne.
- **Contrôle d'accès** : console SIEM restreinte par LDAPS + groupe AD dédié ;
  OpenSearch en écoute localhost uniquement.
- **Disponibilité** : journal tampon Graylog (si OpenSearch indisponible) ;
  garde-fou disque (purge contrôlée à 80 %, jamais de saturation — disque `/data`
  dédié de 7,3 To).
- **Sauvegarde** : configuration du SIEM sauvegardée quotidiennement (chiffrée).
- **Index sets dédiés** : chaque source dispose de son propre index set avec
  rétention différenciée (sécurité 365 j ; FortiGate 180 j ; BunkerWeb 90 j),
  garantissant un cloisonnement et une politique de conservation explicite.

## 3. Documents formels ISO à dériver (à générer ensuite)

Ce corpus technique permet de rédiger les documents normatifs suivants :

1. **Politique de journalisation et de surveillance** ← `POLITIQUE-RETENTION.md`
   + ce mapping (A.8.15/8.16/8.17).
2. **Procédure de gestion des incidents** ← `PROCEDURE-INCIDENT.md`
   (A.5.24–5.28).
3. **Procédure d'exploitation du SIEM** ← `PROCEDURE-EXPLOITATION-SIEM.md`.
4. **Registre des actifs surveillés / sources** ← `INVENTAIRE-SOURCES.md`
   (alimente l'inventaire des actifs A.5.9).
5. **Registre des règles de détection** ← `REGISTRE-DETECTIONS.md`.
6. **Enregistrements de preuve** (records) : rapports mensuels/hebdo archivés,
   historique des alertes, tableaux de bord (A.5.28).

## 4. Déclaration d'applicabilité (SoA) — note

Les contrôles ci-dessus sont **mis en œuvre** (au moins partiellement) par le
SIEM. La SoA du SMSI doit référencer le SIEM comme moyen de mise en œuvre pour
ces contrôles, et ce document comme preuve de couverture.

---
*Support technique au SMSI OMNITECH — à valider et dater par le RSSI.
Dernière revue : **2026-06-14**. Voir aussi `GUIDE.md` (vue d'ensemble),
`CONTEXT.md` (détail d'implémentation), `INVENTAIRE-SOURCES.md` (actifs A.5.9),
`REGISTRE-DETECTIONS.md` (règles A.8.16) et `POLITIQUE-RETENTION.md` (durées).*


<a id="doc-10"></a>

---

<!-- ============================== REGISTRE-DETECTIONS.md ============================== -->

# Registre des règles de détection — SIEM OMNITECH

> Catalogue **exhaustif** des **88 définitions d'événements** actives (alertes
> Graylog ; 87 règles d'agrégation + 1 événement système), classées par domaine.
> Sert de preuve de couverture de surveillance (ISO 27001 **A.8.16**) et de
> référence d'exploitation. *Dernière revue : 2026-06-14 (recoupé live).*
>
> **Priorités** : **P3 = critique** (action immédiate) · **P2 = important** (à
> traiter rapidement). **Tier** de notification : **M** = e-mail « réveille-moi »
> (compromission confirmée / santé SIEM) · **T** = Teams (firehose, toutes les
> alertes). Anti-tempête par entité (`group_by`), grâce ≥ 60 min sur le tier mail.
>
> Source de vérité : définitions Graylog (`13-graylog-alerts.sh`, `16-m365-input.sh`,
> `21-alert-hygiene.sh`, `36-soar.sh`, `47-detections-extra.sh`, `48`, modules 37-46,
> `59-file-audit.sh`, `60-integrity.sh`). Tag MITRE via `lookups/mitre-attack.csv`.

## Répartition

| Priorité | Nombre | Tier mail | Tier Teams |
|----------|--------|-----------|------------|
| P3 (critique) | 54 | — | — |
| P2 (important) | 33 | — | — |
| **Total agrégation** | **87** | **26 (mail)** | **87 (Teams)** |

> Toutes les alertes vont à **Teams** (firehose) ; **26** critiques vont **aussi**
> au mail (cf. `KEEP[]` de `22-alert-routing.sh`). Au-delà des définitions, des
> **tags d'enrichissement** posés au pipeline n'ont pas d'alerte dédiée (anti-bruit) :
> `persistence_autorun` (T1547.001), `remote_discovery` (T1018), `service_stop_securite`
> (T1489), `threat_intel`, `explicit_cred_use` — visibles en investigation/dashboards.

---

## 1. Identité & Active Directory (A.8.2 / A.8.5 / A.5.18)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Force brute (≥10 échecs / compte / 10 min) | P3 | T | 4625 agrégé par compte (exclut `*$`/ninjaone/ADSync) | T1110 |
| Password spraying (≥8 comptes / IP / 10 min) | P3 | T | 4625, `card(user)` par IP | T1110.003 |
| Force brute SUIVIE d'un succès (même compte / 15 min) | P3 | **M** | 4625 puis 4624 | T1110 |
| Tentative sur compte désactivé | P2 | T | échec motif `compte_desactive` | T1078 |
| Compte verrouillé (4740) | P2 | T | verrouillage AD (effet spraying) | — |
| Compte créé dans le domaine (4720) | P2 | T | création de compte AD | T1136.002 |
| Création de compte LOCAL (4720 hors DC) | P2 | T | compte local hors contrôleur | T1136.001 |
| Ajout au groupe Administrateurs LOCAL (4732) | P2 | T | élévation locale | T1098 |
| Modification d'un groupe privilégié | P3 | T | 4728/4732/4756 (`priv_group_label`) | T1098 |
| DCSync suspect | P3 | **M** | 4662 GUID réplication DS | T1003.006 |
| Kerberoasting suspect (≥5 SPN / compte / 10 min) | P3 | T | 4769 RC4/anormaux | T1558.003 |
| Kerberos RC4 / downgrade | P3 | T | `kerberos_rc4` (downgrade chiffrement) | T1558.003 |
| AS-REP roasting (compte sans pré-auth) | P3 | T | 4768 `PreAuthType=0` | T1558.004 |
| Shadow Credentials (msDS-KeyCredentialLink) | P3 | T | modif clé d'authentification | T1556.005 |
| Abus AD CS / certificats (ESC1-ESC8) | P3 | T | `adcs_abuse` | T1649 |
| Accès credentials GPP/SYSVOL | P3 | T | `gpp_creds_access` | T1552.006 |
| Reconnaissance LDAP (énumération annuaire) | P3 | T | `ldap_recon` | T1087.002 |
| Modification de GPO par un humain (5136) | P3 | T | `groupPolicyContainer`, hors SYSTEM/`*$` | T1484.001 |
| Connexion compte admin (adm-*) hors heures ouvrées | P3 | T | 4624 adm-* + `off_hours:oui` | T1078 |
| Échec logon service/batch (compte de service cassé) | P3 | T | 4625 LogonType 4/5 | — |
| Balayage de partages admin (≥3 hôtes / compte / 15 min) | P3 | T | 5140 `card(host)` | T1021.002 |

## 2. Endpoint & exécution / élévation (A.8.7)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Accès mémoire LSASS (vol de credentials) | P2 | T | Sysmon 10 → lsass.exe | T1003.001 |
| Injection de processus (Sysmon 8/25) | P2 | T | CreateRemoteThread / tamper | T1055 |
| PowerShell suspect | P2 | T | 4104 encodé / `-enc` / FromBase64 | T1059.001 |
| LOLBin suspect (binaire système détourné) | P2 | T | certutil/regsvr32/rundll32/mshta/bitsadmin | T1218 |
| Masquerading (binaire système déplacé/renommé) | P2 | T | nom légitime hors chemin attendu | T1036.005 |
| Usage de credentials explicites (RunAs / lateral) | P2 | T | 4648 hors `*$`/self | T1078 |
| Exécution à distance WMI (lateral) | P2 | T | `wmi_lateral_exec` | T1047 |
| **Contournement UAC (élévation)** | P3 | **M** | Sysmon 1 : fodhelper/eventvwr/sdclt… → shell | T1548.002 |
| Defender : détection ou désactivation | P3 | T | Defender Operational (détection/AV off) | T1562.001 |
| Indicateur de ransomware (suppression shadow copies) | P3 | **M** | vssadmin/wmic shadow delete | T1490 / T1486 |
| Nouveau service installé (7045) | P2 | T | service système hors agents connus | T1543.003 |
| Service Windows installé (hors svchost) | P2 | T | 4697 hors svchost légitime | T1543.003 |
| Tâche planifiée créée (4698) | P2 | T | `scheduled_task`, agrégé hôte+compte | T1053.005 |

## 3. Réseau, VPN & exposition (A.8.20–A.8.22 / A.5.7)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| IP malveillante (Tor / Spamhaus) | P3 | T | threat-intel lookup sur IP publique | T1071 |
| FortiGate : virus / IPS | P3 | T | UTM (virus/ips/attack) | — |
| Service exposé sur Internet (port à risque) | P3 | T | `exposition_internet` (WAN→port risqué accepté) | T1190 |
| Force brute portail VPN (≥30 échecs / IP / h) | P2 | T | `subtype:vpn status:failure` → **SOAR** | T1110 |
| VPN monté depuis l'étranger | P3 | T | tunnel `remip` hors FR | T1133 |
| Scan réseau interne (reconnaissance / lateral) | P2 | T | `ndr_scan` / `network_scan` | T1046 |
| SOAR : IP bloquée automatiquement | P3 | T | action `omni-soar` (telemetry) | — |

## 4. Cloud Microsoft 365 / Entra (A.5.23)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Compte M365 à risque (Entra ID Protection) | P3 | **M** | `m365_type:risk` atRisk (ML Microsoft), agrégé compte | T1078 |
| M365 connexion réussie hors France | P3 | T | `m365_etranger` (signin réussi non-FR) | T1078 |
| M365 modification de rôle privilégié | P3 | T | `m365_role` (rôle admin Entra) | T1098 |
| M365 transfert mail vers domaine externe | P3 | **M** | `m365_mail_forward` | T1114.003 |
| M365 délégation de boîte mail | P2 | T | `m365_mailbox_deleg` | T1098.002 |
| M365 partage externe / lien anonyme | P2 | T | `m365_partage_externe` | T1567 |
| M365 consentement OAuth applicatif | P2 | T | `m365_oauth_consent` | T1528 |
| M365 force brute (≥10 échecs / compte / 30 min) | P2 | T | signin échec agrégé compte | T1110 |
| Brute force M365 depuis l'étranger (spray cloud) | P2 | T | `m365_brute_externe` (échec non-FR / IP+compte) | T1110 |
| M365 suppression massive de fichiers (≥100 / compte / 15 min) | P2 | T | FileDeleted/Recycled | T1485 |
| Échecs AD + connexion M365 étrangère (même compte / 1 h) | P3 | T | corrélation 4625 + `m365_etranger` | T1078 |

## 5. UEBA / NDR / corrélation (A.5.7 / A.8.16)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Incident critique (kill-chain corrélée) | P3 | **M** | `omni-incident-correlate` (multi-étapes) | — |
| Impossible travel (compte multi-localisé) | P3 | **M** | `ueba_geo` impossible travel | T1078 |
| Nouveau pays pour un compte (first-seen) | P3 | T | `ueba_geo` new_country | T1078.004 |
| Mouvement latéral réussi (1 compte → N hôtes) | P3 | **M** | `lateral_movement` (card host) | T1021 |
| Tunneling DNS suspect (exfiltration) | P3 | T | `ndr_dns` (entropie/sous-domaines) | T1071.004 |
| Anomalie de volume (z-score) | P3 | T | `volume_spike`/`volume_drop` | T1048 / T1562.001 |
| Hôte à risque élevé (score MITRE ≥15 / 1h) | P2 | T | somme `risk_score` par hôte | — |
| Entité à risque UEBA élevé (≥80) | P2 | T | `ueba_score` ≥ 80 | — |
| Beaconing / C2 suspect (NDR) | P2 | T | `ndr_beacon` (intervalle régulier) | T1071 |
| Exfiltration par volume (flux sortant anormal) | P2 | T | `ndr_exfil` / `data_exfil` | T1048 |

## 6. Coffre-fort, WAF, EDR & fichiers sensibles (A.8.7 / A.8.12 / A.5.23)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Brute force coffre Vaultwarden (≥10 échecs / IP / 15 min) | P3 | **M** | `vault_auth_fail` (src_ip + compte) | T1555.005 |
| ESET : détection/menace antivirus | P2 | **M** | `eset_detection` (menace poste/serveur) | T1204 |
| BunkerWeb : pic de blocages WAF (≥20 / IP / 10 min) | P3 | T | `waf_block` agrégé IP | T1190 |
| WAF : scan applicatif (≥25 erreurs 404 / IP / 10 min) | P3 | T | HTTP 404 répétés / IP | T1190 |
| Accès massif à des fichiers sensibles (exfiltration ?) | P3 | **M** | `file_sensitive_access` ≥200 / compte / 10 min | T1039 |
| Suppressions massives de fichiers (ransomware ?) | P3 | **M** | `file_delete_sensible` ≥30 / compte / 10 min | T1485 |

## 7. Virtualisation vSphere (A.8.9)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| vSphere brute force (≥5 échecs / source / 10 min) | P2 | T | `vsphere_auth_fail` par src_ip | T1110 |
| vSphere accès SSH/Shell ESXi | P2 | T | `vsphere_shell_ssh` (ESXi shell — cf. note source) | T1059 |
| vSphere suppression de VM | P3 | T | `vsphere_vm_destroy` | T1485 |

## 8. Vulnérabilités, PKI & leurre (A.8.8 / A.8.16)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Vulnérabilité KEV exploitée (à patcher en urgence) | P3 | T | `vuln_kev` (CISA Known Exploited) | T1190 |
| COMPTE CANARI touché (intrusion AD probable) | P3 | **M** | leurre AD (faux positifs ~nuls) | T1078 (decoy) |
| Certificat du parc expire bientôt | P3 | **M** | `cert_parc` (Get-OmniCertExpiry) | — |
| Certificat SIEM expire bientôt (<45j) | P3 | **M** | `siem_cert` auto-renouv. | — |

## 9. NPS / RADIUS (A.8.5)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| NPS : refus d'accès en masse (≥10 / compte / 15 min) | P3 | T | 6273/6274 (Wi-Fi/VPN RADIUS) | T1110 |

## 10. Santé SIEM, intégrité & exploitation (A.8.15 / A.8.16 / A.8.13)

| Règle | Prio | Tier | Logique | Contrôle |
|-------|------|------|---------|----------|
| Sabotage de l'audit (1102/4719/4794/104) | P3 | **M** | effacement/désactivation journalisation | A.8.15 / T1562.002 |
| **Intégrité des logs COMPROMISE (chaîne rompue)** | P3 | **M** | `siem_integrity` `integrity_state:compromis` | A.8.15 / A.5.28 |
| Silence Winlogbeat (0 log Windows / 15 min) | P3 | **M** | absence de flux Windows | A.8.16 (go-dark) |
| Hôte go-dark (collecte interrompue >26h) | P2 | T | `collecte_sla` `sla_type:go_dark` | A.8.16 |
| Robot d'analyse en panne (auto-supervision) | P3 | **M** | `siem_health` job_fail | A.8.16 |
| Disque SIEM >80% (/data) | P3 | **M** | `disk_warn` | A.8.6 (capacité) |
| PURGE D'URGENCE rétention (disque presque plein) | P3 | **M** | `disk_guard_prune` (≥88% → 82%) | A.8.6 |
| Backup config SIEM absent (>26h) / en échec | P3 | **M** | `backup_config_*` | A.8.13 |
| Veeam : job en échec ou avertissement | P3 | **M** | `veeam_job_echec` (résultat final eid 190) | A.8.13 / T1490 |
| Rapport hebdomadaire en échec | P3 | **M** | `omni-weekly-report` | A.5.25 (revue) |

---

## Maintenance du registre
À chaque ajout/retrait de définition (`13`/`16`/`47`/`48`/`59`/`60`…) : mettre à
jour la table concernée + la répartition. Compteurs vérifiables en direct :
`GET /api/events/definitions` (total) et `22-alert-routing.sh` (sortie « MAIL
conservé sur N »). Couverture technique : cf. **COUVERTURE-MITRE-ATTACK.md** +
le calque `mitre-navigator-layer.json`.


<a id="doc-11"></a>

---

<!-- ============================== COUVERTURE-MITRE-ATTACK.md ============================== -->

# Couverture MITRE ATT&CK — SIEM OMNITECH

> Généré/maintenu avec `57-mitre-coverage.sh` · Dernière revue : 2026-06-14
> Calque visuel : **`docs/mitre-navigator-layer.json`** → à charger dans
> [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (*Open Existing Layer*).

## Résumé exécutif
- **58 tags de détection mappés MITRE** (sous-ensemble des **88 définitions d'événements** :
  les alertes de santé/exploitation — backup, disque, robots… — n'ont pas de technique ATT&CK)
  → **44 techniques** ATT&CK distinctes → **12/14 tactiques** couvertes.
  *(màj 2026-06-14 : + Privilege Escalation comblée [uac_bypass/scheduled_task/service_install], + `m365_brute_externe` T1110 [spray cloud, donnée réelle], + `remote_discovery` T1018, + `service_stop_securite` T1489 → Discovery 3, Impact 4.)*
- Chaque détection pose un `alert_tag` mappé technique + tactique + score de risque (`lookups/mitre-attack.csv`), réutilisé par le scoring d'hôte (UEBA), les alertes et les dashboards.
- Les 2 tactiques non couvertes (**Reconnaissance**, **Resource Development**) sont **hors périmètre** d'un SIEM défensif interne (scan externe pré-compromission / acquisition d'infra attaquant — non visibles côté défenseur). Couverture *effective* = complète.

## Couverture par tactique
| Tactique | Techniques | Exemples de détections |
|---|---|---|
| Initial Access | 3 | exposition_internet (T1190), m365_risque/impossible_travel (T1078), waf_block |
| Execution | 3 | powershell_suspect (T1059.001), defender (T1204.002), eset_detection |
| Persistence | 4 | persistence_autorun (T1547.001), local_account_create (T1136), m365_role (T1098) |
| **Privilege Escalation** | **3** | **uac_bypass (T1548.002), scheduled_task (T1053.005), service_install (T1543.003)** — *ajouté 2026-06-14* |
| Defense Evasion | 7 | winsec_critique (T1562.002), sysmon_injection (T1055), lolbin_suspect (T1218), masquerading |
| Credential Access | 11 | lsass_access (T1003.001), dcsync (T1003.006), kerberoasting (T1558.003), adcs_abuse (T1649), gpp_creds, vault_auth_fail |
| Discovery | 2 | network_scan (T1046), ldap_recon (T1087.002) |
| Lateral Movement | 3 | lateral_movement (T1021), wmi_lateral_exec (T1047), admin_share (T1021.002) |
| Collection | 1 | m365_mail_forward (T1114.003) |
| Command and Control | 2 | beaconing/threat_intel (T1071), dns_tunneling (T1071.004) |
| Exfiltration | 2 | data_exfil/volume_spike (T1048), m365_partage_externe (T1567) |
| Impact | 3 | ransomware_indicator (T1486), vsphere_vm_destroy (T1485), veeam_job_echec (T1490) |

## Trous & axes d'enrichissement (priorisés)
1. **Collection (1) / Exfiltration (2)** — ajouter T1005 (données poste local), T1039 (partages réseau), T1056 (capture d'entrée). *[P2]*
2. **Discovery (2)** — ajouter T1018 (remote system discovery), T1482 (trust de domaine), T1057/T1083. *[P2]*
3. **Lateral Movement** — ajouter **T1550** (Pass-the-Hash / Pass-the-Ticket) — clé en environnement AD. *[P1]*
4. **Initial Access** — **T1566 (Phishing)** : nécessite la télémétrie de sécurité mail (au-delà de M365 signin). *[P2, dépend source]*
5. **Impact** — T1489 (Service Stop), T1498 (DoS). *[P3]*
6. **Execution/Persistence** — T1059.003 (cmd), T1505.003 (web shell sur IIS/serveurs exposés). *[P2]*

## Validation (purple team) — prouver que ça se déclenche
Méthode : exécuter le test [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) correspondant sur un poste **de test** et vérifier que le SIEM lève l'`alert_tag` attendu (page Investigation → `alert_tag:<tag>`), idéalement l'alerte.

| Technique | Test Atomic | `alert_tag` attendu | Source |
|---|---|---|---|
| T1003.001 LSASS | T1003.001 (comsvcs/procdump) | `lsass_access` | Sysmon 10 |
| T1558.003 Kerberoasting | T1558.003 | `kerberoasting` | 4769 |
| T1053.005 Scheduled Task | T1053.005 (`schtasks /create`) | `scheduled_task` | 4698 |
| T1543.003 Service | T1543.003 (`sc create`) | `service_install` | 4697 |
| **T1548.002 UAC bypass** | T1548.002 (fodhelper) | `uac_bypass` | Sysmon 1 |
| T1547.001 Run keys | T1547.001 | `persistence_autorun` | Sysmon 13 |
| T1059.001 PowerShell | T1059.001 (encoded) | `powershell_suspect` | 4104 |
| T1218 LOLBin | T1218.010 (regsvr32) | `lolbin_suspect` | Sysmon 1 |
| T1046 Network scan | T1046 | `network_scan` | FortiGate |
| T1087.002 LDAP recon | T1087.002 | `ldap_recon` | 4662/Sysmon |
| T1562.002 Clear logs | T1070.001 (`wevtutil cl`) | `winsec_critique` | 1102 |

> ⚠️ Ne PAS jouer les tests destructifs (T1486 ransomware, T1485 destruction) en production.
> Tenir un journal des campagnes de validation (date, technique, détecté oui/non, MTTD) — utile aussi pour ISO A.8.16.

## Maintenance
À chaque nouvelle détection : ajouter la ligne dans `lookups/mitre-attack.csv` (via `add_mitre` dans le script de détection), puis **relancer `57-mitre-coverage.sh`** pour régénérer le calque Navigator et le bilan de couverture.


<a id="doc-12"></a>

---

<!-- ============================== INVENTAIRE-SOURCES.md ============================== -->

# Inventaire des sources surveillées — SIEM OMNITECH

> Registre des sources de journaux collectées par le SIEM, leur volume,
> rétention et criticité. Alimente l'inventaire des actifs (ISO 27001 A.5.9) et
> prouve la couverture de surveillance (A.8.16). Le débit est mesuré
> automatiquement (voir page « Santé collecte » et supervision de couverture).

## 1. Sources collectées

| Source (stream) | Origine | Transport (input) | Volume ~/jour | Rétention | Criticité |
|-----------------|---------|-------------------|---------------|-----------|-----------|
| **Windows Security** | Postes & serveurs AD (audit) | Winlogbeat → Beats TLS 5044 | ~5,5 Go | **365 j** | Haute |
| **Sysmon** | Endpoints (télémétrie processus/réseau) | Winlogbeat → Beats TLS 5044 | ~1,8 Go* | **365 j** | Haute |
| **Windows autres** | Veeam (canal « Veeam Backup »), AD CS (PKI), Defender, services | Winlogbeat → Beats TLS 5044 | ~2,7 Go | **365 j** | Moyenne |
| **FortiGate** | Pare-feu (trafic, UTM, VPN) | FortiAnalyzer → syslog 1514 (key=value) | ~11 Go | **180 j** | Haute |
| **Microsoft 365 / Entra** | Cloud (sign-in, audit, activité) | API Graph → collecteur → GELF HTTP 12201 | ~0,02 Go | **365 j** | Haute |
| **vSphere** | ESXi / vCenter | syslog UDP/TCP 1516 | ~0,6 Go | **365 j** | Haute |
| **ESET PROTECT** | Console antivirus (10.33.50.20) | syslog JSON TCP 1515 (514 redirigé) | faible | **365 j** | Haute |
| **BunkerWeb (WAF)** | Reverse-proxy WAF (10.33.70.1) | Filebeat → Beats TLS 5044 | ~0,3 Go** | **90 j** | Haute |
| **Interne SIEM** | Analyses maison (UEBA/NDR/incidents/santé/vuln) | GELF local 12201 | faible | défaut | Haute |

\* Sysmon après filtrage du bruit (EventID 12 registre).
\*\* BunkerWeb après *drop* du bruit stderr/metrics (~97 % du volume brut).

**NPS (RADIUS, 10.33.50.247)** : déjà mappé côté SIEM (lookup `win-events.csv`,
EventID 6272/6273/6274 → `event_source:nps`). En attente de remontée : à
déployer Winlogbeat sur le serveur NPS. Alerte associée déjà créée (script 13).

Total ~22 Go/jour sur disque (avant compression). `/data` = 7,3 To dédié.
Détail capacité et projections : `POLITIQUE-RETENTION.md`.

## 2. Couverture & continuité (A.8.16)

- **Couverture mesurée** : taux d'hôtes « gérés » émettant dans les dernières
  24 h, calculé en continu (page « Santé collecte »). Cible : ~100 %.
- **Détection des trous** : un hôte qui cesse d'émettre (>26 h) est signalé
  *go-dark* (alerte P2) — couvre la panne d'agent comme le sabotage.
- **Auto-supervision** : les ~13 robots d'analyse sont eux-mêmes surveillés
  (alerte P3 si l'un s'arrête) — la détection ne peut pas devenir aveugle
  silencieusement.

## 3. Champs normalisés (interopérabilité)

Tous les événements sont normalisés vers un schéma commun (champs unifiés) pour
permettre la corrélation cross-source :

- Identité : `host`, `user`, `src_ip`, `src_host`, `event_id`, `event_action`,
  `event_source`, `event_category`.
- Sécurité : `alert_tag` (détection), `mitre_technique` / `mitre_tactic`,
  `risk_score` / `risk_severity`.
- Réseau : `action`, `dest_ip`, `dest_country`, `srccountry`, `bytes_*`,
  géolocalisation.
- M365 : `m365_type` (signin / audit / **risk** — Entra ID Protection), `m365_workload`,
  `src_country`, `upn` (`alert_tag:m365_risque` sur compte atRisk).
- ESET : `eset_event_type`, `eset_severity`, `eset_action`, `eset_target`, `eset_detail`,
  `eset_hostname`, `eset_user` (préfixe `eset_` ; `alert_tag:eset_detection` sur menace).
  *(Les champs `eset_threat_name`/`eset_object_uri` n'existent pas — corrigé 2026-06-14.)*
- BunkerWeb / WAF : `waf_vhost`, `http_method`, `http_url`, `http_status`,
  `http_user_agent`, `src_ip` (`alert_tag:waf_block` sur HTTP 403).
- Vaultwarden (coffre MDP) : `vault_user`, `src_ip`, `vw_level`, `vw_module`
  (routage `filebeat_event_source=vaultwarden`, index dédié `omni-vaultwarden`).
- Réseau/identité (enrichissement) : `src_hostname`/`dest_hostname` (attribution DHCP
  FortiGate, script 56), `identity`/`identity_human` (corrélation inter-sources, script 58).

Le routage de chaque source repose sur `event_source` (FortiGate, ESET, vSphere,
M365, Veeam, NPS) ou `filebeat_event_source` (BunkerWeb). Côté FortiGate, le
champ `source` Graylog est positionné sur le nom de l'équipement (`host` =
`devname` renommé), ce qui permet de séparer les logs par pare-feu.

## 4. Horodatage (A.8.17)

Toutes les sources et le SIEM sont synchronisés NTP sur le contrôleur de domaine
(PDC emulator, 10.33.50.250). Le champ `timestamp` est en UTC, cohérent entre
sources, ce qui garantit la fiabilité des corrélations temporelles (impossible
travel, kill-chain, beaconing).

Cas particulier FortiGate : l'horodatage SIEM est dérivé du champ `eventtime`
(epoch nanosecondes) émis par l'équipement, et non de l'en-tête syslog du FAZ —
ceci évite tout décalage lié au relais FortiAnalyzer.

## 5. Protection des sources (intégrité de la collecte)

- Flux entrants restreints par pare-feu local (nftables) aux sous-réseaux/hôtes
  autorisés (cf. `00-vars.env` : NET_BEATS, IP_FAZ, VSPHERE_NET, IP_ESET,
  IP_BUNKERWEB, IP_NPS).
- Transport chiffré pour les agents Beats (Winlogbeat / Filebeat) : entrée Beats
  TLS 5044 (certificat `/etc/graylog/certs/graylog.crt`). ESET, FortiGate et
  vSphere sont en syslog sur les VLAN internes restreints au pare-feu.
- Comptes de collecte dédiés (M365 : app Entra à privilèges de lecture ; AD :
  compte de service de bind LDAPS).

---
*Inventaire à tenir à jour lors de l'ajout/retrait d'une source. Voir
`ISO27001-MAPPING.md` (A.8.15/8.16), `INTEGRATION-SOURCES.md` (procédures
d'intégration) et `POLITIQUE-RETENTION.md` (durées). Revue : 2026-06-14.*


<a id="doc-13"></a>

---

<!-- ============================== INTEGRATION-SOURCES.md ============================== -->

# Intégration de nouvelles sources — ESET / NPS / BunkerWeb

> Procédure d'ajout des 3 sources. Côté SIEM tout est déjà provisionné
> (`52-new-sources.sh`). Il reste / restait la config **côté source**, détaillée ici.
>
> **Revue : 2026-06-14.**

## État réel des 3 sources (au 2026-06-14)

| Source | Côté SIEM | Côté source | Données reçues |
|--------|-----------|-------------|----------------|
| **ESET PROTECT** (10.33.50.20) | ✅ input Syslog TCP 1515, stream `OMNI - ESET`, pipeline `eset_*` | ✅ syslog configuré | ✅ **arrive** (volume faible — détections ponctuelles, champs `eset_*` parsés) |
| **BunkerWeb** (10.33.70.1, hôte `bx-waf-it-vm`) | ✅ stream `OMNI - BunkerWeb`, pipeline `http_*`/`waf_*` | ✅ **Filebeat déployé** (logs Docker) | ✅ **arrive** (~15,5 k docs, flux nominal) |
| **NPS / RADIUS** (10.33.50.247, `bx-nps-it-vm`) | ✅ lookup `win-events.csv` + widgets/alerte prêts | ⚠️ Winlogbeat actif mais **canal Security absent** | ❌ **0× 6272/6273/6274** (voir diagnostic §2) |

> ESET et BunkerWeb sont donc **opérationnels** ; la section qui les concerne sert
> désormais de référence (rappel de conf) plus que de tâche à faire. NPS reste la
> seule source réellement « en attente » côté serveur.

### Routage / rétention par source

- **ESET** : index set dédié `omni-eset`, **rétention 365 j** (forensique).
- **BunkerWeb** : index set dédié `omni-bunkerweb`, **rétention 90 j** (volume).
- **NPS** : pas d'index dédié — les events atterrissent dans le stream *Windows
  Security* (rétention Windows = 365 j).

---

## 1. ESET PROTECT (10.33.50.20) — ✅ opérationnel

**Côté SIEM (fait) :** input *Syslog TCP* sur **1515** (TLS désactivé sur cet
input), et le pare-feu **redirige 514 → 1515** (ton ESET reste donc sur 514).
Stream `OMNI - ESET` (routé sur `gl2_source_input` de l'input ESET). Le pipeline
pose `event_source=eset`, parse le JSON ESET en champs **`eset_*`**
(`eset_event_type`, `eset_severity`, `eset_action`, `eset_hostname`, `eset_user`,
`eset_target`, `eset_detail`…), calcule un **`eset_risk_score`** (lookup
`eset-severity`, défaut 3), un **`eset_outcome`** (remédiée / non remédiée) et
pose le tag **`eset_detection`** (`alert_tag`) sur les menaces (`Threat_Event` /
`HipsAggregated_Event`). La règle `omni-eset-08-source-fix` réécrit `source` avec
`eset_hostname` (corrige le `source=mois` issu du syslog FR).

**Côté ESET PROTECT (déjà configuré par toi) :** Serveur syslog
`10.33.50.20 → 10.33.220.10:514`, TCP, format **syslog** (payload JSON ESET).

> **Vérifié au 2026-06-14 :** les events arrivent bien dans `OMNI - ESET` et les
> champs `eset_*` sont correctement extraits. Volume faible (détections
> ponctuelles) — c'est attendu, pas un problème de collecte.

⚠️ **Un seul point à vérifier — le cadrage (framing)** : Graylog attend par
défaut un cadrage **LF (non-transparent framing)**. Si tu as choisi
« octets comptabilisés » (octet-counting RFC 6587) et que les messages
arrivent **collés/tronqués**, bascule ESET sur **non-transparent / nouvelle
ligne (LF)**. Vérifie l'arrivée :
- Console Graylog → *Search* → `gl2_source_input` de l'input ESET, ou stream
  `OMNI - ESET`. Tu dois voir les events sous ~1 min.

---

## 2. NPS / RADIUS (10.33.50.247, `bx-nps-it-vm`) — ⚠️ en attente côté serveur

**Côté SIEM (déjà géré) :** les events NPS **6272** (accès accordé), **6273**
(refusé), **6274** (rejeté) sont **automatiquement enrichis** (lookup
`win-events.csv` → `event_action=acces_reseau_nps_*`, `event_category=nps`) et
apparaissent dans le stream *Windows Security* + le widget « Accès NPS refusés ».
Rien à créer.

**Côté serveur NPS (à faire) :** déployer **Winlogbeat** (le même agent que le
reste du parc) sur `10.33.50.247`. Le plus simple :
1. Lancer `Install-OmniSiem-NinjaOne.ps1` sur ce serveur (il installe Winlogbeat
   + Sysmon + la conf, et 10.33.50.247 est déjà autorisé sur le 5044 via le /16).
2. Les events NPS sont dans le journal **Security** (déjà collecté par
   `winlogbeat.yml`). Aucune conf supplémentaire.

> Pré-requis côté NPS : l'audit doit générer 6272-6274 (par défaut activé si NPS
> est rôle RADIUS ; sinon `auditpol /set /subcategory:"Network Policy Server"
> /success:enable /failure:enable`).

### Diagnostic (état au 2026-06-14)

Constaté à l'audit : `bx-nps-it-vm` (10.33.50.247) **émet bien via Beats 5044**
(~435 docs/24h) mais **uniquement du Sysmon** — **aucun event du canal Security**
(donc 0× 6272/6273/6274). Deux causes possibles, à corriger côté serveur :

1. **Audit NPS non activé.** Sur Windows **français**, le nom anglais de la
   sous-catégorie échoue → utiliser le **GUID** (indépendant de la langue) :
   ```powershell
   $g="{0CCE9243-69AE-11D9-BED3-505054503030}"
   auditpol /set /subcategory:$g /success:enable /failure:enable
   auditpol /get /subcategory:$g     # doit afficher "Réussite et Échec"
   ```
2. **Winlogbeat ne collecte pas le canal Security sur ce serveur.** Vérifier que
   `C:\Program Files\winlogbeat\winlogbeat.yml` contient bien
   `- name: Security` sous `winlogbeat.event_logs:` (sinon seul Sysmon remonte).
   Re-déployer via `Install-OmniSiem-NinjaOne.ps1` si la conf locale a dérivé.

Puis **provoquer une authentification RADIUS** (les 6272/6273 ne sont émis que sur
une vraie demande d'accès) et vérifier côté SIEM : recherche `event_id:6272`.
Tant que ce flux n'arrive pas, les widgets **[NPS en attente]** de la page
« Sources externes » restent vides — c'est attendu, pas un bug.

> Côté SIEM, **rien à faire** : le lookup `win-events.csv` mappe déjà
> 6272/6273/6274 → `acces_reseau_nps_*`, le widget « Accès NPS refusés » et
> l'**alerte P3** « OMNI - NPS : refus d'accès en masse (≥10 / compte / 15 min) »
> (script `13-graylog-alerts.sh`, sur le stream Windows Security) sont prêts.

> **Vérifié au 2026-06-14 :** toujours **0** event 6272/6273/6274 dans l'index —
> le canal Security du serveur NPS ne remonte pas encore (cf. causes ci-dessus).

---

## 3. BunkerWeb (10.33.70.1, hôte `bx-waf-it-vm`) — Filebeat → Beats 5044 — ✅ opérationnel

**Côté SIEM (fait) :** stream `OMNI - BunkerWeb`. ⚠️ **Le stream est routé sur le
champ `filebeat_event_source=bunkerweb`** (et **non** `event_source`) : Filebeat
envoie un champ `fields.event_source` que l'input Beats de Graylog **préfixe en
`filebeat_`**. C'est seulement *ensuite*, dans le pipeline, que la règle
`omni-bunkerweb-00-normalise` recopie `filebeat_event_source` → `event_source`.
Le pipeline pose alors `event_category=waf`, parse les accès nginx/BunkerWeb
(`src_ip`, `http_method`, `http_status`, `http_user_agent`, octets, vhost,
classe HTTP 2xx/3xx/4xx/5xx), pose le tag **`waf_block`** (HTTP 403 / ModSecurity),
détecte les **backends 5xx** et les **outils offensifs** dans le User-Agent, et
**drope ~97 % de bruit** (stderr/metrics) via `omni-bunkerweb-02-drop-noise`.
Réutilise l'input **Beats TLS 5044** existant (10.33.70.1 déjà autorisé via le /16).

> **Vérifié au 2026-06-14 :** flux nominal (~15,5 k docs), `event_source=bunkerweb`
> bien posé, parsing HTTP OK. Les logs proviennent du **conteneur Docker BunkerWeb**
> (`/var/lib/docker/containers/*/*-json.log`) — le déploiement réel est l'**option
> Docker** ci-dessous, pas le paquet systemd.

> ⚠️ **Point clé si tu redéploies Filebeat :** **ne mets PAS `fields_under_root:
> true`**. Si tu le mets, `event_source` arrive à la racine et n'est **pas**
> préfixé `filebeat_` → le stream `OMNI - BunkerWeb` (qui filtre sur
> `filebeat_event_source`) **ne matchera plus**. Laisse Filebeat poser le champ
> sous `fields:` (comportement par défaut, préfixé par Graylog).

### Étapes (Debian)

**a. Installer Filebeat (OSS) :**
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-8.15.0-amd64.deb
sudo dpkg -i filebeat-oss-8.15.0-amd64.deb
```

**b. Copier la CA du SIEM** (le Beats input est en TLS) sur le serveur :
```bash
# depuis le SIEM, ou récupère /etc/graylog/certs/omnitech-rootca.crt
sudo install -m 644 omnitech-rootca.crt /etc/filebeat/omnitech-rootca.crt
```

**c. Repérer les logs BunkerWeb.** Selon l'installation :
- **Docker (déploiement réel sur `bx-waf-it-vm`)** : BunkerWeb tourne en conteneur,
  ses logs sont écrits par le driver json-file Docker. Filebeat pointe donc sur
  `/var/lib/docker/containers/*/*-json.log` (la conf utilise le module/`add_docker_metadata`
  ou un filtrage par conteneur ; le drop du bruit stderr/metrics se fait côté
  pipeline Graylog, règle `omni-bunkerweb-02-drop-noise`).
- **Paquet/systemd** (autre installation possible) : `/var/log/bunkerweb/access.log`,
  `error.log`, et l'audit ModSecurity `/var/log/bunkerweb/modsec_audit.log` (si activé).

**d. `/etc/filebeat/filebeat.yml` — variante Docker (celle en production) :**
```yaml
filebeat.inputs:
  - type: filestream
    id: bunkerweb
    paths:
      - /var/lib/docker/containers/*/*-json.log
    parsers:
      - container: ~                 # décode l'enveloppe json-log Docker
    fields:
      event_source: bunkerweb        # <- NE PAS mettre fields_under_root: true.
                                     #    Graylog préfixe -> filebeat_event_source,
                                     #    sur lequel le stream OMNI - BunkerWeb filtre.

output.logstash:                      # protocole Beats (= input Graylog 5044)
  hosts: ["10.33.220.10:5044"]
  ssl.certificate_authorities: ["/etc/filebeat/omnitech-rootca.crt"]

logging.level: warning
```

> **Variante paquet/systemd** : remplace `paths:` par les `access.log` / `error.log`
> / `modsec_audit.log` de `/var/log/bunkerweb/` et retire le parser `container`.
> **Conserve** `fields: { event_source: bunkerweb }` **sans** `fields_under_root`.

**e. Démarrer :**
```bash
sudo systemctl enable --now filebeat
sudo filebeat test output      # doit afficher 'talk to server... OK'
```

**f. Vérifier côté SIEM** : stream `OMNI - BunkerWeb` se remplit sous ~1 min.
Recherche de contrôle : `event_source:bunkerweb` (après normalisation pipeline) ou
`filebeat_event_source:bunkerweb` (champ brut, immédiat). Le champ `source` doit
afficher l'hôte WAF (`bx-waf-it-vm`).

### Alternative sans agent (rsyslog)
Si tu préfères ne pas installer Filebeat : configure BunkerWeb/nginx pour logguer
en syslog vers le SIEM, mais il faudra un input syslog dédié BunkerWeb (dis-le moi,
je l'ajoute). **Filebeat reste recommandé** (structuré, parsing access/ModSecurity).

---

## Récapitulatif des flux à ouvrir (FortiGate, si segmentation inter-VLAN)
| Source | → SIEM | Port | Protocole |
|--------|--------|------|-----------|
| ESET 10.33.50.20 | 10.33.220.10 | **514** (→1515) | TCP syslog |
| NPS 10.33.50.247 | 10.33.220.10 | **5044** | TCP (Beats TLS) |
| BunkerWeb 10.33.70.1 | 10.33.220.10 | **5044** | TCP (Beats TLS) |

*Le pare-feu LOCAL du SIEM est déjà ouvert pour ces flux.*


<a id="doc-14"></a>

---

<!-- ============================== POLITIQUE-RETENTION.md ============================== -->

# Politique de rétention des journaux - OMNITECH Security (SIEM Graylog)

Référence ISO/IEC 27001:2022 — A.8.15 (Journalisation), A.8.16 (Surveillance),
A.8.17 (Synchronisation des horloges). Approche **risk-based** : la durée est
adaptée à la valeur sécurité/forensic de chaque source, dans la limite du
stockage disponible.

> Revue : 2026-06-14 — à valider et dater par le RSSI.

## Durées de conservation (en ligne, consultable)

Chaque source dispose d'un **index set dédié** (préfixe `omni-*`) avec rotation
journalière (`P1D`) et rétention exprimée en nombre d'index (1 index = 1 jour).
La rétention « supprime » (delete) les index une fois la fenêtre dépassée.

| Source                          | Index set        | Durée  | Justification                                                            |
|---------------------------------|------------------|--------|-------------------------------------------------------------------------|
| Windows Security (AD)           | `omni-winsec`    | 365 j  | Dossier sécurité : authentification, comptes, privilèges, PKI           |
| Sysmon (endpoint)               | `omni-sysmon`    | 365 j  | Détections, chasse, processus/réseau (hors bruit registre)              |
| Windows autres (Veeam, ADCS…)   | `omni-winother`  | 365 j  | Sauvegardes Veeam, PKI/ADCS, services système                           |
| Microsoft 365 / Entra           | `omni-m365`      | 365 j  | Connexions cloud, partages, rôles, audit Entra ID (collecté en GELF)    |
| vSphere                         | `omni-vsphere`   | 365 j  | Accès hyperviseur, suppressions de VM                                   |
| ESET PROTECT (EDR/AV)           | `omni-eset`      | 365 j  | Détections poste/serveur, valeur forensique élevée (syslog JSON)        |
| FortiGate (pare-feu)            | `omni-fortigate` | 180 j  | Trafic volumineux : 6 mois de fenêtre forensic ; les événements         |
|                                 |                  |        | sécurité (deny/UTM/VPN) restent corrélables sur toute la fenêtre        |
| BunkerWeb (WAF)                 | `omni-bunkerweb` | 90 j   | Logs HTTP/WAF à fort volume ; 90 j couvrent le besoin d'investigation   |
| Vaultwarden (coffre MDP)        | `omni-vaultwarden` | 90 j | Coffre de mots de passe : échecs d'auth, accès admin. **Index dédié** pour éviter que le volume/rejeu n'évince les events internes du SIEM |

Sources annexes :
- **NPS / RADIUS** : champs mappés et index prêts côté SIEM, mais la collecte
  n'est **pas encore activée côté client** (aucun volume à ce jour).
- **Télémétrie interne SIEM** (stream « OMNI - Interne SIEM » : santé collecte,
  disk-guard, contrôle de certificats) : conservée dans l'index set Graylog par
  défaut, rétention courte (gestion opérationnelle, pas de valeur d'audit long
  terme).

## Événements explicitement EXCLUS (risque accepté, faible valeur / fort volume)

La réduction de bruit est appliquée **au stage 30 du pipeline, APRÈS toute
détection** (script 41-retention-iso.sh) : elle ne casse aucune règle de
détection, elle évite seulement de stocker durablement des événements à fort
volume et faible valeur.

| Source           | Event                              | Motif                                                                                                       |
|------------------|------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Sysmon           | EID 12 (RegistryEvent add/delete)  | ~62 % du volume Sysmon, bruit ; la persistance registre reste couverte par l'EID 13 (Value Set), conservé   |
| Windows Security | 4673 (Sensitive Privilege Use)     | Très volumineux, quasi-100 % bénin (services système)                                                        |
| Windows Security | 4627 (Group Membership)            | Redondant avec 4624 (déjà conservé)                                                                          |

Conservés volontairement malgré leur volume : **4662** (requis pour la détection
DCSync) et **4688** (traçabilité de création de processus).

## Intégrité & protection (A.8.15)
- Index OpenSearch en écriture seule (pas de modification a posteriori).
- Détection d'effacement de journaux (1102 / 4719 / 1100 / 104) -> alerte.
- Sauvegarde quotidienne de la configuration ; horloges synchronisées (NTP).
- Accès SIEM restreint (LDAPS, groupe AD dédié).
- Horodatage normalisé à la source de l'événement (ex. FortiGate : champ
  `eventtime`), garantissant l'ordre chronologique réel en forensic.

## Garde-fou de capacité (disk-guard)
Disque **/data dédié, 7,3 To**. Le service `omni-disk-guard` (32-disk-guard.sh,
timer systemd toutes les 6 h) constitue le filet de sécurité ultime, au-delà de
la rétention nominale ci-dessus :

| Seuil d'occupation /data | Action                                                                                          |
|--------------------------|-------------------------------------------------------------------------------------------------|
| < 80 %                   | Rien : la rétention normale supprime les index à J+rétention                                     |
| ≥ 80 %                   | Alerte (GELF -> mail « Disque SIEM >80% ») — revoir le plan de rétention                         |
| ≥ 88 %                   | **Purge d'urgence** : suppression des index `omni-*` les plus ANCIENS (jamais l'index actif d'un flux) jusqu'à repasser sous **82 %**, + alerte |

Ce mécanisme s'interpose AVANT les watermarks OpenSearch (95 % = indices passés
en lecture seule = collecte stoppée). Revue mensuelle du Go/jour réel (cf.
supervision de la collecte). Au volume actuel, /data est occupé à ~2 % (147 Go).

---

_Document généré et maintenu par 41-retention-iso.sh — à valider et dater par le
RSSI. Voir aussi : POL-SUPERVISION-JOURNALISATION.md, INVENTAIRE-SOURCES.md,
ISO27001-MAPPING.md._


<a id="doc-15"></a>

---

<!-- ============================== PROCEDURE-INCIDENT.md ============================== -->

# Procédure de détection et de réponse aux incidents de sécurité

> Décrit comment un événement de sécurité est détecté, évalué, traité et clos via
> le SIEM OMNITECH. Couvre ISO/IEC 27001:2022 **A.5.24** (préparation),
> **A.5.25** (évaluation/décision), **A.5.26** (réponse), **A.5.27**
> (enseignements), **A.5.28** (preuves).
>
> **Statut :** procédure opérationnelle — à valider/approuver par le RSSI.

## 1. Rôles et responsabilités

| Rôle | Responsabilité |
|------|----------------|
| **Analyste SOC / Administrateur** | Triage quotidien, qualification, traitement de 1er niveau |
| **RSSI** | Décision sur incidents majeurs, communication, enseignements |
| **SIEM (automatisé)** | Détection, corrélation, scoring, notification, réponse réflexe (SOAR) |

## 2. Chaîne de traitement (du log à l'incident clos)

```
Événement ─► Détection (88 règles) ─► Enrichissement (MITRE + score) ─► Corrélation
   (alert_tag)        (alerte P2/P3)         (risk_score, technique)      (kill-chain)
                                                                              │
                          ┌───────────────────────────────────────────────────┘
                          ▼
   Notification (e-mail/Teams) + Incident horodaté (page « Incidents »)
                          │
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
   ÉVALUATION (A.5.25)  RÉPONSE (A.5.26)   CLÔTURE + ENSEIGNEMENTS (A.5.27)
```

## 3. Détection (A.5.24)

- **Automatique et continue** : 88 règles de détection (cf.
  `REGISTRE-DETECTIONS.md`) + détection comportementale (UEBA/NDR).
- **Priorisation** : **P3** = critique (sabotage d'audit, DCSync, ransomware,
  incident corrélé critique, canari…) ; **P2** = important (LSASS, beaconing,
  tunnel DNS, go-dark, entité UEBA ≥80…).
- **Notification** : chaque déclenchement envoie un e-mail + un message Teams au
  canal SOC. Anti-tempête : pas de renvoi en boucle (délai par entité).

## 4. Évaluation et décision (A.5.25)

L'analyste qualifie via le SIEM :

1. **Page « Direction »** — y a-t-il des incidents critiques / entités à risque ?
2. **Page « Incidents »** — lire le **récit d'attaque** (kill-chain ordonnée) :
   entité, séquence de tactiques, fenêtre temporelle, score.
3. **Page « UEBA / NDR »** — score de l'entité, facteur dominant.
4. **Page « Investigation »** — taper `host:…` ou `user:…` pour tout corréler
   (message brut conservé pour le forensic).

**Décision** : faux positif (documenter) / incident mineur (traiter) / incident
majeur (escalade RSSI). Critères d'escalade : technique critique (T1003, T1486,
DCSync), compte à privilèges, score ≥80, ou plusieurs tactiques enchaînées.

## 5. Réponse (A.5.26)

- **Réflexe automatique (SOAR)** : une IP attaquante répétée (force brute VPN /
  password spraying) est bloquée automatiquement au pare-feu (TTL configurable),
  **jamais** sur une IP interne ou sur liste blanche. Playbooks **isolation d'hôte /
  désactivation de compte** conçus (attente API NinjaOne) → cf. `SOAR-PLAYBOOKS.md` ;
  d'ici là, ces actions restent **manuelles**.
- **Pivot d'investigation** : utiliser le champ **`identity`** (page « Identité »)
  pour reconstituer l'activité d'une personne sur **toutes** les sources
  (AD + M365 + VPN + endpoint), et `src_hostname` pour résoudre une IP interne.
- **Confinement manuel** : désactiver le compte compromis (AD/M365), isoler
  l'hôte, révoquer les sessions, bloquer l'IP/domaine.
- **Éradication** : retirer la persistance (tâche/service/clé Run), corriger la
  vulnérabilité (page « Vulnérabilités »), forcer le changement de mot de passe.
- **Reprise** : restaurer depuis sauvegarde Veeam si nécessaire (page
  « Sauvegardes »), vérifier le retour à la normale.

## 6. Collecte de preuves (A.5.28)

- Les journaux pertinents sont **conservés et horodatés** (12 mois pour le
  dossier sécurité), en **écriture seule** + **registre d'intégrité signé**
  (tamper-evidence) attestant qu'ils n'ont pas été altérés sur l'intervalle.
- Le **message brut** est conservé (champ `message`) pour l'analyse forensique.
- Export possible : recherche Graylog → export CSV ; **sceller** l'export
  (`sha256sum`) + joindre l'attestation `omni-integrity --verify` → **chaîne de
  possession** (procédure détaillée : `PROCEDURE-INTEGRITE-PREUVE.md`).
- La **chaîne de corrélation** (incident) documente la séquence horodatée.

## 7. Clôture et enseignements (A.5.27)

- Documenter la qualification, les actions, la cause racine.
- Si récurrent : ajuster les seuils, ajouter/affiner une règle de détection,
  étendre une liste blanche (ex. beaconing SaaS légitime).
- Les **rapports hebdomadaire et mensuel** consolident les tendances et le top
  des risques pour la revue de direction.

## 8. Indicateurs (pour la revue de direction)

- Nombre d'incidents critiques / élevés (mois).
- Couverture de collecte (%) et hôtes go-dark.
- Top entités à risque (UEBA), top techniques ATT&CK observées.
- Vulnérabilités KEV exposées.

Source : rapport mensuel (`omni-monthly-report`, archivé `/kit/rapports/`).

---
*Voir `ISO27001-MAPPING.md` (correspondance contrôles), `REGISTRE-DETECTIONS.md`
(règles), `PROCEDURE-EXPLOITATION-SIEM.md` (exploitation courante).*


<a id="doc-16"></a>

---

<!-- ============================== PROCEDURE-EXPLOITATION-SIEM.md ============================== -->

# Procédure d'exploitation du SIEM OMNITECH

> Décrit l'exploitation courante, la maintenance et le contrôle du bon
> fonctionnement du SIEM. Support des contrôles ISO/IEC 27001:2022 A.8.15
> (journalisation), A.8.16 (surveillance), A.8.6 (gestion des capacités).
>
> **Statut :** procédure opérationnelle — à valider/approuver par le RSSI.

## 1. Architecture (rappel)

- **Graylog** (collecte/recherche) + **OpenSearch** (stockage) + **MongoDB**
  (config), sur une VM dédiée. Disque de données `/data` (7,3 To).
- Collecte : Winlogbeat (Windows), FortiAnalyzer (pare-feu), API Graph (M365),
  syslog (vSphere).
- **~13 robots d'analyse** (timers systemd) calculant détection comportementale,
  corrélation, supervision (cf. tableau §4).
- Console : `https://<siem>` (LDAPS + groupe AD). Kit & rapports :
  `https://<siem>/kit/`.

## 2. Contrôles quotidiens (analyste SOC)

Routine matinale (~10 min) :

1. **Direction** — incidents critiques ? entités à risque ? tendances.
2. **Incidents** — traiter les incidents critiques du jour.
3. **UEBA / NDR** — top entités à risque, détections comportementales.
4. **Santé collecte** — couverture ~100 % ? aucun hôte go-dark ? **robots
   d'analyse 0 en panne** ?
5. **Boîte mail / Teams** — traiter les alertes reçues (cf.
   `PROCEDURE-INCIDENT.md`).

## 3. Contrôles périodiques

| Fréquence | Action |
|-----------|--------|
| Hebdomadaire | Lire le rapport hebdo (e-mail) ; revue des comptes à privilèges |
| Mensuel | Rapport exécutif (PDF) pour la revue de direction ; revue du Go/jour vs capacité ; revue des listes blanches (SOAR, beaconing, DNS) |
| Trimestriel | Revue des règles de détection (faux positifs, lacunes) ; test de restauration sauvegarde config |
| Annuel | Revue de la politique de rétention ; revue de couverture vs inventaire des actifs |

## 4. Tâches automatiques (robots) — supervision

Tous planifiés (timers systemd), **auto-supervisés** par `omni-self-health` :

| Robot | Fréquence | Rôle |
|-------|-----------|------|
| omni-collect-health | 1 h | Couverture SLA + go-dark |
| omni-vuln-scan | 1 j | Vulnérabilités (CISA KEV) |
| omni-ueba-score | 30 min | Score de risque d'entité |
| omni-ueba-geo | 30 min | Impossible travel |
| omni-ndr-beacon | 6 h | Beaconing C2 |
| omni-ndr-dns | 1 h | Tunneling DNS |
| omni-ueba-volume | 1 h | Anomalie de volume |
| omni-incident-correlate | 15 min | Corrélation d'incidents |
| omni-geo-flux | 30 s | Carte cyber temps réel |
| omni-self-health | 30 min | Auto-supervision des robots |
| omni-weekly-report | hebdo | Rapport hebdomadaire |
| omni-monthly-report | mensuel | Rapport exécutif PDF |

**Contrôle** : `systemctl list-timers 'omni-*'` ; en cas de panne, l'alerte
« Robot d'analyse en panne » (P3) se déclenche automatiquement.

## 5. Gestion de la capacité (A.8.6)

- Débit mesuré : ~29 Go/jour (sur disque, compressé). Voir
  `POLITIQUE-RETENTION.md`.
- **Garde-fou** : purge contrôlée des plus anciens index au-delà de 80 %
  d'occupation de `/data` (alerte « Disque >80 % » puis « PURGE D'URGENCE »).
- Rétention différenciée : sécurité 365 j, trafic pare-feu 90 j.
- **Revue mensuelle obligatoire** du Go/jour (croissance du parc/UTM).

## 6. Maintenance & sécurité du SIEM

- **Sauvegarde** : configuration sauvegardée quotidiennement (chiffrée,
  passphrase au coffre). Alerte si échec/absence.
- **Accès** : console restreinte LDAPS + groupe AD dédié ; OpenSearch en
  localhost ; SSH restreint au VLAN d'admin.
- **Intégrité** : index en écriture seule ; détection de sabotage des journaux
  (alerte P3).
- **Mises à jour** : appliquer les correctifs Graylog/OpenSearch lors des
  fenêtres planifiées ; vérifier la reprise de collecte après.
- **Certificat** : le certificat du SIEM s'auto-renouvelle ; alerte si <45 j.

## 7. Continuité

- Journal tampon Graylog (≈10 Go) absorbe une indisponibilité temporaire
  d'OpenSearch sans perte.
- En cas d'arrêt d'une source : alerte go-dark / silence Winlogbeat.
- Sauvegarde config = reconstruction rapide de la configuration.

---
*Voir `GUIDE.md` (vue d'ensemble accessible), `PROCEDURE-INCIDENT.md` (réponse),
`ISO27001-MAPPING.md` (contrôles), `CONTEXT.md` (détail technique).*


<a id="doc-17"></a>

---

<!-- ============================== PROCEDURE-INTEGRITE-PREUVE.md ============================== -->

# Intégrité & valeur probante des journaux — OMNITECH SIEM

> ISO/IEC 27001 : A.8.15 (journalisation + **protection des journaux**), A.8.2 (droits d'accès privilégiés), A.5.28 (collecte de preuves). · 2026-06-14

## Problème adressé
Graylog OSS n'a pas d'archivage natif (Enterprise) et un administrateur peut supprimer/altérer des index (démontré : purge de 22,9 M docs). Sans contrôle, les journaux n'ont pas de **valeur probante**. On met en place une **preuve d'inaltérabilité (tamper-evidence)** OSS + du **moindre privilège**.

## Dispositif en place

### 1. Registre d'intégrité haché-en-chaîne + signé (`60-integrity.sh` → `/usr/local/sbin/omni-integrity`)
- **Quotidien (03:30)** : un *maillon* capture l'état du corpus (par index : `docs`, `bytes`, `uuid` ; totaux). Chaque maillon inclut le **hash SHA-256 du maillon précédent** (chaînage) et est **signé HMAC-SHA256** avec une clé root-only (`/etc/graylog/omni-integrity.key`, chmod 600).
- **Hors-SIEM** : le registre `/var/lib/omni-integrity/chain.jsonl` est copié à chaque exécution vers `//10.33.50.5/Public/SIEM/integrity/` → un insider du SIEM **ne peut pas réécrire l'historique** (la copie hors-bande + la signature le trahiraient).
- **Attestation** : chaque exécution émet un événement `event_source:siem_integrity` dans le SIEM lui-même (le SIEM atteste de son propre état).
- **Vérification à tout moment** : `omni-integrity --verify` → recalcule tous les hash, vérifie la signature HMAC et le chaînage. *Toute* altération (suppression masquée, édition) **casse la chaîne** (testé : falsifier une valeur ⇒ « CHAINE COMPROMISE »).

**En cas d'enquête / audit** : exécuter `omni-integrity --verify`, puis comparer `chain.jsonl` (SIEM) avec la copie SMB hors-bande (doivent être identiques jusqu'au dernier maillon commun). Une divergence ou une chaîne rompue = manipulation à investiguer.

### 2. Moindre privilège (anti-tampering préventif) — ISO A.8.2
- Rôle Graylog **« OMNI - Analyste (lecture seule) »** créé : lecture flux/recherches/dashboards, **aucun droit d'admin ni de suppression**.
- **Politique** : les comptes SOC utilisent ce rôle. Le compte **admin** (seul à pouvoir supprimer index/streams) est **break-glass** : usage exceptionnel, traçé (accès au SIEM journalisé), MDP au coffre, idéalement MFA.

### 3. Sauvegarde de configuration chiffrée hors-bande (`30-backup-config.sh`)
- Archive **AES-256** de la config (sans les logs) poussée quotidiennement vers le partage SMB, rétention bornée. Garantit la reconstruction (cf. `PRA-RECONSTRUCTION-SIEM.md`).

## Procédure d'extraction de preuve (chaîne de possession)
Pour produire des logs à valeur probante (incident, réquisition) :
1. Délimiter la recherche (Graylog ou OpenSearch) : période + critères, **horodatage UTC**.
2. Exporter le résultat (CSV/JSON).
3. **Sceller** : `sha256sum export.json > export.json.sha256` + noter date/heure, opérateur, motif.
4. Joindre l'extrait du registre d'intégrité (`omni-integrity --verify` + le maillon couvrant la période) qui atteste que le corpus n'a pas été altéré sur l'intervalle.
5. Conserver l'ensemble (export + hash + attestation) sur support maîtrisé ; journaliser la remise (qui/quand/à qui).

## Limites & évolution
- Le registre prouve l'inaltérabilité de l'**état** du corpus (suppression/altération **détectable**), pas une immutabilité du **contenu** au niveau bit. Pour aller plus loin : expédier les logs vers un stockage **WORM / S3 Object Lock** (immuable côté stockage) — chantier infra à part.
- Entra ID **P1** actuel : passer en **P2** enrichit la détection cloud (niveaux de risque, riskyUsers) — cf. couverture M365.

## Contrôles périodiques (à inscrire au plan d'exploitation)
- **Hebdo** : `omni-integrity --verify` (et comparaison avec la copie SMB).
- **Mensuel** : revue des comptes Graylog (qui a l'admin ?) + rotation de la clé HMAC si compromission suspectée.


<a id="doc-18"></a>

---

<!-- ============================== PROCEDURE-CHIFFREMENT-REPOS.md ============================== -->

# Chiffrement des données au repos — /data (OpenSearch) · OMNITECH SIEM

> ISO/IEC 27001 **A.8.24** (cryptographie) / **A.5.33** (protection des enregistrements). · **Réalisé le 2026-06-14.**
> Dispositif en production : **LUKS2 (header inline) + déverrouillage automatique TPM2**.

## Ce qui protège quoi
- ✅ Vol de disque, mise au rebut / SAV, vol du **serveur éteint** : `/data` illisible sans la clé (le TPM ne la libère jamais hors de cette plateforme ; passphrase de secours au coffre).
- ❌ Root compromis **machine allumée** (FS monté en clair) → couvert par ailleurs : RBAC (rôle lecture seule), intégrité signée des journaux, TLS console/Beats.
- Périmètre : seul `/data` (les **logs** OpenSearch) est chiffré. Le rootfs (OS + config) ne l'est pas — la config sensible y vit (`00-vars.env` chmod 600). Durcissement futur possible : chiffrer le rootfs.

## Configuration en place (référence)
| Élément | Valeur |
|---|---|
| Device | `/dev/sda1` (7,3 To) |
| Conteneur | **LUKS2 header inline**, `aes-xts-plain64`, clé 512 bits, PBKDF argon2id |
| LUKS UUID | `ff2e8939-9317-4932-a120-71113bb9d839` |
| Mapper | `/dev/mapper/cryptdata` |
| Filesystem | XFS (label `omni-data`), `path.data: /data/opensearch` + `/data/graylog-journal` |
| Keyslot 0 | **passphrase de secours** (→ Vaultwarden) |
| Keyslot 1 | **TPM2** (token `systemd-tpm2`, PCR 7) — déverrouillage auto au boot |
| `/etc/crypttab` | `cryptdata UUID=ff2e8939-… none luks,tpm2-device=auto,nofail` |
| `/etc/fstab` | `/dev/mapper/cryptdata /data xfs defaults,noatime,nofail 0 2` |
| Sauvegarde header | chiffrée AES-256 → `//10.33.50.5/Public/SIEM/luks/omni-luks-header-AAAA-MM-JJ.img.enc` + copie locale `/root/` |

> ⚠️ **TPM en banque PCR SHA-1** (ce TPM n'expose pas SHA-256) → scellement un peu moins robuste, sans impact sur la protection au repos. Durcissement : activer la banque PCR SHA-256 au BIOS Dell, puis ré-enrôler (cf. *Recovery*).

## Sécurité des clés (ordre d'importance)
1. **Passphrase de secours** (keyslot 0) → **Vaultwarden uniquement**, jamais en clair sur le serveur. Seul moyen de rouvrir `/data` si le TPM / la carte mère change. Le fichier temporaire `/etc/luks/.data-pass` est **détruit (`shred`) après enrôlement TPM + mise au coffre**.
2. **Sauvegarde du header** (`luksHeaderBackup`, chiffrée, hors-bande SMB) : un header corrompu = `/data` irrécupérable même avec la passphrase. → restaurable (cf. *Recovery*). Re-sauvegarder après **tout** changement de keyslot.
3. **TPM2** = confort (déverrouillage transparent au boot) ; disque illisible si sorti/volé (autre plateforme).

## Recovery — exploitation courante
```bash
# Ouverture MANUELLE (TPM indisponible) — demande la passphrase de secours (Vaultwarden)
cryptsetup open /dev/sda1 cryptdata
mount /data
systemctl start opensearch graylog-server

# Le TPM ne déverrouille plus au boot (MAJ firmware / Secure Boot / banque PCR) :
#   au boot, saisir la passphrase à l'invite, puis ré-enrôler le TPM :
systemd-cryptenroll /dev/sda1 --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7

# Restaurer le header depuis la sauvegarde hors-bande (header corrompu) :
#   1) récupérer le .enc sur le partage SMB, le déchiffrer (BACKUP_PASSPHRASE : 00-vars.env / coffre)
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in omni-luks-header-AAAA-MM-JJ.img.enc -out hdr.img
#   2) restaurer :
cryptsetup luksHeaderRestore /dev/sda1 --header-backup-file hdr.img

# Ajouter / changer la passphrase de secours :
cryptsetup luksAddKey /dev/sda1            # (puis luksRemoveKey pour l'ancienne)

# Re-sauvegarder le header après TOUT changement de keyslot :
cryptsetup luksHeaderBackup /dev/sda1 --header-backup-file /root/omni-luks-header-$(date +%F).img
```

## Comment ç'a été déployé (2026-06-14)
Méthode **reformatage chiffré à neuf** (rapide, ~10 min) plutôt qu'un rechiffrement in-place (≈ **21 h** pour 7,3 To au niveau bloc). Possible parce que **toute la config est hors `/data`** (MongoDB `/var/lib/mongodb`, scripts `/root/omnitech-siem-setup`, lookups, `data_dir` Graylog `/var/lib/graylog-server`) : seuls les **logs indexés** vivaient sur `/data`, jugés reconstituables (purge/repeuplement déjà pratiqués).
```bash
systemctl stop graylog-server opensearch          # /data libéré
umount /data
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 \
   --pbkdf argon2id --batch-mode --key-file /etc/luks/.data-pass /dev/sda1
cryptsetup open --key-file /etc/luks/.data-pass /dev/sda1 cryptdata
mkfs.xfs -f -L omni-data /dev/mapper/cryptdata
# /etc/fstab -> /dev/mapper/cryptdata ; mount /data
mkdir -p /data/opensearch /data/graylog-journal
chown opensearch:opensearch /data/opensearch ; chown graylog:graylog /data/graylog-journal ; chmod 750 /data/*
systemd-cryptenroll /dev/sda1 --tpm2-device=auto --tpm2-pcrs=7 --unlock-key-file=/etc/luks/.data-pass
# /etc/crypttab (cf. tableau) ; systemctl daemon-reload
systemctl start opensearch graylog-server
bash 54-post-purge-repopulate.sh                  # reconstruit les index ranges + repeuple
# validation du TPM par reboot (avec opérateur, console accessible)
```

## Annexe — alternative « préserver les données » (rechiffrement in-place, **non utilisé ici**)
Si un jour il faut chiffrer **sans perdre** les données d'un volume, en acceptant la durée (≈ 21 h / 7,3 To) :
- XFS ne rétrécit pas → **header détaché** obligatoire (jamais `--reduce-device-size`, qui casse le remontage XFS) :
  `cryptsetup reencrypt --encrypt --header /etc/luks/hdr.img --type luks2 --resilience checksum /dev/sdX`
  (reprenable via `--resume-only --header …`), puis `open --header` / `mount` / `systemd-cryptenroll --header`.
- Le **chiffrement online** (`cryptsetup open` d'abord, puis `reencrypt --resume-only --active-name cryptdata`) permet de garder le volume **monté et en service** pendant l'opération.
- ⚠️ On **ne peut pas annuler nativement** un `--encrypt` partiel (`--decrypt` le refuse : *« option --decrypt conflictuelle »*) : il faut soit le mener à terme, soit recopier la zone de tête en clair via le mapper ouvert. *(Validé sur loopback le 2026-06-14.)*

## Complémentaire (transit — priorité moindre, VLAN SIEM isolé = palliatif)
ESET (1515) / vSphere (1516) / FortiGate-FAZ (1514) en syslog **clair** → migrer en **syslog-over-TLS** (supporté par ESET PROTECT, vSphere, FortiGate) quand possible. Beats (5044) et console (9000) sont déjà en TLS.


<a id="doc-19"></a>

---

<!-- ============================== SOAR-PLAYBOOKS.md ============================== -->

# SOAR — Playbooks de réponse automatisée (OMNITECH SIEM)

> Cadrage du chantier « SOAR avancé » · 2026-06-14
> État : PB-01 en production. PB-02→05 **conçus, en attente de l'API NinjaOne**
> (accès à activer côté tenant, compte Owner — l'intégration se fera dès réception).

## Architecture (existant)
Service `omni-soar` (`/usr/local/sbin/omni-soar`) : HTTP local `127.0.0.1:8088`.
Une notification Graylog HTTP POST → action → garde-fous → état → effet.
- État : `/var/lib/omni-soar/blocklist.json`. Effet : `/var/www/siem-kit/soar/blocklist.txt` (threat feed servi par nginx, consommé par le FortiGate).
- **Garde-fous déjà en place (à conserver pour TOUT nouveau playbook) :** jamais d'IP RFC1918 / loopback / link-local / réservée, jamais la **whitelist**, seuil de hits, **cap** (taille max), **TTL** (expiration auto). Toute action est tracée en GELF (`event_source:siem_soar`).

## Catalogue des playbooks

| # | Playbook | Déclencheur (alert_tag) | Action | Dépendance | Statut |
|---|---|---|---|---|---|
| **PB-01** | Bloquer IP attaquante | Force brute VPN, password spraying | Ajout au threat feed FortiGate (TTL) | FortiGate (fait) | ✅ **PROD** |
| **PB-02** | Isoler un hôte compromis | `ransomware_indicator`, `lsass_access`, `lateral_movement` (confirmé) | NinjaOne : isolation réseau du device | **API NinjaOne** | 🟡 conçu |
| **PB-03** | Désactiver un compte | `canary`, `impossible_travel`, `dcsync` (confirmé) | Désactivation compte AD (script NinjaOne sur DC, ou LDAP) | **API NinjaOne** (ou LDAPS) | 🟡 conçu |
| **PB-04** | Ouvrir un ticket | Toute alerte P3 (mail tier) | Création d'un incident avec contexte (identité, hôte, MITRE) | **API ticketing NinjaOne** | 🟡 conçu |
| **PB-05** | Enrichir IOC | `threat_intel`, IP/domaine externes | Enrichissement TI + retro-hunt | MISP/feed (optionnel) | 🟡 conçu |

## Conception détaillée (PB-02 → PB-04)
Chaque playbook = un nouvel endpoint du service `omni-soar` (`/isolate`, `/disable`, `/ticket`), appelé par une notification Graylog dédiée, avec les **mêmes garde-fous renforcés** :

- **PB-02 Isoler hôte** — `POST /isolate {host}`.
  - Garde-fous CRITIQUES : **jamais** un contrôleur de domaine, le SIEM, l'hyperviseur, un serveur d'infra (whitelist de **rôles d'hôte** à définir) ; `risk_score >= 12` requis ; **réversible** (dé-isolation auto après TTL ou manuelle) ; option **confirmation manuelle** (tier « propose, n'exécute pas » pour les actions destructrices).
  - NinjaOne : endpoint *device isolation* (API `https://eu.ninjarmm.com/api/v2/...`, scope *management*).
- **PB-03 Désactiver compte** — `POST /disable {identity}` (s'appuie sur le champ **`identity`** unifié posé par `58`).
  - Garde-fous : **jamais** un compte *break-glass*/service/admin critique (whitelist de comptes) ; réversible (réactivation tracée) ; journalisé.
  - Mécanisme : script NinjaOne `Disable-ADAccount` sur un DC, ou bind LDAPS dédié (compte de service à privilèges minimaux : *Account Operators* restreint).
- **PB-04 Ticket** — `POST /ticket {event}` → ticket pré-rempli (titre = alerte, corps = identité + hôte + technique MITRE + lien Graylog). Sert de file d'incidents (pallie l'absence de case-management en OSS).

## Prérequis côté client (à fournir avant intégration)
1. 🔑 **API NinjaOne** : `client_id` + `client_secret` (OAuth2), scopes *management* (PB-02/03) et *ticketing* (PB-04). Région EU (`eu.ninjarmm.com`). → stocker dans `00-vars.env` (chmod 600) façon `FORTI_DHCP_TOKEN`.
2. **Whitelist de rôles d'hôte** à ne JAMAIS isoler (DC, SIEM, hyperviseurs, NAS, cœur réseau).
3. **Whitelist de comptes** à ne JAMAIS désactiver (break-glass, comptes de service critiques).

## Validation (avant mise en prod de chaque playbook)
Mode **dry-run** d'abord (`SOAR_DRYRUN=1` : le service logge l'action sans l'exécuter), sur un hôte/compte de TEST, puis bascule. Tester explicitement qu'une cible whitelistée / RFC1918 est **refusée**. Tenir un journal des déclenchements (utile ISO A.5.25/5.26).

> Dès que l'API NinjaOne est disponible : implémentation des endpoints `/isolate`, `/disable`, `/ticket` dans `omni-soar` + notifications + garde-fous, en dry-run puis prod.


<a id="doc-20"></a>

---

<!-- ============================== REPONSE-AUTOMATISEE.md ============================== -->

# Détection avancée & réponse automatisée — Canari AD + SOAR

*Version 1.0 — 12/06/2026 — Classification : interne — Réf ISO A.8.16, A.5.26.*

Ce document décrit les deux dispositifs « actifs » du SIEM : le **compte
canari** (détection d'intrusion à très faible bruit) et le **SOAR-light**
(réponse automatique par blocage d'IP).

---

## 1. Compte canari AD (détection d'intrusion interne)

### Principe
Un compte Active Directory **leurre**, crédible et attractif (il a l'air d'un
compte de service SQL privilégié), mais **sans aucun privilège réel** et qui
n'est **jamais utilisé légitimement**. Toute authentification, tentative ou
requête Kerberos le concernant ne peut être que le fait d'un attaquant qui
énumère l'annuaire, fait du brute force, du Kerberoasting ou du mouvement
latéral. **Taux de faux positifs quasi nul par construction.**

### Mise en œuvre
| Élément | Détail |
|---|---|
| Compte AD | `windows/New-OmniCanary.ps1` — mot de passe aléatoire jamais communiqué, `PasswordNeverExpires`, **SPN MSSQLSvc** (piège à Kerberoasting → génère un 4769), `logonHours` nuls, aucune appartenance privilégiée |
| Détection SIEM | lookup `omni-canary` (CSV `lookups/canary-accounts.csv`) + règle pipeline `omni-winsec-10-canary` (matche user / TargetUserName / SubjectUserName / ServiceName) |
| Alerte | **« OMNI - COMPTE CANARI touché »** — P3, mail + Teams, immédiate |
| Provisionnement | `35-canary.sh` (lookup + alerte), puis rejouer `12-graylog-pipelines.sh` |

### Exploitation
- **Ajouter un canari** : éditer `canary-accounts.csv` + relancer `35-canary.sh`.
- **Déclenchement = incident** : toute alerte canari est traitée en priorité
  (cf. playbook P-4, PRO §6). Identifier le poste/IP source immédiatement.
- Recommandé : un canari par zone sensible (un nom différent, crédible).

---

## 2. SOAR-light (blocage automatique d'IP attaquantes)

### Principe
Quand une attaque réseau est détectée (brute force / spraying VPN), le SIEM
publie l'IP source dans une **liste de blocage** que le FortiGate lit en
*External Threat Feed* et bloque. Architecture **découplée** : le SIEM n'a
**aucun identifiant** sur le pare-feu (sécurité), et le blocage **expire seul**.

### Chaîne complète
```
Alerte Graylog (Force brute VPN / Password spraying)
   │  notification HTTP
   ▼
omni-soar (service, 127.0.0.1:8088)
   │  sécurités : jamais RFC1918, jamais SOAR_WHITELIST,
   │  seuil SOAR_MIN_HITS, plafond SOAR_MAX, TTL SOAR_TTL_HOURS
   ▼
/var/www/siem-kit/soar/blocklist.txt   (servi en HTTPS)
   │  poll toutes les 2 min
   ▼
FortiGate External Connector "OMNI_SOAR_Blocklist"
   │
   ├─ local-in-policy  → bloque le portail SSLVPN (trafic vers le boîtier)
   └─ firewall policy  → bloque les services publiés (trafic traversant)
   ▼
Blocage — expiration automatique après TTL (défaut 24 h)
```

### Composants
| Élément | Rôle |
|---|---|
| `/usr/local/sbin/omni-soar` | service webhook → décision → feed (GELF de traçabilité) |
| `/usr/local/sbin/omni-soar-expire` (+ timer horaire) | retire les IP expirées |
| `36-soar.sh` | crée la notification HTTP, l'attache aux alertes VPN/spraying, crée l'alerte de traçabilité |
| `fortigate/06-soar-threatfeed.conf` | connecteur + policies FortiGate |
| Alerte **« OMNI - SOAR : IP bloquée automatiquement »** | mail à chaque blocage |

### Garde-fous (paramètres `00-vars.env`)
| Paramètre | Défaut | Rôle |
|---|---|---|
| `SOAR_WHITELIST` | (vide) | **IP publiques à NE JAMAIS bloquer** : sites OMNITECH, peers IPsec, admins. À renseigner. |
| `SOAR_MIN_HITS` | 5 | occurrences minimum de l'IP dans le backlog pour bloquer |
| `SOAR_MAX` | 500 | plafond d'IP simultanément bloquées |
| `SOAR_TTL_HOURS` | 24 | durée de blocage avant expiration auto |

Sécurités structurelles : **aucune IP privée** (RFC1918) n'est jamais bloquée ;
chaque blocage est **tracé** (mail + GELF) ; un faux positif se **débloque
seul** au bout du TTL.

### Exploitation
- **Voir les IP bloquées** : console SIEM (page Sauvegardes / recherche
  `event_action:ip_bloquee`) ou FortiGate GUI (*External Connectors → View
  Entries*). Les commandes `diagnose` CLI ne sont pas supportées sur toutes
  les versions FortiOS.
- **Débloquer manuellement** : retirer l'IP de `/var/lib/omni-soar/blocklist.json`
  puis `python3 /usr/local/sbin/omni-soar-expire`.
- **Compléter la whitelist** : indispensable avant exploitation réelle —
  ajouter les IP publiques fixes des sites et des admins.
- **Test de bout en bout** : injecter une IP de test dans le feed et vérifier
  qu'elle est lue côté FortiGate (poll ≤ 2 min, visible dans les logs nginx).

> ⚠️ Le SOAR agit **automatiquement** sur le pare-feu. Maintenir la whitelist
> à jour est une responsabilité d'exploitation (revue mensuelle, PRO §2).

## Évolution — SOAR avancé (cadrage)

Le blocage d'IP ci-dessus est **PB-01** (en production). Les playbooks suivants
sont **conçus**, en attente de l'**API NinjaOne** (cf. **`SOAR-PLAYBOOKS.md`**) :
- **PB-02 Isoler un hôte** compromis (ransomware / LSASS / lateral confirmé).
- **PB-03 Désactiver un compte** (s'appuie sur le champ `identity`) — canari /
  impossible travel / DCSync.
- **PB-04 Ouvrir un ticket** d'incident pré-rempli ; **PB-05 Enrichir IOC**.

Garde-fous renforcés (mêmes principes que PB-01) : **jamais** un contrôleur de
domaine / le SIEM / l'hyperviseur / un compte break-glass ; **dry-run** d'abord ;
actions réversibles et tracées. Tant que NinjaOne n'est pas branché, l'isolation
et la désactivation restent **manuelles** (cf. PROCEDURE-INCIDENT §5).


<a id="doc-21"></a>

---

<!-- ============================== LDAPS.md ============================== -->

# LDAPS — Authentification Active Directory sur la console Graylog

*Objectif : comptes nominatifs AD pour la console (traçabilité ISO A.5.16/A.8.5),
le compte local `admin` ne servant plus que de secours.*

## 0. Choix retenus (12/06/2026)

- Compte de liaison : **`svc_siem`** (réutilisé — utilisateur standard,
  également utilisé pour le dépôt des sauvegardes).
- Compte de test / référence admin : **`adm-jmorin`**.
- DC cible : **bx-ad-01-it-vm.omnitech.security (10.33.50.250)**.
- Pré-requis pare-feu : règle FortiGate **425** (Réseau ELK → DC) doit
  inclure le service **LDAPS-GC** (636/3269) — `append service "LDAPS-GC"`.
- **Accès restreint aux membres du groupe « Admins du domaine »** (filtre
  LDAP `memberOf` récursif) : un compte AD hors groupe ne peut pas
  s'authentifier du tout.
- Rôle attribué automatiquement : **Admin** (population déjà restreinte).
- Compte local `admin` conservé en secours (coffre).

> **ÉTAT : OPÉRATIONNEL (12/06/2026).** Backend « Active Directory OMNITECH »
> actif (LDAPS 636, certificat vérifié par la Root CA interne). DN du groupe
> confirmé par LDAP : `CN=Admins du domaine,OU=Comptes_Service,OU=_Support,
> OU=Entreprise,DC=omnitech,DC=security`. Filtre testé : adm-jmorin (admin)
> admis, svc_siem (non-admin) rejeté. Règle FortiGate 425 : LDAPS-GC ajouté.

## 1. Pré-requis (côté AD — 5 minutes)

1. **Compte de liaison** (lecture seule, jamais interactif) :
   **`svc_siem`** — compte de service du domaine déjà existant (réutilisé,
   il sert aussi au dépôt des sauvegardes), mot de passe fort, « le mot de
   passe n'expire pas », aucune appartenance privilégiée. Le bind se fait au
   format UPN : `svc_siem@omnitech.security`.
2. **LDAPS actif sur les DC** : avec AD CS + auto-enrollment c'est déjà le
   cas en général. Vérification depuis le SIEM (contre le DC réellement
   ciblé) :
   ```bash
   echo | openssl s_client -connect bx-ad-01-it-vm.omnitech.security:636 \
     -CAfile /etc/graylog/certs/omnitech-rootca.crt 2>/dev/null | grep "Verify return"
   # attendu : Verify return code: 0 (ok)   <- confirmé en prod (14/06/2026)
   ```
   (La JVM de Graylog fait déjà confiance à la Root CA via `cacerts-omni.jks`.)
3. Règle FortiGate **425** (Réseau ELK → DC) : ajouter le service
   **LDAPS-GC** (TCP 636 + Global Catalog 3269) — `append service "LDAPS-GC"`.
   La règle n'ouvrait au départ que web+ping ; le service LDAPS-GC a bien été
   ajouté (cf. section 0).

## 2. Mise en place (côté SIEM)

```bash
# 1. renseigner les variables dans 00-vars.env :
LDAP_HOST='bx-ad-01-it-vm.omnitech.security'
LDAP_BIND_DN='svc_siem@omnitech.security'          # bind au format UPN
LDAP_BIND_PASS='********'
LDAP_REQUIRED_GROUP_DN='CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security'
# (optionnels avec valeurs par défaut : LDAP_PORT=636, LDAP_SEARCH_BASE=DC=omnitech,DC=security)

# 2. executer :
bash /root/omnitech-siem-setup/33-ldaps-auth.sh
```

Le script crée le backend « Active Directory OMNITECH » (Active Directory,
LDAPS :636, `transport_security=tls`, `verify_certificates=true`), applique
le filtre LDAP restrictif (cf. section 3), attribue le rôle par défaut
**Admin**, puis l'ACTIVE. Le script est **idempotent** (rejoue sans casser un
backend déjà créé). Il vérifie d'abord le certificat LDAPS contre la Root CA
interne ; s'il est injoignable, il avertit mais continue (Graylog refusera
simplement les connexions tant que ce n'est pas corrigé).

## 3. Fonctionnement et attribution des rôles

- **Accès restreint par filtre LDAP** : le `user_search_pattern` du backend
  n'autorise QUE les membres (récursifs) du groupe « Admins du domaine ».
  Un compte AD hors de ce groupe est invisible au backend et **ne peut pas
  s'authentifier du tout** :
  ```
  (&(objectClass=user)
    (|(sAMAccountName={0})(userPrincipalName={0}))
    (memberOf:1.2.840.113556.1.4.1941:=CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security))
  ```
  Le OID `1.2.840.113556.1.4.1941` (LDAP_MATCHING_RULE_IN_CHAIN) rend
  l'appartenance **récursive** (groupes imbriqués pris en compte).
- La population étant déjà restreinte aux administrateurs du domaine, le
  backend attribue **directement le rôle `Admin`** (`default_roles`) à la
  première connexion — pas de promotion manuelle à faire.
  > En édition Open Source il n'existe pas de team sync (mapping rôle ⇄ groupe
  > AD) ; le choix « filtre group-restricted + rôle Admin par défaut » est la
  > façon d'obtenir un accès admin réservé sans Enterprise.
- Connexion avec `sAMAccountName` (ou UPN) + mot de passe AD ; le nom complet
  affiché vient de `displayName`.
- Le compte local `admin` reste actif en secours (si l'AD est indisponible,
  la console reste administrable) — mot de passe au coffre.

## 4. Retour arrière

System → Authentication → désactiver le backend (l'authentification locale
reprend seule), ou via API : `POST /system/authentication/services/configuration`
avec `{"active_backend": null}`.

---
*Dernière revue : 14/06/2026 — faits vérifiés contre `33-ldaps-auth.sh`,
`00-vars.env` et le backend actif (API Graylog). Backend OPÉRATIONNEL,
certificat LDAPS vérifié (`Verify return code: 0`).*


<a id="doc-22"></a>

---

<!-- ============================== GUIDE-DEPANNAGE.md ============================== -->

# Guide de dépannage — SIEM OMNITECH

*Version 1.1 — révisé le 14/06/2026 — Classification : interne. Format : symptôme → cause → solution.
Référence technique exhaustive des incidents résolus : `CONTEXT.md` (section « PIÈGE À RETENIR »).*

> Sources actuellement collectées : AD/Sysmon (Winlogbeat, Beats TLS 5044), FortiGate (via
> FortiAnalyzer, syslog 1514 TCP/UDP), Microsoft 365 (GELF HTTP 12201, collecte *pull*),
> vSphere (syslog 1516 TCP/UDP), Veeam (canal Windows), **ESET PROTECT** (syslog JSON TCP 1515,
> champs `eset_*`), **BunkerWeb WAF** (Filebeat sur le Beats 5044 partagé, champs `http_*`/`waf_*`).
> **NPS** est mappé (lookup `win-events.csv`) mais pas encore remonté côté client.

## 1. Collecte — une source ne remonte plus

| Symptôme | Cause probable | Solution |
|---|---|---|
| Un canal Windows **Security** muet, les autres OK | Liste `event_id` trop longue dans winlogbeat.yml (> ~23 expressions → ERROR_EVT_INVALID_QUERY) | Utiliser des **plages** (`4624-4799`), jamais une liste plate. Redéployer via `Install-OmniSiem-NinjaOne.ps1` |
| Un hôte n'apparaît plus du tout | Agent arrêté / pare-feu 5044 | Sur l'hôte : `Get-Service winlogbeat` ; tester `Test-NetConnection <siem> -Port 5044` |
| FortiGate : seul `voip` en UTM, pas virus/IPS/web | Profils UTM non attachés aux policies | `fortigate/05/06-utm-*.conf` ; vérifier `show firewall policy <id>` |
| FortiGate : `source` = adresse IP au lieu du nom d'équipement | Règle de normalisation non appliquée | Le pipeline pose `source` = champ `host` (règle `omni-forti-06-source-host`, script 12) ; vérifier que la règle est dans le stage FortiGate |
| FortiGate : horodatage décalé / événements « dans le futur » | `timestamp` non recalé sur l'heure d'origine de l'équipement | Le pipeline pose `timestamp` depuis `eventtime` (epoch ns → ms, règle `omni-forti-05-eventtime`, corrigé 14/06) |
| vSphere : logs présents mais **0 host/event_action** | Stage pipeline `match either` avec une seule règle conditionnelle → bloque le reste | Mettre la normalisation dans le même stage (corrigé 12/06) |
| Serveur Veeam : pas de canal « Veeam Backup » | Aucun job depuis le dernier contrôle (normal) **ou** canal non collecté | Attendre un job ; sinon relancer `Install-OmniSiem` (auto-détecte le canal) |
| M365 : volume très faible / page vide | Collecteur planté **ou** curseur non rejoué après purge | `journalctl -u omni-m365-fetch` (et `omni-m365-activity`) ; reset curseur `/var/lib/omni-m365/state.json` |
| **ESET** : input 1515 vide alors que la console ESET émet | Redirection 514→1515 absente côté pare-feu, ou syslog ESET désactivé | ESET PROTECT (10.33.50.20) envoie en **514**, redirigé vers 1515 par le pare-feu ; vérifier l'input `ESET (Syslog TCP 1515)` et la règle de redirection |
| **ESET** : messages reçus mais non parsés (`eset_*` absents) | Format non-JSON ou préfixe syslog non strippé | Le pipeline strip tout avant le 1er `{` puis `set_fields(..., "eset_")` (règle `omni-eset-05-json`) ; vérifier que `event_source=eset` est bien posé |
| **BunkerWeb** : logs WAF qui atterrissent dans « OMNI - Windows autres » | BunkerWeb partage le **Beats 5044** avec Winlogbeat → routage par `filebeat_event_source` | Filebeat doit poser `filebeat_event_source=bunkerweb` ; une règle d'exclusion (`inverted`) écarte BunkerWeb de « OMNI - Windows autres » (script 52) |
| **NPS** : rien ne remonte | Normal à ce stade : mappé mais pas encore activé côté client | NPS (10.33.50.247) passera par Winlogbeat/Beats 5044 ; mapping prêt via lookup `win-events.csv` |
| **Vaultwarden** : logs coffre dans « OMNI - Windows autres » | Même partage Beats 5044 → routage par `filebeat_event_source` | Filebeat doit poser `filebeat_event_source=vaultwarden` ; exclusion (`inverted`) + **index dédié `omni-vaultwarden`** (script 55). Le bruit « too many admin requests » (boucle conteneur) est droppé au pipeline |
| **`src_hostname` vide** sur les logs FortiGate internes | Attribution DHCP en panne | `systemctl status omni-fortidhcp-fetch.timer` + `journalctl -u omni-fortidhcp-fetch` ; vérifier token RO FortiGate + lookup `omni-dhcp-attribution` (script 56) |
| **Alerte « Intégrité des logs COMPROMISE »** | Chaîne de hachage rompue (suppression/altération) | `omni-integrity --verify` ; comparer `/var/lib/omni-integrity/chain.jsonl` avec la copie SMB `/SIEM/integrity/` ; figer & investiguer (script 60) |

## 2. Indexation — messages perdus

| Symptôme | Cause | Solution |
|---|---|---|
| **Indexer failures** > 0 (System → Indexer failures) | Champ typé rejeté (ex `src_ip` = "N/A"/"x.x"/ip:port) | Corriger **à la source ou au pipeline** (jamais assouplir le mapping). Cf. clean_ip / regex IP |
| Recherche « vide » alors que les logs arrivent | Index range non recalculé (après purge/manip) | `POST /api/system/indices/ranges/rebuild` |
| Tout semble vide sur 24h/7j après une **purge** | Comportement attendu : l'historique a été effacé, la collecte repart de zéro | Regarder une fenêtre « depuis la purge » ; les agents ne rejouent pas l'historique. La repopulation des dashboards est gérée par `54-post-purge-repopulate.sh` |
| Une source plus ancienne que sa rétention a disparu | Comportement attendu (rétention par index set) | Rétentions : **FortiGate 180 j** ; Windows/Sysmon/vSphere/M365/ESET **365 j** ; **BunkerWeb 90 j**. Disque `/data` = 7,3 To |

## 3. Alertes — trop, ou pas assez

| Symptôme | Cause | Solution |
|---|---|---|
| Tempête de mails identiques | Grâce trop courte / pas de clé / échec service compté comme brute force | `21-alert-hygiene.sh` (grâces ≥ 60 min, clés par compte/IP, exclusion logon type 4/5) |
| Trop d'alertes par mail (pas que le critique) | Routage 2 tiers non (ré)appliqué | `22-alert-routing.sh` : **Teams = firehose** (toutes les alertes, ~87) ; **mail = critique « réveille-moi » uniquement** (~26 : compromission confirmée + santé SIEM). À relancer après 13/21 |
| Plus aucune alerte Teams reçue | Flux Power Automate throttlé/cassé (échoue **en silence**, Graylog reçoit 202) | Vérifier l'**historique d'exécution** du flux Power Automate (pas les logs Graylog) |
| Plus aucun mail critique reçu | Notification mail retirée de toutes les définitions, ou SMTP cassé | Vérifier que `22-alert-routing.sh` a bien conservé le mail sur la liste `KEEP` ; tester l'envoi SMTP depuis Graylog |
| Une alerte ne se déclenche jamais | Le stream interrogé ne route pas la source ; ou `key_spec` sans `field_spec` | Vérifier les règles du stream ; toute clé doit avoir une entrée `field_spec` |
| Incident critique compté plusieurs fois | Doublons de kill-chain | Dédup au niveau de la corrélation d'incidents (`omni-incident-correlate`, corrigé 14/06) |
| Faux positifs récurrents | Détection trop large | Exclusion ciblée **au pipeline** (script 12/13/21), pas en console seule. Exclusions en place : comptes machine `*$` + comptes de service (`ninjaone`, `ADSyncMSA`) pour la force brute ; `wakeup-ssrs.ps1` pour PowerShell ; `vpxuser`/`dcui`/`localhost` pour la force brute vSphere |

## 4. Console / authentification

| Symptôme | Cause | Solution |
|---|---|---|
| « invalid credentials » avec un compte AD admin | Port 636 (LDAPS) bloqué → backend non créé → compte AD inconnu | Ouvrir 636 (règle FortiGate 425) puis `bash 33-ldaps-auth.sh` |
| Login AD refusé pour un compte admin du domaine | DN du groupe erroné dans le filtre | Récupérer le DN exact (`ldapsearch ... memberOf`) ; le groupe peut être hors `CN=Users` |
| Console inaccessible / boucle JSON.parse | TLS mal configuré (truststore, http_publish_uri) | CA dans `cacerts-omni.jks`, `http_publish_uri` = FQDN → 127.0.0.1 via /etc/hosts |

## 5. Sauvegarde / capacité / SOAR

| Symptôme | Cause | Solution |
|---|---|---|
| Sauvegarde config échoue (SMB) | Montage CIFS refusé (guest) / pare-feu 445 | `/root/.smb-siem.cred` (compte dédié, chmod 600) ; règle FortiGate Réseau ELK → Files 445 |
| `/data` se remplit | Volume anormal d'un flux | `32-disk-guard.sh` (timer `omni-disk-guard`) alerte à 80 %, purge d'urgence à 88 % ; revoir `41-retention-iso.sh` |
| SOAR : `diagnose` CLI échoue sur FortiGate | Commande non supportée par la version | Vérifier via **GUI** (External Connectors → View Entries) ; les logs nginx du SIEM prouvent le poll |
| SOAR ne bloque pas le portail VPN | Trafic « local-in » non filtré par une firewall policy forward | Utiliser une **`local-in-policy`** (le portail écoute sur le boîtier) |
| FortiGate ne lit pas le feed (HTTPS) | Root CA OMNITECH absente du FortiGate | Importer la CA (*System → Certificates*) ou servir le feed en HTTP |
| Certificat console / parc proche de l'expiration | Surveillance permanente | `omni-cert-check` (télémétrie continue) alerte par mail ; renouvellement console automatisé via `omni-cert-renew` (CSR → AD CS via SMB) |

## 6. Purge / remise à zéro propre

| Symptôme / besoin | Détail | Solution |
|---|---|---|
| Repartir sur des index vides sans perdre la config | Après validation des correctifs de faux positifs | `53-purge-clean.sh` : cycle deflector + suppression des anciens index via l'API (streams, pipelines, lookups, inputs, alertes, dashboards conservés ; `gl-system-events` conservé). **DESTRUCTIF** |
| Dashboards vides juste après une purge | Widgets dérivés non re-calculés tant que les robots n'ont pas re-tourné | `53-` enchaîne automatiquement `54-post-purge-repopulate.sh` (rebuild ranges + re-fetch M365 + relance des robots). Désactiver l'enchaînement : `PURGE_NO_REPOP=1` |
| Après purge, UEBA/NDR/vulnérabilités restent partiellement vides | Normal : baseline UEBA, motifs NDR sur heures, inventaire vuln quotidien nécessitent de la donnée fraîche | Attendre l'accumulation — ce n'est pas un bug |

## 7. Réflexes de diagnostic (commandes utiles, sur le SIEM)

```bash
# état général
systemctl status graylog-server opensearch mongod nginx
systemctl list-timers 'omni-*'
curl -s '127.0.0.1:9200/_cat/indices/omni-*?h=index,docs.count,store.size&s=index'

# débit d'un flux (5 min) — préfixes : omni-winsec omni-sysmon omni-winother
#   omni-fortigate omni-m365 omni-vsphere omni-eset omni-bunkerweb
curl -s "127.0.0.1:9200/omni-<flux>_*/_count" -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-5m"}}}}'

# un hôte remonte-t-il ?  (recherche source:<hostname> sur 15 min via la console)

# journal d'un collecteur
journalctl -u omni-m365-fetch -n 20
journalctl -u omni-m365-activity -n 20
tail -f /var/log/graylog-server/server.log
```

## 8. Pièges API Graylog 7.x (à connaître pour intervenir au pipeline)

- **Pas de ternaire** dans les règles pipeline : utiliser `if/else`.
- `contains()` prend **2 arguments** (`contains(valeur, sous-chaîne)`).
- Sur les `POST` d'entités, encapsuler le corps dans l'**enveloppe** `{entity}` attendue.
- Cycle du deflector : `POST /system/deflector/{id}/cycle` (utilisé par la purge).
- Dashboard unique **« OMNI - SOC »** (24 pages) : `requires={}` → 100 % OSS, **pas d'Enterprise**.

---

> En cas d'incident non listé : consigner symptôme + résolution dans `CONTEXT.md`
> (section « PIÈGE À RETENIR ») pour enrichir ce guide.
> Voir aussi : `INTEGRATION-SOURCES.md`, `POLITIQUE-RETENTION.md`, `PROCEDURE-INCIDENT.md`.


<a id="doc-23"></a>

---

<!-- ============================== GLOSSAIRE.md ============================== -->

# Glossaire — SIEM OMNITECH

*Termes employés dans le dossier documentaire, pour les lecteurs non
spécialistes (direction, audit, nouveaux arrivants).*

> Date de revue : 2026-06-14.

## Concepts généraux

| Terme | Définition |
|---|---|
| **SIEM** | *Security Information and Event Management*. Système qui centralise les journaux de tout le SI, les corrèle, détecte les menaces et alerte. Ici : Graylog. |
| **SOC** | *Security Operations Center*. La fonction de supervision de sécurité (chez OMNITECH : l'équipe IT, outillée par le SIEM). |
| **Journal / log** | Trace horodatée d'un événement (connexion, accès, action). La matière première du SIEM. |
| **Graylog** | Le logiciel SIEM (open source) qui ingère, traite et présente les logs. |
| **OpenSearch** | La base de données qui stocke et indexe les logs (moteur de recherche). |
| **Input** | Point d'entrée des logs dans Graylog (un port + un protocole). |
| **Stream** | Flux nommé qui regroupe les messages d'une même source (ex. « Windows Security »). |
| **Pipeline / règle** | Traitement appliqué aux messages : normalisation, enrichissement, marquage. |
| **Index / rétention** | Stockage par période ; la rétention est la durée de conservation avant suppression automatique. |
| **Détection / alerte** | Règle qui surveille un motif (ex. 10 échecs de connexion) et notifie quand il se produit. |
| **Dashboard** | Tableau de bord visuel (ici « OMNI - SOC », tableau unique de 24 pages, 100 % open source — aucune licence Enterprise requise). |
| **GeoIP** | Enrichissement qui associe une IP à un pays/ville (pour la cartographie). |
| **Lookup** | Table de correspondance (ex. code d'événement → libellé lisible, IP canari → compte). |

## Sources de logs et collecteurs

| Terme | Définition |
|---|---|
| **AD (Active Directory)** | Annuaire Microsoft qui gère comptes, postes et authentifications du domaine ; principale source d'événements de sécurité. |
| **Winlogbeat** | Agent installé sur les machines Windows (AD, serveurs) qui envoie leurs journaux au SIEM, chiffré (Beats sur le port 5044, TLS). |
| **Sysmon** | Outil Microsoft qui produit une télémétrie détaillée des postes (processus, réseau, création de fichiers…) ; rétention 365 j. |
| **FortiGate** | Pare-feu Fortinet d'OMNITECH ; ses logs (trafic + UTM) sont volumineux, d'où une rétention dédiée de 180 j. Le champ `source` porte le nom de l'équipement. |
| **FortiAnalyzer (FAZ)** | Collecteur Fortinet qui centralise les logs des pare-feu FortiGate et les transmet au SIEM (syslog, port 1514). |
| **UTM** | *Unified Threat Management* : fonctions de sécurité du pare-feu (antivirus, IPS, filtrage web/DNS). |
| **M365 (Microsoft 365)** | Suite cloud Microsoft (messagerie, OneDrive…) ; l'activité d'audit est récupérée par un collecteur puis injectée en GELF. |
| **GELF** | *Graylog Extended Log Format* : format de log structuré utilisé pour les collecteurs M365 et l'auto-surveillance du SIEM. |
| **vSphere / vCenter** | Plateforme de virtualisation VMware ; les hôtes ESXi et le vCenter envoient leurs logs en syslog (port 1516). |
| **Veeam** | Solution de sauvegarde ; ses journaux alimentent la détection liée aux sauvegardes (suppression, échecs). |
| **ESET PROTECT** | Console antivirus/EDR ESET ; envoie ses détections en syslog JSON (port 1515) vers le stream « OMNI - ESET » (champs `eset_*`), rétention 365 j. |
| **BunkerWeb** | Pare-feu applicatif web (WAF) protégeant les services exposés ; ses logs sont remontés par Filebeat vers l'input Beats (5044) → stream « OMNI - BunkerWeb » (champs `http_*` / `waf_*`), rétention 90 j. |
| **WAF** | *Web Application Firewall* : filtre les requêtes HTTP malveillantes (injections, scans…) ; ici assuré par BunkerWeb. |
| **Filebeat** | Agent léger qui lit des fichiers de logs (ex. BunkerWeb) et les expédie au SIEM via l'input Beats. |
| **NPS** | *Network Policy Server* (serveur RADIUS Microsoft) ; mappé dans la documentation mais pas encore remonté côté client. |

## Menaces et techniques d'attaque

| Terme | Définition |
|---|---|
| **DCSync** | Technique d'attaque : se faire passer pour un contrôleur de domaine pour voler les mots de passe AD. |
| **Kerberoasting** | Attaque qui extrait des tickets Kerberos pour casser les mots de passe de comptes de service. |
| **Brute force / spraying** | Essais massifs de mots de passe (brute force = un compte ; spraying = un mot de passe sur beaucoup de comptes). |
| **Ransomware** | Logiciel qui chiffre les données pour extorsion ; détecté ici via la suppression des sauvegardes (shadow copies). |
| **LSASS** | Processus Windows qui détient les identifiants en mémoire ; cible classique de vol de mots de passe. |
| **Compte canari** | Compte leurre jamais utilisé ; toute activité le concernant signale une intrusion (lookup `omni-canary`, alerte critique mail + Teams). |

## Détection, réponse et alerting

| Terme | Définition |
|---|---|
| **MITRE ATT&CK** | Référentiel public des tactiques et techniques d'attaque ; le SIEM corrèle les détections par tactique pour repérer les chaînes d'attaque. |
| **UEBA** | *User and Entity Behavior Analytics* : score de risque comportemental par hôte/compte (détections + vulnérabilités + anomalies fusionnées). |
| **NDR** | *Network Detection and Response* : détection des comportements réseau suspects (scans, exfiltration DNS…). |
| **SOAR** | *Security Orchestration, Automation and Response* : réponse automatisée (ici, blocage d'IP attaquantes sur le pare-feu). |
| **Threat feed** | Liste d'IP/domaines malveillants qu'un pare-feu lit pour bloquer ; le SIEM en alimente une dynamiquement. |
| **LDAPS** | LDAP sécurisé (chiffré) : protocole d'authentification des comptes AD sur la console. |
| **P2 / P3** | Niveaux de priorité des alertes (P3 = critique ; P2 = important). Le P3 « réveille-moi » part en mail ; toutes priorités confondues partent aussi sur Teams. |
| **Routage 2 tiers (mail / Teams)** | Acheminement des notifications : **Teams = firehose** (toutes les alertes) ; **mail = 26 alertes critiques** seulement (compromission confirmée + santé du SIEM). Évite le spam de la boîte mail (script `22-alert-routing.sh`). |
| **Grâce (anti-tempête)** | Délai pendant lequel une même alerte ne re-notifie pas, pour éviter le spam (≥ 60 min sur les alertes mail récurrentes). |

## Gouvernance et exploitation

| Terme | Définition |
|---|---|
| **RTO / RPO** | Objectifs de continuité : temps de reprise (RTO) et perte de données maximale (RPO). |
| **IaC** | *Infrastructure as Code* : toute la configuration est dans des scripts reproductibles, pas faite « à la main ». |
| **Purge / repopulation** | Procédure d'exploitation : `53-purge-clean.sh` efface les données en conservant la configuration, puis `54-post-purge-repopulate.sh` réamorce les flux. |
| **ISO 27001** | Norme internationale de management de la sécurité de l'information ; ce dossier en couvre les mesures de journalisation/surveillance. |

## Détection avancée, intégrité & chiffrement

| Terme | Définition |
|---|---|
| **MITRE ATT&CK** | Référentiel mondial des techniques d'attaque (T####). Chaque détection y est mappée ; la couverture (44 techniques) se visualise en chargeant le calque `mitre-navigator-layer.json` dans ATT&CK Navigator. |
| **KEV** | *Known Exploited Vulnerabilities* (catalogue CISA) : failles **activement exploitées** dans la nature → priorité de correction absolue. |
| **Intégrité / tamper-evidence** | Registre quotidien **haché-en-chaîne et signé** de l'état des journaux, copié hors-SIEM : rend toute suppression/altération rétroactive **prouvable** (valeur probante d'audit). |
| **Identité unifiée (`identity`)** | Compte canonique (sans domaine ni `@upn`) corrélant une même personne à travers AD, M365, VPN, endpoint ; `identity_human` regroupe les comptes `adm-`/`svc-` sous la personne. |
| **Attribution DHCP (`src_hostname`)** | Corrélation IP→machine via les baux DHCP du FortiGate : répond à « qui se cache derrière 10.33.x.x » en investigation. |
| **SOAR** | *Security Orchestration, Automation & Response* : réponse réflexe (ex. blocage d'une IP attaquante), avec garde-fous (jamais une IP interne ou en liste blanche). |
| **TPM2 / LUKS** | Chiffrement du disque de données `/data` : LUKS2 chiffre, le **TPM2** (puce de la carte mère) déverrouille automatiquement au démarrage — le disque reste illisible s'il est volé/extrait. |
| **Entra ID Protection** | Moteur de risque (ML) de Microsoft sur le tenant M365 : signale les comptes « à risque » (impossible travel, identifiants fuités…) — ingéré dans le SIEM (`m365_type:risk`). |


<a id="doc-24"></a>

---

<!-- ============================== CHANGELOG.md ============================== -->

# Journal des modifications — SIEM OMNITECH

Toutes les évolutions notables du dispositif. Format : date — changement.
*Dernière revue : 2026-06-14.*

## 2026-06-14 (audit de cohérence & nouvelles sources)

### Nouvelles sources intégrées (`52-new-sources.sh`)
- **ESET PROTECT** (10.33.50.20) : input Syslog TCP 1515 (514 redirigé par le
  pare-feu), stream « OMNI - ESET », `event_source=eset` (+ tag menace). Index set
  dédié `omni-eset` (rétention 365 j). Alerte « ESET : détection » (route mail).
- **BunkerWeb WAF** (10.33.70.1) : Filebeat → Beats 5044, stream « OMNI - BunkerWeb »
  (routage par `event_source=bunkerweb` posé par Filebeat), tag WAF, champs `http_*`/`waf_*`.
  Index set dédié `omni-bunkerweb` (rétention 90 j), page dashboard « WAF BunkerWeb ».
- **NPS** (10.33.50.247) : déjà mappé côté SIEM (lookup `win-events.csv` 6272/6273/6274
  + alerte ajoutée en 13). Reste à déployer Winlogbeat côté serveur — **pas encore
  remonté côté client**.

### Bugs corrigés (audit de cohérence 2026-06-14)
- **Timestamp FortiGate** : pose du `timestamp` depuis `eventtime` (epoch
  nanosecondes) — règle `omni-forti-05-eventtime`, conforme A.8.17 (synchro horaire).
- **Faux positifs brute-force** : exclusion des comptes machine (`*$`) et des comptes
  de service bruyants (`ninjaone`, `ADSyncMSA_*`) qui échouent en boucle.
- **PowerShell** : exclusion de `wakeup-ssrs.ps1` (tâche légitime récurrente).
- **vSphere brute-force** : exclusion de `vpxuser` / `dcui` / `localhost`.
- **Déduplication des incidents** : `event_source=incident` routé vers « OMNI - Interne
  SIEM » avec exclusion symétrique côté M365 (anti-dup) — `44-incidents.sh`.
- **cert-check** passé en télémétrie permanente.

### Architecture & rétentions
- **Index sets dédiés** ESET et BunkerWeb (séparation des flux et des rétentions).
- Rétentions actuelles : **FortiGate = 180 j** ; Windows/Sysmon/vSphere/M365/ESET = 365 j ;
  **BunkerWeb = 90 j**. Disque `/data` : 7,3 To.
- FortiGate : `source` = nom de l'équipement (host).

### Routage des alertes (2 tiers — `22-alert-routing.sh`)
- **Teams = firehose** : toutes les alertes.
- **Mail = critique « réveille-moi »** uniquement (compromission confirmée + santé
  SIEM), 26 alertes. Grâce des alertes mail récurrentes relevée à ≥ 60 min.
- Templates mail/Teams enrichis et *source-aware* (script 13).

### Outillage de purge
- `53-purge-clean.sh` : purge des **données** (logs + historique d'alertes) en
  conservant **toute la configuration** (méthode : cycle deflector + suppression des
  anciens index via l'API). Enchaîne sur `54-post-purge-repopulate.sh` (reconstruction
  des ranges, re-fetch M365, relance des robots d'analyse).

### Vérifications (live)
- Dashboard unique **« OMNI - SOC » à 24 pages**, `requires={}` (100 % OSS, pas
  d'Enterprise).
- 144 règles de pipeline, 88 définitions d'événements, 13 streams actifs (dont
  ESET, BunkerWeb, FortiGate).

### Sources & enrichissements ajoutés (suite de journée)
- **Vaultwarden** (BX-VAULTWARDEN, Docker → Filebeat) : stream + pipeline dédiés
  (`55-vaultwarden.sh`), **index set dédié `omni-vaultwarden`** (90 j) — évite
  l'éviction des events internes du SIEM. Kit client `/kit/vw-filebeat.sh`
  (anti-rejeu : `ignore_older 72h` + registry persistant). Détections coffre :
  `vault_auth_fail` (brute-force avec src_ip/compte), MITRE T1555.
- **Attribution DHCP FortiGate** (`56-fortidhcp.sh`) : collecteur API REST
  (token lecture seule) → lookup `omni-dhcp-attribution` (ip→hostname/MAC), timer
  15 min. Le pipeline FortiGate pose `src_hostname`/`dest_hostname` sur les IP
  internes (règles `omni-forti-06-dhcp-src/dest`) → « qui est derrière 10.33.x.x ».
- **Identité unifiée** (`58-identity-correlation.sh`) : champs `identity`
  (compte canonique : sans domaine/upn, minuscules) + `identity_human` (regroupe
  `adm-X`/`svc-X` sous la personne) sur winsec/sysmon/winother/M365/FortiGate/vSphere.
  Page dashboard **« Identité »** (pivot 1 personne, toutes sources). Corrèle déjà
  jmorin/adm-jmorin sur FortiGate+AD+Sysmon.
- **M365 / Entra ID Protection** : ingestion des `riskDetections` (permission
  `IdentityRiskEvent.Read.All`) → `m365_type:risk`, tag `m365_risque` (atRisk),
  alerte mail. A révélé le compte **jaubert** flaggé atRisk (attaque cloud étrangère).
  Détection `m365_brute_externe` (échecs M365 hors-FR, T1110).

### Détection — couverture MITRE & nouvelles règles
- **Carte de couverture MITRE ATT&CK** (`57-mitre-coverage.sh`) : calque
  `docs/mitre-navigator-layer.json` (à charger dans ATT&CK Navigator) + bilan.
  **58 détections / 44 techniques / 12-14 tactiques** (cf. COUVERTURE-MITRE-ATTACK.md).
- **Privilege Escalation comblée** (`47-detections-extra.sh`) : `uac_bypass`
  (T1548.002), `scheduled_task` (T1053.005), `service_install` (T1543.003). +
  `remote_discovery` (T1018), `service_stop_securite` (T1489).
- **Audit fichiers sensibles** (`59-file-audit.sh`) : parse 4663/5145, tags
  `file_sensitive_access` (T1039) / `file_delete_sensible` (T1485), alertes accès/
  suppression de masse (exfil/ransomware). *Armé* — nécessite les SACL côté serveurs.

### Intégrité & chiffrement (piliers ISO)
- **Intégrité des logs** (`60-integrity.sh`, A.8.15) : registre quotidien
  **haché-en-chaîne + signé HMAC** de l'état du corpus, copie hors-SIEM (SMB),
  `omni-integrity --verify` (hebdo + alerte mail si chaîne rompue — testé : une
  falsification est détectée). **Rôle Graylog « OMNI - Analyste (lecture seule) »**
  (moindre privilège, A.8.2).
- **Chiffrement au repos** `/data` (A.8.24/A.5.33) **réalisé le 2026-06-14** :
  **LUKS2 (header inline, aes-xts 512 bits) + déverrouillage TPM2/PCR7**. Reformatage
  chiffré à neuf (config hors `/data` préservée, logs repeuplés). Voir PROCEDURE-CHIFFREMENT-REPOS.md.
- **SOAR avancé** : cadrage des playbooks (isoler hôte / désactiver compte /
  ticket) en attente de l'API NinjaOne. Voir SOAR-PLAYBOOKS.md.

### Audit multi-agent & corrections (cohérence)
- **Halt-traps de pipeline corrigés** (un stage « match either » sans règle
  satisfaite stoppe le pipeline) : Exposition réseau (privflags + 4ᵉ direction
  `transit`), Sources externes (règle pass-through), Identité (pass-through/stage).
- **Veeam** : `veeam_job_echec` = échec **final** du job (eid 190) seulement ;
  les retries transitoires (eid 450, « restore point locked ») → `veeam_job_warn`
  (visu, pas d'alerte). Fini les faux « backup échoué ».
- **SOAR rebranché et rendu permanent** (le sync de 13 le préservait désormais),
  **champs ESET** corrigés (`eset_action`), **boucle Vaultwarden** droppée
  (~9k/j de bruit), **`vw_level`** unifié, **faux « robot en panne »**
  (omni-self-health : calcul d'âge robuste) supprimés. Nouveaux robots supervisés.
- **Mail anti-spam** : 26 alertes critiques en mail (tier « réveille-moi »),
  tout le reste en Teams (firehose). Ajout « Sabotage de l'audit » au mail.

### Hygiène données
- **Purge du rejeu Vaultwarden** : Filebeat avait rejoué tout l'historique
  conteneur (2023→2026). ~23 M docs antidatés purgés de l'index Default `graylog_*`
  **et** ~23 M de l'index Windows `omni-winother_*` (double routage corrigé). Les
  événements internes/Windows réels sont préservés.

## 2026-06-12 (après-midi — corrections, audit & optimisations)

### Bugs corrigés (audit de cohérence)
- **vSphere ne parsait rien** : le stage 0 du pipeline ne contenait que la
  règle « drop bruit » en *match either* — tout message non-bruit était bloqué
  avant la normalisation (0 host/event_action sur 44k logs/15 min). Corrigé.
- **Collecteur M365 Activité planté** (datetime naive vs aware) : crashait à
  chaque exécution après la première → page M365 Activité vide. Corrigé +
  reset des curseurs → 53 000+ events M365 (Exchange/SharePoint/OneDrive/Teams).
- Correctif appliqué au binaire **et** au script source (anti-régression).

### Optimisations
- **vSphere −87 %** : filtrage du bruit stockage ESXi (traces vSAN, osfsd,
  envoy-access, vmkwarning ; application_name vide côté ESXi → filtrage sur le
  contenu). 26k → 3,4k logs/5 min, événements de sécurité conservés.
- **SOAR whitelist** renseignée (IP VPN France légitimes + IP site Ivry),
  testée. À compléter par les IP publiques des sites Bordeaux/PACA.

### Vérifications
- Audit complet : 56 règles pipeline (0 erreur), 0 échec d'indexation, tous
  services/timers OK, 43 définitions, throughput nominal.
- Veeam confirmé fonctionnel (canal « Veeam Backup » + alerte d'échec active).
- Purge des logs (base saine) : collecte temps réel vérifiée sur tous les flux.

## 2026-06-12 (consolidation)

### Sécurité / détection
- **SOAR-light** : blocage automatique d'IP attaquantes (alertes VPN/spraying)
  via threat feed lu par le FortiGate. Sécurités : jamais d'IP interne/whitelist,
  seuil, plafond, expiration 24 h, traçabilité.
- **Compte canari AD** : détection d'intrusion interne (lookup + règle + alerte
  + script de création `New-OmniCanary.ps1` avec SPN piège à Kerberoasting).
- Durcissement VPN FortiGate (géo-restriction FR) — campagne de spraying stoppée.
- UTM FortiGate complet activé sur les 3 clusters (AV/IPS/web/DNS/app-control).

### Résilience / conformité
- Sauvegarde de configuration quotidienne chiffrée (AES-256) externalisée SMB,
  rétention 14 j, auto-surveillée + **PRA** (plan de reconstruction) + RESTORE.md.
- Rétentions alignées ISO (365 j identité/cloud, 180 j réseau/endpoint) + garde-fou
  disque (alerte 80 %, purge d'urgence 88 %).
- **Rapport hebdomadaire automatique** (lundi 08:00) — preuve de revue.
- **Dossier documentaire ISO 27001** : politique, standard, procédure, dossier
  d'architecture, registre de conformité, PRA, LDAPS, synthèse exécutive.
- Authentification console par **LDAPS** restreinte aux Admins du domaine.

### Exploitation
- Intégration **Veeam** (canal Windows) — a révélé un job critique en échec.
- Script d'enrôlement Windows unique `Install-OmniSiem-NinjaOne.ps1`.
- Correctif tempête d'alertes (grâces/clés, détection des comptes de service).
- **Purge des logs** (base saine) après la phase de build/tests.

## 2026-06-13 (UEBA/NDR, MITRE ATT&CK & corrélation d'incidents)

### Détection avancée (au-delà de Graylog)
- **Couche UEBA / NDR** (`40-ueba-ndr.sh`) : collecteurs `omni-ueba-volume`
  (anomalie de volume par source, z-score même-heure-du-jour), score, géo, et
  nouveau pays — robots autonomes alimentant le stream interne SIEM.
- **NDR réseau** : détection de scan interne (`48-ndr-scan.sh`, T1046),
  exfiltration/tunneling DNS (`43-ndr-dns.sh`, T1071.004), beaconing, mouvement
  latéral et exfiltration.
- **Reconnaissance LDAP / annuaire** (`49-ldap-recon.sh`) : détection
  BloodHound / SharpHound via le collecteur `omni-ldap-recon`.
- **Corrélation attack-chain → incidents** (`44-incidents.sh`) : le corrélateur
  `omni-incident-correlate` agrège les détections d'une même entité en incidents
  notés (`incident_score`), routés vers « OMNI - Interne SIEM ».
- **Détections complémentaires** (`47-detections-extra.sh`) : 5 règles issues de
  la revue multi-agent, dans un pipeline dédié.

### Cartographie & MITRE
- **Mapping MITRE ATT&CK + score de risque** (`37-mitre-attack.sh`) :
  `alert_tag` → technique (Txxxx) / tactique / sévérité / score, via lookup CSV.
- **Carte cyber temps réel** (`42-carte-cyber.sh`) : arcs de flux animés générés
  hors Graylog (`omni-geo-flux` → `flux.json`).
- **Exposition Internet & classe de port à risque** (`49-expo-port-class.sh`) :
  enrichissement des flux FortiGate.

### Exploitation & supervision
- **Auto-supervision des robots** (`46-self-health.sh`) : `omni-self-health`
  route `event_source=siem_health` → INT, timer 30 min (alerte « Robot d'analyse
  en panne »).
- **Rapport exécutif mensuel** (`45-monthly-report.sh`) : HTML + PDF (weasyprint),
  envoi le 1er du mois à 06:00, archivé sous `/var/www/siem-kit/rapports/`.
- **Ventilation des échecs M365 par code Azure AD** (`48-m365-fail-codes.sh`).

## 2026-06-11 (mise en production initiale)
- Build du SIEM : modèle (index/streams/inputs), 55 règles pipeline,
  détections, dashboard 24 pages, TLS bout-en-bout, collecte M365, FortiAnalyzer,
  vSphere, déploiement des agents Windows (NinjaOne + GPO).

---
*Tenir à jour à chaque évolution. Référence technique détaillée : `CONTEXT.md`
(racine du dépôt). Voir aussi `INTEGRATION-SOURCES.md`, `INVENTAIRE-SOURCES.md`,
`POLITIQUE-RETENTION.md` et `REPONSE-AUTOMATISEE.md` dans `docs/`.*


<a id="doc-25"></a>

---

<!-- ============================== AUDIT-DASHBOARD-2026-06-14.md ============================== -->

# Audit dashboards SIEM — feuille de route (senior SoC)

> **Audit multi-agent du 2026-06-14** (24 agents, validé contre la donnée live).
> Plan d'amélioration des 24 pages du dashboard OMNI - SOC. Implémenté **par lots**.
> Suivi d'avancement en bas de fichier.

All 24 pages confirmed, widget counts match the audits. The DHCP lookup responds without error (single_value null for that test IP, but `has_error:false` — the table is wired correctly). I have everything verified. The audits are accurate and reliable. Now I'll synthesize the complete improvement plan.

A note on the DHCP lookup: `has_error:false` but `single_value:null` for `10.33.60.15` — consistent with the audit's observation that some internal IPs (fixed-IP infra) don't resolve. This is worth flagging in the transverse recommendations.

I have all I need. Producing the plan.

---

# PLAN D'AMÉLIORATION — Dashboard « OMNI - SOC » (24 pages, view `6a2e3d1bb61861c0c217afed`)

> Vérifié live (OpenSearch + API Graylog) : `vault_admin` = **9,54 M docs** (95 % du SIEM, source Vaultwarden = HTTP 404 `/admin/users`, `risk_score=6`) écrase la quasi-totalité des agrégats non filtrés. Les tags `threat_intel / eset_detection / m365_etranger / waf_block / vsphere_shell_ssh / vsphere_vm_destroy / powershell_suspect / winsec_critique / admin_share` = **0 doc** (câblage mort, pas post-purge). Les champs fantômes `dark_host / hours_silent / priv_group_label / cert_subject_disp / waf_ua_outil / service_logon_fail / fwd_target` = **0**. À l'inverse `risk_score / mitre_technique / src_ip_country_code / crscore / vuln_ransomware(381 oui) / ueba_score` sont peuplés, et le lookup **`omni-dhcp-attribution`** existe et répond (`has_error:false`).

## 1) Vue d'ensemble — état des pages

| Statut | Pages | Verdict |
|---|---|---|
| **Fortes (garder, ajustements mineurs)** | **Vulnérabilités**, **UEBA/NDR**, **Santé collecte** | Réellement peuplées, bien câblées, vraie question SOC. Manque surtout enrichissement/corrélation. |
| **À retravailler en priorité (P1 structurel)** | **Direction**, **Alertes**, **ATT&CK** | Intoxiquées par `vault_admin` : KPI/heatmap/pie/score faussés. 1 filtre global = 80 % du gain. |
| **Cassées au câblage (widgets morts à recâbler)** | **vSphere**, **VPN & Exposition**, **Sources externes**, **Comptes & conformité**, **Comptes à privilèges**, **M365 Activité**, **WAF BunkerWeb**, **Endpoint**, **Cartographie**, **Sauvegardes** | Pivots/queries sur tags/champs/actions inexistants alors que la donnée équivalente existe. Pas du post-purge. |
| **Correctes mais diluées (redondance + manques)** | **Incidents**, **Identité AD**, **M365**, **Réseau**, **Hunting**, **Certificats**, **Investigation** | Bonne question, trop de KPI mono-valeur, viz inadaptées, corrélations absentes. |
| **Faibles (refonte de fond)** | **vSphere**, **VPN & Exposition** | Ne répondent pas à leur question : scope absent / moitié des widgets morts. |

**Priorité de chantier** : (A) purge du bruit `vault_admin` sur Direction/Alertes/ATT&CK/Investigation → (B) recâblage des widgets morts (tags/actions inexistants) → (C) enrichissement DHCP + chaîne détection→hôte→compte→score → (D) déduplication KPI/viz.

---

## 2) Plan par page (actions retenues, requête/pivot/viz concrète)

> Convention : `RP`=row_pivot, `CP`=column_pivot, `S`=series, `TR`=timerange.

### Direction (P1 — intoxiquée)
- **CORRIGER** Détections 24h (`b2a8c5a8`) + Posture (`ab7a5dc3`) : query → `alert_tag:* AND NOT alert_tag:vault_admin`. Top réel : vuln_kev(1157), vsphere_auth_fail(798), vault_admin_abuse(808), exposition_internet(142). **[P1]**
- **CORRIGER** Menaces réseau (`ec6131db`) : `threat_intel`=0 → `alert_tag:fortigate_utm OR alert_tag:exposition_internet`. **[P1]**
- **AJOUTER** *Abus admin Vaultwarden* : KPI `count()` sur `alert_tag:vault_admin_abuse` (808) + mini-table `RP user, src_ip / S count()`. **[P1]**
- **MODIFIER** Exposition Internet pays (`f41b196d`) : `action:deny AND NOT srccountry:Reserved AND NOT srccountry:France` (Reserved=63379 = interne). Garder `card(src_ip)`. **[P2]**
- **AJOUTER** *KEV exploitables* : KPI `count()` `alert_tag:vuln_kev` + table `RP host / S count(), card(alert_tag)`. **[P2]**
- **FUSIONNER** 3 widgets volume (`4bee57de`+`e347ba67`+`46dd56c5`) → 1 KPI « Événements 24h » + timeline empilée par source ; déplacer « Hôtes actifs » vers Santé collecte. **[P2]**
- **MODIFIER** Top hôtes/comptes par score (`aeb9a091`/`80b33ec8`) : blinder `_exists_:risk_score AND NOT event_source:vaultwarden`, passer en barres horizontales triées `sum(risk_score)`, ajouter `card(alert_tag)`. **[P2]**
- **MODIFIER** UEBA ≥70 (`97655507`) : ajouter mini-table `RP ueba_entity / S max(ueba_score)` (24h). Incidents critiques (`d441b696`) : `incident_severity:(critique OR eleve)`, TR 24h. **[P3]**

### Alertes (P1 — file de triage à reconstruire)
- **MODIFIER (query globale page)** : `alert_tag:* AND risk_score:>=7` (élimine 43k de bruit ; garde vuln_kev/vault_admin_abuse/exposition_internet/beaconing/sysmon_injection/lsass_access). **[P1]**
- **AJOUTER** *File de triage par gravité* : table `RP alert_tag, host / S max(risk_score), count(), card(mitre_technique)` triée `max(risk_score) desc`. **[P1]**
- **AJOUTER** *Top ATT&CK des alertes* : bar `RP mitre_technique / S count()`, filtre `risk_score>=7`. **[P2]**
- **AJOUTER** *Alertes réseau enrichies* : table `RP src_ip, dest_ip / S count(), max(risk_score)`, query `alert_tag:(beaconing OR network_scan OR data_exfil) AND _exists_:src_ip`, **colonne hostname via `omni-dhcp-attribution` sur src_ip**. **[P2]**
- **CORRIGER** Détail (`c0aa0653`) : `fields=[timestamp, risk_score, alert_tag, mitre_technique, host, user, src_ip, dest_ip, event_source]` ; retirer `command_line`(0)/`process_name`(8) ; aligner TR sur 24h. **[P2]**
- **REVIZ** Heatmap (`12f2f641`) : appliquer `risk_score>=7` (sinon cellule vault_admin sature). **FUSIONNER** « Types distincts » (`28497eab`) dans le bar `Volume par type`, ou le muer en KPI « Alertes critiques (score≥8) ». **[P3]**

### ATT&CK (P1 — intoxiquée par T1078 vault_admin = 9,54 M)
- **MODIFIER** tous les agrégats : suffixer `AND NOT alert_tag:vault_admin`. Heatmap (`b6a994d5`), Score cumulé (`0848489a` → `count()` critique+moyen ou `max(risk_score)`), Pie sévérité (`a934638d` → bar), KPI couverture (`270cb1fa`/`765e614c`). **[P1]**
- **AJOUTER** *Techniques par HÔTE* : table `RP host, mitre_technique, mitre_technique_name / S count(), max(risk_score)`, tri score desc, `NOT vault_admin`. **[P1]**
- **AJOUTER** *Initial Access externe enrichi* : table `RP src_ip / S count(), card(host), card(user)`, query `mitre_tactic:"Initial Access" OR mitre_technique:(T1190 OR T1110)`, enrichir src_ip (DHCP interne / pivot TI externe). **[P2]**
- **FUSIONNER** Tactiques par score (`a72dbf6c`) + Couverture par tactique (`6c9c1303`) → garder la table, supprimer le bar count (ou le muer en `card(mitre_technique)` par tactique). **[P2]**
- **MODIFIER** Détail (`fdccdb79`) : `AND NOT alert_tag:vault_admin`, tri `risk_score desc`. **[P2/P3]**

### UEBA / NDR (FORTE — enrichir)
- **MODIFIER** Scan interne (`9d041578`) : **colonne hostname via `omni-dhcp-attribution(entity_host)`** + `risk_severity, mitre_technique, scan_deny`, tri `scan_dest_count desc`. **[P1]**
- **MODIFIER** Exfiltration (`32e0b717`) : enrichir `entity_host`→hostname, ajouter `dest_ip_country_code, risk_severity, mitre_technique(T1048), exfil_bytes_sent`, tri `exfil_gb desc`. **[P1]**
- **CORRIGER** Distribution scores (`6a51d984`) : sort `pivot ueba_score Ascending` (sort actuel sur champ absent) ; idéalement bucketiser 0-39/40-69/70-100. **[P2]**
- **MODIFIER** Beaconing (`1b958908`) : ajouter `dest_ip_country_code, risk_severity, mitre_technique`, enrichir src_ip, tri `beacon_hits desc`. **[P2]**
- **FUSIONNER** Anomalies volume KPI (`c6599dee`)+table (`3ec25c5c`) ; ajouter `risk_severity, anomaly_kind`. **AJOUTER** *Top entités NDR par tactique MITRE* (`RP mitre_tactic, entity_host / S count(), max(risk_score)`). **[P2]**
- **REVIZ** Pie facteur dominant (`4b27f8c3`) → barres. **AJOUTER** pont *UEBA≥70 → événements NDR de l'entité* (jointure `ueba_entity`). **[P3]**

### Santé collecte (FORTE — fiabiliser fenêtres + heartbeat 360)
- **CORRIGER** go-dark (`ccfdcbd5`/`b011288b`) : pivots `dark_host/hours_silent/host_volume_30d`=**0** (job d'émission cassé). Recâbler sur donnée réelle : `event_source:(windows OR sysmon OR windows_security) / RP host / S latest(timestamp)` tri asc, TR 7j fixe. **[P1]**
- **CORRIGER** « 24h » à `timerange=null` (`f7a031ef`, `491038eb`, `3a3d36ad`, `453be60b`, `3c590f25`, `48cd3130`, `b22ffb97`…) : fixer TR `relative 86400` (sinon le titre « 24h » ment). **[P1]**
- **CORRIGER** Canaux Windows (`0bda5c1f`) : retirer `OR event_source:sysmon` (sysmon n'a pas de `channel`). **[P2]**
- **AJOUTER** *Heartbeat global* : table query vide, `RP event_source(30) / S count(), max(timestamp)` tri `max(timestamp) asc` → repère LA source coupée. **[P2]**
- **MODIFIER** Dernière réception (`453be60b`) : inclure `vaultwarden, m365, vsphere, veeam` (+ NPS à terme). **FUSIONNER** go-dark détail avec « Dernière activité par hôte » (`cb882ac8`). **AJOUTER** KPI santé `forti_dhcp` (567 docs, pivot d'enrichissement). **RETIRER** « Comptes M365 vus » (`31c818a5`, relève des pages M365). **[P2/P3]**

### Identité AD (recâbler 2 widgets cassés + corrélations)
- **CORRIGER** Comptes de service en échec : `service_logon_fail`=0 → `event_id:4625 AND user:*$` / `RP user / S count(), card(host)`. **[P1]**
- **CORRIGER** RDP par hôte : `event_action:rdp_session_ouverte`=1 → `event_id:4624 AND logon_type_label:rdp_interactif_distant` (ou table `RP host / CP logon_type_label`). **[P1]**
- **AJOUTER** *Échecs AD par origine enrichie* : `event_id:4625 / RP src_ip, user / S count()` + **hostname via `omni-dhcp-attribution`** ; heatmap `src_ip x user`. **[P1]**
- **AJOUTER** *Kerberoasting* : `event_id:4769 AND winlogbeat_winlog_event_data_TicketEncryptionType:0x17 AND NOT *TargetUserName:*$` / `RP TargetUserName, ServiceName`. **[P2]**
- **MODIFIER** Raisons d'échec : exclure le bruit service `NOT user:ninjaone AND NOT user:*$`, pie→bar (restriction_compte=1465 vient quasi only de ninjaone). **FUSIONNER** échecs par compte ↔ heatmap compte×hôte ; bloc NTLM (4 widgets → 1 table `RP TargetUserName / CP LmPackageName` + 1 KPI 4776). **[P2]**
- **MODIFIER** admins off-hours : retirer `CP day_period` (1 seule valeur), ajouter `CP host`. **AJOUTER** *Spray* : `event_id:4625 AND NOT user:ninjaone / RP src_ip / S card(user)`. **[P3]**

### Comptes à privilèges (recâblage lourd)
- **CORRIGER** Modifs groupes priv (KPI+table) : `priv_group_label`=0 et 4728/4732/4756=0 → vérifier collecte 472x ; sinon pivoter `winlogbeat_winlog_event_data_TargetUserName`. **[P1]**
- **CORRIGER** Ajouts groupe sensible (détail) : query 472x=0, `MemberName`=0 → fallback MESSAGES `event_id:4670`(21k)/`4662`(224k) ciblé `adm-*`. **[P1]**
- **CORRIGER** Détections comptes sensibles : `dcsync/kerberoasting/m365_role`=0 → `alert_tag:(vault_admin_abuse OR explicit_cred_use OR lsass_access OR audit_config_change OR sysmon_injection OR persistence_autorun)`, colonne `risk_score`. **[P1]**
- **CORRIGER** 4672 : filtrer bruit `AND (account_class:admin OR user:adm\-*) AND NOT user:(*$ OR SYSTEM OR "Système" OR "Administrateur" OR ninjaone OR DWM-*)`. **[P2]**
- **AJOUTER** *Logon type admin* (`event_id:4624 AND user:adm\-* / RP user, LogonType`) ; *Top admins par risk_score* ; *Abus Vaultwarden* (`alert_tag:vault_admin_abuse`). **REVIZ** « D'où se connectent les admins » : enrichir src_ip→hostname. **FUSIONNER** les 3 tables d'activité admin en une seule (`RP user / S count(), card(host), card(src_ip), card(event_action), max(risk_score)`). **[P2/P3]**

### Comptes & conformité (recâblage actions/catégories)
- **CORRIGER** Services installés : `7045`=0 → `event_id:4697 OR event_action:service_installe` (14). **[P1]**
- **CORRIGER** Sabotage audit : `winsec_critique`=0 → `event_category:sabotage_audit OR event_id:4719(96) OR alert_tag:audit_config_change`. **[P1]**
- **CORRIGER** Partages admin : `admin_share`=0 → `event_id:5140`(1611) (+ filtre `C$/ADMIN$/IPC$`). **[P1]**
- **AJOUTER** *Abus admin Vaultwarden* (`alert_tag:vault_admin_abuse`, identifier le bon champ acteur — `vault_user` vide). **[P1]**
- **CORRIGER** Cycle de vie / Certificats / PKI : recâbler sur `event_id:(4720..4781)` (post-purge légitime) et `event_category:certificats`(52, `cert_subject/cert_expiry`) plutôt que actions inexistantes. **[P2]**
- **FUSIONNER** KPI 4720/4725/4726 + 2 tables cycle de vie → 1 table (`CP event_id / RP user`). **RETIRER** « Rôles M365 modifiés » (source non couverte). **REVIZ** pie cycle de vie → table. **[P2/P3]**

### M365
- **AJOUTER** *Échecs par pays/IP* : `m365_type:signin AND event_action:echec_connexion / RP src_country, src_ip / S count(), card(user)` (signal réel HK29/IL11/MA8 = spray). **[P1]**
- **FUSIONNER** 4 widgets échecs → garder table `RP user / CP m365_fail_label` (`a411115c`) + KPI trend. **CORRIGER** « Hors France/risque » (`cf99db0b`/`3f1ebb9c`) : `m365*` tags=0 → `m365_type:signin AND NOT src_country:FR`. **[P1]**
- **FUSIONNER** 3 widgets audit Entra → table `RP user, event_action, target`. **REVIZ** pie pays → bar + `card(user)`. **AJOUTER** *Connexions réussies pays inhabituel* (`connexion_reussie / RP user / CP src_country`). **REVIZ** legacy auth (`RP client_app, user`). **RETIRER** OS appareils (`9fa197da`). **[P2/P3]**

### M365 Activité (pilier exfil = câblage mort)
- **CORRIGER** 5 widgets (transferts/partages/délégations) : `m365_mail_forward/mailbox_deleg/partage_externe`=0 → détection native `event_action:(New-InboxRule OR Set-InboxRule OR Set-Mailbox OR Add-MailboxPermission OR Add-RecipientPermission)` ; sinon **retirer** les KPI à 0 trompeurs. **[P1]**
- **CORRIGER** détails : `fwd_target/share_target/share_file`=0 → champs réels `timestamp, user, upn, m365_workload, event_action, result, src_ip, src_ip_country_code`. **[P1]**
- **FUSIONNER** pie charge + timeline charge. **MODIFIER** Accès boîtes (`a9c3071c`) : ajouter `src_ip_country_code` / `NOT src_ip_country_code:FR`. **AJOUTER** *Mouvement données* (`Send`+`AttachmentAccess` par user). **RETIRER/muer** KPI count global. **[P2/P3]**

### Endpoint
- **CORRIGER** « Activité endpoint 24h » : **query vide → agrège tout le SIEM** → `event_source:(sysmon OR windows OR windows_security)`. **[P1]**
- **CORRIGER** 3 widgets détections : `powershell_suspect/defender`=0 → `alert_tag:(sysmon_injection OR lsass_access OR persistence_autorun OR explicit_cred_use OR beaconing OR data_exfil)`. **[P1]**
- **CORRIGER** Destinations réseau : pivot `dest_ip` casse (`array_index_out_of_bounds` = mapping ip/keyword) → réparer mapping + **enrichir dest_ip→hostname** + `CP dest_port`. **[P1]**
- **MODIFIER** Chaînes parent→enfant : normaliser granularité (basename des deux), exclure bruit (seal_ulscom/NinjaRMM). **AJOUTER** *Couverture 4688 vs Sysmon* (`RP host / CP event_source`), *détection→hôte→compte→score*, *Top menaces ESET* (pré-câblé, vide post-purge). **FUSIONNER** 4 KPI volume → barre « Posture endpoint ». **[P2/P3]**

### Hunting
- **CORRIGER** Persistance Run (`4c403775`/`655301a2`) : `*Run*`=7311 (99,97 % bruit W32Time) → `event_id:13 AND TargetObject:(*CurrentVersion\\Run* OR *RunOnce* OR *Winlogon\\Shell* OR *Userinit* OR *Image File Execution Options*)`. **[P1]**
- **CORRIGER** Pipes nommés (`b98108c6`) : Sysmon 17/18 non collectés (`PipeName` absent) → activer config Sysmon ou retirer le widget. **[P1]**
- **RETIRER** 4 KPI numériques doublons (LSASS/AppData/Office-shell/Run) — garder les tables. **[P1]**
- **MODIFIER** Connexions sortantes (`19ee9aee`) : `RP host, process_name, dest_ip, dest_port` + filtre non-RFC1918. AppData/LSASS : ajouter `command_line` / `GrantedAccess:(0x1010 OR 0x1410)`. **AJOUTER** enrichissement DHCP, LOLBins (certutil/regsvr32/mshta/rundll32). **REVIZ** baselining « 1re vue 30j ». **[P2/P3]**

### Réseau
- **CORRIGER** 2 widgets TI (`7aaacd07`/`29921e8d`) : `threat_intel`=0 → `alert_tag:(network_scan OR exposition_internet)`, pivot `src_ip` + `card(dest_port)`. **[P1]**
- **CORRIGER** Heatmap pays (`21e9e216`) : `srccountry`(19 %) → `src_country`(77 %). **[P1]**
- **AJOUTER** *Réputation FortiGate* : `RP src_ip / S max(crscore), count()`, filtre `crlevel:(high OR critical)` (crscore peuplé). **[P1]**
- **AJOUTER** *Enrichissement hostname* (`src_hostname/dest_hostname`=0) via `omni-dhcp-attribution` sur les tables internes. **MODIFIER** dest_country pie → bar + `NOT Reserved` ; top destinations `dest_ip_reserved_ip:false`. **FUSIONNER** 2 widgets UTM. **AJOUTER** *VPN par user/pays*. **REVIZ** « 24h » à TR null. **[P2/P3]**

### VPN & Exposition (FAIBLE — refonte)
- **CORRIGER** 5 widgets SSL (`ssl-login-fail`=0) → confirmer si portail SSL exposé ; sinon **retirer**, sinon remapper sur l'action réelle. **[P1]**
- **CORRIGER** spray (`user` vide sur SSL, `xauthuser`='N/A') : identifier le vrai champ user ou supprimer. **[P1]**
- **MODIFIER** Pairs IPsec par pays : ajouter `card(vpntunnel), card(remip)` + widget jumeau `NOT remip_country_code:FR` (= le widget Exposition manquant). **AJOUTER** *Volume session IPsec* (`tunnel-stats / sum(sentbyte/rcvdbyte)`), *map sur `remip_geolocation`* (tout le trafic, pas que SSL), *TI sur remip externes*. **FUSIONNER** KPI/table tunnels et 4740. **[P2/P3]**

### Sources externes (ESET câblage mort + NPS surdimensionné)
- **CORRIGER** 9 widgets ESET : `eset_detection`=0 + champs `eset_threat_name/action_taken/object_uri`=0 → faire produire le tag (`eset_event_type:Threat_Event`) ou basculer sur champs réels (`eset_action, eset_domain, eset_detail, eset_risk_score, eset_user`). **[P1]**
- **AJOUTER** *ESET ip→hostname* (`eset_ipv4` + `dhcp_hostname`), *ESET risque par hôte* (`max(eset_risk_score)`). **FUSIONNER** 3 widgets volume ESET. **RETIRER/regrouper** les 6 widgets NPS (en attente client) en 1 placeholder. **REVIZ** pies. **[P2/P3]**

### WAF BunkerWeb
- **CORRIGER** Outils offensifs (`b3352645`) : `waf_ua_outil:true`=0 → `http_user_agent:(*sqlmap* OR *nikto* OR *nmap* OR *nuclei* OR *Wget* OR *python-requests* OR *curl* OR *Scanner*)`, `RP src_ip, http_user_agent`. **[P1]**
- **CORRIGER** 5xx par site (`fa02eb2c`) : `waf_backend_down`=0 → `http_status:(500 502 503 504)`, `RP waf_vhost / CP http_status`. **[P1]**
- **CORRIGER** Blocages (`e55470c4`/`9341a715`) : `waf_block`=0 → `http_status:(403 OR 429)`. **[P1]**
- **CORRIGER** « Threat intel » (`013db8cd`) : `waf_src_externe:true` = juste IP publique → renommer OU `src_ip_threat_indicated:true`. **[P1]**
- **AJOUTER** *Top pays sources* (`src_ip_country_code`, AD=1273 anormal !), *Scan énumération 4xx par IP*, *Attaques chemins sensibles* (`http_url:(*.env* OR *wp-login* OR *.git* OR *admin*)`). **FUSIONNER** 5xx. **REVIZ** pie codes → area. **[P1/P2/P3]**

### Cartographie
- **CORRIGER** brute force VPN (`318efc77`) + KPI échecs (`67bbc6ff`) : `ssl-login-fail`=0 → `subtype:vpn AND status:failure`(8238). **[P1]**
- **CORRIGER** M365 hors France (`624a1753`) : `m365_etranger`=0 → `m365_type:signin AND NOT src_country:FR`. **[P1]**
- **AJOUTER** *M365 échecs par upn* (`_exists_:m365_fail_code / RP upn / CP src_country`). **MODIFIER** cartes : TR null → 7j fixe + overlay `status:failure`. **FUSIONNER** triplets carte+table+KPI (VPN et M365). **AJOUTER** enrichissement DHCP. **[P2/P3]**

### vSphere (FAIBLE — refonte)
- **CORRIGER** « Comptes vus » (`070aaf5a`) + « Actions » (`68a8f61f`) : **query vide → tout le SIEM** → `source:vcenter OR source:bx-esxi*` (et réparer extraction `user` polluée). **[P1]**
- **CORRIGER** SSH/Shell (`14d3302d`/`5eb869ac`) : `vsphere_shell_ssh`=0 mais 136 docs bruts → `(source:bx-esxi* OR source:vcenter) AND (message:"TSM-SSH" OR message:esxShell OR message:"ESXi Shell")` + réparer tag pipeline. **[P1]**
- **CORRIGER** VM supprimées (`0ffa862f`/`22fef4c1`) : `vsphere_vm_destroy`=0 mais 667 docs → `source:vcenter AND (message:VmRemoved OR message:VmDestroy OR message:"removed from inventory")` + extraire user/vm_name. **[P1]**
- **REVIZ** Sources échec auth (`d5e07e71`) : **enrichir src_ip→hostname** (10.33.80.23=150 échecs). **AJOUTER** *Échecs auth → src_ip×host (bruteforce)*, *Snapshots*. **MODIFIER** « Évènements 24h » (query vide+TR null), hôtes ESXi (scope). **RETIRER** dépendance `config_modifiee` (faux positif debug wcp + pollue `vsphere_auth_fail`). **[P1/P2/P3]**

### Sauvegardes
- **CORRIGER** 6 widgets supervision SIEM (`358f3c33`, `cefafff3`, `eec815e1`, `46b8a22b`, `27efcf09`) : `backup_config_ok/echec`, `disk_warn`, `disk_guard_prune`=0 → modèle réel `siem_health` (`health_type:summary/job_fail`, champs `health_ok/fail/total`) ; échec = `alert_tag:siem_job_fail`. **[P1]**
- **RETIRER** KPI « Évènements Veeam » (doublon). **FUSIONNER** 3 widgets `veeam_job_echec` (1 seul host). **AJOUTER** *Ratio succès/échec* (`CP winlogbeat_log_level`), *Échec sauvegarde joyaux* (`message:(*VAULT* OR *PKI* OR *DEV* OR *GIT*)` — échec live = BX-VAULTWARDEN, T1490), *Fraîcheur collecte Veeam* (`max(timestamp)`). **REVIZ** pie sévérité → bar. **[P1/P2/P3]**

### Certificats
- **CORRIGER** Détail PKI (`1bc0c149`) + Certs par demandeur (`b03a7b5c`) : `cert_subject_disp`=0 → `cert_request_id`/`cert_requester` (réels). **[P1]**
- **MODIFIER** KPI parc : `count()`(52 instances, doublons) → `card(cert_subject)` + `trend:false` (snapshot). **FUSIONNER** refus+revoc, détail SIEM ×2, demandeur ×2. **RETIRER** KPI `card(event_action)` (non-actionnable). **AJOUTER** *Refus AD CS par demandeur* (`event_id:4888`), *corrélation cert_requester → comptes priv/UEBA*, *répartition par tranche de jours*. **REVIZ** timeline → barres empilées. **[P1/P2/P3]**

### Vulnérabilités (FORTE — affiner priorisation)
- **MODIFIER** Exposition KEV par hôte (`f3563442`) : ajouter `max(vuln_cvss)` + colonne ransomware, tri `sum(vuln_cve_count) desc`. **[P1]**
- **AJOUTER** *Focus remédiation ransomware* : `vuln_ransomware:oui`(381) / `RP vuln_product / S count(), card(host), max(vuln_cvss)` → file de patch (Firefox 44, FortiClient 22, Silverlight 19…). **[P1]**
- **CORRIGER** Risque cumulé (`0ca40118`) : `risk_score` binaire (7/10) ≈ count → pondérer (`sum(vuln_cve_count)` ou criticité d'actif) + exposer `risk_severity`. **[P1]**
- **AJOUTER** *Hôtes KEV sans EDR* (croisement vuln↔ESET). **FUSIONNER** KPI « Hôtes exposés » dans la table. **MODIFIER** détails : tri `vuln_cvss desc` / `patch_age_days desc` (pas timestamp). **REVIZ** bloc patch_age (8 docs). **[P2/P3]**

### Investigation
- **CORRIGER** Connexions/DNS (`22dd4c08`) : EID22 a **0 `dest_ip`** → scinder en *DNS* (`event_source:sysmon AND event_id:22 / RP dns_query, host`) et *Connexions* (`event_id:3 / RP dest_ip, dest_port`), scoper `event_source:sysmon`. **[P1]**
- **AJOUTER** enrichissement DHCP sur « IP sources » (src_ip→hostname). **[P1]**
- **FUSIONNER** KPI Détections + table type/score. **MODIFIER** 3 KPI (host/user/events) en query vide → exclure vaultwarden ou retirer (95 % bruit). **CORRIGER** mapping `src_ip/dest_ip` keyword vs ip (graylog_13, vsphere). **AJOUTER** *Process tree EID1*, *Score UEBA par entité*. **REVIZ** timeline (line non empilée / `NOT vaultwarden`). **[P2/P3]**

### Incidents
- **MODIFIER** TR de tous les widgets : `1200s`(20 min) → `86400s` mini (incident réel s'étale sur 3,6 h). **[P1]**
- **FUSIONNER** 3 KPI `card(incident_entity)` + pie sévérité → 1 KPI + bar horizontal `RP incident_severity`. **[P1]**
- **AJOUTER** *Corrélation incident→UEBA* (`incident_entity`↔`ueba_entity`, `ueba_score`/`ueba_top_factor`), *Couverture MITRE* (`incident_tactic_list`, `incident_techniques`). **REVIZ** pie → bar. **CORRIGER** « chaîne la plus longue » (`trend:false`). **MODIFIER** détail : tri `incident_score desc`. **[P2/P3]**

---

## 3) Recommandations TRANSVERSES senior SoC

**a) Flux de triage inter-pages (parcours analyste/lead/direction)**
- **Direction** (posture, hors bruit) → **Alertes** (file `risk_score≥7`) → **Investigation** (coller IOC/host/user) → pages sources (Endpoint/Réseau/M365/vSphere) → **Incidents** (corrélé). Aujourd'hui ce flux est cassé par le bruit `vault_admin` en tête (Direction/Alertes/ATT&CK/Investigation). **Action n°1 = neutraliser ce bruit partout** (`AND NOT alert_tag:vault_admin` ou `risk_score>=7`), avec **une page « Vaultwarden » dédiée** pour `vault_admin` + `vault_admin_abuse` + `vault_auth_fail` (joyau coffre, 808 abus réels).

**b) Cohérence des visualisations**
- **Pies à bannir** sur échelles ordinales/déséquilibrées : sévérité, codes HTTP, facteur dominant, accordé/refusé → **barres horizontales triées**. Réserver le pie à ≤3 catégories équilibrées.
- **Timeranges** : interdire `timerange=null` quand le titre annonce une fenêtre (« 24h »). Beaucoup de widgets (Santé collecte, Réseau, Cartographie, vSphere) héritent du sélecteur global → titre mensonger. **Fixer un TR explicite** ou retirer la mention.
- **Tables** : trier par la **métrique d'action** (risk_score / cvss / patch_age / latest(timestamp)), jamais par `timestamp desc` quand ce n'est pas un flux d'événements (Vulnérabilités, Certificats, Incidents).
- **KPI mono-valeur** : supprimer ceux qui dupliquent une table voisine (Hunting ×4, Sauvegardes ×3, M365 ×4, VPN, Incidents ×3, Investigation ×3) → barres de KPI compactes et actionnables (avec seuil couleur <100 %, >seuil).

**c) Enrichissements de corrélation (le plus gros gain qualitatif)**
- **Attribution DHCP `omni-dhcp-attribution` (ip→hostname) PARTOUT** où un `src_ip/dest_ip` interne est pivoté : Alertes, Identité AD, Comptes à privilèges, Endpoint, Réseau, vSphere, Investigation, Cartographie, ESET. *(Caveat vérifié : le lookup répond `has_error:false` mais ne résout pas les IP fixes d'infra type 10.33.80.23 — documenter ces IP statiques ; surveiller la santé de `forti_dhcp` (567 docs, faible) car sa coupure casse silencieusement l'enrichissement — cf. piège `ensure_lookup`.)*
- **Chaîne détection→hôte→compte→score** : généraliser une table type `RP host, user / S count(detections), max(risk_score), card(alert_tag), card(mitre_technique)` + jointure `ueba_score` (356 docs). À poser au minimum sur Endpoint, Alertes, ATT&CK, Investigation, Incidents.
- **Geo / threat-intel sur src externes** : `src_ip_country_code`/`src_ip_threat_indicated`/`crscore` sont peuplés et **sous-exploités** (Réseau, WAF, VPN, M365). Brancher un vrai feed TI ou, à défaut, recouper WAF `src_ip` ↔ FortiGate `crlevel`.

**d) Widgets clés manquants (vu les sources disponibles)**
- **Vaultwarden `vault_admin_abuse`** (808) absent de Direction, Comptes à privilèges, Conformité — joyau coffre.
- **Heartbeat 360 toutes sources** (Santé collecte) : `RP event_source / S max(timestamp)` tri asc.
- **Focus ransomware** (Vulnérabilités) : `vuln_ransomware:oui`(381) → file de patch.
- **Échec backup des joyaux** (Sauvegardes) : Vaultwarden/PKI/DEV/GIT (T1490 déjà observé).
- **Auto-supervision SIEM réelle** (`siem_health`) : remplacer les 6 widgets morts par le vrai modèle (sinon faux « tout va bien »).

**e) Dette de pipeline à signaler à l'équipe ingest** (hors dashboard, mais bloque l'actionnabilité)
- Tags jamais posés : `threat_intel, eset_detection, m365_etranger/m365_risque, waf_block, vsphere_shell_ssh, vsphere_vm_destroy, m365_mail_forward/mailbox_deleg/partage_externe, powershell_suspect, defender, winsec_critique, admin_share, dcsync/kerberoasting/m365_role`.
- Émission cassée/absente : doc `go_dark` détaillée (`dark_host/...`), garde-fou disque (`disk_warn/disk_guard_prune`), `service_logon_fail`, champs M365 exfil (`fwd_target/...`), `cert_subject_disp`.
- Mappings à réparer : `src_ip`/`dest_ip` en conflit **keyword vs ip** (graylog_13, omni-vsphere_3) → casse pivots et requêtes CIDR.
- Extractions à corriger : `user` vSphere pollué (`0.01, is, data`), `config_modifiee` = bruit debug wcp mal taggé `vsphere_auth_fail`.

---

## 4) TOP 10 à appliquer EN PREMIER (fort impact, faible risque)

> Toutes sont des **changements de query/pivot/viz côté dashboard** (READ-ONLY sur la donnée, réversibles, sans dépendance pipeline).

| # | Page | Action | Changement concret | Impact |
|---|---|---|---|---|
| **1** | Direction, Alertes, ATT&CK, Investigation | **Neutraliser le bruit `vault_admin`** | Suffixer `AND NOT alert_tag:vault_admin` (ou query page `risk_score:>=7`) sur tous les widgets `alert_tag:*` / `mitre_technique:*` | Rend 4 pages lisibles : signal passe de ~44k « détections » à ~900 réelles |
| **2** | Alertes | **File de triage par gravité** | Nouvelle table `RP alert_tag, host / S max(risk_score), count(), card(mitre_technique)` tri `max(risk_score) desc` | Transforme une liste plate en vraie file SOC |
| **3** | Cartographie + VPN | **Brute-force VPN réel** | `action:ssl-login-fail`(0) → `subtype:vpn AND status:failure`(8238) sur `318efc77`/`67bbc6ff` | Supprime un faux « 0 échec » dangereux |
| **4** | Santé collecte | **Fixer les TR « 24h » = null** | TR `relative 86400` sur ~10 widgets dont le titre dit 24h | Chiffres parc-vs-actif redeviennent comparables |
| **5** | Vulnérabilités | **Focus remédiation ransomware** | Table `vuln_ransomware:oui / RP vuln_product / S count(), card(host), max(vuln_cvss)` | File de patch directement actionnable (page déjà forte) |
| **6** | WAF | **Outils offensifs + pays sources** | `waf_ua_outil:true`(0) → regex `http_user_agent`; nouveau widget `src_ip_country_code` (AD=1273 anormal) | Détection scan/exploit immédiate |
| **7** | M365 + Cartographie | **Hors-France réel** | `alert_tag:m365_etranger`(0) → `m365_type:signin AND NOT src_country:FR` | KPI passe de 0 à 56 connexions étrangères |
| **8** | Réseau | **Heatmap pays + réputation FortiGate** | `srccountry`(19 %)→`src_country`(77 %); nouveau `max(crscore)` filtré `crlevel:(high OR critical)` | 80 % du trafic refusé enfin visible + priorisation native |
| **9** | Hunting | **Persistance Run dé-bruitée + retrait 4 KPI doublons** | `*Run*`(7311 bruit)→`TargetObject:(*CurrentVersion\\Run* OR *RunOnce* OR *Winlogon\\Shell*)`; supprimer LSASS/AppData/Office/Run KPI | Élimine 99,97 % de faux positifs, dégonfle la page |
| **10** | Direction + Comptes à privilèges | **Widget Abus admin Vaultwarden** | KPI + table `alert_tag:vault_admin_abuse`(808) | Remonte un risque joyau aujourd'hui invisible |

**Note d'implémentation** : les actions #1–#10 modifient uniquement `query`/`row_pivot`/`series`/`visualization`/`timerange` dans le JSON de la vue — aucune ne touche la donnée ni le pipeline. Les corrections de **mapping IP** (Endpoint/Investigation) et l'**émission des tags manquants** (vSphere, ESET, M365 exfil, siem_health) sont à traiter dans un second temps avec l'équipe ingest (impact plus élevé, hors périmètre READ-ONLY).

Fichiers de référence : générateur dashboard `/root/omnitech-siem-setup/14-graylog-dashboards.sh` ; lookup DHCP `omni-dhcp-attribution` (créé via scripts `49-enrich-*` — vérifier qu'`ensure_lookup` y est bien défini, cf. piège mémoire).

---

## Suivi d'implémentation
- [x] Cause racine vault_admin (9,54M) corrigée (drop boucle + exclusion winother) + suppression des résidus.
- [x] VPN brute-force : ssl-login-fail(0) -> status:failure (8562 révélés).
- [x] M365 hors-France : m365_etranger(0) -> signin AND NOT src_country:FR.
- [x] Réseau/Carto heatmap : srccountry -> src_country.
- [x] Page WAF (waf_block->403/429, 5xx=1695, outils offensifs UA, pays sources AD=1274).
- [x] LOT 2 : Direction (recâble menaces + KPI coffre/KEV) + Alertes (file triage risk_score>=7) + ATT&CK (techniques/hote).
- [x] LOT 3 : Endpoint (scope+detections) + Hunting (Run de-bruite) + Vulns (focus ransomware) + Incidents (TR 24h).
- [x] LOT 4 : Identite AD (RDP par hote 4624+logon_type, raisons echecs hors comptes service) + Comptes priv (4672 -> account_class:admin/adm-* : 6110->486) + Comptes & conformite (4697/service_installe, 5140 partages admin, sabotage 4719/audit_config_change, abus coffre).
- [x] LOT 5 : M365 (echecs par PAYS/IP source 24h) + Cartographie (m365/VPN deja corrige). ESET source-limited (4 evts audit, cable correct, en attente de volume) ; M365 Activite/exfil idem (faible volume post-purge).
- [x] CAPSTONE : enrichissement DHCP src_ip/dest_ip interne -> hostname dans le pipeline FortiGate (regles omni-forti-06-dhcp-src/dest, stage 6 pour ne pas stopper le pipeline). Verifie live : 189 docs/2min enrichis (BX-INFO-JMO-LT, GL-S200...). Integration rendue **reproductible** : nouveau script `56-fortidhcp.sh` (collecteur + timer 15min + lookup) — avant, lookup/fetcher/timer n'existaient qu'en live.
- [x] LOT 6 :
  - **Certificats** : `cert_subject_disp` (0 doc, jamais pose par le pipeline) remplace par `cert_request_id` dans la table « emis par demandeur » et le detail PKI. (Certs emis 4887=0 post-purge = source-limited, cablage correct.)
  - **vSphere** : tags `vsphere_shell_ssh`/`vsphere_vm_destroy` = 0 (jamais matches) ; `config_modifiee` (807) s'est avere etre du **bruit debug `wcp`** (authz vCenter), pas du vrai changement de config. Widgets SSH/Shell + VM-destroy recables sur les seuls signaux FIABLES du flux : `vsphere_auth_fail` (976) et `snapshot_sauvegarde` (98). **Action source-side documentee** : la detection reelle de l'activation SSH/Shell ESXi et des suppressions de VM exige un transfert d'**evenements vCenter structures** (vpxd events / vobd ESXi) au lieu du firehose syslog brut noye dans le debug/perf — a faire cote vCenter, hors portee dashboard.
  - **Sauvegardes** : bloc auto-supervision (`backup_config_ok`/`disk_warn`/... = 0, event_actions inexistantes) recable sur le vrai schema `event_source:siem_health` (`health_type` summary/job_fail, `health_ok`/`health_fail`/`health_total`) + KPI Veeam erreurs (`winlogbeat_log_level:erreur`, 3 echecs reels sur BX-VAULTWARDEN).
  - **Investigation** : widget « Connexions / DNS » (pivot dest_ip alors que Sysmon EID22 n'a PAS de dest_ip) scinde en « Connexions reseau (Sysmon 3 -> dest_ip) » + « Requetes DNS (Sysmon 22 -> dns_query, 146k docs) ».
- **CAPSTONE** (rappel) : enrichissement DHCP src/dest_hostname dans le pipeline FortiGate + script reproductible `56-fortidhcp.sh`.

### Reste cote source (hors dashboard, pour le client)
- vCenter : configurer le transfert d'evenements structures (vpxd/vobd) pour rendre fiable la detection SSH-enable / VM-destroy / lockdown sur l'hyperviseur.
- NinjaOne : autorisations API via le compte Owner du tenant (PREREQUIS du chantier SOAR avance, cf. SOAR-PLAYBOOKS.md), puis collecteur `omni-ninjaone-fetch`.
- Vaultwarden : stopper le conteneur en boucle `ab9e3bdd` + restreindre l'acces `/admin` ; **persister le registry Filebeat / `ignore_older` (fait cote kit) pour stopper le rejeu d'historique**.
- ESET : forwarder syslog vers le SIEM (TCP 1515) ne remonte que ~4 events -> verifier l'export cote console ESET PROTECT (cf. INTEGRATION-SOURCES.md).
- **TODO client : installer l'antivirus ESET SUR le SIEM lui-meme (VM Debian bx-it-graylog-vm)** pour la protection endpoint du collecteur (durcissement A.8.7 antimalware).
- Veeam : decaler le job Backup Copy (cause du verrou de point de restauration, cf. detections veeam_job_echec/warn).
