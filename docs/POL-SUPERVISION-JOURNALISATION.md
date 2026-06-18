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
