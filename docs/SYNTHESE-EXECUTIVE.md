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
