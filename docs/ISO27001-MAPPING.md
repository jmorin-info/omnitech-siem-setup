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
