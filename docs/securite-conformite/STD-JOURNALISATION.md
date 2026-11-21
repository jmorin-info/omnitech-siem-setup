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
