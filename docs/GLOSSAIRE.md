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
