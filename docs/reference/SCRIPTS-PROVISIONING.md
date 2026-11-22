# Scripts de provisioning numérotés : inventaire et statut

Ce document recense les 105 scripts `NN-*.sh` de la racine du dépôt. Ils ne
sont **ni renommés ni déplacés** : leurs noms sont cités par l'installateur
(`tools/install-platform.py`), par d'autres scripts, par la documentation et
par trois unités systemd de production (voir [Contraintes](#contraintes-pour-toute-renumérotation)).
Les scripts à usage unique non numérotés sont rangés dans
[`tools/ponctuel/`](../../tools/ponctuel/README.md).

**Ne jamais exécuter les scripts numérotés en boucle ou par un joker.**
Certains purgent des journaux, modifient des rétentions ou recréent des
entités. Seul le nom complet identifie une opération.

## Méthode et légende

Inventaire établi le 21/11/2026 à partir des en-têtes des scripts et d'un
contrôle **en lecture seule** de la production (`bx-it-graylog-vm`) : API
Graylog en GET (pipelines, streams, inputs, définitions d'événements, tableaux
de bord, tables de correspondance, jeux d'index, backend d'authentification),
présence des unités systemd et des exécutables sous `/usr/local/sbin`,
paquets installés.

| Colonne | Signification |
|---|---|
| Idempotent | « oui » : l'en-tête du script le déclare (non vérifié par réexécution) ; « non déclaré » : aucune mention ; « non » : script destructif |
| Dépendances | Prérequis déclarés dans l'en-tête. Sauf mention contraire, les scripts « API » lisent `00-vars.env`, chargent `lib-graylog.sh` et exigent l'API Graylog (script 04) |
| Trace en production | Artefact constaté en lecture seule. « n.v. » : non vérifiable sans écriture ou sans analyse fine (modification d'entités existantes, règles nftables) |
| Statut | **socle** : exécuté par l'installateur ; **optionnel** : extension activée selon le site ; **ponctuel** : opération unique ou manuelle ; **obsolète** : remplacé ou retiré ; **outil** : utilitaire à lancer sur décision |

## Inventaire

### 00 à 14 : socle de la plateforme

| N° | Script | Rôle | Idempotent | Dépendances | Trace en production | Statut |
|---|---|---|---|---|---|---|
| 00 | `00-preflight.sh` | Analyse de la machine avant installation (CPU/AVX, RAM, disques, réseau, DNS, ports) | sans objet (lecture seule) | `00-vars.env` | sans objet | socle |
| 01 | `01-base.sh` | Préparation système : nom d'hôte, NTP, sysctl, THP, fail2ban, mises à jour automatiques, disque de données | oui | `00-vars.env` | `/etc/sysctl.d/99-siem.conf` présent | socle |
| 02 | `02-mongodb.sh` | MongoDB 8.0, replica set mono-nœud `rs0`, authentification, écoute locale | non déclaré | 01 | `mongodb-org` 8.0.38 | socle |
| 03 | `03-opensearch.sh` | OpenSearch 2.19 mono-nœud, écoute locale, dépôt de snapshots | non déclaré | 01 | `opensearch` 2.19.7, surcharge systemd présente | socle |
| 04 | `04-graylog.sh` | Graylog 7.2 (dépôt officiel), API locale, journal disque, SMTP | non déclaré | 02, 03 | `graylog-server` 7.2.2 | socle |
| 05 | `05-nginx-tls.sh` | Nginx frontal TLS, clé et CSR pour la PKI interne, certificat temporaire | non déclaré | 04 | nginx actif | socle |
| 06 | `06-firewall.sh` | Table nftables dédiée, réseaux du site uniquement | non déclaré | `00-vars.env` | n.v. (lecture nftables exclue du chantier) | socle |
| 07 | `07-inputs.sh` | Inputs Graylog : Beats TLS 5044, Syslog 1514 (FortiAnalyzer) | oui | 04, 06 | inputs « Winlogbeat (Beats TLS 5044) » et « FortiAnalyzer » 1514 TCP/UDP | socle |
| 08 | `08-backup.sh` | Sauvegarde applicative quotidienne (`siem-backup`) : mongodump, snapshot complet, configurations | non déclaré | 02, 03, 04 | unité présente, minuterie **désactivée** (remplacée par `oms-snap-siem` et 30) | socle (installateur) ; remplacé en production |
| 09 | `09-snmpd.sh` | Agent SNMPv3 lecture seule pour Centreon | non déclaré | 06 (IP Centreon) | `snmpd` activé | optionnel |
| 10 | `10-graylog-model.sh` | Modèle de données : jeux d'index, profil de types de champs, streams | oui | 04, 07 | jeux d'index `omni-*` présents | socle |
| 11 | `11-graylog-enrichment.sh` | Tables de correspondance (événements Windows, codes d'échec, groupes privilégiés) | oui | 10 | 34 tables de correspondance | socle |
| 12 | `12-graylog-pipelines.sh` | Pipelines de normalisation et de détection, schéma de champs commun | oui | 10, 11 | pipelines « OMNI - Windows Security », « OMNI - FortiGate »... | socle |
| 13 | `13-graylog-alerts.sh` | SMTP, notifications et définitions d'événements de base | oui | 10, 11, 12 | définitions et notifications présentes | socle |
| 14 | `14-graylog-dashboards.sh` | Tableau de bord multi-pages « OMNI - SOC » | oui | 10, 12 (16 pour la page M365) | tableau de bord « OMNI - SOC » | socle |

### 15 à 37 : sources, alerting, résilience

| N° | Script | Rôle | Idempotent | Dépendances | Trace en production | Statut |
|---|---|---|---|---|---|---|
| 15 | `15-rapport-hebdo.sh` | Rapport hebdomadaire HTML par `cron.weekly` | non déclaré | `00-vars.env` | `/etc/cron.weekly/omni-siem-rapport` présent | optionnel (recouvre 34, à arbitrer) |
| 16 | `16-m365-input.sh` | Réception Microsoft 365 : input GELF HTTP 12201, jeu d'index, stream | oui | 10 à 13 | input « M365 (GELF HTTP 12201) » | optionnel |
| 17 | `17-m365-fetcher.sh` | Collecteur Microsoft Graph vers GELF (minuterie 5 min) | oui | 16, variables `M365_*` | `omni-m365-fetch.timer` | optionnel |
| 18 | `18-m365-activity.sh` | Audit Exchange, SharePoint, OneDrive (Management Activity API) | oui | 16 | `omni-m365-activity.timer`, pipeline « OMNI - M365 Activite » | optionnel |
| 19 | `19-vsphere.sh` | Collecte ESXi/vCenter : inputs 1516, jeu d'index, pipeline | oui | 06 | inputs « vSphere » 1516, pipeline « OMNI - vSphere » | optionnel |
| 21 | `21-alert-hygiene.sh` | Surcouche anti-tempête des définitions (délais de grâce, clés) | oui | 13 (à relancer après chaque 13) | n.v. | optionnel |
| 22 | `22-alert-routing.sh` | Ancien routage mail/Teams à deux niveaux | non déclaré | sans objet | sans objet | **obsolète** (remplacé par 38-alert-triage) |
| 27 | `27-harden-services.sh` | Durcissement systemd de masse des services `omni-*` et `oms-*` | oui | services installés | fichiers `hardening.conf` présents | optionnel |
| 28 | `28-vpn-remip-ti.sh` | Détection T1133 : connexion SSL-VPN depuis une IP malveillante | oui | 12 | définition « Login SSL-VPN depuis IP malveillante ou Tor (T1133) » | optionnel |
| 29 | `29-drift-check.sh` | Contrôle de dérive dépôt/production, minuterie et alerte | oui | 06, 21, 30 | `omni-drift-check.timer` | optionnel |
| 30 | `30-backup-config.sh` | Sauvegarde chiffrée de la configuration, export SMB, test de restaurabilité | non déclaré | `00-vars.env` (partage SMB) | `omni-backup-config.timer` (l'unité appelle le script de la copie `/root/omnitech-siem-setup`) | optionnel |
| 31 | `31-retention-iso.sh` | Rétentions des jeux d'index (version du 12/06/2026) | oui | 10 | sans objet | **obsolète** (remplacé par 83, lui-même partiellement annulé) |
| 32 | `32-disk-guard.sh` | Garde-fou du disque `/data` toutes les 6 h | non déclaré | 31 | `omni-disk-guard.timer` (appelle le script de la copie `/root`) | optionnel |
| 33 | `33-ldaps-auth.sh` | Authentification Active Directory (LDAPS) sur la console Graylog | oui | compte de liaison AD | backend « Active Directory OMNITECH » | optionnel |
| 34 | `34-weekly-report.sh` | Rapport hebdomadaire `omni-weekly-report` (lundi 08:00) | oui | `00-vars.env` | `omni-weekly-report.timer` | optionnel |
| 35 | `35-canary.sh` | Compte canari Active Directory et sa détection | oui | 12 | définition « COMPTE CANARI touché » | optionnel |
| 36 | `36-soar.sh` | SOAR léger : service de blocage, notification HTTP, expiration | oui | 12 | `omni-soar.service` actif | optionnel |
| 37 | `37-mitre-attack.sh` | Correspondance `alert_tag` vers MITRE ATT&CK et score de risque | oui | 11, 12 | pipeline « OMNI - Enrichissement ATT&CK » | optionnel |

### 38 à 60 : triage, analyses comportementales, détections

| N° | Script | Rôle | Idempotent | Dépendances | Trace en production | Statut |
|---|---|---|---|---|---|---|
| 38 | `38-alert-triage.sh` | Triage des alertes (règles déterministes et couche LLM sur la zone grise) | oui | 13, 36 | `omni-alert-triage.service` actif | optionnel (proposé par l'installateur) |
| 38 | `38-vuln-scan.sh` | Vulnérabilités : catalogue CISA KEV et ancienneté des correctifs | oui | 12, 21 | `omni-vuln-scan.timer` | optionnel |
| 39 | `39-alert-digest.sh` | Récapitulatif des alertes retenues (l'en-tête indique lundi et jeudi 08:00) | oui | 38-alert-triage | `omni-alert-digest.timer`, réglée en production du lundi au vendredi à 08:00 (écart avec le script) | optionnel |
| 39 | `39-collect-health.sh` | Supervision de la collecte (couverture, silence par hôte) | oui | 12, 21 | `omni-collect-health.timer` | optionnel |
| 40 | `40-purge-logs.sh` | Purge du contenu des index de journaux, configuration conservée | **non (destructif)** | 30 (sauvegarde préalable) | sans objet | ponctuel, manuel uniquement |
| 40 | `40-ueba-ndr.sh` | UEBA/NDR : volume, voyage impossible, beaconing, score d'entité | oui | 12, 21, 37 | minuteries `omni-ueba-*`, `omni-ndr-beacon` | optionnel |
| 41 | `41-retention-iso.sh` | Réduction de bruit (pipeline étape 30) et rétention différenciée | oui | 12 | pipeline « OMNI - Reduction volume (ISO) » ; volet rétention remplacé par 83 | optionnel (partiellement remplacé) |
| 42 | `42-carte-cyber.sh` | Carte des flux temps réel servie sous `/kit/` | oui | nginx, OpenSearch | `omni-geo-flux.timer` | optionnel |
| 43 | `43-ndr-dns.sh` | Détection d'exfiltration et de tunnel DNS | oui | 21, 37 | `omni-ndr-dns.timer` | optionnel |
| 44 | `44-incidents.sh` | Ancien moteur de corrélation `omni-incident-correlate` | oui | sans objet | unité présente, minuterie désactivée | **obsolète** (remplacé par `oms-xdr`) |
| 45 | `45-monthly-report.sh` | Rapport exécutif mensuel (HTML et PDF) | non déclaré | `00-vars.env` | `omni-monthly-report.timer` | optionnel |
| 46 | `46-self-health.sh` | Auto-supervision des robots d'analyse | non déclaré | 21 | `omni-self-health.timer` | optionnel |
| 47 | `47-detections-extra.sh` | Détections complémentaires (GPO, etc.) en pipeline dédié | oui | 12, 37 | pipeline « OMNI - Detections complementaires » | optionnel |
| 48 | `48-m365-fail-codes.sh` | Libellés des codes d'échec de connexion M365 | oui | 12 | pipeline « OMNI - Enrichissement M365 » | optionnel |
| 48 | `48-ndr-scan.sh` | Détection de balayage réseau interne | oui | 21, 37 | `omni-ndr-scan.timer` | optionnel |
| 49 | `49-enrich-lots.sh` | Enrichissements lots 1 et 2 (hors heures, classes de comptes) | oui | 12, 37 | pipelines « Enrichissement off-hours », « Enrichissement comptes » | optionnel |
| 49 | `49-expo-port-class.sh` | Exposition Internet et classe de port à risque (FortiGate) | oui | 12 | pipeline « OMNI - Exposition reseau » | optionnel |
| 49 | `49-ldap-recon.sh` | Détection de reconnaissance LDAP (BloodHound, SharpHound) | oui | collecteur `omni-ldap-recon` | `omni-ldap-recon.timer` | optionnel |
| 50 | `50-enrich-lot3.sh` | Lot 3 : GPP, Kerberos RC4, ajout administrateur local, collecteurs | oui | 12, 37 | pipeline « OMNI - Detections Lot3 » | optionnel |
| 51 | `51-enrich-lot4.sh` | Lot 4 : WMI latéral, shadow credentials, abus AD CS | oui | 12, 37 | pipeline « OMNI - Detections Lot4 » | optionnel |
| 52 | `52-new-sources.sh` | Sources ESET PROTECT, BunkerWeb, NPS | oui | 06, 07, 12 | input « ESET (Syslog TCP 1515) », pipeline « OMNI - Sources externes » | optionnel |
| 53 | `53-purge-clean.sh` | Purge des données et de l'historique d'alertes, configuration conservée | **non (destructif)** | sauvegarde préalable | sans objet | ponctuel, manuel uniquement |
| 54 | `54-post-purge-repopulate.sh` | Repopulation des tableaux de bord après une purge | oui | 53 | sans objet | ponctuel |
| 55 | `55-vaultwarden.sh` | Source Vaultwarden (Filebeat) : stream, pipeline, détections | oui | 12, input 5044 | stream et pipeline « OMNI - Vaultwarden » | optionnel |
| 56 | `56-fortidhcp.sh` | Correspondance IP, MAC et nom d'hôte depuis le DHCP FortiGate | oui | 12, jeton API lecture seule | `omni-fortidhcp-fetch.timer` | optionnel |
| 57 | `57-mitre-coverage.sh` | Génère le calque ATT&CK Navigator (`docs/detection/mitre-navigator-layer.json`) | oui | `lookups/mitre-attack.csv` | sans objet (artefact du dépôt) | outil |
| 58 | `58-identity-correlation.sh` | Champ canonique `identity` commun à toutes les sources | oui | 12, 49 | pipeline « OMNI - Identite unifiee » | optionnel |
| 59 | `59-file-audit.sh` | Audit d'accès aux fichiers sensibles (4663, 5145) | oui | SACL côté serveurs | pipeline « OMNI - Audit fichiers » | optionnel |
| 60 | `60-integrity.sh` | Registre d'intégrité quotidien chaîné (HMAC) des journaux | oui | clé HMAC | minuteries `omni-integrity` et `omni-integrity-verify` | optionnel |

### 61 à 99 : supervision, console, détections avancées, sources récentes

| N° | Script | Rôle | Idempotent | Dépendances | Trace en production | Statut |
|---|---|---|---|---|---|---|
| 61 | `61-supervision-robots.sh` | Versionne `omni-self-health` et `omni-collect-health` | oui | API | exécutables présents | optionnel |
| 62 | `62-auto-security-updates.sh` | Mises à jour de sécurité durcies ; `unattended-upgrades` ne redémarre jamais, le redémarrage automatique est porté par `oms-maj-siem` (dimanche 04:30, si `/var/run/reboot-required`) | oui | aucune | `/etc/apt/apt.conf.d/52omni-siem.conf` | optionnel |
| 63 | `63-fortimanager.sh` | Source FortiManager : inputs 1517, jeu d'index, pipeline | oui | 06, 07, 12, 37 | inputs « FortiManager (Syslog 1517) », pipeline | optionnel |
| 64 | `64-m365-fwd-audit.sh` | Audit des règles de transfert de messagerie existantes | oui | 16, 17 | `omni-m365-fwd-audit.timer` | optionnel |
| 65 | `65-mobile-pwa.sh` | Première version de la PWA mobile et de son backend | oui | 04, 05, 12, 13 | `omni-mobile-api.service` actif | optionnel (publication reprise par 71) |
| 66 | `66-threatintel.sh` | Flux IOC abuse.ch (Feodo, URLhaus) en tables de correspondance | oui | 11, 12, 37 | pipeline « OMNI - Threat Intel IOC », `omni-ti-feeds.timer` | optionnel |
| 67 | `67-detection-coverage.sh` | Détections ciblées sur les lacunes ATT&CK (inspirées Sigma) | oui | 12, 37 | pipeline « OMNI - Couverture ATT&CK etendue » | optionnel |
| 68 | `68-iso-evidence.sh` | Dossier de preuves ISO 27001 mensuel | oui | API, OpenSearch | `omni-iso-evidence.timer` (appelle le script de la copie `/root`) | optionnel |
| 69 | `69-ad-response.sh` | Actionneur de désactivation de compte AD (LDAPS, garde-fous) | oui | compte de service | `omni-ad-disable` présent | optionnel |
| 70 | `70-leak-github.sh` | Surveillance de fuites sur GitHub | oui | jeton GitHub | `omni-leak-github.timer` | optionnel |
| 71 | `71-soc-console.sh` | Console SOC complète, backend et routes nginx | non déclaré (préserve la configuration) | 05 | `/var/www/siem-soc` publié | socle |
| 72 | `72-leak-darkweb.sh` | Fuites et dark web (RansomLook, ransomware.live, HIBP, Dehashed) | oui | 70 | minuteries `omni-leak-*` | optionnel |
| 73 | `73-detection-ad.sh` | Détection AD : Kerberoasting (T1558.003) | oui | 37 | pipeline « OMNI - Detection AD » | optionnel |
| 74 | `74-source-watchdog.sh` | Détection de source silencieuse | oui | API | `omni-source-watchdog.timer` | optionnel |
| 75 | `75-console-hardening.sh` | En-têtes de sécurité de la console et de la PWA | oui | 05 | `/etc/nginx/snippets/omni-sec-headers.conf` | optionnel |
| 76 | `76-detection-cmdline.sh` | Vol des ruches SAM, effacement des journaux | oui | 12 | pipeline « OMNI - Detection cmdline » | optionnel |
| 77 | `77-ml-scoring.sh` | Couche ML `oms-ml` : anomalies et réduction de faux positifs | oui | OpenSearch, GELF 12201, 21 | minuteries `oms-ml-anomaly`, `oms-ml-fp` | optionnel |
| 78 | `78-detection-tuning.sh` | Câblage de l'alerte d'arrêt des services de sécurité | oui | 47, 13 | n.v. | optionnel |
| 79 | `79-interne-indexset.sh` | Jeu d'index dédié au stream « OMNI - Interne SIEM » | oui | 21 | jeu d'index `omni-interne` | ponctuel (correctif appliqué) |
| 80 | `80-detection-extra2.sh` | Détecteurs ATT&CK haute fidélité (Defender, etc.) | oui | 12, 37, 13 | pipeline « OMNI - Detections extra2 » | optionnel |
| 81 | `81-fp-allowlist.sh` | Liste d'autorisation des motifs bénins (étape 25) | oui | 12, 37 | pipeline « OMNI - Allowlist FP » | optionnel |
| 82 | `82-graylog-analytics-dashboard.sh` | Tableau de bord « OMNI - Analytics » | oui | 21 | tableau de bord « OMNI - Analytics » | optionnel |
| 83 | `83-retention-consolidee.sh` | Source unique des rétentions : réglages de rotation et de rétention des jeux d'index (index futurs) | oui (plan par défaut, `--apply` pour écrire) | 10, 52, 55, 63, 79 | jeux `omni-*` en rotation héritée (P1D ou P1M), sans hiérarchisation | actif (révisé le 22/11/2026, voir note) |
| 84 | `84-dashboards-triage-site.sh` | Tableau de bord « OMNI - Triage & Multi-site » | oui | 82, 97-multisite-soar | tableau de bord présent | optionnel |
| 84 | `84-kerberoast-dedup.sh` | Consolidation des alertes Kerberos (anti-doublon) | oui (simulation par défaut) | 13 | n.v. | ponctuel |
| 85 | `85-detection-extra3.sh` | Neuf détecteurs Sysmon haute fidélité | oui | 12, 37, 13 | pipeline « OMNI - Detections extra3 » | optionnel |
| 85 | `85-detections-backlog.sh` | Détections issues du backlog ATT&CK (T1219, T1572...) | oui | 13 | définition « Logiciel d'acces distant non autorise (RAT/RMM) - T1219 » | optionnel |
| 86 | `86-detections-backlog2.sh` | Second lot du backlog ATT&CK | oui | 12 | définitions présentes | optionnel |
| 86 | `86-services-versioning.sh` | Versionne `omni-cert-check`, `omni-cert-renew`, `omni-postboot-check` | oui | aucune | unités et exécutables présents | optionnel |
| 87 | `87-detection-extra4.sh` | Escalade de privilèges et mouvement latéral | oui | 12, 37, 13 | pipeline « OMNI - Detections extra4 » | optionnel |
| 88 | `88-deception-honeytokens.sh` | Couche de leurres (comptes, SPN, noms canaris) | oui (simulation par défaut) | 81 | pipeline « OMNI - Deception » | optionnel |
| 89 | `89-attack-graph.sh` | Graphe d'exposition `oms-graph` | oui | 21, 88 | minuteries `oms-graph`, `oms-graph-respond` | optionnel |
| 90 | `90-fortiems.sh` | Source FortiClient EMS (syslog TLS 1518) | oui | input EMS, 06 | input « FortiClient EMS (Syslog TLS 1518) », pipeline | optionnel |
| 91 | `91-dns.sh` | Détections DNS du contrôleur de domaine | oui | 12, 37 | pipeline « OMNI - DNS (DC) » | optionnel |
| 92 | `92-linux.sh` | Récepteur Linux (syslog 1519), parsing, détections | oui | 12, 06 | input « Linux (Syslog TCP 1519) », pipeline | optionnel |
| 93 | `93-aruba.sh` | Commutateurs Aruba (syslog 1520), parsing, inventaire | oui | 12, 13, 06 | inputs « Aruba » 1520, pipeline | optionnel |
| 94 | `94-entra.sh` | Détections Entra ID complémentaires | oui | 16, 17 | pipeline « OMNI - Entra (gaps) » | optionnel |
| 95 | `95-kit-deploy.sh` | Publication du kit d'enrôlement sous `/kit/` avec empreintes | oui | artefacts Windows | `/var/www/siem-kit/SHA256SUMS` | optionnel |
| 96 | `96-correlation.sh` | Corrélation multi-sources (segment réseau, utilisateur) | oui | 93, 13 | pipeline « OMNI - Enrichissement reseau » | optionnel |
| 97 | `97-enrich-alerts.sh` | Enrichit le contenu des alertes (regroupement, champs) | oui | API | n.v. | ponctuel |
| 97 | `97-multisite-soar.sh` | Dimension site FortiGate (BDX/IV/LC) et alimentation SOAR WAF | oui | 36, 12, 93 | table `omni-fortigate-site` | optionnel |
| 98 | `98-index-templates.sh` | Bridage du mapping des index à fort volume | oui | OpenSearch | gabarit non posé (préfixes vides par choix documenté) | outil (non appliqué) |
| 99 | `99-cert-orchestrator.sh` | Source Cert Orchestrator (GELF UDP 12201) | non déclaré | 06 | input absent, jeu d'index retiré | **obsolète** (serveur décommissionné) |

Les numéros 20 et 23 à 26 ne sont pas attribués.

### Note sur le script 83

Jusqu'au 21/11/2026, `83-retention-consolidee.sh` migrait les jeux d'index vers
la rotation `TimeBasedSizeOptimizing` avec hiérarchisation (`data_tiering`
`hot_only`). Sur la version de Graylog alors en service, cette migration a
supprimé des index à environ 30 jours au lieu de la rétention demandée
(incident de septembre 2026) ; le retour arrière
`tools/ponctuel/revert-index-rotation-legacy.sh` a été appliqué.

Révision du 22/11/2026 (décision de l'administrateur) : le script ne fait plus
cette migration. Il ne modifie que les réglages des jeux d'index (rotation
temporelle héritée et nombre d'index conservés), qui s'appliquent aux index
futurs, et :

- affiche le plan par défaut et n'écrit qu'avec `--apply` (la variable `APPLY=1`
  n'est plus reconnue) ;
- ne supprime, ne réduit ni ne réindexe aucun index existant et n'émet aucun
  appel `DELETE` ;
- ne réduit jamais une rétention : si la durée demandée est plus courte que la
  rétention effective en place (nombre d'index × période de rotation), il
  l'affiche en avertissement « ATTENTION » et laisse le réglage inchangé ;
- refuse un réglage qui conserverait moins d'index qu'il n'en existe (Graylog
  supprimerait les plus anciens), par exemple un passage de P1D à P1M, et
  refuse d'agir si OpenSearch ne permet pas de compter les index ;
- se contente de signaler un écart de routage des streams (plus de correction
  automatique).

Code retour 3 si au moins un jeu d'index est écarté. Tests hors ligne :
`tests/test_retention_consolidee.py`.

Relevé du 22/11/2026 (API Graylog en GET) : six jeux sont en rotation
quotidienne (`omni-winsec`, `omni-winother`, `omni-sysmon`, `omni-vsphere`,
`omni-fortigate`, `omni-bunkerweb`) et les autres en rotation mensuelle avec
4 index conservés (5 pour `omni-seal-audit`), soit une rétention effective
d'environ 120 jours. Pour `omni-m365`, `omni-eset`, `omni-seal-*`, elle est
inférieure à la [politique de rétention](../securite-conformite/POLITIQUE-RETENTION.md) :
le plan du script propose de l'allonger (impact disque à évaluer avant
`--apply`). Pour les jeux à 90 jours, la rétention en place est plus longue que
la politique : le script le signale et ne la réduit pas.

## Autres scripts de la racine

| Fichier | Rôle | Statut |
|---|---|---|
| `install.sh` | Point d'entrée unique de l'installation neuve (`tools/install-platform.py`), plan en lecture seule par défaut | actif |
| `lib-graylog.sh`, `lib-platform.sh` | Fonctions communes (API Graylog, enveloppes d'entités, détection de la plateforme) | bibliothèques |
| `00-vars.env.example` | Gabarit commenté de la configuration du site (le fichier réel `00-vars.env` n'est jamais versionné) | gabarit |
| `stack-versions.env` | Versions épinglées de la pile pour les installations neuves | référence |
| `run-tests.sh` | Suites de tests hors ligne et contrôle des liens de la documentation | actif |
| `scan-depot.sh` | Blocage des secrets et des mentions d'outillage dans les commits (crochets Git) | actif |
| `generer-manifeste.sh`, `synchro-manifeste.sh`, `manifeste-deploye.txt` | Comparaison et recopie du code en service vers `deploye/` | actifs |
| `sync-deploye.sh` | Ancien outil de recopie, réduit à un message de renvoi vers `synchro-manifeste.sh` | retiré (suppression à arbitrer) |
| `verif-post-reboot.sh` | Vérification en lecture seule après un redémarrage (déchiffrement `/data`, services, collecte) | outil |
| `seal_graylog_setup.py` | Orchestrateur de l'intégration SEAL vers Graylog (voir `seal/`) | optionnel |

## Numéros en double

Neuf préfixes sont partagés par plusieurs scripts : 38, 39, 40, 48, 49 (trois
scripts), 84, 85, 86 et 97. Ils proviennent de travaux menés en parallèle qui
ont chacun pris « le numéro suivant ». Ces scripts sont **indépendants** :
aucun ne dépend de l'autre script portant le même numéro, sauf
`39-alert-digest.sh`, qui suppose le service installé par `38-alert-triage.sh`.
L'ordre alphabétique (celui d'un `ls`) convient donc, mais seul le nom complet
désigne une opération.

| Préfixe | Scripts | Remarque |
|---|---|---|
| 38 | `38-alert-triage.sh`, `38-vuln-scan.sh` | indépendants |
| 39 | `39-alert-digest.sh`, `39-collect-health.sh` | le récapitulatif suppose le triage (38) |
| 40 | `40-purge-logs.sh`, `40-ueba-ndr.sh` | **la purge est destructive** et manuelle |
| 48 | `48-m365-fail-codes.sh`, `48-ndr-scan.sh` | indépendants |
| 49 | `49-enrich-lots.sh`, `49-expo-port-class.sh`, `49-ldap-recon.sh` | indépendants |
| 84 | `84-dashboards-triage-site.sh`, `84-kerberoast-dedup.sh` | le second est ponctuel |
| 85 | `85-detection-extra3.sh`, `85-detections-backlog.sh` | indépendants |
| 86 | `86-detections-backlog2.sh`, `86-services-versioning.sh` | indépendants |
| 97 | `97-enrich-alerts.sh`, `97-multisite-soar.sh` | le premier est ponctuel |

## Synthèse

| Statut | Nombre | Scripts |
|---|---|---|
| socle | 15 | 00 à 08, 10 à 14, 71 (08 est remplacé en production mais reste utilisé par les installations neuves) |
| optionnel | 77 | extensions activées sur l'installation de référence |
| ponctuel | 6 | 40-purge-logs, 53, 54, 79, 84-kerberoast-dedup, 97-enrich-alerts |
| outil | 2 | 57, 98 |
| obsolète | 4 | 22, 31, 44, 99 |
| à arbitrer | 1 | 83 (voir la note ci-dessus) |

Le décompte « optionnel » inclut 41 (partiellement remplacé) et 15 (recouvre 34).

## Plan de renumérotation et de regroupement (proposition, non appliquée)

Objectif : rendre l'ordre d'exécution lisible, supprimer les doublons et
séparer ce qui s'installe de ce qui s'exécute une fois. Rien n'est appliqué
tant que les contraintes ci-dessous ne sont pas levées.

### Principes

1. **Le socle garde ses numéros** (00 à 14, 71) : il est cité par
   l'installateur, la documentation d'installation et les tests.
2. **Les extensions sont regroupées par domaine**, dans des plages réservées
   avec des trous pour les ajouts futurs :

   | Plage | Domaine | Exemples actuels |
   |---|---|---|
   | 100-199 | Sources et collecteurs | 16, 17, 18, 19, 52, 55, 56, 63, 64, 90, 92, 93, 94 |
   | 200-299 | Détections | 28, 35, 47, 50, 51, 67, 73, 76, 78, 80, 85, 86, 87, 88, 91 |
   | 300-399 | Enrichissement et corrélation | 37, 48-m365, 49 (trois), 58, 66, 81, 96, 97-multisite |
   | 400-499 | Triage, réponse et SOAR | 36, 38-triage, 39-digest, 69 |
   | 500-599 | Analyses comportementales et ML | 40-ueba, 43, 48-ndr, 49-ldap, 77, 89 |
   | 600-699 | Supervision et résilience | 27, 29, 30, 32, 39-collect, 46, 60, 61, 62, 74, 86-services |
   | 700-799 | Console, tableaux de bord, rapports | 14 (reste au socle), 15, 34, 42, 45, 65, 75, 82, 84-dashboards, 95 |
   | 800-899 | Conformité | 41 (volet réduction), 57, 68, 83 corrigé |

3. **Les opérations uniques quittent la numérotation** : 40-purge-logs, 53, 54,
   79, 84-kerberoast-dedup et 97-enrich-alerts rejoignent `tools/ponctuel/`
   (ou un dossier `maintenance/` pour les purges, qui restent des procédures
   manuelles documentées).
4. **Les scripts obsolètes sont retirés** (22, 31, 44, 99), leur historique
   restant dans Git ; 98 rejoint `tools/` comme outil.
5. **L'ordre est décrit par un manifeste** (par exemple
   `provisioning/plan.yaml` : identifiant, script, dépendances, idempotence,
   caractère destructif) lu par l'installateur et par le gestionnaire SSH, au
   lieu d'être déduit des numéros.

### Contraintes pour toute renumérotation

- Trois unités systemd de production appellent des scripts par leur chemin :
  `omni-backup-config.service` (30), `omni-disk-guard.service` (32) et
  `omni-iso-evidence.service` (68), toutes vers la copie
  `/root/omnitech-siem-setup`. Elles doivent être mises à jour dans la même
  livraison.
- `tools/install-platform.py` (liste des phases), `manager/inventory.py`
  (classement par préfixe) et les tests associés citent les noms actuels.
- Les en-têtes de nombreux scripts citent leurs prérequis par numéro.
- Prévoir une période de transition : liens symboliques ou scripts de renvoi
  aux anciens noms, signalés comme dépréciés, puis suppression.
