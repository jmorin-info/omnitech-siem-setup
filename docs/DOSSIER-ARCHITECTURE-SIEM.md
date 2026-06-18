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
