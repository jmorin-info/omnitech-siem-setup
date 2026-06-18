# CONTEXT.md — SIEM Graylog OMNITECH Security (contexte technique du projet)

Dernière mise à jour : 2026-06-11. Ce document décrit l'état **réel et vérifié**
de la VM `bx-it-graylog-vm` (10.33.220.10, VLAN 220) et de tout ce qui a été
provisionné. Tout est reproductible via les scripts de `~/omnitech-siem-setup/`.

---

## 1. Architecture

```
Postes/Serveurs Windows ──Winlogbeat(TLS 5044)──┐
FortiAnalyzer 10.33.80.253 ──syslog 1514────────┤
                                                ▼
   nginx 443 (TLS PKI) ──► Graylog 7.1.3 (API HTTPS 127.0.0.1:9000, TLS PKI)
                                │                │
                        MongoDB 127.0.0.1   OpenSearch 2.x 127.0.0.1:9200
                                                │  (données sur /data = sda 7,3T)
```

- **VM** : Debian 13, 8 vCPU / 32 Go. Heap OpenSearch 12g, heap Graylog 4g,
  cache Mongo 1g. Données OpenSearch + journal Graylog sur `/data` (sda).
  Sauvegardes sur `/home/siem-backup` (sdb). **Ne pas toucher sdc (clé USB).**
- **Comptes/secrets** : `00-vars.env` (chmod 600) + `SECRETS.md`. Admin web
  Graylog = `admin` / `GRAYLOG_ADMIN_PASS`.
- **SMTP** : relais interne `smtp-internal.omnitech-security.fr:25`, alertes
  vers `informatique@omnitech-security.fr`.

### TLS — état précis (corrigé le 11/06, source d'incident)
- Certificat PKI (AD CS « Root CA OMNITECH SECURITY ») dans `/etc/graylog/certs/`
  (`graylog.crt`/`.key` + `omnitech-rootca.crt`).
  SAN : FQDN, `bx-it-graylog-vm`, IP `10.33.220.10` (PAS 127.0.0.1).
- **API Graylog en TLS de bout en bout** : `http_enable_tls = true`,
  `http_bind_address = 127.0.0.1:9000`,
  `http_publish_uri = https://bx-it-graylog-vm.omnitech.security:9000/`.
  Le FQDN résout en 127.0.0.1 via `/etc/hosts` (volontaire : le self-call
  passe la vérification de nom du certificat).
- **Truststore JVM** : `/etc/graylog/server/cacerts-omni.jks` (cacerts du JVM
  embarqué + Root CA importée), branché via `GRAYLOG_SERVER_JAVA_OPTS` dans
  `/etc/default/graylog-server`. Sans ça : boucle de WARN `ProxiedResource`,
  UI cassée (« JSON.parse: unexpected character »).
- **nginx 443** : cert PKI + chaîne, `proxy_pass https://127.0.0.1:9000` avec
  `proxy_ssl_verify on` (CA = Root CA OMNITECH).
- **Input Beats 5044** : certs PKI copiés vers
  `/etc/graylog/server/certs/graylog.crt` + `graylog-pkcs8.key`
  (chemins référencés par l'input en base). Les clients Winlogbeat valident
  avec `omnitech-rootca.pem`.
- Tout appel API en script : `https://${SIEM_FQDN}:9000/api` +
  `--cacert /etc/graylog/certs/omnitech-rootca.crt` (cf. `lib-graylog.sh`).

---

## 2. Scripts (`~/omnitech-siem-setup/`) — tous idempotents

| Script | Rôle | État |
|---|---|---|
| 00-preflight / 00-vars.env | checks + variables/secrets | exécutés |
| 01-base … 09-snmpd | OS, Mongo, OpenSearch, Graylog, nginx, nftables, inputs, backup, snmp | exécutés |
| `lib-graylog.sh` | helpers API (curl TLS, wrap_entity, ensure_rule/pipeline, post_entity) | sourcé par 10-14 |
| `10-graylog-model.sh` | index sets, profil de types `omni-ip-fields`, streams | **exécuté OK** |
| `11-graylog-enrichment.sh` | lookups CSV, GeoIP DB-IP + cron mensuel, Threat Intel | **exécuté OK** |
| `12-graylog-pipelines.sh` | 28 règles + 4 pipelines + ordre processeurs | **exécuté OK** |
| `13-graylog-alerts.sh` | SMTP, notification e-mail, 14 event definitions | **exécuté OK** |
| `14-graylog-dashboards.sh` | 4 dashboards (API views) | **exécuté OK** |
| `windows/` | kit AD : GPO audit, Sysmon+Winlogbeat (NinjaOne), confs | à dérouler côté AD |

**Pièges API Graylog 7.x rencontrés (ne pas re-tomber dedans) :**
1. `POST /streams`, `/events/notifications`, `/events/definitions`, `/views`
   exigent l'enveloppe `{"entity": {...}, "share_request": {...}}`
   (`CreateEntityRequest`). C'était la cause du « ECHEC stream » initial.
   → `lib-graylog.sh::wrap_entity` / `post_entity` (essaie direct, retombe
   sur l'enveloppe si « entity cannot be null »).
2. Cache lookup : `ttl_empty` est un **Long** (secondes), pas un booléen.
3. `GET /system/indices/index_sets/profiles/all` renvoie un **tableau nu**.
4. Ordre processeurs requis : `Message Filter Chain → Stream Rule Processor →
   Pipeline Processor → GeoIP Resolver` (streams routés AVANT pipelines,
   GeoIP APRÈS la normalisation src_ip/dest_ip).
5. Les logs de test injectés avec un timestamp « futur » (TZ) n'apparaissent
   pas dans les recherches relatives — vérifier dans OpenSearch directement :
   `curl -s 127.0.0.1:9200/omni-*/_search`.

---

## 3. Modèle de données

### Index sets (rotation 1 jour, replicas 0, shards 1)
| Index set | Préfixe | Rétention |
|---|---|---|
| OMNI - Windows Security | `omni-winsec` | 90 j |
| OMNI - Sysmon | `omni-sysmon` | 60 j |
| OMNI - Windows autres | `omni-winother` | 60 j |
| OMNI - FortiGate | `omni-fortigate` | 90 j |

Profil de types `omni-ip-fields` appliqué aux 4 : `src_ip`/`dest_ip` en type
OpenSearch `ip` → recherches CIDR (`src_ip:"10.33.0.0/16"`).

### Streams (retirés du flux par défaut, routés par input + canal)
- **OMNI - Windows Security** : input Beats + canal `Security`
- **OMNI - Sysmon** : input Beats + canal `Microsoft-Windows-Sysmon/Operational`
- **OMNI - Windows autres** : input Beats, hors Security/Sysmon
- **OMNI - FortiGate** : inputs syslog TCP/UDP 1514

### Champs normalisés (produits par les pipelines, schéma commun)
`event_id`, `event_source` (windows_security|sysmon|windows|fortigate),
`event_action`, `event_category`, `user`, `host`, `src_ip`, `src_port`,
`dest_ip`, `dest_port`, `process_name`, `process_path`, `command_line`,
`parent_process`, `dns_query`, `logon_type_label`, `failure_reason`,
`priv_group_label`, `channel`, et **`alert_tag`** (winsec_critique, dcsync,
kerberoasting, sysmon_injection, powershell_suspect, defender, fortigate_utm).
GeoIP ajoute `<champ>_geo_*` sur les IP publiques.

### Lookups (CSV dans `/etc/graylog/lookup/`, sources dans `lookups/`)
`omni-win-event-action` / `-category` (EventID Security), `omni-sysmon-event-action`,
`omni-winother-action` (clé `canal:eventid`), `omni-logon-type`,
`omni-logon-failure` (sous-statuts 4625/4776), `omni-kerb-failure`,
`omni-priv-group-rid` (RID → nom de groupe privilégié).

### Pipelines (stages 0=normalisation, 5=lookups, 10=détections)
1 pipeline par stream, 28 règles `omni-*`. Détections notables :
- DCSync : 4662 + GUID réplication (`1131f6aa`/`1131f6ad`) + compte non machine
- Kerberoasting : 4769 + chiffrement RC4 (0x17) + SPN non machine
- Sabotage audit : 1102/4719/4794/4765/4766 + System:104
- PowerShell suspect : 4104 ScriptBlock + Sysmon 1 (motifs -enc, downloadstring…)
- FortiGate : parsing key=value natif + renommage srcip→src_ip etc. + tag UTM

---

## 4. Alerting (14 définitions, notification mail « OMNI - Mail equipe IT »)

P3 : Sabotage audit · Force brute (≥10 échecs/compte/10 min) · Password
spraying (≥8 comptes/IP/10 min) · Groupe privilégié modifié · DCSync ·
Kerberoasting (≥5 SPN/compte/10 min) · Defender détection/désactivation ·
FortiGate virus/IPS · **Silence Winlogbeat (0 log Windows/15 min)**.
P2 : Compte verrouillé 4740 · Compte créé 4720 · Injection processus
(Sysmon 8/25) · PowerShell suspect · Nouveau service 7045.
Grace 10 min, backlog 5 messages dans le mail.

## 5. Dashboards
`OMNI - Windows Securite`, `OMNI - Endpoint`, `OMNI - FortiGate`,
`OMNI - Detections` (vue alert_tag toutes sources). Regénérables :
supprimer le dashboard puis relancer `14-graylog-dashboards.sh`.

---

## 6. Volet AD / Windows (kit `windows/`, cf. README-WINDOWS.md)

Ordre : dépôt NETLOGON\SIEM → `Deploy-AuditGPO.ps1` (pilote puis prod) →
`Deploy-AgentsGPO.ps1` (déploiement domaine entier par GPO/tâche planifiée ;
NinjaOne = canal alternatif) → FortiAnalyzer (cf. `FORTIANALYZER.md`).
- GPO `OMNI-AUDIT-Baseline` : audit avancé (CSV), cmdline dans 4688,
  ScriptBlock+Module logging, Security 2 Go, SCENoApplyLegacyAuditPolicy.
- `winlogbeat.yml` collecte : Security (liste EventID ciblée), Sysmon (tout),
  PowerShell 4103/4104, Defender, System, RDP LocalSessionManager 21-25,
  NTLM 8001-8004. Sortie logstash TLS 5044, CA = Root CA OMNITECH.
- **État réel : BX-AD-01-IT-VM envoie déjà** (logs winsec/sysmon/winother
  vérifiés enrichis dans OpenSearch). Reste : déploiement de masse NinjaOne,
  FortiAnalyzer → 1514, BX-AD02 + serveurs sensibles.

## 7. Exploitation courante

```bash
cd ~/omnitech-siem-setup && source 00-vars.env && source lib-graylog.sh
api_get /system | jq .lifecycle              # santé API
api_get /system/inputstates | jq .           # inputs RUNNING ?
curl -s 127.0.0.1:9200/_cat/indices/omni-*?h=index,docs.count
tail -f /var/log/graylog-server/server.log
journalctl -u graylog-server -f
```
Relancer n'importe quel script 10-14 = sans danger (idempotents, mise à jour
des règles/pipelines si la source change).

## 7bis. Ajouts du 11/06 après-midi (tout vérifié en prod)
- **Teams** : notification `teams-notification-v2` (webhook Workflows dans
  `00-vars.env::TEAMS_WEBHOOK_URL`), rattachée avec le mail aux 19 alertes
  (sync automatique en fin de `13-graylog-alerts.sh`). Mails en ASCII pur.
- **Corrélation** : compteurs `logon_fail`/`logon_ok` (pipeline) → alerte
  « Force brute SUIVIE d'un succès » (sum&&sum) ; tag `admin_share`
  (5140/5145 ADMIN$/C$) → « Balayage de partages admin » (card(host)≥3) ;
  « Tentative sur compte désactivé » (failure_reason).
- **Threat Intel branchée** : `threat_intel_lookup_ip` sur src/dest publiques
  FortiGate (cidr_match exclut RFC1918) → tag `threat_intel` + alerte.
- **VPN étranger** : alerte par requête `remip_country_code` (GeoIP s'exécute
  APRÈS les pipelines → jamais de tag pipeline sur des champs geo !).
- **Dashboard** `OMNI - Authentification AD` (9 widgets, 3 streams).
- **Kit auto-hébergé** : nginx `/kit/` ← `/var/www/siem-kit` (Sysmon64,
  winlogbeat zip+yml, sysmonconfig, root CA) ; script NinjaOne autonome
  `windows/Deploy-SiemAgents-NinjaOne.ps1` (TOFU CA, idempotent).
- **Backup** : bug corrigé (la purge supprimait les snapshots IN_PROGRESS —
  filtre `state=="SUCCESS"` ajouté) ; chaîne testée (mongodump+snapshot+tar).
- **Rapport hebdo** : `15-rapport-hebdo.sh` → `/etc/cron.weekly/omni-siem-rapport`.
- **Sources** : winlogbeat.yml collecte AD CS (4886-4889) + NPS (6272-6274),
  lookups enrichis (catégories pki/nps).
- **GPO** : `OMNI-AUDIT-Baseline` + `OMNI-SIEM-Agents` déployées, liées à
  `OU=Entreprise` (+DC pour l'audit) ; convergence parc ~12h-14h quotidien.
- **M365 EN PRODUCTION** (16h30) : app `OMNI-SIEM-Collector` (creds dans
  `00-vars.env::M365_*`), `16-m365-input.sh` (input GELF 127.0.0.1:12201,
  index `omni-m365` 180 j, stream, pipeline tags `m365_etranger`/`m365_risque`/
  `m365_role`, 4 alertes) + `17-m365-fetcher.sh` (collecteur Python stdlib
  `/usr/local/sbin/omni-m365-fetch`, timer 5 min, curseurs
  `/var/lib/omni-m365/state.json`, espaces OData encodés en %20 !) +
  dashboard `OMNI - Microsoft 365`. Vérifié : 501 messages backfillés,
  signIns + directoryAudits OK ; `riskDetections` en 403 tant que
  `IdentityRiskEvent.Read.All`/`IdentityRiskyUser.Read.All` ne sont pas
  consentis (licence Entra P2 requise) — le fetcher tolère.

## 7ter. Refonte SOC (11/06 fin de journée)
- **Dashboard unique « OMNI - SOC » 5 pages** (Synthese+KPIs / Identite AD+M365 /
  Endpoint / Reseau / Comptes & conformite), 33 agrégations + 5 tables de
  messages (triage). Généré par `14-graylog-dashboards.sh` v2 (builder Python
  inline, multi-pages = plusieurs queries dans le search + `titles.tab`).
  Les 6 anciens dashboards mono-page sont supprimés à chaque run.
- **user M365 = partie locale de l'UPN** (`_upn` = complet) → corrélation
  on-prem↔cloud par compte. Alerte « Echecs AD + connexion M365 etrangere »
  (sum(logon_fail)≥5 && sum(m365_foreign)≥1, multi-streams). 24 alertes au total.
- **4103 retiré de la collecte** (Module Logging = flood NinjaOne, 4 368 evts/2 h
  sur un seul poste) ; 4104 conservé. `/kit/winlogbeat.yml` à jour — recopier
  dans NETLOGON\SIEM pour le canal GPO.
- **BX-INFO-JMO-LT** remonte (Sysmon/System/PowerShell) mais 0 Security tant
  que la GPO d'audit n'est pas effective sur le poste (vérifier `gpresult /r`
  + `auditpol /get /category:*`). Les hôtes apparaissent en FQDN complet.

## 8. Reste à faire (backlog)
1. Déploiement de masse Sysmon/Winlogbeat : `windows/Deploy-AgentsGPO.ps1`
   (pilote → prod) ; NinjaOne en complément hors domaine.
2. FortiAnalyzer : suivre `FORTIANALYZER.md` (forwarding syslog TCP 1514,
   filtres severity/vpn/admin/UTM ; Graylog déjà prêt).
3. Restreindre `NET_ADMIN` (nftables) au VLAN d'admin réel.
4. Tester l'envoi mail réel (System > Notifications > Test) depuis le VLAN 220.
5. Renouvellement cert PKI (expire 2028-06-10) : redéposer dans
   `/etc/graylog/certs/`, re-copier vers `server/certs` + nginx, restart.
6. Éventuel input CEF 5555 si le FAZ forwarde en CEF plutôt que syslog.

## 7quater. Passe du 11/06 soir
- Teams CORRIGE : le gabarit v2 par defaut postait la carte sans l'enveloppe
  `{"type":"message","attachments":[...]}` attendue par Power Automate ->
  adaptive_card custom enveloppee dans 13 (variables JMTE). Test direct curl
  et test Graylog recus dans le canal.
- Parc : 20+ hotes remontent (GPO/NinjaOne convergees). BX-INFO-JMO-LT : tout
  sauf Security tant que la GPO d'audit n'est pas effective (gpresult /r).
- Dashboard OMNI - SOC : 8 pages (ajout "Alertes" et "Hunting" - LSASS,
  Office->shell, AppData/Temp, persistance Run, pipes, binaires sortants).
- Compte lecture seule `soc-viewer` (role Reader) cree.
- `ISO27001.md` : auto-evaluation Annexe A 2022 (couvert vs 9 ecarts dont
  export NAS des sauvegardes, test de restauration, comptes nominatifs).

## 7quinquies. Exchange/SharePoint - O365 Management Activity (11/06)
- `18-m365-activity.sh` : abonnements Audit.Exchange/SharePoint/General
  (permission ActivityFeed.Read OK), collecteur `/usr/local/sbin/omni-m365-activity`
  (timer 10 min, etat /var/lib/omni-m365/activity-state.json, dedup par
  contentId, overlap 30 min). POST subscriptions/start exige Content-Length:0
  (sinon HTTP 411). Events -> input GELF 12201 -> stream/index omni-m365
  (m365_type=activity), pipeline SEPARE "OMNI - M365 Activite".
- Detections (flags poses par le collecteur, tagues par le pipeline) :
  forward_external (InboxRule/Set-Mailbox vers domaine hors
  omnitech-security.fr/omnitech.security) -> m365_mail_forward (P3) ;
  mailbox_deleg (Add-MailboxPermission) -> m365_mailbox_deleg (P2) ;
  external_share (AnonymousLink/CompanyLink/SecureLink externe) ->
  m365_partage_externe (P2). 3 alertes mail+Teams.
- Verifie : 27 313 events/24h (Exchange/SharePoint/OneDrive/Teams), 9 partages
  externes detectes (ex: Roadmap27001.docx -> invissys.com). 0 forward/deleg
  (pas d'attaque) mais detections armees.
- Dashboard : page "M365 Activite" (workloads, top operations, partages
  externes, acces boites, triage forward/delegation). SOC = 10 pages.
- NOTE volume : MailItemsAccessed verbeux (~12k/24h) ; filtrable si besoin.
- Partenaire recurrent invissys.com : a ajouter en domaine "connu" si trop de
  bruit sur les partages externes legitimes.

## 7sexies. Passe sante + FortiGate + vSphere (11/06 soir)
- SANTE : disque /data 2%, cluster green. BUG corrige : 119 echecs d'indexation
  M365 (src_ip au format ip:port rejete par le type 'ip') -> fonction clean_ip()
  dans les 2 collecteurs (17 et 18).
- Detections ajoutees (12+13) : ransomware_indicator (vssadmin/wbadmin/bcdedit
  delete shadows, P3), lsass_access (Sysmon 10 + GrantedAccess suspect, P2),
  tache planifiee 4698 (P2). 34 alertes OMNI au total.
- FortiGate : dossier `fortigate/` = 01-utm-logging.conf (le FortiGate ne logge
  PAS ses profils UTM = le vrai trou) + 02-faz-forwarding.conf (filtre revise).
  Detail dans FORTIANALYZER.md.
- vSphere : `19-vsphere.sh` (inputs syslog TCP+UDP 1516, index omni-vsphere 90j,
  stream, pipeline parsing best-effort, tags vsphere_auth_fail/shell_ssh/
  vm_destroy/config, 3 alertes). Parsing VALIDE sur logs de test (user/ip/tags
  OK). Pare-feu 1516 ouvert (VSPHERE_NET). Cote ESXi/vCenter : VSPHERE.md.
- Dashboard OMNI - SOC : 13 pages (ajout vSphere).

## 7septies. RESOLU : canal Security muet (11/06 nuit) - PIEGE A RETENIR
SYMPTOME : le DC (puis tout poste avec audit actif) n'envoie AUCUN event
Security, alors que les autres canaux (Sysmon...) remontent normalement.
FAUSSE PISTE : journal Security plein / mode "ne pas ecraser". Le clear + audit
ne changent rien (c'etait hors sujet, mais sans dommage).
CAUSE REELLE : la liste `event_id` du canal Security dans winlogbeat.yml etait
trop longue (~48 EventID). L'API Windows Event Log limite le nombre
d'expressions par requete -> "La requete specifiee n'est pas valide"
(ERROR_EVT_INVALID_QUERY) et Winlogbeat ne lit PLUS RIEN sur ce canal.
DIAGNOSTIC CLE : `wevtutil qe Security /q:"*[System[(EventID=4624)]]"` MARCHE
(canal sain) mais les logs winlogbeat montrent "Open() error ... Security ...
requete invalide". => c'est la config de l'agent, pas le journal.
CORRECTIF : winlogbeat.yml canal Security en RANGES (6 expressions) :
  event_id: 1100-1104, 4624-4799, 4886-4889, 5136-5145, 6272-6274, 7045
Pousse via /kit + NETLOGON. Redeploye par Deploy-SiemAgents-NinjaOne.ps1
(telecharge le yml + restart). NE JAMAIS remettre une longue liste plate.
Si un journal a ete cleared pendant que winlogbeat tournait : purger aussi le
registre `C:\ProgramData\winlogbeat\.winlogbeat.yml` (bookmark obsolete).
RESULTAT : DC + parc remontent le Security (19k+/30min DC). Lookup win-events
enrichi des EventID de la plage (4670,4673,4674,4727,4730,4731,4734,4767,4778,
4779). Regle vSphere vm-destroy affinee pour exclure les snapshots Veeam.

## 7octies. Incident 12/06 matin : spam "Force brute" + Teams muet — RESOLU

**Symptome** : toute la nuit, mails "OMNI - Force brute" (adm-jmorin, 297
echecs/10 min, IP source vide) classes spam par Exchange ; AUCUNE autre
notification recue, Teams compris.

**Causes (3 etages)** :
1. **BX-AD02-IT-VM** : un service Windows tourne avec `adm-jmorin` SANS le
   droit *Ouvrir une session en tant que service* (4625 type 5, Status
   0xC000015B, appelant services.exe, 1 echec/2 s depuis des JOURS, 1792/h
   constant). Devenu visible seulement quand AD02 a recu le winlogbeat corrige
   (backfill ignore_older=72h). Identification cote hote :
   `Get-CimInstance Win32_Service | ? StartName -like '*adm-jmorin*'`.
2. Definition Force brute trop brute : query `event_id:4625` (types
   service/batch inclus), grace 10 min, pas de cle -> re-notification toutes
   les 10 min toute la nuit (+ "SUIVIE d'un succes" des qu'il se connectait).
3. Le volume a fait classer les mails en spam ET a tue le flux Power Automate
   (throttle/quota interne, Graylog recoit 202 -> ZERO erreur loguee) ->
   **panne silencieuse de toutes les alertes Teams**. Pendant ce temps le
   vrai signal est passe inapercu : spraying SSLVPN depuis Internet (10k+
   echecs/16 h, comptes AD reels vises) -> 38 verrouillages AD dans la nuit.

**Correctifs appliques (12 modifie + NOUVEAU 21-alert-hygiene.sh)** :
- Pipeline : `logon_fail` seulement si LogonType != 4/5 ; nouveau compteur
  `service_logon_fail` (types 4/5) ; `failure_reason` corrige (SubStatus 0x0
  -> fallback lookup Status ; ligne `0x0,succes` retiree du CSV, regle 4776
  ignore Status 0x0) ; exclusions injection Sysmon (dwm/winlogon/csrss/
  unknown) ; 4104 exclut le Path Azure AD Sync ; FortiGate : src_ip/dest_ip
  non-IP jetes (octets corrompus FAZ), user="N/A"/IP supprime.
- Definitions (21) : Force brute -> query `4625 AND logon_fail:1`, grace 1 h,
  key=["user"] ; SUIVIE d'un succes -> grace 1 h key user ; spraying ->
  30 min key src_ip ; VPN/verrouille/injection/PowerShell -> grace 1 h ;
  nouvelle def **"OMNI - Echec logon service/batch (compte de service
  casse)"** (mail seul, grace 4 h, key user+source).
- `fortigate/03-vpn-hardening.conf` : geo-FR sur le portail SSLVPN +
  login-attempt-limit/login-block-time + reco MFA/SAML (A APPLIQUER).

**PIEGES A RETENIR** :
- key_spec d'une definition n'est accepte par l'API que si chaque cle a une
  entree field_spec (template `${source.<champ>}`) — sinon le PUT echoue avec
  `key_spec can only contain fields defined in field_spec`, et api_put renvoie
  quand meme exit 0 : TOUJOURS verifier la presence de `.id` dans la reponse.
- Le grace s'applique PAR CLE quand key_spec est pose : un nouveau compte
  attaque notifie immediatement meme si un autre compte est en grace.
- Echec logon type 4/5 = hygiene (compte de service), JAMAIS de la force
  brute : separer les deux detections.
- Teams via Power Automate echoue EN SILENCE : apres toute tempete, verifier
  l'historique d'execution du flux Power Automate (pas les logs Graylog).
- Relancer `21-alert-hygiene.sh` apres CHAQUE re-run de 13-graylog-alerts.sh
  (13 recree avec grace=600000 / key=[]).

## 7nonies. Passe du 12/06 matin (apres l'incident)

- **Cause AD02 identifiee par Julien** : service `Fortinet_FSAE` (FSSO
  Collector !) qui tournait avec adm-jmorin -> passe en Systeme local.
  Tempete stoppee a 08:06:29. BONUS : FSSO etait mort depuis des jours ->
  l'attribution `user=` dans les logs FortiGate etait a ZERO ; restauree
  (10k+ logs attribues/15 min). Si refonte un jour : compte FORTIGATE-SVC.
- **`windows/Install-OmniSiem-NinjaOne.ps1`** (aussi sur /kit) : script
  NinjaOne UNIQUE et definitif, remplace Deploy-SiemAgents + Set-OmniAudit.
  CA TOFU + audit (baseline /kit) + Sysmon (hash) + Winlogbeat (restart
  SEULEMENT si conf/version changent) + canal "Veeam Backup" auto-detecte
  + sante (test output, scan erreurs de canal "requete invalide") + resume
  [OK]/[KO], exit 1 si KO. Planification quotidienne recommandee.
- **Liens console retires** des 3 templates de notification (mail texte,
  mail HTML, carte Teams Action.OpenUrl) — en prod ET dans 13.
- **Veeam B&R** : regles omni-winother-10-veeam(-echec), alerte "OMNI -
  Veeam : job en echec ou avertissement" (P3 mail, grace 4 h, creee par 21
  section [3/3]), page dashboard "Sauvegardes". Cote serveur Veeam : juste
  lancer Install-OmniSiem (auto-detection). Doc : VEEAM.md.
- **Dashboard OMNI - SOC : 15 pages** (+ "VPN & Exposition" : carte des
  attaques portail, IP/comptes vises, tunnels legitimes, verrouillages AD ;
  + "Sauvegardes" ; + widgets comptes de service casses sur Identite AD).
- **Verif impact 03-vpn-hardening** : 100 % des tunnels reussis viennent de
  France (7 users) sur l'historique disponible -> geo-FR sans impact connu.
  login-attempt-limit releve a 5 (choix Julien 12/06). NOUVEAU
  `fortigate/04-proxy-inspection.conf` : bascule des regles en inspection
  proxy (par regle, GUI multi-selection ou CLI), feature-set proxy sur les
  profils AV/webfilter, EXCEPTION regles VoIP (rester flow), surveillance
  conserve mode, et reco deep inspection via SubCA AD CS a terme.
- **IDENTITE DU FORTIGATE BDX (piege)** : hostname CLI = `BX-FW02-IT-RT-S`,
  serial FG120GTK23000193, HA a-p primary — mais le FAZ forwarde ses logs
  sous son nom d'enregistrement FAZ **OMNITECH-BDX_FG120G** (champ devname).
  Meme boitier. Verif : `get system status` (serial). FortiOS 7.4.11.
  Pieges CLI FortiOS : grep busybox sans -E (utiliser `| grep -f motif` =
  contexte de config avec l'ID de regle) ; `av-block-log` n'existe plus.
- **`fortigate/05-utm-policies-bdx.conf`** : attachement UTM PRET A COLLER,
  genere depuis le `show firewall policy` reel (12/06). Tiers : A=users/wifi
  pile complete (441/1261/1256), B=entrants exposes 87/925 (IPS+AV), C=IoT
  217, D=~35 regles serveurs->Internet (AV+IPS+DNS+App), E=user->endpoints
  externes (AV+IPS). Exceptions : Teams (10), VoIP, FortiGuard, OpenVAS,
  flux SIEM. Regle morte 469 "TEST" (dstaddr-negate) a supprimer.
- **RESOLU 12/06 ~10h30 via `06-utm-fix-bdx.conf`** : le 05 n'attachait pas
  les profils (conflit feature-set proxy vs regles flow, silencieux au
  collage). Sequence qui marche : 1) unset av/web du bloc E, 2) inspection-
  mode proxy sur les 63 regles, 3) feature-set proxy, 4) attachement.
  VERIFIE : 9300+ logs UTM/10 min au SIEM (dns 4.2k, app-ctrl 4.2k, ssl,
  webfilter). `diagnose log test` = excellent test bout-en-bout (toutes
  categories injectees -> visibles SIEM en secondes). 02-faz-forwarding
  OBSOLETE (filtre FAZ d'origine = defauts, rien a changer).
- **03 VPN hardening APPLIQUE 12/06 09:45 locale** : spraying 104/5min ->
  0 des 09:50, tunnels FR continuent (2-4/15 min). Plus de verrouillages AD
  par le portail. Surveiller RAM/conserve mode 1 semaine (63 regles proxy) :
  `get system performance status`.
- **Veeam INTEGRE 12/06 ~11h45** : BX-VEEAM-IT-SV (10.33.240.1, VLAN
  LAN_BACKUP) enrole via Install-OmniSiem manuel (TLS12 a forcer pour le
  bootstrap iwr sur Server 2016 ; regle FW corrigee : append TCP_5044 a la
  regle SIEM, la 1339 d'origine avait srcintf DMZ_PUBLIQUE = jamais matche).
  Canal "Veeam Backup" auto-detecte + 72h backfill. Bug locale corrige dans
  Install-OmniSiem (verif auditpol "Success|ussite" pour OS FR) -> les runs
  NinjaOne du matin ont pu s'afficher failed A TORT (cosmetique).
- **TROUVAILLE Veeam** : le job horaire "[1 heure] - VM Backup critical
  light" ECHOUE sur BX-VAULTWARDEN-IT-VM (le coffre-fort de mots de passe !)
  depuis au moins le 09/06 (~25 echecs/jour), silencieusement. L'alerte
  "OMNI - Veeam : job en echec" enverra desormais 1 mail/4h tant que ce
  n'est pas repare. A investiguer dans la console VBR (detail de session).

## 7decies. Resilience + retention ISO (12/06 midi)

- **Sauvegarde config quotidienne** : `30-backup-config.sh` + timer systemd
  `omni-backup-config.timer` (03:15, Persistent). Contenu : mongodump (URI
  auth lue dans server.conf), /etc/graylog+opensearch+nginx+systemd,
  /usr/local/sbin, kit, ~/omnitech-siem-setup. SANS les indices (logs).
  Archive AES-256 (`BACKUP_PASSPHRASE` dans 00-vars.env, A METTRE AU COFFRE)
  -> copie locale /var/backups/siem + export `//10.33.50.5/Public/SIEM`,
  retention 14 j des deux cotes. Statut auto-envoye en GELF (12201) ->
  alertes "Backup config SIEM en echec" + "absent >26h" (21 section [4/4]).
  Procedure de reconstruction complete : `RESTORE.md` (tester 1 fois sur VM
  jetable !). RESTE COTE JULIEN : regle FortiGate Reseau ELK -> H_OMS_FILES
  service SMB (mount cifs en erreur 115 sinon) + eventuel /root/.smb-siem.cred
  si guest refuse (username/password/domain, chmod 600).
- **Retention ISO appliquee** (`31-retention-iso.sh`, base volumetrie mesuree
  12/06 post-UTM, /data = 7,3 To dedie, ~25 Go/j tous flux) :
  winsec/winother/m365 = 365 j, sysmon/vsphere/fortigate = 180 j.
  Projection a saturation ~5,6 To (77 %). REVUE MENSUELLE du Go/j (surtout
  fortigate ~11 Go/j) ; options si derive : fortigate 120 j ou split
  traffic/UTM en 2 index sets. Relancer 31 apres tout re-run de 10.
- **Backup OPERATIONNEL 12/06 ~12h15** : 1ere archive (26 Mo chiffres) sur
  //10.33.50.5/Public/SIEM. Compte : svc_siem (cred /root/.smb-siem.cred,
  600). Regle FW creee par Julien (445 ok). Garde-fou disque actif
  (`32-disk-guard.sh` + timer 6 h : warn 80 %, purge urgence 88 %->82 %).
- **DOSSIER DOCUMENTAIRE ISO cree (docs/)** : 00-INDEX, POL-SUPERVISION-
  JOURNALISATION (politique, retentions, engagements), STD-JOURNALISATION
  (sources/transport/champs/severites/comptes), PRO-EXPLOITATION-SIEM
  (revues quotid/hebdo/mensuelles, triage, gestes), DOSSIER-ARCHITECTURE-
  SIEM (plateforme, versions, flux, 41 alertes, IaC, MEP, backlog),
  LDAPS.md. Inclus dans la sauvegarde quotidienne. A faire signer DSI (POL).
- **LDAPS console OPERATIONNEL** (`33-ldaps-auth.sh`, 12/06) : backend
  "Active Directory OMNITECH" actif, LDAPS 636 vers bx-ad-01-it-vm
  (10.33.50.250), cert verifie par la Root CA. Compte de liaison = svc_siem.
  ACCES RESTREINT aux "Admins du domaine" via filtre LDAP memberOf recursif
  (OID 1.2.840.113556.1.4.1941) sur
  `CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,...`
  (DN confirme par ldapsearch ; le groupe par defaut a ete DEPLACE hors de
  CN=Users). Role Admin par defaut (population deja restreinte). Filtre teste
  OK (adm-jmorin admis, svc_siem rejete). Pre-requis applique : regle FW 425
  + service LDAPS-GC. Compte local admin garde en secours (coffre).
  Pieges : grep busybox cote DC inutile ; le "invalid credentials" initial
  venait du port 636 droppe (backend jamais cree), PAS du mot de passe.
- **RAPPORT HEBDO** (`34-weekly-report.sh` + `/usr/local/sbin/omni-weekly-
  report`, timer lundi 08:00) : mail HTML (alertes/AD/VPN/endpoint/M365/
  sauvegardes/capacite/sante), copie locale /var/backups/siem/rapport-hebdo_*.
  Statut GELF (event_source=siem_report) -> alerte "Rapport hebdo en echec".
  Le stream "OMNI - Interne SIEM" route desormais siem_backup + siem_disk_
  guard + siem_report (3e regle ajoutee). 41 definitions OMNI au total.
- **DOCS ISO COMPLETES (docs/)** : + REGISTRE-CONFORMITE-ISO27001 (mapping
  Annexe A -> preuves + actions ouvertes + methode auditeur) et PRA-
  RECONSTRUCTION-SIEM (RTO 4h / RPO config 24h / logs non sauvegardes,
  scenarios, checklist validation). POL enrichie (cadre normatif, KPI,
  exceptions, validation DSI), STD (matrice EventID, NTP, durcissement),
  PRO (5 playbooks, classification, RACI).
- **PURGE LOGS 12/06 ~13h (base saine)** : `40-purge-logs.sh` (MANUEL,
  CONFIRM=OUI, jamais planifie). Apres la phase build/tests/tempete, remise
  a zero des index de logs (stop graylog -> DELETE omni-*/gl-events/gl-
  system-events + vide graylog_* -> start -> purge index_failures mongo ->
  rebuild ranges). CONFIG MongoDB INTACTE. Resultat : index recrees _0,
  0 echec d'indexation, collecte temps reel reprise immediatement (27 hotes).
  Sauvegarde config faite avant. NE PAS rejouer sans raison.
- **COMPTE CANARI** (`35-canary.sh` + `windows/New-OmniCanary.ps1`, 12/06) :
  lookup omni-canary (CSV lookups/canary-accounts.csv, defaut svc_sql_adm,
  case-insensitive), regle pipeline omni-winsec-10-canary (match user/
  TargetUserName/SubjectUserName/ServiceName sans $ via regex_replace),
  alerte P3 mail+Teams "COMPTE CANARI touche". Script PS cree le compte AD
  leurre (mdp aleatoire jamais utilise, SPN MSSQLSvc pour piege Kerberoasting,
  logonHours=0, AUCUN privilege reel). Ajouter un canari = editer le CSV +
  relancer 35. ORDRE : 35 (lookup) AVANT rejeu de 12 (la regle l'utilise).
  RESTE COTE JULIEN : lancer New-OmniCanary.ps1 sur un DC (ajuster l'OU).
- **SOAR-LIGHT** (`36-soar.sh` + `/usr/local/sbin/omni-soar` service +
  omni-soar-expire timer, 12/06) : architecture THREAT FEED (pas de
  credential sur le FW). Webhook Graylog HTTP (alertes Force brute VPN +
  spraying) -> service 127.0.0.1:8088 -> securites (jamais RFC1918, jamais
  SOAR_WHITELIST, seuil SOAR_MIN_HITS=5, cap SOAR_MAX=500, TTL 24h) -> feed
  /kit/soar/blocklist.txt (servi HTTPS) -> FortiGate External Connector le
  lit + policy deny. Tracabilite GELF event_source=siem_soar -> stream
  interne -> alerte "SOAR : IP bloquee". Teste OK (IP publique bloquee, IP
  interne/sous-seuil ignorees, format backlog message gere). Notification
  Graylog http-notification-v1 : SEULS url/api_key/basic_auth/skip_tls
  (pas de method/content_type, sinon "Unable to map property"). RESTE COTE
  JULIEN : appliquer fortigate/06-soar-threatfeed.conf + SOAR_WHITELIST
  (IP publiques entreprise/admin a ne jamais bloquer). 43 definitions OMNI.
- **BUG vSphere parsing CORRIGE 12/06** : decouvert apres la purge (logs
  enfin visibles "en clair"). Le pipeline vSphere avait `stage 0 match either`
  avec UNE SEULE regle (drop-bruit) ; or en "match either", si aucune regle
  du stage ne matche, le message N'AVANCE PAS aux stages suivants. Donc tout
  message NON-bruit (= la quasi totalite) etait bloque avant la normalisation
  -> 0 host/event_source/event_action sur 44k logs/15min. CORRECTIF : mettre
  la normalisation DANS le stage 0 avec drop-bruit (normalisation matche
  toujours has_field message -> le stage matche toujours -> avance). Resultat:
  parsing OK, 4 ESXi + vcenter visibles. PIEGE A RETENIR : ne jamais laisser
  un stage "match either" avec seulement une regle conditionnelle (drop/tag)
  -> il devient un filtre qui bloque tout ce qui ne matche pas. Toujours y
  adjoindre une regle qui matche toujours (normalisation).
- **BUG M365 Activity CORRIGE 12/06** : le collecteur omni-m365-activity
  plantait a CHAQUE run apres le 1er ("can't compare offset-naive and
  offset-aware datetimes", ligne 134 : datetime.fromisoformat(last) naive vs
  now aware). CORRECTIF : `.replace(tzinfo=timezone.utc)` (corrige sur le
  binaire ET dans 18-m365-activity.sh). Resultat : 52k+ events activite
  (Exchange/SharePoint/OneDrive/Teams). Apres une purge, RESET des curseurs
  M365 (/var/lib/omni-m365/state.json signins/audits a now-24h) pour
  repeupler -> fetch 510 + activity 1006 events. riskDetections 403 = Entra
  P2 requis (connu). PIEGE PYTHON : toujours rendre les datetime aware
  (tzinfo=utc) avant comparaison/soustraction avec now(timezone.utc).
- **GeoIP lookup omni-geoip-city** : has_error=true MAIS table INUTILISEE
  (aucune regle ne l'appelle ; le GeoIP Resolver processor peuple
  src_ip_geolocation = la cartographie marche). Reliquat inoffensif.
- **vSphere drop bruit ESXi (12/06)** : 87% du volume vSphere = bruit ESXi
  (vSAN traces, osfsd, envoy-access, vmkwarning ; application_name VIDE cote
  ESXi -> filtrage sur le CONTENU du message). Regle omni-vsphere-00-drop-
  esxi-bruit (stage 0). Resultat : 26k->7.7k/5min (-70%, ~2.2M/j au lieu de
  7.6M/j), ne reste que vCenter + ESXi auth/events utiles. Garde hostd/vpxa/
  sshd/shell/vobd. Dans 19-vsphere.sh.
- **Veeam CONFIRME OK (12/06)** : canal "Veeam Backup" remonte (apparait des
  qu'un job tourne ; 0 entre 2 jobs = normal). Job "[1 heure] VM Backup
  critical" sur BX-VAULTWARDEN ECHOUE toujours (tag veeam_job_echec pose,
  alerte mail part) -> A REPARER cote Veeam (action Julien).
- **SOAR_WHITELIST appliquee (12/06)** : 159.180.234.120, 92.184.107.14,
  92.184.96.118 (connexions VPN reussies France, logs) + 81.255.193.131
  (IP publique site Ivry, conf H_IVRY_PUB). Testee (IP whitelistee non
  bloquee). A COMPLETER par Julien : IP publiques sortie sites Bordeaux/PACA
  + remote-gw tunnels IPsec (les 92.184.x sont peut-etre dynamiques
  residentielles -> a reviser). Editer 00-vars.env + systemctl restart omni-soar.
- **REDEMARRAGE/BOOT verifie 12/06** : tous services enabled (mongod,
  opensearch, graylog-server, nginx, nftables, omni-soar) + tous timers
  enabled ; /data dans fstab (xfs UUID, monte avant les services). Durci :
  drop-in /etc/systemd/system/graylog-server.service.d/10-omni-deps.conf
  (After/Wants mongod+opensearch) pour garantir l'ordre. Graylog
  Restart=on-failure. => redemarre proprement seul au boot.
- **SURVEILLANCE CERTIFICATS** (`/usr/local/sbin/omni-cert-check` + timer
  omni-cert-check hebdo lundi 07:30) : alerte GELF (event_source=siem_cert)
  si un cert expire dans <45j -> alerte "OMNI - Certificat SIEM expire
  bientot" (44 defs). Certs actuels : console/api graylog.crt expire
  10/06/2028 (728j, emis PKI AD CS), Root CA 2033. Renouvellement auto =
  selon infra (NDES/SCEP -> certmonger ; sinon script Windows certreq qui
  pousse via le partage SMB ; ou manuel). stream interne route maintenant
  siem_backup/disk_guard/report/soar/cert.
- **SUPERVISION CERTIFICATS DU PARC (12/06)** : `windows/Get-OmniCertExpiry.ps1`
  (auto-detecte PKI -> base CA via certutil, sinon magasin LocalMachine\My)
  ecrit les certs expirant <60j dans le journal Windows "OMNI-Certificats"
  (EventID 9001), collecte par winlogbeat (canal ajoute a winlogbeat.yml).
  Pipeline `omni-winother-10-cert-parc` parse (cert_subject/days/store/machine)
  -> alerte "OMNI - Certificat du parc expire bientot" (P3 mail, key cert_machine,
  grace 23h). A DEPLOYER par Julien via NinjaOne sur la PKI (10.33.50.248) +
  serveurs critiques. Script + winlogbeat.yml sur /kit.
- **RENOUVELLEMENT AUTO CERT SIEM (CERTREQ retenu, 12/06)** : SCEP/NDES
  abandonne (connectivite SIEM->NDES jamais ouverte + reconfig template
  NDES delicate). Solution : CSR genere et signe SANS que la cle quitte le
  SIEM. `/usr/local/sbin/omni-cert-renew` (+ timer quotidien 06:00) : si le
  cert expire dans <30j, genere cle.new+CSR, depose sur //10.33.50.5/Public/
  SIEM/certs/graylog.csr ; quand graylog-signed.crt revient (modulus
  verifie), installe + reload nginx + GELF. Cote Windows :
  `windows/Sign-OmniSiemCsr.ps1` (sur /kit) - certreq -submit template
  WebServer, depose le cert signe. A DEPLOYER sur la PKI (10.33.50.248) en
  tache planifiee (compte avec droit Enroll sur WebServer). PARE-FEU : RIEN
  a ouvrir si le signeur est sur la PKI (AC locale + partage Files meme VLAN
  50) ; SIEM->Files 445 deja ouvert (backups). certmonger installe mais
  inutilise. Supprimer la regle FortiGate SIEM->NDES.
- **RENOUVELLEMENT CERT TESTE OK 12/06** : cycle certreq valide de bout
  en bout. Template = **OMS-WebServer** (PAS WebServer standard ; nom
  fige dans Sign-OmniSiemCsr.ps1 et Install-OmniCertTasks). Nouveau cert
  installe (serial ...69D3F9, expire 11/06/2028, SAN OK). Cote SIEM tout
  automatique (timer omni-cert-renew quotidien 06:00, declenche a J-30).
  RESTE : creer la tache PKI OMNI-SiemCertSign (signature auto) via
  Install-OmniCertTasks-PKI.ps1 -SignerUser/-SignerPassword (compte avec
  Enroll sur OMS-WebServer + acces ecriture partage SIEM/certs).
- **PIEGE GELF/streams** : le stream OMNI-M365 route par gl2_source_input
  (l'input GELF 12201) -> il AVALE tout message GELF (backup, disk-guard).
  Solution : stream "OMNI - Interne SIEM" (matching OR sur event_source =
  siem_backup / siem_disk_guard, index set par defaut), cree par 21 [4/4],
  et les 4 defs d'auto-surveillance re-pointees dessus (re-pointage
  idempotent en fin de 21). Page Sauvegardes du dashboard l'inclut.
  Reste cote Julien : appliquer fortigate/01 (UTM), 02 (filtres FAZ),
  03 (durcissement VPN) ; lancer Install-OmniSiem sur le parc + serveur
  Veeam ; M365 riskDetections necessite Entra P2 (en attente).
- **Dashboards v3 - OMNI - SOC 17 pages** (`14-graylog-dashboards.sh` v3,
  builder Python enrichi). Ajout page **Direction** (posture executive,
  lecture 10 s). Generateur etendu (valide en live + probe puis supprime) :
  KPIs avec **tendance J/J-1** (visualization_config trend, dir=LOWER/HIGHER
  -> par defaut sur tous les KPIs numeriques) ; tables **multi-metriques**
  (metrics=[("count"|fn,champ,libelle)] -> series search_type + widget) ;
  **pivot2** (2e row_group), graphes **area**, **annotations d'evenements**
  (event_annotation) sur chronologies. Page **Alertes** re-ancree sur
  `alert_tag` (car `alert:true`/`priority` = 0 : detections = tags pipeline,
  pas des Events Graylog ; ~10.8k alert_tag/24h).
  PIEGE TYPE DE CHAMP : sentbyte/rcvdbyte/duration sont mappes **keyword**
  (le parseur key_value rend des chaines) -> sum()/avg() => illegal_argument.
  FIX : regle `omni-forti-05-octets` (12, stage 5) qui cree **bytes_sent /
  bytes_rcvd / bytes_total** via to_long (mappes **long** des 1re occurrence)
  -> agregations de bande passante OK (vaut pour les NOUVEAUX logs ; sum
  testee = 12 To/h). Reseau enrichi : volume KPIs, "Bande passante (24h)"
  (area sum), top talkers par volume, top dest par octets. cert_days = long
  (les seuils [0 TO 15] sont corrects).
- **Dashboards : fenetres par widget + detail de la detection.** DSL `range=`
  (secondes) -> override de timerange POSE sur le widget ET son search_type
  (`_tr(w)`, valide en live : persiste sur les 2). Constantes D7=604800 /
  D30=2592000. Applique aux DETECTEURS D'EVENEMENTS RARES (50 widgets) :
  PKI/ADCS, changements de groupes priv (4728/4732/4756), DCSync/Kerberoasting,
  vSphere shell/VM destroy, M365 forward/partage/risque, VPN SSL brute force,
  sabotage audit -> 7j ou 30j au lieu de 24h (sinon vides en periode calme).
  Les listes de triage passent en `show_message=True` + champs discriminants
  (qui/quoi/ou + message brut) = "detail de ce qui a declenche". Audit auto
  (extraction des pages + check API : q vide, dim vide, type metrique, overlaps)
  = 0 chevauchement / 0 dim invalide / 0 metrique non-num. NB : beaucoup de
  widgets "vides 24h" sont des detecteurs rares LEGITIMES (pas des bugs) :
  noms de champs/valeurs verifies corrects (gestion_comptes, fwd_target,
  priv_group_label existent, juste pas d'occurrence recente).
- **Dashboards : legendes + enrichissement.** Pas de widget texte/markdown
  natif dans Graylog OSS -> les legendes passent par le champ **`description`**
  du widget (DSL `desc=`, valide : persiste, affiche en ⓘ a cote du titre).
  Serie **`latest(timestamp)`** OK -> page Sante collecte : table "Derniere
  activite par hote (7j)" = detection des **hotes muets** (agent arrete / poste
  hors-ligne). Page Endpoint refondue : chaines **parent -> enfant** (pivot2
  parent_process/process_name), top lignes de commande, tables multi-metriques
  (count + card(host)), trends, area annotee, triage detaille 7j. Direction :
  legendes sur tous les KPIs (lecture management). Probe de schema : POST
  /views accepte SEULEMENT avec l'enveloppe {entity, share_request} (sinon
  "entity cannot be null") ; le POST /views/search la refuse -> garder
  post_entity() qui gere les deux.
- **MITRE ATT&CK + score de risque** (`37-mitre-attack.sh`, NOUVEAU script).
  CSV `lookups/mitre-attack.csv` (alert_tag -> technique/nom/tactique/severite/
  score) -> 5 lookup tables omni-mitre-*. Pipeline DEDIE **"OMNI - Enrichissement
  ATT&CK"** au **stage 20** (donc APRES la pose des alert_tag en stage 10/11),
  connecte aux 6 streams de detection -> pose mitre_technique / mitre_tactic /
  mitre_technique_name / risk_severity / **risk_score (to_long -> long)**.
  Vaut pour les NOUVELLES detections. Pieges : le pipeline doit etre a un stage
  > celui qui pose alert_tag (sinon vide) ; relancer 37 si on ajoute des
  alert_tag. Dashboard : page **ATT&CK** (couverture par tactique, **heatmap**
  tactique x technique, techniques/hotes, severite, score) + **Top hotes/comptes
  par score de risque** sur Direction. ALERTE (dans 13) : "OMNI - Hote a risque
  eleve (score MITRE >=15 /1h)" P2, group_by host, sum(risk_score), 60/5 min,
  notif Teams (helper sum_ge) -> capte un ENCHAINEMENT de detections.
  CSV mitre complete : +defender (T1204.002) +ransomware_indicator (T1486) ;
  couverture MITRE des alert_tag d'ATTAQUE. Tags OPERATIONNELS volontairement NON
  mappes MITRE (hygiene/etat, pas une technique) : cert_expire_parc, vuln_kev,
  vuln_patch, host_go_dark, siem_job_fail (colores mais hors ATT&CK = normal).
  Rapport hebdo (`/usr/local/sbin/omni-weekly-report`) enrichi : section "Menaces
  & risque - MITRE ATT&CK" (helper top_sum : top hotes/comptes par sum(risk_score),
  top techniques/tactiques, detections critiques). Dashboard : table "hotes muets"
  triee `sort_asc` sur latest(timestamp) (DSL sort_on/sort_asc).
- **Gestion des vulnerabilites (facon Wazuh, sans agent dedie)** - choix Julien :
  collecteur PowerShell + KEV/CVSS + anciennete patch.
  * `windows/Get-OmniInventory.ps1` (/kit) : logiciels (registre Uninstall 64/32)
    + OS/build + dernier KB/date -> journal **OMNI-Inventaire** (9101 logiciel,
    9102 OS), format key=value|... . Canal dans winlogbeat.yml. DEPLOIEMENT :
    integre a **Install-OmniSiem-NinjaOne.ps1** (telecharge le script + cree la
    tache quotidienne OMNI-Inventory SYSTEM + 1er inventaire immediat) -> un seul
    lancement NinjaOne suffit. Sinon page Vulnerabilites vide.
  * Pipeline (12) `omni-winother-00-inventory` -> event_source=inventory
    (inv_product/inv_version / os_build/os_last_patch). Stream winother.
  * `/usr/local/sbin/omni-vuln-scan` + `38-vuln-scan.sh` (timer 07:15) : CISA
    **KEV** (~1600 CVE exploitees, cache 7j), matching par mots distinctifs+subset
    (peu de FP : Acrobat 22 / Exchange 18 / vCenter 10), **CVSS** NVD best-effort
    (cache, rate-limit, VULN_NVD_MAX) + **anciennete patch** (VULN_PATCH_MAX_DAYS
    def 35j). GELF event_source=vuln (alert_tag vuln_kev/vuln_patch). Page
    dashboard **Vulnerabilites** (S(INT), page_range 28h). Score integre a Direction.
  * PIEGE GELF : `host` RESERVE (=emetteur->source). Host cible en `_vuln_host`
    -> regle `omni-enrich-20-vuln-host` (pipeline Enrichissement, connecte AUSSI a
    INT) recopie dans `host`. Regle mitre exclut `has_field(vuln_type)` (sinon
    ecrase risk_score). PIEGE DUP : stream M365 avale tout GELF -> double index
    set -> 38 pose regle INVERSEE event_source!=vuln/siem_vuln sur M365.
- **Dashboards DSL ++** : `desc=` (legende widget, champ `description` -> ⓘ),
  highlighting global `COMMON_HL` (rouge/orange par seuil & valeur, 30 regles),
  viz **heatmap** (visualization_config color_scale Viridis). PIEGE : les
  **parametres de dashboard (value-parameter-v1) sont ENTERPRISE** -> marquent la
  vue `requires: Graylog Enterprise` = "missing requirement" en OSS. RETIRES
  (`PARAMS = []`). Drill-down sur la page **Investigation** via la BARRE DE
  RECHERCHE native (query de page, OSS) : taper host:.../user:... filtre tous les
  widgets. DSL `query_string` par page conserve mais non utilise pour parametres.
  19 pages. **4 heatmaps** : Alertes type x heure (DSL `coltime=True` = temps en
  COLONNE), Identite AD compte x hote (spraying), ATT&CK tactique x technique,
  Reseau srccountry x dest_country (deny). DSL `page_range=` (timerange de page) :
  Investigation par defaut 7j. Le selecteur de temps natif Graylog couvre deja le
  besoin de "plage temporelle" interactive (pas de parametre dedie).
  NB decorateurs : peu d'interet en Graylog OSS (le highlighting couvre le besoin
  visuel) -> non implementes volontairement.
  PIEGE confirme : champ event-id Windows = `winlogbeat_winlog_event_id`
  (brut) + `event_id` (normalise) ; PAS `winlog_event_id`. Champ pays
  FortiGate = `srccountry` (src_country=419 = M365 only). Build idempotent.
- **Dashboards v4 (revue coherence/lisibilite, 13/06/2026)** :
  - **Page "Synthese" SUPPRIMEE** (≈80 % redondante avec Direction : memes KPIs +
    aire par source + bar detections + table hotes a risque). Architecture clarifiee
    en 3 niveaux : Direction (pilotage exec) / Alertes+Sante (triage) / pages metier
    (profondeur) + Investigation. **19 -> 19 pages** (Synthese remplacee, pas ajout).
  - **Doublon "groupes privilegies modifies"** retire de *Comptes & conformite*
    (KPI+table) -> remplace par cycle de vie comptes (4725 desactives / 4722 reactives
    / 4726 supprimes) ; reste sur la page dediee *Comptes a privileges*.
  - **2 cartes VPN** (Cartographie vs VPN & Exposition) explicitees comme
    COMPLEMENTAIRES via `desc` (tous acces vs origine des seules attaques portail).
  - **Couche descriptions ⓘ** ajoutee sur tous les KPIs des pages metier (Identite AD,
    M365, Reseau, vSphere, Comptes a privileges/conformite, VPN, Sauvegardes,
    Certificats) : sens du chiffre + ce qu'un pic implique.
- **Octets -> Go/To (lisibilite volumetrie)** : Graylog 7.1.3 OSS **n'a PAS d'unites
  de champ natives** (endpoint `/system/units` = 404, la serie ne porte aucun `unit` ;
  c'est Enterprise/build recent). NE PAS contourner la licence. A la place, conversion
  **figee a l'ingestion** dans `omni-forti-05-octets` (12, stage 5) :
  `bytes_total_gb/sent_gb/rcvd_gb` (Go = /1e9 decimal, convention reseau) + 
  `bytes_total_tb` (To = /1e12), via `to_double(...) / 1e9`. Page Reseau : KPIs totaux
  en **To**, classements par hote/app/dest en **Go** (unite adaptee au contexte).
  Verifie : event 60 octets -> bytes_total_gb=6e-08 (OK) ; 17,5k events enrichis /600s.
  Champs **double** (mapping ES auto, PAS keyword -> sommables). Vaut pour le trafic
  POSTERIEUR a la maj (historique sans ces champs). Build v4 : requires={} (OSS).
- **Dashboards v4.1 (audit data-driven + enrichissement, 13/06/2026)** :
  - **Audit couverture alert_tag** (terms agg OpenSearch 30j vs COMMON_HL vs CSV MITRE,
    script type /tmp/audit_dash.py) : seul `m365_mailbox_deleg` manquait une couleur
    -> ajoutee (ORANGE). `cert_expire_parc` laisse SANS couleur plate volontairement
    (deja colore en GRADUE par cert_days <=30 orange / <=15 rouge). Tags colores/mappes
    "jamais vus" (canary, dcsync, ransomware...) = voulus (pre-armes).
  - **Audit champs morts** : 7 champs sans donnee 30j mais TOUS au bon nom (verifie vs
    emetteurs) -> AUCUN widget retire. `latest(timestamp)`=faux positif (ref serie) ;
    `priv_group_label`/`cert_subject_disp`=rares/PKI (audit AD CS a activer) ;
    `vuln_*`/`patch_age_days`=en attente inventaire. Regle : champ correct + donnee rare
    != widget mort.
  - **Widgets "1re apparition" (baselining)** ajoutes en bas de Hunting : nouveaux hotes,
    nouveaux processus, nouveaux comptes admin, via serie **min(timestamp)** (date,
    sortable ; symetrique de latest()). CAVEAT : "1re apparition" = 1re vue DANS la
    retention (les vieux hotes se groupent au plancher de retention ; le TOP du tri
    descendant = reellement nouveaux). go-dark deja couvert (table Sante collecte) ;
    J/J-1 deja couvert (fleches de tendance dir=) ; SLA % collecte NON fait (exige une
    liste d'actifs attendus / CMDB, non cablee).
  - **Ordre des pages** rendu thematique via cle de tri Python `ORDER[]` (aucun bloc
    deplace, robuste) : Direction, Alertes, ATT&CK, Sante collecte, Identite AD,
    Comptes a privileges, Comptes & conformite, M365, M365 Activite, Endpoint, Hunting,
    Reseau, VPN & Exposition, Cartographie, vSphere, Sauvegardes, Certificats,
    Vulnerabilites, Investigation. Garde-fou : pages hors ORDER -> fin + warning.
  - Couche ⓘ etendue a 100% des KPIs (Alertes, M365 Activite, Hunting, Cartographie,
    Endpoint restants). Build v4.1 verifie : requires={}, 19 onglets, min(timestamp) OK.
- **Supervision de collecte / SLA + go-dark (39-collect-health.sh, 13/06/2026)** :
  Nouveau collecteur `/usr/local/sbin/omni-collect-health` (pattern omni-vuln-scan) :
  derive le parc "gere" du baseline (hote vu < COLLECT_MANAGED_DAYS=14j), calcule
  last_seen par hote (max timestamp sur indices a AGENT : windows/sysmon/winother/
  fortigate/vsphere ; EXCLUT M365 cloud + interne), go-dark = muet > COLLECT_GO_DARK_HOURS
  =26h, couverture = actifs24h/geres*100. Emet GELF event_source=collecte_sla :
  1 event sla_type=summary (sla_coverage_pct/expected/active_24h/go_dark) + 1 par hote
  sla_type=go_dark (alert_tag=host_go_dark, champ **dark_host**, hours_silent, last_seen).
  Timer horaire (minute 07). 1er run reel : geres=72, couverture=100%, go-dark=0.
  PIEGES rencontres :
  - load_env (regex `[A-Z_]+=(.*)`) NE strippe PAS les commentaires EN LIGNE -> mettre
    les commentaires de 00-vars.env sur une ligne SEPAREE (sinon float("26' # ...") KO).
  - stream "OMNI - Interne SIEM" ecrit dans l'INDEX SET PAR DEFAUT (graylog_0), pas un
    omni-* -> chercher par STREAM, pas par index `omni-*`. Routage : regle OR
    event_source=collecte_sla sur INT (39) + exclusion inverse sur M365 (anti-dup).
  - regle de stream fraichement creee : ~qq s de propagation avant routage effectif
    (le 1er scan immediat de 39 peut atterrir en Default seul ; les suivants OK).
  - enrich MITRE (37) : ajout `AND NOT has_field("sla_type")` (sinon champs mitre_*
    VIDES poses sur go-dark -> pollueraient ATT&CK car ""="exists" en ES).
  Dashboard : section "Couverture collecte (SLA)" sur Sante collecte (stream INT ajoute) :
  KPI couverture% (latest, dir=HIGHER) + geres/actifs/go-dark + table+messages go-dark
  (range 7200s = dernier passage, evite les hotes recouvres). host_go_dark ORANGE.
  Alerte 13 : "OMNI - Hote go-dark (>26h)" P2, group_by dark_host, count>=1, within90/
  every60 min. ANTI-TEMPETE : la sync globale de 13 force grace par priorite (P3=10/P2=30
  min) -> exception `case *go-dark*) GRACE=21600000` (6h) pour condition PERSISTANTE.
  Helper ensure_event : 10e arg optionnel grace_min (defaut 10). RESTE : SLA base sur
  baseline glissant (pas une CMDB) -> un hote jamais branche n'est pas "attendu".
- **Couche UEBA / NDR "au-dela de Graylog" (40-ueba-ndr.sh, 13/06/2026)** : 4 collecteurs
  /usr/local/sbin (pattern GELF->INT->enrichi), calculant ce que l'agregation Graylog
  ne sait pas. Garde-fou commun : env `UEBA_DRY=1` = calcul sans emission (test).
  - **omni-ueba-volume** : anomalie de volume par event_source, z-score sur baseline
    MEME-HEURE-DU-JOUR (date_histogram 1h, groupe par heure-du-jour en Python). alert_tag
    volume_spike (z>=4) / volume_drop (z<=-3, mean>=50). LIMITE : retention courte
    (~1-5 j selon source -> MIN_SAMP=3) ; FP pendant l'onboarding (croissance legitime) ;
    s'ameliore quand l'historique grandit (remonter UEBA_VOL_MINSAMP a 7-14).
  - **omni-ueba-geo** : impossible travel. Haversine entre 2 connexions consecutives
    (M365 signin + VPN, champ user) ; vitesse>UEBA_GEO_SPEED(900km/h) & dist>500km.
    Geoloc = src_ip_geolocation/remip_geolocation "lat,lon" (centroide PAYS -> conservateur,
    intra-pays=0). alert_tag impossible_travel. Verifie : Paris->NY 1h=5837km/h leve,
    Paris->Bordeaux 3h=166km/h non leve.
  - **omni-ndr-beacon** : beaconing/C2. Couples src INTERNE->dest EXTERNE (booleens
    src_ip_reserved_ip/dest_ip_reserved_ip), composite agg, puis CV (ecart-type/moyenne)
    des intervalles inter-connexion ; balise = CV<=0.25 & intervalle median 15-3600s.
    PERF : allowlist de prefixes (DNS/MS/Google/CF, NDR_ALLOW_PREFIX) appliquee AVANT le
    fetch timestamps -> 3min->10s (×18) et 11 FP -> 3 candidats. alert_tag beaconing.
    HONNETE : le SaaS legitime "bat" aussi -> exposition a trier (etendre l'allowlist).
  - **omni-ueba-score** : score d'entite UEBA 0-100 (hote ET compte), saturation douce
    100*(1-exp(-raw/K)), K=20. Facteur DETECTIONS = somme du max(risk_score) PAR alert_tag
    DISTINCT (severite-diversite, PAS le volume -> sinon tout sature a 100). + go-dark
    (W=15, hote), beaconing (W=12, par src_ip), authfail (compte). PIEGE double-comptage :
    impossible_travel est dans le CSV MITRE -> alimente deja 'detections' via user ->
    PAS de poids geo separe. Verifie : distribution hotes 18-83 (discriminante).
  Les 4 alert_tag (volume_spike/drop, impossible_travel, beaconing) AJOUTES au CSV MITRE
  (37) -> risk_score + technique (T1048/T1562.001/T1078/T1071) + page ATT&CK + facteur
  detections UEBA. CSV recharge auto sous 60s (check_interval adapter). ueba_score n'a PAS
  d'alert_tag (porte ueba_score) -> non enrichi (normal). Routage 40 : 4 event_source -> INT
  (OR) + exclusion M365 (anti-dup). 4 timers echelonnes (volume horaire, geo/score 30min,
  beacon 6h). Dashboard : page "UEBA / NDR" (pos 4, apres ATT&CK ; 20 pages) ; fenetres
  COURTES (2100s score, 25200s beacon) = dernier passage (evite les doublons des runs).
  COMMON_HL : impossible_travel/beaconing ROUGE, volume_* ORANGE, ueba_score>=40 orange/
  >=70 rouge (ORANGE avant ROUGE = precedence). Alertes 13 : impossible_travel P3,
  beaconing/UEBA(>=80) P2, volume P3 ; toutes en anti-tempete 6h (exception sync etendue
  *go-dark*|*Impossible*|*Beaconing*|*Anomalie de volume*|*UEBA* car re-emises a chaque cycle).
  Helpers 13 : max_series/max_ge ajoutes.
- **Retention ISO 27001 / capacite (41-retention-iso.sh, 13/06/2026)** : analyse capacite
  + tiered retention. MESURE : ~29 Go/jour SUR DISQUE (compresse, 0 replique, mono-noeud) ;
  repartition fortigate 13 (45%) / winsec 7.5 / sysmon 4.9 / winother 2.7 / vsphere 0.6 /
  m365 0.02. Disque /data = 7,3 To utiles, garde-fou disk-guard a 80% -> plafond ~5,8 To.
  CORRECTION : la retention N'ETAIT PAS a 4j -> index sets deja en TimeBased P1D + retention
  180-365j ; les ~4j visibles = SIEM JEUNE (~5j). VRAI risque ISO : a 29 Go/j la politique
  consommerait ~7 To > 80% -> disk-guard purgerait avant terme -> retention affichee NON tenue.
  ISO 27001 A.8.15 : PAS de duree fixe imposee -> politique risque-based documentee + tenue +
  integrite. SOLUTION (tenue dans 5,8 To) : (1) TRIM pipeline stage 30 (APRES detection) :
  drop Sysmon EID12 (registre add/del, 62% sysmon ; persistance=EID13 conserve), winsec 4673
  (priv use) + 4627 (group membership, redondant 4624). GARDE 4662 (DCSync) + 4688 (process).
  Verifie en prod : EID12/4673/4627 -> ~0 indexe, EID1/4624 -> OK. (2) RETENTION tiered :
  securite (winsec/sysmon/winother/m365/vsphere) -> 365j, fortigate -> 90j (trafic, fenetre
  forensic suffisante). Projection ~5,1 To = dossier securite 12 mois dans les 80%. (3) preuve
  d'audit -> docs/POLITIQUE-RETENTION.md (mappe A.8.15/16/17, exclusions risque-acceptees).
  PIEGE evite : PAS de codec best_compression via template ES (casserait les mappings Graylog
  des index sets composables) -> non fait, le trim+tiering suffit. set_retention() = GET index
  set + jq max_number_of_indices + PUT. Reversible (retirer regles = restaure collecte).
  RESTE : pour gagner encore, fortigate 90->60j, ou split index set securite/trafic, ou +disque.
- **Carte cyber temps reel (42-carte-cyber.sh / omni-geo-flux, 13/06/2026)** : arcs de flux
  ANIMES source->entreprise (hors Graylog : sa world-map ne fait que des points). Generateur
  /usr/local/sbin/omni-geo-flux agrege sur fenetre glissante (GEO_FLUX_WINDOW_MIN=10) les flux
  securite geolocalises : deny FortiGate (src_ip_geolocation "lat,lon" + srccountry), threat_intel,
  m365_etranger, attaques portail VPN (remip_geolocation) ; regroupe par (lat,lon arrondis 0.5) +
  type -> arcs (top GEO_FLUX_MAX=160) -> /var/www/siem-kit/flux.json. Page canvas pure (zero lib,
  100% local, pas de CDN/fuite) /var/www/siem-kit/carte-cyber.html : projection equirectangulaire,
  fond carte-world.geojson (177 pays, telecharge 1x), arcs Bezier quadratiques + impulsions mobiles,
  thème SOC, HUD live, refresh 30s. Servi par nginx /kit/ (deja en place, STATIQUE SANS AUTH ->
  ajouter auth_basic si juge sensible). HQ = GEO_HQ_LAT/LON/NAME (Bordeaux 44.88,-0.55). Timer
  omni-geo-flux 30s (OnUnitActiveSec). URL : https://<fqdn>/kit/carte-cyber.html. Verifie : nginx
  200 sur les 3 fichiers, contrats geojson/flux.json OK (1er run : 110 flux, 37 pays, 2390 deny/10min).
  Apercu statique reproductible en SVG pur (sans navigateur/lib) si besoin de capture.
- **Exfiltration / tunneling DNS (43-ndr-dns.sh / omni-ndr-dns, 13/06/2026)** : detecteur NDR
  (au-dela de Graylog : entropie de Shannon + structure des sous-domaines). Sur Sysmon EID22
  (dns_query, 448k/24h) : terms agg (size 40000) sur fenetre NDR_DNS_WINDOW_H=6h -> regroupe
  par eTLD+1 (approx 2 labels, 3 si co.uk/com.au...) -> par domaine : nb sous-domaines distincts,
  entropie moyenne, longueur moyenne. Flag si distinct>=40 ET entropie>=3.6 ET longueur>=20 (tune
  NDR_DNS_*). Allowlist (NDR_DNS_ALLOW) : in-addr.arpa/ip6.arpa (reverse), domaine AD interne,
  CDN/cloud (googlevideo/azure/cloudfront/akamai/office/apple...). Attribution hote via wildcard
  dns_query *domaine + terms host. Emet event_source=ndr_dns alert_tag=dns_tunneling (entity_host,
  dns_domain, dns_distinct_sub/avg_entropy/avg_len). Mappe MITRE T1071.004 (DNS) score 8 (CSV).
  CALIBRE : 208 domaines, 0 FP meme seuils relaches (apres allowlist, domaines legit = peu de
  sous-domaines courts/bas) ; tunnel synthetique base32 (120 sous-dom) entropie 4.18 len 32 ->
  DETECTE. entropy('wwwmailapi')=2.45 vs base32=3.8. Routage INT + exclusion M365. Timer horaire.
  Dashboard : 2 widgets page UEBA/NDR (table domaines suspects + detail hote). Alerte 13 : P2
  group dns_domain, anti-tempete 6h (case grace etendu *Tunneling*). COMMON_HL dns_tunneling ROUGE.
- **Correlation attack-chain -> incidents (44-incidents.sh / omni-incident-correlate, 13/06/2026)** :
  agrege par ENTITE (host/user) les detections MITRE d'une fenetre (INCIDENT_WINDOW_H=24h) et
  reconstruit la KILL-CHAIN ordonnee (ordre canonique ATT&CK CHAIN[]). Incident = >=2 tactiques
  distinctes. Score sature 0-100 (K=30) = somme max(risk_score)/tactique + 3*(diversite-1).
  Emet event_source=incident (incident_entity, incident_score/severity/tactics/kill_chain/
  techniques/first_seen/last_seen/span_h). Nested agg : terms entity -> terms mitre_tactic ->
  max risk_score + min/max timestamp + terms technique/alert_tag. Verifie : BX-VEEAM-IT-SV
  critique 70 = Execution->Defense Evasion->Credential Access->Impact(T1490 ransomware) ; 28
  incidents. PAS de mapping MITRE (pas d'alert_tag -> non enrichi). Route INT (graylog_0). Timer
  15min. Dashboard : PAGE "Incidents" (ORDER pos 3, apres Alertes ; 21 pages) - KPIs + table +
  pie + messages narratifs. COMMON_HL incident_severity/score. Alerte 13 P3 group incident_entity,
  grace 6h (case *Incident*). Inclut les detections NDR/UEBA (deja mappees MITRE) dans les chaines.
- **Rapport executif mensuel PDF (45-monthly-report.sh / omni-monthly-report, 13/06/2026)** :
  HTML auto-suffisant calibre A4 (@page) -> VRAI PDF via weasyprint. PDF ENGINE : wkhtmltopdf
  INDISPONIBLE Debian 13 ; pas de pip/pango par defaut -> installe `apt python3-pip python3-venv
  libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0` + venv /opt/omni-venv avec
  weasyprint 69 (CLI appelee en subprocess : weasyprint in.html out.pdf). Sections : posture 30j
  (KPI cards), incidents kill-chain, carte SVG menaces 30j (threat_map_svg, reutilise le fond
  carte-world.geojson + deny geolocalises), top UEBA hotes/comptes, couverture ATT&CK, sante/
  conformite/capacite. PIEGE : incident/ueba/collecte_sla/vuln sont dans graylog_0 (index defaut
  du stream INT) PAS omni-* -> tri sur incident_score donnait HTTP 400 (No mapping) ; corrige en
  ciblant INT_IDX="graylog_0". Archive /var/www/siem-kit/rapports/rapport-AAAA-MM.{html,pdf}
  (servi /kit/rapports/, nginx 200). Email mensuel (1er du mois 06:00) PDF en piece jointe (SMTP
  REPORT_*). REPORT_NOMAIL=1 = generation sans envoi (test). Verifie : PDF 51 Ko valide v1.7.
- **Polish v5 (coherence/lisibilite/pedagogie, 13/06/2026)** : audit data-driven re-passe
  (alert_tag couleur+MITRE, champs morts sur omni-*,graylog_0) -> AUCUNE incoherence : les
  champs "vides" (dark_host/dns_*/hours_silent/priv_group_label/cert_subject_disp) ont le bon
  nom, 0 doc = evenement rare/absent (couverture 100%, pas de tunnel...). Direction ELEVEE en
  cockpit exec : 2 KPIs de niche (M365 hors France, Certs<15j) remplaces par "Incidents
  critiques" (event_source:incident, card incident_entity, range 1200) + "Entites a risque UEBA
  >=70" (range 2100) -> mene avec le RISQUE CORRELE. Allegement Reseau (20->18 widgets) : retrait
  triage VPN (redondant page VPN) + pie "Repartition actions" (redondante avec l'aire, aire
  elargie 8->12) + heatmap remontee row 23->19. PIEGE : pas de widget TEXTE/markdown en Graylog
  OSS -> pas de bandeau explicatif par page ; l'explicatif passe par desc ⓘ + GUIDE.md.
  **GUIDE.md** (racine + /kit/docs/) : doc langage-clair "comprendre le SIEM en 15 min" pour
  TOUT lecteur (direction/audit/nouvel arrivant) - schema de flux, role de chaque page, analyses
  expliquees simplement, liste des robots/timers, priorites d'alerte, routine matinale,
  GLOSSAIRE (LSASS/DCSync/beaconing/UEBA/KEV/entropie...). Build : 21 pages, requires={}.
- **Auto-supervision (46-self-health.sh / omni-self-health, 13/06/2026)** : "qui surveille les
  surveillants" - verifie via systemd (LoadState/Result/ExecMainExitTimestampMonotonic vs uptime)
  que les ~13 robots ont tourne+reussi recemment. Emet siem_health (summary + job_fail/alert_tag
  siem_job_fail). Widget Sante collecte + alerte 13 P3. Verifie : 9/9 OK.
- **Revue MULTI-AGENT + corrections (workflow siem-review-enrich, 13/06/2026)** : 7 agents en
  parallele (collecteurs analytiques/ops, dashboard, alertes/pipeline, deploiement, frontend,
  coherence transverse) -> trouvailles VERIFIEES de facon adverse contre fichiers+live -> 22
  confirmees. CORRIGE : #1(HIGH) omni-vuln-scan KEV emettait `host` (reserve GELF, perdu) au lieu
  de `vuln_host` -> 0/322 KEV avaient host -> KPIs KEV + rapport a 0 ; fix `vuln_host` (la regle
  37 recopie -> host). VERIFIE : 59/59 KEV frais ont host. #2 omni-collect-health IDX `omni-windows*`
  (index inexistant) -> `omni-winsec*` (winsec etait exclu du SLA). #3/#7/#13 carte : reprojection
  des arcs au resize (projectFlows()), demarrage INCONDITIONNEL + fond de repli si geojson KO,
  echappement XSS du nom de pays. #4 omni-ueba-score : facteur beacon keye par IP jamais applique
  -> IP beacon ajoutees comme entites. #5 dashboard : widgets "Evenements Graylog correles" (requete
  vide=tout le volume, trompeur) RETIRES. #6 alertes : key_spec vide -> grace anti-tempete GLOBALE ;
  fix = generer key_spec+field_spec(template ${source.<cle>}) depuis group_by dans la sync de 13
  (Graylog DEPOUILLE key_spec sans field_spec) -> 21/21 alertes agregees ont grace PAR ENTITE.
  #10 rapport mois en FR (MOIS_FR). #11 46 bloc M365 `&&||&&` (message faux) -> if/else. #15 doc
  CONTEXT "100% MITRE" corrigee (tags operationnels non mappes = normal). #17 self-health faux
  positif post-reboot (age=uptime si jamais tourne). #19 geo-flux type pays = DOMINANT (pas le 1er).
  #20 omni-ndr-dns attribution DNS frontiere de label (term reg OR *.reg). #21 rapport SVG ring[::2]
  +fill-rule evenodd. #22 threatintel +CGNAT 100.64/10 +link-local 169.254/16. #12 warn M365 absent
  dans 43/44. NON corrige (faible/sans impact) : #8 ueba-geo IPsec (0 resultat live), #9 brute-force
  VPN action ssl-login-fail (a verifier cote FAZ), #14 beacon SKIP_PORTS, #16 parse ts (differences
  annulent le decalage), #18 carte frame-rate. Build final dashboard : 21 pages, requires={}.
- **Corpus documentaire ISO 27001 (docs/, 13/06/2026)** : 6 documents support (FR, servis
  /kit/docs/) pour permettre la generation ulterieure des docs SMSI formels. INDEX-DOCUMENTATION.md
  (point d'entree + checklist de preparation ISO), ISO27001-MAPPING.md (PONT capacites SIEM <->
  Annexe A 2022 : A.8.15/16/17, A.5.7/24-28, A.8.7/8/12/13, A.5.23... + emplacement des preuves),
  REGISTRE-DETECTIONS.md (54 regles par domaine+MITRE+prio, factuel via API), INVENTAIRE-SOURCES.md
  (7 sources, volume/retention/criticite), PROCEDURE-INCIDENT.md (A.5.24-28), PROCEDURE-EXPLOITATION-
  SIEM.md (routine quoti/hebdo/mensuelle, 13 robots, capacite). Donnees reelles : 54 alertes (35 P3,
  19 P2), 7 streams. A faire cote user : approbation RSSI + SoA + revue de direction.
- **Passe 2 multi-agent : fixes + nouvelles detections (13/06/2026)** : 12 fixes confirmes
  + 14 enrichissements faisables. APPLIQUE : #1/#4(HIGH) 5 event_source internes (siem_backup/
  disk_guard/report/soar/cert) routes vers INT mais JAMAIS exclus de M365 -> double-indexation
  (14 docs fuites). Fix : exclusions M365 live + dans 21-alert-hygiene.sh (purge differee = perm
  classifier). #2(HIGH) + #7/#8/#10 + OAuth = 47-detections-extra.sh : 5 detections (pipeline
  dedie stage 10) gpo_modification(T1484.001 ; filtre SID!=S-1-5-18 SYSTEM = editions HUMAINES),
  asrep_roasting(T1558.004 ; 4768 PreAuthType==0), lolbin_suspect(T1218 ; certutil urlcache/
  regsvr32 scrobj/rundll32 js/mshta/bitsadmin), persistence_autorun(T1547.001 ; Sysmon13 Run -
  TAG SEUL pas d'alerte car ~85/j installeurs legitimes), m365_oauth_consent(T1528). +alertes 13
  (GPO/AS-REP P3, LOLBin/OAuth/M365-mass-delete P2). Champs VERIFIES en live avant. #3 Veeam :
  niveaux FR (erreur/avertissement) + message warning (OS francais, == "error" etait mort). #11
  Direction tooltip "Comptes echec" = AD+M365 (pas VPN). COMMON_HL +5 tags. BUG LATENT corrige :
  ensure_event posait key_spec:$gb SANS field_spec -> Graylog REFUSE toute nouvelle alerte agregee ;
  fix = generer field_spec(template) depuis group_by aussi a la CREATION (pas que dans la sync).
  Total 59 alertes. NON encore fait : #5/#6 cert SANs/multi-cert, #9 nommage entite canonique,
  #12 SYSVOL creds, + enrichissements (scan reseau, off-hours, NTLM/Kerberos, M365 failure codes,
  est-ouest lateral, masquerading/hash). Dashboard 21 pages requires={}.
- **Enrichissement : detection de scan reseau (48-ndr-scan.sh / omni-ndr-scan, 13/06/2026)** :
  detecte balayage HORIZONTAL (card dest_ip >= SCAN_HOST_MIN=30) / scan VERTICAL (card dest_port
  >= 25 sur <= 3 hotes) depuis sources INTERNES (src_ip_reserved_ip:true) sur deny FortiGate,
  fenetre SCAN_WINDOW_M=60. Cible le lateral/reco interne (pas le scan Internet entrant constant).
  Emet event_source=ndr_scan alert_tag=network_scan (entity_host, scan_type, dest/port count).
  MITRE T1046. Timer 15min, auto-supervise. Alerte 13 P2 (grace 6h, *Scan*). Widget UEBA/NDR +
  COMMON_HL orange. Verifie : 4 scans internes reels (10.13.50.5=35 dests...), enrichi T1046 score5.
  PIEGE NOTE : les collecteurs lisent 00-vars.env (load_env) PAS os.environ -> les overrides par
  var d'env shell sont IGNORES (tester via importlib + override des globals du module, ou editer
  le fichier). Seul UEBA_DRY est lu via os.environ (dans gelf()).
- **Lots 1+2 enrichissements multi-agent (49-enrich-lots.sh + 14/13, 13/06/2026)** : 10 enrichissements
  concus par agents (design parallele, champs verifies live), consolides+appliques par le main loop
  (agents read-only -> pas de conflit). PIPELINE (49, idempotent, ensure_lookup canonique en en-tete) :
  off_hours/day_period (3 regles base+override sur 4624/4625/m365 signin ; to_date($message.timestamp)
  OBLIGATOIRE car timestamp=Object ; format_date(...,"HH"/"e","Europe/Paris") ; pas de if/else) ;
  account_class/is_admin (base+override : user/machine($)/service(svc/MSOL_/vpxuser)/admin(adm-) ;
  verifie : user 6453/machine 2837/admin 465/service 151) ; masquerading T1036.005 (Sysmon EID1 binaire
  systeme hors System32) + explicit_cred_use T1078 (4648) -> ajoutes au pipeline Detections complementaires ;
  forti_severity_num (lookup forti-severity.csv level->num + regle stage 5 -- A BRANCHER dans PL_FORTI de 12,
  fait) ; m365_fail_label (lookup m365-status.csv status_code->libelle FR + regle ; arme, 0 tant qu'aucun
  echec) ; port_class (lookup port-class.csv) + net_direction (cidr_match car reserved_ip pose par GeoIP
  APRES pipelines -> indispo en regle ; 3 regles interne/sortant/entrant via src_priv/dst_priv) + expo_internet
  T... (entrant+accept+port a risque). DASHBOARD (widgets ECRITS PAR LE MAIN LOOP, pas les agents dont le
  code etait incoherent/mal ancre) : est-ouest lateral (Reseau), NTLM vs Kerberos + off-hours admin (Identite
  AD), account_class pie + activite admin (Comptes a privileges), echecs M365 par cause (M365). COMMON_HL
  CURATED (signaux forts only : masquerading/explicit_cred/exposition_internet/off_hours/expo_internet/NTLMv1/
  m365_fail_label ; DROP service/port_class/admin/NTLM-tout = trop bruyant). Alertes 13 : admin hors-heures P3,
  masquerading P2, explicit-cred P2. PIEGES : agents mettent parfois du code dashboard dans shell_blocks
  (filtrer), echappent \$( a tort (casse subst), supposent helpers de 47 (add_mitre/CSV/WD -> en en-tete),
  if/else interdit pipeline (l'agent l'a quand meme utilise -> reecrire en base+override), starts_with/regex 3-args
  rejetes (simplifier). Verifie : 5/5 champs pipeline peuplent ; 63 alertes ; requires={}.
- **Lot 3 enrichissements multi-agent (50-enrich-lot3.sh, 13/06/2026)** : 5 detections de profondeur,
  consignes durcies aux agents -> ZERO piege (pas de if/else, 3-args, dash-in-shell). Les agents ont
  meme ECRIT 2 collecteurs directement via Bash (bonne qualite). DETECTIONS PIPELINE (pipeline dedie
  "OMNI - Detections Lot3" stage 10, winsec) : gpp_creds_access T1552.006 (5145 SYSVOL + groups.xml/
  scheduledtasks/services/datasources.xml) ; kerberos_rc4 T1558.003 (4769 TicketEncryptionType==0x17
  RC4, ServiceName non-machine non-krbtgt ; live=AES256 0x12 only -> arme) ; local_admin_add T1098
  (4732 TargetSid S-1-5-32-544 builtin local ; live 4732=0 -> arme) ; local_account_create T1136.001
  (4720 hors DC). COLLECTEURS (agents) : omni-ndr-exfil T1048 (multi_terms src interne/dest externe,
  sum bytes_sent > EXFIL_BYTES_GB=1Go/fenetre ; egress SIEM 160.79.104.10 dans EXFIL_ALLOW_DEST=>0 FP ;
  arme) ; omni-ueba-geo-newcountry T1078.004 (nouveau pays/compte vs baseline 30j ; reutilise routage
  ueba_geo ; alert_tag=new_country ; 0 actuel). MITRE CSV : 2 lignes agent MALFORMEES (desc en colonnes)
  -> reecrites correctement dans 50. 6 alertes 13 (exfil/local-admin/local-create P2 ; gpp/rc4/new_country
  P3 ; kerberos_rc4 count_ge 5 anti-bruit). COMMON_HL +6. Widget exfil sur UEBA/NDR. 2 collecteurs ->
  self-health (12/12 OK). + Fix cert SAN (omni-cert-renew : FQDN+nom court+IP au CSR, CERT_SAN_IP
  surchargeable). Total 69 alertes, requires={}. Collecteurs lisent maintenant os.environ EXFIL_* (override).
- **Lot 4 enrichissements multi-agent (51-enrich-lot4.sh, 13/06/2026)** : 5 detections AD/identite
  avancees, consignes durcies -> 0 piege (agents). PIPELINE "OMNI - Detections Lot4" : wmi_lateral_exec
  T1047 (sysmon EID1 parent wmiprvse->LOLBin + EID19/20/21 WmiEvent ; exclusions SCCM/monitoring) ;
  shadow_credentials T1556.005 (5136 AttributeLDAPDisplayName=msDS-KeyCredentialLink, acteur !=S-1-5-18) ;
  adcs_abuse T1649 ESC1 (4886/4887 event_source=adcs, SAN non-vide via negation signature texte + @) +
  ESC8 (AuthenticationService=NTLM) au stage 11 (apres adcs base stage 10). COLLECTEURS (agents) :
  omni-ldap-recon T1087.002 (pic d'acces annuaire 4662 par compte) ; omni-ndr-lateral T1021 (1 compte ->
  N hotes en 4624 type3/10 reussis). Toutes ARMEES (0 donnee = pas d'attaque). PIEGES : 2 lignes MITRE
  agent malformees (reecrites) ; regle WMI refusee car `NOT lowercase(x) == "y"` (precedence : NOT lie la
  String avant ==) -> corrige en `!= "y"`. L'agent AD CS a detecte le PIEGE faux-positif FortiGate VoIP
  (champ event_id=4887/4889 parasite dans omni-fortigate) -> scope STRICT event_source==adcs. 5 alertes
  (AD CS/Shadow/LDAP P3, WMI/lateral P2). COMMON_HL +5. 2 collecteurs -> self-health (14/14 OK). Total
  74 alertes, requires={}. La QA des lots 1-3 (workflow) a echoue 2x sur limite de session -> a relancer.
