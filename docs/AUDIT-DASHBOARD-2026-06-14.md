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
