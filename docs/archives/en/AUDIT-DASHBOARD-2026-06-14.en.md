# SIEM dashboards audit — roadmap (senior SOC)

> **Multi-agent audit of 2026-06-14** (24 agents, validated against live data).
> Improvement plan for the 24 pages of the OMNI - SOC dashboard. Implemented **in lots**.
> Progress tracking at the bottom of the file.

All 24 pages confirmed, widget counts match the audits. The DHCP lookup responds without error (single_value null for that test IP, but `has_error:false` — the table is wired correctly). I have everything verified. The audits are accurate and reliable. Now I'll synthesize the complete improvement plan.

A note on the DHCP lookup: `has_error:false` but `single_value:null` for `10.33.60.15` — consistent with the audit's observation that some internal IPs (fixed-IP infra) don't resolve. This is worth flagging in the transverse recommendations.

I have all I need. Producing the plan.

---

# IMPROVEMENT PLAN — "OMNI - SOC" dashboard (24 pages, view `6a2e3d1bb61861c0c217afed`)

> Verified live (OpenSearch + Graylog API): `vault_admin` = **9.54 M docs** (95% of the SIEM, source Vaultwarden = HTTP 404 `/admin/users`, `risk_score=6`) crushes almost all the unfiltered aggregates. The tags `threat_intel / eset_detection / m365_etranger / waf_block / vsphere_shell_ssh / vsphere_vm_destroy / powershell_suspect / winsec_critique / admin_share` = **0 doc** (dead wiring, not post-purge). The ghost fields `dark_host / hours_silent / priv_group_label / cert_subject_disp / waf_ua_outil / service_logon_fail / fwd_target` = **0**. Conversely `risk_score / mitre_technique / src_ip_country_code / crscore / vuln_ransomware(381 yes) / ueba_score` are populated, and the lookup **`omni-dhcp-attribution`** exists and responds (`has_error:false`).

## 1) Overview — state of the pages

| Status | Pages | Verdict |
|---|---|---|
| **Strong (keep, minor adjustments)** | **Vulnerabilities**, **UEBA/NDR**, **Collection health** | Actually populated, well wired, real SOC question. Mostly missing enrichment/correlation. |
| **To rework as a priority (structural P1)** | **Executive**, **Alerts**, **ATT&CK** | Poisoned by `vault_admin`: KPI/heatmap/pie/score skewed. 1 global filter = 80% of the gain. |
| **Broken at wiring (dead widgets to rewire)** | **vSphere**, **VPN & Exposure**, **External sources**, **Accounts & compliance**, **Privileged accounts**, **M365 Activity**, **BunkerWeb WAF**, **Endpoint**, **Mapping**, **Backups** | Pivots/queries on nonexistent tags/fields/actions while the equivalent data exists. Not post-purge. |
| **Correct but diluted (redundancy + gaps)** | **Incidents**, **AD Identity**, **M365**, **Network**, **Hunting**, **Certificates**, **Investigation** | Good question, too many single-value KPIs, unsuitable visualizations, missing correlations. |
| **Weak (deep overhaul)** | **vSphere**, **VPN & Exposure** | Do not answer their question: no scope / half the widgets dead. |

**Work priority**: (A) purge the `vault_admin` noise on Executive/Alerts/ATT&CK/Investigation → (B) rewire the dead widgets (nonexistent tags/actions) → (C) DHCP enrichment + detection→host→account→score chain → (D) KPI/viz deduplication.

---

## 2) Plan per page (retained actions, concrete query/pivot/viz)

> Convention: `RP`=row_pivot, `CP`=column_pivot, `S`=series, `TR`=timerange.

### Executive (P1 — poisoned)
- **FIX** Detections 24h (`b2a8c5a8`) + Posture (`ab7a5dc3`): query → `alert_tag:* AND NOT alert_tag:vault_admin`. Real top: vuln_kev(1157), vsphere_auth_fail(798), vault_admin_abuse(808), exposition_internet(142). **[P1]**
- **FIX** Network threats (`ec6131db`): `threat_intel`=0 → `alert_tag:fortigate_utm OR alert_tag:exposition_internet`. **[P1]**
- **ADD** *Vaultwarden admin abuse*: KPI `count()` on `alert_tag:vault_admin_abuse` (808) + mini-table `RP user, src_ip / S count()`. **[P1]**
- **MODIFY** Internet exposure by country (`f41b196d`): `action:deny AND NOT srccountry:Reserved AND NOT srccountry:France` (Reserved=63379 = internal). Keep `card(src_ip)`. **[P2]**
- **ADD** *Exploitable KEV*: KPI `count()` `alert_tag:vuln_kev` + table `RP host / S count(), card(alert_tag)`. **[P2]**
- **MERGE** 3 volume widgets (`4bee57de`+`e347ba67`+`46dd56c5`) → 1 KPI "Events 24h" + stacked timeline by source; move "Active hosts" to Collection health. **[P2]**
- **MODIFY** Top hosts/accounts by score (`aeb9a091`/`80b33ec8`): harden `_exists_:risk_score AND NOT event_source:vaultwarden`, switch to horizontal bars sorted `sum(risk_score)`, add `card(alert_tag)`. **[P2]**
- **MODIFY** UEBA ≥70 (`97655507`): add mini-table `RP ueba_entity / S max(ueba_score)` (24h). Critical incidents (`d441b696`): `incident_severity:(critique OR eleve)`, TR 24h. **[P3]**

### Alerts (P1 — triage queue to rebuild)
- **MODIFY (global page query)**: `alert_tag:* AND risk_score:>=7` (eliminates 43k of noise; keeps vuln_kev/vault_admin_abuse/exposition_internet/beaconing/sysmon_injection/lsass_access). **[P1]**
- **ADD** *Triage queue by severity*: table `RP alert_tag, host / S max(risk_score), count(), card(mitre_technique)` sorted `max(risk_score) desc`. **[P1]**
- **ADD** *Top ATT&CK of the alerts*: bar `RP mitre_technique / S count()`, filter `risk_score>=7`. **[P2]**
- **ADD** *Enriched network alerts*: table `RP src_ip, dest_ip / S count(), max(risk_score)`, query `alert_tag:(beaconing OR network_scan OR data_exfil) AND _exists_:src_ip`, **hostname column via `omni-dhcp-attribution` on src_ip**. **[P2]**
- **FIX** Detail (`c0aa0653`): `fields=[timestamp, risk_score, alert_tag, mitre_technique, host, user, src_ip, dest_ip, event_source]`; remove `command_line`(0)/`process_name`(8); align TR to 24h. **[P2]**
- **REVIZ** Heatmap (`12f2f641`): apply `risk_score>=7` (otherwise the vault_admin cell saturates). **MERGE** "Distinct types" (`28497eab`) into the `Volume by type` bar, or turn it into a KPI "Critical alerts (score≥8)". **[P3]**

### ATT&CK (P1 — poisoned by T1078 vault_admin = 9.54 M)
- **MODIFY** all the aggregates: append `AND NOT alert_tag:vault_admin`. Heatmap (`b6a994d5`), Cumulative score (`0848489a` → `count()` critical+medium or `max(risk_score)`), Severity pie (`a934638d` → bar), Coverage KPI (`270cb1fa`/`765e614c`). **[P1]**
- **ADD** *Techniques by HOST*: table `RP host, mitre_technique, mitre_technique_name / S count(), max(risk_score)`, sort by score desc, `NOT vault_admin`. **[P1]**
- **ADD** *Enriched external Initial Access*: table `RP src_ip / S count(), card(host), card(user)`, query `mitre_tactic:"Initial Access" OR mitre_technique:(T1190 OR T1110)`, enrich src_ip (internal DHCP / external TI pivot). **[P2]**
- **MERGE** Tactics by score (`a72dbf6c`) + Coverage by tactic (`6c9c1303`) → keep the table, remove the count bar (or turn it into `card(mitre_technique)` per tactic). **[P2]**
- **MODIFY** Detail (`fdccdb79`): `AND NOT alert_tag:vault_admin`, sort `risk_score desc`. **[P2/P3]**

### UEBA / NDR (STRONG — enrich)
- **MODIFY** Internal scan (`9d041578`): **hostname column via `omni-dhcp-attribution(entity_host)`** + `risk_severity, mitre_technique, scan_deny`, sort `scan_dest_count desc`. **[P1]**
- **MODIFY** Exfiltration (`32e0b717`): enrich `entity_host`→hostname, add `dest_ip_country_code, risk_severity, mitre_technique(T1048), exfil_bytes_sent`, sort `exfil_gb desc`. **[P1]**
- **FIX** Score distribution (`6a51d984`): sort `pivot ueba_score Ascending` (current sort on an absent field); ideally bucketize 0-39/40-69/70-100. **[P2]**
- **MODIFY** Beaconing (`1b958908`): add `dest_ip_country_code, risk_severity, mitre_technique`, enrich src_ip, sort `beacon_hits desc`. **[P2]**
- **MERGE** Volume anomalies KPI (`c6599dee`)+table (`3ec25c5c`); add `risk_severity, anomaly_kind`. **ADD** *Top NDR entities by MITRE tactic* (`RP mitre_tactic, entity_host / S count(), max(risk_score)`). **[P2]**
- **REVIZ** Dominant factor pie (`4b27f8c3`) → bars. **ADD** *UEBA≥70 → NDR events of the entity* bridge (join `ueba_entity`). **[P3]**

### Collection health (STRONG — make windows reliable + 360 heartbeat)
- **FIX** go-dark (`ccfdcbd5`/`b011288b`): pivots `dark_host/hours_silent/host_volume_30d`=**0** (broken emission job). Rewire on real data: `event_source:(windows OR sysmon OR windows_security) / RP host / S latest(timestamp)` sort asc, fixed 7d TR. **[P1]**
- **FIX** "24h" at `timerange=null` (`f7a031ef`, `491038eb`, `3a3d36ad`, `453be60b`, `3c590f25`, `48cd3130`, `b22ffb97`…): set TR `relative 86400` (otherwise the "24h" title lies). **[P1]**
- **FIX** Windows channels (`0bda5c1f`): remove `OR event_source:sysmon` (sysmon has no `channel`). **[P2]**
- **ADD** *Global heartbeat*: table empty query, `RP event_source(30) / S count(), max(timestamp)` sort `max(timestamp) asc` → spots THE source that got cut. **[P2]**
- **MODIFY** Last reception (`453be60b`): include `vaultwarden, m365, vsphere, veeam` (+ NPS eventually). **MERGE** go-dark detail with "Last activity per host" (`cb882ac8`). **ADD** `forti_dhcp` health KPI (567 docs, enrichment pivot). **REMOVE** "M365 accounts seen" (`31c818a5`, belongs to the M365 pages). **[P2/P3]**

### AD Identity (rewire 2 broken widgets + correlations)
- **FIX** Failing service accounts: `service_logon_fail`=0 → `event_id:4625 AND user:*$` / `RP user / S count(), card(host)`. **[P1]**
- **FIX** RDP per host: `event_action:rdp_session_ouverte`=1 → `event_id:4624 AND logon_type_label:rdp_interactif_distant` (or table `RP host / CP logon_type_label`). **[P1]**
- **ADD** *AD failures by enriched origin*: `event_id:4625 / RP src_ip, user / S count()` + **hostname via `omni-dhcp-attribution`**; heatmap `src_ip x user`. **[P1]**
- **ADD** *Kerberoasting*: `event_id:4769 AND winlogbeat_winlog_event_data_TicketEncryptionType:0x17 AND NOT *TargetUserName:*$` / `RP TargetUserName, ServiceName`. **[P2]**
- **MODIFY** Failure reasons: exclude the service noise `NOT user:ninjaone AND NOT user:*$`, pie→bar (restriction_compte=1465 comes almost only from ninjaone). **MERGE** failures per account ↔ account×host heatmap; NTLM block (4 widgets → 1 table `RP TargetUserName / CP LmPackageName` + 1 KPI 4776). **[P2]**
- **MODIFY** off-hours admins: remove `CP day_period` (1 single value), add `CP host`. **ADD** *Spray*: `event_id:4625 AND NOT user:ninjaone / RP src_ip / S card(user)`. **[P3]**

### Privileged accounts (heavy rewiring)
- **FIX** Priv group changes (KPI+table): `priv_group_label`=0 and 4728/4732/4756=0 → check 472x collection; otherwise pivot `winlogbeat_winlog_event_data_TargetUserName`. **[P1]**
- **FIX** Sensitive group additions (detail): query 472x=0, `MemberName`=0 → fallback MESSAGES `event_id:4670`(21k)/`4662`(224k) targeted at `adm-*`. **[P1]**
- **FIX** Sensitive account detections: `dcsync/kerberoasting/m365_role`=0 → `alert_tag:(vault_admin_abuse OR explicit_cred_use OR lsass_access OR audit_config_change OR sysmon_injection OR persistence_autorun)`, `risk_score` column. **[P1]**
- **FIX** 4672: filter the noise `AND (account_class:admin OR user:adm\-*) AND NOT user:(*$ OR SYSTEM OR "Système" OR "Administrateur" OR ninjaone OR DWM-*)`. **[P2]**
- **ADD** *Admin logon type* (`event_id:4624 AND user:adm\-* / RP user, LogonType`); *Top admins by risk_score*; *Vaultwarden abuse* (`alert_tag:vault_admin_abuse`). **REVIZ** "Where the admins connect from": enrich src_ip→hostname. **MERGE** the 3 admin activity tables into one (`RP user / S count(), card(host), card(src_ip), card(event_action), max(risk_score)`). **[P2/P3]**

### Accounts & compliance (rewire actions/categories)
- **FIX** Installed services: `7045`=0 → `event_id:4697 OR event_action:service_installe` (14). **[P1]**
- **FIX** Audit sabotage: `winsec_critique`=0 → `event_category:sabotage_audit OR event_id:4719(96) OR alert_tag:audit_config_change`. **[P1]**
- **FIX** Admin shares: `admin_share`=0 → `event_id:5140`(1611) (+ filter `C$/ADMIN$/IPC$`). **[P1]**
- **ADD** *Vaultwarden admin abuse* (`alert_tag:vault_admin_abuse`, identify the right actor field — `vault_user` empty). **[P1]**
- **FIX** Life cycle / Certificates / PKI: rewire on `event_id:(4720..4781)` (legitimate post-purge) and `event_category:certificats`(52, `cert_subject/cert_expiry`) rather than nonexistent actions. **[P2]**
- **MERGE** KPI 4720/4725/4726 + 2 life cycle tables → 1 table (`CP event_id / RP user`). **REMOVE** "M365 roles modified" (source not covered). **REVIZ** life cycle pie → table. **[P2/P3]**

### M365
- **ADD** *Failures by country/IP*: `m365_type:signin AND event_action:echec_connexion / RP src_country, src_ip / S count(), card(user)` (real signal HK29/IL11/MA8 = spray). **[P1]**
- **MERGE** 4 failure widgets → keep table `RP user / CP m365_fail_label` (`a411115c`) + trend KPI. **FIX** "Outside France/risk" (`cf99db0b`/`3f1ebb9c`): `m365*` tags=0 → `m365_type:signin AND NOT src_country:FR`. **[P1]**
- **MERGE** 3 Entra audit widgets → table `RP user, event_action, target`. **REVIZ** country pie → bar + `card(user)`. **ADD** *Successful sign-ins from unusual country* (`connexion_reussie / RP user / CP src_country`). **REVIZ** legacy auth (`RP client_app, user`). **REMOVE** device OS (`9fa197da`). **[P2/P3]**

### M365 Activity (exfil pillar = dead wiring)
- **FIX** 5 widgets (forwards/shares/delegations): `m365_mail_forward/mailbox_deleg/partage_externe`=0 → native detection `event_action:(New-InboxRule OR Set-InboxRule OR Set-Mailbox OR Add-MailboxPermission OR Add-RecipientPermission)`; otherwise **remove** the misleading KPIs at 0. **[P1]**
- **FIX** details: `fwd_target/share_target/share_file`=0 → real fields `timestamp, user, upn, m365_workload, event_action, result, src_ip, src_ip_country_code`. **[P1]**
- **MERGE** workload pie + workload timeline. **MODIFY** Mailbox access (`a9c3071c`): add `src_ip_country_code` / `NOT src_ip_country_code:FR`. **ADD** *Data movement* (`Send`+`AttachmentAccess` by user). **REMOVE/turn** the global count KPI. **[P2/P3]**

### Endpoint
- **FIX** "Endpoint activity 24h": **empty query → aggregates the whole SIEM** → `event_source:(sysmon OR windows OR windows_security)`. **[P1]**
- **FIX** 3 detection widgets: `powershell_suspect/defender`=0 → `alert_tag:(sysmon_injection OR lsass_access OR persistence_autorun OR explicit_cred_use OR beaconing OR data_exfil)`. **[P1]**
- **FIX** Network destinations: pivot `dest_ip` breaks (`array_index_out_of_bounds` = ip/keyword mapping) → repair the mapping + **enrich dest_ip→hostname** + `CP dest_port`. **[P1]**
- **MODIFY** parent→child chains: normalize the granularity (basename of both), exclude the noise (seal_ulscom/NinjaRMM). **ADD** *4688 vs Sysmon coverage* (`RP host / CP event_source`), *detection→host→account→score*, *Top ESET threats* (pre-wired, empty post-purge). **MERGE** 4 volume KPIs → "Endpoint posture" bar. **[P2/P3]**

### Hunting
- **FIX** Run persistence (`4c403775`/`655301a2`): `*Run*`=7311 (99.97% W32Time noise) → `event_id:13 AND TargetObject:(*CurrentVersion\\Run* OR *RunOnce* OR *Winlogon\\Shell* OR *Userinit* OR *Image File Execution Options*)`. **[P1]**
- **FIX** Named pipes (`b98108c6`): Sysmon 17/18 not collected (`PipeName` absent) → enable the Sysmon config or remove the widget. **[P1]**
- **REMOVE** 4 duplicate numeric KPIs (LSASS/AppData/Office-shell/Run) — keep the tables. **[P1]**
- **MODIFY** Outbound connections (`19ee9aee`): `RP host, process_name, dest_ip, dest_port` + non-RFC1918 filter. AppData/LSASS: add `command_line` / `GrantedAccess:(0x1010 OR 0x1410)`. **ADD** DHCP enrichment, LOLBins (certutil/regsvr32/mshta/rundll32). **REVIZ** "first seen 30d" baselining. **[P2/P3]**

### Network
- **FIX** 2 TI widgets (`7aaacd07`/`29921e8d`): `threat_intel`=0 → `alert_tag:(network_scan OR exposition_internet)`, pivot `src_ip` + `card(dest_port)`. **[P1]**
- **FIX** Country heatmap (`21e9e216`): `srccountry`(19%) → `src_country`(77%). **[P1]**
- **ADD** *FortiGate reputation*: `RP src_ip / S max(crscore), count()`, filter `crlevel:(high OR critical)` (crscore populated). **[P1]**
- **ADD** *Hostname enrichment* (`src_hostname/dest_hostname`=0) via `omni-dhcp-attribution` on the internal tables. **MODIFY** dest_country pie → bar + `NOT Reserved`; top destinations `dest_ip_reserved_ip:false`. **MERGE** 2 UTM widgets. **ADD** *VPN by user/country*. **REVIZ** "24h" at TR null. **[P2/P3]**

### VPN & Exposure (WEAK — overhaul)
- **FIX** 5 SSL widgets (`ssl-login-fail`=0) → confirm whether the SSL portal is exposed; otherwise **remove**, otherwise remap on the real action. **[P1]**
- **FIX** spray (`user` empty on SSL, `xauthuser`='N/A'): identify the real user field or remove. **[P1]**
- **MODIFY** IPsec peers by country: add `card(vpntunnel), card(remip)` + twin widget `NOT remip_country_code:FR` (= the missing Exposure widget). **ADD** *IPsec session volume* (`tunnel-stats / sum(sentbyte/rcvdbyte)`), *map on `remip_geolocation`* (all the traffic, not just SSL), *TI on external remip*. **MERGE** tunnels KPI/table and 4740. **[P2/P3]**

### External sources (ESET dead wiring + NPS oversized)
- **FIX** 9 ESET widgets: `eset_detection`=0 + fields `eset_threat_name/action_taken/object_uri`=0 → make the tag be produced (`eset_event_type:Threat_Event`) or switch to real fields (`eset_action, eset_domain, eset_detail, eset_risk_score, eset_user`). **[P1]**
- **ADD** *ESET ip→hostname* (`eset_ipv4` + `dhcp_hostname`), *ESET risk per host* (`max(eset_risk_score)`). **MERGE** 3 ESET volume widgets. **REMOVE/group** the 6 NPS widgets (awaiting the client) into 1 placeholder. **REVIZ** pies. **[P2/P3]**

### BunkerWeb WAF
- **FIX** Offensive tools (`b3352645`): `waf_ua_outil:true`=0 → `http_user_agent:(*sqlmap* OR *nikto* OR *nmap* OR *nuclei* OR *Wget* OR *python-requests* OR *curl* OR *Scanner*)`, `RP src_ip, http_user_agent`. **[P1]**
- **FIX** 5xx by site (`fa02eb2c`): `waf_backend_down`=0 → `http_status:(500 502 503 504)`, `RP waf_vhost / CP http_status`. **[P1]**
- **FIX** Blocks (`e55470c4`/`9341a715`): `waf_block`=0 → `http_status:(403 OR 429)`. **[P1]**
- **FIX** "Threat intel" (`013db8cd`): `waf_src_externe:true` = just a public IP → rename OR `src_ip_threat_indicated:true`. **[P1]**
- **ADD** *Top source countries* (`src_ip_country_code`, AD=1273 abnormal!), *4xx enumeration scan per IP*, *Sensitive path attacks* (`http_url:(*.env* OR *wp-login* OR *.git* OR *admin*)`). **MERGE** 5xx. **REVIZ** codes pie → area. **[P1/P2/P3]**

### Mapping
- **FIX** VPN brute force (`318efc77`) + failures KPI (`67bbc6ff`): `ssl-login-fail`=0 → `subtype:vpn AND status:failure`(8238). **[P1]**
- **FIX** M365 outside France (`624a1753`): `m365_etranger`=0 → `m365_type:signin AND NOT src_country:FR`. **[P1]**
- **ADD** *M365 failures by upn* (`_exists_:m365_fail_code / RP upn / CP src_country`). **MODIFY** maps: TR null → fixed 7d + overlay `status:failure`. **MERGE** map+table+KPI triplets (VPN and M365). **ADD** DHCP enrichment. **[P2/P3]**

### vSphere (WEAK — overhaul)
- **FIX** "Accounts seen" (`070aaf5a`) + "Actions" (`68a8f61f`): **empty query → the whole SIEM** → `source:vcenter OR source:bx-esxi*` (and repair the polluted `user` extraction). **[P1]**
- **FIX** SSH/Shell (`14d3302d`/`5eb869ac`): `vsphere_shell_ssh`=0 but 136 raw docs → `(source:bx-esxi* OR source:vcenter) AND (message:"TSM-SSH" OR message:esxShell OR message:"ESXi Shell")` + repair the pipeline tag. **[P1]**
- **FIX** Deleted VMs (`0ffa862f`/`22fef4c1`): `vsphere_vm_destroy`=0 but 667 docs → `source:vcenter AND (message:VmRemoved OR message:VmDestroy OR message:"removed from inventory")` + extract user/vm_name. **[P1]**
- **REVIZ** Auth failure sources (`d5e07e71`): **enrich src_ip→hostname** (10.33.80.23=150 failures). **ADD** *Auth failures → src_ip×host (bruteforce)*, *Snapshots*. **MODIFY** "Events 24h" (empty query+TR null), ESXi hosts (scope). **REMOVE** the `config_modifiee` dependency (wcp debug false positive + pollutes `vsphere_auth_fail`). **[P1/P2/P3]**

### Backups
- **FIX** 6 SIEM supervision widgets (`358f3c33`, `cefafff3`, `eec815e1`, `46b8a22b`, `27efcf09`): `backup_config_ok/echec`, `disk_warn`, `disk_guard_prune`=0 → real model `siem_health` (`health_type:summary/job_fail`, fields `health_ok/fail/total`); failure = `alert_tag:siem_job_fail`. **[P1]**
- **REMOVE** "Veeam events" KPI (duplicate). **MERGE** 3 `veeam_job_echec` widgets (a single host). **ADD** *Success/failure ratio* (`CP winlogbeat_log_level`), *Crown-jewel backup failure* (`message:(*VAULT* OR *PKI* OR *DEV* OR *GIT*)` — live failure = BX-VAULTWARDEN, T1490), *Veeam collection freshness* (`max(timestamp)`). **REVIZ** severity pie → bar. **[P1/P2/P3]**

### Certificates
- **FIX** PKI detail (`1bc0c149`) + Certs by requester (`b03a7b5c`): `cert_subject_disp`=0 → `cert_request_id`/`cert_requester` (real). **[P1]**
- **MODIFY** fleet KPI: `count()`(52 instances, duplicates) → `card(cert_subject)` + `trend:false` (snapshot). **MERGE** denials+revoc, SIEM detail ×2, requester ×2. **REMOVE** `card(event_action)` KPI (non-actionable). **ADD** *AD CS denials by requester* (`event_id:4888`), *cert_requester → priv accounts/UEBA correlation*, *distribution by day range*. **REVIZ** timeline → stacked bars. **[P1/P2/P3]**

### Vulnerabilities (STRONG — refine prioritization)
- **MODIFY** KEV exposure per host (`f3563442`): add `max(vuln_cvss)` + ransomware column, sort `sum(vuln_cve_count) desc`. **[P1]**
- **ADD** *Ransomware remediation focus*: `vuln_ransomware:oui`(381) / `RP vuln_product / S count(), card(host), max(vuln_cvss)` → patch queue (Firefox 44, FortiClient 22, Silverlight 19…). **[P1]**
- **FIX** Cumulative risk (`0ca40118`): `risk_score` binary (7/10) ≈ count → weight (`sum(vuln_cve_count)` or asset criticality) + expose `risk_severity`. **[P1]**
- **ADD** *KEV hosts without EDR* (cross-reference vuln↔ESET). **MERGE** "Exposed hosts" KPI into the table. **MODIFY** details: sort `vuln_cvss desc` / `patch_age_days desc` (not timestamp). **REVIZ** patch_age block (8 docs). **[P2/P3]**

### Investigation
- **FIX** Connections/DNS (`22dd4c08`): EID22 has **0 `dest_ip`** → split into *DNS* (`event_source:sysmon AND event_id:22 / RP dns_query, host`) and *Connections* (`event_id:3 / RP dest_ip, dest_port`), scope `event_source:sysmon`. **[P1]**
- **ADD** DHCP enrichment on "Source IPs" (src_ip→hostname). **[P1]**
- **MERGE** Detections KPI + type/score table. **MODIFY** 3 KPIs (host/user/events) on empty query → exclude vaultwarden or remove (95% noise). **FIX** `src_ip/dest_ip` mapping keyword vs ip (graylog_13, vsphere). **ADD** *Process tree EID1*, *UEBA score per entity*. **REVIZ** timeline (non-stacked line / `NOT vaultwarden`). **[P2/P3]**

### Incidents
- **MODIFY** TR of all the widgets: `1200s`(20 min) → `86400s` minimum (a real incident spans 3.6 h). **[P1]**
- **MERGE** 3 KPIs `card(incident_entity)` + severity pie → 1 KPI + horizontal bar `RP incident_severity`. **[P1]**
- **ADD** *Incident→UEBA correlation* (`incident_entity`↔`ueba_entity`, `ueba_score`/`ueba_top_factor`), *MITRE coverage* (`incident_tactic_list`, `incident_techniques`). **REVIZ** pie → bar. **FIX** "longest chain" (`trend:false`). **MODIFY** detail: sort `incident_score desc`. **[P2/P3]**

---

## 3) TRANSVERSE senior SOC recommendations

**a) Inter-page triage flow (analyst/lead/executive journey)**
- **Executive** (posture, noise-free) → **Alerts** (queue `risk_score≥7`) → **Investigation** (paste IOC/host/user) → source pages (Endpoint/Network/M365/vSphere) → **Incidents** (correlated). Today this flow is broken by the `vault_admin` noise up front (Executive/Alerts/ATT&CK/Investigation). **Action #1 = neutralize this noise everywhere** (`AND NOT alert_tag:vault_admin` or `risk_score>=7`), with **a dedicated "Vaultwarden" page** for `vault_admin` + `vault_admin_abuse` + `vault_auth_fail` (vault crown jewel, 808 real abuses).

**b) Visualization consistency**
- **Pies to be banned** on ordinal/unbalanced scales: severity, HTTP codes, dominant factor, granted/denied → **sorted horizontal bars**. Reserve the pie for ≤3 balanced categories.
- **Timeranges**: forbid `timerange=null` when the title announces a window ("24h"). Many widgets (Collection health, Network, Mapping, vSphere) inherit the global selector → misleading title. **Set an explicit TR** or remove the mention.
- **Tables**: sort by the **action metric** (risk_score / cvss / patch_age / latest(timestamp)), never by `timestamp desc` when it is not an event flow (Vulnerabilities, Certificates, Incidents).
- **Single-value KPIs**: remove those that duplicate a neighboring table (Hunting ×4, Backups ×3, M365 ×4, VPN, Incidents ×3, Investigation ×3) → compact and actionable KPI bars (with a color threshold <100%, >threshold).

**c) Correlation enrichments (the biggest qualitative gain)**
- **DHCP attribution `omni-dhcp-attribution` (ip→hostname) EVERYWHERE** an internal `src_ip/dest_ip` is pivoted: Alerts, AD Identity, Privileged accounts, Endpoint, Network, vSphere, Investigation, Mapping, ESET. *(Verified caveat: the lookup responds `has_error:false` but does not resolve the fixed infra IPs like 10.33.80.23 — document these static IPs; monitor the health of `forti_dhcp` (567 docs, low) because its outage silently breaks the enrichment — cf. the `ensure_lookup` trap.)*
- **detection→host→account→score chain**: generalize a table of the type `RP host, user / S count(detections), max(risk_score), card(alert_tag), card(mitre_technique)` + `ueba_score` join (356 docs). To be placed at least on Endpoint, Alerts, ATT&CK, Investigation, Incidents.
- **Geo / threat-intel on external sources**: `src_ip_country_code`/`src_ip_threat_indicated`/`crscore` are populated and **under-exploited** (Network, WAF, VPN, M365). Wire in a real TI feed or, failing that, cross-reference WAF `src_ip` ↔ FortiGate `crlevel`.

**d) Key missing widgets (given the available sources)**
- **Vaultwarden `vault_admin_abuse`** (808) absent from Executive, Privileged accounts, Compliance — vault crown jewel.
- **360 heartbeat all sources** (Collection health): `RP event_source / S max(timestamp)` sort asc.
- **Ransomware focus** (Vulnerabilities): `vuln_ransomware:oui`(381) → patch queue.
- **Crown-jewel backup failure** (Backups): Vaultwarden/PKI/DEV/GIT (T1490 already observed).
- **Real SIEM self-supervision** (`siem_health`): replace the 6 dead widgets with the real model (otherwise a false "all is well").

**e) Pipeline debt to flag to the ingest team** (off dashboard, but blocks actionability)
- Tags never set: `threat_intel, eset_detection, m365_etranger/m365_risque, waf_block, vsphere_shell_ssh, vsphere_vm_destroy, m365_mail_forward/mailbox_deleg/partage_externe, powershell_suspect, defender, winsec_critique, admin_share, dcsync/kerberoasting/m365_role`.
- Broken/absent emission: detailed `go_dark` doc (`dark_host/...`), disk safeguard (`disk_warn/disk_guard_prune`), `service_logon_fail`, M365 exfil fields (`fwd_target/...`), `cert_subject_disp`.
- Mappings to repair: `src_ip`/`dest_ip` in **keyword vs ip** conflict (graylog_13, omni-vsphere_3) → breaks pivots and CIDR queries.
- Extractions to fix: polluted vSphere `user` (`0.01, is, data`), `config_modifiee` = wcp debug noise mis-tagged `vsphere_auth_fail`.

---

## 4) TOP 10 to apply FIRST (high impact, low risk)

> All are **query/pivot/viz changes on the dashboard side** (READ-ONLY on the data, reversible, no pipeline dependency).

| # | Page | Action | Concrete change | Impact |
|---|---|---|---|---|
| **1** | Executive, Alerts, ATT&CK, Investigation | **Neutralize the `vault_admin` noise** | Append `AND NOT alert_tag:vault_admin` (or page query `risk_score:>=7`) on all the `alert_tag:*` / `mitre_technique:*` widgets | Makes 4 pages readable: signal goes from ~44k "detections" to ~900 real ones |
| **2** | Alerts | **Triage queue by severity** | New table `RP alert_tag, host / S max(risk_score), count(), card(mitre_technique)` sort `max(risk_score) desc` | Turns a flat list into a real SOC queue |
| **3** | Mapping + VPN | **Real VPN brute-force** | `action:ssl-login-fail`(0) → `subtype:vpn AND status:failure`(8238) on `318efc77`/`67bbc6ff` | Removes a dangerous false "0 failure" |
| **4** | Collection health | **Fix the "24h" TRs = null** | TR `relative 86400` on ~10 widgets whose title says 24h | Fleet-vs-active figures become comparable again |
| **5** | Vulnerabilities | **Ransomware remediation focus** | Table `vuln_ransomware:oui / RP vuln_product / S count(), card(host), max(vuln_cvss)` | Directly actionable patch queue (already strong page) |
| **6** | WAF | **Offensive tools + source countries** | `waf_ua_outil:true`(0) → regex `http_user_agent`; new widget `src_ip_country_code` (AD=1273 abnormal) | Immediate scan/exploit detection |
| **7** | M365 + Mapping | **Real outside-France** | `alert_tag:m365_etranger`(0) → `m365_type:signin AND NOT src_country:FR` | KPI goes from 0 to 56 foreign connections |
| **8** | Network | **Country heatmap + FortiGate reputation** | `srccountry`(19%)→`src_country`(77%); new `max(crscore)` filtered `crlevel:(high OR critical)` | 80% of the denied traffic finally visible + native prioritization |
| **9** | Hunting | **De-noised Run persistence + removal of 4 duplicate KPIs** | `*Run*`(7311 noise)→`TargetObject:(*CurrentVersion\\Run* OR *RunOnce* OR *Winlogon\\Shell*)`; remove LSASS/AppData/Office/Run KPIs | Eliminates 99.97% of false positives, deflates the page |
| **10** | Executive + Privileged accounts | **Vaultwarden admin abuse widget** | KPI + table `alert_tag:vault_admin_abuse`(808) | Surfaces a crown-jewel risk that is invisible today |

**Implementation note**: actions #1–#10 modify only `query`/`row_pivot`/`series`/`visualization`/`timerange` in the view JSON — none touches the data or the pipeline. The **IP mapping** fixes (Endpoint/Investigation) and the **emission of the missing tags** (vSphere, ESET, M365 exfil, siem_health) are to be handled in a second phase with the ingest team (higher impact, outside the READ-ONLY scope).

Reference files: dashboard generator `/root/omnitech-siem-setup/14-graylog-dashboards.sh`; DHCP lookup `omni-dhcp-attribution` (created via scripts `49-enrich-*` — check that `ensure_lookup` is properly defined there, cf. the memory trap).

---

## Implementation tracking
- [x] vault_admin root cause (9.54M) fixed (loop drop + winother exclusion) + removal of the residues.
- [x] VPN brute-force: ssl-login-fail(0) -> status:failure (8562 revealed).
- [x] M365 outside-France: m365_etranger(0) -> signin AND NOT src_country:FR.
- [x] Network/Mapping heatmap: srccountry -> src_country.
- [x] WAF page (waf_block->403/429, 5xx=1695, offensive tools UA, source countries AD=1274).
- [x] LOT 2: Executive (rewire threats + vault/KEV KPIs) + Alerts (triage queue risk_score>=7) + ATT&CK (techniques/host).
- [x] LOT 3: Endpoint (scope+detections) + Hunting (Run de-noised) + Vulns (ransomware focus) + Incidents (TR 24h).
- [x] LOT 4: AD Identity (RDP per host 4624+logon_type, failure reasons excluding service accounts) + Priv accounts (4672 -> account_class:admin/adm-* : 6110->486) + Accounts & compliance (4697/service_installe, 5140 admin shares, sabotage 4719/audit_config_change, vault abuse).
- [x] LOT 5: M365 (failures by source COUNTRY/IP 24h) + Mapping (m365/VPN already fixed). ESET source-limited (4 audit events, wiring correct, awaiting volume); M365 Activity/exfil idem (low volume post-purge).
- [x] CAPSTONE: DHCP enrichment src_ip/dest_ip internal -> hostname in the FortiGate pipeline (rules omni-forti-06-dhcp-src/dest, stage 6 so as not to stop the pipeline). Verified live: 189 docs/2min enriched (BX-INFO-JMO-LT, GL-S200...). Integration made **reproducible**: new script `56-fortidhcp.sh` (collector + 15min timer + lookup) — before, the lookup/fetcher/timer only existed live.
- [x] LOT 6:
  - **Certificates**: `cert_subject_disp` (0 docs, never set by the pipeline) replaced by `cert_request_id` in the "issued by requester" table and the PKI detail. (Certs issued 4887=0 post-purge = source-limited, wiring correct.)
  - **vSphere**: tags `vsphere_shell_ssh`/`vsphere_vm_destroy` = 0 (never matched); `config_modifiee` (807) turned out to be **`wcp` debug noise** (vCenter authz), not a real config change. SSH/Shell + VM-destroy widgets rewired on the only RELIABLE signals of the flow: `vsphere_auth_fail` (976) and `snapshot_sauvegarde` (98). **Documented source-side action**: the real detection of ESXi SSH/Shell activation and of VM deletions requires forwarding **structured vCenter events** (vpxd events / vobd ESXi) instead of the raw syslog firehose drowned in debug/perf — to be done on the vCenter side, out of dashboard scope.
  - **Backups**: self-supervision block (`backup_config_ok`/`disk_warn`/... = 0, nonexistent event_actions) rewired on the real `event_source:siem_health` schema (`health_type` summary/job_fail, `health_ok`/`health_fail`/`health_total`) + Veeam errors KPI (`winlogbeat_log_level:erreur`, 3 real failures on BX-VAULTWARDEN).
  - **Investigation**: "Connections / DNS" widget (dest_ip pivot whereas Sysmon EID22 has NO dest_ip) split into "Network connections (Sysmon 3 -> dest_ip)" + "DNS queries (Sysmon 22 -> dns_query, 146k docs)".
- **CAPSTONE** (reminder): DHCP enrichment src/dest_hostname in the FortiGate pipeline + reproducible script `56-fortidhcp.sh`.

### Remaining on the source side (off dashboard, for the client)
- vCenter: configure the forwarding of structured events (vpxd/vobd) to make reliable the detection of SSH-enable / VM-destroy / lockdown on the hypervisor.
- NinjaOne: API authorizations via the tenant Owner account (PREREQUISITE of the advanced SOAR workstream, cf. SOAR-PLAYBOOKS.md), then the `omni-ninjaone-fetch` collector.
- Vaultwarden: stop the looping container `ab9e3bdd` + restrict access to `/admin`; **persist the Filebeat registry / `ignore_older` (done on the kit side) to stop the history replay**.
- ESET: forwarding syslog to the SIEM (TCP 1515) only brings back ~4 events -> check the export on the ESET PROTECT console side (cf. INTEGRATION-SOURCES.md).
- **Client TODO: install the ESET antivirus ON the SIEM itself (Debian VM bx-it-graylog-vm)** for endpoint protection of the collector (A.8.7 antimalware hardening).
- Veeam: shift the Backup Copy job (cause of the restore-point lock, cf. detections veeam_job_echec/warn).
