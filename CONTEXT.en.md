# CONTEXT.md — SIEM Graylog OMNITECH Security (project technical context)

Last updated: 2026-06-11. This document describes the **actual and verified** state
of the `bx-it-graylog-vm` VM (10.33.220.10, VLAN 220) and everything that has been
provisioned. Everything is reproducible via the scripts in `~/omnitech-siem-setup/`.

---

## 1. Architecture

```
Windows workstations/servers ──Winlogbeat(TLS 5044)──┐
FortiAnalyzer 10.33.80.253 ──syslog 1514────────┤
                                                ▼
   nginx 443 (TLS PKI) ──► Graylog 7.1.3 (API HTTPS 127.0.0.1:9000, TLS PKI)
                                │                │
                        MongoDB 127.0.0.1   OpenSearch 2.x 127.0.0.1:9200
                                                │  (data on /data = sda 7.3T)
```

- **VM**: Debian 13, 8 vCPU / 32 GB. OpenSearch heap 12g, Graylog heap 4g,
  Mongo cache 1g. OpenSearch data + Graylog journal on `/data` (sda).
  Backups on `/home/siem-backup` (sdb). **Do not touch sdc (USB key).**
- **Accounts/secrets**: `00-vars.env` (chmod 600) + `SECRETS.md`. Graylog web
  admin = `admin` / `GRAYLOG_ADMIN_PASS`.
- **SMTP**: internal relay `smtp-internal.omnitech-security.fr:25`, alerts
  to `informatique@omnitech-security.fr`.

### TLS — precise state (fixed on 06/11, source of an incident)
- PKI certificate (AD CS "Root CA OMNITECH SECURITY") in `/etc/graylog/certs/`
  (`graylog.crt`/`.key` + `omnitech-rootca.crt`).
  SAN: FQDN, `bx-it-graylog-vm`, IP `10.33.220.10` (NOT 127.0.0.1).
- **Graylog API in end-to-end TLS**: `http_enable_tls = true`,
  `http_bind_address = 127.0.0.1:9000`,
  `http_publish_uri = https://bx-it-graylog-vm.omnitech.security:9000/`.
  The FQDN resolves to 127.0.0.1 via `/etc/hosts` (intentional: the self-call
  passes the certificate name verification).
- **JVM truststore**: `/etc/graylog/server/cacerts-omni.jks` (embedded JVM
  cacerts + imported Root CA), wired via `GRAYLOG_SERVER_JAVA_OPTS` in
  `/etc/default/graylog-server`. Without it: `ProxiedResource` WARN loop,
  broken UI ("JSON.parse: unexpected character").
- **nginx 443**: PKI cert + chain, `proxy_pass https://127.0.0.1:9000` with
  `proxy_ssl_verify on` (CA = Root CA OMNITECH).
- **Beats input 5044**: PKI certs copied to
  `/etc/graylog/server/certs/graylog.crt` + `graylog-pkcs8.key`
  (paths referenced by the input in the database). Winlogbeat clients validate
  with `omnitech-rootca.pem`.
- Every scripted API call: `https://${SIEM_FQDN}:9000/api` +
  `--cacert /etc/graylog/certs/omnitech-rootca.crt` (see `lib-graylog.sh`).

---

## 2. Scripts (`~/omnitech-siem-setup/`) — all idempotent

| Script | Role | State |
|---|---|---|
| 00-preflight / 00-vars.env | checks + variables/secrets | executed |
| 01-base … 09-snmpd | OS, Mongo, OpenSearch, Graylog, nginx, nftables, inputs, backup, snmp | executed |
| `lib-graylog.sh` | API helpers (curl TLS, wrap_entity, ensure_rule/pipeline, post_entity) | sourced by 10-14 |
| `10-graylog-model.sh` | index sets, `omni-ip-fields` type profile, streams | **executed OK** |
| `11-graylog-enrichment.sh` | CSV lookups, GeoIP DB-IP + monthly cron, Threat Intel | **executed OK** |
| `12-graylog-pipelines.sh` | 28 rules + 4 pipelines + processor order | **executed OK** |
| `13-graylog-alerts.sh` | SMTP, email notification, 14 event definitions | **executed OK** |
| `14-graylog-dashboards.sh` | 4 dashboards (API views) | **executed OK** |
| `windows/` | AD kit: audit GPO, Sysmon+Winlogbeat (NinjaOne), configs | to roll out on the AD side |

**Graylog 7.x API pitfalls encountered (don't fall into them again):**
1. `POST /streams`, `/events/notifications`, `/events/definitions`, `/views`
   require the `{"entity": {...}, "share_request": {...}}` envelope
   (`CreateEntityRequest`). This was the cause of the initial "stream FAILURE".
   → `lib-graylog.sh::wrap_entity` / `post_entity` (tries direct, falls back
   to the envelope on "entity cannot be null").
2. Lookup cache: `ttl_empty` is a **Long** (seconds), not a boolean.
3. `GET /system/indices/index_sets/profiles/all` returns a **bare array**.
4. Required processor order: `Message Filter Chain → Stream Rule Processor →
   Pipeline Processor → GeoIP Resolver` (streams routed BEFORE pipelines,
   GeoIP AFTER src_ip/dest_ip normalization).
5. Test logs injected with a "future" timestamp (TZ) don't appear
   in relative searches — check directly in OpenSearch:
   `curl -s 127.0.0.1:9200/omni-*/_search`.

---

## 3. Data model

### Index sets (1-day rotation, replicas 0, shards 1)
| Index set | Prefix | Retention |
|---|---|---|
| OMNI - Windows Security | `omni-winsec` | 90 d |
| OMNI - Sysmon | `omni-sysmon` | 60 d |
| OMNI - Windows other | `omni-winother` | 60 d |
| OMNI - FortiGate | `omni-fortigate` | 90 d |

`omni-ip-fields` type profile applied to all 4: `src_ip`/`dest_ip` as OpenSearch
`ip` type → CIDR searches (`src_ip:"10.33.0.0/16"`).

### Streams (removed from the default stream, routed by input + channel)
- **OMNI - Windows Security**: Beats input + `Security` channel
- **OMNI - Sysmon**: Beats input + `Microsoft-Windows-Sysmon/Operational` channel
- **OMNI - Windows other**: Beats input, excluding Security/Sysmon
- **OMNI - FortiGate**: syslog TCP/UDP 1514 inputs

### Normalized fields (produced by the pipelines, common schema)
`event_id`, `event_source` (windows_security|sysmon|windows|fortigate),
`event_action`, `event_category`, `user`, `host`, `src_ip`, `src_port`,
`dest_ip`, `dest_port`, `process_name`, `process_path`, `command_line`,
`parent_process`, `dns_query`, `logon_type_label`, `failure_reason`,
`priv_group_label`, `channel`, and **`alert_tag`** (winsec_critique, dcsync,
kerberoasting, sysmon_injection, powershell_suspect, defender, fortigate_utm).
GeoIP adds `<field>_geo_*` on public IPs.

### Lookups (CSV in `/etc/graylog/lookup/`, sources in `lookups/`)
`omni-win-event-action` / `-category` (Security EventID), `omni-sysmon-event-action`,
`omni-winother-action` (key `channel:eventid`), `omni-logon-type`,
`omni-logon-failure` (4625/4776 sub-statuses), `omni-kerb-failure`,
`omni-priv-group-rid` (RID → privileged group name).

### Pipelines (stages 0=normalization, 5=lookups, 10=detections)
1 pipeline per stream, 28 `omni-*` rules. Notable detections:
- DCSync: 4662 + replication GUID (`1131f6aa`/`1131f6ad`) + non-machine account
- Kerberoasting: 4769 + RC4 encryption (0x17) + non-machine SPN
- Audit tampering: 1102/4719/4794/4765/4766 + System:104
- PowerShell suspect: 4104 ScriptBlock + Sysmon 1 (patterns -enc, downloadstring…)
- FortiGate: native key=value parsing + srcip→src_ip renaming etc. + UTM tag

---

## 4. Alerting (14 definitions, mail notification "OMNI - Mail equipe IT")

P3: Audit tampering · Brute force (≥10 failures/account/10 min) · Password
spraying (≥8 accounts/IP/10 min) · Privileged group modified · DCSync ·
Kerberoasting (≥5 SPN/account/10 min) · Defender detection/deactivation ·
FortiGate virus/IPS · **Winlogbeat silence (0 Windows logs/15 min)**.
P2: Account locked out 4740 · Account created 4720 · Process injection
(Sysmon 8/25) · PowerShell suspect · New service 7045.
Grace 10 min, backlog of 5 messages in the mail.

## 5. Dashboards
`OMNI - Windows Securite`, `OMNI - Endpoint`, `OMNI - FortiGate`,
`OMNI - Detections` (alert_tag view across all sources). Regenerable:
delete the dashboard then re-run `14-graylog-dashboards.sh`.

---

## 6. AD / Windows component (`windows/` kit, see README-WINDOWS.md)

Order: NETLOGON\SIEM drop → `Deploy-AuditGPO.ps1` (pilot then prod) →
`Deploy-AgentsGPO.ps1` (whole-domain deployment via GPO/scheduled task;
NinjaOne = alternative channel) → FortiAnalyzer (see `FORTIANALYZER.md`).
- GPO `OMNI-AUDIT-Baseline`: advanced audit (CSV), cmdline in 4688,
  ScriptBlock+Module logging, Security 2 GB, SCENoApplyLegacyAuditPolicy.
- `winlogbeat.yml` collects: Security (targeted EventID list), Sysmon (all),
  PowerShell 4103/4104, Defender, System, RDP LocalSessionManager 21-25,
  NTLM 8001-8004. Output logstash TLS 5044, CA = Root CA OMNITECH.
- **Actual state: BX-AD-01-IT-VM is already sending** (winsec/sysmon/winother
  logs verified enriched in OpenSearch). Remaining: NinjaOne mass deployment,
  FortiAnalyzer → 1514, BX-AD02 + sensitive servers.

## 7. Day-to-day operations

```bash
cd ~/omnitech-siem-setup && source 00-vars.env && source lib-graylog.sh
api_get /system | jq .lifecycle              # API health
api_get /system/inputstates | jq .           # inputs RUNNING?
curl -s 127.0.0.1:9200/_cat/indices/omni-*?h=index,docs.count
tail -f /var/log/graylog-server/server.log
journalctl -u graylog-server -f
```
Re-running any 10-14 script = safe (idempotent, updates
the rules/pipelines if the source changes).

## 7bis. Additions of the 06/11 afternoon (all verified in prod)
- **Teams**: `teams-notification-v2` notification (Workflows webhook in
  `00-vars.env::TEAMS_WEBHOOK_URL`), attached along with the mail to the 19 alerts
  (automatic sync at the end of `13-graylog-alerts.sh`). Mails in pure ASCII.
- **Correlation**: `logon_fail`/`logon_ok` counters (pipeline) → alert
  "Brute force FOLLOWED by a success" (sum&&sum); tag `admin_share`
  (5140/5145 ADMIN$/C$) → "Admin share sweep" (card(host)≥3);
  "Attempt on a disabled account" (failure_reason).
- **Threat Intel wired**: `threat_intel_lookup_ip` on FortiGate public src/dest
  (cidr_match excludes RFC1918) → tag `threat_intel` + alert.
- **Foreign VPN**: alert via `remip_country_code` query (GeoIP runs
  AFTER the pipelines → never any pipeline tag on geo fields!).
- **Dashboard** `OMNI - Authentification AD` (9 widgets, 3 streams).
- **Self-hosted kit**: nginx `/kit/` ← `/var/www/siem-kit` (Sysmon64,
  winlogbeat zip+yml, sysmonconfig, root CA); standalone NinjaOne script
  `windows/Deploy-SiemAgents-NinjaOne.ps1` (TOFU CA, idempotent).
- **Backup**: bug fixed (the purge was deleting IN_PROGRESS snapshots —
  `state=="SUCCESS"` filter added); chain tested (mongodump+snapshot+tar).
- **Weekly report**: `15-rapport-hebdo.sh` → `/etc/cron.weekly/omni-siem-rapport`.
- **Sources**: winlogbeat.yml collects AD CS (4886-4889) + NPS (6272-6274),
  enriched lookups (pki/nps categories).
- **GPO**: `OMNI-AUDIT-Baseline` + `OMNI-SIEM-Agents` deployed, linked to
  `OU=Entreprise` (+DC for audit); fleet convergence ~12h-14h daily.
- **M365 IN PRODUCTION** (16:30): app `OMNI-SIEM-Collector` (creds in
  `00-vars.env::M365_*`), `16-m365-input.sh` (GELF input 127.0.0.1:12201,
  index `omni-m365` 180 d, stream, pipeline tags `m365_etranger`/`m365_risque`/
  `m365_role`, 4 alerts) + `17-m365-fetcher.sh` (Python stdlib collector
  `/usr/local/sbin/omni-m365-fetch`, 5 min timer, cursors
  `/var/lib/omni-m365/state.json`, OData spaces encoded as %20!) +
  dashboard `OMNI - Microsoft 365`. Verified: 501 messages backfilled,
  signIns + directoryAudits OK; `riskDetections` returns 403 as long as
  `IdentityRiskEvent.Read.All`/`IdentityRiskyUser.Read.All` are not
  consented (Entra P2 license required) — the fetcher tolerates it.

## 7ter. SOC redesign (06/11 end of day)
- **Single dashboard "OMNI - SOC" 5 pages** (Overview+KPIs / AD+M365 Identity /
  Endpoint / Network / Accounts & compliance), 33 aggregations + 5 message tables
  (triage). Generated by `14-graylog-dashboards.sh` v2 (inline Python builder,
  multi-page = several queries in the search + `titles.tab`).
  The 6 old single-page dashboards are deleted on each run.
- **M365 user = local part of the UPN** (`_upn` = full) → on-prem↔cloud
  correlation by account. Alert "AD failures + foreign M365 sign-in"
  (sum(logon_fail)≥5 && sum(m365_foreign)≥1, multi-stream). 24 alerts total.
- **4103 removed from collection** (Module Logging = NinjaOne flood, 4,368 events/2 h
  on a single workstation); 4104 kept. `/kit/winlogbeat.yml` up to date — recopy
  into NETLOGON\SIEM for the GPO channel.
- **BX-INFO-JMO-LT** reports (Sysmon/System/PowerShell) but 0 Security as long
  as the audit GPO is not effective on the workstation (check `gpresult /r`
  + `auditpol /get /category:*`). Hosts appear as full FQDN.

## 8. Remaining work (backlog)
1. Mass Sysmon/Winlogbeat deployment: `windows/Deploy-AgentsGPO.ps1`
   (pilot → prod); NinjaOne as a complement off-domain.
2. FortiAnalyzer: follow `FORTIANALYZER.md` (syslog TCP 1514 forwarding,
   severity/vpn/admin/UTM filters; Graylog already ready).
3. Restrict `NET_ADMIN` (nftables) to the actual admin VLAN.
4. Test real mail sending (System > Notifications > Test) from VLAN 220.
5. PKI cert renewal (expires 2028-06-10): redeposit in
   `/etc/graylog/certs/`, re-copy to `server/certs` + nginx, restart.
6. Possible CEF input 5555 if the FAZ forwards in CEF rather than syslog.

## 7quater. Pass of the 06/11 evening
- Teams FIXED: the default v2 template posted the card without the
  `{"type":"message","attachments":[...]}` envelope expected by Power Automate ->
  custom adaptive_card wrapped in 13 (JMTE variables). Direct curl test
  and Graylog test received in the channel.
- Fleet: 20+ hosts reporting (GPO/NinjaOne converged). BX-INFO-JMO-LT: everything
  except Security as long as the audit GPO is not effective (gpresult /r).
- Dashboard OMNI - SOC: 8 pages (added "Alerts" and "Hunting" - LSASS,
  Office->shell, AppData/Temp, Run persistence, pipes, outbound binaries).
- Read-only account `soc-viewer` (Reader role) created.
- `ISO27001.md`: Annex A 2022 self-assessment (covered vs 9 gaps including
  NAS export of backups, restore test, named accounts).

## 7quinquies. Exchange/SharePoint - O365 Management Activity (06/11)
- `18-m365-activity.sh`: Audit.Exchange/SharePoint/General subscriptions
  (ActivityFeed.Read permission OK), collector `/usr/local/sbin/omni-m365-activity`
  (10 min timer, state /var/lib/omni-m365/activity-state.json, dedup by
  contentId, 30 min overlap). POST subscriptions/start requires Content-Length:0
  (otherwise HTTP 411). Events -> GELF input 12201 -> stream/index omni-m365
  (m365_type=activity), SEPARATE pipeline "OMNI - M365 Activite".
- Detections (flags set by the collector, tagged by the pipeline):
  forward_external (InboxRule/Set-Mailbox to a domain outside
  omnitech-security.fr/omnitech.security) -> m365_mail_forward (P3);
  mailbox_deleg (Add-MailboxPermission) -> m365_mailbox_deleg (P2);
  external_share (external AnonymousLink/CompanyLink/SecureLink) ->
  m365_partage_externe (P2). 3 mail+Teams alerts.
- Verified: 27,313 events/24h (Exchange/SharePoint/OneDrive/Teams), 9 external
  shares detected (e.g., Roadmap27001.docx -> invissys.com). 0 forward/deleg
  (no attack) but detections armed.
- Dashboard: "M365 Activite" page (workloads, top operations, external
  shares, mailbox access, forward/delegation triage). SOC = 10 pages.
- VOLUME NOTE: MailItemsAccessed is verbose (~12k/24h); filterable if needed.
- Recurring partner invissys.com: to be added as a "known" domain if too much
  noise on legitimate external shares.

## 7sexies. Health + FortiGate + vSphere pass (06/11 evening)
- HEALTH: /data disk 2%, cluster green. BUG fixed: 119 M365 indexing failures
  (src_ip in ip:port format rejected by the 'ip' type) -> clean_ip() function
  in both collectors (17 and 18).
- Detections added (12+13): ransomware_indicator (vssadmin/wbadmin/bcdedit
  delete shadows, P3), lsass_access (Sysmon 10 + suspect GrantedAccess, P2),
  scheduled task 4698 (P2). 34 OMNI alerts total.
- FortiGate: `fortigate/` folder = 01-utm-logging.conf (the FortiGate does NOT
  log its UTM profiles = the real gap) + 02-faz-forwarding.conf (revised filter).
  Detail in FORTIANALYZER.md.
- vSphere: `19-vsphere.sh` (syslog TCP+UDP 1516 inputs, index omni-vsphere 90d,
  stream, best-effort parsing pipeline, tags vsphere_auth_fail/shell_ssh/
  vm_destroy/config, 3 alerts). Parsing VALID on test logs (user/ip/tags
  OK). Firewall 1516 open (VSPHERE_NET). ESXi/vCenter side: VSPHERE.md.
- Dashboard OMNI - SOC: 13 pages (added vSphere).

## 7septies. RESOLVED: silent Security channel (06/11 night) - PITFALL TO REMEMBER
SYMPTOM: the DC (then every workstation with audit active) sends NO Security
event, while the other channels (Sysmon...) report normally.
FALSE LEAD: Security log full / "do not overwrite" mode. Clearing + audit
change nothing (that was off-topic, but harmless).
REAL CAUSE: the `event_id` list of the Security channel in winlogbeat.yml was
too long (~48 EventID). The Windows Event Log API limits the number of
expressions per query -> "The specified query is invalid"
(ERROR_EVT_INVALID_QUERY) and Winlogbeat reads NOTHING MORE on that channel.
KEY DIAGNOSTIC: `wevtutil qe Security /q:"*[System[(EventID=4624)]]"` WORKS
(channel healthy) but the winlogbeat logs show "Open() error ... Security ...
invalid query". => it's the agent config, not the log.
FIX: winlogbeat.yml Security channel in RANGES (6 expressions):
  event_id: 1100-1104, 4624-4799, 4886-4889, 5136-5145, 6272-6274, 7045
Pushed via /kit + NETLOGON. Redeployed by Deploy-SiemAgents-NinjaOne.ps1
(downloads the yml + restart). NEVER put back a long flat list.
If a log was cleared while winlogbeat was running: also purge the
`C:\ProgramData\winlogbeat\.winlogbeat.yml` registry (stale bookmark).
RESULT: DC + fleet report Security (19k+/30min DC). win-events lookup
enriched with the range's EventID (4670,4673,4674,4727,4730,4731,4734,4767,4778,
4779). vSphere vm-destroy rule refined to exclude Veeam snapshots.

## 7octies. Incident 06/12 morning: "Brute force" spam + silent Teams — RESOLVED

**Symptom**: all night, "OMNI - Force brute" mails (adm-jmorin, 297
failures/10 min, empty source IP) classified as spam by Exchange; NO other
notification received, including Teams.

**Causes (3 layers)**:
1. **BX-AD02-IT-VM**: a Windows service runs with `adm-jmorin` WITHOUT the
   *Log on as a service* right (4625 type 5, Status
   0xC000015B, caller services.exe, 1 failure/2 s for DAYS, 1792/h
   constant). Became visible only when AD02 received the fixed winlogbeat
   (backfill ignore_older=72h). Host-side identification:
   `Get-CimInstance Win32_Service | ? StartName -like '*adm-jmorin*'`.
2. Brute force definition too crude: query `event_id:4625` (service/batch
   types included), grace 10 min, no key -> re-notification every
   10 min all night (+ "FOLLOWED by a success" as soon as it connected).
3. The volume caused the mails to be classified as spam AND killed the Power
   Automate flow (internal throttle/quota, Graylog receives 202 -> ZERO error logged) ->
   **silent outage of all Teams alerts**. Meanwhile the
   real signal went unnoticed: SSLVPN spraying from the Internet (10k+
   failures/16 h, real AD accounts targeted) -> 38 AD lockouts during the night.

**Fixes applied (12 modified + NEW 21-alert-hygiene.sh)**:
- Pipeline: `logon_fail` only if LogonType != 4/5; new counter
  `service_logon_fail` (types 4/5); `failure_reason` fixed (SubStatus 0x0
  -> fallback lookup on Status; line `0x0,succes` removed from the CSV, 4776 rule
  ignores Status 0x0); Sysmon injection exclusions (dwm/winlogon/csrss/
  unknown); 4104 excludes the Azure AD Sync Path; FortiGate: non-IP
  src_ip/dest_ip discarded (corrupted FAZ octets), user="N/A"/IP removed.
- Definitions (21): Brute force -> query `4625 AND logon_fail:1`, grace 1 h,
  key=["user"]; FOLLOWED by a success -> grace 1 h key user; spraying ->
  30 min key src_ip; VPN/lockout/injection/PowerShell -> grace 1 h;
  new def **"OMNI - Service/batch logon failure (broken service
  account)"** (mail only, grace 4 h, key user+source).
- `fortigate/03-vpn-hardening.conf`: geo-FR on the SSLVPN portal +
  login-attempt-limit/login-block-time + MFA/SAML recommendation (TO APPLY).

**PITFALLS TO REMEMBER**:
- A definition's key_spec is only accepted by the API if each key has a
  field_spec entry (template `${source.<field>}`) — otherwise the PUT fails with
  `key_spec can only contain fields defined in field_spec`, and api_put still
  returns exit 0: ALWAYS check the presence of `.id` in the response.
- Grace applies PER KEY when key_spec is set: a newly attacked account
  is notified immediately even if another account is in grace.
- Logon failure type 4/5 = hygiene (service account), NEVER brute
  force: separate the two detections.
- Teams via Power Automate fails SILENTLY: after any storm, check
  the Power Automate flow's run history (not the Graylog logs).
- Re-run `21-alert-hygiene.sh` after EACH re-run of 13-graylog-alerts.sh
  (13 recreates with grace=600000 / key=[]).

## 7nonies. Pass of 06/12 morning (after the incident)

- **AD02 cause identified by Julien**: `Fortinet_FSAE` service (FSSO
  Collector!) running with adm-jmorin -> switched to Local System.
  Storm stopped at 08:06:29. BONUS: FSSO had been dead for days ->
  the `user=` attribution in the FortiGate logs was ZERO; restored
  (10k+ logs attributed/15 min). If ever redesigned: FORTIGATE-SVC account.
- **`windows/Install-OmniSiem-NinjaOne.ps1`** (also on /kit): the ONE
  and definitive NinjaOne script, replaces Deploy-SiemAgents + Set-OmniAudit.
  CA TOFU + audit (baseline /kit) + Sysmon (hash) + Winlogbeat (restart
  ONLY if config/version change) + auto-detected "Veeam Backup" channel
  + health (test output, scan for "invalid query" channel errors) + summary
  [OK]/[KO], exit 1 if KO. Daily scheduling recommended.
- **Console links removed** from the 3 notification templates (text mail,
  HTML mail, Teams card Action.OpenUrl) — in prod AND in 13.
- **Veeam B&R**: rules omni-winother-10-veeam(-echec), alert "OMNI -
  Veeam: job failed or warning" (P3 mail, grace 4 h, created by 21
  section [3/3]), dashboard page "Backups". On the Veeam server: just
  run Install-OmniSiem (auto-detection). Doc: VEEAM.md.
- **Dashboard OMNI - SOC: 15 pages** (+ "VPN & Exposure": portal
  attack map, targeted IPs/accounts, legitimate tunnels, AD lockouts;
  + "Backups"; + broken-service-account widgets on AD Identity).
- **03-vpn-hardening impact check**: 100% of successful tunnels come from
  France (7 users) over the available history -> geo-FR with no known impact.
  login-attempt-limit raised to 5 (Julien's choice 06/12). NEW
  `fortigate/04-proxy-inspection.conf`: switch rules to proxy inspection
  (per rule, GUI multi-selection or CLI), proxy feature-set on the
  AV/webfilter profiles, EXCEPTION for VoIP rules (stay flow), monitoring
  keeps mode, and recommendation for deep inspection via AD CS SubCA eventually.
- **BDX FORTIGATE IDENTITY (pitfall)**: CLI hostname = `BX-FW02-IT-RT-S`,
  serial FG120GTK23000193, HA a-p primary — but the FAZ forwards its logs
  under its FAZ registration name **OMNITECH-BDX_FG120G** (devname field).
  Same box. Check: `get system status` (serial). FortiOS 7.4.11.
  FortiOS CLI pitfalls: busybox grep without -E (use `| grep -f pattern` =
  config context with the rule ID); `av-block-log` no longer exists.
- **`fortigate/05-utm-policies-bdx.conf`**: UTM attachment READY TO PASTE,
  generated from the actual `show firewall policy` (06/12). Tiers: A=users/wifi
  full stack (441/1261/1256), B=exposed inbound 87/925 (IPS+AV), C=IoT
  217, D=~35 servers->Internet rules (AV+IPS+DNS+App), E=user->external
  endpoints (AV+IPS). Exceptions: Teams (10), VoIP, FortiGuard, OpenVAS,
  SIEM traffic. Dead rule 469 "TEST" (dstaddr-negate) to be removed.
- **RESOLVED 06/12 ~10:30 via `06-utm-fix-bdx.conf`**: the 05 was not attaching
  the profiles (proxy feature-set conflict vs flow rules, silent on
  paste). The sequence that works: 1) unset av/web of block E, 2) inspection-
  mode proxy on the 63 rules, 3) feature-set proxy, 4) attachment.
  VERIFIED: 9300+ UTM logs/10 min to the SIEM (dns 4.2k, app-ctrl 4.2k, ssl,
  webfilter). `diagnose log test` = excellent end-to-end test (all
  categories injected -> visible in SIEM within seconds). 02-faz-forwarding
  OBSOLETE (original FAZ filter = defaults, nothing to change).
- **03 VPN hardening APPLIED 06/12 09:45 local**: spraying 104/5min ->
  0 as of 09:50, FR tunnels continue (2-4/15 min). No more AD lockouts
  via the portal. Monitor RAM/conserve mode for 1 week (63 proxy rules):
  `get system performance status`.
- **Veeam INTEGRATED 06/12 ~11:45**: BX-VEEAM-IT-SV (10.33.240.1, VLAN
  LAN_BACKUP) enrolled via manual Install-OmniSiem (TLS12 must be forced for the
  iwr bootstrap on Server 2016; FW rule fixed: append TCP_5044 to the
  SIEM rule, the original 1339 had srcintf DMZ_PUBLIQUE = never matched).
  "Veeam Backup" channel auto-detected + 72h backfill. Locale bug fixed in
  Install-OmniSiem (auditpol "Success|ussite" check for FR OS) -> the morning
  NinjaOne runs may have wrongly shown as failed (cosmetic).
- **Veeam FINDING**: the hourly job "[1 heure] - VM Backup critical
  light" FAILS on BX-VAULTWARDEN-IT-VM (the password vault!)
  since at least 06/09 (~25 failures/day), silently. The alert
  "OMNI - Veeam: job failed" will now send 1 mail/4h until it is
  fixed. To investigate in the VBR console (session detail).

## 7decies. Resilience + ISO retention (06/12 noon)

- **Daily config backup**: `30-backup-config.sh` + systemd timer
  `omni-backup-config.timer` (03:15, Persistent). Content: mongodump (auth
  URI read from server.conf), /etc/graylog+opensearch+nginx+systemd,
  /usr/local/sbin, kit, ~/omnitech-siem-setup. WITHOUT the indices (logs).
  AES-256 archive (`BACKUP_PASSPHRASE` in 00-vars.env, TO PUT IN THE VAULT)
  -> local copy /var/backups/siem + export `//10.33.50.5/Public/SIEM`,
  14 d retention on both sides. Status auto-sent as GELF (12201) ->
  alerts "SIEM config backup failed" + "absent >26h" (21 section [4/4]).
  Full rebuild procedure: `RESTORE.md` (test it once on a throwaway
  VM!). REMAINING ON JULIEN'S SIDE: FortiGate ELK Network rule -> H_OMS_FILES
  SMB service (mount cifs errors 115 otherwise) + possible /root/.smb-siem.cred
  if guest is refused (username/password/domain, chmod 600).
- **ISO retention applied** (`31-retention-iso.sh`, based on volume measured
  06/12 post-UTM, /data = 7.3 TB dedicated, ~25 GB/d all flows):
  winsec/winother/m365 = 365 d, sysmon/vsphere/fortigate = 180 d.
  Saturation projection ~5.6 TB (77%). MONTHLY REVIEW of GB/d (especially
  fortigate ~11 GB/d); options if drift: fortigate 120 d or split
  traffic/UTM into 2 index sets. Re-run 31 after any re-run of 10.
- **Backup OPERATIONAL 06/12 ~12:15**: 1st archive (26 MB encrypted) on
  //10.33.50.5/Public/SIEM. Account: svc_siem (cred /root/.smb-siem.cred,
  600). FW rule created by Julien (445 ok). Disk safeguard active
  (`32-disk-guard.sh` + 6 h timer: warn 80%, emergency purge 88%->82%).
- **ISO DOCUMENTATION FOLDER created (docs/)**: 00-INDEX, POL-SUPERVISION-
  JOURNALISATION (policy, retentions, commitments), STD-JOURNALISATION
  (sources/transport/fields/severities/accounts), PRO-EXPLOITATION-SIEM
  (daily/weekly/monthly reviews, triage, actions), DOSSIER-ARCHITECTURE-
  SIEM (platform, versions, flows, 41 alerts, IaC, deployment, backlog),
  LDAPS.md. Included in the daily backup. POL to be signed by the IT
  director.
- **LDAPS console OPERATIONAL** (`33-ldaps-auth.sh`, 06/12): backend
  "Active Directory OMNITECH" active, LDAPS 636 to bx-ad-01-it-vm
  (10.33.50.250), cert verified by the Root CA. Bind account = svc_siem.
  ACCESS RESTRICTED to "Domain Admins" via recursive memberOf LDAP filter
  (OID 1.2.840.113556.1.4.1941) on
  `CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,...`
  (DN confirmed by ldapsearch; the default group was MOVED out of
  CN=Users). Admin role by default (population already restricted). Filter tested
  OK (adm-jmorin admitted, svc_siem rejected). Prerequisite applied: FW rule 425
  + LDAPS-GC service. Local admin account kept as a fallback (vault).
  Pitfalls: busybox grep on the DC useless; the initial "invalid credentials"
  came from port 636 being dropped (backend never created), NOT from the password.
- **WEEKLY REPORT** (`34-weekly-report.sh` + `/usr/local/sbin/omni-weekly-
  report`, Monday 08:00 timer): HTML mail (alerts/AD/VPN/endpoint/M365/
  backups/capacity/health), local copy /var/backups/siem/rapport-hebdo_*.
  GELF status (event_source=siem_report) -> alert "Weekly report failed".
  The stream "OMNI - Interne SIEM" now routes siem_backup + siem_disk_
  guard + siem_report (3rd rule added). 41 OMNI definitions total.
- **ISO DOCS COMPLETED (docs/)**: + REGISTRE-CONFORMITE-ISO27001 (Annex A
  mapping -> evidence + open actions + auditor method) and PRA-
  RECONSTRUCTION-SIEM (RTO 4h / RPO config 24h / logs not backed up,
  scenarios, validation checklist). POL enriched (normative framework, KPI,
  exceptions, IT director validation), STD (EventID matrix, NTP, hardening),
  PRO (5 playbooks, classification, RACI).
- **LOG PURGE 06/12 ~13:00 (healthy base)**: `40-purge-logs.sh` (MANUAL,
  CONFIRM=OUI, never scheduled). After the build/tests/storm phase, reset
  of the log indices (stop graylog -> DELETE omni-*/gl-events/gl-
  system-events + empty graylog_* -> start -> purge mongo index_failures ->
  rebuild ranges). MongoDB CONFIG INTACT. Result: indices recreated _0,
  0 indexing failures, real-time collection resumed immediately (27 hosts).
  Config backup done beforehand. DO NOT re-run without reason.
- **CANARY ACCOUNT** (`35-canary.sh` + `windows/New-OmniCanary.ps1`, 06/12):
  omni-canary lookup (CSV lookups/canary-accounts.csv, default svc_sql_adm,
  case-insensitive), pipeline rule omni-winsec-10-canary (match user/
  TargetUserName/SubjectUserName/ServiceName without $ via regex_replace),
  P3 mail+Teams alert "CANARY ACCOUNT touched". The PS script creates the AD
  decoy account (random password never used, MSSQLSvc SPN as a Kerberoasting trap,
  logonHours=0, NO real privilege). Add a canary = edit the CSV +
  re-run 35. ORDER: 35 (lookup) BEFORE replaying 12 (the rule uses it).
  REMAINING ON JULIEN'S SIDE: run New-OmniCanary.ps1 on a DC (adjust the OU).
- **SOAR-LIGHT** (`36-soar.sh` + `/usr/local/sbin/omni-soar` service +
  omni-soar-expire timer, 06/12): THREAT FEED architecture (no
  credential on the FW). Graylog HTTP webhook (Brute force VPN +
  spraying alerts) -> service 127.0.0.1:8088 -> safeguards (never RFC1918, never
  SOAR_WHITELIST, threshold SOAR_MIN_HITS=5, cap SOAR_MAX=500, TTL 24h) -> feed
  /kit/soar/blocklist.txt (served over HTTPS) -> FortiGate External Connector reads
  it + deny policy. Traceability GELF event_source=siem_soar -> internal
  stream -> alert "SOAR: IP blocked". Tested OK (public IP blocked, internal/
  sub-threshold IP ignored, backlog message format handled). Notification
  Graylog http-notification-v1: ONLY url/api_key/basic_auth/skip_tls
  (no method/content_type, otherwise "Unable to map property"). REMAINING ON
  JULIEN'S SIDE: apply fortigate/06-soar-threatfeed.conf + SOAR_WHITELIST
  (company/admin public IPs never to block). 43 OMNI definitions.
- **vSphere parsing BUG FIXED 06/12**: discovered after the purge (logs
  finally visible "in the clear"). The vSphere pipeline had `stage 0 match either`
  with a SINGLE rule (drop-noise); but in "match either", if no stage rule
  matches, the message DOES NOT ADVANCE to the following stages. So every
  NON-noise message (= nearly all of them) was blocked before normalization
  -> 0 host/event_source/event_action on 44k logs/15min. FIX: put
  the normalization IN stage 0 with drop-noise (normalization always matches
  has_field message -> the stage always matches -> advances). Result:
  parsing OK, 4 ESXi + vcenter visible. PITFALL TO REMEMBER: never leave
  a "match either" stage with only one conditional rule (drop/tag)
  -> it becomes a filter that blocks everything that doesn't match. Always
  add a rule that always matches (normalization).
- **M365 Activity BUG FIXED 06/12**: the omni-m365-activity collector
  crashed on EVERY run after the 1st ("can't compare offset-naive and
  offset-aware datetimes", line 134: datetime.fromisoformat(last) naive vs
  now aware). FIX: `.replace(tzinfo=timezone.utc)` (fixed on the
  binary AND in 18-m365-activity.sh). Result: 52k+ activity events
  (Exchange/SharePoint/OneDrive/Teams). After a purge, RESET the M365
  cursors (/var/lib/omni-m365/state.json signins/audits to now-24h) to
  repopulate -> fetch 510 + activity 1006 events. riskDetections 403 = Entra
  P2 required (known). PYTHON PITFALL: always make datetimes aware
  (tzinfo=utc) before comparison/subtraction with now(timezone.utc).
- **GeoIP lookup omni-geoip-city**: has_error=true BUT table UNUSED
  (no rule calls it; the GeoIP Resolver processor populates
  src_ip_geolocation = mapping works). Harmless leftover.
- **vSphere ESXi noise drop (06/12)**: 87% of the vSphere volume = ESXi noise
  (vSAN traces, osfsd, envoy-access, vmkwarning; application_name EMPTY on the
  ESXi side -> filtering on the message CONTENT). Rule omni-vsphere-00-drop-
  esxi-bruit (stage 0). Result: 26k->7.7k/5min (-70%, ~2.2M/d instead of
  7.6M/d), only vCenter + useful ESXi auth/events remain. Keeps hostd/vpxa/
  sshd/shell/vobd. In 19-vsphere.sh.
- **Veeam CONFIRMED OK (06/12)**: "Veeam Backup" channel reporting (appears as
  soon as a job runs; 0 between two jobs = normal). Job "[1 heure] VM Backup
  critical" on BX-VAULTWARDEN STILL FAILS (tag veeam_job_echec set,
  mail alert sent) -> TO BE FIXED on the Veeam side (Julien's action).
- **SOAR_WHITELIST applied (06/12)**: 159.180.234.120, 92.184.107.14,
  92.184.96.118 (successful VPN connections France, logs) + 81.255.193.131
  (Ivry site public IP, conf H_IVRY_PUB). Tested (whitelisted IP not
  blocked). TO BE COMPLETED by Julien: Bordeaux/PACA sites public egress IPs
  + IPsec tunnel remote-gw (the 92.184.x may be dynamic
  residential -> to be reviewed). Edit 00-vars.env + systemctl restart omni-soar.
- **REBOOT/BOOT verified 06/12**: all services enabled (mongod,
  opensearch, graylog-server, nginx, nftables, omni-soar) + all timers
  enabled; /data in fstab (xfs UUID, mounted before the services). Hardened:
  drop-in /etc/systemd/system/graylog-server.service.d/10-omni-deps.conf
  (After/Wants mongod+opensearch) to guarantee the order. Graylog
  Restart=on-failure. => restarts cleanly on its own at boot.
- **CERTIFICATE MONITORING** (`/usr/local/sbin/omni-cert-check` + timer
  omni-cert-check weekly Monday 07:30): GELF alert (event_source=siem_cert)
  if a cert expires in <45d -> alert "OMNI - SIEM certificate expiring
  soon" (44 defs). Current certs: console/api graylog.crt expires
  10/06/2028 (728d, issued by PKI AD CS), Root CA 2033. Auto renewal =
  depends on infra (NDES/SCEP -> certmonger; otherwise Windows certreq script that
  pushes via the SMB share; or manual). The internal stream now routes
  siem_backup/disk_guard/report/soar/cert.
- **FLEET CERTIFICATE MONITORING (06/12)**: `windows/Get-OmniCertExpiry.ps1`
  (auto-detects PKI -> CA database via certutil, otherwise LocalMachine\My store)
  writes certs expiring <60d to the Windows "OMNI-Certificats" log
  (EventID 9001), collected by winlogbeat (channel added to winlogbeat.yml).
  Pipeline `omni-winother-10-cert-parc` parses (cert_subject/days/store/machine)
  -> alert "OMNI - Fleet certificate expiring soon" (P3 mail, key cert_machine,
  grace 23h). TO BE DEPLOYED by Julien via NinjaOne on the PKI (10.33.50.248) +
  critical servers. Script + winlogbeat.yml on /kit.
- **SIEM CERT AUTO RENEWAL (CERTREQ chosen, 06/12)**: SCEP/NDES
  abandoned (SIEM->NDES connectivity never opened + NDES template reconfig
  tricky). Solution: CSR generated and signed WITHOUT the key leaving the
  SIEM. `/usr/local/sbin/omni-cert-renew` (+ daily timer 06:00): if the
  cert expires in <30d, generates key.new+CSR, deposits on //10.33.50.5/Public/
  SIEM/certs/graylog.csr; when graylog-signed.crt comes back (modulus
  verified), installs + reloads nginx + GELF. Windows side:
  `windows/Sign-OmniSiemCsr.ps1` (on /kit) - certreq -submit template
  WebServer, deposits the signed cert. TO BE DEPLOYED on the PKI (10.33.50.248) as a
  scheduled task (account with Enroll right on WebServer). FIREWALL: NOTHING
  to open if the signer is on the PKI (local CA + Files share same VLAN
  50); SIEM->Files 445 already open (backups). certmonger installed but
  unused. Remove the FortiGate SIEM->NDES rule.
- **CERT RENEWAL TESTED OK 06/12**: certreq cycle validated end
  to end. Template = **OMS-WebServer** (NOT standard WebServer; name
  hardcoded in Sign-OmniSiemCsr.ps1 and Install-OmniCertTasks). New cert
  installed (serial ...69D3F9, expires 11/06/2028, SAN OK). SIEM side everything
  automatic (timer omni-cert-renew daily 06:00, triggered at D-30).
  REMAINING: create the PKI task OMNI-SiemCertSign (auto signature) via
  Install-OmniCertTasks-PKI.ps1 -SignerUser/-SignerPassword (account with
  Enroll on OMS-WebServer + write access to the SIEM/certs share).
- **GELF/streams PITFALL**: the OMNI-M365 stream routes by gl2_source_input
  (the GELF input 12201) -> it SWALLOWS every GELF message (backup, disk-guard).
  Solution: stream "OMNI - Interne SIEM" (OR matching on event_source =
  siem_backup / siem_disk_guard, default index set), created by 21 [4/4],
  and the 4 self-monitoring defs re-pointed to it (re-pointing
  idempotent at the end of 21). The dashboard's Backups page includes it.
  Remaining on Julien's side: apply fortigate/01 (UTM), 02 (FAZ filters),
  03 (VPN hardening); run Install-OmniSiem on the fleet + Veeam
  server; M365 riskDetections requires Entra P2 (pending).
- **Dashboards v3 - OMNI - SOC 17 pages** (`14-graylog-dashboards.sh` v3,
  enriched Python builder). Added **Direction** page (executive posture,
  10 s read). Extended generator (validated live + probe then deleted):
  KPIs with **D/D-1 trend** (visualization_config trend, dir=LOWER/HIGHER
  -> by default on all numeric KPIs); **multi-metric** tables
  (metrics=[("count"|fn,field,label)] -> series search_type + widget);
  **pivot2** (2nd row_group), **area** charts, **event annotations**
  (event_annotation) on timelines. **Alerts** page re-anchored on
  `alert_tag` (because `alert:true`/`priority` = 0: detections = pipeline tags,
  not Graylog Events; ~10.8k alert_tag/24h).
  FIELD TYPE PITFALL: sentbyte/rcvdbyte/duration are mapped **keyword**
  (the key_value parser yields strings) -> sum()/avg() => illegal_argument.
  FIX: rule `omni-forti-05-octets` (12, stage 5) which creates **bytes_sent /
  bytes_rcvd / bytes_total** via to_long (mapped **long** from the 1st occurrence)
  -> bandwidth aggregations OK (applies to NEW logs; sum
  tested = 12 TB/h). Network enriched: volume KPIs, "Bandwidth (24h)"
  (area sum), top talkers by volume, top dest by bytes. cert_days = long
  (the [0 TO 15] thresholds are correct).
- **Dashboards: per-widget windows + detection detail.** DSL `range=`
  (seconds) -> timerange override SET on the widget AND its search_type
  (`_tr(w)`, validated live: persists on both). Constants D7=604800 /
  D30=2592000. Applied to RARE EVENT DETECTORS (50 widgets):
  PKI/ADCS, priv group changes (4728/4732/4756), DCSync/Kerberoasting,
  vSphere shell/VM destroy, M365 forward/share/risk, VPN SSL brute force,
  audit tampering -> 7d or 30d instead of 24h (otherwise empty in a quiet period).
  The triage lists switch to `show_message=True` + discriminating fields
  (who/what/where + raw message) = "detail of what triggered it". Auto audit
  (page extraction + API check: empty q, empty dim, metric type, overlaps)
  = 0 overlap / 0 invalid dim / 0 non-num metric. NB: many
  "empty over 24h" widgets are LEGITIMATE rare detectors (not bugs):
  field/value names verified correct (gestion_comptes, fwd_target,
  priv_group_label exist, just no recent occurrence).
- **Dashboards: legends + enrichment.** No native text/markdown widget
  in Graylog OSS -> legends go through the widget's **`description`**
  field (DSL `desc=`, validated: persists, shown as ⓘ next to the title).
  Series **`latest(timestamp)`** OK -> Collection Health page: table "Last
  activity by host (7d)" = detection of **silent hosts** (agent stopped / host
  offline). Endpoint page reworked: **parent -> child** chains (pivot2
  parent_process/process_name), top command lines, multi-metric tables
  (count + card(host)), trends, annotated area, detailed 7d triage. Direction:
  legends on all KPIs (management read). Schema probe: POST
  /views accepted ONLY with the {entity, share_request} envelope (otherwise
  "entity cannot be null"); the POST /views/search refuses it -> keep
  post_entity() which handles both.
- **MITRE ATT&CK + risk score** (`37-mitre-attack.sh`, NEW script).
  CSV `lookups/mitre-attack.csv` (alert_tag -> technique/name/tactic/severity/
  score) -> 5 omni-mitre-* lookup tables. DEDICATED pipeline **"OMNI - ATT&CK
  Enrichment"** at **stage 20** (thus AFTER the alert_tag are set at stage 10/11),
  connected to the 6 detection streams -> sets mitre_technique / mitre_tactic /
  mitre_technique_name / risk_severity / **risk_score (to_long -> long)**.
  Applies to NEW detections. Pitfalls: the pipeline must be at a stage
  > the one that sets alert_tag (otherwise empty); re-run 37 if you add
  alert_tag. Dashboard: **ATT&CK** page (coverage by tactic, **heatmap**
  tactic x technique, techniques/hosts, severity, score) + **Top hosts/accounts
  by risk score** on Direction. ALERT (in 13): "OMNI - High-risk host
  (MITRE score >=15 /1h)" P2, group_by host, sum(risk_score), 60/5 min,
  Teams notif (helper sum_ge) -> catches a CHAIN of detections.
  mitre CSV completed: +defender (T1204.002) +ransomware_indicator (T1486);
  MITRE coverage of the ATTACK alert_tag. OPERATIONAL tags deliberately NOT
  mapped to MITRE (hygiene/state, not a technique): cert_expire_parc, vuln_kev,
  vuln_patch, host_go_dark, siem_job_fail (colored but outside ATT&CK = normal).
  Weekly report (`/usr/local/sbin/omni-weekly-report`) enriched: section "Threats
  & risk - MITRE ATT&CK" (helper top_sum: top hosts/accounts by sum(risk_score),
  top techniques/tactics, critical detections). Dashboard: "silent hosts" table
  sorted `sort_asc` on latest(timestamp) (DSL sort_on/sort_asc).
- **Vulnerability management (Wazuh-style, without a dedicated agent)** - Julien's
  choice: PowerShell collector + KEV/CVSS + patch age.
  * `windows/Get-OmniInventory.ps1` (/kit): software (Uninstall registry 64/32)
    + OS/build + last KB/date -> **OMNI-Inventaire** log (9101 software,
    9102 OS), format key=value|... . Channel in winlogbeat.yml. DEPLOYMENT:
    integrated into **Install-OmniSiem-NinjaOne.ps1** (downloads the script + creates the
    daily OMNI-Inventory SYSTEM task + 1st inventory immediately) -> a single
    NinjaOne launch is enough. Otherwise the Vulnerabilities page is empty.
  * Pipeline (12) `omni-winother-00-inventory` -> event_source=inventory
    (inv_product/inv_version / os_build/os_last_patch). Winother stream.
  * `/usr/local/sbin/omni-vuln-scan` + `38-vuln-scan.sh` (timer 07:15): CISA
    **KEV** (~1600 exploited CVEs, 7d cache), matching by distinctive words+subset
    (few FP: Acrobat 22 / Exchange 18 / vCenter 10), **CVSS** NVD best-effort
    (cache, rate-limit, VULN_NVD_MAX) + **patch age** (VULN_PATCH_MAX_DAYS
    def 35d). GELF event_source=vuln (alert_tag vuln_kev/vuln_patch). Page
    dashboard **Vulnerabilites** (S(INT), page_range 28h). Score integrated into Direction.
  * GELF PITFALL: `host` RESERVED (=sender->source). Target host in `_vuln_host`
    -> rule `omni-enrich-20-vuln-host` (Enrichment pipeline, connected ALSO to
    INT) copies it into `host`. mitre rule excludes `has_field(vuln_type)` (otherwise
    it overwrites risk_score). DUP PITFALL: the M365 stream swallows all GELF -> double index
    set -> 38 sets an INVERTED rule event_source!=vuln/siem_vuln on M365.
- **Dashboards DSL ++**: `desc=` (widget legend, `description` field -> ⓘ),
  global highlighting `COMMON_HL` (red/orange by threshold & value, 30 rules),
  viz **heatmap** (visualization_config color_scale Viridis). PITFALL: the
  **dashboard parameters (value-parameter-v1) are ENTERPRISE** -> they mark the
  view `requires: Graylog Enterprise` = "missing requirement" in OSS. REMOVED
  (`PARAMS = []`). Drill-down on the **Investigation** page via the native SEARCH
  BAR (page query, OSS): typing host:.../user:... filters all
  the widgets. Per-page DSL `query_string` kept but not used for parameters.
  19 pages. **4 heatmaps**: Alerts type x hour (DSL `coltime=True` = time in
  COLUMN), AD Identity account x host (spraying), ATT&CK tactic x technique,
  Network srccountry x dest_country (deny). DSL `page_range=` (page timerange):
  Investigation defaults to 7d. Graylog's native time selector already covers the
  need for an interactive "time range" (no dedicated parameter).
  NB decorators: little value in Graylog OSS (highlighting covers the visual
  need) -> deliberately not implemented.
  Confirmed PITFALL: Windows event-id field = `winlogbeat_winlog_event_id`
  (raw) + `event_id` (normalized); NOT `winlog_event_id`. FortiGate country
  field = `srccountry` (src_country=419 = M365 only). Idempotent build.
- **Dashboards v4 (consistency/legibility review, 13/06/2026)**:
  - **"Synthese" page REMOVED** (≈80% redundant with Direction: same KPIs +
    area by source + detections bar + at-risk hosts table). Architecture clarified
    into 3 levels: Direction (exec steering) / Alerts+Health (triage) / business pages
    (depth) + Investigation. **19 -> 19 pages** (Synthese replaced, not added).
  - **"privileged groups modified" duplicate** removed from *Accounts & compliance*
    (KPI+table) -> replaced with account lifecycle (4725 disabled / 4722 re-enabled
    / 4726 deleted); remains on the dedicated *Privileged accounts* page.
  - **2 VPN maps** (Mapping vs VPN & Exposure) clarified as
    COMPLEMENTARY via `desc` (all accesses vs origin of portal attacks only).
  - **Descriptions layer ⓘ** added on all business-page KPIs (AD Identity,
    M365, Network, vSphere, Privileged accounts/compliance, VPN, Backups,
    Certificates): meaning of the number + what a spike implies.
- **Bytes -> GB/TB (volume legibility)**: Graylog 7.1.3 OSS **has NO native field
  units** (endpoint `/system/units` = 404, the series carries no `unit`;
  that's Enterprise/recent build). DO NOT circumvent the license. Instead, conversion
  **fixed at ingestion** in `omni-forti-05-octets` (12, stage 5):
  `bytes_total_gb/sent_gb/rcvd_gb` (GB = /1e9 decimal, network convention) + 
  `bytes_total_tb` (TB = /1e12), via `to_double(...) / 1e9`. Network page: total KPIs
  in **TB**, rankings by host/app/dest in **GB** (unit adapted to context).
  Verified: event 60 bytes -> bytes_total_gb=6e-08 (OK); 17.5k events enriched /600s.
  **double** fields (auto ES mapping, NOT keyword -> summable). Applies to traffic
  AFTER the update (history without these fields). Build v4: requires={} (OSS).
- **Dashboards v4.1 (data-driven audit + enrichment, 13/06/2026)**:
  - **alert_tag coverage audit** (OpenSearch terms agg 30d vs COMMON_HL vs MITRE CSV,
    script type /tmp/audit_dash.py): only `m365_mailbox_deleg` was missing a color
    -> added (ORANGE). `cert_expire_parc` deliberately left WITHOUT a flat color
    (already colored GRADUATED by cert_days <=30 orange / <=15 red). Colored/mapped
    tags "never seen" (canary, dcsync, ransomware...) = intentional (pre-armed).
  - **Dead fields audit**: 7 fields with no data over 30d but ALL with the right name
    (verified vs senders) -> NO widget removed. `latest(timestamp)`=false positive
    (series ref); `priv_group_label`/`cert_subject_disp`=rare/PKI (AD CS audit to enable);
    `vuln_*`/`patch_age_days`=pending inventory. Rule: correct field + rare data
    != dead widget.
  - **"first appearance" widgets (baselining)** added at the bottom of Hunting: new hosts,
    new processes, new admin accounts, via series **min(timestamp)** (date,
    sortable; symmetric to latest()). CAVEAT: "first appearance" = 1st seen WITHIN the
    retention (old hosts group at the retention floor; the TOP of the descending sort
    = actually new). go-dark already covered (Collection Health table); D/D-1 already
    covered (dir= trend arrows); SLA % collection NOT done (requires a
    list of expected assets / CMDB, not wired).
  - **Page order** made thematic via Python sort key `ORDER[]` (no block
    moved, robust): Direction, Alerts, ATT&CK, Collection Health, AD Identity,
    Privileged accounts, Accounts & compliance, M365, M365 Activity, Endpoint, Hunting,
    Network, VPN & Exposure, Mapping, vSphere, Backups, Certificates,
    Vulnerabilities, Investigation. Safeguard: pages outside ORDER -> end + warning.
  - ⓘ layer extended to 100% of KPIs (Alerts, M365 Activity, Hunting, Mapping,
    remaining Endpoint). Build v4.1 verified: requires={}, 19 tabs, min(timestamp) OK.
- **Collection monitoring / SLA + go-dark (39-collect-health.sh, 13/06/2026)**:
  New collector `/usr/local/sbin/omni-collect-health` (omni-vuln-scan pattern):
  derives the "managed" fleet from the baseline (host seen < COLLECT_MANAGED_DAYS=14d), computes
  last_seen per host (max timestamp over AGENT indices: windows/sysmon/winother/
  fortigate/vsphere; EXCLUDES M365 cloud + internal), go-dark = silent > COLLECT_GO_DARK_HOURS
  =26h, coverage = active24h/managed*100. Emits GELF event_source=collecte_sla:
  1 event sla_type=summary (sla_coverage_pct/expected/active_24h/go_dark) + 1 per host
  sla_type=go_dark (alert_tag=host_go_dark, field **dark_host**, hours_silent, last_seen).
  Hourly timer (minute 07). 1st real run: managed=72, coverage=100%, go-dark=0.
  PITFALLS encountered:
  - load_env (regex `[A-Z_]+=(.*)`) does NOT strip INLINE comments -> put
    the 00-vars.env comments on a SEPARATE line (otherwise float("26' # ...") KO).
  - stream "OMNI - Interne SIEM" writes to the DEFAULT INDEX SET (graylog_0), not an
    omni-* -> search by STREAM, not by `omni-*` index. Routing: OR rule
    event_source=collecte_sla on INT (39) + inverse exclusion on M365 (anti-dup).
  - freshly created stream rule: ~few s of propagation before effective routing
    (39's 1st immediate scan can land in Default only; the following ones OK).
  - MITRE enrich (37): added `AND NOT has_field("sla_type")` (otherwise mitre_*
    fields EMPTY set on go-dark -> would pollute ATT&CK since ""="exists" in ES).
  Dashboard: "Collection coverage (SLA)" section on Collection Health (INT stream added):
  coverage% KPI (latest, dir=HIGHER) + managed/active/go-dark + go-dark table+messages
  (range 7200s = last pass, avoids re-covered hosts). host_go_dark ORANGE.
  Alert 13: "OMNI - Host go-dark (>26h)" P2, group_by dark_host, count>=1, within90/
  every60 min. ANTI-STORM: 13's global sync forces grace by priority (P3=10/P2=30
  min) -> exception `case *go-dark*) GRACE=21600000` (6h) for a PERSISTENT condition.
  Helper ensure_event: optional 10th arg grace_min (default 10). REMAINING: SLA based on
  a sliding baseline (not a CMDB) -> a host never connected is not "expected".
- **UEBA / NDR layer "beyond Graylog" (40-ueba-ndr.sh, 13/06/2026)**: 4 collectors
  /usr/local/sbin (GELF->INT->enriched pattern), computing what Graylog aggregation
  can't. Common safeguard: env `UEBA_DRY=1` = compute without emitting (test).
  - **omni-ueba-volume**: volume anomaly per event_source, z-score on the
    SAME-HOUR-OF-DAY baseline (date_histogram 1h, grouped by hour-of-day in Python). alert_tag
    volume_spike (z>=4) / volume_drop (z<=-3, mean>=50). LIMIT: short retention
    (~1-5 d depending on source -> MIN_SAMP=3); FP during onboarding (legitimate
    growth); improves as the history grows (raise UEBA_VOL_MINSAMP to 7-14).
  - **omni-ueba-geo**: impossible travel. Haversine between 2 consecutive connections
    (M365 signin + VPN, user field); speed>UEBA_GEO_SPEED(900km/h) & dist>500km.
    Geoloc = src_ip_geolocation/remip_geolocation "lat,lon" (COUNTRY centroid -> conservative,
    intra-country=0). alert_tag impossible_travel. Verified: Paris->NY 1h=5837km/h raised,
    Paris->Bordeaux 3h=166km/h not raised.
  - **omni-ndr-beacon**: beaconing/C2. INTERNAL src->EXTERNAL dest pairs (booleans
    src_ip_reserved_ip/dest_ip_reserved_ip), composite agg, then CV (std dev/mean)
    of inter-connection intervals; beacon = CV<=0.25 & median interval 15-3600s.
    PERF: allowlist of prefixes (DNS/MS/Google/CF, NDR_ALLOW_PREFIX) applied BEFORE the
    timestamps fetch -> 3min->10s (×18) and 11 FP -> 3 candidates. alert_tag beaconing.
    HONEST: legitimate SaaS also "beats" -> exposure to triage (extend the allowlist).
  - **omni-ueba-score**: UEBA entity score 0-100 (host AND account), soft saturation
    100*(1-exp(-raw/K)), K=20. DETECTIONS factor = sum of max(risk_score) PER DISTINCT
    alert_tag (severity-diversity, NOT volume -> otherwise everything saturates to 100). + go-dark
    (W=15, host), beaconing (W=12, per src_ip), authfail (account). Double-counting PITFALL:
    impossible_travel is in the MITRE CSV -> already feeds 'detections' via user ->
    NO separate geo weight. Verified: host distribution 18-83 (discriminating).
  The 4 alert_tag (volume_spike/drop, impossible_travel, beaconing) ADDED to the MITRE CSV
  (37) -> risk_score + technique (T1048/T1562.001/T1078/T1071) + ATT&CK page + UEBA
  detections factor. CSV reloaded auto within 60s (check_interval adapter). ueba_score has NO
  alert_tag (carries ueba_score) -> not enriched (normal). Routing 40: 4 event_source -> INT
  (OR) + M365 exclusion (anti-dup). 4 staggered timers (volume hourly, geo/score 30min,
  beacon 6h). Dashboard: "UEBA / NDR" page (pos 4, after ATT&CK; 20 pages); SHORT
  windows (2100s score, 25200s beacon) = last pass (avoids run duplicates).
  COMMON_HL: impossible_travel/beaconing RED, volume_* ORANGE, ueba_score>=40 orange/
  >=70 red (ORANGE before RED = precedence). Alerts 13: impossible_travel P3,
  beaconing/UEBA(>=80) P2, volume P3; all anti-storm 6h (extended sync exception
  *go-dark*|*Impossible*|*Beaconing*|*Anomalie de volume*|*UEBA* since re-emitted every cycle).
  Helpers 13: max_series/max_ge added.
- **ISO 27001 retention / capacity (41-retention-iso.sh, 13/06/2026)**: capacity analysis
  + tiered retention. MEASURED: ~29 GB/day ON DISK (compressed, 0 replica, single-node);
  breakdown fortigate 13 (45%) / winsec 7.5 / sysmon 4.9 / winother 2.7 / vsphere 0.6 /
  m365 0.02. Disk /data = 7.3 TB usable, disk-guard safeguard at 80% -> ceiling ~5.8 TB.
  CORRECTION: retention was NOT at 4d -> index sets already TimeBased P1D + retention
  180-365d; the ~4d visible = YOUNG SIEM (~5d). REAL ISO risk: at 29 GB/d the policy
  would consume ~7 TB > 80% -> disk-guard would purge before term -> displayed retention NOT met.
  ISO 27001 A.8.15: NO fixed duration imposed -> documented + met + integrity risk-based
  policy. SOLUTION (fits in 5.8 TB): (1) TRIM pipeline stage 30 (AFTER detection):
  drop Sysmon EID12 (registry add/del, 62% sysmon; persistence=EID13 kept), winsec 4673
  (priv use) + 4627 (group membership, redundant with 4624). KEEP 4662 (DCSync) + 4688 (process).
  Verified in prod: EID12/4673/4627 -> ~0 indexed, EID1/4624 -> OK. (2) TIERED retention:
  security (winsec/sysmon/winother/m365/vsphere) -> 365d, fortigate -> 90d (traffic, forensic
  window sufficient). Projection ~5.1 TB = 12-month security dossier within 80%. (3) audit
  evidence -> docs/POLITIQUE-RETENTION.md (maps A.8.15/16/17, risk-accepted exclusions).
  PITFALL avoided: NO best_compression codec via ES template (would break the Graylog mappings
  of the composable index sets) -> not done, the trim+tiering is enough. set_retention() = GET index
  set + jq max_number_of_indices + PUT. Reversible (removing rules = restores collection).
  REMAINING: to gain more, fortigate 90->60d, or split security/traffic index set, or +disk.
- **Real-time cyber map (42-carte-cyber.sh / omni-geo-flux, 13/06/2026)**: ANIMATED flow arcs
  source->company (outside Graylog: its world-map only does points). Generator
  /usr/local/sbin/omni-geo-flux aggregates over a sliding window (GEO_FLUX_WINDOW_MIN=10) the
  geolocated security flows: FortiGate deny (src_ip_geolocation "lat,lon" + srccountry), threat_intel,
  m365_etranger, VPN portal attacks (remip_geolocation); groups by (lat,lon rounded to 0.5) +
  type -> arcs (top GEO_FLUX_MAX=160) -> /var/www/siem-kit/flux.json. Pure canvas page (zero lib,
  100% local, no CDN/leak) /var/www/siem-kit/carte-cyber.html: equirectangular projection,
  background carte-world.geojson (177 countries, downloaded 1x), quadratic Bezier arcs + moving pulses,
  SOC theme, live HUD, 30s refresh. Served by nginx /kit/ (already in place, STATIC WITHOUT AUTH ->
  add auth_basic if deemed sensitive). HQ = GEO_HQ_LAT/LON/NAME (Bordeaux 44.88,-0.55). Timer
  omni-geo-flux 30s (OnUnitActiveSec). URL: https://<fqdn>/kit/carte-cyber.html. Verified: nginx
  200 on the 3 files, geojson/flux.json contracts OK (1st run: 110 flows, 37 countries, 2390 deny/10min).
  Static preview reproducible in pure SVG (without browser/lib) if a capture is needed.
- **DNS exfiltration / tunneling (43-ndr-dns.sh / omni-ndr-dns, 13/06/2026)**: NDR detector
  (beyond Graylog: Shannon entropy + subdomain structure). On Sysmon EID22
  (dns_query, 448k/24h): terms agg (size 40000) over a window NDR_DNS_WINDOW_H=6h -> groups
  by eTLD+1 (approx 2 labels, 3 if co.uk/com.au...) -> per domain: number of distinct subdomains,
  average entropy, average length. Flag if distinct>=40 AND entropy>=3.6 AND length>=20 (tune
  NDR_DNS_*). Allowlist (NDR_DNS_ALLOW): in-addr.arpa/ip6.arpa (reverse), internal AD domain,
  CDN/cloud (googlevideo/azure/cloudfront/akamai/office/apple...). Host attribution via wildcard
  dns_query *domain + terms host. Emits event_source=ndr_dns alert_tag=dns_tunneling (entity_host,
  dns_domain, dns_distinct_sub/avg_entropy/avg_len). Maps MITRE T1071.004 (DNS) score 8 (CSV).
  CALIBRATED: 208 domains, 0 FP even with relaxed thresholds (after allowlist, legit domains = few
  short/low subdomains); synthetic base32 tunnel (120 subdomains) entropy 4.18 len 32 ->
  DETECTED. entropy('wwwmailapi')=2.45 vs base32=3.8. Routing INT + M365 exclusion. Hourly timer.
  Dashboard: 2 widgets on the UEBA/NDR page (suspicious domains table + host detail). Alert 13: P2
  group dns_domain, anti-storm 6h (extended case grace *Tunneling*). COMMON_HL dns_tunneling RED.
- **Attack-chain correlation -> incidents (44-incidents.sh / omni-incident-correlate, 13/06/2026)**:
  aggregates by ENTITY (host/user) the MITRE detections of a window (INCIDENT_WINDOW_H=24h) and
  reconstructs the ordered KILL-CHAIN (canonical ATT&CK order CHAIN[]). Incident = >=2 distinct
  tactics. Saturated score 0-100 (K=30) = sum max(risk_score)/tactic + 3*(diversity-1).
  Emits event_source=incident (incident_entity, incident_score/severity/tactics/kill_chain/
  techniques/first_seen/last_seen/span_h). Nested agg: terms entity -> terms mitre_tactic ->
  max risk_score + min/max timestamp + terms technique/alert_tag. Verified: BX-VEEAM-IT-SV
  critical 70 = Execution->Defense Evasion->Credential Access->Impact(T1490 ransomware); 28
  incidents. NO MITRE mapping (no alert_tag -> not enriched). Route INT (graylog_0). Timer
  15min. Dashboard: "Incidents" PAGE (ORDER pos 3, after Alerts; 21 pages) - KPIs + table +
  pie + narrative messages. COMMON_HL incident_severity/score. Alert 13 P3 group incident_entity,
  grace 6h (case *Incident*). Includes the NDR/UEBA detections (already mapped to MITRE) in the chains.
- **Monthly executive PDF report (45-monthly-report.sh / omni-monthly-report, 13/06/2026)**:
  self-contained HTML calibrated to A4 (@page) -> REAL PDF via weasyprint. PDF ENGINE: wkhtmltopdf
  UNAVAILABLE on Debian 13; no pip/pango by default -> installs `apt python3-pip python3-venv
  libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0` + venv /opt/omni-venv with
  weasyprint 69 (CLI called via subprocess: weasyprint in.html out.pdf). Sections: 30d posture
  (KPI cards), kill-chain incidents, 30d threat SVG map (threat_map_svg, reuses the
  carte-world.geojson background + geolocated deny), top UEBA hosts/accounts, ATT&CK coverage, health/
  compliance/capacity. PITFALL: incident/ueba/collecte_sla/vuln are in graylog_0 (default index
  of the INT stream) NOT omni-* -> sorting on incident_score gave HTTP 400 (No mapping); fixed by
  targeting INT_IDX="graylog_0". Archive /var/www/siem-kit/rapports/rapport-AAAA-MM.{html,pdf}
  (served /kit/rapports/, nginx 200). Monthly email (1st of the month 06:00) PDF attached (SMTP
  REPORT_*). REPORT_NOMAIL=1 = generation without sending (test). Verified: PDF 51 KB valid v1.7.
- **Polish v5 (consistency/legibility/pedagogy, 13/06/2026)**: data-driven audit re-run
  (alert_tag color+MITRE, dead fields on omni-*,graylog_0) -> NO inconsistency: the
  "empty" fields (dark_host/dns_*/hours_silent/priv_group_label/cert_subject_disp) have the right
  name, 0 doc = rare/absent event (100% coverage, no tunnel...). Direction ELEVATED to
  an exec cockpit: 2 niche KPIs (M365 outside France, Certs<15d) replaced with "Critical
  incidents" (event_source:incident, card incident_entity, range 1200) + "UEBA at-risk entities
  >=70" (range 2100) -> led with CORRELATED RISK. Network lightened (20->18 widgets): removed
  VPN triage (redundant with VPN page) + "Action breakdown" pie (redundant with the area, area
  widened 8->12) + heatmap moved up row 23->19. PITFALL: no TEXT/markdown widget in Graylog
  OSS -> no explanatory banner per page; the explanation goes through desc ⓘ + GUIDE.md.
  **GUIDE.md** (root + /kit/docs/): plain-language doc "understand the SIEM in 15 min" for
  ANY reader (management/audit/newcomer) - flow diagram, role of each page, analyses
  explained simply, list of robots/timers, alert priorities, morning routine,
  GLOSSARY (LSASS/DCSync/beaconing/UEBA/KEV/entropy...). Build: 21 pages, requires={}.
- **Self-monitoring (46-self-health.sh / omni-self-health, 13/06/2026)**: "who watches the
  watchers" - checks via systemd (LoadState/Result/ExecMainExitTimestampMonotonic vs uptime)
  that the ~13 robots ran+succeeded recently. Emits siem_health (summary + job_fail/alert_tag
  siem_job_fail). Collection Health widget + alert 13 P3. Verified: 9/9 OK.
- **MULTI-AGENT review + fixes (siem-review-enrich workflow, 13/06/2026)**: 7 agents in
  parallel (analytical/ops collectors, dashboard, alerts/pipeline, deployment, frontend,
  cross-cutting consistency) -> findings VERIFIED adversarially against files+live -> 22
  confirmed. FIXED: #1(HIGH) omni-vuln-scan KEV emitted `host` (reserved GELF, lost) instead
  of `vuln_host` -> 0/322 KEV had host -> KEV KPIs + report at 0; fix `vuln_host` (rule
  37 copies -> host). VERIFIED: 59/59 fresh KEV have host. #2 omni-collect-health IDX `omni-windows*`
  (nonexistent index) -> `omni-winsec*` (winsec was excluded from the SLA). #3/#7/#13 map:
  reprojection of the arcs on resize (projectFlows()), UNCONDITIONAL start + fallback background if geojson KO,
  XSS escaping of the country name. #4 omni-ueba-score: beacon factor keyed by IP never applied
  -> beacon IPs added as entities. #5 dashboard: "Correlated Graylog events" widgets (empty
  query=all the volume, misleading) REMOVED. #6 alerts: empty key_spec -> GLOBAL anti-storm grace;
  fix = generate key_spec+field_spec(template ${source.<key>}) from group_by in the sync of 13
  (Graylog STRIPS key_spec without field_spec) -> 21/21 aggregated alerts have grace PER ENTITY.
  #10 month report in FR (MOIS_FR). #11 46 M365 block `&&||&&` (false message) -> if/else. #15 doc
  CONTEXT "100% MITRE" fixed (operational tags not mapped = normal). #17 self-health false
  positive post-reboot (age=uptime if never ran). #19 geo-flux country type = DOMINANT (not the 1st).
  #20 omni-ndr-dns DNS attribution at label boundary (term reg OR *.reg). #21 report SVG ring[::2]
  +fill-rule evenodd. #22 threatintel +CGNAT 100.64/10 +link-local 169.254/16. #12 warn M365 absent
  in 43/44. NOT fixed (low/no impact): #8 ueba-geo IPsec (0 live result), #9 brute-force
  VPN action ssl-login-fail (to check on the FAZ side), #14 beacon SKIP_PORTS, #16 parse ts (differences
  cancel out the offset), #18 map frame-rate. Final dashboard build: 21 pages, requires={}.
- **ISO 27001 documentation corpus (docs/, 13/06/2026)**: 6 supporting documents (FR, served
  /kit/docs/) to enable the later generation of the formal ISMS docs. INDEX-DOCUMENTATION.md
  (entry point + ISO preparation checklist), ISO27001-MAPPING.md (BRIDGE SIEM capabilities <->
  Annex A 2022: A.8.15/16/17, A.5.7/24-28, A.8.7/8/12/13, A.5.23... + evidence location),
  REGISTRE-DETECTIONS.md (54 rules by domain+MITRE+prio, factual via API), INVENTAIRE-SOURCES.md
  (7 sources, volume/retention/criticality), PROCEDURE-INCIDENT.md (A.5.24-28), PROCEDURE-EXPLOITATION-
  SIEM.md (daily/weekly/monthly routine, 13 robots, capacity). Real data: 54 alerts (35 P3,
  19 P2), 7 streams. To be done on the user side: CISO approval + SoA + management review.
- **Multi-agent pass 2: fixes + new detections (13/06/2026)**: 12 confirmed fixes
  + 14 feasible enrichments. APPLIED: #1/#4(HIGH) 5 internal event_source (siem_backup/
  disk_guard/report/soar/cert) routed to INT but NEVER excluded from M365 -> double-indexing
  (14 leaking docs). Fix: M365 exclusions live + in 21-alert-hygiene.sh (deferred purge = perm
  classifier). #2(HIGH) + #7/#8/#10 + OAuth = 47-detections-extra.sh: 5 detections (dedicated
  pipeline stage 10) gpo_modification(T1484.001; filter SID!=S-1-5-18 SYSTEM = HUMAN edits),
  asrep_roasting(T1558.004; 4768 PreAuthType==0), lolbin_suspect(T1218; certutil urlcache/
  regsvr32 scrobj/rundll32 js/mshta/bitsadmin), persistence_autorun(T1547.001; Sysmon13 Run -
  TAG ONLY no alert since ~85/d legitimate installers), m365_oauth_consent(T1528). +alerts 13
  (GPO/AS-REP P3, LOLBin/OAuth/M365-mass-delete P2). Fields VERIFIED live beforehand. #3 Veeam:
  FR levels (error/warning) + warning message (French OS, == "error" was dead). #11
  Direction tooltip "Failed accounts" = AD+M365 (not VPN). COMMON_HL +5 tags. LATENT BUG fixed:
  ensure_event set key_spec:$gb WITHOUT field_spec -> Graylog REFUSES any new aggregated alert;
  fix = generate field_spec(template) from group_by also at CREATION (not just in the sync).
  Total 59 alerts. NOT yet done: #5/#6 cert SANs/multi-cert, #9 canonical entity naming,
  #12 SYSVOL creds, + enrichments (network scan, off-hours, NTLM/Kerberos, M365 failure codes,
  east-west lateral, masquerading/hash). Dashboard 21 pages requires={}.
- **Enrichment: network scan detection (48-ndr-scan.sh / omni-ndr-scan, 13/06/2026)**:
  detects HORIZONTAL sweep (card dest_ip >= SCAN_HOST_MIN=30) / VERTICAL scan (card dest_port
  >= 25 on <= 3 hosts) from INTERNAL sources (src_ip_reserved_ip:true) on FortiGate deny,
  window SCAN_WINDOW_M=60. Targets lateral/internal recon (not the constant inbound Internet scan).
  Emits event_source=ndr_scan alert_tag=network_scan (entity_host, scan_type, dest/port count).
  MITRE T1046. Timer 15min, auto-monitored. Alert 13 P2 (grace 6h, *Scan*). UEBA/NDR widget +
  COMMON_HL orange. Verified: 4 real internal scans (10.13.50.5=35 dests...), enriched T1046 score5.
  PITFALL NOTE: the collectors read 00-vars.env (load_env) NOT os.environ -> the overrides via
  shell env var are IGNORED (test via importlib + override of the module globals, or edit
  the file). Only UEBA_DRY is read via os.environ (in gelf()).
- **Multi-agent enrichment batches 1+2 (49-enrich-lots.sh + 14/13, 13/06/2026)**: 10 enrichments
  designed by agents (parallel design, fields verified live), consolidated+applied by the main loop
  (read-only agents -> no conflict). PIPELINE (49, idempotent, canonical ensure_lookup in the header):
  off_hours/day_period (3 rules base+override on 4624/4625/m365 signin; to_date($message.timestamp)
  MANDATORY because timestamp=Object; format_date(...,"HH"/"e","Europe/Paris"); no if/else);
  account_class/is_admin (base+override: user/machine($)/service(svc/MSOL_/vpxuser)/admin(adm-);
  verified: user 6453/machine 2837/admin 465/service 151); masquerading T1036.005 (Sysmon EID1 system
  binary outside System32) + explicit_cred_use T1078 (4648) -> added to the Complementary Detections pipeline;
  forti_severity_num (lookup forti-severity.csv level->num + rule stage 5 -- TO WIRE into 12's PL_FORTI,
  done); m365_fail_label (lookup m365-status.csv status_code->FR label + rule; armed, 0 until any
  failure); port_class (lookup port-class.csv) + net_direction (cidr_match because reserved_ip is set by GeoIP
  AFTER pipelines -> unavailable in a rule; 3 rules internal/outbound/inbound via src_priv/dst_priv) + expo_internet
  T... (inbound+accept+risky port). DASHBOARD (widgets WRITTEN BY THE MAIN LOOP, not the agents whose
  code was inconsistent/badly anchored): east-west lateral (Network), NTLM vs Kerberos + off-hours admin (AD
  Identity), account_class pie + admin activity (Privileged accounts), M365 failures by cause (M365). COMMON_HL
  CURATED (strong signals only: masquerading/explicit_cred/exposition_internet/off_hours/expo_internet/NTLMv1/
  m365_fail_label; DROP service/port_class/admin/NTLM-all = too noisy). Alerts 13: off-hours admin P3,
  masquerading P2, explicit-cred P2. PITFALLS: agents sometimes put dashboard code in shell_blocks
  (filter), wrongly escape \$( (breaks subst), assume 47's helpers (add_mitre/CSV/WD -> in the header),
  if/else forbidden in pipeline (the agent used it anyway -> rewrite as base+override), starts_with/regex 3-args
  rejected (simplify). Verified: 5/5 pipeline fields populate; 63 alerts; requires={}.
- **Multi-agent enrichment batch 3 (50-enrich-lot3.sh, 13/06/2026)**: 5 depth detections,
  hardened instructions to the agents -> ZERO pitfall (no if/else, 3-args, dash-in-shell). The agents
  even WROTE 2 collectors directly via Bash (good quality). PIPELINE DETECTIONS (dedicated pipeline
  "OMNI - Detections Lot3" stage 10, winsec): gpp_creds_access T1552.006 (5145 SYSVOL + groups.xml/
  scheduledtasks/services/datasources.xml); kerberos_rc4 T1558.003 (4769 TicketEncryptionType==0x17
  RC4, ServiceName non-machine non-krbtgt; live=AES256 0x12 only -> armed); local_admin_add T1098
  (4732 TargetSid S-1-5-32-544 builtin local; live 4732=0 -> armed); local_account_create T1136.001
  (4720 outside DC). COLLECTORS (agents): omni-ndr-exfil T1048 (multi_terms internal src/external dest,
  sum bytes_sent > EXFIL_BYTES_GB=1GB/window; SIEM egress 160.79.104.10 in EXFIL_ALLOW_DEST=>0 FP;
  armed); omni-ueba-geo-newcountry T1078.004 (new country/account vs 30d baseline; reuses ueba_geo
  routing; alert_tag=new_country; 0 currently). MITRE CSV: 2 MALFORMED agent lines (desc in columns)
  -> rewritten correctly in 50. 6 alerts 13 (exfil/local-admin/local-create P2; gpp/rc4/new_country
  P3; kerberos_rc4 count_ge 5 anti-noise). COMMON_HL +6. exfil widget on UEBA/NDR. 2 collectors ->
  self-health (12/12 OK). + Cert SAN fix (omni-cert-renew: FQDN+short name+IP in the CSR, CERT_SAN_IP
  overridable). Total 69 alerts, requires={}. Collectors now read os.environ EXFIL_* (override).
- **Multi-agent enrichment batch 4 (51-enrich-lot4.sh, 13/06/2026)**: 5 advanced AD/identity
  detections, hardened instructions -> 0 pitfall (agents). PIPELINE "OMNI - Detections Lot4": wmi_lateral_exec
  T1047 (sysmon EID1 parent wmiprvse->LOLBin + EID19/20/21 WmiEvent; SCCM/monitoring exclusions);
  shadow_credentials T1556.005 (5136 AttributeLDAPDisplayName=msDS-KeyCredentialLink, actor !=S-1-5-18);
  adcs_abuse T1649 ESC1 (4886/4887 event_source=adcs, non-empty SAN via text signature negation + @) +
  ESC8 (AuthenticationService=NTLM) at stage 11 (after adcs base stage 10). COLLECTORS (agents):
  omni-ldap-recon T1087.002 (directory access spike 4662 per account); omni-ndr-lateral T1021 (1 account ->
  N hosts in successful 4624 type3/10). All ARMED (0 data = no attack). PITFALLS: 2 malformed agent MITRE
  lines (rewritten); WMI rule refused because `NOT lowercase(x) == "y"` (precedence: NOT binds the
  String before ==) -> fixed to `!= "y"`. The AD CS agent detected the FortiGate VoIP false-positive
  PITFALL (parasitic event_id=4887/4889 field in omni-fortigate) -> STRICT scope event_source==adcs. 5 alerts
  (AD CS/Shadow/LDAP P3, WMI/lateral P2). COMMON_HL +5. 2 collectors -> self-health (14/14 OK). Total
  74 alerts, requires={}. The QA of batches 1-3 (workflow) failed 2x on session limit -> to be re-run.
