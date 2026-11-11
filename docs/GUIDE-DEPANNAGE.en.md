# Troubleshooting Guide — SIEM OMNITECH

*Version 1.1 — revised 14/06/2026 — Classification: internal. Format: symptom → cause → solution.
Exhaustive technical reference of resolved incidents: `CONTEXT.md` (section "PIÈGE À RETENIR").*

> Sources currently collected: AD/Sysmon (Winlogbeat, Beats TLS 5044), FortiGate (via
> FortiAnalyzer, syslog 1514 TCP/UDP), Microsoft 365 (GELF HTTP 12201, *pull* collection),
> vSphere (syslog 1516 TCP/UDP), Veeam (Windows channel), **ESET PROTECT** (syslog JSON TCP 1515,
> `eset_*` fields), **BunkerWeb WAF** (Filebeat on the shared Beats 5044, `http_*`/`waf_*` fields).
> **NPS** is mapped (lookup `win-events.csv`) but not yet forwarded on the client side.

## 1. Collection — a source stops reporting

| Symptom | Probable cause | Solution |
|---|---|---|
| A Windows **Security** channel silent, the others OK | `event_id` list too long in winlogbeat.yml (> ~23 expressions → ERROR_EVT_INVALID_QUERY) | Use **ranges** (`4624-4799`), never a flat list. Redeploy via `Install-OmniSiem-NinjaOne.ps1` |
| A host no longer appears at all | Agent stopped / firewall 5044 | On the host: `Get-Service winlogbeat`; test `Test-NetConnection <siem> -Port 5044` |
| FortiGate: only `voip` in UTM, no virus/IPS/web | UTM profiles not attached to policies | `fortigate/05/06-utm-*.conf`; check `show firewall policy <id>` |
| FortiGate: `source` = IP address instead of device name | Normalization rule not applied | The pipeline sets `source` = `host` field (rule `omni-forti-06-source-host`, script 12); verify the rule is in the FortiGate stage |
| FortiGate: timestamp shifted / events "in the future" | `timestamp` not realigned on the device's original time | The pipeline sets `timestamp` from `eventtime` (epoch ns → ms, rule `omni-forti-05-eventtime`, fixed 14/06) |
| vSphere: logs present but **0 host/event_action** | Pipeline stage `match either` with a single conditional rule → blocks the rest | Put the normalization in the same stage (fixed 12/06) |
| Veeam server: no "Veeam Backup" channel | No job since the last check (normal) **or** channel not collected | Wait for a job; otherwise re-run `Install-OmniSiem` (auto-detects the channel) |
| M365: very low volume / empty page | Collector crashed **or** cursor not replayed after a purge | `journalctl -u omni-m365-fetch` (and `omni-m365-activity`); reset cursor `/var/lib/omni-m365/state.json` |
| **ESET**: input 1515 empty while the ESET console is emitting | 514→1515 redirection missing on the firewall side, or ESET syslog disabled | ESET PROTECT (10.33.50.20) sends on **514**, redirected to 1515 by the firewall; check the `ESET (Syslog TCP 1515)` input and the redirection rule |
| **ESET**: messages received but not parsed (`eset_*` absent) | Non-JSON format or syslog prefix not stripped | The pipeline strips everything before the first `{` then `set_fields(..., "eset_")` (rule `omni-eset-05-json`); verify that `event_source=eset` is correctly set |
| **BunkerWeb**: WAF logs landing in "OMNI - Windows autres" | BunkerWeb shares the **Beats 5044** with Winlogbeat → routing by `filebeat_event_source` | Filebeat must set `filebeat_event_source=bunkerweb`; an exclusion rule (`inverted`) removes BunkerWeb from "OMNI - Windows autres" (script 52) |
| **NPS**: nothing reporting | Normal at this stage: mapped but not yet activated on the client side | NPS (10.33.50.247) will go through Winlogbeat/Beats 5044; mapping ready via lookup `win-events.csv` |
| **Vaultwarden**: vault logs in "OMNI - Windows autres" | Same Beats 5044 sharing → routing by `filebeat_event_source` | Filebeat must set `filebeat_event_source=vaultwarden`; exclusion (`inverted`) + **dedicated index `omni-vaultwarden`** (script 55). The "too many admin requests" noise (container loop) is dropped at the pipeline |
| **`src_hostname` empty** on internal FortiGate logs | DHCP attribution down | `systemctl status omni-fortidhcp-fetch.timer` + `journalctl -u omni-fortidhcp-fetch`; check FortiGate RO token + lookup `omni-dhcp-attribution` (script 56) |
| **Alert "Log integrity COMPROMISED"** | Hash chain broken (deletion/tampering) | `omni-integrity --verify`; compare `/var/lib/omni-integrity/chain.jsonl` with the SMB copy `/SIEM/integrity/`; freeze & investigate (script 60) |

## 2. Indexing — lost messages

| Symptom | Cause | Solution |
|---|---|---|
| **Indexer failures** > 0 (System → Indexer failures) | Typed field rejected (e.g. `src_ip` = "N/A"/"x.x"/ip:port) | Fix **at the source or the pipeline** (never loosen the mapping). Cf. clean_ip / IP regex |
| Search "empty" while logs are arriving | Index range not recalculated (after purge/manipulation) | `POST /api/system/indices/ranges/rebuild` |
| Everything looks empty over 24h/7d after a **purge** | Expected behavior: history was wiped, collection restarts from zero | Look at a "since the purge" window; agents do not replay history. Dashboard repopulation is handled by `54-post-purge-repopulate.sh` |
| A source older than its retention has disappeared | Expected behavior (retention per index set) | Retentions: **FortiGate 180 d**; Windows/Sysmon/vSphere/M365/ESET **365 d**; **BunkerWeb 90 d**. Disk `/data` = 7.3 TB |

## 3. Alerts — too many, or not enough

| Symptom | Cause | Solution |
|---|---|---|
| Storm of identical emails | Grace too short / no key / service failure counted as brute force | `21-alert-hygiene.sh` (grace ≥ 60 min, keys per account/IP, logon type 4/5 exclusion) |
| Too many alerts by email (not just the critical ones) | 2-tier routing not (re)applied | `22-alert-routing.sh`: **Teams = firehose** (all alerts, ~87); **email = critical "wake-me-up" only** (~26: confirmed compromise + SIEM health). To re-run after 13/21 |
| No more Teams alerts received | Power Automate flow throttled/broken (fails **silently**, Graylog receives 202) | Check the Power Automate flow's **run history** (not the Graylog logs) |
| No more critical emails received | Email notification removed from all definitions, or SMTP broken | Verify that `22-alert-routing.sh` did keep email on the `KEEP` list; test SMTP sending from Graylog |
| An alert never fires | The queried stream does not route the source; or `key_spec` without `field_spec` | Check the stream rules; every key must have a `field_spec` entry |
| Critical incident counted several times | Kill-chain duplicates | Dedup at the incident correlation level (`omni-incident-correlate`, fixed 14/06) |
| Recurring false positives | Detection too broad | Targeted exclusion **at the pipeline** (script 12/13/21), not in the console alone. Exclusions in place: machine accounts `*$` + service accounts (`ninjaone`, `ADSyncMSA`) for brute force; `wakeup-ssrs.ps1` for PowerShell; `vpxuser`/`dcui`/`localhost` for vSphere brute force |

## 4. Console / authentication

| Symptom | Cause | Solution |
|---|---|---|
| "invalid credentials" with an AD admin account | Port 636 (LDAPS) blocked → backend not created → AD account unknown | Open 636 (FortiGate rule 425) then `bash 33-ldaps-auth.sh` |
| AD login refused for a domain admin account | Wrong group DN in the filter | Retrieve the exact DN (`ldapsearch ... memberOf`); the group may be outside `CN=Users` |
| Console unreachable / JSON.parse loop | TLS misconfigured (truststore, http_publish_uri) | CA in `cacerts-omni.jks`, `http_publish_uri` = FQDN → 127.0.0.1 via /etc/hosts |

## 5. Backup / capacity / SOAR

| Symptom | Cause | Solution |
|---|---|---|
| Config backup fails (SMB) | CIFS mount refused (guest) / firewall 445 | `/root/.smb-siem.cred` (dedicated account, chmod 600); FortiGate rule Réseau ELK → Files 445 |
| `/data` filling up | Abnormal volume from a flow | `32-disk-guard.sh` (timer `omni-disk-guard`) alerts at 80%, emergency purge at 88%; review `41-retention-iso.sh` |
| SOAR: `diagnose` CLI fails on FortiGate | Command not supported by the version | Verify via **GUI** (External Connectors → View Entries); the SIEM nginx logs prove the poll |
| SOAR does not block the VPN portal | "local-in" traffic not filtered by a forward firewall policy | Use a **`local-in-policy`** (the portal listens on the appliance) |
| FortiGate does not read the feed (HTTPS) | OMNITECH Root CA missing from the FortiGate | Import the CA (*System → Certificates*) or serve the feed over HTTP |
| Console / fleet certificate near expiration | Continuous monitoring | `omni-cert-check` (continuous telemetry) alerts by email; console renewal automated via `omni-cert-renew` (CSR → AD CS over SMB) |

## 6. Clean purge / reset

| Symptom / need | Detail | Solution |
|---|---|---|
| Restart on empty indices without losing the config | After validating false-positive fixes | `53-purge-clean.sh`: deflector cycle + deletion of old indices via the API (streams, pipelines, lookups, inputs, alerts, dashboards preserved; `gl-system-events` preserved). **DESTRUCTIVE** |
| Dashboards empty right after a purge | Derived widgets not recomputed until the robots have re-run | `53-` automatically chains `54-post-purge-repopulate.sh` (rebuild ranges + re-fetch M365 + restart the robots). Disable the chaining: `PURGE_NO_REPOP=1` |
| After a purge, UEBA/NDR/vulnerabilities stay partially empty | Normal: UEBA baseline, NDR patterns over hours, daily vuln inventory all require fresh data | Wait for accumulation — this is not a bug |

## 7. Diagnostic reflexes (useful commands, on the SIEM)

```bash
# general state
systemctl status graylog-server opensearch mongod nginx
systemctl list-timers 'omni-*'
curl -s '127.0.0.1:9200/_cat/indices/omni-*?h=index,docs.count,store.size&s=index'

# throughput of a flow (5 min) — prefixes: omni-winsec omni-sysmon omni-winother
#   omni-fortigate omni-m365 omni-vsphere omni-eset omni-bunkerweb
curl -s "127.0.0.1:9200/omni-<flux>_*/_count" -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-5m"}}}}'

# is a host reporting?  (search source:<hostname> over 15 min via the console)

# collector journal
journalctl -u omni-m365-fetch -n 20
journalctl -u omni-m365-activity -n 20
tail -f /var/log/graylog-server/server.log
```

## 8. Graylog 7.x API pitfalls (to know before intervening at the pipeline)

- **No ternary** in pipeline rules: use `if/else`.
- `contains()` takes **2 arguments** (`contains(value, substring)`).
- On entity `POST`s, wrap the body in the expected `{entity}` **envelope**.
- Deflector cycle: `POST /system/deflector/{id}/cycle` (used by the purge).
- Single dashboard **"OMNI - SOC"** (24 pages): `requires={}` → 100% OSS, **no Enterprise**.

---

> For an incident not listed here: record symptom + resolution in `CONTEXT.md`
> (section "PIÈGE À RETENIR") to enrich this guide.
> See also: `INTEGRATION-SOURCES.md`, `POLITIQUE-RETENTION.md`, `PROCEDURE-INCIDENT.md`.
