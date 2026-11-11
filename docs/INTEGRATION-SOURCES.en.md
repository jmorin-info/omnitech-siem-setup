# Integrating new sources — ESET / NPS / BunkerWeb

> Procedure for adding the 3 sources. On the SIEM side everything is already provisioned
> (`52-new-sources.sh`). What remains / remained is the configuration **on the source side**, detailed here.
>
> **Reviewed: 2026-06-14.**

## Actual status of the 3 sources (as of 2026-06-14)

| Source | SIEM side | Source side | Data received |
|--------|-----------|-------------|----------------|
| **ESET PROTECT** (10.33.50.20) | ✅ Syslog TCP input 1515, stream `OMNI - ESET`, pipeline `eset_*` | ✅ syslog configured | ✅ **arriving** (low volume — occasional detections, `eset_*` fields parsed) |
| **BunkerWeb** (10.33.70.1, host `bx-waf-it-vm`) | ✅ stream `OMNI - BunkerWeb`, pipeline `http_*`/`waf_*` | ✅ **Filebeat deployed** (Docker logs) | ✅ **arriving** (~15.5k docs, nominal flow) |
| **NPS / RADIUS** (10.33.50.247, `bx-nps-it-vm`) | ✅ `win-events.csv` lookup + widgets/alert ready | ⚠️ Winlogbeat active but **Security channel missing** | ❌ **0× 6272/6273/6274** (see diagnostic §2) |

> ESET and BunkerWeb are therefore **operational**; the section covering them now
> serves as reference (config reminder) rather than a task to do. NPS remains the
> only source truly "pending" on the server side.

### Routing / retention per source

- **ESET**: dedicated index set `omni-eset`, **365-day retention** (forensics).
- **BunkerWeb**: dedicated index set `omni-bunkerweb`, **90-day retention** (volume).
- **NPS**: no dedicated index — the events land in the *Windows
  Security* stream (Windows retention = 365 days).

---

## 1. ESET PROTECT (10.33.50.20) — ✅ operational

**SIEM side (done):** *Syslog TCP* input on **1515** (TLS disabled on this
input), and the firewall **redirects 514 → 1515** (your ESET therefore stays on 514).
Stream `OMNI - ESET` (routed on the `gl2_source_input` of the ESET input). The pipeline
sets `event_source=eset`, parses the ESET JSON into **`eset_*`** fields
(`eset_event_type`, `eset_severity`, `eset_action`, `eset_hostname`, `eset_user`,
`eset_target`, `eset_detail`…), computes an **`eset_risk_score`** (lookup
`eset-severity`, default 3), an **`eset_outcome`** (remediated / not remediated) and
sets the **`eset_detection`** tag (`alert_tag`) on threats (`Threat_Event` /
`HipsAggregated_Event`). The rule `omni-eset-08-source-fix` rewrites `source` with
`eset_hostname` (fixing the `source=month` coming from the FR syslog).

**ESET PROTECT side (already configured by you):** syslog server
`10.33.50.20 → 10.33.220.10:514`, TCP, **syslog** format (ESET JSON payload).

> **Verified on 2026-06-14:** the events do arrive in `OMNI - ESET` and the
> `eset_*` fields are correctly extracted. Low volume (occasional
> detections) — this is expected, not a collection problem.

⚠️ **One point to check — the framing**: Graylog expects by
default **LF (non-transparent) framing**. If you chose
"octet-counting" (RFC 6587) and messages
arrive **stuck together/truncated**, switch ESET to **non-transparent / newline
(LF)**. Check arrival:
- Graylog console → *Search* → `gl2_source_input` of the ESET input, or stream
  `OMNI - ESET`. You should see the events within ~1 min.

---

## 2. NPS / RADIUS (10.33.50.247, `bx-nps-it-vm`) — ⚠️ pending on the server side

**SIEM side (already handled):** NPS events **6272** (access granted), **6273**
(denied), **6274** (rejected) are **automatically enriched** (lookup
`win-events.csv` → `event_action=acces_reseau_nps_*`, `event_category=nps`) and
appear in the *Windows Security* stream + the "NPS access denied" widget.
Nothing to create.

**NPS server side (to do):** deploy **Winlogbeat** (the same agent as the
rest of the estate) on `10.33.50.247`. The simplest way:
1. Run `Install-OmniSiem-NinjaOne.ps1` on this server (it installs Winlogbeat
   + Sysmon + the config, and 10.33.50.247 is already allowed on 5044 via the /16).
2. The NPS events are in the **Security** log (already collected by
   `winlogbeat.yml`). No additional config.

> Prerequisite on the NPS side: auditing must generate 6272-6274 (enabled by default if NPS
> is a RADIUS role; otherwise `auditpol /set /subcategory:"Network Policy Server"
> /success:enable /failure:enable`).

### Diagnostic (status as of 2026-06-14)

Observed during the audit: `bx-nps-it-vm` (10.33.50.247) **does emit via Beats 5044**
(~435 docs/24h) but **only Sysmon** — **no event from the Security channel**
(hence 0× 6272/6273/6274). Two possible causes, to fix on the server side:

1. **NPS auditing not enabled.** On **French** Windows, the English name of the
   subcategory fails → use the **GUID** (language-independent):
   ```powershell
   $g="{0CCE9243-69AE-11D9-BED3-505054503030}"
   auditpol /set /subcategory:$g /success:enable /failure:enable
   auditpol /get /subcategory:$g     # must show "Réussite et Échec"
   ```
2. **Winlogbeat is not collecting the Security channel on this server.** Verify that
   `C:\Program Files\winlogbeat\winlogbeat.yml` does contain
   `- name: Security` under `winlogbeat.event_logs:` (otherwise only Sysmon comes through).
   Redeploy via `Install-OmniSiem-NinjaOne.ps1` if the local config has drifted.

Then **trigger a RADIUS authentication** (6272/6273 are only emitted on
a real access request) and check on the SIEM side: search `event_id:6272`.
As long as this flow does not arrive, the **[NPS pending]** widgets of the
"External sources" page stay empty — this is expected, not a bug.

> On the SIEM side, **nothing to do**: the `win-events.csv` lookup already maps
> 6272/6273/6274 → `acces_reseau_nps_*`, the "NPS access denied" widget and
> the **P3 alert** "OMNI - NPS: mass access denial (≥10 / account / 15 min)"
> (script `13-graylog-alerts.sh`, on the Windows Security stream) are ready.

> **Verified on 2026-06-14:** still **0** event 6272/6273/6274 in the index —
> the NPS server's Security channel is not coming through yet (see causes above).

---

## 3. BunkerWeb (10.33.70.1, host `bx-waf-it-vm`) — Filebeat → Beats 5044 — ✅ operational

**SIEM side (done):** stream `OMNI - BunkerWeb`. ⚠️ **The stream is routed on the
`filebeat_event_source=bunkerweb` field** (and **not** `event_source`): Filebeat
sends a `fields.event_source` field that Graylog's Beats input **prefixes as
`filebeat_`**. It is only *afterwards*, in the pipeline, that the rule
`omni-bunkerweb-00-normalise` copies `filebeat_event_source` → `event_source`.
The pipeline then sets `event_category=waf`, parses the nginx/BunkerWeb accesses
(`src_ip`, `http_method`, `http_status`, `http_user_agent`, bytes, vhost,
HTTP class 2xx/3xx/4xx/5xx), sets the **`waf_block`** tag (HTTP 403 / ModSecurity),
detects **5xx backends** and **offensive tools** in the User-Agent, and
**drops ~97% of noise** (stderr/metrics) via `omni-bunkerweb-02-drop-noise`.
Reuses the existing **Beats TLS 5044** input (10.33.70.1 already allowed via the /16).

> **Verified on 2026-06-14:** nominal flow (~15.5k docs), `event_source=bunkerweb`
> properly set, HTTP parsing OK. The logs come from the **BunkerWeb Docker container**
> (`/var/lib/docker/containers/*/*-json.log`) — the actual deployment is the **Docker
> option** below, not the systemd package.

> ⚠️ **Key point if you redeploy Filebeat:** **do NOT set `fields_under_root:
> true`**. If you set it, `event_source` arrives at the root and is **not**
> prefixed `filebeat_` → the `OMNI - BunkerWeb` stream (which filters on
> `filebeat_event_source`) **will no longer match**. Let Filebeat put the field
> under `fields:` (default behavior, prefixed by Graylog).

### Steps (Debian)

**a. Install Filebeat (OSS):**
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-8.15.0-amd64.deb
sudo dpkg -i filebeat-oss-8.15.0-amd64.deb
```

**b. Copy the SIEM CA** (the Beats input is over TLS) to the server:
```bash
# from the SIEM, or fetch /etc/graylog/certs/omnitech-rootca.crt
sudo install -m 644 omnitech-rootca.crt /etc/filebeat/omnitech-rootca.crt
```

**c. Locate the BunkerWeb logs.** Depending on the installation:
- **Docker (actual deployment on `bx-waf-it-vm`)**: BunkerWeb runs in a container,
  its logs are written by the Docker json-file driver. Filebeat therefore points at
  `/var/lib/docker/containers/*/*-json.log` (the config uses the module/`add_docker_metadata`
  or per-container filtering; the stderr/metrics noise drop is done on the
  Graylog pipeline side, rule `omni-bunkerweb-02-drop-noise`).
- **Package/systemd** (another possible installation): `/var/log/bunkerweb/access.log`,
  `error.log`, and the ModSecurity audit `/var/log/bunkerweb/modsec_audit.log` (if enabled).

**d. `/etc/filebeat/filebeat.yml` — Docker variant (the one in production):**
```yaml
filebeat.inputs:
  - type: filestream
    id: bunkerweb
    paths:
      - /var/lib/docker/containers/*/*-json.log
    parsers:
      - container: ~                 # decodes the Docker json-log envelope
    fields:
      event_source: bunkerweb        # <- DO NOT set fields_under_root: true.
                                     #    Graylog prefixes -> filebeat_event_source,
                                     #    on which the OMNI - BunkerWeb stream filters.

output.logstash:                      # Beats protocol (= Graylog input 5044)
  hosts: ["10.33.220.10:5044"]
  ssl.certificate_authorities: ["/etc/filebeat/omnitech-rootca.crt"]

logging.level: warning
```

> **Package/systemd variant**: replace `paths:` with the `access.log` / `error.log`
> / `modsec_audit.log` of `/var/log/bunkerweb/` and remove the `container` parser.
> **Keep** `fields: { event_source: bunkerweb }` **without** `fields_under_root`.

**e. Start:**
```bash
sudo systemctl enable --now filebeat
sudo filebeat test output      # must show 'talk to server... OK'
```

**f. Check on the SIEM side**: the `OMNI - BunkerWeb` stream fills up within ~1 min.
Control search: `event_source:bunkerweb` (after pipeline normalization) or
`filebeat_event_source:bunkerweb` (raw field, immediate). The `source` field must
show the WAF host (`bx-waf-it-vm`).

### Agentless alternative (rsyslog)
If you prefer not to install Filebeat: configure BunkerWeb/nginx to log
in syslog to the SIEM, but a dedicated BunkerWeb syslog input will be needed (tell me,
I'll add it). **Filebeat remains recommended** (structured, access/ModSecurity parsing).

---

## Summary of flows to open (FortiGate, if inter-VLAN segmentation)
| Source | → SIEM | Port | Protocol |
|--------|--------|------|-----------|
| ESET 10.33.50.20 | 10.33.220.10 | **514** (→1515) | TCP syslog |
| NPS 10.33.50.247 | 10.33.220.10 | **5044** | TCP (Beats TLS) |
| BunkerWeb 10.33.70.1 | 10.33.220.10 | **5044** | TCP (Beats TLS) |

*The SIEM's LOCAL firewall is already open for these flows.*
