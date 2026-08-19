# OMS-XDR Integration ↔ existing OMNITECH SIEM

**06/18/2026.** oms-xdr does **not** run in parallel with the SIEM: it grafts onto it as a
**correlation + LLM + response** layer, consuming the detections already produced.

## 1. Module → existing mapping

| oms-xdr module | Integration status | Decision |
|---|---|---|
| `correlation.py` + `rules.yaml` | **Rewired** onto `alert_tag` + normalized fields (`event_id`/`src_ip`/`user`/`host`) and real stream IDs | Consumes detections; overlaps `omni-incident-correlate` → **to arbitrate** (see §3) |
| `enrich.py` (Ollama/Mistral) | **Net-new** — this is the validated local LLM triage ("local first") | Keep; internal Ollama 10.33.120.55 |
| `remediation.py` (playbooks) | **Net-new**, structured by scenario; complements the `alert-explain` lookup (by tag) | Keep both (tag-level vs scenario-level) |
| `responder.py` (FGT/AD/Ninja) | **= the response actuators**; dry-run double-lock | FGT: **delegate to the `omni-soar` feed** (no direct FortiOS write); AD/Ninja = net-new |
| `netscan.py` (active nmap) | **Disabled** (`enabled:false`) | KEV + passive first decision |
| `graylog_client.send_gelf` | **Rewired** onto the existing GELF HTTP input 12201 (no longer 12222) | Reuses the bus; incidents tagged `event_source=xdr_incident` |

## 2. What was done (this commit)

- `rules.yaml`: 11 signals rewired onto the real schema (alert_tag/normalized), 6 rules unchanged.
- `config.yaml`: real stream IDs (FortiGate/Windows/Sysmon/Internal), GELF → 127.0.0.1:12201 (HTTP), `netscan.enabled:false`, response in dry-run.
- `graylog_client.py`: GELF **HTTP** send (reuses the existing input) in addition to TCP.
- `correlation.py`: incidents marked `_event_source=xdr_incident` (routing/dashboard like the other `event_source=siem_*`).

## 3. Still to integrate (recommended order)

1. **Validate in dry-run**: `python -m oms_xdr.engine --once` read-only → verify the incidents produced and **the FortiGate field names** (`subtype`/`status`) against real data.
2. **Route the incidents**: stream rule on `event_source:xdr_incident` → "OMS-XDR Incidents" dashboard page (or merge into "Internal SIEM").
3. **FortiGate responder → `omni-soar`**: replace the direct `api/v2/cmdb` write with adding to the `omni-soar` feed (already-proven safe path: no creds on the FW, TTL, whitelist, kill-switch).
4. **Arbitrate the correlation overlap**: oms-xdr (named, data-driven scenarios) vs `omni-incident-correlate` (entity kill-chain 0-100). Recommendation: oms-xdr becomes the **reference** correlation engine; `omni-incident-correlate` retired once coverage is validated.
5. **AD/NinjaOne actuators**: wire up when the ESET/AD API accounts are provided (LDAP/WinRM runbook), human-in-the-loop first.
6. **Deployment**: systemd timer (like the 26 `omni-*`), secrets via `00-vars.env`/Vaultwarden, dedicated read-only Graylog token.

## 4. Guardrails preserved

Dry-run by default (double lock `dry_run=false` AND `auto_*`), netscan disabled, exclusions to be carried over
(never the partner IPsec ranges / DC / critical service accounts), GELF audit of every action.

## 5. Validation (06/18/2026) — OK end to end

- `pytest` 10/10 green, `ruff` clean after rewiring.
- Real `--once` cycle: **local OpenSearch** read OK, **1 correlated incident** produced
  (`CR_CRED_ABUSE`), responder in **RECOMMENDATION** (dry-run respected), incident
  **reinjected into the SIEM** (GELF 12201, `event_source=xdr_incident`, indexed).
- Read rewired onto OpenSearch (`/api/search/messages` returns 400 on 7.1); Graylog
  token made **optional**.
- Tuning: exclusion of machine accounts (`NOT user:*$`) on the brute force /
  logon signals; Ollama connection timeout brought down to 5 s (non-blocking daemon).

### Identified follow-ups
1. **Ollama unreachable** from the SIEM VM (10.33.220.10 → 10.33.120.55:11434 timeout):
   open the firewall flow to enable LLM narration (deterministic fallback OK in the meantime).
2. **Service account false positives** (e.g. `ninjaone`): add a configurable exclusion
   (or consume the `account_class` field from the existing enrichment).
3. Route `event_source:xdr_incident` to a dedicated dashboard page.
4. FortiGate responder → delegate to the `omni-soar` feed (already-proven safe path).

## 6. Follow-ups COMPLETED (06/18/2026)

- **LOCAL Ollama** on the SIEM VM (127.0.0.1:11434, CPU-only, `qwen2.5:3b`) — LLM narration validated.
- **False positives**: exclusion `account_class:machine/service` + `ninjaone`/`fortinet` classified as service (49-enrich).
- **FortiGate responder → `omni-soar` feed** (no credential on the FW; public-only/whitelist/TTL/cap).
- **"OMS-XDR" dashboard page** (route `event_source:xdr_incident` → Internal SIEM stream; KPI + tables + narration).
- **systemd deployment**: `oms-xdr.timer` (5 min cycle, dry-run, OpenSearch read, root, from the repo).

### Remaining (when available)
- ESET/AD API to make `disable_ad_account` / `isolate_ninjaone` executable (runbook), human-in-the-loop first.
- Final arbitration of oms-xdr vs `omni-incident-correlate` correlation (retire the old one once coverage is confirmed).
- Open `auto_block_fortigate` (dry_run=false) after an observation period on the incidents stream.
