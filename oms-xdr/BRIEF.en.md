# BRIEF.md — OMS-XDR project brief

This file is intended for the project maintainer. Read it first before any modification.

> ⚠️ **State integrated into the SIEM (18/06/2026): source of truth = `docs/INTEGRATION-OMNITECH.md`.**
> Differences vs the original brief below: **local OpenSearch read** (not the
> `/api/search/messages` API, which returns 400 in **Graylog 7.1**); **GELF HTTP 12201** (existing
> input); **LOCAL Ollama `127.0.0.1:11434` model `qwen2.5:3b`** (no longer 10.33.120.55);
> FortiGate blocking **delegated to the `omni-soar` feed**; **Graylog token not required**;
> deployed as `oms-xdr.timer` (5 min). `make run-once` no longer requires a token.

## 1. Objective

OMS-XDR is an **XDR overlay** on top of OMNITECH Security's Graylog SIEM.
It reproduces the key functions of an MXDR (cross-domain correlation,
enrichment, guided remediation, semi-autonomous response) **without an external SOC**.
See `README.md` for the MXDR → equivalents mapping.

## 2. Operating principle

```
OpenSearch ─(terms agg / messages, omni-*)─►  correlation.py  ──►  Incident
                                                │
              enrich.py (Ollama/Mistral) ◄──────┤
              remediation.py (playbooks) ◄──────┤
              responder.py (FGT/AD/Ninja) ◄─────┤
                                                ▼
Graylog ◄──(GELF HTTP 12201, event_source=xdr_incident)── engine.py + Teams
```

**Deliberately decoupled** architecture: no Graylog Java plugin. **Integration
on the SIEM VM** (18/06/2026): read via **local OpenSearch** (like the
`omni-*` services), write to the SIEM's **existing GELF bus** (HTTP input
12201). Signals consume the existing detections (`alert_tag` + normalized
schema) — see `docs/INTEGRATION-OMNITECH.md`.

## 3. Structure

| File | Role |
|---|---|
| `oms_xdr/config.py` | YAML loading |
| `oms_xdr/graylog_client.py` | search (Search Scripting API) + aggregation + GELF sending |
| `oms_xdr/rules.yaml` | **data**: atomic signals + correlation rules (MITRE) |
| `oms_xdr/correlation.py` | engine: signals → rules → `Incident` |
| `oms_xdr/remediation.py` | playbooks per rule/technique (OMNITECH actions) |
| `oms_xdr/enrich.py` | FR analyst narration via Ollama (deterministic fallback) |
| `oms_xdr/responder.py` | containment actions (dry-run by default) |
| `oms_xdr/engine.py` | orchestrator + dedup + notification |
| `oms_xdr/netscan.py` | nmap network discovery + baseline diff → GELF |
| `deploy/` | systemd units, env, Graylog provisioning |
| `tests/` | pytest (correlation, remediation) |

## 4. Commands

```bash
make install      # venv + dependencies + package in editable
make test         # pytest
make lint         # ruff (if installed)
make run-once     # one correlation cycle (requires OMS_GRAYLOG_TOKEN)
make scan-quick   # top-1000 network scan
```

Without make:
```bash
python -m oms_xdr.engine --once --config /etc/oms-xdr/config.yaml
python -m oms_xdr.netscan --mode quick --config /etc/oms-xdr/config.yaml
pytest -q
```

## 5. Conventions (to be respected in any contribution)

- **User outputs/business logs in French**, expert CISO register. Code identifiers
  in English. No filler, no hand-holding.
- Type hints everywhere, `from __future__ import annotations`, per-module logging
  (`logging.getLogger("oms-xdr.<module>")`).
- **No hardcoded secrets.** Everything via environment variables (see `oms-xdr.env`).
  Ideally injection from Vaultwarden (`vaultwarden.omnitech-security.fr`).
- Detection is **data-driven**: enrich `rules.yaml` rather than the code.
  A new signal = an entry in `signals:`; a new chain = an entry in `rules:`.
- Robustness: a failed signal/cycle must never bring down the daemon.

## 6. SECURITY CONSTRAINT (non-negotiable)

- `response.dry_run: true` is the default. **Never** wire up an action that
  executes without the dual lock `dry_run=false` AND `auto_<action>=true`.
- `netscan` scans ONLY the internal networks declared in `netscan.targets`.
  Do not add any target outside the OMNITECH perimeter.
- Any real response action (FGT blocking, AD account disabling,
  endpoint isolation) must remain traceable (WARNING log + `actions` field of the incident).

## 7. Infrastructure constants (context, do not commit sensitive values)

- Graylog: `https://10.33.220.10` (Debian 13, Graylog 6.x, OpenSearch 2.x, MongoDB rs0).
- AD: domain `omnitech.security`, DC `10.33.50.250` (BX-AD-01-IT-VM).
- FortiGate 120G HA (FortiOS 7.4.x), FortiManager + FortiAnalyzer (CEF 1514).
- Internal Ollama: `http://10.33.120.55:11434` (Mistral 7B).
- ESET EDR, NinjaOne RMM (~150 endpoints), Centreon 24.10, Veeam 3-2-1-1.

## 8. Priority tasks (see `docs/ROADMAP.md` for details)

1. Signed AD runbooks (WinRM/NinjaOne) to make `disable_ad_account` / `force_pwd_reset` executable.
2. Threat intel: Graylog lookup tables (abuse.ch, OTX) + `S_C2_IOC` signal.
3. Sysmon signals (NinjaOne deployment): T1055, T1003, parent/child process.
4. Per-entity EWMA anomalies (replace fixed thresholds).
5. Vuln correlation: cross `netscan` ↔ POL_018 (CVSS matrix).
6. Graylog "OMS-XDR Incidents" dashboard + scheduled weekly report.

## 9. Definition of "done" for a contribution

- `make test` passes (add a test for any new signal/rule/action).
- No secret introduced; `dry_run` remains the default.
- README/ROADMAP updated if behavior or scope changes.
