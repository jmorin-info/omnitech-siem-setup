# SLA for acknowledging severe SEAL alarms

Detects **severe physical-security alarms that remain open without being
handled** beyond a deadline (SLA), across both sites (QA + OMEGA), and notifies.

## Why a poller (and not just a Graylog detection)

A Graylog event definition aggregates a window and triggers on a threshold.
It **cannot express "an alarm open WITHOUT a closure event"**
(anti-join / absence). The poller does this through **per-alarm-group state
correlation** and then emits a marker that Graylog is able to alert on.

## Data model (verified against the actual collection)

- Each alarm = one `EVEN_GROUP_ID`. The `ALARMES` view re-emits a row on each
  lifecycle transition → several Graylog events per group. The **last one**
  (max timestamp) carries the current state.
- `EVEN_LIFESTATUS`: `END` = closed/resolved · `LIV` = active/in progress · `INF` = informational.
  - **Resolved** = last status `END` (or `ACK_EVEN_ID` present = acknowledged in console).
  - **Open** = last status `LIV` → SLA candidate.
  - `INF` (and others) = informational → **out of SLA scope**.
  - `END_EVEN_ID` alone is NOT reliable (present even on `LIV` groups).
- `severity_num` is **unusable as a rank** (these are codes, not a score).
  SLA severity therefore comes from a **set of REEV codes** (see `severe-codes.json`).
- The majority of "alarms" are maintenance noise (loss of the SEM97 module,
  DOMBOX) or one-off events with no lifecycle (access denial SEM122… already
  covered by threshold detections). They are **excluded** from the SLA.

## Default policy

| Code | Class | SLA | Label |
|------|--------|-----|---------|
| SEM218 | critical | 15 min | Intrusion detected by video |
| SEM113 | critical | 15 min | Door break-in |
| SEM805 | critical | 15 min | Manual trigger |
| SEM118 | high | 60 min | Stuck push button |
| SEM73  | high | 60 min | UTL database modified |

Adjustable per site (`SEAL_SLA_SITE_MULT`) and per code (`severe-codes.json`).

## Full chain

```
alarmes SEAL (stream Alarmes)
   │
   ▼  seal_sla_poller.py  (timer 1 min)   ── état par groupe, âge > SLA ? ──┐
   │                                                                        │
   ▼  émet un marqueur GELF  alert_tag=seal_sla_breach  (idempotent)        │
   │     _seal_site _sla_class _sla_minutes _age_minutes _REEV_CODE ...     │
   ▼                                                                        │
détections SLA-001 (critique) / SLA-002 (élevée)  ── group_by seal_site ────┤
   │     → notification Teams/mail (sévérité selon la classe)               │
   ▼                                                                        │
widget « Backlog SLA par site »  (dashboard SEAL - Vue multi-site)  ◄───────┘
```

Idempotence: the poller emits **only one marker per breach** (plus one more at
each escalation tier = `factor × SLA`). The detections run on a tumbling window
(one alert per marker). No flooding.

## Installation

```bash
sudo seal/sla/install-sla-poller.sh      # deploys everything, timer DISABLED, dry-run test
```

The script displays the current breaches (`--once`). **After review**:

```bash
sudo systemctl enable --now oms-seal-sla.timer
journalctl -u oms-seal-sla.service -f
```

The timer is deliberately left disabled (same logic as dead-man
switches: activation after acceptance testing, once the policy has been validated).

## Manual use

```bash
# computation only, no emission or state write (review)
/opt/oms-seal-sla/.venv/bin/python /opt/oms-seal-sla/seal_sla_poller.py --once

# real cycle (emits + updates state) — normally launched by the timer
/opt/oms-seal-sla/.venv/bin/python /opt/oms-seal-sla/seal_sla_poller.py
```

## Configuration

Everything is in `/etc/oms-seal-sla/seal-sla.env` (see `deploy/seal-sla.env.example`).
No secret: local OpenSearch read, local GELF emission.

For a different estate, **discover the codes** then adjust `severe-codes.json`:

```
event_domain:alarm            # then look at REEV_CODE / event_action / EVEN_LIFESTATUS
```

## Rules of engagement observed

- **Local** OpenSearch read only; no write on the SEAL side.
- No impact on the co-managed tenant; no secret held by the poller.
- Idempotent; `--once` safe; timer disabled by default.
