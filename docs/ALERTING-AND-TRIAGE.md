# Alerting &amp; triage

Raw detections are firehosed to Microsoft Teams and to the SOC console, but **only qualified,
actionable alerts reach the security mailbox**. That decision is made by the
`omni-alert-triage` micro-service (127.0.0.1:8089), to which every mailing detection is wired
via a single HTTP notification.

## Why a triage tier

Before triage, ~105 event definitions e-mailed directly, producing tens of thousands of
mails per week (one feed alone accounted for 83 %). Direct e-mail also bypassed all filtering,
so a detection the platform *knew* to be noise still reached the inbox. The triage service is
the single mail path: it scores, correlates, de-duplicates, consults an LLM for the grey
zone, and renders one clean message per real alert.

## How a decision is made

1. **Classify** the alert into a tier from its title — **Critical**, **grey zone**, or
   **noise**.
2. **Score** on multiple signals: Graylog priority, critical-asset match
   (`ASSET_CRITICAL_REGEX`), threat-intel, off-hours, and **kill-chain velocity** — the number
   of *distinct* detection types seen on the same entity within the window (a lateral-moving
   attacker lights up several).
3. **Correlate** across sources on canonical keys (identity / host / IP / badge). A SEAL
   console login and a Windows brute force on the same account join up; ≥ N distinct types on
   one entity escalates to a **kill-chain incident**, re-injected for the console.
4. **Grey zone → LLM judge.** For ambiguous alerts, a Claude (Haiku) judge is asked — over a
   **redacted** context (IPs/emails masked before egress) — whether the alert warrants an
   immediate e-mail. Critical alerts are never suppressed; noise is dropped unless it
   escalates by score.
5. **De-duplicate** (title + entity, windowed) and honour **learned false-positive rules**
   (analysts flag FPs from the console; rules are scoped, time-boxed, and never silence a
   Critical).

Every decision is re-injected as `event_source:alert_triage` (`triage_decision`,
`triage_tier`, `triage_score`, `triage_reason`) so the triage itself is searchable and
dashboarded (`OMNI - Triage & Multi-site`).

## The notification

Each e-mail is a single, sober, professional HTML message:

- a colour accent by severity (deep red = *Critique* / *Incident corrélé*, amber = *À
  qualifier*) as the one visual accent — no emoji, no internal jargon;
- a calm **facts table** — who / where / how many — with a human label per entity (no raw
  `user=`/`src_ip=` prefixes) and no duplicated lines;
- the MITRE technique as a **clickable ATT&CK badge** (reconstructed from the title if the
  pipeline did not tag it), plus threat-intel and country tags;
- the business **risk level** when present (e.g. *risque critique 9/10*);
- a four-part **action playbook** — *what it is / what to check / remediation / durable fix* —
  from the guidance lookup, keyed by `alert_tag`;
- the **triggering raw events** (formatted per source: FortiGate key=value, ESET JSON,
  Sysmon), plus **correlated alerts** on the same entity;
- one-click actions: **open in console**, **view logs**, **block IP** (HMAC-signed link),
  **mark false-positive**;
- for physical alerts, the SEAL block: site / zone / door / badge.

Absence detections (a silent flow, a missing backup) render as *"no event received — flow
silent"* rather than the incoherent *"0 occurrences"*, and omit an empty subject line.

## Configuration

Key `omni-alert-triage.env` settings:

| Variable | Role |
|---|---|
| `MAIL_RECIPIENTS` | Destination mailbox(es) |
| `ANTHROPIC_API_KEY` | Enables the grey-zone LLM judge (redacted context) |
| `MAIL_SCORE_THRESHOLD` / `GRAY_SCORE_THRESHOLD` | Score gates for noise-escalation / grey-zone fallback |
| `ASSET_CRITICAL_REGEX` | Critical-asset boost (DCs, AD, …) |
| `KILLCHAIN_COUNT` / `KILLCHAIN_WINDOW` | Kill-chain escalation threshold &amp; window |
| `TRIAGE_DEDUP_SECONDS` | De-duplication window |
| `SEAL_QA_SITE` | Test SEAL site whose alerts stay console-only |

## Automated response (SOAR)

`omni-soar` (127.0.0.1:8088) auto-blocks confirmed attacking **public** IPs by feeding a
FortiGate address group behind a block policy. The action is **guarded** (public IPs only,
whitelist-aware), **reversible** (24 h TTL, clearable), and **auditable** (each block
re-injected as an event, shown on the console). A **manual block** path lets an analyst block
an IP straight from an alert e-mail via an HMAC-signed, time-boxed link.

See also [REPONSE-AUTOMATISEE.md](REPONSE-AUTOMATISEE.md) and [SOAR-PLAYBOOKS.md](SOAR-PLAYBOOKS.md).
