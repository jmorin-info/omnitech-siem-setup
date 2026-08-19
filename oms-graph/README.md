# oms-graph — Attack twin / exposure analysis (OMNI Sentinel, Pillar 2)

**Passively** reconstructs (without an AD probe, from the logon telemetry already
collected by the SIEM) an **exposure** graph of the OMNITECH environment, and puts
it in the service of **defence**: prioritising hardening and **pre-positioning
decoys** (Pillar 1 / deception).

## Model
Two edges derived from Windows logs:
- **HasSession** (`account → host`): EID 4624, LogonType 2/10/11 (console/RDP/cached) —
  *the account's credentials are exposed on this host*.
- **AdminTo** (`account → host`): EID 4672 (special privileges) — *the account is
  administrator of this host*.

**Compromise-propagation** graph: control a host ⇒ harvest the accounts
that have a session on it; control an account ⇒ control the hosts it administers.

## Computations
- **Crown-jewel exposure**: which footholds reach each jewel (DC, SIEM,
  Veeam, PKI, files, vSphere) and in how many hops.
- **Chokepoints**: accounts/hosts on the most paths → where to harden / place a decoy.
- **Blast radius**: if X is compromised, how many hosts/jewels become reachable.
- **Single points**: management accounts (RMM/sync) admin everywhere → PAM + tiering.
- **Decoy recommendations**: where to place a decoy (88) to intercept the most
  paths, with "already covered" tagging via the `omni-deception` register.

## Noise reduction (measured)
Machine accounts (`*$`), system and virtual accounts (DWM/UMFD/MSSQL$/IUSR…) excluded;
ubiquitous management accounts (admin of > N hosts) removed from lateral paths and reported
separately (otherwise they link everything to everything).

## Usage
```
oms-graph analyze [--window 14d] [--top N] [--push]
```
Without `--push`: displays + writes the JSON artefact (`/var/lib/omni-mobile/attack-graph.json`,
read by the SOC console). With `--push`: re-injects the paths in GELF
(`event_source=attack_path`, **informational, no alert_tag** — this is a posture, not
an alert). **Passive** read; performs **no** action on the IS.

Deployment: `89-attack-graph.sh` (venv + `/etc/oms-graph` config + timers +
routing to "OMNI - Interne SIEM").

## Pillar 3 — Graduated response (`respond`)
```
oms-graph respond [--simulate ENTITE] [--push] [--execute]
```
Composes a **triggered decoy** (Pillar 1) with the **twin's context** (Pillar 2) →
a **graded response plan** (critical/high/moderate). `--simulate <host|account>` =
tabletop (hypothetical compromise). `--push` = GELF audit `event_source=sentinel_response`.
`--execute` = execution approval.

**Safeguards (by design)**: DRY-RUN by default. Real execution only if
`response.dry_run=false` + `auto_<action>=true` + env **`OMNI_SENTINEL_ARM=1`** +
`--execute` (quadruple lock). **Scope**: only actions on OMNITECH's own
infrastructure are armable (NinjaOne isolation, FortiGate blocking via the omni-soar feed);
**identity (AD) actions always remain recommendations only**; any
**co-managed** target (invissys) is forced into dry-run. The `oms-graph-respond` timer grades +
audits **without ever executing** (no `--execute`) — execution is **manual and approved**.
