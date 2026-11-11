# OMNI Sentinel — Proactive defense (architecture & governance)

> **Status**: 3 pillars deployed (23/06/2026). Reference document for operations,
> onboarding and the ISO 27001 audit (Stage 2). Local-first, passive read, human-gated.

## 1. Why
A classic SIEM is **reactive**: it detects what has already tripped a signature. OMNI Sentinel
adds a **proactive** layer: model the environment, **get ahead of the attacker**
by pre-positioning traps along their likely paths, and contain them **before impact** —
all under strict control (dry-run by default, bounded scope, audit).

## 2. Architecture (the 3 pillars in a loop)

```
   Passive telemetry (logons 4624/4672, Sysmon, M365, FortiGate)
        │
        ▼
  ┌─────────────────────┐      designates WHERE to place the decoys
  │ PILLAR 2 — Attack   │ ───────────────────────────────────┐
  │ twin (oms-graph)    │                                     │
  │ paths → crown jewels,│ ◀── context (blast radius,         │
  │ chokepoints, blast   │     distance to crown jewels)      │
  └─────────────────────┘                                     ▼
        │ exposure                                ┌─────────────────────┐
        │ (console + GELF attack_path)            │ PILLAR 1 — Deception │
        │                                         │ (88, lookup          │
        ▼                                         │  omni-deception)     │
  ┌─────────────────────┐   a decoy fires         │ accounts/SPN/canaries│
  │ PILLAR 3 — Graded   │ ◀──────────────────────│ 0-FP, ~100% fidelity │
  │ response (respond)   │                         └─────────────────────┘
  │ grade + plan +       │
  │ armed execution      │ ──▶ NinjaOne (isolation) · FortiGate (blocking via omni-soar)
  │ (OMNITECH infra)     │ ──▶ AD: recommendation only (never armed)
  └─────────────────────┘ ──▶ GELF audit sentinel_response
```

**The loop**: the Twin (P2) says *where* the attacker will go → we sow decoys there (P1) → a
touched decoy triggers a response *graded by the Twin's context* (P3). **Detect →
contextualize → respond**, in one motion.

## 3. Pillar 1 — Deception (`88-deception-honeytokens.sh`)
**Decoys with no legitimate use whatsoever**: any contact = attacker.
- **Mechanics**: Graylog lookup `omni-deception` (CSV `lookups/deception-decoys.csv`,
  `key,type`, case-insensitive, reloaded every 60 s). **Adding a decoy = 1 line**, covered
  without touching code.
- **5 rules** (stage 13): `decoy_identity` (T1078, Windows auth 4624/4625/4768 on a decoy
  account/machine), `decoy_kerberoast` (T1558.003, TGS 4769 on a decoy SPN — *zero-FP verified*),
  `decoy_identity` M365, `canary_token` (T1005, Sysmon/FortiGate DNS request to a canary FQDN).
- **0-FP guarantee**: measured collision = 0 over 30 days for the 15 accounts + 5 FQDNs.
- **Bait** (planting the accounts/files): CISO action in dry-run on the OMNITECH AD —
  see `DECEPTION-PLAN.md`. **Never** on the co-managed invissys tenant.

## 4. Pillar 2 — Attack twin (`oms-graph`)
Rebuilds an exposure graph **passively** (no AD probe).
- **Edges**: *HasSession* (4624 LogonType 2/10/11 → credentials exposed on the host) +
  *AdminTo* (4672 → admin of the host). **Control** propagation: controlling a host =
  harvesting its accounts; controlling an account = its admin hosts.
- **Computations**: crown-jewel exposure (DC/SIEM/Veeam/PKI/files/vSphere), **chokepoints**
  (where to harden/decoy), **blast radius**, **single points** (RMM admin everywhere),
  **decoy-placement recommendations**.
- **Anti-noise (measured)**: machine/system/virtual accounts excluded; ubiquitous management
  accounts pulled out of lateral paths (otherwise they link everything to everything).
- **Engineering decision**: the Kerberos edge (4769) is **deliberately dropped** —
  semantically it is *reachability*, not *control*; including it would overvalue
  pivot paths.
- **Outputs**: artifact `/var/lib/omni-mobile/attack-graph.json` (console, *Twin* tab /
  PWA *Exposure*) + GELF `event_source=attack_path` (informational, no alert_tag).

## 5. Pillar 3 — Graded response (`oms-graph respond`)
Composes a trigger (decoy/detection) + the Twin's context → a **graded plan**
(critical/high/moderate). Demonstrable in a tabletop (`respond --simulate <host|account>`), visible
in the console (click on a Twin entity → response modal).

### Security model (quadruple lock)
An action really executes **only if all four** are met:

| Lock | Mechanism |
|---|---|
| 1 | `response.dry_run = false` (config) |
| 2 | `auto_<action> = true` (config, per action) |
| 3 | `OMNI_SENTINEL_ARM=1` (environment variable on the host) |
| 4 | `--execute` (explicit analyst approval — never automatic) |

**Non-bypassable bounds (hard-coded)**:
- **Identity actions (AD/reset)** = recommendation **always**, never armed.
- **Co-managed target** (`invissys` marker) = forced into dry-run.
- **Armable** only on OMNITECH's own infra: NinjaOne isolation, FortiGate blocking
  (delegated to the `omni-soar` feed, no firewall credential).
- The `oms-graph-respond` timer grades + audits **without ever executing** (no `--execute`).
- GELF audit `event_source=sentinel_response` of each plan.

## 6. ISO 27001 mapping
| Control | Sentinel coverage |
|---|---|
| A.8.7 (protection against malware) | Deception + proactive detection |
| A.8.16 (monitoring) | Exposure twin + decoys + audit |
| A.5.7 (threat intelligence) | Attack paths, chokepoints, blast radius |
| A.5.26 (incident response) | Human-gated graded response |
| A.5.15 / A.8.2 (privileged access) | Single points flagged (AC-RA-02) |
| A.8.32 (change management) | Everything versioned, dry-run, reversible |

## 7. Runbook
- **Deploy**: `./88-deception-honeytokens.sh` (traps) then `./89-attack-graph.sh` (twin +
  response). Re-run `57` (ATT&CK map) + `14` (dashboards) after 88.
- **Plant the bait**: follow `DECEPTION-PLAN.md` (*dormant* decoy accounts, canary files)
  on the OMNITECH AD. Add the exact key to `deception-decoys.csv` → covered in < 60 s.
- **Extend**: crown jewels / footholds / decoys in `oms-graph/config.yaml` (1 line).
- **Tabletop**: `oms-graph respond --simulate <host|account>` or click in the console.
- **Arm P3** (on the intended day): `response.dry_run=false` + `auto_isolate_ninjaone=true` (and/or
  `auto_block_fortigate`) in `/etc/oms-graph/config.yaml`, export `OMNI_SENTINEL_ARM=1`,
  provide the `OMS_NINJA_*` creds. Execution still requires `--execute` approval.
- **Cadence**: twin daily, decoy grading every 15 min (audit only).

## 8. Limits (honesty)
- The traps (P1) are **armed but inert** as long as the bait is not planted (CISO action).
- The twin (P2) models **credential-based control** (HasSession/AdminTo) — not
  application exploits nor pure network reachability.
- The real response (P3) requires the NinjaOne creds + explicit arming; by default everything is
  a recommendation.
- Strictly **defensive** and **OMNITECH**-scoped; the co-managed tenant stays out of execution.
