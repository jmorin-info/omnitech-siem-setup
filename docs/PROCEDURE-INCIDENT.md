# Security incident detection and response procedure

> Describes how a security event is detected, assessed, handled and closed via
> the OMNITECH SIEM. Covers ISO/IEC 27001:2022 **A.5.24** (preparation),
> **A.5.25** (assessment/decision), **A.5.26** (response), **A.5.27**
> (lessons learned), **A.5.28** (evidence).
>
> **Status:** operational procedure — to be validated/approved by the CISO.

## 1. Roles and responsibilities

| Role | Responsibility |
|------|----------------|
| **SOC Analyst / Administrator** | Daily triage, qualification, first-level handling |
| **CISO** | Decision on major incidents, communication, lessons learned |
| **SIEM (automated)** | Detection, correlation, scoring, notification, reflex response (SOAR) |

## 2. Processing chain (from log to closed incident)

```
Événement ─► Détection (88 règles) ─► Enrichissement (MITRE + score) ─► Corrélation
   (alert_tag)        (alerte P2/P3)         (risk_score, technique)      (kill-chain)
                                                                              │
                          ┌───────────────────────────────────────────────────┘
                          ▼
   Notification (e-mail/Teams) + Incident horodaté (page « Incidents »)
                          │
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
   ÉVALUATION (A.5.25)  RÉPONSE (A.5.26)   CLÔTURE + ENSEIGNEMENTS (A.5.27)
```

## 3. Detection (A.5.24)

- **Automatic and continuous**: 88 detection rules (see
  `REGISTRE-DETECTIONS.md`) + behavioral detection (UEBA/NDR).
- **Prioritization**: **P3** = critical (audit tampering, DCSync, ransomware,
  critical correlated incident, canary…); **P2** = important (LSASS, beaconing,
  DNS tunnel, go-dark, UEBA entity ≥80…).
- **Notification**: each trigger sends an e-mail + a Teams message to the SOC
  channel. Anti-storm: no looping resends (per-entity delay).

## 4. Assessment and decision (A.5.25)

The analyst qualifies via the SIEM:

1. **"Management" page** — are there any critical incidents / at-risk entities?
2. **"Incidents" page** — read the **attack narrative** (ordered kill-chain):
   entity, sequence of tactics, time window, score.
3. **"UEBA / NDR" page** — entity score, dominant factor.
4. **"Investigation" page** — type `host:…` or `user:…` to correlate everything
   (raw message retained for forensics).

**Decision**: false positive (document) / minor incident (handle) / major
incident (escalate to CISO). Escalation criteria: critical technique (T1003, T1486,
DCSync), privileged account, score ≥80, or several chained tactics.

## 5. Response (A.5.26)

- **Automatic reflex (SOAR)**: a repeated attacking IP (VPN brute force /
  password spraying) is automatically blocked at the firewall (configurable TTL),
  **never** on an internal IP or an allowlisted one. **Host isolation /
  account disabling** playbooks designed (awaiting NinjaOne API) → see `SOAR-PLAYBOOKS.md`;
  until then, these actions remain **manual**.
- **Investigation pivot**: use the **`identity`** field ("Identity" page)
  to reconstruct a person's activity across **all** sources
  (AD + M365 + VPN + endpoint), and `src_hostname` to resolve an internal IP.
- **Manual containment**: disable the compromised account (AD/M365), isolate
  the host, revoke sessions, block the IP/domain.
- **Eradication**: remove persistence (task/service/Run key), fix the
  vulnerability ("Vulnerabilities" page), force a password change.
- **Recovery**: restore from Veeam backup if necessary ("Backups" page),
  verify the return to normal.

## 6. Evidence collection (A.5.28)

- Relevant logs are **retained and timestamped** (12 months for the
  security file), in **write-only** mode + **signed integrity register**
  (tamper-evidence) attesting they have not been altered over the interval.
- The **raw message** is retained (`message` field) for forensic analysis.
- Export possible: Graylog search → CSV export; **seal** the export
  (`sha256sum`) + attach the `omni-integrity --verify` attestation → **chain of
  custody** (detailed procedure: `PROCEDURE-INTEGRITE-PREUVE.md`).
- The **correlation chain** (incident) documents the timestamped sequence.

## 7. Closure and lessons learned (A.5.27)

- Document the qualification, the actions, the root cause.
- If recurring: adjust thresholds, add/refine a detection rule,
  extend an allowlist (e.g. legitimate SaaS beaconing).
- The **weekly and monthly reports** consolidate trends and the top
  risks for the management review.

## 8. Metrics (for the management review)

- Number of critical / high incidents (month).
- Collection coverage (%) and go-dark hosts.
- Top at-risk entities (UEBA), top observed ATT&CK techniques.
- Exposed KEV vulnerabilities.

Source: monthly report (`omni-monthly-report`, archived `/kit/rapports/`).

---
*See `ISO27001-MAPPING.md` (control mapping), `REGISTRE-DETECTIONS.md`
(rules), `PROCEDURE-EXPLOITATION-SIEM.md` (routine operations).*
