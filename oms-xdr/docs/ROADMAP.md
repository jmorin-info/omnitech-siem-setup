# OMS-XDR ROADMAP — actionable tasks

Each task is self-contained and testable. Follow the conventions in `BRIEF.md`
(French output, dry-run by default, detection driven by `rules.yaml`,
one test per addition).

## T1 — Signed AD runbooks (high priority)
Make `responder._disable_ad_account` / `_force_pwd_reset` actually executable.
- Implement a NinjaOne call (signed PowerShell script) or WinRM to `10.33.50.250`.
- PowerShell: `Disable-ADAccount` / `Set-ADAccountPassword -Reset` + `Revoke-AzureADUserAllRefreshToken` (Entra).
- Keep the `dry_run`/`auto_disable_ad_account` double lock.
- Test API failure (account not found, insufficient rights) without crashing.
- **DoD**: test mocking the call + WARNING log recorded.

## T2 — Threat intelligence
New `S_C2_IOC` signal cross-referencing outbound FortiGate flows with IOCs.
- Create/populate a Graylog lookup table (abuse.ch Feodo, OTX) — sync script in `deploy/`.
- Graylog pipeline rule tagging `threat_intel:true` on match.
- Add `S_C2_IOC` to `rules.yaml` + integrate it into `CR_EXECUTION_C2` (any_of).
- **DoD**: correlation test with a simulated IOC.

## T3 — Sysmon signals
Once Sysmon is deployed via NinjaOne:
- Signals: `S_PROC_INJECTION` (Sysmon 8/10, T1055), `S_LSASS_ACCESS` (Sysmon 10 on lsass, T1003.001), `S_SUSP_PARENT_CHILD` (office→cmd/powershell).
- New `CR_ENDPOINT_COMPROMISE` rule linking injection + LSASS access.
- **DoD**: rules + tests + MITRE_CONTEXT entries in `remediation.py`.

## T4 — Anomaly detection (EWMA)
Replace fixed thresholds with an adaptive per-entity baseline.
- Store moving averages/deviations in `state_dir` (EWMA, α≈0.3).
- Trigger if value > mean + k·σ (k configurable).
- Keep a `static`/`ewma` mode per signal in `rules.yaml`.
- **DoD**: `anomaly.py` module + tests on synthetic series.

## T5 — Vulnerability correlation
Cross-reference the ports discovered by `netscan` with the CVSS matrix (POL_018).
- Map service/port → known CVEs (source: Graylog lookup or local file).
- Prioritise `new_open_port` deltas exposing a vulnerable service.
- **DoD**: `S_VULN_EXPOSED` signal + test.

## T6 — Dashboard & reporting
- Provision via API an "OMS-XDR Incidents" dashboard (widgets: incidents by severity,
  top MITRE techniques, top entities) — script in `deploy/`.
- Weekly report (HTML/PDF) of incidents — reuse the SEAL docx pipeline
  (navy #004469, orange #F68D2E, taupe #837274, Arial).
- **DoD**: provisioning script + example generated report.
