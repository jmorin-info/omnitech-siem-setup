# MITRE ATT&CK Coverage — SIEM OMNITECH

> Generated/maintained with `57-mitre-coverage.sh` · Last review: 2026-06-14
> Visual layer: **`docs/mitre-navigator-layer.json`** → to load into
> [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (*Open Existing Layer*).

## Executive summary
- **58 detection tags mapped to MITRE** (a subset of the **88 event definitions**:
  health/operations alerts — backup, disk, robots… — have no ATT&CK technique)
  → **44 distinct** ATT&CK techniques → **12/14 tactics** covered.
  *(upd. 2026-06-14: + Privilege Escalation filled [uac_bypass/scheduled_task/service_install], + `m365_brute_externe` T1110 [cloud spray, real data], + `remote_discovery` T1018, + `service_stop_securite` T1489 → Discovery 3, Impact 4.)*
- Each detection sets an `alert_tag` mapped to technique + tactic + risk score (`lookups/mitre-attack.csv`), reused by host scoring (UEBA), alerts and dashboards.
- The 2 uncovered tactics (**Reconnaissance**, **Resource Development**) are **out of scope** for an internal defensive SIEM (external pre-compromise scanning / attacker infrastructure acquisition — not visible on the defender side). *Effective* coverage = complete.

## Coverage by tactic
| Tactic | Techniques | Detection examples |
|---|---|---|
| Initial Access | 3 | exposition_internet (T1190), m365_risque/impossible_travel (T1078), waf_block |
| Execution | 3 | powershell_suspect (T1059.001), defender (T1204.002), eset_detection |
| Persistence | 4 | persistence_autorun (T1547.001), local_account_create (T1136), m365_role (T1098) |
| **Privilege Escalation** | **3** | **uac_bypass (T1548.002), scheduled_task (T1053.005), service_install (T1543.003)** — *added 2026-06-14* |
| Defense Evasion | 7 | winsec_critique (T1562.002), sysmon_injection (T1055), lolbin_suspect (T1218), masquerading |
| Credential Access | 11 | lsass_access (T1003.001), dcsync (T1003.006), kerberoasting (T1558.003), adcs_abuse (T1649), gpp_creds, vault_auth_fail |
| Discovery | 2 | network_scan (T1046), ldap_recon (T1087.002) |
| Lateral Movement | 3 | lateral_movement (T1021), wmi_lateral_exec (T1047), admin_share (T1021.002) |
| Collection | 1 | m365_mail_forward (T1114.003) |
| Command and Control | 2 | beaconing/threat_intel (T1071), dns_tunneling (T1071.004) |
| Exfiltration | 2 | data_exfil/volume_spike (T1048), m365_partage_externe (T1567) |
| Impact | 3 | ransomware_indicator (T1486), vsphere_vm_destroy (T1485), veeam_job_echec (T1490) |

## Gaps & enrichment axes (prioritized)
1. **Collection (1) / Exfiltration (2)** — add T1005 (local system data), T1039 (network shares), T1056 (input capture). *[P2]*
2. **Discovery (2)** — add T1018 (remote system discovery), T1482 (domain trust), T1057/T1083. *[P2]*
3. **Lateral Movement** — add **T1550** (Pass-the-Hash / Pass-the-Ticket) — key in an AD environment. *[P1]*
4. **Initial Access** — **T1566 (Phishing)**: requires mail security telemetry (beyond M365 signin). *[P2, source-dependent]*
5. **Impact** — T1489 (Service Stop), T1498 (DoS). *[P3]*
6. **Execution/Persistence** — T1059.003 (cmd), T1505.003 (web shell on IIS/exposed servers). *[P2]*

## Validation (purple team) — proving it triggers
Method: run the corresponding [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test on a **test** machine and verify that the SIEM raises the expected `alert_tag` (Investigation page → `alert_tag:<tag>`), ideally the alert.

| Technique | Atomic test | Expected `alert_tag` | Source |
|---|---|---|---|
| T1003.001 LSASS | T1003.001 (comsvcs/procdump) | `lsass_access` | Sysmon 10 |
| T1558.003 Kerberoasting | T1558.003 | `kerberoasting` | 4769 |
| T1053.005 Scheduled Task | T1053.005 (`schtasks /create`) | `scheduled_task` | 4698 |
| T1543.003 Service | T1543.003 (`sc create`) | `service_install` | 4697 |
| **T1548.002 UAC bypass** | T1548.002 (fodhelper) | `uac_bypass` | Sysmon 1 |
| T1547.001 Run keys | T1547.001 | `persistence_autorun` | Sysmon 13 |
| T1059.001 PowerShell | T1059.001 (encoded) | `powershell_suspect` | 4104 |
| T1218 LOLBin | T1218.010 (regsvr32) | `lolbin_suspect` | Sysmon 1 |
| T1046 Network scan | T1046 | `network_scan` | FortiGate |
| T1087.002 LDAP recon | T1087.002 | `ldap_recon` | 4662/Sysmon |
| T1562.002 Clear logs | T1070.001 (`wevtutil cl`) | `winsec_critique` | 1102 |

> ⚠️ Do NOT run destructive tests (T1486 ransomware, T1485 destruction) in production.
> Keep a log of validation campaigns (date, technique, detected yes/no, MTTD) — also useful for ISO A.8.16.

## Maintenance
For each new detection: add the line in `lookups/mitre-attack.csv` (via `add_mitre` in the detection script), then **re-run `57-mitre-coverage.sh`** to regenerate the Navigator layer and the coverage report.
