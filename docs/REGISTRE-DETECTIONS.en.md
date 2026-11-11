# Register of detection rules — OMNITECH SIEM

> **Exhaustive** catalog of the **88 active event definitions** (Graylog
> alerts; 87 aggregation rules + 1 system event), classified by domain.
> Serves as evidence of monitoring coverage (ISO 27001 **A.8.16**) and as an
> operational reference. *Last review: 2026-06-14 (cross-checked live).*
>
> **Priorities**: **P3 = critical** (immediate action) · **P2 = important** (to
> be handled quickly). Notification **tier**: **M** = "wake me up" email
> (confirmed compromise / SIEM health) · **T** = Teams (firehose, all
> alerts). Per-entity storm control (`group_by`), grace ≥ 60 min on the email tier.
>
> Source of truth: Graylog definitions (`13-graylog-alerts.sh`, `16-m365-input.sh`,
> `21-alert-hygiene.sh`, `36-soar.sh`, `47-detections-extra.sh`, `48`, modules 37-46,
> `59-file-audit.sh`, `60-integrity.sh`). MITRE tag via `lookups/mitre-attack.csv`.

## Breakdown

| Priority | Count | Email tier | Teams tier |
|----------|--------|-----------|------------|
| P3 (critical) | 54 | — | — |
| P2 (important) | 33 | — | — |
| **Aggregation total** | **87** | **26 (email)** | **87 (Teams)** |

> All alerts go to **Teams** (firehose); **26** critical ones **also** go
> to email (cf. `KEEP[]` of `22-alert-routing.sh`). Beyond the definitions, some
> **enrichment tags** set at the pipeline have no dedicated alert (anti-noise):
> `persistence_autorun` (T1547.001), `remote_discovery` (T1018), `service_stop_securite`
> (T1489), `threat_intel`, `explicit_cred_use` — visible in investigation/dashboards.

---

## 1. Identity & Active Directory (A.8.2 / A.8.5 / A.5.18)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| Brute force (≥10 failures / account / 10 min) | P3 | T | 4625 aggregated by account (excludes `*$`/ninjaone/ADSync) | T1110 |
| Password spraying (≥8 accounts / IP / 10 min) | P3 | T | 4625, `card(user)` by IP | T1110.003 |
| Brute force FOLLOWED by a success (same account / 15 min) | P3 | **M** | 4625 then 4624 | T1110 |
| Attempt on a disabled account | P2 | T | failure reason `compte_desactive` | T1078 |
| Locked account (4740) | P2 | T | AD lockout (spraying effect) | — |
| Account created in the domain (4720) | P2 | T | AD account creation | T1136.002 |
| LOCAL account creation (4720 outside DC) | P2 | T | local account outside controller | T1136.001 |
| Added to the LOCAL Administrators group (4732) | P2 | T | local elevation | T1098 |
| Modification of a privileged group | P3 | T | 4728/4732/4756 (`priv_group_label`) | T1098 |
| Suspicious DCSync | P3 | **M** | 4662 DS replication GUID | T1003.006 |
| Suspicious Kerberoasting (≥5 SPN / account / 10 min) | P3 | T | 4769 RC4/abnormal | T1558.003 |
| Kerberos RC4 / downgrade | P3 | T | `kerberos_rc4` (encryption downgrade) | T1558.003 |
| AS-REP roasting (account without pre-auth) | P3 | T | 4768 `PreAuthType=0` | T1558.004 |
| Shadow Credentials (msDS-KeyCredentialLink) | P3 | T | authentication key modification | T1556.005 |
| AD CS / certificate abuse (ESC1-ESC8) | P3 | T | `adcs_abuse` | T1649 |
| GPP/SYSVOL credential access | P3 | T | `gpp_creds_access` | T1552.006 |
| LDAP reconnaissance (directory enumeration) | P3 | T | `ldap_recon` | T1087.002 |
| GPO modification by a human (5136) | P3 | T | `groupPolicyContainer`, excluding SYSTEM/`*$` | T1484.001 |
| Admin account (adm-*) login outside working hours | P3 | T | 4624 adm-* + `off_hours:oui` | T1078 |
| Service/batch logon failure (broken service account) | P3 | T | 4625 LogonType 4/5 | — |
| Admin share sweep (≥3 hosts / account / 15 min) | P3 | T | 5140 `card(host)` | T1021.002 |

## 2. Endpoint & execution / elevation (A.8.7)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| LSASS memory access (credential theft) | P2 | T | Sysmon 10 → lsass.exe | T1003.001 |
| Process injection (Sysmon 8/25) | P2 | T | CreateRemoteThread / tamper | T1055 |
| Suspicious PowerShell | P2 | T | 4104 encoded / `-enc` / FromBase64 | T1059.001 |
| Suspicious LOLBin (hijacked system binary) | P2 | T | certutil/regsvr32/rundll32/mshta/bitsadmin | T1218 |
| Masquerading (system binary moved/renamed) | P2 | T | legitimate name outside expected path | T1036.005 |
| Use of explicit credentials (RunAs / lateral) | P2 | T | 4648 outside `*$`/self | T1078 |
| Remote WMI execution (lateral) | P2 | T | `wmi_lateral_exec` | T1047 |
| **UAC bypass (elevation)** | P3 | **M** | Sysmon 1: fodhelper/eventvwr/sdclt… → shell | T1548.002 |
| Defender: detection or disabling | P3 | T | Defender Operational (detection/AV off) | T1562.001 |
| Ransomware indicator (shadow copy deletion) | P3 | **M** | vssadmin/wmic shadow delete | T1490 / T1486 |
| New service installed (7045) | P2 | T | system service outside known agents | T1543.003 |
| Windows service installed (outside svchost) | P2 | T | 4697 outside legitimate svchost | T1543.003 |
| Scheduled task created (4698) | P2 | T | `scheduled_task`, aggregated host+account | T1053.005 |

## 3. Network, VPN & exposure (A.8.20–A.8.22 / A.5.7)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| Malicious IP (Tor / Spamhaus) | P3 | T | threat-intel lookup on public IP | T1071 |
| FortiGate: virus / IPS | P3 | T | UTM (virus/ips/attack) | — |
| Service exposed on the Internet (risky port) | P3 | T | `exposition_internet` (WAN→accepted risky port) | T1190 |
| VPN portal brute force (≥30 failures / IP / h) | P2 | T | `subtype:vpn status:failure` → **SOAR** | T1110 |
| VPN established from abroad | P3 | T | tunnel `remip` outside FR | T1133 |
| Internal network scan (reconnaissance / lateral) | P2 | T | `ndr_scan` / `network_scan` | T1046 |
| SOAR: IP blocked automatically | P3 | T | `omni-soar` action (telemetry) | — |

## 4. Microsoft 365 / Entra cloud (A.5.23)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| At-risk M365 account (Entra ID Protection) | P3 | **M** | `m365_type:risk` atRisk (Microsoft ML), aggregated account | T1078 |
| M365 successful sign-in outside France | P3 | T | `m365_etranger` (successful non-FR signin) | T1078 |
| M365 privileged role modification | P3 | T | `m365_role` (Entra admin role) | T1098 |
| M365 mail forward to an external domain | P3 | **M** | `m365_mail_forward` | T1114.003 |
| M365 mailbox delegation | P2 | T | `m365_mailbox_deleg` | T1098.002 |
| M365 external share / anonymous link | P2 | T | `m365_partage_externe` | T1567 |
| M365 application OAuth consent | P2 | T | `m365_oauth_consent` | T1528 |
| M365 brute force (≥10 failures / account / 30 min) | P2 | T | signin failure aggregated by account | T1110 |
| M365 brute force from abroad (cloud spray) | P2 | T | `m365_brute_externe` (non-FR failure / IP+account) | T1110 |
| M365 mass file deletion (≥100 / account / 15 min) | P2 | T | FileDeleted/Recycled | T1485 |
| AD failures + foreign M365 sign-in (same account / 1 h) | P3 | T | correlation 4625 + `m365_etranger` | T1078 |

## 5. UEBA / NDR / correlation (A.5.7 / A.8.16)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| Critical incident (correlated kill-chain) | P3 | **M** | `omni-incident-correlate` (multi-stage) | — |
| Impossible travel (multi-located account) | P3 | **M** | `ueba_geo` impossible travel | T1078 |
| New country for an account (first-seen) | P3 | T | `ueba_geo` new_country | T1078.004 |
| Successful lateral movement (1 account → N hosts) | P3 | **M** | `lateral_movement` (card host) | T1021 |
| Suspicious DNS tunneling (exfiltration) | P3 | T | `ndr_dns` (entropy/subdomains) | T1071.004 |
| Volume anomaly (z-score) | P3 | T | `volume_spike`/`volume_drop` | T1048 / T1562.001 |
| High-risk host (MITRE score ≥15 / 1h) | P2 | T | sum of `risk_score` per host | — |
| High UEBA-risk entity (≥80) | P2 | T | `ueba_score` ≥ 80 | — |
| Suspicious beaconing / C2 (NDR) | P2 | T | `ndr_beacon` (regular interval) | T1071 |
| Volume exfiltration (abnormal outbound flow) | P2 | T | `ndr_exfil` / `data_exfil` | T1048 |

## 6. Vault, WAF, EDR & sensitive files (A.8.7 / A.8.12 / A.5.23)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| Vaultwarden vault brute force (≥10 failures / IP / 15 min) | P3 | **M** | `vault_auth_fail` (src_ip + account) | T1555.005 |
| ESET: antivirus detection/threat | P2 | **M** | `eset_detection` (workstation/server threat) | T1204 |
| BunkerWeb: WAF block spike (≥20 / IP / 10 min) | P3 | T | `waf_block` aggregated by IP | T1190 |
| WAF: application scan (≥25 404 errors / IP / 10 min) | P3 | T | repeated HTTP 404 / IP | T1190 |
| Massive access to sensitive files (exfiltration?) | P3 | **M** | `file_sensitive_access` ≥200 / account / 10 min | T1039 |
| Mass file deletions (ransomware?) | P3 | **M** | `file_delete_sensible` ≥30 / account / 10 min | T1485 |

## 7. vSphere virtualization (A.8.9)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| vSphere brute force (≥5 failures / source / 10 min) | P2 | T | `vsphere_auth_fail` by src_ip | T1110 |
| vSphere ESXi SSH/Shell access | P2 | T | `vsphere_shell_ssh` (ESXi shell — cf. source note) | T1059 |
| vSphere VM deletion | P3 | T | `vsphere_vm_destroy` | T1485 |

## 8. Vulnerabilities, PKI & decoy (A.8.8 / A.8.16)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| Exploited KEV vulnerability (to patch urgently) | P3 | T | `vuln_kev` (CISA Known Exploited) | T1190 |
| CANARY ACCOUNT touched (probable AD intrusion) | P3 | **M** | AD decoy (~zero false positives) | T1078 (decoy) |
| Fleet certificate expiring soon | P3 | **M** | `cert_parc` (Get-OmniCertExpiry) | — |
| SIEM certificate expiring soon (<45d) | P3 | **M** | `siem_cert` auto-renew | — |

## 9. NPS / RADIUS (A.8.5)

| Rule | Prio | Tier | Logic | MITRE |
|-------|------|------|---------|-------|
| NPS: mass access denials (≥10 / account / 15 min) | P3 | T | 6273/6274 (Wi-Fi/VPN RADIUS) | T1110 |

## 10. SIEM health, integrity & operation (A.8.15 / A.8.16 / A.8.13)

| Rule | Prio | Tier | Logic | Control |
|-------|------|------|---------|----------|
| Audit sabotage (1102/4719/4794/104) | P3 | **M** | logging clearing/disabling | A.8.15 / T1562.002 |
| **Log integrity COMPROMISED (broken chain)** | P3 | **M** | `siem_integrity` `integrity_state:compromis` | A.8.15 / A.5.28 |
| Winlogbeat silence (0 Windows logs / 15 min) | P3 | **M** | absence of Windows flow | A.8.16 (go-dark) |
| Go-dark host (collection interrupted >26h) | P2 | T | `collecte_sla` `sla_type:go_dark` | A.8.16 |
| Analysis robot down (self-supervision) | P3 | **M** | `siem_health` job_fail | A.8.16 |
| SIEM disk >80% (/data) | P3 | **M** | `disk_warn` | A.8.6 (capacity) |
| EMERGENCY retention PURGE (disk almost full) | P3 | **M** | `disk_guard_prune` (≥88% → 82%) | A.8.6 |
| SIEM config backup missing (>26h) / failed | P3 | **M** | `backup_config_*` | A.8.13 |
| Veeam: job failed or warning | P3 | **M** | `veeam_job_echec` (final result eid 190) | A.8.13 / T1490 |
| Weekly report failed | P3 | **M** | `omni-weekly-report` | A.5.25 (review) |

---

## Register maintenance
On each addition/removal of a definition (`13`/`16`/`47`/`48`/`59`/`60`…): update
the relevant table + the breakdown. Counters verifiable live:
`GET /api/events/definitions` (total) and `22-alert-routing.sh` (output "MAIL
kept out of N"). Technical coverage: cf. **COUVERTURE-MITRE-ATTACK.md** +
the layer `mitre-navigator-layer.json`.
