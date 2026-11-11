# Windows / Active Directory component — exact steps

Everything that happens on the **DC (BX-AD-01-IT-VM / 10.33.50.250)** side and on the
**workstations/servers** side. Suggested order: 1 → 5, in pilot first.

> **⭐ Recommended path (12/06): `Install-OmniSiem-NinjaOne.ps1`** — the
> SINGLE and definitive script for NinjaOne (SYSTEM, 64-bit, daily
> scheduling). It REPLACES `Deploy-SiemAgents-NinjaOne.ps1` +
> `Set-OmniAudit-NinjaOne.ps1`: Root CA (TOFU), audit policy, Sysmon,
> Winlogbeat (restart only if the config changes), "Veeam Backup" channel
> added automatically on the Veeam server, and health check
> (test output 5044 + scan of channel errors). [OK]/[KO] summary per
> component, exit 1 if a component is KO (visible in NinjaOne).
> The GPO/NETLOGON sections below remain valid as an alternative path
> without NinjaOne.

## 0. Prepare the distribution point (once, on the DC)

```powershell
# On BX-AD-01-IT-VM, as domain admin:
$d = "C:\Windows\SYSVOL\sysvol\omnitech.security\scripts\SIEM"   # = NETLOGON\SIEM
New-Item -ItemType Directory -Path $d -Force
# Place there:
#  - Sysmon64.exe                  <- https://live.sysinternals.com/Sysmon64.exe
#  - sysmonconfig-omnitech.xml     <- this kit
#  - winlogbeat-oss-8.17.4-windows-x86_64.zip
#       <- https://artifacts.elastic.co/downloads/beats/winlogbeat/
#          !! OSS version mandatory (the standard one refuses a non-Elastic output)
#  - winlogbeat.yml                <- this kit (check the SIEM FQDN inside it)
#  - omnitech-rootca.pem           <- Base64 export of the Root CA:
#       On BX-PKI2022: certutil -ca.cert C:\temp\rootca.cer
#       then rename .cer (already Base64? otherwise: certutil -encode rootca.cer omnitech-rootca.pem)
```
NETLOGON is replicated on both DCs and readable by the computer accounts:
perfect for a deployment without Internet.

## 1. Audit GPO (on the DC)

```powershell
cd <kit>\windows
# Links by default to omnitech.security/Entreprise + Domain Controllers:
.\Deploy-AuditGPO.ps1
```
What the GPO applies: the advanced audit policy from the CSV (4624/4625, 4688,
4768/4769/4776, account management, 4662/5136, USB/Removable Storage, NPS,
Certification Services for the PKI, 1102…), the **command line in the
4688s**, the **PowerShell Script Block + Module Logging**, a Security log of
**2 GB**, and the enforcement of the advanced policy (SCENoApplyLegacyAuditPolicy).

Verification on a pilot client:
```cmd
gpupdate /force
auditpol /get /category:*
wevtutil gl Security        :: maxSize must show 2147483648
```

DC notes: the *DS Access/DS Changes* subcategories produce events
**only** on domain controllers — DCSync detection (4662)
works with the partition's default SACL. Exhaustive 5136s
may require a SACL expansion (optional, later).

## 2. Sysmon + Winlogbeat deployment across the WHOLE domain

### Option A (recommended): GPO, from AD — `Deploy-AgentsGPO.ps1`

```powershell
cd <kit>\windows
# Links by default to omnitech.security/Entreprise:
.\Deploy-AgentsGPO.ps1
```

The `OMNI-SIEM-Agents` GPO pushes a **SYSTEM scheduled task** to each
machine (at boot +5 min, + every day at 12:00 with random delay 0-2 h)
which runs `\\omnitech.security\NETLOGON\SIEM\Deploy-SysmonWinlogbeat.ps1`.
Since this script is idempotent, the GPO also serves as a **maintenance** channel:
replacing `winlogbeat.yml` or `sysmonconfig-omnitech.xml` in NETLOGON\SIEM
is enough, the fleet converges in under 24 h.

Deployment tracking (on the SIEM): count the hosts that report in —
Graylog search `streams:OMNI - Sysmon`, aggregation on `host`, or
the *OMNI - Windows Securite* dashboard.

### IMPORTANT if you deploy via NinjaOne (and not via GPO)

The `OMNI-AUDIT-Baseline` GPO does **not** apply to workstations managed by
NinjaOne outside the GPO scope → they send Sysmon/PowerShell but **0
Security event** (Windows audits almost nothing by default). In that case, push
the audit policy **locally** with a 2nd NinjaOne script:

`Set-OmniAudit-NinjaOne.ps1` (SYSTEM, 64-bit, daily) applies exactly
the same baseline as the GPO (auditpol /restore + 4688 cmdline + ScriptBlock
4104 + SCENoApplyLegacyAuditPolicy + 2 GB Security log). Idempotent, the
CSV baseline is embedded in the script (no network dependency).
Verification on the workstation: `auditpol /get /category:*` then, after a few
minutes, the host reports the 4624/4625/4688 in Graylog (*AD Identity* page).

To be chained with `Deploy-SiemAgents-NinjaOne.ps1`: two distinct NinjaOne
scripts (agents + audit), or call the audit at the end of the agents script.

### Option B: NinjaOne (non-domain fleet, VIPs, catch-up)

In NinjaOne: *Administration > Scripting* → new PowerShell script,
paste `Deploy-SysmonWinlogbeat.ps1`, execution as **SYSTEM**, 64-bit.
Assign it as a scheduled task (e.g. daily) on the
PILOT then PRODUCTION_POSTES / PRODUCTION_SERVEURS groups — it is idempotent:
it installs, updates the config, or does nothing if everything is compliant.
The two channels can coexist without conflict (same script, same source).

Also target the sensitive servers: **BX-AD02, WSUS, PKI (BX-PKI2022),
NPS, file servers** — since DC1 already has Winlogbeat, the script will
simply bring it up to level (same conf for everyone).

Verification on a workstation:
```powershell
Get-Service Sysmon64, winlogbeat
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
Get-Content "C:\ProgramData\winlogbeat\logs\winlogbeat*" -Tail 20   # "Connection to backoff(...) established"
```

## 3. On the FortiAnalyzer side (10.33.80.253)

*System Settings > Advanced > Log Forwarding > Create New*:
mode **Forwarding**, server `10.33.220.10`, protocol **syslog** port `1514`
(or **CEF** port `5555` → then create the CEF input in Graylog: System >
Inputs > CEF TCP). Add **filters**: event severity ≥ warning,
auth/admin/vpn/ips/av/local-in subtypes — the verbose *accept* traffic stays
in the FAZ (it is the network lake, Graylog does the correlation).

## 4. DNS (on the DC)

```powershell
Add-DnsServerResourceRecordA -ZoneName "omnitech.security" -Name "bx-it-graylog-vm" -IPv4Address "10.33.220.10" -CreatePtr
```

## 5. What the clients produce (incoming data model)

| Collected Windows channel | Key EventIDs | Detection use |
|---|---|---|
| Security | 4624/4625/4634/4648/4740 | auth, bruteforce, lateralization |
| Security | 4768/4769/4771/4776 | Kerberos, Kerberoasting, NTLM |
| Security | 4720-4756 | account/group lifecycle |
| Security | 4662/5136 | DCSync, AD changes |
| Security | 4688 (+cmdline), 4697/4698, 7045 | execution, services, tasks |
| Security | 1102, 4719 | log clearing, audit sabotage |
| Sysmon | 1, 3, 6, 7, 8, 10, 11, 12-14, 17-21, 22, 25 | process+hash, network, LSASS, persistence, DNS |
| PowerShell/Operational | 4103, 4104 | malicious script blocks |
| Defender/Operational | 1116/1117, 5001/5007 | detections, AV disabling |
| System | 104, 7045, 6008… | services, abnormal shutdowns |

The Graylog pipelines (script 12) then normalize to: `event_id`,
`event_source`, `event_action`, `event_category`, `user`, `host`, `src_ip`,
`dest_ip`, `dest_port`, `process_name`, `process_path`, `command_line`,
`parent_process`, `dns_query`, `logon_type_label`, `failure_reason`,
`priv_group_label`, `alert_tag` — these are the fields used by the
detections (script 13) and the dashboards (script 14).
