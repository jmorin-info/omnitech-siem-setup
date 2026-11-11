# Veeam Backup & Replication -> Graylog — procedure

On the SIEM side everything is ready (2026-06-12 pass):
- pipeline rules `omni-winother-10-veeam` (+ `-echec`): events from the Windows
  **"Veeam Backup"** channel are normalised (`event_source:veeam`,
  `event_category:sauvegarde`) and failed/warning jobs are tagged
  `alert_tag:veeam_job_echec` (error/warning level, or a "failed" message);
- alert **"OMNI - Veeam : job en echec ou avertissement"** (P3, e-mail,
  4 h grace period);
- dashboard page **OMNI - SOC > Sauvegardes** (volume, severity, failures per
  server, Veeam vSphere backup snapshots, triage).

## 1. On the Veeam server: NOTHING specific to do

Simply run **`Install-OmniSiem-NinjaOne.ps1`** (the single NinjaOne script) on
the Veeam server: it detects the Windows "Veeam Backup" log and automatically
adds the channel to THIS machine's Winlogbeat configuration.
The channel records job start/end, success/warning/failure.

Optional local check:
```powershell
Get-WinEvent -ListLog "Veeam Backup"            # does the log exist?
Get-WinEvent -LogName "Veeam Backup" -MaxEvents 5 | fl TimeCreated,LevelDisplayName,Message
```

## 2. Check on the SIEM side (~2 min after deployment)

```bash
curl -s "127.0.0.1:9200/omni-winother_*/_search?size=3" -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"event_source":"veeam"}},"sort":[{"timestamp":"desc"}]}' \
  | jq -r '.hits.hits[]._source | "\(.timestamp) | \(.source) | \(.winlogbeat_log_level) | \(.alert_tag // "-")"'
```
Then the **OMNI - SOC > Sauvegardes** dashboard.

## 3. Alternative / complement: native syslog (Veeam 12.1+)

Veeam B&R >= 12.1 can push its events over syslog (RFC 5424):
**Main menu > General Options > Event Forwarding > Syslog servers**
-> `bx-it-graylog-vm.omnitech.security`, port `1516` (existing vSphere/syslog
input) or a dedicated input. Provides structured fields (jobId, etc.).
The Windows channel is sufficient for the "failed job" alert; enable syslog
only if you want fine-grained per-job detail.

## 4. Good to know

- The alert only fires on error/warning: a nominal backup cycle sends NOTHING
  by e-mail (anti-noise).
- For an end-to-end test: re-run a job against a non-existent VM or cut the
  repository target — the alert should fire within a quarter of an hour.
- The vSphere snapshots created/removed by Veeam during backups are visible on
  the same page (rule `snapshot_sauvegarde` of the vSphere section) — this is
  the visual "pulse" of the backups.
