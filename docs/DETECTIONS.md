# Detection engine

The platform runs **197 Graylog event definitions** (192 enabled), each mapped to a MITRE
ATT&CK technique and tactic, evaluated over the normalised streams. Detections are grouped by
kill-chain phase.

## Coverage by kill-chain phase

| Phase | Representative detections |
|---|---|
| **Initial access** | Malicious-IP SSL-VPN login (T1133), M365 legacy auth / MFA bypass (T1078.004), foreign M365 sign-in, anomalous geographic login — new country / impossible travel (T1078) |
| **Execution** | Office → interpreter (macro), WMI process-create, InstallUtil / certutil LOLBins, service-launched shell, malware on endpoint (ESET / FortiClient) |
| **Credential access** | LSASS memory access (T1003.001), NTDS.dit extraction, DCSync, Kerberoasting, AS-REP roasting, SAM/SYSTEM hive theft, GPP/SYSVOL creds, Vaultwarden brute force |
| **Persistence / privilege** | AdminSDHolder, RBCD (T1098.005), Shadow Credentials, autorun/Run keys (T1547), scheduled tasks (4698), IFEO hijack, privileged-group change, Zerologon |
| **Defence evasion** | Defender tamper / disable, AMSI bypass, event-log clearing (wevtutil), USN-journal deletion, audit sabotage, **silent-source detection (T1562.001)** |
| **Discovery / lateral** | AD recon (nltest/dsquery/LDAP), internal scan, admin-share sweep, WinRM lateral movement, RunAs credential use |
| **Collection / exfiltration** | Sensitive-file mass access, volume exfiltration (T1048, with legitimate-egress allow-listing) |
| **Impact** | Ransomware precursors — shadow-copy deletion, backup destruction, mass file deletion; extortion-site mention; dark-web leak |
| **Physical (SEAL)** | Intrusion / door forcing (ALM-003), badge refused out-of-hours (ACC-008), master-key assignment, brute force on console, dead-man flow interruption |
| **Health / assurance** | Backup failure/absence, disk pressure, certificate expiry, robot self-supervision, repo↔production drift, log-integrity chain |

Full catalogue: [REGISTRE-DETECTIONS.md](REGISTRE-DETECTIONS.md).
ATT&CK matrix: [COUVERTURE-MITRE-ATTACK.md](COUVERTURE-MITRE-ATTACK.md).

## Anatomy of a detection

Each event definition is provisioned idempotently (see [DEPLOYMENT.md](DEPLOYMENT.md)) with:

- a **query** on the normalised fields (e.g. `event_source:ueba_geo AND alert_tag:(impossible_travel OR new_country)`);
- a **`group_by`** key (e.g. `user`, `host`, `src_ip`) so alerts and de-duplication are
  **per-entity**, never global;
- an **aggregation condition** (count / cardinality thresholds) and a schedule;
- a **priority** (1 info / 2 high / 3 critical);
- **notifications** wired to the triage service (mail decisioning) and Teams (firehose).

## Enrichment pipeline

Normalisation and enrichment run in **40 pipelines / 250 rules**:

- **GeoIP** on source/destination IPs (country + coordinates).
- **Threat intelligence** — Tor/Spamhaus/URLhaus/abuse.ch feeds flag known-bad IPs and
  domains; shared-infrastructure allow-lists prevent large SaaS/CDN false positives.
- **MITRE lookup** — `alert_tag` → technique/tactic/name, so every alert carries its ATT&CK
  mapping.
- **Per-source field mapping** — vendor fields normalised to the common schema.
- **Noise &amp; false-positive allow-lists** — learned over time (service accounts, machine
  accounts, legitimate egress such as offsite backup targets, benign scanners).

## Behavioural analytics (UEBA / NDR)

Beyond static detections, ~39 robots add behavioural coverage and re-inject findings as
events:

| Robot family | Detects |
|---|---|
| **UEBA geo** | New-country / impossible-travel logins (VPN-filtered, 1 alert/account/day) |
| **UEBA volume** | Per-entity data-volume anomalies (z-score) |
| **UEBA score** | Cumulative per-entity risk score |
| **NDR beacon** | Beaconing / C2 (periodic outbound) |
| **NDR DNS** | DNS tunnelling / anomalies |
| **NDR exfil** | Volume-based exfiltration (allow-listed egress) |
| **NDR lateral** | Internal lateral movement |
| **NDR scan** | Internal reconnaissance / scanning |
| **ML anomaly** | IsolationForest anomaly scoring |
| **Health** | Backup, disk, drift, certificate, robot self-supervision, source freshness |

## Correlation into incidents

The triage service correlates detections across sources on canonical keys (identity / host /
IP / badge). When enough *distinct* detection types hit the same entity inside the window, a
**kill-chain incident** is raised (`event_source:alert_correlation`) — this is what turns a
scatter of single alerts into one prioritised incident, and it feeds the console's Incidents
and Attack-graph views.
