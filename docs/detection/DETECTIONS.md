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

Each event definition is provisioned idempotently (see [../DEPLOYMENT.md](../DEPLOYMENT.md)) with:

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

## Correlation layer v3 (November 2026)

An additive layer: its own pipeline stage, its own event definitions (prefix "OMNI v3 - ") and a
lookup table of critical assets. Highlights: gMSA password read by a user account, Kerberos
RC4/DES coming back, firewall administration from a public IP or with the local break-glass
account, unremediated EDR detection (critical on a tier-0 asset), backup job or restore-point
deletion, and EDR detection followed by an admin logon on the same host within the hour.
Each rule was replayed over 30 days before activation. Build, test and rollback scripts:
[`../../tools/omni-v3/`](../../tools/omni-v3/).

## Detection layer v5 (November 2026)

A second additive layer, built like v3: its own pipelines, rules prefixed `omni-v5-` and event
definitions prefixed "OMNI v5 - ". Until 2026-12-04 these definitions are in rollout: the daily
digest lists them in a dedicated section instead of sending one mail per alert.

- **Active Directory and Microsoft 365** (pipeline "OMNI v5 - Detections AD et M365", stage 45):
  Kerberoasting with AES tickets (RC4 is disabled, so rules keyed on encryption type 0x17 no longer
  fire), AS-REP roasting preparation, DCSync and Shadow Credentials allowed only for the exact
  Entra Connect account, AD CS SAN abuse (ESC1/ESC6) and template or CA changes (ESC4/ESC7),
  service installed on a domain controller or PKI, GPO linked to the domain root or the Domain
  Controllers OU, LSASS memory read outside a strict allow-list, decoy account, canary files,
  external mail forwarding, suspicious inbox rules and MFA fatigue. Microsoft 365 definitions use
  five-hour windows because Exchange audit records arrive late (about 85 minutes median). Site
  values (domain controllers, Entra Connect account, decoy account, canary file names) are read
  from `/etc/omni-v5-ad/site.json`; template: `site.exemple.json`.
- **Threat intelligence** (pipeline "OMNI v5 - TI enrichissement", stage 19): `omni-v5-ti-fetch`
  refreshes Feodo Tracker, Tor exit nodes, ThreatFox, URLhaus and MalwareBazaar every two hours
  into lookup tables; rules enrich FortiGate, Sysmon and ESET events, and a retro-hunt script
  searches the last 90 days. Popular domains and proven false positives are filtered out. Blocking
  high-confidence Feodo C2 addresses on the FortiGate is prepared but disabled.
- **Collection**: normalisation of Directory Service (unsigned LDAP binds), AppLocker and LAPS read
  events, a GELF TCP input for domain-controller DNS queries, and direct syslog from a site
  firewall as a fallback for FortiAnalyzer. Linux auditd rules and their deployment script are in
  `tools/omni-v5-collecte/auditd/`.

Detection rules were checked in the Graylog simulator and replayed over 30 days of real data before
activation. Build, test and rollback scripts: [`../../tools/omni-v5-ad/`](../../tools/omni-v5-ad/),
[`../../tools/omni-v5-ti/`](../../tools/omni-v5-ti/) and
[`../../tools/omni-v5-collecte/`](../../tools/omni-v5-collecte/). Filtered export of the resulting
Graylog objects: [`../../objets-graylog/v5/`](../../objets-graylog/v5/).
