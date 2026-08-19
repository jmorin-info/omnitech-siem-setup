# Data sources

Roughly twenty logical log sources feed the platform. Each is normalised to a common schema
and watched for silence by the source-freshness watchdog.

## Source catalogue

| Source | Transport / input | `event_source` | Primary value |
|---|---|---|---|
| Windows Security | Winlogbeat → Beats TLS (5044) | `windows_security` | Authentication, privilege use, account &amp; GPO changes, Kerberos |
| Sysmon | Winlogbeat | `sysmon` | Process / network / registry telemetry (EDR-grade) |
| Windows (other) | Winlogbeat | `windows` | Services, scheduled tasks, PowerShell, DNS-server audit |
| FortiGate (multi-site) | Syslog via FortiAnalyzer (1514) | `fortigate` | Traffic, UTM, IPS, virus, SSL-VPN, DoS — `fortigate_site` = BDX / IV / LC |
| FortiManager | Syslog (1517) | `fortimanager` | Admin logins, configuration changes |
| FortiGate DHCP | API feeder | `forti_dhcp` | DHCP lease ↔ identity mapping |
| FortiClient EMS | Syslog TLS (1518) | `fortiems` | Endpoint AV detections, vulnerabilities, protection state |
| Microsoft 365 / Entra ID | GELF HTTP (fetcher) | `m365` | Sign-ins, MFA/device registration, mail forwarding, role changes, Identity Protection |
| VMware vSphere | Syslog (1516) | `vsphere` | Host/VM lifecycle, authentication, snapshots |
| ESET | Syslog (1515) | `eset` | Endpoint AV detections |
| Aruba | Syslog TCP/UDP (1520) | `aruba` | Switch/AP auth, port-security, STP |
| Linux | Syslog (1519) | `linux` | Host authentication and system logs |
| BunkerWeb (WAF) | — | `bunkerweb` | Application-firewall blocks and scanner activity |
| Vaultwarden | Filebeat / GELF | `vaultwarden` | Password-vault access and brute force |
| NinjaOne (inventory) | — | `inventory` | Asset inventory |
| Veeam | Winlogbeat — "Veeam Backup" channel | `veeam` | Backup job success / warning / failure |
| ADCS | — | `adcs` | Certificate-services abuse (ESC1–ESC8) |
| Certificate parc | GELF UDP (12201) | `cert_parc` | Certificate-orchestrator inventory &amp; expiry |
| Windows DNS | Winlogbeat — DNSServer/Audit | `dns` | DNS record changes, cache flush, sensitive zones |
| **SEAL** (physical) | GELF TCP (12202) | `seal` | Badge access, doors, alarms, intrusion, dead-man switches |

> **Derived (internal) sources**, re-injected by the robots and the triage service, are also
> searchable and dashboarded: `alert_triage`, `alert_correlation`, `ueba_geo`, `ueba_score`,
> `ueba_volume`, `ndr_beacon`, `ndr_dns`, `ndr_exfil`, `ndr_lateral`, `ndr_scan`, `ml_anomaly`,
> `attack_path`, `xdr_incident`, and the `siem_*` health/self-supervision events.

## Common normalised schema

Every message, whatever its origin, is enriched to a shared field set so detections and the
console are source-agnostic:

| Field | Meaning |
|---|---|
| `event_source` | Logical source (see table) |
| `event_action` | Normalised action (e.g. `connexion_reussie`, `echec_connexion`) |
| `alert_tag` | Detection tag driving MITRE lookup and playbook selection |
| `src_ip` / `dest_ip` | Source / destination IP (with GeoIP country + threat-intel flags) |
| `user` / `upn` | Account (canonicalised for cross-source correlation) |
| `host` | Affected host |
| `mitre_technique` / `mitre_tactic` | ATT&CK mapping |
| `risk_severity` / `risk_score` | Business risk from the analytics robots |

## Freshness monitoring

The `omni-source-watchdog` timer checks the max-timestamp of each monitored source against a
per-source silence threshold (minutes). When a collector goes quiet beyond its threshold it
raises a `source_silent` alert (ATT&CK **T1562.001**, *Impair Defenses*) — a blinded source is
itself a security event. Thresholds are configured in `WATCHDOG_SOURCES` and cover the
19 externally-fed sources.

## Integration notes

Source-specific setup is documented per source: Veeam ([../VEEAM.md](../VEEAM.md)),
Microsoft 365 / Entra ([../M365.md](../M365.md), [ENTRA-SETUP.md](ENTRA-SETUP.md)),
vSphere ([../VSPHERE.md](../VSPHERE.md)), FortiGate via FortiAnalyzer
([../FORTIANALYZER.md](../FORTIANALYZER.md)), LDAPS ([LDAPS.md](LDAPS.md)), plus the overall
[INTEGRATION-SOURCES.md](INTEGRATION-SOURCES.md) and [INVENTAIRE-SOURCES.md](INVENTAIRE-SOURCES.md).
