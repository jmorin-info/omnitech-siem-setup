# Log Retention Policy - OMNITECH Security (Graylog SIEM)

ISO/IEC 27001:2022 reference — A.8.15 (Logging), A.8.16 (Monitoring),
A.8.17 (Clock synchronization). **Risk-based** approach: the duration is
adapted to the security/forensic value of each source, within the limit of
available storage.

> Review: 2026-06-14 — to be validated and dated by the CISO.

## Retention periods (online, searchable)

Each source has a **dedicated index set** (prefix `omni-*`) with daily rotation
(`P1D`) and retention expressed as a number of indices (1 index = 1 day).
Retention "deletes" the indices once the window has been exceeded.

| Source                          | Index set        | Duration | Justification                                                            |
|---------------------------------|------------------|----------|-------------------------------------------------------------------------|
| Windows Security (AD)           | `omni-winsec`    | 180 d    | Security file: authentication, accounts, privileges, PKI (6 months)     |
| Sysmon (endpoint)               | `omni-sysmon`    | 90 d     | Detections, hunting, process/network (excluding registry noise); large volume — 90 d under capacity constraint (see capacity note) |
| Windows other (Veeam, ADCS…)    | `omni-winother`  | 90 d     | Veeam backups, PKI/ADCS, system services; 90 d under capacity constraint |
| Microsoft 365 / Entra           | `omni-m365`      | 365 d    | Cloud sign-ins, shares, roles, Entra ID audit (collected in GELF)       |
| vSphere                         | `omni-vsphere`   | 180 d    | Hypervisor access, VM deletions (6 months)                              |
| ESET PROTECT (EDR/AV)           | `omni-eset`      | 180 d    | Workstation/server detections, high forensic value (syslog JSON) (6 months) |
| FortiGate (firewall)            | `omni-fortigate` | 180 d    | High-volume traffic: 6-month forensic window (raised to 180 d on 14/08 for intrusion investigation depth) |
|                                 |                  |          | security events (deny/UTM/VPN) remain correlatable across the whole window |
| BunkerWeb (WAF)                 | `omni-bunkerweb` | 90 d     | High-volume HTTP/WAF logs; 90 d covers the investigation need           |
| Vaultwarden (password vault)    | `omni-vaultwarden` | 90 d   | Password vault: auth failures, admin access. **Dedicated index** to prevent volume/replay from evicting the SIEM's internal events |
| FortiManager (admin/config)     | `omni-fortimanager` | 90 d  | FAZ administration/configuration logs (changes, admin access). **Dedicated index** (created by `63`). 90 d under capacity constraint (to be raised if long-term traceability is needed) |
| SIEM internal (UEBA/ML/health)  | `omni-interne`   | 90 d     | Re-injected events: UEBA/ML scores, collection SLA, robot health, XDR incidents. 90 d covers trend analysis and ML training (windows ≤ 7 d). **Dedicated index** (created by `79`) |

Ancillary sources:
- **NPS / RADIUS**: fields mapped and index ready on the SIEM side, but
  collection is **not yet enabled on the client side** (no volume to date).
- **SIEM internal telemetry** (stream "OMNI - Interne SIEM": collection health,
  disk-guard, certificate monitoring): kept in the default Graylog index set,
  short retention (operational management, no long-term audit value).

## Events explicitly EXCLUDED (accepted risk, low value / high volume)

Noise reduction is applied **at pipeline stage 30, AFTER all detection**
(script 41-retention-iso.sh): it breaks no detection rule, it only avoids
durably storing high-volume, low-value events.

| Source           | Event                              | Reason                                                                                                       |
|------------------|------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Sysmon           | EID 12 (RegistryEvent add/delete)  | ~62% of Sysmon volume, noise; registry persistence remains covered by EID 13 (Value Set), which is retained  |
| Windows Security | 4673 (Sensitive Privilege Use)     | Very high volume, almost 100% benign (system services)                                                       |
| Windows Security | 4627 (Group Membership)            | Redundant with 4624 (already retained)                                                                        |

Deliberately retained despite their volume: **4662** (required for DCSync
detection) and **4688** (process creation traceability).

## Integrity & protection (A.8.15)
- OpenSearch indices are write-only (no after-the-fact modification).
- Log-clearing detection (1102 / 4719 / 1100 / 104) -> alert.
- Daily configuration backup; clocks synchronized (NTP).
- SIEM access restricted (LDAPS, dedicated AD group).
- Timestamp normalized at the event source (e.g. FortiGate: `eventtime`
  field), guaranteeing the real chronological order in forensics.

## Justification of durations (capacity constraint — A.8.15 risk-based)
The durations above result from a **risk × disk capacity** trade-off verified
on 2026-08-14. A uniform 365-d retention on all security sources would require
**~9 TB** — beyond the 7.3 TB `/data` disk — hence unrealistic. The chosen
approach: longest retention for the sources with the **highest traceability
value and lowest volume** (M365/Entra 365 d, SEAL 365-730 d), an
**intermediate 180-d tier** for medium-volume security sources (Windows Security,
ESET, vSphere, FortiGate — 6-month forensic window), and **90 d** for very
high-volume or low unit-value sources (Sysmon, Windows other, WAF/BunkerWeb,
Vaultwarden, DHCP, SIEM internal). Projection at full retention: **~5.3 TB ≈ 72%**
of the disk (replicas = 0, single node), below the 80% alert threshold. Any
extension of a high-volume source (e.g. Sysmon → 180 d) must be validated by a
capacity recalculation so as not to cross the emergency purge threshold (88%).

## Capacity safeguard (disk-guard)
Dedicated **/data disk, 7.3 TB**. The `omni-disk-guard` service (32-disk-guard.sh,
systemd timer every 6 h) is the ultimate safety net, beyond the nominal
retention above:

| /data occupancy threshold | Action                                                                                          |
|---------------------------|-------------------------------------------------------------------------------------------------|
| < 80%                     | Nothing: normal retention deletes indices at D+retention                                          |
| ≥ 80%                     | Alert (GELF -> "SIEM disk >80%" email) — review the retention plan                               |
| ≥ 88%                     | **Emergency purge**: deletion of the OLDEST `omni-*` indices (never a stream's active index) until dropping back below **82%**, + alert |

This mechanism intervenes BEFORE the OpenSearch watermarks (95% = indices
switched to read-only = collection stopped). Monthly review of the actual
GB/day (see collection supervision). At the current volume, /data is ~2%
occupied (147 GB).

---

_Document generated and maintained by 41-retention-iso.sh — to be validated and
dated by the CISO. See also: POL-SUPERVISION-JOURNALISATION.md, INVENTAIRE-SOURCES.md,
ISO27001-MAPPING.md._
