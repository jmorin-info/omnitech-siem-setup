# Inventory of monitored sources — OMNITECH SIEM

> Register of the log sources collected by the SIEM, their volume,
> retention and criticality. Feeds the asset inventory (ISO 27001 A.5.9) and
> proves monitoring coverage (A.8.16). Throughput is measured
> automatically (see the "Collection health" page and coverage supervision).

## 1. Collected sources

| Source (stream) | Origin | Transport (input) | Volume ~/day | Retention | Criticality |
|-----------------|---------|-------------------|---------------|-----------|-----------|
| **Windows Security** | Workstations & AD servers (audit) | Winlogbeat → Beats TLS 5044 | ~5.5 GB | **365 d** | High |
| **Sysmon** | Endpoints (process/network telemetry) | Winlogbeat → Beats TLS 5044 | ~1.8 GB* | **365 d** | High |
| **Windows other** | Veeam ("Veeam Backup" channel), AD CS (PKI), Defender, services | Winlogbeat → Beats TLS 5044 | ~2.7 GB | **365 d** | Medium |
| **FortiGate** | Firewall (traffic, UTM, VPN) | FortiAnalyzer → syslog 1514 (key=value) | ~11 GB | **180 d** | High |
| **Microsoft 365 / Entra** | Cloud (sign-in, audit, activity) | Graph API → collector → GELF HTTP 12201 | ~0.02 GB | **365 d** | High |
| **vSphere** | ESXi / vCenter | syslog UDP/TCP 1516 | ~0.6 GB | **365 d** | High |
| **ESET PROTECT** | Antivirus console (10.33.50.20) | syslog JSON TCP 1515 (514 redirected) | low | **365 d** | High |
| **BunkerWeb (WAF)** | Reverse-proxy WAF (10.33.70.1) | Filebeat → Beats TLS 5044 | ~0.3 GB** | **90 d** | High |
| **SIEM internal** | In-house analyses (UEBA/NDR/incidents/health/vuln) | local GELF 12201 | low | default | High |

\* Sysmon after filtering out noise (EventID 12 registry).
\*\* BunkerWeb after *dropping* the stderr/metrics noise (~97% of the raw volume).

**NPS (RADIUS, 10.33.50.247)**: already mapped on the SIEM side (lookup `win-events.csv`,
EventID 6272/6273/6274 → `event_source:nps`). Awaiting ingestion: Winlogbeat
to be deployed on the NPS server. Associated alert already created (script 13).

Total ~22 GB/day on disk (before compression). `/data` = 7.3 TB dedicated.
Capacity detail and projections: `POLITIQUE-RETENTION.md`.

## 2. Coverage & continuity (A.8.16)

- **Measured coverage**: rate of "managed" hosts emitting within the last
  24 h, computed continuously ("Collection health" page). Target: ~100%.
- **Gap detection**: a host that stops emitting (>26 h) is flagged
  *go-dark* (P2 alert) — covers both agent failure and sabotage.
- **Self-supervision**: the ~13 analysis robots are themselves monitored
  (P3 alert if one stops) — detection cannot go blind
  silently.

## 3. Normalized fields (interoperability)

All events are normalized to a common schema (unified fields) to
enable cross-source correlation:

- Identity: `host`, `user`, `src_ip`, `src_host`, `event_id`, `event_action`,
  `event_source`, `event_category`.
- Security: `alert_tag` (detection), `mitre_technique` / `mitre_tactic`,
  `risk_score` / `risk_severity`.
- Network: `action`, `dest_ip`, `dest_country`, `srccountry`, `bytes_*`,
  geolocation.
- M365: `m365_type` (signin / audit / **risk** — Entra ID Protection), `m365_workload`,
  `src_country`, `upn` (`alert_tag:m365_risque` on an atRisk account).
- ESET: `eset_event_type`, `eset_severity`, `eset_action`, `eset_target`, `eset_detail`,
  `eset_hostname`, `eset_user` (`eset_` prefix; `alert_tag:eset_detection` on a threat).
  *(The `eset_threat_name`/`eset_object_uri` fields do not exist — fixed 2026-06-14.)*
- BunkerWeb / WAF: `waf_vhost`, `http_method`, `http_url`, `http_status`,
  `http_user_agent`, `src_ip` (`alert_tag:waf_block` on HTTP 403).
- Vaultwarden (password vault): `vault_user`, `src_ip`, `vw_level`, `vw_module`
  (routing `filebeat_event_source=vaultwarden`, dedicated index `omni-vaultwarden`).
- Network/identity (enrichment): `src_hostname`/`dest_hostname` (FortiGate DHCP
  attribution, script 56), `identity`/`identity_human` (cross-source correlation, script 58).

The routing of each source relies on `event_source` (FortiGate, ESET, vSphere,
M365, Veeam, NPS) or `filebeat_event_source` (BunkerWeb). On the FortiGate side, the
Graylog `source` field is set to the device name (`host` =
renamed `devname`), which allows logs to be separated per firewall.

## 4. Timestamping (A.8.17)

All sources and the SIEM are NTP-synchronized on the domain controller
(PDC emulator, 10.33.50.250). The `timestamp` field is in UTC, consistent across
sources, which guarantees the reliability of temporal correlations (impossible
travel, kill-chain, beaconing).

FortiGate special case: the SIEM timestamp is derived from the `eventtime` field
(epoch nanoseconds) emitted by the device, and not from the FAZ syslog header —
this avoids any drift related to the FortiAnalyzer relay.

## 5. Source protection (collection integrity)

- Incoming flows restricted by local firewall (nftables) to the authorized
  subnets/hosts (cf. `00-vars.env`: NET_BEATS, IP_FAZ, VSPHERE_NET, IP_ESET,
  IP_BUNKERWEB, IP_NPS).
- Encrypted transport for the Beats agents (Winlogbeat / Filebeat): Beats TLS
  input 5044 (certificate `/etc/graylog/certs/graylog.crt`). ESET, FortiGate and
  vSphere are on syslog over the internal VLANs restricted at the firewall.
- Dedicated collection accounts (M365: Entra app with read privileges; AD:
  LDAPS bind service account).

---
*Inventory to be kept up to date when adding/removing a source. See
`ISO27001-MAPPING.md` (A.8.15/8.16), `INTEGRATION-SOURCES.md` (integration
procedures) and `POLITIQUE-RETENTION.md` (durations). Review: 2026-06-14.*
