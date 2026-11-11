# Architecture

## Overview

OMNI SIEM is a single-node, on-premise platform (`bx-it-graylog-vm`) that ingests, normalises,
stores, detects on, correlates, and acts on security telemetry from the whole OMNITECH estate.
It is built on the Graylog / OpenSearch / MongoDB stack and extended with a custom
detection, triage, response, and visualisation tier.

```
                         ┌──────────────────────────────────────────────────────┐
   Log sources           │                    bx-it-graylog-vm                    │
 ─────────────           │                                                        │
  Winlogbeat  ──TLS 5044─▶│  Graylog inputs ─▶ pipelines (40) ─▶ streams (22)      │
  FortiGate   ──Syslog───▶│      │              normalise/enrich       │           │
  (via FAZ)               │      │              tag MITRE / alert_tag  │           │
  M365/Entra  ──GELF─────▶│      ▼                                     ▼           │
  vSphere     ──Syslog───▶│  OpenSearch (indices on /data, 7.3 TB) ◀── event       │
  ESET / EMS  ──Syslog───▶│      ▲                                   definitions   │
  Aruba/Linux ──Syslog───▶│      │                                    (197)        │
  Vaultwarden ──GELF─────▶│      │                                     │           │
  SEAL (phys) ──GELF─────▶│  analytics robots (39) ──GELF re-inject──▶ alerts       │
  …                       │  (UEBA, NDR, watchdog, health)             │           │
                          │                                            ▼           │
                          │                     Teams / SOAR / omni-alert-triage    │
                          │   /soc/ console  ·  mobile PWA  ·  e-mail              │
                          └──────────────────────────────────────────────────────┘
```

## Core components

| Component | Role |
|---|---|
| **Graylog** | Ingestion (inputs), stream routing, pipeline processing, event definitions, dashboards, notifications, RBAC |
| **OpenSearch** | Search/analytics backend; message indices; snapshot repository for DR |
| **MongoDB** | Graylog configuration store (dashboards, streams, pipelines, users) |
| **NGINX + TLS** | Reverse proxy fronting the Graylog UI and the SOC console; certificate management |
| **systemd** | Runs every custom service and robot as a hardened unit with timers |

## Custom services

| Service | Port | Role |
|---|---|---|
| `omni-alert-triage` | 8089 | Alert scoring, cross-source correlation, LLM grey-zone judge, e-mail rendering, learned FP suppression |
| `omni-soar` | 8088 | Auto-block webhook → FortiGate address group |
| `omni-mobile-api` | — | Backend for the mobile PWA and the `/soc/` console |
| `omni-source-watchdog` | timer | Per-source freshness monitoring (silent-source detection) |
| ~35 analytics robots | timers | UEBA (geo, volume, score), NDR (beaconing, DNS, exfil, lateral, scan), health, enrichment |

All custom code is Python **stdlib-only** (no third-party runtime dependencies), which keeps
the attack surface and the maintenance burden low.

## Data flow

1. **Ingest.** 15 Graylog inputs receive logs over Beats/TLS (Winlogbeat), Syslog TCP/UDP
   (FortiGate via FortiAnalyzer, vSphere, ESET, Aruba, Linux, FortiManager), and GELF
   (M365 fetcher, SEAL, cert orchestrator, Vaultwarden).
2. **Normalise &amp; enrich.** 40 pipelines / 250 rules map every source to a common schema
   (`event_source`, `event_action`, `alert_tag`, `src_ip`, `user`, `host`, `mitre_technique`,
   `mitre_tactic`, GeoIP, threat-intel flags…) and route messages into 22 streams.
3. **Store.** Messages land in per-source OpenSearch index sets on the encrypted `/data`
   volume, with ISO-aligned retention per source.
4. **Detect.** 197 event definitions evaluate the streams; each carries a MITRE technique and
   a `group_by` key so alerts are per-entity, not global.
5. **Analyse.** ~39 robots run behavioural analytics (geo-velocity, beaconing, DNS anomalies,
   volume exfiltration, lateral movement, per-entity risk) and health checks, re-injecting
   their findings as first-class events.
6. **Route.** Every mailing detection notifies a single HTTP endpoint — the triage service.
   Teams and SOAR are wired in parallel where relevant.
7. **Triage.** `omni-alert-triage` decides whether a human is e-mailed and renders a clean
   notification (see [ALERTING-AND-TRIAGE.md](ALERTING-AND-TRIAGE.md)).
8. **Visualise / respond.** Analysts work in the Graylog dashboards and the `/soc/` console;
   attacking public IPs are auto-blocked back into the FortiGate.

## Storage &amp; volumes

| Path | Filesystem | Use |
|---|---|---|
| `/data` | LUKS-encrypted (7.3 TB) | OpenSearch indices (message data) |
| `/var` | 22 GB | Graylog/OpenSearch runtime, cluster state |
| `/home` | 805 GB | Application backups &amp; snapshot repository *(see note in OPERATIONS.md)* |
| `/` | 55 GB | OS |

## Network &amp; hardening

- TLS on the Graylog UI (9000) and the reverse proxy (443); Beats input on 5044 (TLS).
- The console is reachable per RSSI policy; SSH is locked down.
- The data volume is encrypted at rest (LUKS); the LUKS header is backed up off-box.
- Every service runs under systemd hardening (restricted capabilities, `Restart=on-failure`).
- Secrets live in `00-vars.env` (root, `600`) and per-service `.env` files; none are committed
  (see `SECRETS.example.md`).
