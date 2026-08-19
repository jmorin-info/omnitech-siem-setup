# SOC console "OMNI SOC" — Guide

Web console + mobile PWA for operating the OMNITECH SIEM/XDR. **VPN-only**,
AD authentication (delegated to Graylog/LDAPS). Built on the
`omni-mobile-api` backend (OpenSearch read, stdlib + pywebpush) served by nginx.
Premium interface (glassmorphism, glow, micro-interactions), keyboard accessible.

## Access
- **Desktop console**: `https://bx-it-graylog-vm.omnitech.security/soc/`
- **Mobile app (PWA)**: `https://bx-it-graylog-vm.omnitech.security/m/` → *Share → Add to Home Screen* (installable, web-push).
- Login: **AD account** (the same credentials as the Graylog console).
- Shortcuts: **Ctrl/Cmd + K** = palette (navigation + **entity search**); **?** = help & shortcuts; **Esc** = close; **Enter/Space** = activate the focused element.

## Pages (desktop)
| Page | Content |
|---|---|
| **Overview** | KPIs **with trend** (▲/▼ % vs previous period), 24 h detections curve, ATT&CK tactics donut, top detections/sources, **ML Anomalies** + **UEBA Risk** (real scores), real-time feed (SSE), geographic origins |
| **Incidents** | Queue of **cases** (oms-xdr): status, assignment, notes; **True/False positive disposition** → feeds the FP-reduction ML model |
| **Detections** | **Filterable** list (tactic/source) + **free search** + **CSV export**; real severity (`risk_severity`) + risk score; click → Entity-360 |
| **ATT&CK Matrix** | Tactics × techniques heatmap, colored by real activity (7 d), clickable cells (drill) |
| **Attack graph** | Entities ↔ techniques graph, **filterable** (tactic, volume threshold, entity centering) |
| **Leaks & Dark Web** | Summary by category (extortion/credentials/GitHub), RansomLook/HIBP/Dehashed, reassuring "no leak" state |
| **Health & Collection** | Cluster status, **self-supervision robots** (X/Y), **collection coverage (SLA)** + **go-dark hosts**, freshness per source |
| **Report** | Printable executive summary (PDF): KPIs, coverage, **operational posture (robots/SLA)**, **ML & UEBA at-risk entities**, incidents, sources |
| **Entity-360** (panel) | An entity's sheet: **ML score + UEBA score**, tactics, ATT&CK techniques, recent events ("load more" pagination) |

## ML layer (oms-ml)
The console surfaces the scores from the **`oms-ml`** package (local sklearn, cf. `oms-ml/README.md`):
- **Unsupervised anomaly** (IsolationForest) per entity → `ml_score` reinjected as GELF (`event_source=ml_anomaly`), visible on the Overview and Entity-360.
- **Supervised false-positive reduction**: trained from the **TP/FP disposition** set by analysts at case closure (closed loop).
- Internal events (`ueba_score`, `collecte_sla`, `siem_health`, `xdr_incident`, `ml_anomaly`) are written to the **`omni-interne`** index set (cf. `79-interne-indexset.sh`) — without which the console (which reads `omni-*`) would not see them.

## Ergonomics & UX
- **Toasts**: non-blocking feedback on actions (case qualified, export, session expired, network error).
- **Help (?)**: keyboard shortcuts, role of each page, glossary of signals (ML, UEBA, severity, go-dark, KEV).
- **Density**: comfortable/compact toggle (persisted).
- **Loading**: skeletons on first display, "Updated Xs ago" badge, adjustable **refresh cadence** (30 s / 60 s / pause).
- **Accessibility**: navigation and modals operable via keyboard (visible focus, focus-trap, ARIA).

## Mobile PWA
**Summary** tabs (KPIs, curve, tactics), **Alerts**, **Incidents**, and **Threat** —
console parity: threat level + KPIs, **ML anomalies & UEBA risk** (gauges), detections with colored severity. Installable, web-push.

## Architecture
```
Browser (VPN) → nginx 443 → /soc/ (static) + /m/ (PWA) + /m/api/* (proxy → omni-mobile-api 127.0.0.1:8090)
omni-mobile-api: Graylog auth (LDAPS) → HMAC cookie; OpenSearch read; SSE; web-push VAPID
```
- **Endpoints** `/m/api/`: login, me, kpis, **kpi-trend**, timeseries, by-tactic, top-detections, top-sources,
  alerts, cases (+POST case with `disposition`), detections, **entity-search**, entity (size/from + scores), attack-matrix,
  graph, **leaks2**, health, report, geo, risk, stream (SSE), vapid/subscribe (push).
- **Performance**: in-memory micro-cache with TTL (30 s, `MOBILE_CACHE_TTL`) on the heavy aggregations
  (attack-matrix, report, kpis, health, geo, terms) — ATT&CK matrix ~783→7 ms, report ~811→3 ms.
- **Security**: VPN-only, HttpOnly+Secure+SameSite=Strict cookie, login rate-limit (5/15 min),
  CSP/HSTS/X-Frame-Options headers (`75-console-hardening.sh`).
- **Redaction mode** (`MOBILE_REDACT=1`): consistently pseudonymizes accounts/hosts/IPs/SIDs
  (reversible map for Entity-360) — used to produce anonymized screenshots. **Disabled in operation.**

## Operation
- Backend: `systemctl status omni-mobile-api`; conf `/etc/default/omni-mobile`.
- Deployment / update: `65-mobile-pwa.sh` (PWA + backend), `71-soc-console.sh` (console).
- Front-end libraries vendored locally (`chart.min.js`, `cytoscape.min.js`) — no CDN at runtime.
- **Tests** (offline, without OpenSearch): `./run-tests.sh` — redaction (`_rd`/`_scrub`) + oms-ml (anomaly, FP gating); 23 tests.
