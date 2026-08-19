# Deployment

The entire platform is provisioned by **~104 idempotent shell scripts** (`00-preflight.sh` …
`99-cert-orchestrator.sh`), each responsible for one concern and safe to re-run. A Docker
variant exists for DR / staging (`docker/`).

## Prerequisites

- A dedicated host (the reference node is `bx-it-graylog-vm`) with:
  - a LUKS-encrypted data volume mounted at `/data` (indices + snapshot repository sized
    **above** the primary index size — see [OPERATIONS.md](OPERATIONS.md));
  - Debian-family OS, `systemd`, `jq`, `curl`, Python 3 (stdlib only for the custom code).
- Network reachability from the log sources (Beats/TLS 5044, Syslog 1514–1520, GELF 12201/12202).
- Credentials/secrets populated in `00-vars.env` (root, `600`) from
  [SECRETS.example.md](../SECRETS.example.md) — nothing secret is committed.

## Provisioning order

Scripts are numbered so that running them in order builds the platform from bare host to full
SOC. Each is idempotent (safe to re-run; uses paginated, existence-checked Graylog API
helpers in `lib-graylog.sh`).

```
00–09   preflight · base · MongoDB · OpenSearch · Graylog · NGINX/TLS · firewall · inputs · backup · SNMP
10–14   data model · enrichment · pipelines · detections · dashboards
15–22   weekly report · M365 input/fetcher/activity · vSphere · alert hygiene · alert routing
27–49   service hardening · VPN/threat-intel · drift check · retention (ISO) · disk guard · LDAPS ·
        weekly report · canary · SOAR · MITRE ATT&CK · alert-triage · vuln scan · health collect ·
        UEBA/NDR · carte cyber · NDR-DNS · incidents · enrichment lots · port classing · LDAP recon
50–79   enrichment lots · new sources · Vaultwarden · FortiDHCP · MITRE coverage · identity correlation ·
        file audit · integrity · robot supervision · auto-updates · FortiManager · M365 fwd audit ·
        mobile PWA · threat-intel · detection coverage · ISO evidence · AD response · GitHub leak ·
        SOC console · dark-web leak · AD detection · source watchdog · console hardening ·
        cmdline detection · ML scoring · detection tuning · internal index set
80–99   analytics dashboard · FP allow-list · retention consolidation · site dashboards ·
        detections backlog · services versioning · deception/honeytokens · attack graph ·
        FortiClient EMS · DNS · Linux · Aruba · Entra · kit deploy · correlation · multi-site SOAR ·
        enrich-alerts · index templates · cert orchestrator
```

> Exact per-script detail is in the scripts themselves (each has a header block) and in
> [DOSSIER-ARCHITECTURE-SIEM.md](DOSSIER-ARCHITECTURE-SIEM.md).

## Key building blocks

| Path | Role |
|---|---|
| `lib-graylog.sh` | Shared Graylog API helpers (auth, pagination, idempotent create/update, entity wrapping) |
| `00-vars.env` | Central configuration &amp; secrets (root `600`) — **values must not carry inline comments** (a naive parser reads everything after `=`) |
| `triage/omni-alert-triage` | The alert-triage micro-service (+ `.env` template) |
| `lookups/` | 20 lookup tables (action guidance, MITRE map, allow-lists, re-accented labels…) |
| `oms-xdr` / `oms-ml` / `oms-graph` | Correlation, ML scoring, and attack-graph add-ons |
| `seal/` | SEAL physical-access integration (Logstash contract, pipelines, detections, SLA poller) |
| `mobile/` | SOC console (`soc/`) and mobile PWA |
| `kit/`, `windows/`, `fortigate/` | Collector kits and source-side configuration |
| `docker/` | Containerised variant for DR / staging |
| `tests/`, `run-tests.sh` | Test harness |

## Rebuild / disaster recovery

To rebuild from source onto a fresh host, follow
[PRA-RECONSTRUCTION-SIEM.md](PRA-RECONSTRUCTION-SIEM.md): provision the base stack (00–09),
restore MongoDB + the OpenSearch snapshot ([../RESTORE.md](../RESTORE.md)), then re-run the
model/detection/robot scripts. Because provisioning is idempotent, re-running the full suite
on an existing node reconciles drift rather than duplicating objects.

## Verifying a deployment

```bash
# inputs up
curl -s -u admin:$PW -H 'X-Requested-By: cli' https://127.0.0.1:9000/api/system/inputstates | jq '.states[].state'
# detections present & enabled
curl -s -u admin:$PW -H 'X-Requested-By: cli' 'https://127.0.0.1:9000/api/events/definitions?per_page=1' | jq .total
# triage answering
curl -s http://127.0.0.1:8089/stats
# no source silent
/usr/local/sbin/omni-source-watchdog
```
