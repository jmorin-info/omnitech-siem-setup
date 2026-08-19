# OMNITECH SIEM — Docker deployment (full platform)

Reproduces the **core** of the platform in containers: Graylog 7.1.3 engine + OpenSearch 2.19.5
+ MongoDB, **SOC console** (`/soc`), **PWA** (`/m`) + `/m/api` backend, and **TLS nginx** as front end
(`/soc //m //kit` + Graylog). All Graylog **configuration** lives in MongoDB: **restoring the
dump = all the config** (17 streams, 13 inputs, 136 detections, 27 lookups, alerts, notifications).

> **Scope (honest).** The restore brings back the Graylog config + the console + the proxy + the
> **oms-xdr correlation** (dedicated service). For the TLS inputs and the **3D map** to work,
> provide the **certs** (`docker/certs/`) and the **GeoIP** databases (`docker/geoip/`) — see below.
> Remaining are **add-ons** launched separately: **oms-ml / oms-graph** (ML/graph) and the **fetchers**
> (M365/ESET/EMS) — a restore alone does not re-activate them (cf. table).

> For **staging, disaster recovery (DR), portability and demonstration**. Production remains
> the LUKS-encrypted bare-metal deployment; this bundle does not replace it.

## Services & dependencies (what the stack covers)

| Service     | Image / build                       | Role                                           |
|-------------|-------------------------------------|------------------------------------------------|
| `mongodb`   | `mongo:7.0`                         | All the Graylog config                         |
| `opensearch`| `opensearchproject/opensearch:2.19.5` | Event storage/search                         |
| `graylog`   | `graylog/graylog:7.1.3`             | SIEM engine (inputs, pipelines, detections)    |
| `console`   | `Dockerfile.console` (Python+pywebpush) | `/m/api` backend (OpenSearch read, push)    |
| `nginx`     | `nginx:1.27-alpine`                 | TLS, serves `/soc //m //kit`, Graylog proxy    |
| `oms-xdr`   | `Dockerfile.oms-xdr` (Python)       | Correlation/response (reads OpenSearch → GELF Graylog), DRY-RUN |

**Ported vs not ported (after `restore`):**

| Element | State | To activate it |
|---|---|---|
| Graylog config (streams/pipelines/detections/lookups/alerts) | ✅ ported | `restore` (mongodump) |
| Console `/soc` + PWA `/m` + `/m/api` + TLS nginx | ✅ ported | compose services |
| TLS inputs (Beats 5044, EMS 1518) | ⚠️ certs required | drop in `docker/certs/` |
| 3D map / GeoIP (`geo_*`) | ⚠️ mmdb required | `docker/geoip/fetch-geoip.sh` |
| **oms-xdr** correlation | ✅ ported | `oms-xdr` service (stream IDs ✓ after `restore`; readjust if fresh DB) |
| ML (oms-ml) / attack graph (oms-graph) | ➕ add-on | launched separately (`oms-*` folders) |
| M365 / ESET / EMS fetchers / SMB export | ➕ add-on | deployed separately |

**Data prerequisites** (before `restore`, for RUNNING inputs + a living map):
- `docker/geoip/` → `dbip-city-lite.mmdb` + `dbip-asn-lite.mmdb` (`./geoip/fetch-geoip.sh`).
- `docker/certs/` → `graylog.crt`+`graylog-pkcs8.key` (Beats), `fortiems-syslog.cert.pem`+`.key.pem` (EMS).

## Getting started

### Prerequisites
- Docker Engine + Compose v2, ≥ 6 GB free RAM, ≥ 20 GB disk.
- `sudo sysctl -w vm.max_map_count=262144` (persist in `/etc/sysctl.conf`).

```bash
cd docker
cp .env.example .env        # fill in the secrets (see below)
chmod 600 .env
./deploy.sh up              # builds the console + brings up the 5 services
# SOC console: https://<SERVER_NAME>/soc/   |   Graylog: https://<SERVER_NAME>/
```
The first start builds the console image and initializes Graylog (~1–2 min).

### Secrets (.env) — all generable in one line
| Variable | Generation |
|---|---|
| `GRAYLOG_PASSWORD_SECRET` | `openssl rand -hex 48` |
| `GRAYLOG_ROOT_PASSWORD_SHA2` | `echo -n 'Password' \| sha256sum \| cut -d' ' -f1` |
| `MOBILE_SECRET` | `openssl rand -hex 32` (HMAC of the console sessions) |
| `VAPID_PUBLIC_KEY` | *optional* (web push); empty = push disabled |
| `SERVER_NAME` | served name (CN of the self-signed cert generated at first start) |

### Deploy the FULL configuration
**Restore (DR / clone, recommended)** — from a `30-backup-config.sh` backup:
```bash
./deploy.sh restore omni-siem-config_AAAAMMJJ.tar.gz.enc   # asks for the BACKUP_PASSPHRASE
```
Restores the Mongo dump (all the config) + the lookups, restarts Graylog → **identical** SIEM.

**Rebuild from the scripts (IaC)** — empty stack then scripts `1x`–`9x` against the API of
the containerized Graylog (export `API` = URL of the container). Preferable for a fresh DB.

## Scalability
- **OpenSearch**: `OS_HEAP` (~50% of the RAM, max ~31 g). For a multi-node cluster, duplicate
  the `opensearch` service (os01/os02/os03), remove `discovery.type=single-node` and set
  `discovery.seed_hosts` + `cluster.initial_cluster_manager_nodes`; increase the index replicas.
- **Graylog**: `GRAYLOG_MEM` bounds the memory; for load, launch several Graylog nodes
  (same MongoDB + OpenSearch) behind nginx (`upstream` round-robin) — the state is shared in the DB.
- **Ingest**: tune the input buffers/threads (Graylog process/output buffers) according to the RAM.
- Memory limits set via `deploy.resources.limits` (compose v2); adjust to the host.

## Security (to read)
- OpenSearch security **disabled** and bound to the internal Docker network — **never expose**
  `9200`/`27017`. Only `443`/`80` (nginx) are published. nginx generates a **self-signed cert** at
  startup; in production, mount a real certificate on the `nginx_certs` volume.
- The console sets `Secure` cookies → **HTTPS mandatory** (ensured by nginx).
- `.env` (secrets): `chmod 600`, out of git (already `.gitignore`). The CSV lookups (`../lookups`) are
  mounted read-only in Graylog and the console.
- **Hardening (production) — docker secrets**: to avoid exposing the secrets as environment
  variables (visible via `docker inspect`), use the `docker-compose.secrets.yml` override:
  ```bash
  ./gen-secrets.sh                                   # generates ./secrets/* (chmod 600, out of git)
  # put non-empty placeholders in .env (GRAYLOG_PASSWORD_SECRET=managed-by-docker-secret, …)
  docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d
  ```
  The secrets are then mounted at `/run/secrets/*` (Graylog via an entrypoint wrapper, console and
  oms-xdr via the `*_FILE` convention).

## Operation
```bash
./deploy.sh status              # container status
./deploy.sh logs graylog        # (or console / nginx / opensearch)
./deploy.sh down                # stop (volumes preserved)
```

---

## English (summary)
Full containerized platform: Graylog 7.1.3 + OpenSearch 2.19.5 + MongoDB + **SOC console** (`/soc`,
`/m`, `/m/api`) + **TLS nginx**. All Graylog config lives in MongoDB → restoring the backup dump = the
whole platform. `cp .env.example .env` (set `GRAYLOG_PASSWORD_SECRET`, `GRAYLOG_ROOT_PASSWORD_SHA2`,
`MOBILE_SECRET`, `SERVER_NAME`), then `./deploy.sh up`. Restore full config with
`./deploy.sh restore <archive.tar.gz.enc>`. Scale OpenSearch to a multi-node cluster and run several
Graylog nodes behind nginx for load. Optional collectors (M365/ESET/EMS fetchers, oms-xdr/ml/graph)
are separate add-ons. Never expose `9200`/`27017`; only nginx `443/80`. Console requires HTTPS
(Secure cookies); nginx self-signs at first start — mount a real cert for production.
