# SOAR — Automated response playbooks (OMNITECH SIEM)

> Scoping of the "advanced SOAR" workstream · 2026-06-14
> Status: PB-01 in production. PB-02→05 **designed, pending the NinjaOne API**
> (access to be enabled on the tenant side, Owner account — the integration will be done upon receipt).

## Architecture (existing)
`omni-soar` service (`/usr/local/sbin/omni-soar`): local HTTP `127.0.0.1:8088`.
A Graylog HTTP POST notification → action → safeguards → state → effect.
- State: `/var/lib/omni-soar/blocklist.json`. Effect: `/var/www/siem-kit/soar/blocklist.txt` (threat feed served by nginx, consumed by the FortiGate).
- **Safeguards already in place (to keep for ANY new playbook):** never an RFC1918 / loopback / link-local / reserved IP, never the **whitelist**, hit threshold, **cap** (max size), **TTL** (auto expiration). Every action is traced in GELF (`event_source:siem_soar`).

## Playbook catalog

| # | Playbook | Trigger (alert_tag) | Action | Dependency | Status |
|---|---|---|---|---|---|
| **PB-01** | Block attacking IP | VPN brute force, password spraying | Add to FortiGate threat feed (TTL) | FortiGate (done) | ✅ **PROD** |
| **PB-02** | Isolate a compromised host | `ransomware_indicator`, `lsass_access`, `lateral_movement` (confirmed) | NinjaOne: network isolation of the device | **NinjaOne API** | 🟡 designed |
| **PB-03** | Disable an account | `canary`, `impossible_travel`, `dcsync` (confirmed) | AD account disable (NinjaOne script on DC, or LDAP) | **NinjaOne API** (or LDAPS) | 🟡 designed |
| **PB-04** | Open a ticket | Any P3 alert (email tier) | Create an incident with context (identity, host, MITRE) | **NinjaOne ticketing API** | 🟡 designed |
| **PB-05** | Enrich IOC | `threat_intel`, external IP/domain | TI enrichment + retro-hunt | MISP/feed (optional) | 🟡 designed |

## Detailed design (PB-02 → PB-04)
Each playbook = a new endpoint of the `omni-soar` service (`/isolate`, `/disable`, `/ticket`), called by a dedicated Graylog notification, with the **same reinforced safeguards**:

- **PB-02 Isolate host** — `POST /isolate {host}`.
  - CRITICAL safeguards: **never** a domain controller, the SIEM, the hypervisor, an infra server (whitelist of **host roles** to be defined); `risk_score >= 12` required; **reversible** (auto de-isolation after TTL or manual); **manual confirmation** option (tier "proposes, does not execute" for destructive actions).
  - NinjaOne: *device isolation* endpoint (API `https://eu.ninjarmm.com/api/v2/...`, scope *management*).
- **PB-03 Disable account** — `POST /disable {identity}` (relies on the unified **`identity`** field set by `58`).
  - Safeguards: **never** a *break-glass*/service/critical admin account (whitelist of accounts); reversible (traced reactivation); logged.
  - Mechanism: NinjaOne `Disable-ADAccount` script on a DC, or dedicated LDAPS bind (service account with minimal privileges: restricted *Account Operators*).
- **PB-04 Ticket** — `POST /ticket {event}` → pre-filled ticket (title = alert, body = identity + host + MITRE technique + Graylog link). Serves as an incident queue (compensates for the absence of case management in OSS).

## Client-side prerequisites (to provide before integration)
1. 🔑 **NinjaOne API**: `client_id` + `client_secret` (OAuth2), scopes *management* (PB-02/03) and *ticketing* (PB-04). EU region (`eu.ninjarmm.com`). → store in `00-vars.env` (chmod 600) in the manner of `FORTI_DHCP_TOKEN`.
2. **Whitelist of host roles** to NEVER isolate (DC, SIEM, hypervisors, NAS, network core).
3. **Whitelist of accounts** to NEVER disable (break-glass, critical service accounts).

## Validation (before production rollout of each playbook)
**Dry-run** mode first (`SOAR_DRYRUN=1`: the service logs the action without executing it), on a TEST host/account, then switch over. Explicitly test that a whitelisted / RFC1918 target is **refused**. Keep a log of triggers (useful for ISO A.5.25/5.26).

> As soon as the NinjaOne API is available: implementation of the `/isolate`, `/disable`, `/ticket` endpoints in `omni-soar` + notifications + safeguards, in dry-run then prod.
