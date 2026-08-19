# PRA — SIEM reconstruction plan on a new server

*Version 1.0 — 12/06/2026 — Classification: internal — ISO ref A.8.13, A.5.30*

This document describes the **recommissioning of the SIEM on a replacement
server** in the event of loss of the `bx-it-graylog-vm` VM. It complements the
detailed technical procedure `RESTORE.md` (exact commands) with the continuity
framework: objectives, scenarios, roles, validation.

## 1. Continuity objectives

| Indicator | Target value | Rationale |
|---|---|---|
| **RTO** (collection resumption) | ≤ 4 h | after a compliant VM is made available |
| **RPO config** (configuration loss) | ≤ 24 h | daily backup at 03:15 |
| **RPO logs** (history loss) | up to the last retention | **logs are not backed up** (deliberate choice: volume) — only the configuration is |

**Key consequence**: after reconstruction, the entire collection chain,
detections, dashboards and alerts resume identically; the history of prior logs
is lost but real-time collection restarts immediately (agents/forwarders point
to the same FQDN/IP).

## 2. Prerequisites permanently available (to verify now)

| Item | Location | Verified |
|---|---|---|
| Encrypted config archives (14 d) | `\\10.33.50.5\Public\SIEM\omni-siem-config_*.tar.gz.enc` | rotation OK |
| **Decryption passphrase** | Vault (`BACKUP_PASSPHRASE`) | ⚠️ TO BE DEPOSITED IN THE VAULT |
| Local emergency `admin` password | Vault | ✅ |
| `svc_siem` credentials (SMB) | Vault | ✅ |
| Technical procedure | `RESTORE.md` (included in the archive) | ✅ |
| IP/DNS reservation `10.33.220.10` / FQDN | Internal DNS + /etc/hosts | ✅ |
| **Integrity HMAC key** `/etc/graylog/omni-integrity.key` | Vault + out-of-band | ⚠️ without it, the past integrity chain can no longer be **verified** (loss of evidentiary value) |
| **LUKS emergency passphrase for `/data`** + **encrypted header backup** (header **inline**; `omni-luks-header-*.img.enc`) | Passphrase → Vault; header → SMB `/SIEM/luks/` (+ included in the daily encrypted config backup) | ⚠️ without the **passphrase**, `/data` is unrecoverable if the TPM/motherboard changes; the inline header is **backed up/restorable** (`luksHeaderRestore`) |

> Without the backup passphrase, the archives are **unrecoverable**.
> The same applies to the **integrity HMAC key** (audit-trail verification) and the
> **LUKS passphrase/header** (decryption of `/data` on new hardware — the
> TPM is bound to the motherboard, re-enrolment required upon replacement). These 4 secrets
> are the single points of failure of the PRA: presence in the vault verified at
> each quarterly review.

## 3. Scenarios and triggering

| Scenario | Response |
|---|---|
| Corrupted VM / lost system disk, `/data` intact | Rebuild the OS + stack, restore the config, **re-point `/data`** (logs retained) |
| Total loss (VM + data) | Full reconstruction, logs start from zero |
| Temporary unavailability (crashed service) | No PRA: `systemctl restart`; see PRO §4 |

Triggering: decision of the **SIEM Admin** (operational incident) or the
**IT department** (major disaster). Notify the IT team (alerts will cease
during the switchover).

## 4. Reconstruction procedure (summary — details in RESTORE.md)

1. **Provision** a Debian 12+ VM, **same hostname/IP** (`bx-it-graylog-vm`
   / 10.33.220.10), VLAN 220, data disk on `/data`.
2. **Install the stack** at the reference versions (DOSSIER §2: Graylog
   7.1.3, OpenSearch 2.19.5, MongoDB 8.0.24, nginx) + `cifs-utils`.
3. **Retrieve and decrypt** the latest archive from the SMB share
   (`svc_siem` account, vault passphrase).
4. **Restore**: `/etc` files (graylog, opensearch, nginx, systemd),
   `/usr/local/sbin`, `/kit` kit, IaC `~/omnitech-siem-setup`, then
   `mongorestore` of the `graylog` database (Mongo auth handling: RESTORE §4).
5. **Start** mongod → opensearch → graylog-server → nginx; re-enable the
   `omni-*` timers.
6. **Verify** (see §5).

## 5. Post-reconstruction validation (checklist)

- [ ] Console accessible over HTTPS, AD login (LDAPS) **and** local `admin` OK.
- [ ] Inputs listening: `ss -tlnp | grep -E "5044|1514|1516|12201"`.
- [ ] Winlogbeat agents reconnect (search `source:*` < 5 min).
- [ ] FAZ and vSphere emitting (FortiGate / vSphere streams populated).
- [ ] M365 collectors: timers active, last run OK.
- [ ] 88 event definitions present and **enabled**.
- [ ] "OMNI - SOC" dashboard displays (24 pages).
- [ ] Backup: `bash 30-backup-config.sh` succeeds (SMB deposit).
- [ ] A test notification arrives by email **and** Teams.
- [ ] `/data`: indices present (if retained) or recreated; retentions OK.

## 6. Switchover and communication

- During reconstruction, **no alert is emitted**: manually monitor the
  critical points (AD, VPN) via the native consoles
  (FortiGate, Entra) until restoration.
- At the end: inform the IT team of the restoration; record the incident
  and the actual recovery time (RTO measurement) in the incident register.

## 7. PRA maintenance in operational condition

| Action | Frequency |
|---|---|
| **Archive restorability verification** (decryption + tar integrity + presence of Mongo dump/`server.conf`) | **Automatic, at each backup** (`30-backup-config.sh` §3b; failure → GELF `siem_backup echec` + archive not shipped) |
| Verify the presence of the 14 archives on the share | Monthly (PRO §2) |
| Verify the passphrase and secrets in the vault | Quarterly |
| **Real restoration test on a disposable VM** | ≥ 1×/year (A.8.13 requirement) |
| Update the reference versions (DOSSIER §2) | At each version upgrade |

An untested PRA is not a PRA: the annual test is **mandatory** and its
report is retained as audit evidence.

## 8. Restoration test log

| Date | Type | Scope | Result | Evidence |
|---|---|---|---|---|
| **2026-06-22** | **Backup restorability** (non-destructive, offline) | Latest archive `omni-siem-config_2026-06-22.tar.gz.enc`: AES-256 decryption (vault passphrase), `tar` integrity and **content completeness** | **PASS** | Decryption OK (255 MB); valid archive **18,044 entries**; **65 Mongo collections** (`mongodump/graylog/`) including `streams`, `dashboards`, `event_definitions`, `inputs`, `users`, **`pipeline_processor_pipelines` + `pipeline_processor_rules` + `_pipelines_streams`** (all detection logic + connections), `event_notifications`, `grok_patterns`, `scheduler_*`; `etc/graylog/server.conf`, `lookups`, `etc/opensearch` present. Scratch **wiped (`shred`)**. |

> **Scope of the 22/06 test**: it validates the **backup chain** (existence,
> decryptability, integrity, config completeness) — that is, the most frequent
> failure modes (corrupted archive, wrong passphrase, missing collection). It
> **does not replace** the **full reconstruction test on a disposable VM**
> (§7, annual A.8.13 requirement), which additionally validates the
> reinstallation of the stack and the resumption of collection — **still to be
> scheduled** (VM infra required). Useful finding: pipeline rules are indeed backed up
> under `pipeline_processor_*` (and not `pipeline_processing_*`).
