# Operations &amp; resilience

Day-to-day runbook for the OMNI SIEM platform. The authoritative French procedures are
[exploitation/PROCEDURE-EXPLOITATION-SIEM.md](exploitation/PROCEDURE-EXPLOITATION-SIEM.md) and
[exploitation/GUIDE-DEPANNAGE.md](exploitation/GUIDE-DEPANNAGE.md).

## Service health

All custom services run under systemd with `Restart=on-failure`.

```bash
# status of the core services
systemctl status omni-alert-triage omni-soar omni-mobile-api graylog-server

# triage counters (mail / drop / dedup / mail_echec)
curl -s http://127.0.0.1:8089/stats

# analytics-robot timers
systemctl list-timers | grep -E 'omni-|ueba|ndr'

# OpenSearch cluster health (expect green)
curl -s http://127.0.0.1:9200/_cluster/health | jq .status
```

## Source-freshness watchdog

A blinded collector is a security blind spot, so every monitored source has a silence
threshold. The watchdog runs on a timer and raises a `source_silent` alert
(ATT&CK T1562.001) when a source is quiet beyond its threshold.

```bash
# run the watchdog on demand (prints monitored / silent counts)
/usr/local/sbin/omni-source-watchdog

# thresholds (minutes) per source
grep WATCHDOG_SOURCES /etc/default/omni-watchdog
```

Adding a new source? Add it to `WATCHDOG_SOURCES` (repo `74-source-watchdog.sh`) with a
sensible silence threshold, otherwise a future outage of that source goes unnoticed.

## Backups &amp; disaster recovery

The historical nightly `siem-backup` unit (disabled since August 2026) produced three artefacts:
a MongoDB dump (Graylog config), an OpenSearch snapshot (message data) and a config tarball.
They are now produced separately: `omni-mongo-backup`, `oms-snap-siem` and `omni-backup-config`. Restore is documented and validated
in [exploitation/RESTORE.md](exploitation/RESTORE.md); a full rebuild-from-source procedure is
[exploitation/PRA-RECONSTRUCTION-SIEM.md](exploitation/PRA-RECONSTRUCTION-SIEM.md).

Since 22/11/2026 the MongoDB dump runs on its own: `omni-mongo-backup.timer` (02:40, 14-day
local retention, GELF `backup_mongo_ok`/`backup_mongo_echec` with two Graylog detections). A timed
restore into an isolated temporary `mongod` is `sudo bash tools/omni-mongo-restore-test.sh`.
New archives use `omni-mongo-*`; retention preserves inherited `graylog-mongo-*`
archives and runs only after a verified backup. The restore test binds its child
to a private Unix socket, stops only that child and compares collection counts.
Matching counts do not establish matching document contents or a full SIEM recovery.
OpenSearch data is covered by the selective `oms-snap-siem` snapshots (01:30 nightly, weekly
restore test `oms-snap-siem-test`, Wednesday 11:00); the historical `siem-backup.timer` stays
disabled (a full snapshot no longer fits on `/home`).

```bash
sudo /usr/local/sbin/oms-snap-siem --etat           # snapshots of the configured repository
systemctl list-timers 'oms-snap-siem*' omni-mongo-backup.timer
ls -la /home/siem-backup/                            # mongo/ configs/ opensearch-snapshots/
```

### Snapshot repository relocation (`/home` to `/data`)

State on 22/11/2026: repository `graylog_fs` in `/home/siem-backup/opensearch-snapshots`
(505 GB, `/home` 67 % used, physical disk `sda`); `/data` (7.3 TB, 56 % used) is the
LUKS-encrypted disk `sdb` that also holds `path.data`. The repository and its free-space
thresholds are read by `oms-snap-siem` from `/etc/oms-snap-siem.conf` (`DEPOT`,
`DEPOT_CHEMIN`, `LIBRE_MIN_PCT`, `LIBRE_ARRET_PCT`; defaults: `graylog_fs`, `/home/...`, 15, 5).
`omni-drift-check` and `omni-update-status.py` follow the same `DEPOT` value.

```bash
cd /opt/omni-siem/repository
bash tools/migrer-depot-snapshots.sh                    # plan, read-only (GET only)
sudo bash tools/migrer-depot-snapshots.sh --apply       # add path, controlled restart, register, switch, first snapshot
sudo bash tools/migrer-depot-snapshots.sh --rollback    # back to graylog_fs (--avec-redemarrage also restores path.repo)
sudo bash tools/migrer-depot-snapshots.sh --retirer-ancien   # only after 3 successful snapshots in graylog_fs_data
```

- Prerequisite: the new `deploye/sbin/oms-snap-siem` (reads `DEPOT`) is deployed; the plan
  blocks otherwise.
- `--apply` keeps the old path in `path.repo`, restarts OpenSearch only if the new path is
  missing (green required before, API then green awaited after; if the API does not come
  back, `opensearch.yml` is restored and OpenSearch restarted again), registers
  `graylog_fs_data`, verifies it, switches the configuration (thresholds 25 % / 15 % free so
  that a snapshot never triggers the `omni-disk-guard` emergency purge at 88 %) and runs the
  first, full snapshot (estimated at about 460 GB raw on 22/11/2026).
- The old repository stays registered and readable until `graylog_fs_data` holds three
  successful `oms-sel-*` snapshots; its retirement is a separate step that only unregisters
  it. Removing the old path from `path.repo` and deleting the files are printed, never run.
- Trade-off to accept explicitly: on `/data` the snapshots share the physical disk of the
  live indices. They still protect against logical loss (deleted or corrupted index) and are
  encrypted at rest, but no longer against the loss of `sdb`; `/home` is a separate disk but
  unencrypted.

Measured impact of an OpenSearch restart (read-only, 22/11/2026): stop 8 to 25 s, start 60
to 80 s, back to green 3 to 6.5 minutes after start (journal of 15/11 and 17/11). During that
time Graylog buffers in its disk journal (`/data/graylog-journal`, 20 GB, maximum age 12 h);
at about 1.8 KB per message and 500 to 700 msg/s, 7 minutes represent 0.3 to 0.6 GB. Robots
that query OpenSearch during the window (watchdog, oms-xdr, console) report errors for one
cycle. Do not restart between 01:15 and the end of the nightly snapshot, nor during the
Wednesday 11:00 restore test: `oms-snap-siem.service` has `Requires=opensearch.service`.

## Retention

ISO-aligned per-source retention tiers (illustrative):

| Tier | Sources | Retention |
|---|---|---|
| High volume, short | FortiGate, Sysmon, Windows (other) | 90 days |
| Security-relevant | Windows Security, vSphere, ESET | 180 days |
| Cloud audit | Microsoft 365 | 365 days |

Policy: [securite-conformite/POLITIQUE-RETENTION.md](securite-conformite/POLITIQUE-RETENTION.md).

## Alerting hygiene

- The triage service is the **single mail path** — no legacy direct-e-mail notifications
  (they caused double-mails and bypassed filtering). If you provision new detections, wire
  them to the triage + Teams notifications, never to a direct e-mail notification.
- One clean e-mail per real alert; noise stays in Teams and the console.
- Analysts silence confirmed false positives from the console (scoped, time-boxed rules).

## Common tasks

| Task | Where |
|---|---|
| Change mail recipients | `MAIL_RECIPIENTS` in `/etc/omni-alert-triage.env` |
| Enable/adjust the LLM judge | `ANTHROPIC_API_KEY` / `GRAY_SCORE_THRESHOLD` in the same file |
| Add a legitimate egress (stop an exfil FP) | append the IP/CIDR to `EXFIL_ALLOW_DEST` in `00-vars.env` (Warning: no inline comment on the value line) |
| Add / tune a detection | the relevant `NN-*.sh` provisioning script, then re-run it |
| Investigate an entity | `/soc/` console → entity 360° dossier |
| Troubleshoot | [exploitation/GUIDE-DEPANNAGE.md](exploitation/GUIDE-DEPANNAGE.md) |

## Encryption &amp; access

- Data volume: LUKS-encrypted (`/data`); the LUKS header is backed up off-box.
- TLS everywhere; SSH locked down; console exposure per RSSI policy.
- Volume-encryption procedure: [securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md](securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md).
