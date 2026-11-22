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

The nightly `siem-backup` unit produces three artefacts: a MongoDB dump (Graylog config), an
OpenSearch snapshot (message data), and a config tarball. Restore is documented and validated
in [exploitation/RESTORE.md](exploitation/RESTORE.md); a full rebuild-from-source procedure is
[exploitation/PRA-RECONSTRUCTION-SIEM.md](exploitation/PRA-RECONSTRUCTION-SIEM.md).

Since 22/11/2026 the MongoDB dump runs on its own: `omni-mongo-backup.timer` (02:40, 14-day
local retention, GELF `backup_mongo_ok`/`backup_mongo_echec` with two Graylog detections). A timed
restore into an isolated temporary `mongod` is `sudo bash tools/omni-mongo-restore-test.sh`.
OpenSearch data is covered by the selective `oms-snap-siem` snapshots; the historical
`siem-backup.timer` stays disabled (a full snapshot no longer fits on `/home`).

```bash
systemctl status siem-backup.service
systemctl list-timers | grep siem-backup
ls -la /home/siem-backup/            # mongo/ configs/ opensearch-snapshots/
```

> Warning: **Snapshot-repository sizing.** The OpenSearch snapshot repository must live on a volume
> **larger than the primary index size** (≈ 1.45 TB). `/home` (805 GB) is too small to hold a
> full snapshot: if the repository is placed there it fills to 100 %, which then blocks even
> snapshot *deletion* (a disk-full deadlock). Place the repository on `/data` (or a dedicated
> volume), keep `RETENTION_DAYS` consistent with capacity, and monitor with the "Disk SIEM
> &gt; 80 %" detection. To relocate: register the `fs` repository at a path under
> OpenSearch's `path.repo`, which requires an OpenSearch restart (the Graylog disk journal —
> 10 GB — buffers ingestion during the brief restart).

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
