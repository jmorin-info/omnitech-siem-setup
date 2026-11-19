# Deployment

The repository supports a fresh **core SOC** installation and separate workflows
for code updates, integration packs and disaster recovery. The configured OMNITECH
reference installation has additional services and site settings; a fresh install
does not automatically reproduce all of them.

## Fresh native installation

For an Ubuntu walkthrough, see [UBUNTU-DEMARRAGE.md](UBUNTU-DEMARRAGE.md).
Ubuntu 26.04 requires `--experimental-ubuntu-2604` and a compatible kernel; the
MongoDB 8 noble packages are outside vendor support on that OS. Ubuntu 24.04 is
the supported Ubuntu route for this stack.

Follow [INSTALLATION.md](INSTALLATION.md) for prerequisites, platform selection,
exact phase order, storage/network choices and acceptance checks. Ubuntu 22.04/24.04
and Debian 12/13 amd64 are the installer targets. The Graylog compatibility matrix
must be checked for the selected versions; Debian 13 remains outside its current
list of officially supported OS versions.

```bash
cp 00-vars.env.example 00-vars.env
chmod 600 00-vars.env
# Edit the site parameters and secrets.
sudo bash install.sh --generate-secrets
sudo bash install.sh --plan
sudo bash install.sh --apply
```

The installer uses an explicit phase list, records progress and refuses an existing
SIEM. It includes the core stack, initial inputs/model/pipelines/detections/dashboards,
nginx, the complete SOC console and a daily application backup. A failed installation
can be resumed only with the same source revision, configuration and options.

**Never execute every numbered script.** Some are destructive maintenance operations,
change retention, enable site-specific responses or delete/recreate dashboards. An
existence check in a helper does not guarantee full convergence or preservation of
user edits. The native installer is not a generic migration tool.

## Existing installations

Use [UPDATES.md](UPDATES.md) to fetch a fixed Git revision into an isolated cache,
inspect differences, prepare a staged release and apply permitted code files with
backups. Local code conflicts stop the update. Tenant configuration, secrets and
databases are preserved. Database/package changes require their own compatibility
review, backups and migration procedure. A code rollback cannot undo a database migration.

After updating console code, use [CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md) to
publish all assets and activate a backend owned by the new installer. Legacy service
paths and customized nginx locations are preserved and require explicit review.

## Source modules

[INTEGRATIONS-MODULAIRES.md](INTEGRATIONS-MODULAIRES.md) describes the WatchGuard,
UniFi and Palo Alto catalogue, native Content Pack export/installation, dashboards,
parameters and sample-based tests. Actual devices must be configured to forward logs
and qualified against the supported format. Official Illuminate content is licensed
separately and is not redistributed here.

M365/Entra, SEAL, ML/XDR/graph, SOAR, AD response, active scans and business-specific
inventories require their own credentials, configuration and acceptance checks. See
[the optional-component table](INSTALLATION.md#outils-et-connecteurs-optionnels).

## Docker and recovery

The [Docker guide](../docker/README-DOCKER.en.md) describes a distinct staging/DR
profile. Its containers do not include every native service. An empty stack needs
configuration packs or a compatible backup plus device-side setup.

A recovery operation is distinct from an update. Review [RESTORE.md](../RESTORE.md)
and [PRA-RECONSTRUCTION-SIEM.md](PRA-RECONSTRUCTION-SIEM.md), use the backed-up version
manifest and test a real restore on an isolated host. Older version numbers and
object counts in historical procedures describe those dates; they must not be used
to downgrade today's databases. MongoDB configuration dumps do not contain OpenSearch
log data, external secrets, device settings or the entire operational state.

## Validation

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
bash run-tests.sh
python3 tools/audit-portability.py > /tmp/siem-portability.json
```

The suites use simulated clients and synthetic data. A real nginx test runs when
nginx is installed. Passing these tests does not substitute for a fresh VM install,
real device parsing checks or a disaster-recovery exercise. The dated
[portability audit](AUDIT-PORTABILITE-2026-11-19.md) records the initial findings and
reference production state without applying changes to that SIEM.
