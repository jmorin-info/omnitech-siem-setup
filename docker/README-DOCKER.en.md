# Docker: core stack, console and isolated recovery

This bundle pins Graylog 7.2.2, OpenSearch 2.19.7 and MongoDB 8.0.38. nginx serves
HTTPS, `/soc/`, `/m/` and the console API. It is a staging/DR infrastructure profile;
it does not reproduce every native collector, robot and response service.
Read the [full Docker procedure](README-DOCKER.md) and
[installation guide](../docs/INSTALLATION.md) before using existing data.

```bash
cd docker
cp .env.example .env
chmod 600 .env
# Configure secrets, memory sizing and SERVER_NAME.
docker compose config --quiet
bash deploy.sh up
```

Use `https://<SERVER_NAME>/soc/` through nginx on port 443. The local diagnostic
port 9000 hosts Graylog and does not host the SOC console. Replace the temporary
self-signed certificate. Restrict published input ports to expected sources;
MongoDB and OpenSearch remain inside the container network. The console explicitly
allows internal HTTP only to the `graylog` service name; browser access uses HTTPS.

A fresh stack has no site configuration. Import Content Packs or restore a
compatible backup, provide certificates/GeoIP where required and configure devices.
The [WatchGuard/UniFi/Palo Alto modules](../docs/INTEGRATIONS-MODULAIRES.md) require
explicit UDP port publication and firewall configuration. Their default loopback
bind must be changed to receive forwarded container traffic.

XDR is optional (`analytics` profile) and requires a site YAML file with the correct
stream IDs, mounted with `OMS_CONFIG_HOST` and selected by
`OMS_CONFIG_FILE=/app/site-config.yaml`. ML, graph, triage, native timers and external
collectors are not automatically installed by the default Compose profile.

`deploy.sh up` rejects MongoDB containers outside series 8.0, Graylog outside series 7.2
and unidentified orphan Mongo volumes. Do not bypass these guards on existing data.
Database upgrades require a separate migration; [code updates](../docs/UPDATES.md)
do not migrate databases.

Restore requires explicit replacement intent and verified source versions:

```bash
CONFIRM_RESTORE=YES SOURCE_MONGODB_SERIES=8.0 SOURCE_GRAYLOG_SERIES=7.2 \
  bash deploy.sh restore /path/to/backup.tar.gz.enc
```

Keep the original Graylog `password_secret` to decrypt stored credentials. Review
restored certificates, paths, notifications and connector settings before connecting
the isolated environment to real sources. Restored lookups use `runtime-lookups/`,
ignored by Git. MongoDB configuration dumps do not restore OpenSearch log data or
all robot state; a successful import is not proof of complete operational recovery.

For file-backed secrets, see `gen-secrets.sh` and `docker-compose.secrets.yml`.
Check both Compose files with `config --quiet` before starting. Inspect failures
with `bash deploy.sh logs console`, `logs nginx` or `logs graylog`. Native nginx/systemd
installation scripts do not apply inside this profile. See
[console diagnostics](../docs/CONSOLE-DEPLOIEMENT.md) for 404/502 cases.

Compose syntax and the console entrypoint are tested; a full Docker startup and
real-device acceptance test still need to be completed on the target environment.
