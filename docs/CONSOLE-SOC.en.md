# SOC console guide

Open `https://YOUR_FQDN/soc/` over HTTPS and use an account accepted by Graylog.
Local Graylog accounts work; directory accounts require the site's authentication
integration. Network access follows the site's nginx and firewall policy.
For installation or a 404 response, use the [deployment guide](CONSOLE-DEPLOIEMENT.md).

The responsive SOC console is also an installable PWA. On mobile, use the bottom
navigation and menu. A legacy `/m/` app may remain available or redirect to `/soc/`,
depending on the site. Accept **Reload** when a new service worker is available.

## Find information

Navigation groups cover operations, investigations, visibility and administration.
Use **Ctrl/Cmd + K** for navigation, entity lookup and journal searches. A machine
with newly indexed logs appears in searches and matching widgets; historical entity
sheets focus on security activity and are not a complete asset inventory.

The pages depend on their data sources and optional services. An empty indicator
does not prove that a source is monitored. Backend errors and incomplete searches
must remain distinguishable from a valid zero result.

## Configure pages and widgets

Under **Visibility > Modules**, SOC administrators can create pages using local
Graylog streams, filters and a minimum SOC role. Available widget types are counts,
time series, field distributions and recent messages. Presets cover WatchGuard,
Ubiquiti UniFi, Palo Alto and developer vulnerabilities; custom pages are supported.
A native Graylog dashboard can be linked, but its charts are not automatically
converted into SOC widgets.

Choose the streams, verify optional integration filters, simulate the change and
publish with a reason. The configuration persists outside Git and is preserved by
code updates and rollback. The service account must be allowed to read the selected
streams and dashboards; a valid token can otherwise return empty catalogues.
See the [complete page and widget guide](CONSOLE-MODULES.md), including data flow,
backup paths, concurrent edits and known limits.

## Roles and administration

SOC roles are reader (`lecteur`), analyst (`analyste`) and administrator
(`administrateur`). Accounts in `SOC_ADMINS` are administrators; explicit roles are
stored locally. `SOC_DEFAULT_ROLE` defaults to analyst for compatibility. SOC reads
use the backend's OpenSearch scope and do not inherit each user's Graylog stream
permissions. Grant access and configure page roles accordingly.

Administrative writes require role checks, an allowed browser origin, a CSRF token,
an allowed client network and a reason. Changes are audited. High impact actions
normally require another administrator; the self-service update workflow has its
own explicit revision confirmation. `SOC_ADMIN_DRY_RUN=1` simulates writes.
Appearance, site pages and widgets, roles, detections and updates have their own
controls. The [French operator guide](CONSOLE-SOC.md) documents each screen.

## Updates and deployment profiles

The update plan checks the installed backend, nginx roots, health, backups and
candidate tests. Automatic publication supports the configured canonical repository,
the standard web roots and local port 8090, including a retired `/m/` route to `/soc/`.
A copied backend or custom publication profile can require a manual deployment;
the plan refuses unsupported profiles instead of reporting a false alignment.
See [updates](UPDATES.md) and [deployment](CONSOLE-DEPLOIEMENT.md).

Site state, secrets and web assets are separate. The normal widget configuration is
`/var/lib/omni-mobile/modules/config.json`; include custom state paths in backups.
Optional ML, graph, SOAR and collection services require their own configuration.
The integration formats and qualification limits are described in the
[WatchGuard, UniFi and Palo Alto guide](INTEGRATIONS-MODULAIRES.md).
