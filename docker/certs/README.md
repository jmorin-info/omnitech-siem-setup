# TLS input certificates — mounted into Graylog (/etc/graylog/certs)

The restored inputs reference certificate paths. Place here the files
**with the same names** as production (otherwise Beats 5044 and EMS 1518 stay FAILED):

- `graylog.crt` + `graylog-pkcs8.key` — input **Winlogbeat/Beats TLS (5044)**
- `fortiems-syslog.cert.pem` + `fortiems-syslog.key.pem` — input **FortiClient EMS TLS (1518)**

Copy from production (`/etc/graylog/...`) **or** regenerate a self-signed certificate for
staging. Private keys **never versioned** (see .gitignore). For a staging without EMS/Beats TLS,
these inputs can stay FAILED without impacting the rest.
