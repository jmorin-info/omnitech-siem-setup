# Certificats d'inputs TLS — montés dans Graylog (/etc/graylog/certs)

Les inputs restaurés référencent des chemins de certificats. Placer ici les fichiers
**aux mêmes noms** que la prod (sinon Beats 5044 et EMS 1518 restent en FAILED) :

- `graylog.crt` + `graylog-pkcs8.key` — input **Winlogbeat/Beats TLS (5044)**
- `fortiems-syslog.cert.pem` + `fortiems-syslog.key.pem` — input **FortiClient EMS TLS (1518)**

Copier depuis la prod (`/etc/graylog/...`) **ou** régénérer un certificat auto-signé pour le
staging. Clés privées **jamais versionnées** (cf .gitignore). Pour un staging sans EMS/Beats TLS,
ces inputs peuvent rester FAILED sans impacter le reste.
