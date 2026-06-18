# Récapitulatif des secrets — stack SIEM OMNITECH (GABARIT)

> ⚠️ Ce fichier est un **modèle versionné**. Le fichier réel `SECRETS.md` (avec les
> valeurs) n'est **jamais** committé (cf. `.gitignore`). Il reste sur la VM comme
> référence « bris de glace ». Renseigner les valeurs uniquement en local.

| # | Secret (clé) | Valeur | Rôle | Où il vit sur la VM | Origine |
|---|--------------|--------|------|---------------------|---------|
| 1 | `GRAYLOG_ADMIN_PASS` | `‹REDACTED›` | Compte **admin** web/API Graylog (bris de glace) | hash SHA-256 dans `server.conf` (`root_password_sha2`) ; en clair dans `00-vars.env` | Existant |
| 2 | `MONGO_ADMIN_PASS` | `‹REDACTED›` | Utilisateur Mongo `admin` (root) — sauvegardes | `00-vars.env` ; `/usr/local/sbin/siem-backup.sh` (700) | Existant |
| 3 | `MONGO_GRAYLOG_PASS` | `‹REDACTED›` | Utilisateur Mongo `graylog` (rw/dbAdmin base graylog) | `00-vars.env` ; `mongodb_uri` de `server.conf` (640) | Existant |
| 4 | `ANALYST_PASS` | `‹REDACTED›` | Ancien compte analyste — non utilisé par les scripts | — | Existant |
| 5 | `API_PASS` (legacy) | `‹REDACTED›` | Ancien token API — **obsolète** sur la nouvelle stack | — | Existant |
| 6 | `OPENSEARCH_BOOTSTRAP_PASS` | `‹REDACTED›` | Exigé par le paquet opensearch à l'install only — **inerte ensuite** | `00-vars.env` | Nouveau |
| 7 | `password_secret` Graylog | `‹généré 96 hex›` | Poivre de chiffrement interne — **indispensable à toute restauration** | `/root/.graylog_password_secret` (600) ; `server.conf` ; tar backup | Généré par `04-graylog.sh` |
| 8 | Clé privée TLS | `/etc/nginx/ssl/graylog.key` + PKCS#8 | TLS console (Nginx 443) + input Beats 5044 | fichiers (600 / 640) | Généré par `05-nginx-tls.sh` |
| 9 | KeyFile MongoDB | `/etc/mongod.keyfile` | Auth interne replica set rs0 | fichier (400 mongodb) ; tar backup | Généré par `02-mongodb.sh` |
| 10 | `SNMP_V3_AUTH_PASS` / `SNMP_V3_PRIV_PASS` | `‹REDACTED›` | SNMPv3 (SHA/AES) lecture seule Centreon | `00-vars.env` ; `snmpd.conf` | À définir |
| 11 | `M365_CLIENT_SECRET` / `M365_CLIENT_ID` / `M365_TENANT_ID` | `‹REDACTED›` | App Graph `OMNI-SIEM-Collector` | `00-vars.env` | À définir |
| 12 | `LDAP_BIND_PASS` | `‹REDACTED›` | Compte de liaison LDAPS console (svc_siem) | `00-vars.env` | À définir |
| 13 | `BACKUP_PASSPHRASE` | `‹REDACTED›` | Chiffrement AES-256 des archives de sauvegarde | `00-vars.env` (**à mettre au coffre**) | Généré |
| 14 | `TEAMS_WEBHOOK_URL` | `‹REDACTED›` | Webhook Power Automate notifications Teams | `00-vars.env` | À définir |
| 15 | `FORTI_DHCP_TOKEN` | `‹REDACTED›` | Token API FortiGate (lecture DHCP) | `00-vars.env` | À définir |

## Fichiers sensibles et permissions attendues
- `00-vars.env` → `chmod 600 root:root`
- `/root/.graylog_password_secret` → `600`
- `/etc/nginx/ssl/graylog.key`, `/etc/graylog/server/certs/graylog-pkcs8.key` → `600` / `640 root:graylog`
- `/etc/mongod.keyfile` → `400 mongodb:mongodb`
- `/root/.smb-siem.cred` → `600`

## Rotation (après stabilisation)
Procédure par secret : mot de passe admin (hash SHA-256 → `server.conf`), Mongo
(`changeUserPassword`), recréation des tokens API dans l'UI, renouvellement TLS
automatisé (`omni-cert-renew`). Tracer chaque rotation (A.5.37 / REG_016).
