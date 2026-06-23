# Secrets docker (override `docker-compose.secrets.yml`)

Fichiers générés par `../gen-secrets.sh` (jamais versionnés — cf `.gitignore`) :

- `graylog_password_secret` — secret de chiffrement Graylog (≥ 64 car.)
- `graylog_root_password_sha2` — SHA-256 du mot de passe admin
- `mobile_secret` — HMAC des sessions console
- `oms_teams_webhook` — URL webhook Teams (optionnel ; vide = pas de notification)

Montés en `/run/secrets/<nom>` dans les conteneurs (invisibles dans `docker inspect`).
Voir `../docker-compose.secrets.yml` pour l'usage.
