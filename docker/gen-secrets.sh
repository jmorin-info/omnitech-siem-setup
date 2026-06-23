#!/usr/bin/env bash
# Genere les fichiers de secrets pour l'override docker-compose.secrets.yml.
# Idempotent : ne regenere pas un secret deja present. Fichiers hors git (chmod 600).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p secrets && chmod 700 secrets

gen() { # gen <nom> <commande generant la valeur...>
  local name="$1"; shift
  local file="secrets/${name}"
  if [ -s "$file" ]; then echo "  [=] ${name} existe (conserve)"; return; fi
  "$@" > "$file"; chmod 600 "$file"; echo "  [+] ${name} genere"
}

gen graylog_password_secret openssl rand -hex 48
gen mobile_secret           openssl rand -hex 32

# Hash SHA-256 du mot de passe admin Graylog (saisie masquee).
if [ ! -s secrets/graylog_root_password_sha2 ]; then
  read -rsp "  Mot de passe admin Graylog : " PW; echo
  printf '%s' "$PW" | sha256sum | cut -d' ' -f1 > secrets/graylog_root_password_sha2
  chmod 600 secrets/graylog_root_password_sha2
  echo "  [+] graylog_root_password_sha2 genere"
fi

# Webhook Teams (optionnel) : fichier vide par defaut (la reponse reste DRY-RUN).
if [ ! -f secrets/oms_teams_webhook ]; then
  : > secrets/oms_teams_webhook; chmod 600 secrets/oms_teams_webhook
  echo "  [+] oms_teams_webhook (vide — renseigner l'URL si notification Teams)"
fi

echo
echo "OK — secrets dans ./secrets/ (chmod 600, hors git)."
echo "Mettre des PLACEHOLDERS non vides dans .env (GRAYLOG_PASSWORD_SECRET=managed-by-docker-secret, etc.)"
echo "puis : docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d"
