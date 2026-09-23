#!/usr/bin/env bash
# =============================================================================
# fp-tuning3-2026-09-23.sh - Reduction des FP, troisieme passe.
#   1. Authentification legacy M365 : la requete inclut "Authenticated SMTP"
#      alors que sa PROPRE description dit l'exclure ("'Authenticated SMTP' (MFP)
#      exclu"). Mesure 30 j : 27 162 evenements "Authenticated SMTP" contre 3
#      "Other clients". SMTP authentifie = imprimantes multifonctions et
#      applications qui envoient du mail, PAS un contournement de MFA par un
#      attaquant. On aligne la requete sur l'intention documentee : IMAP4, POP3
#      et "Other clients" restent detectes (vrai legacy = vrai bypass MFA).
#   2. "SOAR : IP bloquee automatiquement" : evenement INFORMATIF sur notre
#      PROPRE action reussie (le blocage a deja eu lieu). Il n'appelle aucune
#      decision d'analyste -> passe en evenement non-alertant, la trace reste
#      en console et dans le recap.
#   DRY-RUN par defaut. Appliquer : APPLY=1 ./fp-tuning3-2026-09-23.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api
APPLY="${APPLY:-0}"
DEFS="$(api_get '/events/definitions?per_page=400')"
id_by_title(){ echo "$DEFS" | jq -r --arg t "$1" '.event_definitions[]?|select(.title|test($t))|.id' | head -1; }

echo "=== fp-tuning3 (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)) ==="

echo "[1/2] Legacy M365 : retirer 'Authenticated SMTP'"
ID="$(id_by_title 'Authentification legacy M365')"
NEWQ='event_source:m365 AND m365_type:signin AND event_action:connexion_reussie AND client_app:("Other clients" OR "IMAP4" OR "POP3")'
if [[ -z "$ID" ]]; then warn "detection absente"
else
  CUR="$(echo "$DEFS" | jq -r --arg i "$ID" '.event_definitions[]?|select(.id==$i)|.config.query')"
  if [[ "$CUR" == "$NEWQ" ]]; then skip "deja a jour"
  else
    echo "  ~ APRES: $NEWQ"
    [[ "$APPLY" == "1" ]] && { api_get "/events/definitions/$ID" | jq --arg q "$NEWQ" '.config.query=$q' \
      | api_put "/events/definitions/$ID?schedule=true" | jq -e '.id' >/dev/null 2>&1 \
      && ok "requete mise a jour" || warn "echec"; }
  fi
fi

echo "[2/2] SOAR : IP bloquee -> evenement non-alertant"
ID="$(id_by_title 'SOAR : IP bloqu')"
if [[ -z "$ID" ]]; then warn "detection absente"
else
  CURA="$(echo "$DEFS" | jq -r --arg i "$ID" '.event_definitions[]?|select(.id==$i)|.alert')"
  if [[ "$CURA" == "false" ]]; then skip "deja non-alertante"
  else
    echo "  ~ alert=true -> false"
    [[ "$APPLY" == "1" ]] && { api_get "/events/definitions/$ID" | jq '.alert=false | .notifications=[]' \
      | api_put "/events/definitions/$ID?schedule=true" | jq -e '.id' >/dev/null 2>&1 \
      && ok "passee en evenement non-alertant" || warn "echec"; }
  fi
fi
echo "=== termine ==="
