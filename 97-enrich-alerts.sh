#!/usr/bin/env bash
# =============================================================================
# 97-enrich-alerts.sh - Enrichit le CONTENU des alertes (event definitions).
#   Constat : beaucoup d'alertes ne portaient que le compteur + une cle (ou rien) ;
#   l'evenement genere (vu dans la console SOC / vue Alertes) avait `fields` vide.
#   Les events Graylog peuplent `fields` A PARTIR du group_by (verifie : un event
#   group_by=[user] porte fields={user:...}). On agit donc sur group_by + field_spec.
#
#   [1] PASSE GENERIQUE : toute alerte "OMNI -*" agregee dont field_spec est VIDE
#       mais group_by present -> field_spec = group_by (les champs cles remontent).
#   [2] ENRICHISSEMENT CIBLE : les alertes de correlation recentes recoivent un
#       group_by CONTEXTE (qui/ou/quoi : user, src_ip, net_segment, switch, port)
#       -> l'evenement porte enfin de quoi trianger sans pivoter.
#   Idempotent (PUT). N'altere ni la query ni le seuil (semantique de detection).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

# fabrique un field_spec à partir d'une liste de champs (template-v1 ${source.X})
fs_from_fields() {  # $@ = champs ; sort un objet JSON
  printf '%s\n' "$@" | jq -R . | jq -s 'reduce .[] as $k ({}; . + {($k): {data_type:"string",
      providers:[{type:"template-v1", template:("${source." + $k + "}"), require_values:false}]}})'
}

# remplace group_by + key_spec + field_spec d'une alerte (par titre) puis PUT
set_alert_fields() {  # TITRE  champ1 champ2 ...
  local TITLE="$1"; shift
  local DEF ID FARR FS NEW
  DEF="$(api_get '/events/definitions?per_page=400' | jq -c --arg t "$TITLE" '.event_definitions[]|select(.title==$t)')"
  [[ -z "$DEF" || "$DEF" == "null" ]] && { warn "absente: $TITLE"; return; }
  ID="$(jq -r '.id' <<<"$DEF")"
  FARR="$(printf '%s\n' "$@" | jq -R . | jq -s .)"
  FS="$(fs_from_fields "$@")"
  NEW="$(jq -c --argjson f "$FARR" --argjson fs "$FS" \
    '.config.group_by=$f | .key_spec=$f | .field_spec=$fs' <<<"$DEF")"
  if echo "$NEW" | api_put "/events/definitions/${ID}" >/dev/null 2>&1; then
    ok "enrichi: $TITLE -> [$*]"
  else warn "echec PUT: $TITLE"; fi
}

echo "==> [1/2] Passe generique : field_spec=group_by sur les alertes OMNI agregees au field_spec vide"
api_get '/events/definitions?per_page=400' \
  | jq -r '.event_definitions[] | select(.title|startswith("OMNI"))
           | select(.config.type=="aggregation-v1")
           | select((.field_spec|length)==0 and (.config.group_by|length)>0)
           | .title' | sort -u | while read -r T; do
  [[ -z "$T" ]] && continue
  GB="$(api_get '/events/definitions?per_page=400' | jq -r --arg t "$T" '.event_definitions[]|select(.title==$t)|.config.group_by[]' | tr '\n' ' ')"
  set_alert_fields "$T" $GB
done

echo "==> [2/2] Enrichissement CIBLE des alertes de correlation (contexte qui/ou/quoi)"
set_alert_fields "OMNI - Anomalie d'autorite M365 (user inattendu)"        user src_ip
set_alert_fields "OMNI - Login admin hors segment admin (Aruba/EMS)"       user src_ip net_segment
set_alert_fields "OMNI - Changement config switch (Aruba)"                 source aruba_switch_name
set_alert_fields "OMNI - Violation port-security (Aruba)"                  source aruba_port
set_alert_fields "OMNI - Boucle reseau / STP (Aruba)"                      source aruba_port
# NB : les alertes A SEUIL (brute force SSH/admin switch, count>N par IP) ne sont PAS
# elargies ici -> changer leur group_by fausserait le seuil. La passe [1] leur a deja
# pose field_spec=group_by (l'IP remonte dans l'evenement).

echo
echo "=== 97 termine. Les events portent desormais les champs de contexte (fields)."
echo "    Cote console : get_alerts doit renvoyer 'fields' (cf patch backend). ==="
