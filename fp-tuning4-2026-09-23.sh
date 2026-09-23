#!/usr/bin/env bash
# =============================================================================
# fp-tuning4-2026-09-23.sh - Quatrieme passe : deux detections dont la valeur est
#   en CORRELATION, pas en alerte isolee (arbitrage RSSI du 23/09/2026).
#
#   1. "Connexion compte admin (adm-*) hors heures ouvrees" : 11 024 connexions
#      sur 7 j pour le seul adm-jmorin, depuis des IP INTERNES (10.33.x) = travail
#      d'administration en soiree, pas une anomalie. Le signal n'a de valeur que
#      depuis une source inhabituelle ou combine a autre chose.
#   2. "M365 enregistrement appareil / methode MFA (T1098.005)" : ~30 evenements
#      /30 j, tous des inscriptions legitimes d'utilisateurs reels. Une methode MFA
#      ajoutee n'est suspecte que JUSTE APRES un login anormal -- c'est une
#      correlation, pas une alerte autonome.
#
#   Les deux passent en evenement NON-ALERTANT : la donnee reste indexee et
#   exploitable (chasse, correlation, tableaux de bord), elle ne declenche plus de
#   mail. Reversible : remettre alert=true.
#   DRY-RUN par defaut. Appliquer : APPLY=1 ./fp-tuning4-2026-09-23.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api
APPLY="${APPLY:-0}"
DEFS="$(api_get '/events/definitions?per_page=400')"

mute(){ # $1 = motif de titre  $2 = libelle
  local id st
  id="$(echo "$DEFS" | jq -r --arg t "$1" '.event_definitions[]?|select(.title|test($t))|.id' | head -1)"
  [[ -z "$id" ]] && { warn "absente: $2"; return; }
  st="$(echo "$DEFS" | jq -r --arg i "$id" '.event_definitions[]?|select(.id==$i)|.alert')"
  if [[ "$st" == "false" ]]; then skip "$2 deja non-alertante"; return; fi
  echo "  ~ [$2] alert=true -> false (notifications retirees)"
  [[ "$APPLY" != "1" ]] && return
  api_get "/events/definitions/$id" | jq '.alert=false | .notifications=[]' \
    | api_put "/events/definitions/$id?schedule=true" | jq -e '.id' >/dev/null 2>&1 \
    && ok "$2 : passee en evenement non-alertant" || warn "$2 : echec"
}

echo "=== fp-tuning4 (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)) ==="
mute 'Connexion compte admin \(adm-\*\) hors heures|compte admin .adm' "Admin hors heures ouvrees"
mute 'M365 enregistrement appareil / m.thode MFA'                      "M365 enregistrement MFA/appareil"
echo "=== termine ==="
