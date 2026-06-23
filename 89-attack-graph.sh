#!/usr/bin/env bash
# =============================================================================
# 89-attack-graph.sh - OMNI Sentinel Pilier 2 : jumeau d'attaque (oms-graph).
#   DEFENSIF. Reconstruit PASSIVEMENT (sans sonde AD) un graphe d'exposition depuis
#   la telemetrie de logons deja collectee (4624 sessions interactives = creds
#   exposes ; 4672 = admin sur l'hote). Calcule :
#     - l'EXPOSITION des joyaux (DC/SIEM/Veeam/PKI/fichiers/vSphere) : quels
#       pieds-a-terre les atteignent et en combien de sauts ;
#     - les CHOKEPOINTS (ou durcir / poser un leurre en priorite) ;
#     - le RAYON DE SOUFFLE (si X compromis, que devient atteignable) ;
#     - les POINTS UNIQUES catastrophiques (comptes de gestion admin partout) ;
#     - des RECOMMANDATIONS DE PLACEMENT DE LEURRES (alimente le Pilier 1 / 88).
#   Anti-bruit mesure : comptes machine/systeme/virtuels exclus ; comptes de gestion
#   ubiquitaires (RMM/sync) sortis des chemins lateraux et rapportes a part.
#   Sorties : artefact JSON (/var/lib/omni-mobile/attack-graph.json, lu par la console)
#   + GELF event_source=attack_path (informationnel, SANS alert_tag : posture, pas alerte).
#   Local-first : lecture OpenSearch, graphe code main (requests+PyYAML, pas de sklearn).
#   Idempotent. Prerequis : OpenSearch + input GELF 12201 + stream interne (21) + 88
#   (registre de leurres, pour marquer les recos deja couvertes).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env 2>/dev/null || true
source ./lib-graylog.sh 2>/dev/null || true
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

APP=/root/omnitech-siem-setup/oms-graph
VENV="$APP/.venv"
ETC=/etc/oms-graph
STATE=/var/lib/oms-graph

echo "==> [1/5] venv + dependances (requests, PyYAML)"
if [[ ! -x "$VENV/bin/python" ]]; then python3 -m venv "$VENV"; fi
"$VENV/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt" \
  && echo "    [+] dependances installees" || echo "    [!] pip a echoue (hors-ligne ?)"
( cd "$APP" && "$VENV/bin/pip" install -q --disable-pip-version-check -e . 2>/dev/null ) \
  && echo "    [+] oms_graph installe (editable)" || true

echo "==> [2/5] Configuration $ETC/config.yaml + etat $STATE"
mkdir -p "$ETC" "$STATE"
if [[ -f "$ETC/config.yaml" ]]; then echo "    [=] config existante conservee"
else install -m 644 "$APP/config.yaml" "$ETC/config.yaml" && echo "    [+] config installee"; fi

echo "==> [3/5] Unites systemd (analyse quotidienne)"
for u in oms-graph.service oms-graph.timer; do
  install -m 644 "$APP/deploy/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now oms-graph.timer >/dev/null 2>&1 \
  && echo "    [+] timer actif" || echo "    [!] activation timer KO"

echo "==> [4/5] Routage event_source=attack_path -> 'OMNI - Interne SIEM' (+ exclusion M365)"
if declare -f require_api >/dev/null 2>&1 && require_api 2>/dev/null; then
  ST="$(get_stream_id 'OMNI - Interne SIEM' 2>/dev/null)"
  if [[ -n "${ST:-}" ]]; then
    CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
    echo "$CUR" | grep -qx "attack_path" && echo "    [=] routage deja present" || {
      jq -n '{field:"event_source",type:1,value:"attack_path",inverted:false,description:"oms-graph: exposition"}' \
        | api_post "/streams/${ST}/rules" >/dev/null && echo "    [+] attack_path -> interne"; }
    M365="$(get_stream_id 'OMNI - M365' 2>/dev/null)"
    if [[ -n "${M365:-}" ]]; then
      MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
      echo "$MEX" | grep -qx "attack_path" || jq -n '{field:"event_source",type:1,value:"attack_path",inverted:true,description:"exclusion oms-graph (anti-dup)"}' \
        | api_post "/streams/${M365}/rules" >/dev/null && echo "    [+] M365 exclut attack_path"
    fi
  else echo "    [!] stream 'OMNI - Interne SIEM' introuvable (lancer 21) — routage saute"; fi
else echo "    [!] API Graylog indisponible — routage a relancer"; fi

echo "==> [5/5] Passe de validation (lecture seule, SANS push)"
( cd "$APP" && "$VENV/bin/python" -m oms_graph.run analyze --config "$ETC/config.yaml" 2>&1 ) \
  | grep -vE "^[0-9]{4}-.*(INFO|WARNING)" | sed 's/^/    /' | head -30
echo
echo "=== 89 termine. Jumeau d'attaque oms-graph actif (timer quotidien)."
echo "    Artefact: /var/lib/omni-mobile/attack-graph.json (console). GELF: event_source=attack_path."
echo "    Pour pousser maintenant : oms-graph/.venv/bin/python -m oms_graph.run analyze --push --config $ETC/config.yaml ==="
