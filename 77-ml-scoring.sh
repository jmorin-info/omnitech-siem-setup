#!/usr/bin/env bash
# =============================================================================
# 77-ml-scoring.sh - Couche ML (oms-ml) : scoring d'anomalie + reduction de FP
#   - Anomalie NON-SUPERVISEE par entite (hote/compte) via IsolationForest, log1p
#     + StandardScaler. Reinjecte un ml_score 0-100 + ml_reason en GELF
#     (event_source=ml_anomaly). Entrainable sans label, des maintenant.
#   - Reduction de FAUX POSITIFS SUPERVISEE : labels = disposition analyste des cas
#     SOC (VP/FP). S'auto-saute tant qu'il n'y a pas assez de labels (honnete).
#   - Route event_source=ml_anomaly -> "OMNI - Interne SIEM" (+ exclusion M365),
#     comme l'UEBA (40). Timers systemd : anomalie horaire, FP quotidien.
#   Local-first : sklearn CPU, lecture OpenSearch, reinjection GELF existante.
# Idempotent. Prerequis : OpenSearch + input GELF 12201 + stream interne (21).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env 2>/dev/null || true
source ./lib-graylog.sh 2>/dev/null || true
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

APP=/root/omnitech-siem-setup/oms-ml
VENV="$APP/.venv"
ETC=/etc/oms-ml
STATE=/var/lib/oms-ml

echo "==> [1/6] venv + dependances ML (sklearn, numpy, joblib)"
if [[ ! -x "$VENV/bin/python" ]]; then python3 -m venv "$VENV"; fi
"$VENV/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt" \
  && echo "    [+] dependances installees" \
  || echo "    [!] pip a echoue (hors-ligne ?) — installer les wheels manuellement"
# Paquet importable quel que soit le cwd (sinon 'python -m oms_ml.run' depend du repertoire)
( cd "$APP" && "$VENV/bin/pip" install -q --disable-pip-version-check -e . 2>/dev/null ) \
  && echo "    [+] oms_ml installe (editable)" || true

echo "==> [2/6] Configuration $ETC/config.yaml + etat $STATE"
mkdir -p "$ETC" "$STATE"
if [[ -f "$ETC/config.yaml" ]]; then
  echo "    [=] config existante conservee"
else
  install -m 644 "$APP/config.yaml" "$ETC/config.yaml" && echo "    [+] config installee"
fi

echo "==> [3/6] Unites systemd (anomalie horaire + FP quotidien)"
for u in oms-ml-anomaly.service oms-ml-anomaly.timer oms-ml-fp.service oms-ml-fp.timer; do
  install -m 644 "$APP/deploy/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now oms-ml-anomaly.timer oms-ml-fp.timer >/dev/null 2>&1 \
  && echo "    [+] timers actifs" || echo "    [!] activation timers KO"

echo "==> [4/6] Routage event_source=ml_anomaly -> 'OMNI - Interne SIEM' (+ exclusion M365)"
if declare -f require_api >/dev/null 2>&1 && require_api 2>/dev/null; then
  ST="$(get_stream_id 'OMNI - Interne SIEM' 2>/dev/null)"
  if [[ -n "${ST:-}" ]]; then
    CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
    if echo "$CUR" | grep -qx "ml_anomaly"; then echo "    [=] routage deja present"
    else
      jq -n '{field:"event_source",type:1,value:"ml_anomaly",inverted:false,description:"oms-ml: anomalie"}' \
        | api_post "/streams/${ST}/rules" >/dev/null && echo "    [+] ml_anomaly -> interne"
    fi
    M365="$(get_stream_id 'OMNI - M365' 2>/dev/null)"
    if [[ -n "${M365:-}" ]]; then
      MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
      echo "$MEX" | grep -qx "ml_anomaly" || jq -n '{field:"event_source",type:1,value:"ml_anomaly",inverted:true,description:"exclusion oms-ml (anti-dup)"}' \
        | api_post "/streams/${M365}/rules" >/dev/null && echo "    [+] M365 exclut ml_anomaly"
    fi
  else echo "    [!] stream 'OMNI - Interne SIEM' introuvable (lancer 21) — routage saute"; fi
else echo "    [!] API Graylog indisponible — routage a relancer plus tard"; fi

echo "==> [5/6] Passe de validation (lecture seule, SANS push)"
( cd "$APP" && "$VENV/bin/python" -m oms_ml.run anomaly --entity all --top 8 --config "$ETC/config.yaml" 2>&1 ) \
  | grep -vE 'INFO oms-ml' | sed 's/^/    /'

echo "==> [6/6] Etat du modele supervise (labels analystes)"
( cd "$APP" && "$VENV/bin/python" -m oms_ml.run status --config "$ETC/config.yaml" 2>&1 ) | grep -vE 'INFO oms-ml' | sed 's/^/    /'

echo
echo "=== 77 termine. Anomalie ML active (horaire). FP supervise s'activera"
echo "    des que les cas SOC porteront une disposition VP/FP (cf. console)."
echo "    Pour reinjecter tout de suite : systemctl start oms-ml-anomaly.service"
