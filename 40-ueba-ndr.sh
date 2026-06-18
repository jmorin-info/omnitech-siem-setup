#!/usr/bin/env bash
# =============================================================================
# 40-ueba-ndr.sh - Active la couche UEBA / NDR "au-dela de Graylog" (4 collecteurs)
#   - omni-ueba-volume : anomalie de volume par source (z-score, meme-heure-du-jour)
#   - omni-ueba-geo    : impossible travel (geo-velocite haversine)
#   - omni-ndr-beacon  : beaconing / C2 (regularite temporelle, CV des intervalles)
#   - omni-ueba-score  : score de risque d'entite (UEBA, hote + compte, 0-100)
#   Route les 4 event_source vers "OMNI - Interne SIEM" et les EXCLUT de M365
#   (anti double-comptage). Installe 4 timers systemd echelonnes + 1er passage.
#   Les alert_tag (volume_spike/drop, impossible_travel, beaconing) sont mappes
#   MITRE par le CSV (37) -> risk_score + page ATT&CK + facteur UEBA 'detections'.
# Idempotent. Prerequis : 21 (stream interne) + 12 + 37. Relance 14 + 13 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

SOURCES=(ueba_volume ueba_geo ndr_beacon ueba_score)
for b in omni-ueba-volume omni-ueba-geo omni-ndr-beacon omni-ueba-score; do
  [[ -x "/usr/local/sbin/${b}" ]] || die "/usr/local/sbin/${b} absent."
done

# --- 1. Routage des 4 event_source -> INT (+ exclusion M365) -----------------
echo "==> [1/3] Routage event_source UEBA/NDR -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream 'OMNI - Interne SIEM' introuvable (lancer 21 d'abord)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
for V in "${SOURCES[@]}"; do
  if echo "${CUR}" | grep -qx "${V}"; then skip "regle event_source=${V} deja presente"
  else
    jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:false,
        description:("ueba/ndr: "+$v)}' \
      | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=${V} ajoutee"
  fi
done

M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  for V in "${SOURCES[@]}"; do
    if echo "${MEX}" | grep -qx "${V}"; then skip "M365 exclut deja event_source=${V}"
    else
      jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:true,
          description:("exclusion ueba/ndr (anti-dup): "+$v)}' \
        | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais event_source=${V}"
    fi
  done
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 2. Services + timers systemd (echelonnes) -------------------------------
echo "==> [2/3] Services + timers systemd (echelonnes)"
# bin : description : OnCalendar
units=(
  "omni-ueba-volume:anomalie de volume (z-score):*-*-* *:12:00"
  "omni-ueba-geo:impossible travel (geo-velocite):*-*-* *:17,47:00"
  "omni-ndr-beacon:beaconing / C2 (toutes les 6h):*-*-* 02,08,14,20:22:00"
  "omni-ueba-score:score d'entite UEBA:*-*-* *:27,57:00"
)
for u in "${units[@]}"; do
  BIN="${u%%:*}"; REST="${u#*:}"; DESC="${REST%%:*}"; CAL="${REST#*:}"
  cat > "/etc/systemd/system/${BIN}.service" <<EOF
[Unit]
Description=OMNI SIEM - ${DESC}
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/${BIN}
Nice=15
EOF
  cat > "/etc/systemd/system/${BIN}.timer" <<EOF
[Unit]
Description=OMNI SIEM - ${DESC} (timer)

[Timer]
OnCalendar=${CAL}
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl enable "${BIN}.timer" >/dev/null 2>&1 || true
done
systemctl daemon-reload
for u in "${units[@]}"; do systemctl start "${u%%:*}.timer" >/dev/null 2>&1 || true; done
ok "4 timers UEBA/NDR actifs (echelonnes)"

# --- 3. Premiers passages -----------------------------------------------------
echo "==> [3/3] Premiers passages (beaconing peut prendre ~15s)"
for BIN in omni-ueba-volume omni-ueba-geo omni-ndr-beacon omni-ueba-score; do
  if systemctl start "${BIN}.service"; then
    echo "    $(journalctl -u "${BIN}.service" -n 1 --no-pager -o cat 2>/dev/null)"
  else warn "${BIN} : 1er passage KO (journalctl -u ${BIN})"; fi
done

echo
echo "=== 40-ueba-ndr.sh termine. Relancer 14 (page UEBA/NDR) + 13 (alertes). ==="
