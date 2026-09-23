#!/usr/bin/env bash
# =============================================================================
# Deploiement des correctifs de l'audit alerting/correlation du 17/07/2026.
# A LANCER PAR L'OPERATEUR (le harnais bloque les mutations de prod en autonomie).
#
#   bash tools/deploy-audit-fixes-2026-07-17.sh            # tout, dans l'ordre
#   STEP=1 bash tools/deploy-audit-fixes-2026-07-17.sh     # une seule etape
#
# set -e : arret au premier echec. Chaque etape est idempotente (rejouable).
# Rien ici ne touche : le routage event_source (LOT E), les signaux XDR morts
# (F.1/F.2), ni la def morte live "kill-chain correlee" -> decisions RSSI, voir
# docs/AUDIT-2026-07-17-RESTE-A-TRAITER.md.
#
# ROLLBACK triage :
#   cp /root/omni-alert-triage.deployed-bak-<horodatage> /usr/local/sbin/omni-alert-triage
#   systemctl restart omni-alert-triage
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
STEP="${STEP:-all}"
log(){ printf '\n== %s\n' "$*"; }
run(){ [ "$STEP" = all ] || [ "$STEP" = "$1" ]; }

[ -f 00-vars.env ] || { echo "FATAL: 00-vars.env absent (necessaire aux scripts Graylog)"; exit 1; }

# --- 1. TRIAGE : le coeur des correctifs (8 fixes). Verifie, non-regression prouvee. ---
if run 1; then
  log "1/5 TRIAGE : sauvegarde + deploiement + restart"
  python3 -m py_compile triage/omni-alert-triage
  cp -a /usr/local/sbin/omni-alert-triage "/root/omni-alert-triage.deployed-bak-$(date +%F-%H%M)"
  cp -a triage/omni-alert-triage /usr/local/sbin/omni-alert-triage
  systemctl restart omni-alert-triage
  sleep 2
  if systemctl is-active --quiet omni-alert-triage && curl -sf http://127.0.0.1:8089/stats >/dev/null; then
    echo "   triage actif, /stats repond -> OK"
  else
    echo "   ECHEC : triage muet apres restart. ROLLBACK :"
    echo "     cp /root/omni-alert-triage.deployed-bak-* /usr/local/sbin/omni-alert-triage && systemctl restart omni-alert-triage"
    exit 1
  fi
fi

# --- 2. VEILLE DE VERSION : outil lecture seule + timer quotidien ---
if run 2; then
  log "2/5 VEILLE DE VERSION : install outil + unites + timer"
  install -m 0755 tools/omni-version-watch          /usr/local/sbin/omni-version-watch
  install -m 0644 tools/omni-version-watch.service  /etc/systemd/system/omni-version-watch.service
  install -m 0644 tools/omni-version-watch.timer    /etc/systemd/system/omni-version-watch.timer
  systemctl daemon-reload
  systemctl enable --now omni-version-watch.timer
  systemctl start omni-version-watch.service || true   # 1er passage (oneshot, lecture seule)
  echo "   veille active (revele aujourd'hui : graylog-server 7.1.3 -> 7.1.5 disponible)"
fi

# --- 3. SUPERVISER LA VEILLE (self-health) -- APRES que le timer soit actif (etape 2) ---
if run 3; then
  log "3/5 SELF-HEALTH : cablage de la veille (de-commente APRES activation du timer)"
  sed -i -E 's/^([[:space:]]*)#[[:space:]]*"omni-version-watch":([[:space:]]*)172800,/\1"omni-version-watch":\2172800,/' 61-supervision-robots.sh
  grep -q '^[[:space:]]*"omni-version-watch":' 61-supervision-robots.sh || { echo "   ECHEC sed (ligne non de-commentee)"; exit 1; }
  bash 61-supervision-robots.sh
  echo "   self-health surveille desormais omni-version-watch"
fi

# --- 4. GRAYLOG : provisionner la def de veille (13) + converger la regle Entra (94) ---
if run 4; then
  log "4/5 GRAYLOG : def veille version (13, create-only) + regle credential (94, compare+PUT)"
  bash 13-graylog-alerts.sh
  bash 94-entra.sh
  echo "   def 'Version SIEM en retard' posee ; regle Entra convergee (clause 'credential' nue retiree)"
fi

# --- 5. Rappel : oms-xdr / oms-graph n'ont besoin d'AUCUNE action ---
if run 5; then
  log "5/5 XDR / GRAPH : aucune action requise"
  echo "   oms-xdr.timer et oms-graph.timer tournent depuis le depot (ExecStart -> repo/.venv)."
  echo "   Les correctifs responder.py / engine.py / response.py sont pris au prochain tic (< 5 min)."
  echo "   Verif : journalctl -u oms-xdr --since '10 min ago' | grep -i non-implemente  (au besoin)"
fi

log "DEPLOIEMENT TERMINE."
echo "Non deploye (decisions RSSI, voir docs/AUDIT-2026-07-17-RESTE-A-TRAITER.md) :"
echo "  - LOT E routage event_source (fuite omni-m365/365j) : atomique, risque ingestion."
echo "  - Signaux XDR morts + F.1/F.2 (rules.yaml) : ressuscitent de la detection."
echo "  - Def live 'kill-chain correlee' : a desactiver via l'API/console (create-only ne l'atteint pas)."
