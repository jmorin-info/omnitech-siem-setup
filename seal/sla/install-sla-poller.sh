#!/usr/bin/env bash
# =============================================================================
# install-sla-poller.sh - Installe le poller SLA SEAL sur la VM SIEM.
#
#   - Deploie /opt/oms-seal-sla (poller + venv requests) + /etc/oms-seal-sla
#     (config, non ecrasee si presente) + /var/lib/oms-seal-sla (etat) + units
#     systemd oms-seal-sla.{service,timer}.
#   - IDEMPOTENT. N'ACTIVE PAS le timer : activation manuelle apres revue (comme
#     les dead-man switches ; checkpoint recette). Fait d'abord un test a blanc.
#
#   Aucun secret : le poller lit OpenSearch local et emet en GELF local.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP=/opt/oms-seal-sla
ETC=/etc/oms-seal-sla
VAR=/var/lib/oms-seal-sla

[[ $EUID -eq 0 ]] || { echo "A lancer en root (systemd + /opt)."; exit 1; }

echo "[*] Repertoires..."
mkdir -p "$APP" "$ETC" "$VAR"

echo "[*] Poller + venv (requests)..."
install -m 0755 "${SCRIPT_DIR}/seal_sla_poller.py" "${APP}/seal_sla_poller.py"
install -m 0644 "${SCRIPT_DIR}/README.md" "${APP}/README.md" 2>/dev/null || true
if [[ ! -x "${APP}/.venv/bin/python" ]]; then
  python3 -m venv "${APP}/.venv"
fi
"${APP}/.venv/bin/pip" -q install --upgrade pip >/dev/null 2>&1 || true
"${APP}/.venv/bin/pip" -q install requests >/dev/null

echo "[*] Config (non ecrasee si presente)..."
if [[ -f "${ETC}/seal-sla.env" ]]; then
  echo "    = ${ETC}/seal-sla.env conserve"
else
  install -m 0644 "${SCRIPT_DIR}/deploy/seal-sla.env.example" "${ETC}/seal-sla.env"
  echo "    + ${ETC}/seal-sla.env cree depuis le modele"
fi
[[ -f "${SCRIPT_DIR}/deploy/severe-codes.json.example" ]] && \
  install -m 0644 "${SCRIPT_DIR}/deploy/severe-codes.json.example" "${ETC}/severe-codes.json.example"

echo "[*] Units systemd..."
install -m 0644 "${SCRIPT_DIR}/deploy/oms-seal-sla.service" /etc/systemd/system/oms-seal-sla.service
install -m 0644 "${SCRIPT_DIR}/deploy/oms-seal-sla.timer"   /etc/systemd/system/oms-seal-sla.timer
systemctl daemon-reload

echo "[*] Test a blanc (--once, aucune emission)..."
set -a; # shellcheck disable=SC1091
source "${ETC}/seal-sla.env"; set +a
"${APP}/.venv/bin/python" "${APP}/seal_sla_poller.py" --once || true

cat <<EOF

[OK] Poller SLA installe (timer DESACTIVE).

  Activation (apres revue des breches ci-dessus) :
    systemctl enable --now oms-seal-sla.timer
    systemctl list-timers oms-seal-sla.timer
    journalctl -u oms-seal-sla.service -f

  Detections consommant les marqueurs : SLA-001 (critique) / SLA-002 (elevee)
  -> provisionnees par seal/detections/provision_detections.py (deja actives).
  Widget backlog par site : dashboard "SEAL - Vue multi-site".

  Ajuster la politique : ${ETC}/seal-sla.env (codes severes, SLA, par site).
EOF
