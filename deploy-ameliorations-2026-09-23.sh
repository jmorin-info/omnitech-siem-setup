#!/usr/bin/env bash
# =============================================================================
# deploy-ameliorations-2026-09-23.sh - Deploiement des corrections du 23/09/2026.
#   1. Service de triage  : descriptions nettoyees, correlation par tactiques
#      ATT&CK + cle cible interne, juge LLM (contexte decisif, prompt OMNITECH,
#      explication reelle affichee dans le mail, journalisation des decisions).
#   2. Robot geo (40)     : voyage impossible = 2 positions REELLES et 2 PAYS
#      differents (supprime 199/200 FP mesures sur 90 j) + message lisible.
#   3. Regle 4698 (80)    : indicateurs forts vs faibles + emplacements de
#      confiance (3/3 FP eteints) et correction de l'evasion "-enc".
#   Les playbooks (lookups/alert-guidance.json) sont relus a chaud : rien a faire.
#   Idempotent. Journalise ce qui change.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

echo "==> [1/3] Service de triage"
python3 -m py_compile triage/omni-alert-triage || { echo "ECHEC compilation"; exit 1; }
if diff -q triage/omni-alert-triage /usr/local/sbin/omni-alert-triage >/dev/null 2>&1; then
  echo "    [=] deja a jour"
else
  cp -a /usr/local/sbin/omni-alert-triage "/root/omni-alert-triage.deployed-bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  install -m 755 triage/omni-alert-triage /usr/local/sbin/omni-alert-triage
  systemctl restart omni-alert-triage
  sleep 2
  systemctl is-active --quiet omni-alert-triage && echo "    [+] deploye et redemarre" || { echo "    [!] service KO"; journalctl -u omni-alert-triage -n 20 --no-pager; exit 1; }
fi

echo "==> [2/3] Robot geo (voyage impossible)"
./40-ueba-ndr.sh 2>&1 | grep -Ei 'ueba-geo|impossible|\[\+\]|\[!\]' | tail -8

echo "==> [3/3] Regle pipeline 4698 (tache planifiee)"
./80-detection-extra2.sh 2>&1 | grep -Ei 'schtask|regle|\[\+\]|\[!\]' | tail -8

echo
echo "=== Verification ==="
systemctl is-active omni-alert-triage | sed 's/^/  triage: /'
echo "  playbooks : $(python3 -c "import json;print(len(json.load(open('lookups/alert-guidance.json'))))") entrees"
echo "=== Termine. ==="
