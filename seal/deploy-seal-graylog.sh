#!/usr/bin/env bash
# =============================================================================
#  deploy-seal-graylog.sh - Orchestrateur COTE GRAYLOG de l'integration SEAL
#  OMNITECH SECURITY - MISSION_SEAL_GRAYLOG
#
#  Ajoute "un SEAL" dans Graylog de bout en bout, en UNE commande, IDEMPOTENT :
#    1. Input GELF TCP dedie + 3 index sets + 3 streams (routage event_domain)
#       + lookup REEV + regles de normalisation (pipelines) + exclusion anti-dup M365
#    2. Referentiel de decodage REEV (code -> libelle) : CSV du lookup
#    3. Detections + notification Teams (dead-man switches crees desactives)
#    4. Dashboards (SOC / Pilotage-audit / Sante collecte)
#    5. Correlation oms-xdr : rappel (config fichier, prise au prochain cycle)
#
#  A LANCER sur la VM SIEM (aupres de Graylog), depuis la racine du depot :
#      sudo bash seal/deploy-seal-graylog.sh
#
#  PRE-REQUIS : 00-vars.env renseigne (GRAYLOG_API_URL/TOKEN ou GRAYLOG_ADMIN_PASS,
#  SEAL_DB_* pour la regen REEV), venv seal/.venv (pymssql) pour la regen REEV.
#  NE cree PAS la couche SQL (cf sql/ + Run-SealDDL.ps1, cote SEAL) ni Logstash
#  (cf logstash/install-logstash-siem.sh). Ordre global : voir README.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."          # racine du depot
[[ -f ./00-vars.env ]] || { echo "00-vars.env introuvable (lancer depuis la racine du depot)"; exit 1; }
set -a; source ./00-vars.env; set +a

PY="seal/.venv/bin/python"; [[ -x "$PY" ]] || PY="python3"
step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
fail=0

step "1/5  Input GELF TCP + index sets + streams + pipelines + lookup + anti-dup M365"
$PY seal/graylog/provision_seal.py --apply || fail=1

step "2/5  Referentiels : REEV (code -> libelle) + Zone (OBFI_ID -> zone physique)"
bash seal/graylog/regen_reev_lookup.sh || echo "  [!] regen REEV KO (verifier SEAL_DB_* + venv pymssql ; le lookup restera vide)"
# Zone : necessite vw_SealZone_SIEM (07_, topologie, etape operateur). Best-effort :
# reste vide tant que la vue n'existe pas -> seal_zone non pose, aucun effet de bord.
bash seal/graylog/regen_zone_lookup.sh || echo "  [i] regen ZONE inactif (deployer vw_SealZone_SIEM d'abord, cf docs/ZONES-TOPOLOGIE.md)"

step "3/5  Detections + notification Teams (dead-man switches desactives)"
$PY seal/detections/provision_detections.py --apply || fail=1

step "4/5  Dashboards (SOC / Pilotage-audit / Sante collecte)"
$PY seal/dashboards/provision_dashboards.py --apply || fail=1

step "5/5  Correlation oms-xdr + composants optionnels"
echo "  Signaux/regles SEAL : oms-xdr/oms_xdr/rules.yaml ; streams : oms-xdr/config.yaml."
echo "  Le service oms-xdr.timer lit la config du depot -> pris au prochain cycle (5 min)."
echo "  Pont console SEAL<->AD (identity_console) et enrichissement zone (seal_zone) :"
echo "    poses par les pipelines (regles 15/16), actifs des que les lookups sont peuples."
echo "  SLA d'acquittement des alarmes severes (optionnel, timer DESACTIVE par defaut) :"
echo "    sudo seal/sla/install-sla-poller.sh  puis  systemctl enable --now oms-seal-sla.timer"

echo
if [[ $fail -eq 0 ]]; then
  echo "== Cote Graylog : OK. Verifier l'arrivee des logs (systemctl start logstash cote collecte). =="
else
  echo "== Termine AVEC erreurs (voir ci-dessus). Relançable sans effet de bord (idempotent). =="
fi
exit $fail
