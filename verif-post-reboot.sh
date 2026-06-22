#!/usr/bin/env bash
# =============================================================================
# verif-post-reboot.sh - Verification post-redemarrage securite du SIEM OMNITECH.
#   A lancer EN ROOT apres le reboot (noyau 6.12.90 -> 6.12.94). LECTURE SEULE
#   (ne modifie rien). Confirme dans l'ordre du risque : noyau a jour, /data
#   DECHIFFRE + monte (TPM ou passphrase), services coeur, API Graylog, robots,
#   collecte de logs vivante. Sortie : PASS/FAIL par controle + verdict global.
#   Si /data n'est pas monte (TPM rate) -> instructions de deverrouillage affichees.
# =============================================================================
cd "$(dirname "$0")" 2>/dev/null || true
G="\033[32m"; R="\033[31m"; Y="\033[33m"; N="\033[0m"
ok(){ echo -e "  ${G}OK${N}  $1"; }
ko(){ echo -e "  ${R}KO  $1${N}"; FAIL=$((FAIL+1)); }
wn(){ echo -e "  ${Y}..${N}  $1"; }
FAIL=0
echo "=============================================================="
echo " Verification post-reboot SIEM  -  $(date 2>/dev/null)"
echo "=============================================================="

echo "[1] Noyau & patch de securite"
KC=$(uname -r)
case "$KC" in 6.12.94*) ok "noyau actif : $KC (a jour)";; *) wn "noyau actif : $KC (attendu 6.12.94+ ; verifier la MAJ)";; esac
[[ -e /run/reboot-required || -e /var/run/reboot-required ]] && wn "reboot encore demande (re-verifier needrestart)" || ok "aucun reboot en attente"
KSTA=$(needrestart -b -k 2>/dev/null | awk -F: '/NEEDRESTART-KSTA/{gsub(/ /,"",$2);print $2}')
[[ -z "$KSTA" || "$KSTA" == "1" ]] && ok "needrestart noyau : a jour" || wn "needrestart KSTA=$KSTA (1=ok, >=3=reboot requis)"

echo "[2] Stockage chiffre /data  (LE point critique : TPM2/LUKS2)"
if cryptsetup status cryptdata >/dev/null 2>&1; then ok "LUKS 'cryptdata' OUVERT"
else ko "LUKS 'cryptdata' FERME -> deverrouiller a la console :  cryptsetup open /dev/sdb1 cryptdata"; fi
if mountpoint -q /data; then ok "/data monte ($(df -h /data 2>/dev/null | awk 'NR==2{print $4" libres / "$2}'))"
else ko "/data NON monte -> apres deverrouillage :  mount /data   (ou: systemctl restart data.mount)"; fi
# TPM auto vs passphrase manuelle (indice journal du boot courant)
if journalctl -b 2>/dev/null | grep -qiE "cryptdata.*(tpm2|TPM)"; then ok "deverrouillage par TPM (automatique, nominal)"
else wn "TPM non confirme dans le journal de boot. Si tu as du taper la PASSPHRASE,"
     wn "  re-scelle le TPM :  systemd-cryptenroll /dev/sdb1 --tpm2-device=auto --tpm2-pcrs=7 --wipe-slot=tpm2"; fi

echo "[3] Services coeur"
for s in mongod opensearch graylog-server nginx omni-mobile-api omni-soar; do
  systemctl is-active --quiet "$s" 2>/dev/null && ok "$s actif" || ko "$s INACTIF -> systemctl status $s --no-pager"
done

echo "[4] API Graylog & inputs"
if [[ -f 00-vars.env && -f lib-graylog.sh ]]; then
  source ./00-vars.env 2>/dev/null; source ./lib-graylog.sh 2>/dev/null
  # lib-graylog redefinit ok()/warn() -> on restaure notre affichage PASS/FAIL
  ok(){ echo -e "  ${G}OK${N}  $1"; }; ko(){ echo -e "  ${R}KO  $1${N}"; FAIL=$((FAIL+1)); }; wn(){ echo -e "  ${Y}..${N}  $1"; }
  LC=$(api_get /system 2>/dev/null | jq -r '.lifecycle // "?"' 2>/dev/null)
  [[ "$LC" == "running" ]] && ok "Graylog lifecycle=running" || wn "Graylog lifecycle=$LC (peut prendre 1-2 min au demarrage)"
  IR=$(api_get /system/inputstates 2>/dev/null | jq '[.states[]?|select(.state=="RUNNING")]|length' 2>/dev/null)
  [[ -n "$IR" && "$IR" -gt 0 ]] && ok "$IR input(s) RUNNING" || wn "inputs RUNNING : ${IR:-?} (verifier si 0)"
else wn "00-vars.env / lib-graylog.sh introuvables (lancer depuis le depot)"; fi

echo "[5] Robots d'auto-supervision"
if [[ -x /usr/local/sbin/omni-self-health ]]; then
  SH=$(UEBA_DRY=1 /usr/local/sbin/omni-self-health 2>/dev/null | grep -i "robots OK")
  echo "$SH" | grep -q "18/18" && ok "self-health : ${SH#*] }" || wn "self-health : ${SH:-indispo} (laisser les timers se relancer)"
else wn "omni-self-health indispo"; fi

echo "[6] Collecte de logs vivante"
NEV=$(curl -s -m8 "http://127.0.0.1:9200/omni-*/_count" -H 'Content-Type: application/json' \
        -d '{"query":{"range":{"timestamp":{"gte":"now-10m"}}}}' 2>/dev/null | jq -r '.count // 0' 2>/dev/null)
[[ "${NEV:-0}" -gt 0 ]] && ok "collecte active : ${NEV} events sur 10 min" \
  || wn "0 event sur 10 min -> normal si <5 min apres boot ; sinon verifier inputs/sources emettrices"

echo "=============================================================="
if [[ $FAIL -eq 0 ]]; then echo -e " ${G}VERDICT : OK - SIEM operationnel apres le reboot.${N}"
else echo -e " ${R}VERDICT : $FAIL controle(s) en echec - traiter les lignes 'KO' ci-dessus.${N}"; fi
echo "=============================================================="
exit $FAIL
