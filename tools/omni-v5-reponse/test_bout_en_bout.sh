#!/usr/bin/env bash
# Chantier 5 - test de bout en bout de omni-v5-reponse via nginx (SIMULATION).
# Sessions de test signées localement par sign_session() de omni-mobile-api, TTL réduit à 300 s,
# jamais affichées. Demandeur : test-v5-demandeur (rôle par défaut « analyste »).
# Le test envoie des messages GELF event_source=reponse (simulation) : à lancer sur le serveur SIEM, en root.
# Variables obligatoires :
#   REPONSE_TEST_VALIDEUR        compte membre de SOC_ADMINS utilisé comme valideur
#   REPONSE_TEST_DC              nom d'un contrôleur de domaine (refus attendu)
#   REPONSE_TEST_LEURRE          compte leurre déclaré dans cibles-protegees (refus attendu)
# Facultatives : REPONSE_TEST_HOTE (nom servi par nginx), REPONSE_TEST_CA (certificat racine), REPONSE_TEST_POSTE.
set -uo pipefail
umask 077
VALIDEUR="${REPONSE_TEST_VALIDEUR:?compte SOC_ADMINS de test}"
DC_TEST="${REPONSE_TEST_DC:?nom d un controleur de domaine}"
LEURRE_TEST="${REPONSE_TEST_LEURRE:?compte leurre de cibles-protegees}"
POSTE="${REPONSE_TEST_POSTE:-bx-qa-v5test-pc}"
W=$(mktemp -d /tmp/v5rep-e2e.XXXXXX); trap 'rm -rf "$W"' EXIT
H="${REPONSE_TEST_HOTE:-bx-it-graylog-vm.omnitech.security}"
U="https://$H/m/reponse"
CURL=(curl -s --cacert "${REPONSE_TEST_CA:-/etc/graylog/certs/omnitech-rootca.crt}" --resolve "$H:443:127.0.0.1")
ORI=(-H "Origin: https://$H")
cd /opt/omni-siem/repository/mobile && set -a && . /etc/default/omni-mobile && set +a
.venv/bin/python - "$W" "$VALIDEUR" <<'PY' 2>/dev/null
import importlib.util, sys, os
s = importlib.util.spec_from_file_location('omm', 'omni-mobile-api.py'); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
m.SESSION_TTL = 300
for nom, u in (("dem", "test-v5-demandeur"), ("val", sys.argv[2])):
    open(os.path.join(sys.argv[1], nom), "w").write("oms_session=" + m.sign_session(u))
PY
cd /tmp
[[ -s $W/dem && -s $W/val ]] || { echo "jetons de test non obtenus"; exit 1; }
DEM=(-H "Cookie: $(cat $W/dem)"); VAL=(-H "Cookie: $(cat $W/val)")
n=0; ok=0
verif() { n=$((n+1)); if [[ "$2" == "$3" ]]; then ok=$((ok+1)); echo "OK  T$n $1 (HTTP $2)"; else echo "KO! T$n $1 (HTTP $2, attendu $3)"; fi; }
csrf() { grep -o 'name="csrf" value="[^"]*"' "$1" | head -1 | sed 's/.*value="//; s/"$//'; }

c=$("${CURL[@]}" -o $W/p0 -w '%{http_code}' "$U/proposer"); verif "page de demande sans session -> refus" "$c" 401
c=$("${CURL[@]}" "${DEM[@]}" -o $W/p1 -w '%{http_code}' "$U/proposer?action=isoler_poste_eset&cible=$POSTE&alerte=TEST%20bx-qa-seal-vm"); verif "page de demande (demandeur)" "$c" 200
K=$(csrf $W/p1)
c=$("${CURL[@]}" "${DEM[@]}" "${ORI[@]}" -o $W/p2 -w '%{http_code}' --data-urlencode "csrf=$K" --data-urlencode action=isoler_poste_eset \
    --data-urlencode "cible=$DC_TEST" --data-urlencode "alerte=TEST bx-qa-seal-vm" --data-urlencode "motif=TEST chantier 5 : rejet DC attendu" "$U/demande")
verif "cible interdite DC $DC_TEST -> rejet garde-fou" "$c" 403; grep -o 'contrôleur de domaine[^<]*' $W/p2 | head -1
c=$("${CURL[@]}" "${DEM[@]}" "${ORI[@]}" -o $W/p3 -w '%{http_code}' --data-urlencode "csrf=$K" --data-urlencode action=desactiver_compte_ad \
    --data-urlencode "cible=$LEURRE_TEST" --data-urlencode "alerte=TEST bx-qa-seal-vm" --data-urlencode "motif=TEST chantier 5 : rejet leurre attendu" "$U/demande")
verif "cible interdite (compte leurre) -> rejet garde-fou" "$c" 403; grep -o 'compte leurre[^<]*' $W/p3 | head -1
c=$("${CURL[@]}" "${DEM[@]}" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$K" --data-urlencode action=isoler_poste_eset \
    --data-urlencode "cible=$POSTE" --data-urlencode "motif=TEST sans Origin" "$U/demande")
verif "POST sans en-tête Origin -> refus" "$c" 403
c=$("${CURL[@]}" "${DEM[@]}" "${ORI[@]}" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=faux" --data-urlencode action=isoler_poste_eset \
    --data-urlencode "cible=$POSTE" --data-urlencode "motif=TEST csrf faux" "$U/demande")
verif "jeton de formulaire (CSRF) faux -> refus" "$c" 403
c=$("${CURL[@]}" "${DEM[@]}" "${ORI[@]}" -o $W/p4 -w '%{http_code}' --data-urlencode "csrf=$K" --data-urlencode action=isoler_poste_eset \
    --data-urlencode "cible=$POSTE" --data-urlencode "alerte=TEST bx-qa-seal-vm" \
    --data-urlencode "motif=TEST chantier 5 SIEM v5 : bout en bout en simulation (27/11)" "$U/demande")
verif "demande valide isoler_poste_eset $POSTE" "$c" 201
L=$(grep -o "https://$H/m/reponse/confirmer?id=[0-9a-f]*&amp;t=[A-Za-z0-9_-]*" $W/p4 | head -1 | sed 's/&amp;/\&/')
RID=$(echo "$L" | sed 's/.*id=\([0-9a-f]*\).*/\1/'); T=$(echo "$L" | sed 's/.*t=//')
echo "    demande $RID créée (lien à usage unique reçu, non affiché)"
c=$("${CURL[@]}" "${DEM[@]}" -o /dev/null -w '%{http_code}' "$U/confirmer?id=$RID&t=$T"); verif "confirmation par un non-SOC_ADMINS -> refus" "$c" 403
c=$("${CURL[@]}" "${VAL[@]}" -o /dev/null -w '%{http_code}' "$U/confirmer?id=$RID&t=${T}x"); verif "confirmation avec jeton altéré -> refus" "$c" 403
c=$("${CURL[@]}" "${VAL[@]}" -o $W/p5 -w '%{http_code}' "$U/confirmer?id=$RID&t=$T"); verif "page de confirmation (valideur SOC_ADMINS)" "$c" 200
K2=$(csrf $W/p5)
c=$("${CURL[@]}" "${VAL[@]}" "${ORI[@]}" -o $W/p6 -w '%{http_code}' --data-urlencode "id=$RID" --data-urlencode "t=$T" \
    --data-urlencode "csrf=$K2" --data-urlencode decision=valider "$U/confirmer"); verif "validation -> simulation journalisée" "$c" 200
grep -o 'Simulation enregistrée[^<]*' $W/p6 | head -1
c=$("${CURL[@]}" "${VAL[@]}" "${ORI[@]}" -o $W/p7 -w '%{http_code}' --data-urlencode "id=$RID" --data-urlencode "t=$T" \
    --data-urlencode "csrf=$K2" --data-urlencode decision=valider "$U/confirmer"); verif "rejeu du même jeton -> refus (usage unique)" "$c" 403
grep -o 'jeton déjà utilisé[^<]*' $W/p7 | head -1
echo "$ok/$n contrôles conformes"
echo "$RID" > /tmp/v5rep-e2e-rid.txt
