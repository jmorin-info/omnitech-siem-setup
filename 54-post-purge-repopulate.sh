#!/usr/bin/env bash
# =============================================================================
# 54-post-purge-repopulate.sh - Repopulation des dashboards apres une purge.
#   Apres 53-purge-clean.sh (ou tout reset d'index), les widgets derives sont
#   vides tant que les robots d'analyse n'ont pas re-tourne (certains quotidiens).
#   Ce script : (1) reconstruit les index ranges, (2) re-fetch les logs cloud
#   M365, (3) relance TOUS les robots analytiques pour repeupler tout de suite.
#   Idempotent et sans danger : lance des oneshots de lecture/agregation.
#   NB : UEBA (baseline), NDR (motifs sur heures) et vulnerabilites (inventaire
#   client quotidien) restent partiellement vides tant que la donnee fraiche ne
#   s'est pas accumulee - c'est normal, pas un bug.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
GL="https://127.0.0.1:9000/api"; AUTH=(-u "admin:${GRAYLOG_ADMIN_PASS}")
C=(curl -sk -H X-Requested-By:cli)

echo "==> [1/3] Reconstruction des index ranges"
"${C[@]}" "${AUTH[@]}" -X POST "$GL/system/indices/ranges/rebuild" -o /dev/null && echo "    [+] ranges en reconstruction"

echo "==> [2/3] Re-fetch des sources 'pull' (M365 cloud)"
# M365 se recupere par API (pas un flux pousse) -> a re-tirer explicitement.
for svc in omni-m365-fetch omni-m365-activity; do
  systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 && \
    { systemctl start "$svc" 2>/dev/null && echo "    [+] $svc"; }
done

echo "==> [3/4] Relance des robots d'analyse (repopulation derivee)"
ROBOTS="omni-collect-health omni-self-health omni-cert-check omni-vuln-scan \
        omni-geo-flux omni-ueba-volume omni-ueba-score omni-ueba-geo omni-ueba-geo-newcountry \
        omni-ndr-scan omni-ndr-beacon omni-ndr-dns omni-ndr-exfil omni-ndr-lateral \
        omni-ldap-recon omni-incident-correlate"
for svc in $ROBOTS; do
  systemctl start "$svc" 2>/dev/null && echo "    [+] $svc lance" || echo "    [!] $svc KO"
done

echo "==> [4/4] Verification (apres stabilisation)"
sleep 20
echo "    Sources/robots ayant re-emis :"
"${C[@]}" "${AUTH[@]}" -G "http://127.0.0.1:9200/omni-*,graylog_*/_search" >/dev/null 2>&1 || true
curl -s "http://127.0.0.1:9200/omni-*,graylog_*/_search" -H 'Content-Type: application/json' -d '{
  "size":0,"query":{"range":{"timestamp":{"gte":"now-10m"}}},
  "aggs":{"s":{"terms":{"field":"event_source","size":40}}}}' 2>/dev/null \
  | python3 -c "import sys,json;[print('      ',b['key'],'=',b['doc_count']) for b in json.load(sys.stdin)['aggregations']['s']['buckets']]"

echo
echo "=== 54 termine. Live = immediat ; UEBA/NDR/incidents = quelques heures ;"
echo "    vulnerabilites = prochain inventaire client ; tendances 30j = quelques jours. ==="
