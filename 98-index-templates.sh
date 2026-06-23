#!/usr/bin/env bash
# =============================================================================
# 98-index-templates.sh - Bride l'explosion du mapping des index a fort volume
#   (audit rank8). Le parsing KV FortiGate cree un keyword indexe A VIE pour CHAQUE
#   nouvelle cle -> omni-fortigate = 406 champs, cluster-state qui grossit
#   (anti-scalable sur OpenSearch mono-noeud).
#
#   APPROCHE SURE (legacy, ordre superieur, FUSIONNE avec le template Graylog) :
#     - `dynamic: false` -> les NOUVELLES cles non listees sont stockees dans _source
#       (visibles dans le detail du message) mais NON indexees -> le nombre de champs
#       cesse de croitre.
#     - ALLOWLIST explicite (ci-dessous) en keyword/numerique -> les champs utilises par
#       les dashboards/detections/la carte (GEO inclus !) RESTENT indexes et rapides.
#   N'affecte QUE les NOUVEAUX index (effet a la prochaine rotation), REVERSIBLE
#   (supprimer le template -> retour a dynamic:true).
#
#   /!\ A APPLIQUER EN FENETRE DE MAINTENANCE puis VERIFIER au 1er nouvel index :
#   un champ utile oublie de l'allowlist deviendrait non-cherchable. NE PAS auto-lancer
#   dans 00-run-all : revue + validation requises. Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env 2>/dev/null || true
OS="${OPENSEARCH:-http://127.0.0.1:9200}"

# Champs a GARDER indexes (sinon dashboards/detections/carte casses). Generes en keyword,
# les volumetriques en numerique. La GEO (src_ip_*) est OBLIGATOIRE pour la carte 3D.
kw() { for f in "$@"; do printf '"%s":{"type":"keyword","ignore_above":1024},' "$f"; done; }
num() { for f in "$@"; do printf '"%s":{"type":"long"},' "$f"; done; }

PROPS="$(
  kw src_ip dest_ip src_ip_country_code src_ip_city_name dest_ip_country_code \
     src_ip_geolocation dest_ip_geolocation user host event_source event_action \
     alert_tag mitre_technique mitre_tactic mitre_technique_name risk_severity net_segment \
     action service subtype level devname devid srcintf dstintf proto app appcat \
     policyid attack severity url hostname group msg utmaction src_country dest_country \
     winlogbeat_winlog_event_id winlogbeat_winlog_channel
  num dstport srcport sentbyte rcvdbyte duration http_status
)"
PROPS="${PROPS%,}"   # retire la virgule finale

for P in omni-fortigate; do                # cible le pire offender ; etendre apres validation
  TPL="zz-omni-cap-${P#omni-}"
  body="{\"order\":100,\"index_patterns\":[\"${P}_*\"],\"mappings\":{\"dynamic\":false,\"properties\":{${PROPS}}}}"
  code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT "${OS}/_template/${TPL}" -H 'Content-Type: application/json' -d "${body}")"
  [[ "$code" == "200" ]] && echo "    [+] template ${TPL} (dynamic:false + allowlist sur ${P}_*)" \
                         || echo "    [!] echec ${TPL} (HTTP ${code})"
done

echo
echo "=== 98 PRET (NON applique par defaut). Pour appliquer : bash 98-index-templates.sh"
echo "    Puis a la prochaine rotation : verifier la carte 3D (/m/api/geo-flows non vide),"
echo "    les dashboards FortiGate, et le nb de champs (curl ${OS}/<nouvel-index>/_mapping)."
echo "    Rollback : curl -X DELETE ${OS}/_template/zz-omni-cap-fortigate ==="
