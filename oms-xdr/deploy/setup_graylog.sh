#!/usr/bin/env bash
# =====================================================================
#  OMS-XDR — Provisionnement Graylog (déploiement INTÉGRÉ au SIEM OMNITECH)
#  - NE crée PAS d'input : réutilise l'input GELF HTTP existant (12201).
#  - Route event_source=xdr_incident -> stream "OMNI - Interne SIEM" (idempotent).
#  - Affiche les IDs de streams à reporter dans config.yaml.
#  Pré-requis : OMS_GRAYLOG_TOKEN (token admin) exporté, jq installé.
# =====================================================================
set -euo pipefail
GL="${GL:-https://10.33.220.10}"
TOKEN="${OMS_GRAYLOG_TOKEN:?Exporter OMS_GRAYLOG_TOKEN}"
CURL=(curl -sk -u "${TOKEN}:token" -H "X-Requested-By: oms-xdr" -H "Content-Type: application/json")
INT_TITLE="OMNI - Interne SIEM"

echo "==> Routage des incidents (event_source=xdr_incident -> ${INT_TITLE})"
SID=$("${CURL[@]}" "${GL}/api/streams" | jq -r --arg t "$INT_TITLE" '.streams[]|select(.title==$t)|.id')
if [[ -z "$SID" || "$SID" == "null" ]]; then
  echo "    [!] stream '${INT_TITLE}' introuvable — provisionner le SIEM d'abord."; exit 1
fi
if "${CURL[@]}" "${GL}/api/streams/${SID}" | jq -e '.rules[]?|select(.value=="xdr_incident")' >/dev/null; then
  echo "    [=] règle xdr_incident déjà présente"
else
  "${CURL[@]}" -X POST "${GL}/api/streams/${SID}/rules" \
    -d '{"field":"event_source","value":"xdr_incident","type":1,"inverted":false,"description":"incidents OMS-XDR"}' \
    >/dev/null && echo "    [+] règle xdr_incident ajoutée"
fi

echo
echo "==> IDs de streams (à reporter dans config.yaml -> graylog.streams) :"
"${CURL[@]}" "${GL}/api/streams" | jq -r '.streams[]|select(.title|startswith("OMNI"))|"  \(.id)  \(.title)"'
echo
echo "Réinjection via l'input GELF HTTP existant 12201 (réutilisé). Lecture via OpenSearch. Terminé."
