#!/usr/bin/env bash
# ==============================================================================
# 11-graylog-enrichment.sh - Enrichissement Graylog
#   1. Tables de lookup (CSV deposes dans /etc/graylog/lookup) :
#      event_id -> action/categorie (Security, Sysmon, autres canaux),
#      logon types, sous-statuts 4625/4776, codes echec Kerberos, RID groupes
#      privilegies. Utilisees par les pipelines (12) -> champs lisibles.
#   2. GeoIP : bases DB-IP Lite (mmdb, gratuites, sans compte) + activation du
#      processeur GeoIP. Sans Internet : deposer les .mmdb manuellement dans
#      /var/lib/graylog-server/geoip puis relancer ce script.
#   3. Threat Intelligence (plugin integre) : listes Tor + Spamhaus DROP.
#   4. Ordre des processeurs : GeoIP APRES le Pipeline Processor (sinon les
#      champs src_ip/dest_ip crees par les pipelines ne sont jamais geolocalises).
#
# Idempotent. Prerequis : 10-graylog-model.sh. Suite : 12-graylog-pipelines.sh
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

LOOKUP_DIR="/etc/graylog/lookup"
GEOIP_DIR="/var/lib/graylog-server/geoip"

# ------------------------------------------------------------- 1. CSV lookups
echo "==> [1/4] Tables de lookup (CSV -> data adapter -> cache -> table)"
install -d -m 755 "${LOOKUP_DIR}"
install -m 644 lookups/*.csv "${LOOKUP_DIR}/"
chown -R root:graylog "${LOOKUP_DIR}" 2>/dev/null || true
ok "CSV deployes dans ${LOOKUP_DIR}"

# ensure_lookup <nom> <titre> <csv> <key_col> <val_col>
# ensure_lookup() centralise dans lib-graylog.sh (supprime la copie locale)

ensure_lookup "win-event-action"     "OMNI EventID Security -> action"      "win-events.csv"         "event_id"    "action"
ensure_lookup "win-event-category"   "OMNI EventID Security -> categorie"   "win-events.csv"         "event_id"    "category"
ensure_lookup "sysmon-event-action"  "OMNI EventID Sysmon -> action"        "sysmon-events.csv"      "event_id"    "action"
ensure_lookup "winother-action"      "OMNI Canal:EventID -> action"         "winother-events.csv"    "channel_eid" "action"
ensure_lookup "logon-type"           "OMNI LogonType -> libelle"            "logon-types.csv"        "logon_type"  "label"
ensure_lookup "logon-failure"        "OMNI SubStatus 4625/4776 -> raison"   "win-logon-failure.csv"  "code"        "reason"
ensure_lookup "kerb-failure"         "OMNI Code echec Kerberos -> raison"   "kerb-failure-codes.csv" "code"        "reason"
ensure_lookup "priv-group-rid"       "OMNI RID groupe privilegie -> nom"    "priv-group-rids.csv"    "rid"         "group_label"

# ------------------------------------------------------------------- 2. GeoIP
echo "==> [2/4] GeoIP (DB-IP Lite, format mmdb)"
install -d -m 755 "${GEOIP_DIR}"
YM="$(date +%Y-%m)"
download_mmdb() {  # $1 base (dbip-city-lite|dbip-asn-lite)  $2 cible
  local URL="https://download.db-ip.com/free/$1-${YM}.mmdb.gz"
  if [[ -s "$2" ]]; then skip "$(basename "$2") deja present"; return 0; fi
  if curl -fsSL --max-time 120 "${URL}" -o "$2.gz" 2>/dev/null; then
    gunzip -f "$2.gz" && ok "telecharge: $(basename "$2")"
  else
    warn "telechargement KO: ${URL} (deposer le .mmdb manuellement puis relancer)"
    return 1
  fi
}
GEO_OK=1
download_mmdb "dbip-city-lite" "${GEOIP_DIR}/dbip-city-lite.mmdb" || GEO_OK=0
download_mmdb "dbip-asn-lite"  "${GEOIP_DIR}/dbip-asn-lite.mmdb"  || GEO_OK=0
chown -R graylog:graylog "${GEOIP_DIR}" 2>/dev/null || true

if [[ "${GEO_OK}" == "1" ]]; then
  api_put "/system/cluster_config/org.graylog.plugins.map.config.GeoIpResolverConfig" <<EOF >/dev/null
{
  "enabled": true,
  "enforce_graylog_schema": false,
  "db_vendor_type": "MAXMIND",
  "city_db_path": "${GEOIP_DIR}/dbip-city-lite.mmdb",
  "asn_db_path": "${GEOIP_DIR}/dbip-asn-lite.mmdb",
  "refresh_interval_unit": "HOURS",
  "refresh_interval": 6,
  "use_s3": false
}
EOF
  ok "processeur GeoIP active (mode tous champs IP -> <champ>_country_code, _city_name, _geolocation)"
  # MAJ mensuelle automatique des bases (DB-IP publie 1 fichier/mois)
  cat > /etc/cron.monthly/omni-geoip-update <<CRON
#!/usr/bin/env bash
# MAJ mensuelle des bases GeoIP DB-IP Lite (provisionne par 11-graylog-enrichment.sh)
set -e
YM="\$(date +%Y-%m)"
for b in dbip-city-lite dbip-asn-lite; do
  curl -fsSL "https://download.db-ip.com/free/\${b}-\${YM}.mmdb.gz" -o "${GEOIP_DIR}/\${b}.mmdb.gz" \
    && gunzip -f "${GEOIP_DIR}/\${b}.mmdb.gz" && chown graylog:graylog "${GEOIP_DIR}/\${b}.mmdb"
done
CRON
  chmod 755 /etc/cron.monthly/omni-geoip-update
  ok "cron mensuel de mise a jour: /etc/cron.monthly/omni-geoip-update"
else
  warn "GeoIP non active (bases absentes) - relancer apres depot des .mmdb"
fi

# --------------------------------------------------------- 3. Threat Intel
echo "==> [3/4] Threat Intelligence (Tor exit nodes + Spamhaus DROP)"
api_put "/system/cluster_config/org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration" <<'EOF' >/dev/null && \
  ok "plugin Threat Intel: tor=on spamhaus=on (listes telechargees et rafraichies par Graylog)" || \
  warn "config Threat Intel refusee (non bloquant)"
{
  "tor_enabled": true,
  "spamhaus_enabled": true,
  "abusech_ransom_enabled": false,
  "otx_enabled": false,
  "otx_api_key": null
}
EOF

# --------------------------------------------- 4. Ordre des processeurs
echo "==> [4/4] Ordre des processeurs (GeoIP en DERNIER, apres les pipelines)"
CURRENT_ORDER="$(api_get "/system/messageprocessors/config")"
NEW_ORDER="$(echo "${CURRENT_ORDER}" | jq '
  .processor_order as $o
  | ($o | map(select(.name=="GeoIP Resolver"))) as $geo
  | ($o | map(select(.name!="GeoIP Resolver"))) + $geo
  | {processor_order: ., disabled_processors: []}')"
if [[ "$(echo "${CURRENT_ORDER}" | jq -c '.processor_order')" == "$(echo "${NEW_ORDER}" | jq -c '.processor_order')" ]]; then
  skip "ordre deja correct"
else
  echo "${NEW_ORDER}" | api_put "/system/messageprocessors/config" >/dev/null
  ok "GeoIP Resolver deplace en fin de chaine"
fi
api_get "/system/messageprocessors/config" | jq -r '.processor_order[].name' | sed 's/^/      /'

echo
echo "=== 11-graylog-enrichment.sh termine. Lancer 12-graylog-pipelines.sh ==="
