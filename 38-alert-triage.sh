#!/usr/bin/env bash
# =============================================================================
# 38-alert-triage.sh - Couche de TRIAGE de pertinence des alertes (mail critique
# uniquement). Hybride : regles deterministes (local) + LLM sur la zone grise.
#
#   Probleme : ~105/144 alertes envoyaient un mail -> inondation (dont Tor/Spamhaus
#   ~21k/7j a lui seul). Objectif RSSI : ne recevoir QUE le critique/pertinent.
#
#   Modele : Teams reste cable en direct (firehose SOC). On remplace la notif
#   "Mail equipe IT" par une notif "Triage" (webhook -> omni-alert-triage:8089).
#   Le service classe par tier (CRITICAL/NOISE/GRAY), dedup, FP connus, et
#   n'envoie un MAIL (SMTP) que si critique+pertinent. GRAY -> juge LLM si cle
#   ANTHROPIC_API_KEY presente, sinon defaut fail-safe (OMNI_TRIAGE_GRAY_DEFAULT).
#   Chaque decision -> GELF event_source=alert_triage (tracabilite + dashboard).
#
#   Idempotent. Prerequis : 13 (notifs Mail/Teams), 36-soar.sh (patron service).
#   ATTENTION : le mail depend desormais du service omni-alert-triage (SPOF) ;
#   il est en Restart=on-failure. Surveiller via event_source=alert_triage.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Service omni-alert-triage + config + unit"
install -m 755 triage/omni-alert-triage /usr/local/sbin/omni-alert-triage
mkdir -p /var/lib/omni-alert-triage
# config : ne pas ecraser une config existante (cle API !) ; sinon poser le template
if [[ ! -f /etc/omni-alert-triage.env ]]; then
  install -m 600 triage/omni-alert-triage.env.example /etc/omni-alert-triage.env
  warn "config posee depuis le template — pensez a renseigner ANTHROPIC_API_KEY"
else
  skip "config /etc/omni-alert-triage.env existante conservee"
fi
cat > /etc/systemd/system/omni-alert-triage.service <<'UNIT'
[Unit]
Description=OMNITECH - Triage de pertinence des alertes (mail critique uniquement)
After=network.target graylog-server.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/omni-alert-triage
Restart=on-failure
RestartSec=5
EnvironmentFile=/etc/omni-alert-triage.env
NoNewPrivileges=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now omni-alert-triage.service
sleep 2
ss -lntp | grep -q ':8089' && ok "service omni-alert-triage actif (127.0.0.1:8089)" || warn "service non a l'ecoute"

echo "==> [2/4] Notification Triage (webhook -> 8089)"
TRIAGE_NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Triage (mail critique)")|.id')"
if [[ -z "${TRIAGE_NID}" || "${TRIAGE_NID}" == "null" ]]; then
  TRIAGE_NID="$(jq -n '{title:"OMNI - Triage (mail critique)",
      description:"Webhook vers omni-alert-triage : decide si l_alerte merite un mail - 38-alert-triage.sh",
      config:{type:"http-notification-v1", url:"http://127.0.0.1:8089/triage",
        api_key_as_header:false, api_key:"", api_secret:null, basic_auth:null,
        skip_tls_verification:true}}' \
    | post_entity "/events/notifications" | jqr '.id')"
  ok "notification Triage creee (${TRIAGE_NID})"
else skip "notification Triage existe (${TRIAGE_NID})"; fi
[[ -n "${TRIAGE_NID}" && "${TRIAGE_NID}" != "null" ]] || die "notification Triage absente"

# CRUCIAL : l'allowlist d'URL de Graylog bloque les notifs HTTP non listees. Sans
# cette entree, Graylog refuse de POSTer vers le triage -> AUCUN mail (echec
# silencieux). On ajoute 8089 a cote de SOAR(8088)/push(8090), allowlist conservee.
ALLOW_EP="/system/cluster_config/org.graylog2.system.urlallowlist.UrlAllowlist"
CURALLOW="$(api_get "${ALLOW_EP}")"
if echo "${CURALLOW}" | jq -e '[.entries[]?.value] | index("^http://127\\.0\\.0\\.1:8089/.*$")' >/dev/null 2>&1; then
  skip "URL allowlist : triage 8089 deja present"
else
  echo "${CURALLOW}" | jq -c '.entries += [{"id":"omni-triage-8089","type":"regex","title":"OMNI Triage (local)","value":"^http://127\\.0\\.0\\.1:8089/.*$"}] | {entries,disabled:(.disabled // false)}' \
    | api_put "${ALLOW_EP}" >/dev/null 2>&1 && ok "URL allowlist : 8089 ajoute" || warn "allowlist 8089 : echec"
fi

# Secret partage : la notif envoie l'en-tete X-Triage-Token (api_key_as_header).
# La valeur est lue dans /etc/omni-alert-triage.env (TRIAGE_TOKEN) ; si presente,
# on la pousse dans la config de la notif.
TOK="$(grep -E '^TRIAGE_TOKEN=' /etc/omni-alert-triage.env 2>/dev/null | cut -d= -f2-)"
if [[ -n "${TOK}" ]]; then
  api_get "/events/notifications/${TRIAGE_NID}" \
    | jq -c --arg tok "${TOK}" 'del(._scope) | .config.api_key_as_header=true | .config.api_key="X-Triage-Token" | .config.api_secret={set_value:$tok} | .config.basic_auth=null' \
    | api_put "/events/notifications/${TRIAGE_NID}" >/dev/null 2>&1 && ok "notif Triage : en-tete secret pose" || warn "pose secret : echec"
fi

echo "==> [3/4] Triage = gardien UNIVERSEL du mail (couvre toutes les defs OMNI)"
# Le triage devient le seul juge du mail : sur CHAQUE def OMNI, on retire le mail
# DIRECT (si present) et on garantit la notif Triage. Ainsi meme une alerte
# critique jusque-la en Teams-seul (ex. mail perdu par l'ancien 22-alert-routing)
# est remailee par le triage. Teams reste cable (firehose). Pagine (cf doublons).
MAIL_NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
n=0
for id in $(all_event_defs | jq -r '.event_definitions[] | select(.title|startswith("OMNI")) | .id'); do
  DEF="$(api_get "/events/definitions/${id}")"
  # ne PUT que si un changement est necessaire (idempotent, evite le bruit)
  echo "${DEF}" | jq -e --arg m "$MAIL_NID" --arg tr "$TRIAGE_NID" \
      'any(.notifications[]?; .notification_id==$m) or (any(.notifications[]?; .notification_id==$tr)|not)' >/dev/null || continue
  echo "${DEF}" | jq -c --arg m "$MAIL_NID" --arg tr "$TRIAGE_NID" '
      del(._scope,.matched_at,.updated_at,.scheduler)
      | .notifications = ([.notifications[]? | select(.notification_id!=$m)])
      | (if ([.notifications[]?.notification_id]|index($tr))==null then .notifications += [{notification_id:$tr,notification_parameters:null}] else . end)' \
    | api_put "/events/definitions/${id}" >/dev/null 2>&1
  "${CURL[@]}" -X PUT "${API}/events/definitions/${id}/schedule" >/dev/null 2>&1 || true
  n=$((n+1))
done
ok "${n} definitions (re)cablees vers le Triage"

echo "==> [4/4] Verification"
MAILDIR="$(all_event_defs | jq -r --arg m "$MAIL_NID" '[.event_definitions[]|select(.notifications[]?.notification_id==$m)]|length')"
echo "    definitions avec mail DIRECT restant : ${MAILDIR} (cible 0)"
echo
echo "=== 38 termine. Triage actif : Teams=firehose, Mail=critique trie. ==="
echo "    Activer le LLM zone grise : renseigner ANTHROPIC_API_KEY dans /etc/omni-alert-triage.env"
