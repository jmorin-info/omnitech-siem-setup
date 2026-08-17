#!/usr/bin/env bash
# ==============================================================================
# 99-cert-orchestrator.sh - Source "Cert Orchestrator" (BX-IT-CERT-VM)
#
#   Machine 10.33.120.7 : orchestrateur de renouvellements/demandes de
#   certificats vers OVH. Emet en GELF/UDP (fire-and-forget) vers 12201.
#
#   Pose, de facon IDEMPOTENTE :
#     - input  GELF UDP 0.0.0.0:12201 (coexiste avec le GELF HTTP loopback M365 :
#       TCP 12201 != UDP 12201, et le HTTP est lie a 127.0.0.1 uniquement)
#     - index set 'omni-cert' + stream 'OMNI - Cert Orchestrator' (route sur l'input)
#     - pipeline : tag event_source=cert_parc (garanti quelle que soit la payload
#       de l'app), event_category=pki, severite depuis le NIVEAU GELF structure
#       (fiable - pas de mots-cles devines), et remontee des erreurs.
#
#   Pre-requis cote reseau : nftables ouvre udp/12201 depuis ${IP_CERT}
#   (cf. 06-firewall.sh). Le watchdog connait deja 'cert_parc' (cf. 74).
#
#   NB detections fines (CN, expiration, echec renouvellement OVH) : a ajouter
#   quand on dispose d'un echantillon reel du schema GELF emis par l'app
#   (champs _domain/_status/_action...). Le socle ci-dessous est independant
#   du schema et fonctionne des le premier paquet.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api

IP_CERT="${IP_CERT:-10.33.120.7}"

# ----------------------------------------------------------------- helpers idx
ensure_index_set() {  # prefix  titre  retention_indices -> stdout: id
  local PFX="$1" TITLE="$2" RET="$3" ID
  ID="$(api_get '/system/indices/index_sets?limit=200' | jq -r --arg p "$PFX" '.index_sets[]|select(.index_prefix==$p)|.id')"
  if [[ -n "$ID" ]]; then echo "$ID"; return; fi
  local TMPL; TMPL="$(api_get '/system/indices/index_sets?limit=200' | jq -c '.index_sets[]|select(.index_prefix=="omni-fortigate")')"
  ID="$(echo "$TMPL" | jq --arg t "$TITLE" --arg p "$PFX" --argjson r "$RET" \
        'del(.id,.creation_date,.default,.can_be_default) | .title=$t | .index_prefix=$p | .description=$t | .retention_strategy.max_number_of_indices=$r' \
        | api_post '/system/indices/index_sets' | jqr '.id')"
  [[ -n "$ID" && "$ID" != null ]] && ok "index set '$TITLE' cree" >&2 || warn "index set '$TITLE' refuse" >&2
  echo "$ID"
}
reassign_stream_idx() {  # stream_id  index_set_id
  local SID="$1" IDX="$2" CUR
  [[ -z "$SID" || -z "$IDX" ]] && return
  CUR="$(api_get "/streams/${SID}" | jq -r '.index_set_id')"
  [[ "$CUR" == "$IDX" ]] && return
  local CODE
  CODE="$(api_get "/streams/${SID}" | jq -c --arg i "$IDX" '{title,description,matching_type,remove_matches_from_default_stream,index_set_id:$i,rules:[.rules[]|{field,type,value,inverted}]}' \
    | "${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT "${API}/streams/${SID}" -H 'Content-Type: application/json' -d @-)"
  [[ "$CODE" == "200" ]] && ok "stream reaffecte a l'index set ${IDX}" >&2 || warn "reaffectation stream KO (HTTP ${CODE})" >&2
}

# ------------------------------------------------------------------ [0] input
echo "==> [0/5] Input GELF UDP 0.0.0.0:12201 (Cert Orchestrator)"
IID="$(api_get '/system/inputs' | jq -r '.inputs[]|select(.title=="Cert Orchestrator (GELF UDP 12201)")|.id' | head -1)"
if [[ -z "$IID" ]]; then
  IID="$(api_post '/system/inputs' <<'EOF' | jqr '.id'
{
  "title": "Cert Orchestrator (GELF UDP 12201)",
  "type": "org.graylog2.inputs.gelf.udp.GELFUDPInput",
  "global": true,
  "configuration": {
    "bind_address": "0.0.0.0",
    "port": 12201,
    "recv_buffer_size": 1048576,
    "number_worker_threads": 2,
    "decompress_size_limit": 8388608,
    "override_source": null
  }
}
EOF
)"
  [[ -n "$IID" && "$IID" != null ]] && { ok "input GELF UDP cree ($IID)"; sleep 3; } || die "creation input GELF UDP"
else skip "input GELF UDP existe ($IID)"; fi

# ------------------------------------------------------- [1] index set + stream
echo "==> [1/5] Index set 'omni-cert' + stream 'OMNI - Cert Orchestrator'"
# 90 j (etait 12 : incoherent avec la politique de retention, corrige 02/07/2026
# apres audit — la retention live a ete alignee par PUT le meme jour).
IDX_CERT="$(ensure_index_set 'omni-cert' 'OMNI - Cert Orchestrator' 90)"
if [[ -z "$(get_stream_id 'OMNI - Cert Orchestrator')" ]]; then
  jq -n --arg idx "$IDX_CERT" --arg in "$IID" '{title:"OMNI - Cert Orchestrator",description:"Renouvellements/demandes de certificats OVH (BX-IT-CERT-VM, GELF UDP 12201)",matching_type:"AND",remove_matches_from_default_stream:true,index_set_id:$idx,
    rules:[{field:"gl2_source_input",type:1,value:$in,inverted:false}]}' \
    | post_entity "/streams" | jqr '.stream_id // .id' | { read SID; [[ -n "$SID" && "$SID" != null ]] && { "${CURL[@]}" -X POST "${API}/streams/${SID}/resume" >/dev/null 2>&1; ok "stream cree ($SID)"; } || warn "stream refuse"; }
else skip "stream 'OMNI - Cert Orchestrator' existe"; fi
ST_CERT="$(get_stream_id 'OMNI - Cert Orchestrator')"
reassign_stream_idx "$ST_CERT" "$IDX_CERT"

# --------------------------------------------------------------- [2] pipeline
echo "==> [2/5] Pipeline 'OMNI - Cert Orchestrator' (tag + severite + erreurs)"

# Tag de source GARANTI : tout message du stream provient de l'input cert.
# On normalise event_source=cert_parc (override) pour que watchdog/console le
# voient quelle que soit la payload emise par l'application.
ensure_rule "omni-cert-00-tag" <<'EOF'
rule "omni-cert-00-tag"
when
  has_field("source")
then
  set_field("event_source", "cert_parc");
  set_field("event_category", "pki");
  set_field("host", to_string($message.source));
end
EOF

# Severite depuis le niveau GELF/syslog STRUCTURE (0-7) - signal fiable, pas de
# mot-cle devine. Le langage de pipeline n'a pas de ternaire -> 3 regles par
# bande. <=3 (error/crit/alert/emerg)=eleve, 4 (warning)=moyen, >=5=info.
ensure_rule "omni-cert-05-sev-eleve" <<'EOF'
rule "omni-cert-05-sev-eleve"
when
  to_string($message.event_source) == "cert_parc" AND has_field("level") AND to_long($message.level, 6) <= 3
then
  set_field("risk_severity", "eleve");
end
EOF
ensure_rule "omni-cert-05-sev-moyen" <<'EOF'
rule "omni-cert-05-sev-moyen"
when
  to_string($message.event_source) == "cert_parc" AND to_long($message.level, 6) == 4
then
  set_field("risk_severity", "moyen");
end
EOF
ensure_rule "omni-cert-05-sev-info" <<'EOF'
rule "omni-cert-05-sev-info"
when
  to_string($message.event_source) == "cert_parc" AND to_long($message.level, 6) >= 5
then
  set_field("risk_severity", "info");
end
EOF

# Remontee des erreurs de l'orchestrateur (niveau error+). Echec de
# renouvellement/demande = risque de disponibilite (cert expire -> service KO).
ensure_rule "omni-cert-10-error" <<'EOF'
rule "omni-cert-10-error"
when
  to_string($message.event_source) == "cert_parc" AND has_field("level") AND to_long($message.level, 6) <= 3
then
  set_field("alert_tag", "cert_orchestrator_error");
  set_field("event_action", "erreur_orchestrateur_certificats");
  set_field("risk_severity", "eleve");
end
EOF

PL="$(ensure_pipeline "OMNI - Cert Orchestrator" <<'PIPE'
pipeline "OMNI - Cert Orchestrator"
stage 0 match either
rule "omni-cert-00-tag"
stage 5 match either
rule "omni-cert-05-sev-eleve"
rule "omni-cert-05-sev-moyen"
rule "omni-cert-05-sev-info"
stage 10 match either
rule "omni-cert-10-error"
end
PIPE
)"
[[ -n "$ST_CERT" ]] && connect_pipeline "$ST_CERT" "$PL"

# ------------------------------------------------------------------ [3] alerte
echo "==> [3/5] Alerte 'Orchestrateur de certificats en erreur' (mail IT + Teams)"
# Signal STRUCTURE (niveau GELF <=3 -> alert_tag) : robuste au vocabulaire de
# l'app. Groupe par host, fenetre 10 min, grace 1 h (un echec persistant qui se
# re-loggue ne re-alerte pas en boucle). Un cert non renouvele = risque d'expiration.
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '(if $m=="" or $m=="null" then [] else [{notification_id:$m,notification_parameters:null}] end)+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
T_ALERT="OMNI - Orchestrateur de certificats en erreur"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "$T_ALERT" '.event_definitions[]|select(.title==$t)' >/dev/null; then
  skip "alerte '$T_ALERT' existe"
else
  jq -n --arg t "$T_ALERT" --arg st "$ST_CERT" --argjson n "$NF" \
    '{title:$t,description:"99-cert-orchestrator.sh - echec renouvellement/demande certificat (niveau error+)",priority:2,alert:true,
      config:{type:"aggregation-v1",query:"alert_tag:cert_orchestrator_error",query_parameters:[],streams:[$st],group_by:["host"],
        series:[{id:"count()",type:"count"}],
        conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
        search_within_ms:600000,execute_every_ms:600000,use_cron_scheduling:false,event_limit:50},
      field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T_ALERT' creee" || warn "alerte '$T_ALERT' KO"
fi

# ----------------------------------------------------------------- [4] resume
echo "==> [4/5] Recapitulatif"
ok "input=${IID}  stream=${ST_CERT:-?}  index_set=${IDX_CERT:-?}  pipeline=${PL:-?}"
echo "    Source 'cert_parc' surveillee par le watchdog (74, seuil 2880 min)."
echo "    Detections fines (echec OVH, expiration, CN) : a ajouter sur echantillon reel."
echo "==> [5/5] Termine."
