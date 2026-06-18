#!/usr/bin/env bash
# ==============================================================================
# 13-graylog-alerts.sh - Alerting Graylog
#   1. SMTP dans server.conf (relais interne, cf. 00-vars.env) + restart si besoin
#   2. Notification e-mail "OMNI - Mail equipe IT" -> ALERT_EMAIL
#   3. Definitions d'evenements (les requetes s'appuient sur les champs
#      normalises par 12-graylog-pipelines.sh : user, src_ip, alert_tag...) :
#        P3 = critique (action immediate), P2 = a examiner, P1 = info
#
# Idempotent (par titre). Prerequis : 10 + 11 + 12. Suite : 14-graylog-dashboards.sh
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

GL_CONF="/etc/graylog/server/server.conf"

# ------------------------------------------------------------------- 1. SMTP
echo "==> [1/3] SMTP (${SMTP_RELAY}:${SMTP_PORT})"
if grep -q '^transport_email_enabled = true' "${GL_CONF}"; then
  skip "SMTP deja configure dans server.conf"
else
  sed -i '/^transport_email_/d' "${GL_CONF}"
  cat >> "${GL_CONF}" <<EOF

# --- SMTP (provisionne par 13-graylog-alerts.sh) ---
transport_email_enabled = true
transport_email_hostname = ${SMTP_RELAY}
transport_email_port = ${SMTP_PORT}
transport_email_use_auth = false
transport_email_use_tls = false
transport_email_use_ssl = false
transport_email_from_email = ${SMTP_FROM}
transport_email_subject_prefix = [SIEM OMNI]
transport_email_web_interface_url = https://${SIEM_FQDN}
EOF
  ok "SMTP ajoute -> redemarrage graylog-server"
  systemctl restart graylog-server
  for i in $(seq 1 60); do
    api_get "/system" | jq -e '.version' >/dev/null 2>&1 && break
    sleep 5
  done
  require_api
  ok "API de nouveau disponible"
fi

# ----------------------------------------------------------- 2. Notification
echo "==> [2/3] Notification e-mail -> ${ALERT_EMAIL}"
NOTIF_TITLE="OMNI - Mail equipe IT"

# Gabarit texte (clients mail sans HTML) - syntaxe JMTE de Graylog
BODY_TXT="$(cat <<'EOF'
=== ALERTE SIEM OMNITECH ===
Alerte       : ${event_definition_title}
Contexte     : ${event_definition_description}
Priorité     : ${event.priority}  (1=info | 2=haute | 3=critique)
Quand        : ${event.timestamp} (UTC)
Déclencheur  : ${event.message}
Entité       : ${event.key}
Recherche    : https://bx-it-graylog-vm.omnitech.security/search?q=${event.replay_info.query}&rangetype=absolute&from=${event.replay_info.timerange_start}&to=${event.replay_info.timerange_end}
${if backlog}
--- Messages concernés (max 5) ---
${foreach backlog message}
* ${message.timestamp} | hôte=${if message.fields.host}${message.fields.host}${else}${message.source}${end} | user=${if message.fields.user}${message.fields.user}${else}${message.fields.upn}${end} | src_ip=${if message.fields.src_ip}${message.fields.src_ip}${else}${if message.fields.entity_host}${message.fields.entity_host}${else}${message.fields.dest_ip}${end}${end} | action=${if message.fields.event_action}${message.fields.event_action}${else}${message.fields.alert_tag}${end} | tag=${message.fields.alert_tag}${if message.fields.event_id} | EventID=${message.fields.event_id}${end}${if message.fields.failure_reason} | cause=${message.fields.failure_reason}${end}${if message.fields.mitre_technique_name} | ATT&CK=${message.fields.mitre_tactic}/${message.fields.mitre_technique_name} (${message.fields.mitre_technique})${end}${if message.fields.risk_score} | risque=${message.fields.risk_score}/10${end}
  brut: ${message.message}
${if message.fields.alert_explain}  → ${message.fields.alert_explain}
${end}${if message.fields.alert_remediation}  ➜ À FAIRE : ${message.fields.alert_remediation}
${end}${if message.fields.eset_severity}  [ESET] cible=${message.fields.eset_target} | action=${message.fields.eset_action} (${message.fields.eset_severity}) sur ${message.fields.eset_hostname}
  Detail: ${message.fields.eset_detail} | Remediation: isoler ${message.fields.eset_hostname}, scan complet ESET.
${end}${if message.fields.waf_vhost}  [WAF] ${message.fields.waf_vhost} ${message.fields.http_method} ${message.fields.http_url} -> ${message.fields.http_status} (ua ${message.fields.http_user_agent})
  Remediation: si exploit confirme, bloquer ${message.fields.src_ip} (SOAR /block), inspecter les logs de ${message.fields.waf_vhost}.
${end}${if message.fields.cert_days}  [CERT] "${message.fields.cert_subject}" expire dans ${message.fields.cert_days} jours (le ${message.fields.cert_expiry}) | store=${message.fields.cert_store} | machine=${message.fields.cert_machine}
  Remediation: renouveler / re-enroller ce certificat via AD CS avant expiration.
${end}${if message.fields.dest_port}  [RÉSEAU] ${message.fields.src_ip}${if message.fields.src_hostname} (${message.fields.src_hostname})${end} -> ${message.fields.dest_ip}:${message.fields.dest_port} ${message.fields.service} | ${message.fields.action} | ${message.fields.net_direction} | pays src ${message.fields.src_country}
${end}${if message.fields.process_name}  [ENDPOINT] proc=${message.fields.process_name} (parent ${message.fields.parent_process})
     cmd: ${message.fields.command_line}
${end}${if message.fields.logon_type_label}  [IDENTITÉ] ouverture=${message.fields.logon_type_label} | compte cible=${message.fields.winlogbeat_winlog_event_data_TargetUserName}
${end}${if message.fields.m365_type}  [M365] ${message.fields.upn} | ${message.fields.m365_type} | pays ${message.fields.src_country}
${end}${if message.fields.vuln_product}  [VULN] ${message.fields.vuln_product} | CVSS ${message.fields.vuln_cvss}${if message.fields.vuln_ransomware} | KEV/ransomware (URGENT)${end}
${end}
${end}
${end}
-- Notification automatique Graylog / OMNITECH Security. Anti-tempete : 5 messages max par alerte.
EOF
)"

# Gabarit HTML (CSS inline = compatibilite Outlook/webmail)
BODY_HTML="$(cat <<'EOF'
<!doctype html><html><body style="margin:0;padding:0;background:#eef1f4">
<div style="max-width:780px;margin:16px auto;font-family:'Segoe UI',Arial,sans-serif;background:#ffffff;border:1px solid #dde3ea;border-radius:8px;overflow:hidden">
  <div style="background:#1c2333;padding:16px 22px;border-bottom:4px solid #d6336c">
    <div style="font-size:11px;letter-spacing:2px;color:#8ea2c9;text-transform:uppercase">SIEM OMNITECH - Alerte sécurité</div>
    <div style="font-size:19px;font-weight:600;color:#ffffff;margin-top:3px">${event_definition_title}</div>
  </div>
  <div style="padding:18px 22px">
    <table style="border-collapse:collapse;font-size:13px;color:#212529">
      <tr><td style="padding:3px 16px 3px 0;color:#868e96;vertical-align:top">Priorité</td><td><b>${event.priority}</b> <span style="color:#adb5bd">(1=info 2=haute 3=critique)</span></td></tr>
      <tr><td style="padding:3px 16px 3px 0;color:#868e96;vertical-align:top">Contexte</td><td>${event_definition_description}</td></tr>
      <tr><td style="padding:3px 16px 3px 0;color:#868e96;vertical-align:top">Quand</td><td>${event.timestamp} (UTC)</td></tr>
      <tr><td style="padding:3px 16px 3px 0;color:#868e96;vertical-align:top">Déclencheur</td><td>${event.message}</td></tr>
      ${if event.key}<tr><td style="padding:3px 16px 3px 0;color:#868e96;vertical-align:top">Entité</td><td><b>${event.key}</b></td></tr>${end}
    </table>
    <div style="margin-top:12px"><a href="https://bx-it-graylog-vm.omnitech.security/search?q=${event.replay_info.query}&rangetype=absolute&from=${event.replay_info.timerange_start}&to=${event.replay_info.timerange_end}" style="display:inline-block;background:#1971c2;color:#fff;text-decoration:none;font-size:13px;padding:8px 16px;border-radius:5px">Ouvrir dans Graylog</a></div>
    ${if backlog}
    <div style="margin-top:16px;font-size:11px;color:#868e96;text-transform:uppercase;letter-spacing:1px">Messages concernés (max 5)</div>
    <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:6px">
      <tr style="background:#f8f9fa;color:#495057;text-align:left">
        <th style="padding:6px 8px;border-bottom:2px solid #dde3ea">Quand</th>
        <th style="padding:6px 8px;border-bottom:2px solid #dde3ea">Hôte</th>
        <th style="padding:6px 8px;border-bottom:2px solid #dde3ea">Utilisateur</th>
        <th style="padding:6px 8px;border-bottom:2px solid #dde3ea">IP source</th>
        <th style="padding:6px 8px;border-bottom:2px solid #dde3ea">Action</th>
        <th style="padding:6px 8px;border-bottom:2px solid #dde3ea">Tag</th>
      </tr>
      ${foreach backlog message}
      <tr>
        <td style="padding:6px 8px;white-space:nowrap;color:#495057">${message.timestamp}</td>
        <td style="padding:6px 8px"><b>${if message.fields.host}${message.fields.host}${else}${message.source}${end}</b></td>
        <td style="padding:6px 8px">${if message.fields.user}${message.fields.user}${else}${message.fields.upn}${end}</td>
        <td style="padding:6px 8px">${if message.fields.src_ip}${message.fields.src_ip}${else}${if message.fields.entity_host}${message.fields.entity_host}${else}${message.fields.dest_ip}${end}${end}</td>
        <td style="padding:6px 8px;color:#c2255c">${if message.fields.event_action}${message.fields.event_action}${else}${message.fields.alert_tag}${end}</td>
        <td style="padding:6px 8px;color:#e8590c">${message.fields.alert_tag}</td>
      </tr>
      <tr><td colspan="6" style="padding:2px 8px 7px;color:#868e96;font-size:11px;border-bottom:1px solid #eef1f4;word-break:break-all">${message.message}</td></tr>
      ${if message.fields.failure_reason}<tr><td colspan="6" style="padding:3px 8px;background:#fff9db;color:#7a5200;font-size:11.5px">&#9888; Cause de l'échec : <b>${message.fields.failure_reason}</b>${if message.fields.event_id} &mdash; EventID ${message.fields.event_id}${end}</td></tr>${end}
      ${if message.fields.mitre_technique_name}<tr><td colspan="6" style="padding:3px 8px;background:#edf2ff;color:#364fc7;font-size:11.5px">&#127919; ATT&amp;CK : ${message.fields.mitre_tactic} / <b>${message.fields.mitre_technique_name}</b> (${message.fields.mitre_technique})${if message.fields.risk_score} &mdash; risque <b>${message.fields.risk_score}/10</b>${end}</td></tr>${end}
      ${if message.fields.alert_explain}<tr><td colspan="6" style="padding:3px 8px;background:#f1f3f5;color:#343a40;font-size:11.5px">&#128161; ${message.fields.alert_explain}</td></tr>${end}
      ${if message.fields.alert_remediation}<tr><td colspan="6" style="padding:3px 8px;background:#ebfbee;color:#2b8a3e;font-size:11.5px">&#10145; <b>À faire :</b> ${message.fields.alert_remediation}</td></tr>${end}
      ${if message.fields.eset_severity}<tr><td colspan="6" style="padding:4px 8px;background:#fff5f5;color:#862e2e;font-size:11.5px">ESET : cible <b>${message.fields.eset_target}</b> &mdash; action ${message.fields.eset_action} (${message.fields.eset_severity}) sur <b>${message.fields.eset_hostname}</b> &mdash; ${message.fields.eset_detail}. Remédiation : isoler le poste + scan complet.</td></tr>${end}
      ${if message.fields.waf_vhost}<tr><td colspan="6" style="padding:4px 8px;background:#fff9db;color:#7a5200;font-size:11.5px">WAF : ${message.fields.waf_vhost} ${message.fields.http_method} ${message.fields.http_url} -&gt; <b>${message.fields.http_status}</b> &mdash; ua ${message.fields.http_user_agent}. Remédiation : si exploit, bloquer l'IP (SOAR) + inspecter le vhost.</td></tr>${end}
      ${if message.fields.cert_days}<tr><td colspan="6" style="padding:4px 8px;background:#e7f5ff;color:#1864ab;font-size:11.5px">CERT : <b>${message.fields.cert_subject}</b> expire dans <b>${message.fields.cert_days} j</b> (le ${message.fields.cert_expiry}) &mdash; store ${message.fields.cert_store} sur ${message.fields.cert_machine}. Remédiation : renouveler / re-enroller via AD CS avant expiration.</td></tr>${end}
      ${if message.fields.dest_port}<tr><td colspan="6" style="padding:4px 8px;background:#e6fcf5;color:#0b7285;font-size:11.5px">RÉSEAU : ${message.fields.src_ip}${if message.fields.src_hostname} (<b>${message.fields.src_hostname}</b>)${end} &rarr; <b>${message.fields.dest_ip}:${message.fields.dest_port}</b> ${message.fields.service} &mdash; ${message.fields.action} &mdash; ${message.fields.net_direction} &mdash; pays src ${message.fields.src_country}</td></tr>${end}
      ${if message.fields.process_name}<tr><td colspan="6" style="padding:4px 8px;background:#f3f0ff;color:#5f3dc4;font-size:11.5px">ENDPOINT : proc <b>${message.fields.process_name}</b> (parent ${message.fields.parent_process}) &mdash; cmd <code>${message.fields.command_line}</code></td></tr>${end}
      ${if message.fields.logon_type_label}<tr><td colspan="6" style="padding:4px 8px;background:#fff4e6;color:#9c4221;font-size:11.5px">IDENTITÉ : ouverture <b>${message.fields.logon_type_label}</b> &mdash; compte cible ${message.fields.winlogbeat_winlog_event_data_TargetUserName}</td></tr>${end}
      ${if message.fields.m365_type}<tr><td colspan="6" style="padding:4px 8px;background:#e7f5ff;color:#1864ab;font-size:11.5px">M365 : <b>${message.fields.upn}</b> &mdash; ${message.fields.m365_type} &mdash; pays ${message.fields.src_country}</td></tr>${end}
      ${if message.fields.vuln_product}<tr><td colspan="6" style="padding:4px 8px;background:#fff5f5;color:#862e2e;font-size:11.5px">VULN : <b>${message.fields.vuln_product}</b> &mdash; CVSS ${message.fields.vuln_cvss}${if message.fields.vuln_ransomware} &mdash; <b>KEV/ransomware (URGENT)</b>${end}</td></tr>${end}
      ${end}
    </table>
    ${end}
  </div>
  <div style="background:#f8f9fa;color:#adb5bd;font-size:11px;padding:10px 22px">Notification automatique Graylog - OMNITECH Security. Anti-tempete actif : notifications espacées par alerte, 5 messages affiches max.</div>
</div></body></html>
EOF
)"

NOTIF_BODY="$(jq -n --arg t "${NOTIF_TITLE}" --arg from "${SMTP_FROM}" --arg to "${ALERT_EMAIL}" \
                   --arg txt "${BODY_TXT}" --arg html "${BODY_HTML}" '{
  title: $t,
  description: "Notification e-mail equipe informatique (provisionne par 13-graylog-alerts.sh)",
  config: {
    type: "email-notification-v1",
    sender: $from,
    reply_to: "",
    subject: "[SIEM] ${event_definition_title}",
    body_template: $txt,
    html_body_template: $html,
    email_recipients: [$to],
    user_recipients: [],
    time_zone: "Europe/Paris",
    lookup_recipient_emails: false,
    recipients_lut_name: null,
    recipients_lut_key: null,
    lookup_sender_email: false,
    sender_lut_name: null,
    sender_lut_key: null,
    lookup_reply_to_email: false,
    reply_to_lut_name: null,
    reply_to_lut_key: null,
    single_email: false
  }
}')"

NOTIF_ID="$(api_get "/events/notifications?per_page=100" | jq -r --arg t "${NOTIF_TITLE}" '(.notifications // [])[] | select(.title==$t) | .id')"
if [[ -z "${NOTIF_ID}" ]]; then
  NOTIF_ID="$(echo "${NOTIF_BODY}" | post_entity "/events/notifications" | jqr '.id')"
  [[ -n "${NOTIF_ID}" && "${NOTIF_ID}" != "null" ]] && ok "notification creee (${NOTIF_ID})" || die "creation notification"
else
  echo "${NOTIF_BODY}" | jq --arg i "${NOTIF_ID}" '. + {id: $i}' \
    | api_put "/events/notifications/${NOTIF_ID}" >/dev/null \
    && ok "notification mise a jour (gabarits texte+HTML) (${NOTIF_ID})" \
    || warn "mise a jour notification refusee"
fi

# ------------------------------------------------ 2bis. Notification Teams
TEAMS_ID=""
if [[ -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
  echo "==> [2bis] Notification Teams (canal SOC)"
  TEAMS_TITLE="OMNI - Teams SOC"
  TEAMS_ID="$(api_get "/events/notifications?per_page=100" | jq -r --arg t "${TEAMS_TITLE}" '(.notifications // [])[] | select(.title==$t) | .id')"
  # Carte adaptive ENVELOPPEE {"type":"message","attachments":[...]} : exige par
  # le workflow Power Automate "webhook recu -> publier dans un canal"
  # (le gabarit par defaut de Graylog poste la carte nue -> rien n'apparait).
  CARD="$(cat <<'EOF'
{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "contentUrl": null,
    "content": {
      "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
      "type": "AdaptiveCard", "version": "1.4",
      "msteams": {"width": "Full"},
      "body": [
        {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "color": "Attention",
         "text": "SIEM OMNITECH - ${event_definition_title}"},
        {"type": "FactSet", "facts": [
          {"title": "Priorité", "value": "${event.priority} (1=info 2=haute 3=critique)"},
          {"title": "Contexte", "value": "${event_definition_description}"},
          {"title": "Quand", "value": "${event.timestamp} (UTC)"},
          {"title": "Déclencheur", "value": "${event.message}"},
          {"title": "Entité", "value": "${event.key}"}
        ]},
        {"type": "TextBlock", "wrap": true, "isSubtle": true, "spacing": "Medium",
         "text": "${if backlog}${foreach backlog message}- ${message.timestamp} | ${message.fields.host} | ${message.fields.user} | ${message.fields.src_ip} | ${message.fields.event_action} | ${message.fields.alert_tag}${if message.fields.failure_reason} | cause:${message.fields.failure_reason}${end}${if message.fields.mitre_technique_name} | ATT&CK:${message.fields.mitre_tactic}/${message.fields.mitre_technique_name}${end}${if message.fields.risk_score} | risque:${message.fields.risk_score}/10${end}${if message.fields.alert_remediation} | a faire:${message.fields.alert_remediation}${end}${if message.fields.eset_severity} | ESET:${message.fields.eset_target}/${message.fields.eset_action}(${message.fields.eset_severity}) sur ${message.fields.eset_hostname}${end}${if message.fields.waf_vhost} | WAF:${message.fields.waf_vhost} ${message.fields.http_method} ${message.fields.http_url} ${message.fields.http_status}${end}${if message.fields.cert_days} | CERT:${message.fields.cert_subject} exp ${message.fields.cert_days}j (${message.fields.cert_expiry})${end}${if message.fields.dest_port} | NET:${message.fields.src_ip}-${message.fields.dest_ip}:${message.fields.dest_port} ${message.fields.action}${end}${if message.fields.process_name} | PROC:${message.fields.process_name}${end}${if message.fields.logon_type_label} | LOGON:${message.fields.logon_type_label}${end}${if message.fields.m365_type} | M365:${message.fields.upn}${end}${if message.fields.vuln_product} | VULN:${message.fields.vuln_product} CVSS${message.fields.vuln_cvss}${end}\n${end}${end}"},
        {"type": "ActionSet", "actions": [{"type": "Action.OpenUrl", "title": "Ouvrir dans Graylog", "url": "https://bx-it-graylog-vm.omnitech.security/search?q=${event.replay_info.query}&rangetype=absolute&from=${event.replay_info.timerange_start}&to=${event.replay_info.timerange_end}"}]}
      ]
    }
  }]
}
EOF
)"
  TEAMS_BODY="$(jq -n --arg t "${TEAMS_TITLE}" --arg u "${TEAMS_WEBHOOK_URL}" --arg c "${CARD}" '{
    title: $t,
    description: "Notification Teams via Workflows (provisionne par 13-graylog-alerts.sh)",
    config: { type: "teams-notification-v2", webhook_url: $u, backlog_size: 5, adaptive_card: $c }
  }')"
  if [[ -z "${TEAMS_ID}" ]]; then
    TEAMS_ID="$(echo "${TEAMS_BODY}" | post_entity "/events/notifications" | jqr '.id')"
    [[ -n "${TEAMS_ID}" && "${TEAMS_ID}" != "null" ]] && ok "notification Teams creee (${TEAMS_ID})" || warn "notification Teams refusee"
  else
    echo "${TEAMS_BODY}" | jq --arg i "${TEAMS_ID}" '. + {id:$i}' | api_put "/events/notifications/${TEAMS_ID}" >/dev/null \
      && ok "notification Teams mise a jour (${TEAMS_ID})"
  fi
else
  skip "TEAMS_WEBHOOK_URL vide -> pas de notification Teams (cf. 00-vars.env)"
fi

# ------------------------------------------------------- 3. Event definitions
echo "==> [3/3] Definitions d'evenements"
ST_WINSEC="$(get_stream_id 'OMNI - Windows Security')"
ST_SYSMON="$(get_stream_id 'OMNI - Sysmon')"
ST_WINOTH="$(get_stream_id 'OMNI - Windows autres')"
ST_FORTI="$(get_stream_id  'OMNI - FortiGate')"
ST_INT="$(get_stream_id 'OMNI - Interne SIEM' || true)"
ST_VAULT="$(get_stream_id 'OMNI - Vaultwarden' || true)"

# ensure_event <titre> <priorite 1-3> <query> <streams_json> <group_by_json> \
#              <series_json> <conditions_json> <within_min> <every_min> [grace_min]
# series/conditions vides => evenement "filtre" (chaque message correspond).
# grace_min (optionnel, defaut 10) : anti-tempete = delai mini entre 2 alertes du
#   meme groupe. A monter pour les conditions PERSISTANTES (ex. go-dark) qui se
#   re-declencheraient sinon a chaque cycle.
ensure_event() {
  local TITLE="$1" PRIO="$2" QUERY="$3" STREAMS="$4" GROUPBY="$5" SERIES="$6" COND="$7" WITHIN="$8" EVERY="$9"
  local GRACE="${10:-10}"
  local EXIST ID
  EXIST="$(api_get "/events/definitions?per_page=100" | jq -r --arg t "${TITLE}" '(.event_definitions // .elements // [])[] | select(.title==$t) | .id')"
  if [[ -n "${EXIST}" ]]; then skip "evenement '${TITLE}' existe"; return 0; fi
  ID="$(jq -n --arg t "${TITLE}" --argjson p "${PRIO}" --arg q "${QUERY}" \
        --argjson st "${STREAMS}" --argjson gb "${GROUPBY}" --argjson se "${SERIES}" \
        --argjson co "${COND}" --argjson w "$(( WITHIN * 60000 ))" --argjson e "$(( (EVERY < WITHIN ? WITHIN : EVERY) * 60000 ))" \
        --argjson g "$(( GRACE * 60000 ))" \
        --arg n "${NOTIF_ID}" '{
    title: $t,
    description: ("P" + ($p|tostring) + " - provisionne par 13-graylog-alerts.sh"),
    priority: $p,
    alert: true,
    config: {
      type: "aggregation-v1",
      query: $q,
      query_parameters: [],
      streams: $st,
      group_by: $gb,
      series: $se,
      conditions: $co,
      search_within_ms: $w,
      execute_every_ms: $e,
      use_cron_scheduling: false,
      event_limit: 100
    },
    field_spec: ($gb | map({key: ., value: {data_type: "string",
        providers: [{type: "template-v1", template: ("${source." + . + "}"),
                     require_values: false}]}}) | from_entries),
    key_spec: $gb,
    notification_settings: { grace_period_ms: $g, backlog_size: 5 },
    notifications: [ { notification_id: $n, notification_parameters: null } ]
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id')"
  [[ -n "${ID}" && "${ID}" != "null" ]] && ok "evenement '${TITLE}'" || warn "evenement '${TITLE}' REFUSE"
}

NOCOND='{"expression":null}'
count_ge() { echo "{\"expression\":{\"expr\":\">=\",\"left\":{\"expr\":\"number-ref\",\"ref\":\"count()\"},\"right\":{\"expr\":\"number\",\"value\":$1}}}"; }
count_lt() { echo "{\"expression\":{\"expr\":\"<\",\"left\":{\"expr\":\"number-ref\",\"ref\":\"count()\"},\"right\":{\"expr\":\"number\",\"value\":$1}}}"; }
card_ge()  { echo "{\"expression\":{\"expr\":\">=\",\"left\":{\"expr\":\"number-ref\",\"ref\":\"card($1)\"},\"right\":{\"expr\":\"number\",\"value\":$2}}}"; }
COUNT_SERIES='[{"id":"count()","type":"count"}]'
card_series() { echo "[{\"id\":\"card($1)\",\"type\":\"card\",\"field\":\"$1\"}]"; }
max_series()  { echo "[{\"id\":\"max($1)\",\"type\":\"max\",\"field\":\"$1\"}]"; }
max_ge() { echo "{\"expression\":{\"expr\":\">=\",\"left\":{\"expr\":\"number-ref\",\"ref\":\"max($1)\"},\"right\":{\"expr\":\"number\",\"value\":$2}}}"; }

# --- P3 : critiques -----------------------------------------------------------
ensure_event "OMNI - Sabotage de l'audit (1102/4719/4794/104)" 3 \
  'alert_tag:winsec_critique' "[\"${ST_WINSEC}\",\"${ST_WINOTH}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

# --- Detections critiques jusque-la NON alertees (audit multi-agent 2026-06-14) :
# le tag etait pose par le pipeline et affiche au dashboard, mais AUCUNE definition
# ne le declenchait -> angle mort. Mail = seul l'abus du coffre (attaque active,
# "reveille-moi") ; KEV + exposition = Teams + rapport quotidien (etat a traiter,
# pas intrusion en cours) pour respecter la politique anti-spam mail.
# Brute force REEL du coffre = echecs d'auth (avec src_ip + compte), PAS le tag
# vault_admin_abuse (= rate-limit "Too many admin requests", sans src_ip, sature
# par le conteneur en boucle -> spam mail). vault_admin_abuse reste au dashboard.
[[ -n "${ST_VAULT}" ]] && ensure_event "OMNI - Brute force coffre Vaultwarden (>=10 échecs / IP / 15 min)" 3 \
  'alert_tag:vault_auth_fail' "[\"${ST_VAULT}\"]" \
  '["src_ip","vault_user"]' "${COUNT_SERIES}" "$(count_ge 10)" 15 5 60
[[ -n "${ST_INT}" ]] && ensure_event "OMNI - Vulnérabilité KEV exploitée (à patcher en urgence)" 3 \
  'alert_tag:vuln_kev' "[\"${ST_INT}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 1440 360 1440
ensure_event "OMNI - Service exposé sur Internet (port à risque)" 3 \
  'alert_tag:exposition_internet' "[\"${ST_FORTI}\"]" \
  '["host","dest_port"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 30 720

# Privilege Escalation (tactique comblée par 47) : UAC bypass = critique (mail),
# service install = surveillance (Teams). Tache planifiée déjà couverte par l'alerte 4698.
ensure_event "OMNI - Contournement UAC (élévation de privilèges)" 3 \
  'alert_tag:uac_bypass' "[\"${ST_SYSMON}\"]" \
  '["host","user"]' "${COUNT_SERIES}" "$(count_ge 1)" 15 5 30
ensure_event "OMNI - Service Windows installé (hors svchost)" 2 \
  'alert_tag:service_install' "[\"${ST_WINSEC}\",\"${ST_WINOTH}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 15 60

# Audit fichiers sensibles (59) : acces de MASSE = exfiltration ; suppressions de
# masse = ransomware. Seuils volontairement hauts (les acces unitaires legitimes
# ne declenchent pas). Mail (vol/destruction de donnees = on te reveille).
ensure_event "OMNI - Accès massif à des fichiers sensibles (exfiltration?)" 3 \
  'alert_tag:file_sensitive_access' "[\"${ST_WINSEC}\",\"${ST_WINOTH}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 200)" 10 5 30
ensure_event "OMNI - Suppressions massives de fichiers (ransomware?)" 3 \
  'alert_tag:file_delete_sensible' "[\"${ST_WINSEC}\",\"${ST_WINOTH}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 30)" 10 5 20

# Integrite des logs : la chaine de hachage signee est rompue (suppression/
# alteration retroactive detectee par omni-integrity --verify). Critique -> mail.
[[ -n "${ST_INT}" ]] && ensure_event "OMNI - Intégrité des logs COMPROMISE (chaîne rompue)" 3 \
  'event_source:siem_integrity AND integrity_state:compromis' "[\"${ST_INT}\"]" \
  '[]' '[]' "${NOCOND}" 60 30

# Exclusions anti-faux-positifs : comptes machine (*$) + comptes de service
# bruyants (ninjaone, ADSyncMSA) qui echouent en boucle = bruit, PAS du brute-force.
ensure_event "OMNI - Force brute (>=10 échecs / compte / 10 min)" 3 \
  'event_id:4625 AND logon_fail:1 AND NOT user:*$ AND NOT user:ninjaone AND NOT user:ADSyncMSA_*' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 10)" 10 2

ensure_event "OMNI - Password spraying (>=8 comptes / IP / 10 min)" 3 \
  'event_id:4625 AND _exists_:src_ip AND NOT user:*$' "[\"${ST_WINSEC}\"]" \
  '["src_ip"]' "$(card_series user)" "$(card_ge user 8)" 10 2

ensure_event "OMNI - Modification d'un groupe privilégié" 3 \
  '_exists_:priv_group_label' "[\"${ST_WINSEC}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - DCSync suspect" 3 \
  'alert_tag:dcsync' "[\"${ST_WINSEC}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - Kerberoasting suspect (>=5 SPN / compte / 10 min)" 3 \
  'alert_tag:kerberoasting' "[\"${ST_WINSEC}\"]" \
  '["user"]' "$(card_series winlogbeat_winlog_event_data_ServiceName)" \
  "$(card_ge winlogbeat_winlog_event_data_ServiceName 5)" 10 2

ensure_event "OMNI - Defender : détection ou désactivation" 3 \
  'alert_tag:defender' "[\"${ST_WINOTH}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - FortiGate : virus / IPS" 3 \
  'alert_tag:fortigate_utm' "[\"${ST_FORTI}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - Silence Winlogbeat (0 log Windows / 15 min)" 3 \
  '' "[\"${ST_WINSEC}\"]" \
  '[]' "${COUNT_SERIES}" "$(count_lt 1)" 15 5

# Go-dark : un hote GERE cesse d'emettre (>26h). Pose par omni-collect-health
# (event_source=collecte_sla, sla_type=go_dark) -> stream interne. P2 = angle mort
# (panne, agent arrete... ou compromission silencieuse). Anti-tempete 6h car la
# condition PERSISTE tant que l'hote reste muet (sinon re-alerte chaque heure).
if [[ -n "${ST_INT}" ]]; then
  ensure_event "OMNI - Hôte go-dark (collecte interrompue >26h)" 2 \
    'sla_type:go_dark' "[\"${ST_INT}\"]" \
    '["dark_host"]' "${COUNT_SERIES}" "$(count_ge 1)" 90 60 360

  # --- UEBA / NDR (analytique comportementale, collecteurs 40-ueba-ndr.sh) ----
  # Impossible travel : compte connecte depuis 2 lieux inconciliables -> P3.
  ensure_event "OMNI - Impossible travel (compte multi-localisé)" 3 \
    'event_source:ueba_geo AND alert_tag:impossible_travel' "[\"${ST_INT}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 30
  # Beaconing / C2 : flux externe a intervalle regulier -> P2 (a trier).
  ensure_event "OMNI - Beaconing / C2 suspect (NDR)" 2 \
    'event_source:ndr_beacon AND alert_tag:beaconing' "[\"${ST_INT}\"]" \
    '["dest_ip"]' "${COUNT_SERIES}" "$(count_ge 1)" 420 360
  # Anomalie de volume (z-score) : pic/chute statistique -> P3 (bruite en rodage).
  ensure_event "OMNI - Anomalie de volume (z-score)" 3 \
    'event_source:ueba_volume' "[\"${ST_INT}\"]" \
    '["anomaly_entity"]' "${COUNT_SERIES}" "$(count_ge 1)" 90 60
  # Score UEBA tres eleve : entite a traiter en priorite -> P2 (seuil 80/100).
  ensure_event "OMNI - Entité à risque UEBA élevé (>=80)" 2 \
    'event_source:ueba_score' "[\"${ST_INT}\"]" \
    '["ueba_entity"]' "$(max_series ueba_score)" "$(max_ge ueba_score 80)" 60 30
  # Exfiltration / tunneling DNS : domaine a haute entropie -> P2 (a trier).
  ensure_event "OMNI - Tunneling DNS suspect (exfiltration)" 2 \
    'event_source:ndr_dns AND alert_tag:dns_tunneling' "[\"${ST_INT}\"]" \
    '["dns_domain"]' "${COUNT_SERIES}" "$(count_ge 1)" 120 60
  # Scan reseau interne : balayage horizontal/vertical depuis une source interne -> P2.
  ensure_event "OMNI - Scan réseau interne (reconnaissance / latéral)" 2 \
    'event_source:ndr_scan AND alert_tag:network_scan' "[\"${ST_INT}\"]" \
    '["entity_host"]' "${COUNT_SERIES}" "$(count_ge 1)" 90 30
  # Incident CRITIQUE : kill-chain multi-tactiques sur une entite -> P3.
  ensure_event "OMNI - Incident critique (kill-chain corrélée)" 3 \
    'event_source:incident AND incident_severity:critique' "[\"${ST_INT}\"]" \
    '["incident_entity"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 15
  # Auto-supervision : un robot d'analyse en panne = detection aveugle -> P3.
  ensure_event "OMNI - Robot d'analyse en panne (auto-supervision)" 3 \
    'event_source:siem_health AND alert_tag:siem_job_fail' "[\"${ST_INT}\"]" \
    '["health_job"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 30
else warn "stream interne absent -> alertes go-dark / UEBA-NDR non posees"; fi

# Correlation : >=10 echecs ET >=1 succes pour le MEME compte dans la fenetre
# (compteurs logon_fail/logon_ok poses par le pipeline ; l'ordre echecs->succes
#  n'est pas garanti par l'agregation, mais la coincidence est le signal).
BF_SUCCESS_SERIES='[{"id":"sum(logon_fail)","type":"sum","field":"logon_fail"},{"id":"sum(logon_ok)","type":"sum","field":"logon_ok"}]'
BF_SUCCESS_COND='{"expression":{"expr":"&&","left":{"expr":">=","left":{"expr":"number-ref","ref":"sum(logon_fail)"},"right":{"expr":"number","value":10}},"right":{"expr":">=","left":{"expr":"number-ref","ref":"sum(logon_ok)"},"right":{"expr":"number","value":1}}}}'
ensure_event "OMNI - Force brute SUIVIE d'un succès (même compte / 15 min)" 3 \
  '(event_id:4624 OR event_id:4625) AND NOT user:*$ AND NOT user:ninjaone AND NOT user:ADSyncMSA_*' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${BF_SUCCESS_SERIES}" "${BF_SUCCESS_COND}" 15 3

ensure_event "OMNI - Balayage de partages admin (>=3 hôtes / compte / 15 min)" 3 \
  'alert_tag:admin_share' "[\"${ST_WINSEC}\"]" \
  '["user"]' "$(card_series host)" "$(card_ge host 3)" 15 3

# Score de risque MITRE agrege : un hote qui CUMULE un score eleve sur 1h (seuil 30).
# Exclut event_source:fortigate : le pare-feu logue les attaques des AUTRES sous son
# propre nom d'hote (= capteur, pas une cible) -> sinon faux "hote a risque" sur les FG.
# (ex. LSASS=10 + PowerShell=5, ou plusieurs injections=9). risk_score est pose
# par 37-mitre-attack.sh. Capte un enchainement de detections sur un meme hote
# que les regles unitaires ne declenchent pas forcement.
ST_VS="$(get_stream_id 'OMNI - vSphere' || true)"
sum_ge() { echo "{\"expression\":{\"expr\":\">=\",\"left\":{\"expr\":\"number-ref\",\"ref\":\"sum($1)\"},\"right\":{\"expr\":\"number\",\"value\":$2}}}"; }
RISK_SERIES='[{"id":"sum(risk_score)","type":"sum","field":"risk_score"}]'
RISK_STREAMS="$(jq -n --arg a "$ST_WINSEC" --arg b "$ST_SYSMON" --arg c "$ST_WINOTH" --arg d "$ST_FORTI" --arg e "$ST_VS" \
  '[$a,$b,$c,$d,$e] | map(select(. != "" and . != null))')"
ensure_event "OMNI - Hôte à risque élevé (score MITRE cumulé / 1h)" 2 \
  '_exists_:risk_score AND NOT event_source:fortigate' "${RISK_STREAMS}" \
  '["host"]' "${RISK_SERIES}" "$(sum_ge risk_score 30)" 60 5

# Correlation on-prem <-> cloud : echecs AD + connexion M365 hors France pour
# le MEME compte (user = partie locale de l'UPN cote M365, sAMAccountName cote AD)
ST_M365="$(get_stream_id 'OMNI - M365' || true)"
if [[ -n "${ST_M365}" ]]; then
  XC_SERIES='[{"id":"sum(logon_fail)","type":"sum","field":"logon_fail"},{"id":"sum(m365_foreign)","type":"sum","field":"m365_foreign"}]'
  XC_COND='{"expression":{"expr":"&&","left":{"expr":">=","left":{"expr":"number-ref","ref":"sum(logon_fail)"},"right":{"expr":"number","value":5}},"right":{"expr":">=","left":{"expr":"number-ref","ref":"sum(m365_foreign)"},"right":{"expr":"number","value":1}}}}'
  ensure_event "OMNI - Échecs AD + connexion M365 étrangère (même compte / 1 h)" 3 \
    'event_id:4625 OR alert_tag:m365_etranger' "[\"${ST_WINSEC}\",\"${ST_M365}\"]" \
    '["user"]' "${XC_SERIES}" "${XC_COND}" 60 10
  # Brute-force / spraying M365 depuis l'etranger (donnee reelle : IP etrangeres
  # ciblant des comptes precis). Agrege par IP+compte, seuil 5 echecs/30 min. Teams.
  ensure_event "OMNI - Brute force M365 depuis l'étranger (spray cloud)" 2 \
    'alert_tag:m365_brute_externe' "[\"${ST_M365}\"]" \
    '["src_ip","upn"]' "${COUNT_SERIES}" "$(count_ge 5)" 30 10 30
  # Compte flagge "atRisk" par Entra ID Protection (ML Microsoft) = haute confiance,
  # potentielle compromission cloud -> mail. Agrege par compte (1 alerte/compte/6h).
  ensure_event "OMNI - Compte M365 à risque (Entra ID Protection)" 3 \
    'alert_tag:m365_risque' "[\"${ST_M365}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 120 30 360
fi

ensure_event "OMNI - Indicateur de ransomware (suppression shadow copies)" 3 \
  'alert_tag:ransomware_indicator' "[\"${ST_SYSMON}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - Accès mémoire LSASS (vol de credentials)" 2 \
  'alert_tag:lsass_access' "[\"${ST_SYSMON}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 10 5

# --- P2 : a examiner ----------------------------------------------------------
ensure_event "OMNI - Tentative sur compte désactivé" 2 \
  'failure_reason:compte_desactive' "[\"${ST_WINSEC}\"]" \
  '[]' '[]' "${NOCOND}" 10 5

ensure_event "OMNI - Compte verrouillé (4740)" 2 \
  'event_id:4740' "[\"${ST_WINSEC}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - Compte créé dans le domaine (4720)" 2 \
  'event_id:4720' "[\"${ST_WINSEC}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - Injection de processus (Sysmon 8/25)" 2 \
  'alert_tag:sysmon_injection' "[\"${ST_SYSMON}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

ensure_event "OMNI - PowerShell suspect" 2 \
  'alert_tag:powershell_suspect' "[\"${ST_SYSMON}\",\"${ST_WINOTH}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

# Agrege par hote+compte (au lieu d'1 event par tache) : coupe le filet Teams
# (~117/j de creations legitimes) sans perdre le signal. Utilise le tag
# scheduled_task (= 4698 hors comptes machine, pose par 47).
ensure_event "OMNI - Tâche planifiée créée (4698)" 2 \
  'alert_tag:scheduled_task' "[\"${ST_WINSEC}\"]" \
  '["host","user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 60 60

ensure_event "OMNI - Nouveau service installé (7045)" 2 \
  'channel:System AND event_id:7045 AND NOT winlogbeat_winlog_event_data_ServiceName:(winlogbeat OR Sysmon64 OR Sysmon)' "[\"${ST_WINOTH}\"]" \
  '[]' '[]' "${NOCOND}" 10 5

ensure_event "OMNI - Force brute portail VPN (>=30 échecs / IP / h)" 2 \
  'subtype:vpn AND action:ssl\-login\-fail' "[\"${ST_FORTI}\"]" \
  '["remip"]' "${COUNT_SERIES}" "$(count_ge 30)" 60 15

ensure_event "OMNI - IP malveillante (Tor / Spamhaus)" 3 \
  'alert_tag:threat_intel' "[\"${ST_FORTI}\"]" \
  '[]' '[]' "${NOCOND}" 5 1

# GeoIP s'execute APRES les pipelines -> detection par requete (pas par tag)
ensure_event "OMNI - VPN monté depuis l'étranger" 3 \
  'subtype:vpn AND (action:tunnel\-up OR action:ssl\-login) AND _exists_:remip_country_code AND NOT remip_country_code:FR' "[\"${ST_FORTI}\"]" \
  '[]' '[]' "${NOCOND}" 10 5

# --- Detections complementaires (47-detections-extra.sh) ---------------------
ensure_event "OMNI - Modification de GPO par un humain (5136)" 3 \
  'alert_tag:gpo_modification' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 10
ensure_event "OMNI - AS-REP roasting (compte sans pré-auth)" 3 \
  'alert_tag:asrep_roasting' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 5
ensure_event "OMNI - LOLBin suspect (binaire système détourné)" 2 \
  'alert_tag:lolbin_suspect' "[\"${ST_SYSMON}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 5
# NB : pas de notification dediee pour persistence_autorun (cle Run) : ~85/j dont
# beaucoup d'installeurs legitimes -> trop bruite. Le TAG reste (couleur + score
# MITRE T1547.001 -> alimente UEBA/incidents/Hunting), c'est la le bon niveau.
ST_M365="$(get_stream_id 'OMNI - M365' || true)"
if [[ -n "${ST_M365}" ]]; then
  ensure_event "OMNI - M365 consentement OAuth applicatif" 2 \
    'alert_tag:m365_oauth_consent' "[\"${ST_M365}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 15
  # Suppression massive de fichiers M365 (ransomware / exfil-and-wipe cloud) -> P2
  ensure_event "OMNI - M365 suppression massive de fichiers (>=100 / compte / 15 min)" 2 \
    'event_action:FileRecycled OR event_action:FileDeleted OR event_action:FileVersionsAllDeleted OR event_action:HardDelete' "[\"${ST_M365}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 100)" 15 5
fi


# ===== Alertes enrichissements lots 1+2 (conception multi-agent) =====
# === Enrichissement : Enrichissement OFF-HOURS (heures non ouvrees) sur  ===
# Alerte P3 : connexion REUSSIE d'un compte d'administration (adm-*) hors heures ouvrees.
# A placer dans 13-graylog-alerts.sh apres les ST_* (ST_WINSEC et ST_M365 deja definis ;
# ST_M365 garde par if -n comme dans le script). Cle = user -> grace par compte.
# off_hours=oui est pose par le pipeline d'enrichissement (49) AVANT le routage final.
# On vise 4624 (winsec) + signin reussi (m365). Backlog par compte, 1 notif / 60 min / compte.
if [[ -n "${ST_M365}" ]]; then
  ensure_event "OMNI - Connexion compte admin (adm-*) hors heures ouvrées" 3 \
    '(user:adm\-* OR user:ADM\-* OR user:*\\adm\-* OR user:*\\ADM\-*) AND off_hours:oui AND (event_id:4624 OR (m365_type:signin AND event_action:connexion_reussie))' \
    "[\"${ST_WINSEC}\",\"${ST_M365}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 60
else
  ensure_event "OMNI - Connexion compte admin (adm-*) hors heures ouvrées" 3 \
    '(user:adm\-* OR user:ADM\-* OR user:*\\adm\-* OR user:*\\ADM\-*) AND off_hours:oui AND event_id:4624' \
    "[\"${ST_WINSEC}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 60
fi

# === Enrichissement : Enrichissement MASQUERADING/LOLBIN avance (Sysmon  ===
# A ajouter dans 13-graylog-alerts.sh, section 'Detections complementaires'
# (apres le bloc LOLBin suspect). P2 : masquerading sur une source endpoint
# = forte presomption de compromission, mais pas systematiquement critique.
ensure_event "OMNI - Masquerading : binaire système déplacé ou renommé (T1036.005)" 2 \
  'alert_tag:masquerading' "[\"${ST_SYSMON}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 5

# === Enrichissement : Usage de credentials explicites (4648 - RunAs / mo ===
# --- P2 : usage de credentials explicites (RunAs / mouvement lateral) -----------
# 95-240/j apres restriction sujet non-machine -> P2, pas de page critique.
# Clef = source (explicit_cred_src) : un compte humain qui invoque des creds
# d'un grand nombre d'autres comptes en 30 min = signal de lateral / pivot.
# Seuil >=8 evts/source/30 min : au-dessus du RunAs admin ponctuel legitime.
ensure_event "OMNI - Usage de credentials explicites (RunAs / latéral)" 2 \
  'alert_tag:explicit_cred_use' "[\"${ST_WINSEC}\"]" \
  '["explicit_cred_src"]' "${COUNT_SERIES}" "$(count_ge 8)" 30 15 60

# ===== Alertes Lot 3 (detections de profondeur, multi-agent) =====
ensure_event "OMNI - Exfiltration par volume (flux sortant anormal)" 2 \
  'event_source:ndr_exfil AND alert_tag:data_exfil' "[\"${ST_INT}\"]" \
  '["entity_host"]' "${COUNT_SERIES}" "$(count_ge 1)" 120 60
ensure_event "OMNI - Accès credentials GPP/SYSVOL (T1552.006)" 3 \
  'alert_tag:gpp_creds_access' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 10
ensure_event "OMNI - Kerberos RC4 / downgrade (kerberoasting)" 3 \
  'alert_tag:kerberos_rc4' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 5)" 30 10
ensure_event "OMNI - Ajout au groupe Administrateurs LOCAL (4732)" 2 \
  'alert_tag:local_admin_add' "[\"${ST_WINSEC}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 10
ensure_event "OMNI - Création de compte LOCAL (4720 hors DC)" 2 \
  'alert_tag:local_account_create' "[\"${ST_WINSEC}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 10
if [[ -n "${ST_INT}" ]]; then
  ensure_event "OMNI - Nouveau pays pour un compte (first-seen)" 3 \
    'event_source:ueba_geo AND alert_tag:new_country' "[\"${ST_INT}\"]" \
    '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 30
fi

# ===== Alertes Lot 4 (detections AD/identite avancees, multi-agent) =====
ensure_event "OMNI - Abus AD CS / certificats (ESC1-ESC8)" 3 \
  'alert_tag:adcs_abuse' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 10
ensure_event "OMNI - Shadow Credentials (msDS-KeyCredentialLink)" 3 \
  'alert_tag:shadow_credentials' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 10
ensure_event "OMNI - Exécution à distance WMI (latéral)" 2 \
  'alert_tag:wmi_lateral_exec' "[\"${ST_SYSMON}\"]" \
  '["host"]' "${COUNT_SERIES}" "$(count_ge 1)" 30 10
if [[ -n "${ST_INT}" ]]; then
  ensure_event "OMNI - Reconnaissance LDAP (énumération annuaire)" 3 \
    'event_source:ldap_recon AND alert_tag:ldap_recon' "[\"${ST_INT}\"]" \
    '["entity_user"]' "${COUNT_SERIES}" "$(count_ge 1)" 60 30
  ensure_event "OMNI - Mouvement latéral réussi (1 compte -> N hôtes)" 2 \
    'event_source:ndr_lateral AND alert_tag:lateral_movement' "[\"${ST_INT}\"]" \
    '["entity_user"]' "${COUNT_SERIES}" "$(count_ge 1)" 90 30
fi

# ===== Alertes nouvelles sources (ESET / BunkerWeb / NPS) =====
ST_ESET="$(get_stream_id 'OMNI - ESET' || true)"
ST_BW="$(get_stream_id 'OMNI - BunkerWeb' || true)"
[[ -n "${ST_ESET}" ]] && ensure_event "OMNI - ESET : détection/menace antivirus" 2 \
  'alert_tag:eset_detection' "[\"${ST_ESET}\"]" \
  '["source"]' "${COUNT_SERIES}" "$(count_ge 1)" 15 5
[[ -n "${ST_BW}" ]] && ensure_event "OMNI - BunkerWeb : pic de blocages WAF (>=20 / IP / 10 min)" 3 \
  'alert_tag:waf_block' "[\"${ST_BW}\"]" \
  '["src_ip"]' "${COUNT_SERIES}" "$(count_ge 20)" 10 5
# NPS : refus en masse (RADIUS/VPN brute force) -> P3 (deja enrichi via win-events.csv)
ensure_event "OMNI - NPS : refus d'accès en masse (>=10 / compte / 15 min)" 3 \
  'event_action:acces_reseau_nps_refuse' "[\"${ST_WINSEC}\"]" \
  '["user"]' "${COUNT_SERIES}" "$(count_ge 10)" 15 5

# ---------------------------------- 4. Rattacher TOUTES les notifications
echo "==> [4] Synchronisation des notifications sur les definitions OMNI"
W_P3="$(jq -n --arg e "${NOTIF_ID}" --arg t "${TEAMS_ID}" '[{notification_id:$e}] + (if $t != "" then [{notification_id:$t}] else [] end)')"
W_P2="$(jq -n --arg e "${NOTIF_ID}" --arg t "${TEAMS_ID}" 'if $t != "" then [{notification_id:$t}] else [{notification_id:$e}] end')"
api_get "/events/definitions?per_page=100" \
  | jq -r '(.event_definitions // .elements // [])[] | select(.title|startswith("OMNI")) | .id' \
  | while read -r DID; do
      DEF="$(api_get "/events/definitions/${DID}")"
      P="$(echo "${DEF}" | jq -r '.priority')"
      WANTED="${W_P2}"; GRACE=1800000
      [[ "${P}" == "3" ]] && { WANTED="${W_P3}"; GRACE=600000; }
      # Conditions PERSISTANTES / RE-EMISES a chaque cycle (go-dark, UEBA/NDR :
      # le collecteur re-trouve le meme constat tant qu'il dure) -> anti-tempete
      # long (6h) sinon re-alerte a chaque passage.
      case "$(echo "${DEF}" | jq -r .title)" in
        *go-dark*|*"Impossible travel"*|*Beaconing*|*"Anomalie de volume"*|*UEBA*|*Tunneling*|*Incident*|*Robot*|*Scan*|*lateral*|*"Reconnaissance LDAP"*|*Exfiltration*) GRACE=21600000 ;;
      esac
      # PRESERVER toute notification deja attachee hors mail/teams (ex. SOAR
      # auto-block sur les def brute-force) : sinon ce sync la retirait a chaque run.
      WANTED="$(jq -cn --argjson w "${WANTED}" --argjson cur "$(echo "${DEF}" | jq -c '.notifications')" \
                 --arg m "${NOTIF_ID}" --arg t "${TEAMS_ID}" \
                 '$w + [$cur[]|select(.notification_id!=$m and .notification_id!=$t)|{notification_id}] | unique_by(.notification_id)')"
      CUR="$(echo "${DEF}" | jq -c '[.notifications[].notification_id] | sort')"
      NEW="$(echo "${WANTED}" | jq -c '[.[].notification_id] | sort')"
      CURG="$(echo "${DEF}" | jq -r '.notification_settings.grace_period_ms')"
      # key_spec = group_by -> anti-tempete PAR ENTITE (et non globale). Rattrape
      # les definitions creees avant le correctif (key_spec etait vide).
      # key_spec n'est valide que si chaque cle est declaree dans field_spec
      # (champ template ${source.<cle>}). On genere les deux depuis group_by.
      CURK="$(echo "${DEF}" | jq -c '.key_spec // []')"
      WANTK="$(echo "${DEF}" | jq -c '.config.group_by // []')"
      if [[ "${CUR}" == "${NEW}" && "${CURG}" == "${GRACE}" && "${CURK}" == "${WANTK}" ]]; then continue; fi
      echo "${DEF}" | jq --argjson n "${WANTED}" --argjson g "${GRACE}" '
          .notifications = ($n | map(. + {notification_parameters: null}))
          | .notification_settings.grace_period_ms = $g
          | .key_spec = (.config.group_by // [])
          | .field_spec = ((.config.group_by // [])
              | map({key: ., value: {data_type: "string",
                  providers: [{type: "template-v1", template: ("${source." + . + "}"),
                               require_values: false}]}}) | from_entries)' \
        | api_put "/events/definitions/${DID}" >/dev/null \
        && ok "notifications synchronisees: $(echo "${DEF}" | jq -r .title)" \
        || warn "echec sync: ${DID}"
    done

echo
api_get "/events/definitions?per_page=100" | jq -r '(.event_definitions // .elements // [])[] | select(.title|startswith("OMNI")) | "      - \(.title)"'
echo
echo "=== 13-graylog-alerts.sh termine. Lancer 14-graylog-dashboards.sh ==="
