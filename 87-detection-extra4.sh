#!/usr/bin/env bash
# =============================================================================
# 87-detection-extra4.sh - Detecteurs ATT&CK haute-fidelite / FP mesure nul
#   Comble les tactiques MINCES de la carte de couverture : Privilege Escalation
#   (etait a 3 techniques) et Lateral Movement (3). Trois signatures OFFENSIVES
#   precises, chacune validee sur les donnees REELLES du parc (sonde OpenSearch
#   omni-*) : baseline observee = 0 sur 30 j ALORS QUE le champ porteur est VIVANT
#   (controle positif) -> la regle n'est pas morte, elle ne se declenche que sur
#   l'attaque. La mesure prealable a ecarte 2 faux candidats :
#     - named-pipe PsExec/Cobalt Strike : Sysmon EID17 = 1 event sur 7 j (pipe
#       events NON journalises par la config sonde) -> regle infaisable, ABANDON.
#     - process PSEXESVC/PAExec : pas de controle positif + usage admin IT
#       plausible -> risque FP, ECARTE.
#
#   1) ifeo_debugger (T1574.012, Privilege Escalation / Persistence) : pose d'une
#      valeur 'Debugger' sous 'Image File Execution Options' (Sysmon EID13). C'est
#      le detournement IFEO classique (backdoor accessibilite sethc/utilman, ou
#      hijack d'execution de n'importe quel binaire). Piege mesure : la racine IFEO
#      est ACTIVE et legitime (2088 ecritures/30j : MitigationOptions, AuditLevel,
#      sous-cles Office msaccess/excelcnv...) MAIS la valeur '\Debugger' = 0 hit.
#      Tout hit = detournement delibere. (Confiance haute : champ vivant, signature
#      cadree = 0, technique a tres faible bruit legitime.)
#
#   2) service_host_shell (T1068, Privilege Escalation) : un service systeme hote
#      (spoolsv.exe = Spouleur d'impression, ou services.exe = SCM) lance un
#      interpreteur (cmd/powershell/pwsh/rundll32). Signature d'EXPLOITATION pour
#      elevation (famille PrintNightmare, abus SCM). Piege mesure : spoolsv.exe est
#      bien actif comme ParentImage (8 hits/30 j = enfants LEGITIMES, jamais un
#      shell) -> le champ est vivant, la signature shell = 0. (Confiance haute.)
#
#   3) winrm_lateral (T1021.006, Lateral Movement) : wsmprovhost.exe (hote de
#      fournisseur WinRM = atterrissage d'une commande a distance PSRemoting) lance
#      un outil de RECON/shell (cmd/whoami/net/net1/nltest/quser/systeminfo/
#      tasklist). On EXCLUT volontairement powershell.exe (l'enfant NORMAL d'une
#      session WinRM admin) pour rester sans FP si WinRM venait a etre active.
#      Mesure : wsmprovhost.exe absent du parc (WinRM non utilise) -> tripwire
#      LATENT de defense en profondeur ; tout atterrissage recon = mouvement lateral.
#      (Confiance moyenne : pas de controle positif, WinRM actuellement inactif ;
#      gate recon = robuste si WinRM est active ulterieurement.)
#
#   Pipeline dedie "OMNI - Detections extra4" (stage 13, avant enrichissement MITRE
#   stage 20), connecte au stream Sysmon. MITRE csv append, alertes mk_a (mail +
#   Teams, count>=1). Idempotent.
#   Prerequis : 12 (streams/pipelines) + 37 (lookup MITRE) + 13 (notifications).
#   Relancer ensuite 57 (carte de couverture) puis 14 (couleurs/dashboards).
#   NON DEPLOYE par defaut dans 00-run-all : a deployer apres revue (comme 80/85).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Regles de detection (stream Sysmon)"

# --- 1) Detournement IFEO : valeur Debugger (T1574.012) ----------------------
# EID13 (RegistryEvent value set). Racine IFEO legitime mais '\Debugger' = 0/30j.
ensure_rule "omni-x4-13-ifeo-debugger" <<'EOF'
rule "omni-x4-13-ifeo-debugger"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "13"
  AND contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "Image File Execution Options", true)
  AND ends_with(to_string($message.winlogbeat_winlog_event_data_TargetObject), "\\Debugger", true)
then
  set_field("alert_tag", "ifeo_debugger");
  set_field("event_action", "detournement_ifeo_debugger");
end
EOF

# --- 2) Service systeme hote lance un shell (T1068) --------------------------
# Exploitation pour elevation : spoolsv.exe / services.exe -> cmd/powershell/
# pwsh/rundll32. Baseline 0/30j (spoolsv ParentImage vivant = enfants legitimes).
ensure_rule "omni-x4-13-service-host-shell" <<'EOF'
rule "omni-x4-13-service-host-shell"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\spoolsv.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\services.exe", true) )
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\cmd.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\powershell.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\pwsh.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\rundll32.exe", true) )
then
  set_field("alert_tag", "service_host_shell");
  set_field("event_action", "exploitation_elevation_service");
end
EOF

# --- 3) Mouvement lateral WinRM (T1021.006) ----------------------------------
# wsmprovhost.exe (hote provider WinRM) -> outil de recon/shell. powershell.exe
# EXCLU (enfant normal d'une session WinRM legitime) pour rester sans FP.
ensure_rule "omni-x4-13-winrm-lateral" <<'EOF'
rule "omni-x4-13-winrm-lateral"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "1"
  AND ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\wsmprovhost.exe", true)
  AND ( ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\cmd.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\whoami.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\net.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\net1.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\nltest.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\quser.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\systeminfo.exe", true)
     OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\tasklist.exe", true) )
then
  set_field("alert_tag", "winrm_lateral");
  set_field("event_action", "mouvement_lateral_winrm");
end
EOF

echo "==> [2/4] Pipeline 'OMNI - Detections extra4' (stage 13) + connexion stream Sysmon"
PL="$(ensure_pipeline "OMNI - Detections extra4" <<'PIPE'
pipeline "OMNI - Detections extra4"
stage 13 match either
rule "omni-x4-13-ifeo-debugger"
rule "omni-x4-13-service-host-shell"
rule "omni-x4-13-winrm-lateral"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Sysmon')"
[[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream absent: OMNI - Sysmon"

echo "==> [3/4] MITRE (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || { echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; ok "MITRE +$1"; }; }
add_mitre ifeo_debugger      T1574.012 "Hijack Execution Flow: IFEO Injection"          "Privilege Escalation" critique 8
add_mitre service_host_shell T1068     "Exploitation for Privilege Escalation"          "Privilege Escalation" critique 9
add_mitre winrm_lateral      T1021.006 "Remote Services: Windows Remote Management"     "Lateral Movement"     eleve    7
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE ifeo_debugger / service_host_shell / winrm_lateral"

echo "==> [4/4] Alertes (tier mail + Teams ; tripwire count>=1, baseline reelle = 0)"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
mk_a() { local T="$1" Q="$2" ST="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg st "$ST" --argjson n "$NF" '{title:$t,description:"87-detection-extra4.sh",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"; }
SYS="$(get_stream_id 'OMNI - Sysmon')"
mk_a "OMNI - Detournement IFEO (valeur Debugger)"            "alert_tag:ifeo_debugger"      "$SYS"
mk_a "OMNI - Service systeme lance un shell (exploitation)"  "alert_tag:service_host_shell" "$SYS"
mk_a "OMNI - Mouvement lateral WinRM (wsmprovhost -> recon)" "alert_tag:winrm_lateral"      "$SYS"
echo
echo "=== 87 termine. 3 techniques : T1574.012 (ifeo_debugger, PrivEsc/Persist),"
echo "    T1068 (service_host_shell, PrivEsc), T1021.006 (winrm_lateral, Lateral Movement)."
echo "    Baseline 0 mesuree sur 30 j, champs porteurs vivants (controle positif)."
echo "    Relancer 57 (carte ATT&CK) puis 14 (couleurs/dashboards). ==="
