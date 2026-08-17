#!/usr/bin/env bash
# =============================================================================
# 73-detection-ad.sh - Detection AD : Kerberoasting (T1558.003)
#   Trou de couverture comble : l'environnement utilise AES (0x12) ; une requete
#   de ticket de service Kerberos en RC4 (0x17) pour un compte de SERVICE (non
#   machine $) = downgrade pour crackage hors-ligne = kerberoasting. Tripwire
#   propre (zero FP attendu vu la posture AES). EventID 4769.
#   Idempotent. Prerequis : 37 (MITRE). Relancer 57 (carte) ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/3] Regle de detection kerberoasting (4769 + RC4)"
ensure_rule "omni-winsec-kerberoast" <<'EOF'
rule "omni-winsec-kerberoast"
when
  to_string($message.event_id) == "4769"
  AND to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x17"
  AND ! ends_with(to_string($message.winlogbeat_winlog_event_data_ServiceName), "$", true)
  AND to_string($message.winlogbeat_winlog_event_data_ServiceName) != "krbtgt"
then
  set_field("ad_service", to_string($message.winlogbeat_winlog_event_data_ServiceName));
  set_field("alert_tag", "kerberoasting");
end
EOF
ensure_rule "omni-winsec-asrep" <<'EOF'
rule "omni-winsec-asrep"
when
  to_string($message.event_id) == "4768"
  AND to_string($message.winlogbeat_winlog_event_data_PreAuthType) == "0"
then
  set_field("ad_account", to_string($message.user));
  set_field("alert_tag", "asrep_roasting");
end
EOF

# --- Enrichissement 2026-07 : detections DC additionnelles ---------------------
# Calibrees sur donnees reelles (BX-AD-01-IT-VM / BX-AD02-IT-VM). Volumes quasi nuls
# -> tripwires haute-fidelite. Comptes legitimes exclus (MSOL_ = Azure AD Connect).

# RBCD (Resource-Based Constrained Delegation) : ecriture de
# msDS-AllowedToActOnBehalfOfOtherIdentity = prise de controle par delegation.
# T1098.005. Volume reel : 0. MSOL_ exclu par prudence (jamais vu sur cet attribut).
ensure_rule "omni-winsec-rbcd" <<'EOF'
rule "omni-winsec-rbcd"
when
  to_string($message.event_id) == "5136"
  AND lowercase(to_string($message.winlogbeat_winlog_event_data_AttributeLDAPDisplayName)) == "msds-allowedtoactonbehalfofotheridentity"
  AND to_string($message.winlogbeat_winlog_event_data_SubjectUserSid) != "S-1-5-18"
  AND NOT starts_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "MSOL_", true)
then
  set_field("ad_object", to_string($message.winlogbeat_winlog_event_data_ObjectDN));
  set_field("alert_tag", "rbcd_delegation");
end
EOF

# SPN ajoute a un compte UTILISATEUR (pas machine) : mise en place d'un kerberoast
# cible. T1558.003 (preparation). Les ordinateurs recoivent des SPN legitimement
# -> on borne a ObjectClass=user. Volume reel : 0.
ensure_rule "omni-winsec-spn-user" <<'EOF'
rule "omni-winsec-spn-user"
when
  to_string($message.event_id) == "5136"
  AND lowercase(to_string($message.winlogbeat_winlog_event_data_AttributeLDAPDisplayName)) == "serviceprincipalname"
  AND lowercase(to_string($message.winlogbeat_winlog_event_data_ObjectClass)) == "user"
  AND to_string($message.winlogbeat_winlog_event_data_SubjectUserSid) != "S-1-5-18"
  AND NOT starts_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "MSOL_", true)
then
  set_field("ad_object", to_string($message.winlogbeat_winlog_event_data_ObjectDN));
  set_field("alert_tag", "spn_added_user");
end
EOF

# AdminSDHolder : toute modification de l'ACL du conteneur AdminSDHolder =
# persistance sur les comptes proteges (SDProp la repropage sur tous les
# comptes/groupes Tier-0). T1098. Extremement rare -> alerte directe. Volume : 0.
ensure_rule "omni-winsec-adminsdholder" <<'EOF'
rule "omni-winsec-adminsdholder"
when
  to_string($message.event_id) == "5136"
  AND contains(lowercase(to_string($message.winlogbeat_winlog_event_data_ObjectDN)), "cn=adminsdholder", false)
then
  set_field("ad_object", to_string($message.winlogbeat_winlog_event_data_ObjectDN));
  set_field("alert_tag", "adminsdholder_acl");
end
EOF

# Zerologon (CVE-2020-1472) : changement de mot de passe d'un compte machine
# (4742) declenche par ANONYMOUS LOGON (S-1-5-7) = exploitation Netlogon.
# T1210. 1 occurrence/j observee -> signal fort et rare.
ensure_rule "omni-winsec-zerologon" <<'EOF'
rule "omni-winsec-zerologon"
when
  to_string($message.event_id) == "4742"
  AND to_string($message.winlogbeat_winlog_event_data_SubjectUserSid) == "S-1-5-7"
then
  set_field("ad_object", to_string($message.winlogbeat_winlog_event_data_TargetUserName));
  set_field("alert_tag", "zerologon_suspect");
end
EOF

# Compte renomme (4781) : technique d'evasion/masquage ou detournement de compte
# dormant. T1098. Volume reel : 0.
ensure_rule "omni-winsec-account-renamed" <<'EOF'
rule "omni-winsec-account-renamed"
when
  to_string($message.event_id) == "4781"
  AND NOT ends_with(to_string($message.winlogbeat_winlog_event_data_NewTargetUserName), "$", false)
then
  set_field("ad_object", to_string($message.winlogbeat_winlog_event_data_NewTargetUserName));
  set_field("alert_tag", "account_renamed");
end
EOF

# Compte PRIVILEGIE reactive (4722) : reactivation d'un compte admin/service
# dormant = persistance. On borne aux cibles privilegiees (adm-/adm_/svc-/svc_/
# administrat) pour eviter le bruit onboarding. T1098. Volume reel : ~3/j au total.
ensure_rule "omni-winsec-priv-account-enabled" <<'EOF'
rule "omni-winsec-priv-account-enabled"
when
  to_string($message.event_id) == "4722"
  AND ( starts_with(lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName)), "adm-", false)
    OR starts_with(lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName)), "adm_", false)
    OR starts_with(lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName)), "svc-", false)
    OR starts_with(lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName)), "svc_", false)
    OR contains(lowercase(to_string($message.winlogbeat_winlog_event_data_TargetUserName)), "administrat", false) )
then
  set_field("ad_object", to_string($message.winlogbeat_winlog_event_data_TargetUserName));
  set_field("alert_tag", "priv_account_enabled");
end
EOF

PL="$(ensure_pipeline "OMNI - Detection AD" <<'PIPE'
pipeline "OMNI - Detection AD"
stage 12 match either
rule "omni-winsec-kerberoast"
rule "omni-winsec-asrep"
rule "omni-winsec-rbcd"
rule "omni-winsec-spn-user"
rule "omni-winsec-adminsdholder"
rule "omni-winsec-zerologon"
rule "omni-winsec-account-renamed"
rule "omni-winsec-priv-account-enabled"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Windows Security')"; [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL"

echo "==> [2/3] MITRE"
CSV="lookups/mitre-attack.csv"
grep -q '^kerberoasting,' "$CSV" || echo 'kerberoasting,T1558.003,Kerberoasting,Credential Access,critique,9' >> "$CSV"
grep -q '^asrep_roasting,' "$CSV" || echo 'asrep_roasting,T1558.004,AS-REP Roasting,Credential Access,eleve,8' >> "$CSV"
grep -q '^rbcd_delegation,' "$CSV" || echo 'rbcd_delegation,T1098.005,Resource-Based Constrained Delegation,Persistence,critique,9' >> "$CSV"
grep -q '^spn_added_user,' "$CSV" || echo 'spn_added_user,T1558.003,SPN ajoute a un compte utilisateur,Credential Access,eleve,8' >> "$CSV"
grep -q '^adminsdholder_acl,' "$CSV" || echo 'adminsdholder_acl,T1098,Modification ACL AdminSDHolder,Persistence,critique,9' >> "$CSV"
grep -q '^zerologon_suspect,' "$CSV" || echo 'zerologon_suspect,T1210,Zerologon (Netlogon) suspecte,Lateral Movement,critique,10' >> "$CSV"
grep -q '^account_renamed,' "$CSV" || echo 'account_renamed,T1098,Compte renomme,Persistence,moyen,6' >> "$CSV"
grep -q '^priv_account_enabled,' "$CSV" || echo 'priv_account_enabled,T1098,Compte privilegie reactive,Persistence,eleve,7' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE kerberoasting (T1558.003)"

echo "==> [3/3] Alerte"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
SYS="$(get_stream_id 'OMNI - Windows Security')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
mk_ad_alert() {  # titre query priorite
  local T="$1" Q="$2" P="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --arg st "$SYS" --argjson p "$P" --argjson n "$NF" '{title:$t,description:"Detection AD Kerberos (73-detection-ad.sh)",priority:$p,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[$st],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"
}
mk_ad_alert "OMNI - Kerberoasting (ticket Kerberos RC4 demande)" "alert_tag:kerberoasting" 3
mk_ad_alert "OMNI - AS-REP Roasting (compte sans pré-auth Kerberos)" "alert_tag:asrep_roasting" 3
mk_ad_alert "OMNI - RBCD : délégation contrainte ajoutée (T1098.005)" "alert_tag:rbcd_delegation" 3
mk_ad_alert "OMNI - SPN ajouté à un compte utilisateur (kerberoast ciblé)" "alert_tag:spn_added_user" 3
mk_ad_alert "OMNI - AdminSDHolder modifié (persistance Tier-0)" "alert_tag:adminsdholder_acl" 3
mk_ad_alert "OMNI - Zerologon suspecté (4742 par ANONYMOUS LOGON)" "alert_tag:zerologon_suspect" 3
mk_ad_alert "OMNI - Compte AD renommé (4781)" "alert_tag:account_renamed" 2
mk_ad_alert "OMNI - Compte privilégié réactivé (4722)" "alert_tag:priv_account_enabled" 2
echo
echo "=== 73 termine. Tripwire kerberoasting actif (silencieux tant que pas de RC4). Relancer 57. ==="
