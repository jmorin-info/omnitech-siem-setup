#!/usr/bin/env bash
# =============================================================================
# 88-deception-honeytokens.sh - OMNI Sentinel : couche de DECEPTION (honeytokens).
#   Defense PROACTIVE, pas reactive : au lieu d'attendre une signature, on FABRIQUE
#   le piege. Des leurres (comptes/SPN/FQDN canari) qui n'ont AUCUN usage legitime
#   -> tout contact = attaquant, fidelite ~100%, FP structurellement nul.
#
#   Concu + mesure + VERIFIE ADVERSARIALEMENT (workflow 15 agents, 2026-06-23) sur
#   les donnees REELLES du parc. Carte d'environnement derivee en direct (nommage,
#   joyaux, pieds-a-terre) -> leurres places sur les CHEMINS D'ATTAQUE vers les
#   joyaux (DC, SIEM, Veeam, Vault, PKI, fichiers, vSphere) et credibles (se fondent
#   dans la nomenclature reelle bx-*/svc_*/adm-*).
#
#   COLLISION VERIFIEE = 0 sur 30 j pour les 15 comptes/machines + 5 FQDN canari
#   (TargetUserName/ServiceName/QueryName) -> 0-FP par construction : la regle
#   s'arme et ne tire qu'au CONTACT d'un leurre.
#
#   Registre extensible : lookups/deception-decoys.csv (key->type) via lookup Graylog
#   'omni-deception'. Julien ajoute 1 ligne -> couvert en <60 s, SANS toucher au code.
#
#   5 regles (stage 13), pilotees par le lookup, multi-sources :
#     1) decoy_identity   (T1078, Credential Access)   : windows_security 4624/4625/4768,
#        TargetUserName est un leurre 'identity' -> auth Windows sur compte/machine leurre.
#     2) decoy_kerberoast (T1558.003, Credential Access): windows_security 4769,
#        ServiceName est un leurre -> TGS demande pour un compte-leurre = Kerberoasting
#        a FIDELITE ABSOLUE (distinct du 73 heuristique RC4 ; ici aucun service reel).
#     3) decoy_identity (M365)  (T1078.004)            : m365, champ 'user' est un leurre
#        -> sign-in cloud sur compte leurre (surface cloud jumelle).
#     4) canary_token (Sysmon)  (T1005, Collection)    : sysmon EID22, QueryName == FQDN
#        canari -> un fichier appat (KeePass/VPN/SSH/Office/.lnk) a ete ouvert.
#     5) canary_token (FortiGate)                      : fortigate qname == FQDN canari
#        -> visibilite reseau complementaire (requete ne passant pas par un hote Sysmon).
#
#   Verdicts adversariaux : decoy_kerberoast zero_fp=TRUE (le plus fort) ; decoy_identity
#   deploy (FP non-structurel = DISCIPLINE de provisionning, cf plan) ; canary revise ->
#   domaine canari EXTERNE disjoint de la zone AD (fait : *.bkp-omnitech-vault.net etc.,
#   PAS sous omnitech.security) ; decoy_host DROP (EID3 = bruit de scan) -> fondu dans
#   'identity' via les comptes MACHINE leurres (bx-ad03-it-vm$...) ; decoy_file DROP
#   (pas d'audit lecture fichier) -> remplace par le canari embarque.
#
#   L'APPAT (creer les comptes en AD, deposer les fichiers canari) est l'action de Julien
#   en DRY-RUN sur l'AD/infra OMNITECH -- JAMAIS sur le tenant co-manage invissys.com.
#   Voir docs/DECEPTION-PLAN.md (genere). La detection ci-dessous est le PIEGE, deja arme.
#
#   Pipeline 'OMNI - Deception' (stage 13) connecte aux streams Windows Security / Sysmon
#   / M365 / FortiGate. MITRE csv + alertes mk_a (count>=1, priorite haute). Idempotent.
#   Prerequis : 12 (streams) + 37 (MITRE) + 13 (notifications). Relancer 57 + 14 ensuite.
#   NON DEPLOYE par defaut dans 00-run-all : a deployer apres revue (comme 80/85/87).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/5] Registre de leurres -> lookup 'omni-deception' (CSV key->type, re-lecture 60s)"
# Filtre les commentaires/lignes vides : CSVFileDataAdapter rejette tout le fichier
# si une ligne n'a pas 2 colonnes (piege connu, cf 81-fp-allowlist.sh).
grep -vE '^[[:space:]]*(#|$)' lookups/deception-decoys.csv > "${LOOKUP_DIR}/deception-decoys.csv"
chmod 644 "${LOOKUP_DIR}/deception-decoys.csv"
chown root:graylog "${LOOKUP_DIR}/deception-decoys.csv" 2>/dev/null || true
ok "deception-decoys.csv deploye dans ${LOOKUP_DIR}/ ($(grep -vcE '^[[:space:]]*(#|$)' lookups/deception-decoys.csv) lignes hors en-tete)"
ensure_lookup "deception" "OMNI Deception (cle -> type de leurre)" "deception-decoys.csv" "key" "type"

echo "==> [2/5] Regles de detection (lookup omni-deception ; case_insensitive)"

# --- 1) Leurre IDENTITE : auth Windows sur compte/machine leurre (T1078) ------
ensure_rule "omni-dec-13-identity" <<'EOF'
rule "omni-dec-13-identity"
when
  to_string($message.event_source) == "windows_security"
  AND ( to_string($message.winlogbeat_winlog_event_id) == "4624"
     OR to_string($message.winlogbeat_winlog_event_id) == "4625"
     OR to_string($message.winlogbeat_winlog_event_id) == "4768" )
  AND to_string(lookup_value("omni-deception", to_string($message.winlogbeat_winlog_event_data_TargetUserName))) == "identity"
then
  set_field("alert_tag", "decoy_identity");
  set_field("event_action", "leurre_identite_touche");
  set_field("deception", true);
end
EOF

# --- 2) Leurre KERBEROAST : TGS demande pour un compte-leurre (T1558.003) -----
ensure_rule "omni-dec-13-kerberoast" <<'EOF'
rule "omni-dec-13-kerberoast"
when
  to_string($message.event_source) == "windows_security"
  AND to_string($message.winlogbeat_winlog_event_id) == "4769"
  AND to_string(lookup_value("omni-deception", to_string($message.winlogbeat_winlog_event_data_ServiceName))) == "identity"
then
  set_field("alert_tag", "decoy_kerberoast");
  set_field("event_action", "leurre_kerberoast_tgs");
  set_field("deception", true);
end
EOF

# --- 3) Leurre IDENTITE (M365) : sign-in cloud sur compte leurre (T1078.004) --
ensure_rule "omni-dec-13-m365" <<'EOF'
rule "omni-dec-13-m365"
when
  to_string($message.event_source) == "m365"
  AND to_string(lookup_value("omni-deception", to_string($message.user))) == "identity"
then
  set_field("alert_tag", "decoy_identity");
  set_field("event_action", "leurre_identite_cloud");
  set_field("deception", true);
end
EOF

# --- 4) Token CANARI (Sysmon) : requete DNS vers un FQDN canari (T1005) -------
ensure_rule "omni-dec-13-canary-sysmon" <<'EOF'
rule "omni-dec-13-canary-sysmon"
when
  to_string($message.event_source) == "sysmon"
  AND to_string($message.winlogbeat_winlog_event_id) == "22"
  AND to_string(lookup_value("omni-deception", to_string($message.winlogbeat_winlog_event_data_QueryName))) == "canary"
then
  set_field("alert_tag", "canary_token");
  set_field("event_action", "canari_dns_ouverture_appat");
  set_field("deception", true);
end
EOF

# --- 5) Token CANARI (FortiGate) : visibilite reseau complementaire ----------
ensure_rule "omni-dec-13-canary-forti" <<'EOF'
rule "omni-dec-13-canary-forti"
when
  to_string($message.event_source) == "fortigate"
  AND to_string(lookup_value("omni-deception", to_string($message.qname))) == "canary"
then
  set_field("alert_tag", "canary_token");
  set_field("event_action", "canari_dns_forti");
  set_field("deception", true);
end
EOF

echo "==> [3/5] Pipeline 'OMNI - Deception' (stage 13) + connexion multi-streams"
PL="$(ensure_pipeline "OMNI - Deception" <<'PIPE'
pipeline "OMNI - Deception"
stage 13 match either
rule "omni-dec-13-identity"
rule "omni-dec-13-kerberoast"
rule "omni-dec-13-m365"
rule "omni-dec-13-canary-sysmon"
rule "omni-dec-13-canary-forti"
end
PIPE
)"
for S in 'OMNI - Windows Security' 'OMNI - Sysmon' 'OMNI - M365' 'OMNI - FortiGate'; do
  SID="$(get_stream_id "$S")"
  [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream absent: $S"
done

echo "==> [4/5] MITRE (CSV 37)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "$CSV" || { echo "$1,$2,$3,$4,$5,$6" >> "$CSV"; ok "MITRE +$1"; }; }
add_mitre decoy_identity   T1078     "Valid Accounts (honeytoken)"          "Credential Access" critique 9
add_mitre decoy_kerberoast T1558.003 "Kerberoasting (SPN leurre)"           "Credential Access" critique 9
add_mitre canary_token     T1005     "Data from Local System (canari)"      "Collection"        critique 9
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE decoy_identity / decoy_kerberoast / canary_token"

echo "==> [5/5] Alertes (mail + Teams ; honeytouch = priorite HAUTE, count>=1)"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
# mk_a TITRE QUERY STREAMS_JSON : alerte multi-streams (un honeytoken traverse plusieurs sources)
mk_a() { local T="$1" Q="$2" ST="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  jq -n --arg t "$T" --arg q "$Q" --argjson st "$ST" --argjson n "$NF" '{title:$t,description:"88-deception-honeytokens.sh",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:$st,group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:0,backlog_size:25},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"; }
WSEC="$(get_stream_id 'OMNI - Windows Security')"; SYSM="$(get_stream_id 'OMNI - Sysmon')"
M365="$(get_stream_id 'OMNI - M365')"; FGT="$(get_stream_id 'OMNI - FortiGate')"
SID_ID="$(jq -n --arg a "$WSEC" --arg b "$M365" '[$a,$b]')"
SID_KB="$(jq -n --arg a "$WSEC" '[$a]')"
SID_CA="$(jq -n --arg a "$SYSM" --arg b "$FGT" '[$a,$b]')"
mk_a "OMNI - LEURRE Identite touche (honeytoken compte/machine)" "alert_tag:decoy_identity"   "$SID_ID"
mk_a "OMNI - LEURRE Kerberoast (TGS sur SPN leurre)"             "alert_tag:decoy_kerberoast" "$SID_KB"
mk_a "OMNI - LEURRE Canari ouvert (fichier appat)"               "alert_tag:canary_token"     "$SID_CA"
echo
echo "=== 88 termine. OMNI Sentinel - couche deception armee (5 regles, lookup omni-deception)."
echo "    3 tags : decoy_identity (T1078), decoy_kerberoast (T1558.003), canary_token (T1005)."
echo "    Collision 0 / baseline 0 verifies. L'APPAT = action Julien (docs/DECEPTION-PLAN.md, dry-run AD OMNITECH)."
echo "    Relancer 57 (carte ATT&CK) puis 14 (dashboards). ==="
