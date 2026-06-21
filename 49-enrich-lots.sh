#!/usr/bin/env bash
# 49-enrich-lots.sh - Enrichissements lots 1+2 (multi-agent) : regles pipeline + lookups + MITRE.
# Idempotent. Prerequis 12+37. Relance 14+13. (widgets/alertes/couleurs dans 14/13.)
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis."
require_api
LOOKUP_DIR="/etc/graylog/lookup"
CSV="lookups/mitre-attack.csv"
WD="winlogbeat_winlog_event_data"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }

# ensure_lookup() centralise dans lib-graylog.sh (supprime la copie locale)

# ---- Enrichissement OFF-HOURS (heures non ouvrees) sur les a ----
# =============================================================================
# Enrichissement OFF-HOURS sur les authentifications (winsec 4624/4625 + M365 signin).
# A placer dans un script 49-enrich-offhours.sh (style 47), APRES source 00-vars.env + lib-graylog.sh.
# Pose off_hours=oui/non et day_period=heures_ouvrees/nuit/week-end selon l'heure LOCALE.
# Pas de if/else (interdit pipeline) -> 3 regles dans un meme stage 'match either' :
#   R1 = defaut (toujours, pose off_hours=non + day_period=heures_ouvrees)
#   R2 = nuit  (HH<7 ou HH>=20)  -> override off_hours=oui + day_period=nuit
#   R3 = week-end (jour-semaine>=6) -> override off_hours=oui + day_period=week-end
# Les regles d'un stage s'executent dans l'ordre de declaration, les mutations persistent
# (semantique standard Graylog, idem 47). Week-end+nuit -> R3 gagne (libelle week-end), OK.
# IMPORTANT : to_date($message.timestamp) est OBLIGATOIRE (timestamp = Object, refuse direct).
# =============================================================================

ensure_rule "omni-enrich-10-offhours-base" <<EOF
rule "omni-enrich-10-offhours-base"
when
  ( to_string(\$message.event_source) == "windows_security"
    AND ( to_long(\$message.event_id, 0) == 4624 OR to_long(\$message.event_id, 0) == 4625 ) )
  OR
  ( to_string(\$message.event_source) == "m365" AND to_string(\$message.m365_type) == "signin" )
then
  set_field("off_hours", "non");
  set_field("day_period", "heures_ouvrees");
end
EOF

ensure_rule "omni-enrich-10-offhours-nuit" <<EOF
rule "omni-enrich-10-offhours-nuit"
when
  ( ( to_string(\$message.event_source) == "windows_security"
      AND ( to_long(\$message.event_id, 0) == 4624 OR to_long(\$message.event_id, 0) == 4625 ) )
    OR ( to_string(\$message.event_source) == "m365" AND to_string(\$message.m365_type) == "signin" ) )
  AND ( to_long(format_date(to_date(\$message.timestamp), "HH", "Europe/Paris"), 12) < 7
     OR to_long(format_date(to_date(\$message.timestamp), "HH", "Europe/Paris"), 12) >= 20 )
then
  set_field("off_hours", "oui");
  set_field("day_period", "nuit");
end
EOF

ensure_rule "omni-enrich-10-offhours-weekend" <<EOF
rule "omni-enrich-10-offhours-weekend"
when
  ( ( to_string(\$message.event_source) == "windows_security"
      AND ( to_long(\$message.event_id, 0) == 4624 OR to_long(\$message.event_id, 0) == 4625 ) )
    OR ( to_string(\$message.event_source) == "m365" AND to_string(\$message.m365_type) == "signin" ) )
  AND to_long(format_date(to_date(\$message.timestamp), "e", "Europe/Paris"), 1) >= 6
then
  set_field("off_hours", "oui");
  set_field("day_period", "week-end");
end
EOF

# ---- Enrichissement OFF-HOURS (heures non ouvrees) sur les a ----
# Pipeline DEDIE (stage 10) + connexion aux streams Windows Security et M365.
# Stage 'match either' : tous les messages traversent ; les regles non gatees ne mutent rien.
PL="$(ensure_pipeline "OMNI - Enrichissement off-hours" <<'EOF'
pipeline "OMNI - Enrichissement off-hours"
stage 10 match either
rule "omni-enrich-10-offhours-base"
rule "omni-enrich-10-offhours-nuit"
rule "omni-enrich-10-offhours-weekend"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - M365"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done
# NOTE : si la normalisation event_source/m365_type est faite dans un AUTRE pipeline,
# s'assurer que ce pipeline-ci tourne APRES (stage 10 ici > stages de normalisation 0/5
# des pipelines existants ; l'ordre inter-pipelines suit le numero de stage global).

# ---- Enrichissement ACCOUNT_CLASS (account_class + is_admin) ----
# === Bloc a coller dans un script 47-style (ex: nouveau 49-account-class.sh) ===
# Prerequis : source 00-vars.env + lib-graylog.sh ; require_api. Idempotent.
# Conventions de nommage VERIFIEES en live (terms sur le champ user, omni-*).
# Strategie SANS if/else : 4 regles a when MUTUELLEMENT EXCLUSIFS, normalisation
# du compte INLINE dans chaque regle (DOMAINE\\compte et compte@upn -> compte nu,
# en minuscules) car les variables let ne survivent pas d'une regle a l'autre.
# Ordre de specificite garanti par l'exclusivite des gardes (machine > admin >
# service > user), donc l'ordre des regles dans le stage 'match either' est neutre.

# Classement base+override (stage : base puis overrides, dernier matchant gagne).
# user est deja bare (verifie live : adm-jmorin). Pas de regex (rejete GL 7.1) ;
# starts_with/contains en 2/3 args, lowercase() pour l'insensibilite a la casse.
ensure_rule "omni-acct-05-base" <<'RULE'
rule "omni-acct-05-base"
when has_field("user") AND to_string($message.user) != ""
then
  set_field("account_class", "user");
  set_field("is_admin", false);
end
RULE

ensure_rule "omni-acct-05-machine" <<'RULE'
rule "omni-acct-05-machine"
when has_field("user") AND ends_with(to_string($message.user), "$")
then set_field("account_class", "machine");
end
RULE

ensure_rule "omni-acct-05-service" <<'RULE'
rule "omni-acct-05-service"
when has_field("user")
  AND NOT ends_with(to_string($message.user), "$")
  AND ( contains(to_string($message.user), "svc", true)
     OR contains(to_string($message.user), "service", true)
     OR contains(to_string($message.user), "MSOL_", true)
     OR contains(to_string($message.user), "vpxuser", true)
     OR contains(to_string($message.user), "ninjaone", true)
     OR contains(to_string($message.user), "fortinet", true) )
then set_field("account_class", "service");
end
RULE

ensure_rule "omni-acct-05-admin" <<'RULE'
rule "omni-acct-05-admin"
when has_field("user")
  AND ( starts_with(lowercase(to_string($message.user)), "adm-")
     OR starts_with(lowercase(to_string($message.user)), "adm_") )
then
  set_field("account_class", "admin");
  set_field("is_admin", true);
end
RULE

PL_ACCT="$(ensure_pipeline "OMNI - Enrichissement comptes" <<'PIPE'
pipeline "OMNI - Enrichissement comptes"
stage 5 match either
rule "omni-acct-05-base"
rule "omni-acct-05-machine"
rule "omni-acct-05-service"
rule "omni-acct-05-admin"
end
PIPE
)"
for ST in "OMNI - Windows Security" "OMNI - Windows autres" "OMNI - M365" "OMNI - Sysmon"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_ACCT}" || warn "stream absent: ${ST}"
done

# ---- Enrichissement MASQUERADING/LOLBIN avance (Sysmon EID1) ----
# === A coller dans un script 47-style (apres 'WD="winlogbeat_winlog_event_data"') ===
# Regle 1 : binaire systeme connu execute depuis un chemin INHABITUEL
# (hors C:\Windows\System32\, SysWOW64\, WinSxS\, et explorer hors C:\Windows\explorer.exe).
# On identifie le binaire par la FIN de process_path (toujours present, 100% couverture)
# pour rester robuste meme si process_name manque. Chemins legitimes verifies en live.
ensure_rule "omni-extra-10-masq-path" <<EOF
rule "omni-extra-10-masq-path"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 1
  AND (
       ends_with(to_string(\$message.process_path), "\\\\svchost.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\lsass.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\services.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\smss.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\csrss.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\wininit.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\winlogon.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\spoolsv.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\userinit.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\lsm.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\taskhostw.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\sihost.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\RuntimeBroker.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\dllhost.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\conhost.exe", true)
    OR ends_with(to_string(\$message.process_path), "\\\\explorer.exe", true)
  )
  AND NOT starts_with(to_string(\$message.process_path), "C:\\\\Windows\\\\System32\\\\", true)
  AND NOT starts_with(to_string(\$message.process_path), "C:\\\\Windows\\\\SysWOW64\\\\", true)
  AND NOT starts_with(to_string(\$message.process_path), "C:\\\\Windows\\\\WinSxS\\\\", true)
  AND to_string(\$message.process_path) != "C:\\\\Windows\\\\explorer.exe"
then
  set_field("alert_tag", "masquerading");
  set_field("event_action", "masquerading_chemin");
end
EOF

# ---- Enrichissement MASQUERADING/LOLBIN avance (Sysmon EID1) ----
# Regle 2 : nom du process != OriginalFileName (binaire RENOMME).
# Restreint aux OriginalFileName SENSIBLES (outils detournes par les attaquants)
# pour eviter les FP d'installeurs/temp (CodeSetup-*.tmp etc. observes en live).
# Compare la fin de process_path (= nom reel sur disque) a l'OriginalFileName du PE.
ensure_rule "omni-extra-10-masq-name" <<EOF
rule "omni-extra-10-masq-name"
when
  to_string(\$message.event_source) == "sysmon" AND to_long(\$message.event_id, 0) == 1
  AND has_field("${WD}_OriginalFileName")
  AND (
       to_string(\$message.${WD}_OriginalFileName) == "svchost.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "lsass.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "services.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "powershell.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "powershell_ise.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "cmd.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "psexec.c"
    OR to_string(\$message.${WD}_OriginalFileName) == "rundll32.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "regsvr32.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "mshta.exe"
    OR to_string(\$message.${WD}_OriginalFileName) == "wmic.exe"
  )
  AND NOT ends_with(to_string(\$message.process_path), to_string(\$message.${WD}_OriginalFileName), true)
then
  set_field("alert_tag", "masquerading");
  set_field("event_action", "masquerading_nom");
end
EOF

# ---- Enrichissement MASQUERADING/LOLBIN avance (Sysmon EID1) ----
# Brancher les 2 regles dans le pipeline dedie (ajouter les 2 lignes 'rule' au
# stage 10 'match either' de 'OMNI - Detections complementaires'). Bloc complet :
PL="$(ensure_pipeline "OMNI - Detections complementaires" <<'EOF'
pipeline "OMNI - Detections complementaires"
stage 10 match either
rule "omni-extra-10-gpo"
rule "omni-extra-10-asrep"
rule "omni-extra-10-lolbin"
rule "omni-extra-10-autorun"
rule "omni-extra-10-oauth"
rule "omni-extra-10-masq-path"
rule "omni-extra-10-masq-name"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon" "OMNI - M365"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done

# ---- Enrichissement MASQUERADING/LOLBIN avance (Sysmon EID1) ----
# Ajout MITRE (CSV 37 / fonction add_mitre du 47) :
add_mitre masquerading T1036.005 "Masquerading: Match Legitimate Name or Location" "Defense Evasion" eleve 7
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

# ---- Usage de credentials explicites (4648 - RunAs / mouveme ----
# === Regle stage 10 : usage de credentials explicites (4648 RunAs / lateral) ===
# A coller dans un script 47-style (apres source 00-vars.env + lib-graylog.sh).
# Modelee EXACTEMENT sur 47-detections-extra.sh (heredoc EOF non-quote, $ et \\ echappes).
# Restreinte au SUJET non-machine (sinon ~4.5k/j de bruit ADSync/DC, cf. proof).
# NE TOUCHE PAS event_action (deja pose par la normalisation stage 0).
WD="winlogbeat_winlog_event_data"
ensure_rule "omni-extra-10-explicit-cred" <<EOF
rule "omni-extra-10-explicit-cred"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4648
  AND has_field("${WD}_TargetUserName")
  AND has_field("${WD}_SubjectUserName")
  AND NOT ends_with(to_string(\$message.${WD}_TargetUserName), "\$")
  AND NOT ends_with(to_string(\$message.${WD}_SubjectUserName), "\$")
  AND to_string(\$message.${WD}_SubjectUserName) != "-"
  AND lowercase(to_string(\$message.${WD}_TargetUserName)) != lowercase(to_string(\$message.${WD}_SubjectUserName))
then
  set_field("alert_tag", "explicit_cred_use");
  set_field("explicit_cred_src", to_string(\$message.${WD}_SubjectUserName));
  set_field("explicit_cred_target", to_string(\$message.${WD}_TargetUserName));
end
EOF

# ---- Usage de credentials explicites (4648 - RunAs / mouveme ----
# === Rattacher la regle au pipeline DEDIE existant (cree par 47, deja connecte
# a OMNI - Windows Security). On RE-DECLARE le pipeline complet avec la nouvelle
# regle ajoutee au stage 10 (ensure_pipeline est idempotent / met a jour la source). ===
PL="$(ensure_pipeline "OMNI - Detections complementaires" <<'EOF'
pipeline "OMNI - Detections complementaires"
stage 10 match either
rule "omni-extra-10-gpo"
rule "omni-extra-10-asrep"
rule "omni-extra-10-lolbin"
rule "omni-extra-10-autorun"
rule "omni-extra-10-oauth"
rule "omni-extra-10-explicit-cred"
rule "omni-extra-10-masq-path"
rule "omni-extra-10-masq-name"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon" "OMNI - M365"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done

# ---- Usage de credentials explicites (4648 - RunAs / mouveme ----
# === MITRE : ajouter les techniques au CSV 37 (idempotent, meme helper que 47) ===
# T1078 (Valid Accounts) + T1021 (Remote Services / lateral). severite=moyen, score 5.
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }
add_mitre explicit_cred_use T1078 "Valid Accounts" "Defense Evasion" moyen 5
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

# ---- Enrichissement SEVERITE FORTIGATE NORMALISEE (forti_sev ----
# --- lookups/forti-severity.csv (niveau FortiGate -> severite numerique normalisee) ---
# Echelle normalisee : plus le nombre est GRAND, plus c'est grave (inverse du syslog
# ou emergency=0). Permet tri/seuils intuitifs (forti_severity_num:>=4) en dashboard/alerte.
#   emergency=7 alert=6 critical=5 error=4 warning=3 notice=2 information=1 (+ debug=0 par prudence)
cat > lookups/forti-severity.csv <<'CSV'
level,num
emergency,7
alert,6
critical,5
error,4
warning,3
notice,2
information,1
debug,0
CSV
ok "forti-severity.csv ecrit (lookups/)"

# ---- Enrichissement SEVERITE FORTIGATE NORMALISEE (forti_sev ----
# --- Deploiement du CSV dans le repertoire de lookup Graylog ---
install -m 644 lookups/forti-severity.csv /etc/graylog/lookup/forti-severity.csv
chown root:graylog /etc/graylog/lookup/forti-severity.csv 2>/dev/null || true
ok "forti-severity.csv deploye dans /etc/graylog/lookup"

# ---- Enrichissement SEVERITE FORTIGATE NORMALISEE (forti_sev ----
# --- Table de lookup level -> num (reutilise le helper ensure_lookup de 37-mitre-attack.sh ;
#     si execute hors 37, recopier la fonction ensure_lookup dans le script avant cet appel) ---
# ensure_lookup <nom> <titre> <csv> <key_col> <val_col>
ensure_lookup "forti-severity" "OMNI niveau FortiGate -> severite numerique" "forti-severity.csv" "level" "num"

# ---- Enrichissement SEVERITE FORTIGATE NORMALISEE (forti_sev ----
# --- Regle pipeline FortiGate : pose forti_severity_num (long) au STAGE 5 ---
# Modele EXACT 47-detections-extra.sh (heredoc EOF NON-quote : echapper \$message et \").
# Le lookup omni-forti-severity est insensible a la casse (case_insensitive_lookup:true).
ensure_rule "omni-forti-05-severity" <<EOF
rule "omni-forti-05-severity"
when
  to_string(\$message.event_source) == "fortigate"
  AND has_field("level")
then
  set_field("forti_severity_num", to_long(lookup_value("omni-forti-severity", to_string(\$message.level)), 0));
end
EOF

# ---- Enrichissement SEVERITE FORTIGATE NORMALISEE (forti_sev ----
# --- Brancher la regle dans le pipeline FortiGate, STAGE 5 (editer PL_FORTI de 12-graylog-pipelines.sh) ---
# Ajouter la ligne 'rule "omni-forti-05-severity"' au stage 5, puis relancer 12 (ensure_pipeline
# met a jour la source si elle change = idempotent). Bloc stage 5 resultant attendu :
#   stage 5 match either
#   rule "omni-forti-05-renommage"
#   rule "omni-forti-05-octets"
#   rule "omni-forti-05-severity"

# ---- Ventilation des echecs de connexion M365 par code d'ech ----
# ===========================================================================
# 1) CSV : lookups/m365-status.csv  (code Azure AD -> libelle FR)
#    Cle = status_code (keyword pose par le collecteur M365).
#    Couvre les codes vus en live (50053/50126/50014/500142/50074/50140/90094)
#    + les codes d'echec Azure AD usuels (le brief) pour les echecs a venir.
# ===========================================================================
cat > /root/omnitech-siem-setup/lookups/m365-status.csv <<'CSV'
status_code,label
0,Succes
50053,Compte verrouille (trop d'echecs)
50126,Identifiants invalides
50125,Reinitialisation/changement de mot de passe requis
50055,Mot de passe expire
50057,Compte desactive
50058,Session expiree (auth silencieuse impossible)
50059,Aucune information de tenant (utilisateur inconnu)
50034,Compte introuvable dans le tenant
50076,MFA requise (Conditional Access)
50074,MFA requise (preuve forte exigee)
50079,Enrolement MFA requis
50072,Inscription MFA utilisateur requise
53003,Bloque par Conditional Access
53004,MFA a configurer (Conditional Access)
53000,Appareil non conforme (Conditional Access)
53001,Appareil non enregistre/joint (Conditional Access)
53011,Acces bloque par evaluation de risque continue
50140,Interruption 'Rester connecte' (KMSI)
50158,Authentification externe/contexte requis
50097,Authentification de l'appareil requise
50105,Utilisateur non assigne a l'application
65001,Consentement applicatif requis
65004,Consentement utilisateur refuse
70044,Session expiree ou revoquee
50173,Jeton frais requis (mot de passe change)
50177,Jeton d'app externe requis
50133,Session invalide (mot de passe expire/recent)
50014,Limite invite atteinte (redemption en attente)
500142,Redemption invitee en cours
90094,Consentement administrateur requis
81010,SSO transparent : echec de validation du ticket Kerberos
81012,SSO transparent : utilisateur connecte different
CSV
echo "OK lookups/m365-status.csv ($(wc -l < /root/omnitech-siem-setup/lookups/m365-status.csv) lignes)"

# ---- Ventilation des echecs de connexion M365 par code d'ech ----
# ===========================================================================
# 2) Script idempotent : 48-m365-fail-codes.sh
#    - deploie le CSV  - ensure_lookup  - ensure_rule (pose m365_fail_label)
#    - pipeline DEDIE stage 15 (apres normalisation) connecte au seul
#      stream 'OMNI - M365'.
#    Modeles : ensure_lookup (37), ensure_rule/ensure_pipeline/connect (47).
#    Relancer 14-graylog-dashboards.sh ensuite pour les widgets.
# ===========================================================================
cat > /root/omnitech-siem-setup/48-m365-fail-codes.sh <<'SH'
#!/usr/bin/env bash
# =============================================================================
# 48-m365-fail-codes.sh - Ventilation des echecs de connexion M365 par CODE.
#   Les sign-in M365 portent le code Azure AD dans status_code (verifie live).
#   Ce script : table de lookup status_code->libelle FR (CSV m365-status.csv),
#   + regle pipeline (stage 15) qui pose m365_fail_label sur chaque echec
#   (event_action:echec_connexion), connectee au stream 'OMNI - M365'.
#   -> page 'M365' : echecs ventiles par libelle (relancer 14 ensuite).
# Idempotent. Prerequis : 12 (streams/pipelines). Relance 14 apres.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api
LOOKUP_DIR="/etc/graylog/lookup"

# (ensure_lookup canonique en en-tete)

echo "==> [1/4] Deploiement du CSV m365-status.csv"
install -m 644 lookups/m365-status.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/m365-status.csv" 2>/dev/null || true
ok "m365-status.csv deploye"

echo "==> [2/4] Table de lookup status_code -> libelle FR"
ensure_lookup "m365-status" "OMNI status_code M365 -> libelle FR" "m365-status.csv" "status_code" "label"

echo "==> [3/4] Regle d'enrichissement (pose m365_fail_label)"
# default_single_value 'Autre echec' couvre tout code non encore reference.
ensure_rule "omni-m365-15-faillabel" <<'EOF'
rule "omni-m365-15-faillabel"
when
  to_string($message.m365_type) == "signin"
  AND to_string($message.event_action) == "echec_connexion"
then
  let code = to_string($message.status_code);
  set_field("m365_fail_code", code);
  set_field("m365_fail_label", lookup_value("omni-m365-status", code));
end
EOF

echo "==> [4/4] Pipeline dedie (stage 15) + connexion au stream OMNI - M365"
PL_M365="$(ensure_pipeline "OMNI - Enrichissement M365" <<'EOF'
pipeline "OMNI - Enrichissement M365"
stage 15 match either
rule "omni-m365-15-faillabel"
end
EOF
)"
SID="$(get_stream_id "OMNI - M365")"
[[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_M365}" || warn "stream absent: OMNI - M365"

echo
echo "=== 48-m365-fail-codes.sh termine. Les NOUVEAUX echecs M365 portent"
echo "    m365_fail_label / m365_fail_code. Relancer 14-graylog-dashboards.sh"
echo "    pour la ventilation par libelle sur la page M365. ==="
SH
chmod +x /root/omnitech-siem-setup/48-m365-fail-codes.sh
echo OK 48-m365-fail-codes.sh

# ---- Exposition Internet + classe de port a risque (FortiGat ----
#!/usr/bin/env bash
# =============================================================================
# 49-expo-port-class.sh - Exposition Internet + classe de port a risque (FortiGate)
#   Enrichit chaque flux FortiGate avec :
#     - port_class    : classe du service destination (RDP/SSH/SMB/SQL/...) via
#                       lookup CSV dest_port -> classe (lookups/port-class.csv).
#     - net_direction : entrant / sortant / interne / transit, deduit des roles
#                       d'interface (srcintfrole / dstintfrole : wan|lan|dmz).
#     - expo_internet : "oui" si flux ENTRANT depuis le WAN ACCEPTE vers un port
#                       a risque -> port reellement exposable depuis Internet.
#   + page Reseau : top ports a risque exposes / acceptes depuis le WAN.
#
#   CHAMPS VERIFIES EN LIVE (omni-fortigate_*) :
#     - srcintfrole / dstintfrole : keyword, valeurs {lan, wan, dmz, undefined}.
#     - dest_port                 : keyword (chaine) -> lookup direct sur la valeur.
#     - action                    : keyword {accept, deny, pass, permit, blocked...}.
#     - src_ip_reserved_ip / dest_ip_reserved_ip : bool, mais SEULEMENT 'true' ou
#       ABSENT (jamais 'false') -> un IP publique = champ MANQUANT. On NE s'appuie
#       donc PAS sur reserved_ip pour la direction ; les roles d'interface (wan/lan)
#       sont le signal fiable.
# Idempotent. Prerequis : 12 (streams/pipelines FortiGate). Relance 14 ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api
LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/4] CSV lookups/port-class.csv (dest_port -> classe de port a risque)"
cat > lookups/port-class.csv <<'CSV'
dest_port,port_class
20,FTP
21,FTP
22,SSH
23,Telnet
25,SMTP
53,DNS
69,TFTP
110,POP3
111,RPC
135,RPC-DCOM
137,NetBIOS
138,NetBIOS
139,NetBIOS
143,IMAP
161,SNMP
162,SNMP
389,LDAP
445,SMB
465,SMTPS
512,rexec
513,rlogin
514,rsh-syslog
587,SMTP-Sub
636,LDAPS
873,rsync
993,IMAPS
995,POP3S
1080,SOCKS
1099,RMI
1433,SQL-Server
1434,SQL-Browser
1521,Oracle
1723,PPTP
2049,NFS
2082,cPanel
2083,cPanel
2222,SSH-Alt
2375,Docker
2376,Docker-TLS
2483,Oracle
2484,Oracle
3000,Web-Dev
3306,MySQL
3389,RDP
3390,RDP-Alt
4444,Metasploit
5000,Web-Dev
5432,PostgreSQL
5500,VNC
5555,ADB
5601,Kibana
5631,pcAnywhere
5900,VNC
5901,VNC
5985,WinRM
5986,WinRM-TLS
6000,X11
6379,Redis
6443,Kube-API
7001,WebLogic
8000,Web-Alt
8008,Web-Alt
8080,Web-Proxy
8081,Web-Proxy
8443,Web-Alt-TLS
8888,Web-Alt
9000,Web-Alt
9090,Web-Admin
9200,Elasticsearch
9300,Elasticsearch
10000,Webmin
11211,Memcached
15672,RabbitMQ
27017,MongoDB
27018,MongoDB
50000,SAP
CSV
install -m 644 lookups/port-class.csv "${LOOKUP_DIR}/"
chown root:graylog "${LOOKUP_DIR}/port-class.csv" 2>/dev/null || true
ok "port-class.csv deploye ($(($(wc -l < lookups/port-class.csv) - 1)) ports classes)"

# ensure_lookup <nom> <titre> <csv> <key_col> <val_col>  (modele 37-mitre-attack.sh)
# (ensure_lookup canonique en en-tete)

echo "==> [2/4] Table de lookup (dest_port -> port_class)"
ensure_lookup "port-class" "OMNI dest_port -> classe de port a risque" "port-class.csv" "dest_port" "port_class"

echo "==> [3/4] Regles d'enrichissement FortiGate (port_class + net_direction + expo_internet)"

# port_class : pose UNIQUEMENT si dest_port est un port a risque connu (le when
# teste la non-vacuite du lookup -> aucun champ vide sur le trafic banal).
ensure_rule "omni-forti-15-port-class" <<'EOF'
rule "omni-forti-15-port-class"
when
  to_string($message.event_source) == "fortigate" AND has_field("dest_port")
  AND to_string(lookup_value("omni-port-class", to_string($message.dest_port)), "") != ""
then
  set_field("port_class", to_string(lookup_value("omni-port-class", to_string($message.dest_port))));
end
EOF

# net_direction : deduit des ROLES d'interface (signal fiable). reserved_ip n'a
# que 'true'/absent, inutilisable seul. if/then/else imbrique (pas de reaffectation
# de let, non supportee par le langage de regles Graylog).
#   entrant : WAN -> non-WAN (exposition depuis Internet) ; sortant : non-WAN -> WAN ;
#   transit : WAN -> WAN ; interne : reste (LAN<->LAN, DMZ<->LAN, undefined...).
# net_direction via cidr_match (le champ reserved_ip est pose par le processeur
# GeoIP APRES les pipelines -> indisponible ici ; on teste les plages privees).
# Pose d'abord src_priv/dst_priv (oui/non) puis 3 regles de direction exclusives.
# IMPORTANT (anti-HALT) : when garde sur fortigate UNIQUEMENT (pas de has_field
# src_ip/dest_ip) : ce stage 14 est 'match either' avec une SEULE regle ; s'il ne
# matchait pas (log FortiGate sans src/dest IP : UTM/IPS, system, DNS...), le
# pipeline STOPPAIT -> stages 15/16 sautes (ni net_direction ni port_class ni
# exposition_internet). cidr_match(to_ip("",...)) = false -> src_priv/dst_priv
# valent false sur IP absente, sans erreur. Toujours matche => jamais de halt.
ensure_rule "omni-forti-14-privflags" <<'EOF'
rule "omni-forti-14-privflags"
when to_string($message.event_source) == "fortigate"
then
  set_field("src_priv",
    (cidr_match("10.0.0.0/8", to_ip(to_string($message.src_ip), "0.0.0.0"))
     OR cidr_match("192.168.0.0/16", to_ip(to_string($message.src_ip), "0.0.0.0"))
     OR cidr_match("172.16.0.0/12", to_ip(to_string($message.src_ip), "0.0.0.0"))));
  set_field("dst_priv",
    (cidr_match("10.0.0.0/8", to_ip(to_string($message.dest_ip), "0.0.0.0"))
     OR cidr_match("192.168.0.0/16", to_ip(to_string($message.dest_ip), "0.0.0.0"))
     OR cidr_match("172.16.0.0/12", to_ip(to_string($message.dest_ip), "0.0.0.0"))));
end
EOF
ensure_rule "omni-forti-15-dir-interne" <<'EOF'
rule "omni-forti-15-dir-interne"
when to_string($message.event_source) == "fortigate" AND to_bool($message.src_priv) == true AND to_bool($message.dst_priv) == true
then set_field("net_direction", "interne");
end
EOF
ensure_rule "omni-forti-15-dir-sortant" <<'EOF'
rule "omni-forti-15-dir-sortant"
when to_string($message.event_source) == "fortigate" AND to_bool($message.src_priv) == true AND to_bool($message.dst_priv) == false
then set_field("net_direction", "sortant");
end
EOF
ensure_rule "omni-forti-15-dir-entrant" <<'EOF'
rule "omni-forti-15-dir-entrant"
when to_string($message.event_source) == "fortigate" AND to_bool($message.src_priv) == false AND to_bool($message.dst_priv) == true
then set_field("net_direction", "entrant");
end
EOF
# 4e direction (public->public) : couvre le dernier quadrant src/dst pour qu'AU
# MOINS une regle de direction matche TOUJOURS au stage 15 (sinon halt sur les
# flux WAN<->WAN : local-out, transit, NAT). Avec les 4 regles, le stage 15 ne
# stoppe jamais le pipeline (stage 16 expo-internet toujours atteint).
ensure_rule "omni-forti-15-dir-transit" <<'EOF'
rule "omni-forti-15-dir-transit"
when to_string($message.event_source) == "fortigate" AND to_bool($message.src_priv) == false AND to_bool($message.dst_priv) == false
then set_field("net_direction", "transit");
end
EOF

# expo_internet : flux ENTRANT (source WAN), ACCEPTE, vers un port a risque
# (port_class pose au stage 15) = service reellement exposable depuis Internet.
ensure_rule "omni-forti-16-expo-internet" <<'EOF'
rule "omni-forti-16-expo-internet"
when
  to_string($message.event_source) == "fortigate"
  AND to_string($message.net_direction) == "entrant"
  AND has_field("port_class")
  AND (to_string($message.action) == "accept"
    OR to_string($message.action) == "pass"
    OR to_string($message.action) == "permit")
then
  set_field("expo_internet", "oui");
  set_field("alert_tag", "exposition_internet");
end
EOF

echo "==> [3b] Technique MITRE pour l'exposition (CSV 37 si present)"
CSV37="lookups/mitre-attack.csv"
if [[ -f "${CSV37}" ]]; then
  grep -q "^exposition_internet," "${CSV37}" \
    || { echo 'exposition_internet,T1190,Exploit Public-Facing Application,Initial Access,eleve,7' >> "${CSV37}"; ok "MITRE +exposition_internet"; }
  install -m 644 "${CSV37}" /etc/graylog/lookup/mitre-attack.csv
  chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
fi

echo "==> [4/4] Pipeline 'OMNI - Exposition reseau' (stages 15/16) + connexion FortiGate"
PL_EXPO="$(ensure_pipeline "OMNI - Exposition reseau" <<'EOF'
pipeline "OMNI - Exposition reseau"
stage 14 match either
rule "omni-forti-14-privflags"
stage 15 match either
rule "omni-forti-15-port-class"
rule "omni-forti-15-dir-interne"
rule "omni-forti-15-dir-sortant"
rule "omni-forti-15-dir-entrant"
rule "omni-forti-15-dir-transit"
stage 16 match either
rule "omni-forti-16-expo-internet"
end
EOF
)"
SID="$(get_stream_id 'OMNI - FortiGate')"
[[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_EXPO}" || warn "stream absent: OMNI - FortiGate"

echo
echo "=== 49-expo-port-class.sh termine. Relancer 14-graylog-dashboards.sh pour les widgets Reseau. ==="

echo "=== 49 termine. Relancer 14+13. ==="
