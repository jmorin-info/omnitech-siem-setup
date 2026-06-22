#!/usr/bin/env bash
# =============================================================================
# 81-fp-allowlist.sh - REDUCTION DES FAUX POSITIFS (AXE A / priorite RSSI)
#   Mecanisme ADDITIF et REVERSIBLE : une ALLOWLIST de motifs benins connus
#   (CSV lookups/fp-allowlist.csv) + un pipeline dedie "OMNI - Allowlist FP"
#   pose a STAGE 25 -- soit APRES l'enrichissement MITRE (stage 20, qui pose
#   risk_score / mitre_technique / risk_severity) et AVANT la reduction ISO
#   (stage 30). Pour un evenement reconnu benin la regle :
#       set_field("fp_allowlist", true);
#       set_field("fp_allowlist_reason", <motif>);
#       remove_field("alert_tag");          # <- supprime l'ALERTE, pas l'evenement
#   => les event definitions qui interrogent  alert_tag:scheduled_task  /
#      alert_tag:service_install  (count>=1, fenetre 1 h, mail+Teams) NE
#      MATCHENT PLUS le bruit allowliste, MAIS l'evenement reste indexe avec
#      tout son enrichissement (visibilite + scoring conserves : risk_score,
#      mitre_technique, risk_severity sont deja poses au stage 20).
#   Aucun evenement n'est jete. Aucune alerte/notification n'est modifiee.
#
#   MESURES TERRAIN (OpenSearch omni-winsec*/omni-sysmon*, 30 j) :
#     scheduled_task  : 77 evts, 75 (97%) = auto-update logiciel legitime.
#     service_install : 317 evts, 273 (86%) = agents/outils legitimes
#                       (dont nos propres winlogbeat / Sysmon64 / SysmonDrv).
#     persistence_autorun : 1301 evts ~100% FP (msedge/OneDrive/Lists) ; PAS
#                       d'alerte count>=1 cablee -> nettoye ici aussi (dashboards).
#
#   POURQUOI substring + CSV : le csvfile Graylog fait du lookup EXACT, or
#   plusieurs familles benignes ont un suffixe VARIABLE (Windows Hello
#   CredentialEnrollmentManagerUserSvc_<hex>, MicrosoftEdgeAutoLaunch_<hash>,
#   OneDrive Standalone Update Task-<SID>). On combine donc :
#     (A) table lookup 'omni-fp-allowlist' (cle EXACTE) pour les noms STABLES
#         -> EXTENSIBLE par simple ajout de ligne dans le CSV ;
#     (B) un bloc contains() balise '### FAMILLES A SUFFIXE VARIABLE ###' pour
#         les familles dont seul un FRAGMENT de chemin/nom est stable
#         -> EXTENSIBLE en ajoutant une ligne OR.
#
#   REVERSIBILITE : deconnecter le pipeline des streams (UI Pipelines) OU vider
#   le CSV + retirer le bloc (B) puis relancer ce script. Le champ fp_allowlist
#   n'existe nulle part avant ce script (verifie : 0 doc).
#
#   Idempotent. Prerequis : 12 (streams/pipelines) + 37 (enrichissement MITRE
#   stage 20). NE relance PAS d'alerte (les alertes existantes restent telles
#   quelles). Voir la section "ETENDRE L'ALLOWLIST" en bas de ce fichier.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
LOOKUP_DIR="/etc/graylog/lookup"

echo "==> [1/4] Deploiement du CSV d'allowlist + table de lookup"
# IMPORTANT : le CSVFileDataAdapter de Graylog REJETTE TOUT le fichier si une seule
# ligne n'a pas 2 colonnes (IllegalStateException "invalid lines"). Les lignes de
# commentaire '#' (NF=1) cassaient donc la table -> lookup VIDE (allowlist morte).
# On livre une version FILTREE (en-tete 'match_key,reason' + lignes de donnees) ;
# les commentaires restent dans la source versionnee lookups/fp-allowlist.csv.
grep -vE '^[[:space:]]*(#|$)' lookups/fp-allowlist.csv > "${LOOKUP_DIR}/fp-allowlist.csv"
chmod 644 "${LOOKUP_DIR}/fp-allowlist.csv"
chown root:graylog "${LOOKUP_DIR}/fp-allowlist.csv" 2>/dev/null || true
ok "fp-allowlist.csv (filtre, sans commentaires) deploye dans ${LOOKUP_DIR}/"
# Table cle->raison. Cle EXACTE (case_insensitive_lookup=true via ensure_lookup).
# On indexe sur 'match_key' (motif benin normalise) et on recupere 'reason'.
ensure_lookup "fp-allowlist" "OMNI Allowlist FP (motif benin -> raison)" \
              "fp-allowlist.csv" "match_key" "reason"

echo "==> [2/4] Regles d'allowlist (1 par detection ciblee ; 1 condition par regle)"

# --- service_install (4697) ---------------------------------------------------
# (A) cle EXACTE : ServiceName stable (winlogbeat, Sysmon64, SysmonDrv, IntelTACD,
#     com.docker.service, TeamViewer, AnyDesk, NTP, VBox*...) -> via la table CSV.
# (B) FAMILLES A SUFFIXE VARIABLE : on teste un FRAGMENT de chemin .exe constant.
#     CredentialEnrollmentManager (Windows Hello) a un ServiceName aleatoire
#     (CredentialEnrollmentManagerUserSvc_<hex>) -> seul le chemin .exe est stable.
ensure_rule "omni-fp-25-service-install" <<'EOF'
rule "omni-fp-25-service-install"
when
  to_string($message.alert_tag) == "service_install"
  AND (
    is_not_null(lookup_value("omni-fp-allowlist",
        lowercase(to_string($message.winlogbeat_winlog_event_data_ServiceName))))
    ### FAMILLES A SUFFIXE VARIABLE / chemins stables (etendre par une ligne OR) ###
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "credentialenrollmentmanager.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\winlogbeat\\winlogbeat.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\sysmon64.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\sysmondrv.sys", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\teamviewer\\teamviewer_service.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\anydesk\\anydesk.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\oracle\\virtualbox\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\drivers\\vbox", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "com.docker.service", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\googleupdater\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\drivers\\inteltacd.sys", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "cowork-svc.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_ServiceFileName), "\\ntp\\bin\\ntpd.exe", true)
  )
then
  set_field("fp_allowlist", true);
  set_field("fp_allowlist_reason", "service_install: outil/agent legitime (allowlist 81)");
  remove_field("alert_tag");
end
EOF

# --- scheduled_task (4698) ----------------------------------------------------
# Familles d'auto-update / maintenance logiciel (TaskName a prefixe stable).
# Inclut explicitement les taches de deploiement OMNITECH (\OMNI-SIEM-Deploy,
# \OMNI-Inventory) comme demande, en plus du bruit logiciel observe.
ensure_rule "omni-fp-25-scheduled-task" <<'EOF'
rule "omni-fp-25-scheduled-task"
when
  to_string($message.alert_tag) == "scheduled_task"
  AND (
    is_not_null(lookup_value("omni-fp-allowlist",
        lowercase(to_string($message.winlogbeat_winlog_event_data_TaskName))))
    ### FAMILLES A SUFFIXE VARIABLE / prefixe de chemin stable (etendre par OR) ###
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "\\googleuserpeh\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "\\googlesystem\\googleupdater", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "\\powertoys\\autorun", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "mozilla", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "onedrive standalone update", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "\\microsoft\\windows\\restartmanager\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "ccleaner", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "softlanding", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "\\omni-siem-deploy", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TaskName), "\\omni-inventory", true)
  )
then
  set_field("fp_allowlist", true);
  set_field("fp_allowlist_reason", "scheduled_task: maintenance/MAJ logiciel legitime (allowlist 81)");
  remove_field("alert_tag");
end
EOF

# --- persistence_autorun (Sysmon 13) ------------------------------------------
# ~100% FP mesure (msedge / OneDrive / Microsoft.Lists). Pas d'alerte count>=1
# cablee, mais on nettoie le bruit dashboard/scoring de la meme facon.
# Garde-fou : on n'allowliste QUE si le process ecrivain est un binaire de
# confiance OU si la valeur de cle Run appartient a une famille benigne connue.
ensure_rule "omni-fp-25-autorun" <<'EOF'
rule "omni-fp-25-autorun"
when
  to_string($message.alert_tag) == "persistence_autorun"
  AND (
       contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "microsoftedgeautolaunch", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "msedge_cleanup", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "delete cached", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "\\run\\microsoft.lists", true)
    OR ( ( contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\microsoft onedrive\\", true)
        OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\appdata\\local\\microsoft\\onedrive\\", true) )
       AND contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "\\run\\onedrive", true) )
    OR ( contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\edge\\application\\msedge.exe", true)
       AND contains(to_string($message.winlogbeat_winlog_event_data_TargetObject), "\\runonce\\", true) )
    // [Audit FP] ecrivain = binaire signe MS/editeur dans SON chemin de confiance (auto-reference) :
    // OneDrive (Setup/Sync), msedge (toute cle Run), VS Installer, EdgeWebView, Copilot. CHEMIN-ancre
    // (pas le nom seul) -> garde-fou usurpation. Mesure : ~817/1000 residuels couverts, 0 suspect.
    OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\microsoft onedrive\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\appdata\\local\\microsoft\\onedrive\\", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\onedrivesetup.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\edge\\application\\msedge.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\microsoft visual studio\\installer\\setup.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\edgewebview\\application\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_Image), "\\microsoft\\copilot\\application\\mscopilot.exe", true)
  )
then
  set_field("fp_allowlist", true);
  set_field("fp_allowlist_reason", "persistence_autorun: navigateur/OneDrive/VS/Copilot signe (allowlist 81)");
  remove_field("alert_tag");
end
EOF

# --- sysmon_injection (Sysmon 8/25) -------------------------------------------
# Mesure : ~99% FP. Parc TRES orienté dev -> le bruit dominant = les DEBUGGEURS
# Visual Studio (devenv/msvsmon) qui "injectent" dans les builds en cours de debug
# (\bin\Debug\, \source\repos\), + logiciels signes (Citrix appprotection, Autodesk,
# NinjaRemote) et processus systeme (svchost/dllhost/WerFault/explorer). 0 cible
# lsass observee. GARDE-FOU ABSOLU : on n'allowliste JAMAIS une injection vers lsass
# (vol d'identifiants) -> elle continue d'alerter. L'evenement reste indexe (scoring).
ensure_rule "omni-fp-25-sysmon-injection" <<'EOF'
rule "omni-fp-25-sysmon-injection"
when
  to_string($message.alert_tag) == "sysmon_injection"
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_TargetImage), "\\lsass.exe", true)
  AND (
       ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\devenv.exe", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\msvsmon.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\vsdbg", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\remote debugger\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TargetImage), "\\bin\\debug\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TargetImage), "\\bin\\release\\", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_TargetImage), "\\source\\repos\\", true)
    OR starts_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "C:\\Program Files", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\werfault.exe", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\svchost.exe", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\dllhost.exe", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\wudfhost.exe", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\explorer.exe", true)
    OR ends_with(to_string($message.winlogbeat_winlog_event_data_SourceImage), "\\code.exe", true)
    OR contains(to_string($message.winlogbeat_winlog_event_data_SourceImage), "antigravity", true)
  )
then
  set_field("fp_allowlist", true);
  set_field("fp_allowlist_reason", "sysmon_injection: injecteur legitime (debugger/programme signe/systeme ; jamais lsass)");
  remove_field("alert_tag");
end
EOF

# --- admin_share (5140/5145) : acces C$ en LOOPBACK ---------------------------
# Mesure (audit FP) : ~99% du volume = la machine accedant a SON PROPRE C$ via
# 127.0.0.1/::1 -> PAS du mouvement lateral (le lateral est DISTANT par definition :
# la cible logue l'IP source distante de l'attaquant, jamais loopback). Les acces
# C$ DISTANTS (autre IP) continuent d'alerter (vrai vecteur PsExec/SMB). 0 VP perdu.
ensure_rule "omni-fp-25-adminshare-loopback" <<'EOF'
rule "omni-fp-25-adminshare-loopback"
when
  to_string($message.alert_tag) == "admin_share"
  AND ( to_string($message.winlogbeat_winlog_event_data_IpAddress) == "127.0.0.1"
     OR to_string($message.winlogbeat_winlog_event_data_IpAddress) == "::1" )
then
  set_field("fp_allowlist", true);
  set_field("fp_allowlist_reason", "admin_share: acces C$ local (loopback) = pas de lateral");
  remove_field("alert_tag");
end
EOF

# --- powershell_suspect : -EncodedCommand wrappe par Claude Code -----------------
# Mesure (audit FP) : 1222/1241 (98,5%) ont ParentImage=claude.exe (Claude Code sur
# postes dev : npm/pkg/winget). 200 payloads -enc decodes = 100% automation benigne ;
# 0/1222 indicateur malveillant sur 30j. GARDE-FOU (decision RSSI, go Julien) : on
# n'allowliste QUE si parent=claude.exe ET enfant=powershell.exe ET le motif est -enc,
# JAMAIS un indicateur de telechargement/credential (meme en clair). Les enfants pwsh/
# bash et les parents node.exe restent alertes. Masquerade = meme risque que sysmon_injection.
ensure_rule "omni-fp-25-ps-claude" <<'EOF'
rule "omni-fp-25-ps-claude"
when
  to_string($message.alert_tag) == "powershell_suspect"
  AND ends_with(to_string($message.winlogbeat_winlog_event_data_ParentImage), "\\claude.exe", true)
  AND ends_with(to_string($message.winlogbeat_winlog_event_data_Image), "\\powershell.exe", true)
  // Couvre les 2 motifs benins de Claude Code : -EncodedCommand (wrapper npm/pkg/winget)
  // ET -ExecutionPolicy Bypass -Command "$env:Path = ...GetEnvironmentVariable" (setup PATH).
  // GARDE-FOU : denylist EXHAUSTIVE d'indicateurs malveillants EN CLAIR (download/exec/cred/
  // obfusc/furtivite). En -enc le payload est encode -> la surete repose sur parent=claude.exe
  // (200 payloads decodes par l'audit = 100% benins, 0/1222 malveillant sur 30j). Enfants
  // pwsh/bash et parents node.exe NON couverts (restent alertes).
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "downloadstring", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "downloadfile", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "downloaddata", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "invoke-webrequest", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "webclient", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "bitstransfer", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "bitsadmin", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "certutil", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "frombase64string", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "invoke-expression", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "iex(", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "mimikatz", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "sekurlsa", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "comsvcs", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "reflection.assembly", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), "-windowstyle hidden", true)
  AND NOT contains(to_string($message.winlogbeat_winlog_event_data_CommandLine), " -w hidden", true)
then
  set_field("fp_allowlist", true);
  set_field("fp_allowlist_reason", "powershell_suspect: Claude Code (env-setup/-EncodedCommand benin ; aucun indicateur download/exec/cred)");
  remove_field("alert_tag");
end
EOF

echo "==> [3/4] Pipeline 'OMNI - Allowlist FP' (stage 25) + connexion streams"
# Stage 25 = APRES MITRE (20) donc risk_score/mitre_* deja poses (scoring garde),
# AVANT la reduction ISO (30). match either : une seule des 3 regles s'applique.
PL="$(ensure_pipeline "OMNI - Allowlist FP" <<'PIPE'
pipeline "OMNI - Allowlist FP"
stage 25 match either
rule "omni-fp-25-service-install"
rule "omni-fp-25-scheduled-task"
rule "omni-fp-25-autorun"
rule "omni-fp-25-sysmon-injection"
rule "omni-fp-25-adminshare-loopback"
rule "omni-fp-25-ps-claude"
end
PIPE
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon"; do
  SID="$(get_stream_id "$ST")"
  [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL" || warn "stream absent: $ST"
done

echo "==> [4/4] Recapitulatif"
ok "Allowlist active. fp_allowlist=true + alert_tag retire pour les motifs benins."
skip "Les evenements restent indexes AVEC risk_score / mitre_technique (stage 20)."
skip "Aucune alerte modifiee ; aucun evenement supprime ; entierement reversible."
echo
echo "=== 81 termine. ==="
echo "Verifier l'effet (apres ~1 cycle d'ingestion) :"
echo "  - bruit residuel :  alert_tag:scheduled_task   /  alert_tag:service_install"
echo "  - allowlistes     :  fp_allowlist:true  (visibles, scores, hors alerte)"
echo
echo "ETENDRE L'ALLOWLIST :"
echo "  * Nom STABLE (service a nom fixe, tache a chemin fixe) -> ajouter une ligne"
echo "    dans lookups/fp-allowlist.csv :   <motif_minuscule>,<raison>"
echo "    (le cache lookup se rafraichit en <=60 s ; pas besoin de relancer 81)."
echo "  * Famille a SUFFIXE VARIABLE (chemin .exe constant) -> ajouter une ligne OR"
echo "    sous le marqueur '### FAMILLES A SUFFIXE VARIABLE ###' de la regle"
echo "    concernee, puis relancer  bash ./81-fp-allowlist.sh  (idempotent)."
echo "  * NE relance NI 13 NI 14 : aucune alerte/notification n'a change."
