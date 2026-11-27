#!/usr/bin/env python3
# OMNITECH SIEM v5 - chantier 1 « Détections AD et Microsoft 365 » (27/11/2026, go jmorin).
# Usage (root, sur BX-IT-GRAYLOG-VM, dans /root/omni-v5-ad) :
#   python3 -I v5_ad_build.py --simuler          syntaxe des règles + streams + définitions, ne crée rien
#   python3 -I v5_ad_build.py --rejeu            rejeu 30 jours (logique identique aux règles, en Python) -> rejeu.json
#   python3 -I v5_ad_build.py --appliquer        sauvegarde, crée/maj (idempotent), écrit retour.sh
#   python3 -I v5_ad_build.py --mesure           latence de traitement, tampons, journal
#   python3 -I v5_ad_build.py --retour-simuler   liste ce que --retour supprimerait
#   python3 -I v5_ad_build.py --retour           supprime PAR NOM tous les objets du chantier 1 (et rien d'autre)
#   python3 -I v5_ad_build.py --source           affiche la source des règles et du pipeline (hors ligne)
# Aucun secret affiché ni écrit.
# Valeurs propres au site (contrôleurs de domaine, compte Entra Connect, compte leurre, fichiers canaris, GPO
# réécrite par l'agent RMM, domaines de messagerie, notifications) : /etc/omni-v5-ad/site.json, ou le fichier
# désigné par OMNI_V5_AD_SITE. Modèle : site.exemple.json. Avec les valeurs réelles du site, les règles, le pipeline
# et les requêtes produits sont identiques à ceux en production.
import collections, datetime as dt, json, os, re, subprocess, sys, time
sys.path.insert(0, "/root/omni-v5-ad")
from v5_lib import api, osq, total

MODE = sys.argv[1] if len(sys.argv) > 1 else "--simuler"
TS = time.strftime("%Y%m%d-%H%M")
SAUV = f"/var/backups/siem/v5-ad-avant-{TS}"
PIPE_TITLE = "OMNI v5 - Detections AD et M365"
PIPE_STREAMS = ["OMNI - Windows Security", "OMNI - Windows autres", "OMNI - Sysmon", "OMNI - M365"]
DESC_REGLE = "OMNITECH SIEM v5 chantier 1 (27/11/2026)"

# ------------------------------------------------------------------ valeurs du site
SITE_FICHIER = os.environ.get("OMNI_V5_AD_SITE", "/etc/omni-v5-ad/site.json")
try:
    with open(SITE_FICHIER, encoding="utf-8") as _f:
        SITE = json.load(_f)
except (OSError, ValueError) as _e:
    sys.exit(f"valeurs du site illisibles : {SITE_FICHIER} ({type(_e).__name__}) ; copier et adapter site.exemple.json")
N_TEAMS, N_TRIAGE = SITE["notifications"]["teams"], SITE["notifications"]["triage"]
REPLICATION = SITE["comptes_replication"]            # comptes machine des DC + compte Entra Connect exact (casse de l'annuaire)
DC_ALLOW = [a.lower() for a in REPLICATION]
ENTRA = SITE["compte_entra_connect"].lower()
TIER0 = [h.lower() for h in SITE["hotes_tier0"]]     # contrôleurs de domaine et autorités de certification
LEURRE = SITE["compte_leurre"].lower()
TAG_LEURRE = "leurre_" + re.sub(r"[^a-z0-9]+", "_", LEURRE).strip("_")
CANARIS = SITE["fichiers_canaris"]
CA_MACHINE = SITE["compte_machine_ca"].lower()        # compte machine de l'autorité de certification (republication AIA)
GPO_AGENT = SITE["gpo_agent_rmm"].lower()             # GUID entre accolades de la GPO réécrite par l'agent RMM
GMSA_SAUV = SITE["prefixe_gmsa_sauvegarde"].lower()   # préfixe du gMSA qui installe VeeamVssSupport
RMM_DOSSIER = SITE["dossier_agent_rmm"].lower()       # dossier d'installation propre à l'organisation dans l'agent RMM
DOMAINES = SITE["domaines_messagerie"]                # domaines internes (transfert vers un autre domaine = externe)
DOM_RX_REGLE = "|".join(d.lower().replace(".", "\\\\.") for d in DOMAINES)
DOM_RX = re.compile(r"(?i)@(" + "|".join(re.escape(d.lower()) for d in DOMAINES) + r")\s*$")

# ------------------------------------------------------------------ règles
R = collections.OrderedDict()
def F(n): return f"to_string($message.winlogbeat_winlog_event_data_{n})"
EID = "to_string($message.winlogbeat_winlog_event_id)"

def tags(tag, sev, mitre, entite, detail):
    return (f'  set_field("v5_tag", "{tag}");\n  set_field("v5_severite", "{sev}");\n  set_field("v5_mitre", "{mitre}");\n'
            f'  set_field("v5_entite", lowercase({entite}));\n  set_field("v5_detail", {detail});\n')

R["omni-v5-ad-kerberoast-aes"] = f'''rule "omni-v5-ad-kerberoast-aes"
// Kerberoasting en AES : RC4 est désactivé sur le domaine, les détections existantes (0x17) ne peuvent plus rien voir.
// TGS réussi vers un COMPTE UTILISATEUR (pas $, pas krbtgt), hors ticket vers soi-même (U2U).
when
  {EID} == "4769" &&
  {F("Status")} == "0x0" &&
  has_field("winlogbeat_winlog_event_data_ServiceName") &&
  !contains({F("ServiceName")}, "$") &&
  !starts_with(lowercase({F("ServiceName")}), "krbtgt") &&
  lowercase({F("ServiceName")}) != "{LEURRE}" &&
  lowercase({F("ServiceName")}) != lowercase(to_string(regex("^([^@]+)", {F("TargetUserName")}, ["u"])["u"]))
then
{tags("kerberoast_aes", "ELEVE", "T1558.003", F("TargetUserName"), 'concat("TGS vers le compte utilisateur ", ' + F("ServiceName") + ')')}end'''

R[f"omni-v5-ad-leurre-{LEURRE}"] = f'''rule "omni-v5-ad-leurre-{LEURRE}"
// Compte leurre (site.json, compte_leurre) : aucun usage légitime, ne jamais le modifier. Absent de la table omni-deception.
when
  lowercase({F("TargetUserName")}) == "{LEURRE}" ||
  starts_with(lowercase({F("TargetUserName")}), "{LEURRE}@") ||
  lowercase({F("ServiceName")}) == "{LEURRE}" ||
  lowercase({F("SubjectUserName")}) == "{LEURRE}" ||
  contains(lowercase({F("ObjectDN")}), "cn={LEURRE},")
then
{tags(TAG_LEURRE, "CRITIQUE", "T1558.003", '"' + LEURRE + '"', 'concat(concat("Evenement ", ' + EID + '), " sur le compte leurre")')}end'''

R["omni-v5-ad-asrep-preparation"] = f'''rule "omni-v5-ad-asrep-preparation"
// AS-REP roasting ciblé : quelqu'un retire la pré-authentification Kerberos d'un compte (UAC 0x400000).
when
  ({EID} == "4738" &&
   regex("(?i)(%%2096|pr[ée]-?auth[^\\\\n]*(activ|enabl))", {F("UserAccountControl")}).matches == true) ||
  ({EID} == "5136" &&
   {F("AttributeLDAPDisplayName")} == "userAccountControl" &&
   {F("OperationType")} == "%%14674" &&
   (to_long($message.winlogbeat_winlog_event_data_AttributeValue, 0) / 4194304) % 2 == 1)
then
{tags("asrep_preparation", "ELEVE", "T1558.004", 'to_string($message.winlogbeat_winlog_event_data_SubjectUserName)', 'concat("Pre-authentification Kerberos retiree : ", to_string($message.winlogbeat_winlog_event_data_TargetUserName, ' + F("ObjectDN") + '))')}end'''

R["omni-v5-ad-dcsync"] = f'''rule "omni-v5-ad-dcsync"
// DCSync : droits de réplication (Get-Changes, -All, -In-Filtered-Set au bon GUID 89e95b76-444d...) exercés par
// un compte autre que les 3 DC et le compte Entra Connect EXACT. La règle existante exclut tout compte $ et tout MSOL_*.
when
  {EID} == "4662" &&
  (contains({F("Properties")}, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", true) ||
   contains({F("Properties")}, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", true) ||
   contains({F("Properties")}, "89e95b76-444d-4c62-991a-0facbeda640c", true)) &&
''' + " &&\n".join(f'  lowercase({F("SubjectUserName")}) != "{a}"' for a in DC_ALLOW) + f'''
then
{tags("dcsync", "CRITIQUE", "T1003.006", F("SubjectUserName"), 'concat("Replication d\'annuaire demandee par ", ' + F("SubjectUserName") + ')')}end'''

R["omni-v5-ad-shadow-credentials"] = f'''rule "omni-v5-ad-shadow-credentials"
// Shadow Credentials : écriture de msDS-KeyCredentialLink par un autre acteur que le compte Entra Connect EXACT
// (la règle existante exclut SYSTEM et tout MSOL_*) ; l'écriture d'un ordinateur sur son propre objet est exclue.
when
  {EID} == "5136" &&
  lowercase({F("AttributeLDAPDisplayName")}) == "msds-keycredentiallink" &&
  lowercase({F("SubjectUserName")}) != "{ENTRA}" &&
  !(ends_with({F("SubjectUserName")}, "$") &&
    starts_with(lowercase({F("ObjectDN")}), concat(concat("cn=", lowercase(regex_replace("\\\\$$", {F("SubjectUserName")}, ""))), ",")))
then
{tags("shadow_credentials", "CRITIQUE", "T1556", F("SubjectUserName"), 'concat("msDS-KeyCredentialLink modifie sur ", ' + F("ObjectDN") + ')')}end'''

R["omni-v5-ad-adcs-san"] = f'''rule "omni-v5-ad-adcs-san"
// AD CS ESC1/ESC6 : demande (4886) portant un SAN de type UPN, attribut de requête « SAN: », ou certificat émis (4887)
// dont l'UPN du SAN n'est pas celui du demandeur. Au 27/11, aucune demande légitime ne porte d'UPN (auto-inscription :
// SAN ajouté par la CA depuis l'annuaire ; OMS-WebServer : noms DNS uniquement).
when
  ({EID} == "4886" &&
   regex("(?i)(nom principal|principal name|autre nom|other name|upn=)", {F("SubjectAlternativeName")}).matches == true) ||
  (({EID} == "4886" || {EID} == "4887") &&
   regex("(?i)(^|\\\\n)\\\\s*san:", {F("Attributes")}).matches == true) ||
  ({EID} == "4887" &&
   regex("(?i)(?:nom principal|principal name)=([^@\\\\s]+)@", {F("SubjectAlternativeName")}).matches == true &&
   lowercase(to_string(regex("(?i)(?:nom principal|principal name)=([^@\\\\s]+)@", {F("SubjectAlternativeName")}, ["u"])["u"])) !=
     lowercase(to_string(regex("([^\\\\\\\\]+)$", {F("Requester")}, ["r"])["r"])))
then
{tags("adcs_san", "CRITIQUE", "T1649", F("Requester"), 'concat(concat(concat("Demande ", ' + F("RequestId") + '), " SAN "), ' + F("SubjectAlternativeName") + ')')}end'''

R["omni-v5-ad-adcs-modele-ca"] = f'''rule "omni-v5-ad-adcs-modele-ca"
// AD CS ESC4/ESC7/ESC6 : modification d'un modèle (4899/4900, 5136 pKICertificateTemplate), de la sécurité de la CA (4882),
// de sa configuration (4885/4890/4892) ou de CN=Public Key Services (NTAuth, services d'inscription).
// Au 27/11 AUCUNE de ces sources n'est journalisée (filtre d'audit CA partiel, pas de SACL sur la partition Configuration) :
// règle prête, alimentée dès la pose de l'audit (script Activer-Audit-ADCS.ps1, décision jmorin).
when
  (to_string($message.winlogbeat_winlog_channel) == "Security" &&
   ({EID} == "4882" || {EID} == "4885" || {EID} == "4890" || {EID} == "4892" || {EID} == "4899" || {EID} == "4900")) ||
  ({EID} == "5136" &&
   (lowercase({F("ObjectClass")}) == "pkicertificatetemplate" ||
    lowercase({F("ObjectClass")}) == "pkienrollmentservice" ||
    lowercase({F("ObjectClass")}) == "certificationauthority" ||
    contains(lowercase({F("ObjectDN")}), "cn=public key services,")) &&
   // FP prouvé 27/11 11:55 : la CA republie cACertificateDN sur son objet AIA à chaque démarrage de certsvc
   !(lowercase({F("SubjectUserName")}) == "{CA_MACHINE}" &&
     {F("AttributeLDAPDisplayName")} == "cACertificateDN" &&
     contains(lowercase({F("ObjectDN")}), ",cn=aia,cn=public key services,")))
then
{tags("adcs_modele_ca", "ELEVE", "T1649", 'to_string($message.winlogbeat_winlog_event_data_SubjectUserName, to_string($message.source))', 'concat(concat("AD CS modifie (evenement ", ' + EID + '), ")")')}end'''

T0_COND = " ||\n   ".join(f'lowercase(to_string($message.source)) == "{h}"' for h in TIER0)
IMG = "lowercase(to_string($message.winlogbeat_winlog_event_data_ImagePath))"
R["omni-v5-ad-service-tier0"] = f'''rule "omni-v5-ad-service-tier0"
// Persistance : service installé (7045) sur un contrôleur de domaine ou une PKI. Exclusions PROUVÉES sur 30 jours,
// par binaire à son chemin d'installation : Veeam (gMSA), ESET, NinjaOne, VMware Tools, Sysmon, Winlogbeat, Defender.
when
  {EID} == "7045" &&
  ({T0_COND}) &&
  !(to_string($message.winlogbeat_winlog_event_data_ServiceName) == "VeeamVssSupport" &&
    contains({IMG}, "c:\\\\windows\\\\veeamvsssupport\\\\veeamguesthelper.exe") &&
    starts_with(lowercase(to_string($message.winlogbeat_winlog_user_name)), "{GMSA_SAUV}")) &&
  !starts_with({IMG}, "\\"c:\\\\program files\\\\eset\\\\") &&
  !starts_with({IMG}, "\\"c:\\\\programdata\\\\eset\\\\remoteadministrator\\\\") &&
  regex("^(\\\\\\\\systemroot\\\\\\\\)?system32\\\\\\\\drivers\\\\\\\\(eamonm|ehdrv|eelam|epfw|epfwwfp)\\\\.sys$", {IMG}).matches == false &&
  !starts_with({IMG}, "\\"c:\\\\program files (x86)\\\\ninjaone\\\\") &&
  !starts_with({IMG}, "\\"c:\\\\program files\\\\ninjaremote\\\\") &&
  regex("^\\"c:\\\\\\\\program files \\\\(x86\\\\)\\\\\\\\{RMM_DOSSIER}-[0-9.]+\\\\\\\\(njvmagent|nmsmanager|ninjarmmagent|ninjarmmagentpatcher)\\\\.exe\\"", {IMG}).matches == false &&
  !starts_with({IMG}, "\\"c:\\\\program files\\\\vmware\\\\vmware tools\\\\") &&
  regex("^(\\\\\\\\systemroot\\\\\\\\)?system32\\\\\\\\(drivers|driverstore\\\\\\\\filerepository\\\\\\\\vm3d\\\\.inf_amd64_[0-9a-f]+)\\\\\\\\(vm[a-z0-9_-]*|vsock|vmci)\\\\.sys$", {IMG}).matches == false &&
  !({IMG} == "c:\\\\windows\\\\system32\\\\dllhost.exe /processid:{{480b4670-6610-4465-b6c5-e9b5c4e0da31}}") &&
  {IMG} != "c:\\\\windows\\\\sysmon64.exe" &&
  {IMG} != "c:\\\\windows\\\\sysmondrv.sys" &&
  !starts_with({IMG}, "\\"c:\\\\program files\\\\winlogbeat\\\\winlogbeat.exe\\"") &&
  !starts_with({IMG}, "\\"c:\\\\programdata\\\\microsoft\\\\windows defender\\\\platform\\\\") &&
  regex("^system32\\\\\\\\drivers\\\\\\\\(wd\\\\\\\\[a-z0-9]+|ksld)\\\\.sys$", {IMG}).matches == false
then
{tags("service_tier0", "ELEVE", "T1543.003", "to_string($message.source)", 'concat(concat(to_string($message.winlogbeat_winlog_event_data_ServiceName), " -> "), to_string($message.winlogbeat_winlog_event_data_ImagePath))')}end'''

R["omni-v5-ad-gpo-sensible"] = f'''rule "omni-v5-ad-gpo-sensible"
// Persistance par GPO : (a) lien de GPO modifié sur la racine du domaine ou l'OU Domain Controllers (non couvert par
// omni-extra-10-gpo, qui ne regarde que groupPolicyContainer) ; (b) GPO modifiée par SYSTEM ou un compte machine
// (exclus par la règle existante), hors GPO de déploiement de l'agent RMM réécrite 2 fois par heure par l'agent (site.json).
when
  {EID} == "5136" &&
  ((lowercase({F("AttributeLDAPDisplayName")}) == "gplink" &&
    (lowercase({F("ObjectClass")}) == "domaindns" || starts_with(lowercase({F("ObjectDN")}), "ou=domain controllers,"))) ||
   (lowercase({F("ObjectClass")}) == "grouppolicycontainer" &&
    ({F("SubjectUserSid")} == "S-1-5-18" || ends_with({F("SubjectUserName")}, "$")) &&
    !contains(lowercase({F("ObjectDN")}), "{GPO_AGENT}")))
then
{tags("gpo_sensible", "ELEVE", "T1484.001", F("SubjectUserName"), 'concat(concat(' + F("AttributeLDAPDisplayName") + ', " modifie sur "), ' + F("ObjectDN") + ')')}end'''

SI = "lowercase(to_string($message.winlogbeat_winlog_event_data_SourceImage))"
GA = "to_string($message.winlogbeat_winlog_event_data_GrantedAccess)"
R["omni-v5-ad-lsass-lecture"] = f'''rule "omni-v5-ad-lsass-lecture"
// Accès LSASS avec droit de lecture mémoire (bit PROCESS_VM_READ 0x10, quel que soit le masque) par un binaire hors
// liste stricte (chemin complet + masque observé). Comble : masques absents de la liste existante (0x1418, 0x12f4d0...)
// et l'exclusion large *NinjaOne* / *WerFaultSecure* de la définition existante (WerFaultSecure sert aux vidages LSASS).
when
  {EID} == "10" &&
  ends_with(lowercase(to_string($message.winlogbeat_winlog_event_data_TargetImage)), "\\\\lsass.exe") &&
  regex("^0x[0-9a-fA-F]*[13579bdfBDF][0-9a-fA-F]$", {GA}).matches == true &&
  !(({SI} == "c:\\\\program files (x86)\\\\ninjaone\\\\ninjarmmagent.exe" || {SI} == "c:\\\\program files\\\\ninjaone\\\\ninjarmmagent.exe" ||
     {SI} == "c:\\\\program files (x86)\\\\ninjaone\\\\njbinarymetering.exe" || {SI} == "c:\\\\program files\\\\vmware\\\\vmware tools\\\\vmtoolsd.exe") &&
    {GA} == "0x1410") &&
  {SI} != "c:\\\\windows\\\\system32\\\\csrss.exe" &&
  {SI} != "c:\\\\windows\\\\system32\\\\wininit.exe" &&
  !((regex("^c:\\\\\\\\programdata\\\\\\\\microsoft\\\\\\\\windows defender\\\\\\\\platform\\\\\\\\[0-9.\\\\-]+\\\\\\\\msmpeng\\\\.exe$", {SI}).matches == true ||
     {SI} == "c:\\\\program files\\\\windows defender\\\\msmpeng.exe" || {SI} == "c:\\\\windows\\\\system32\\\\mrt.exe") &&
    ({GA} == "0x1010" || {GA} == "0x1410" || {GA} == "0x1418")) &&
  !({SI} == "c:\\\\windows\\\\system32\\\\msiexec.exe" &&
    contains(lowercase(to_string($message.winlogbeat_winlog_event_data_CallTrace)), "\\\\perfproc.dll+"))
then
{tags("lsass_lecture", "CRITIQUE", "T1003.001", "to_string($message.source)", 'concat(concat(to_string($message.winlogbeat_winlog_event_data_SourceImage), " masque "), ' + GA + ')')}end'''

CAN_COND = " ||\n   ".join(f'ends_with(lowercase({F("ObjectName")}), "\\\\{c.lower()}")' for c in CANARIS)
R["omni-v5-ad-canari-fichier"] = f'''rule "omni-v5-ad-canari-fichier"
// Fichiers canaris (PRÉPARÉS, non posés : Poser-Canaris-Fichiers.ps1). Lecture par un humain = exploration/exfiltration.
when
  ({EID} == "4663" || {EID} == "5145") &&
  ({CAN_COND}) &&
  {F("SubjectUserSid")} != "S-1-5-18" &&
  !ends_with({F("SubjectUserName")}, "$")
then
{tags("canari_fichier", "CRITIQUE", "T1083", F("SubjectUserName"), 'concat("Fichier canari ouvert : ", ' + F("ObjectName") + ')')}end'''

# ---- M365
R["omni-v5-m365-transfert-externe"] = r'''rule "omni-v5-m365-transfert-externe"
// Transfert/redirection vers une adresse externe (Set-Mailbox, New/Set-InboxRule ; champs posés par omni-m365-activity).
// Même logique que omni-m365act-10, mais avec une définition à fenêtre de 5 h : l'audit Exchange arrive avec 85 min
// de retard médian (max 279 min) et la définition existante (15 min) n'a JAMAIS déclenché.
when
  to_string($message.event_source) == "m365" &&
  (has_field("forward_external") ||
   (has_field("fwd_target") &&
    regex("(?i)@(__DOMAINES__)\\s*$", to_string($message.fwd_target)).matches == false))
then
  set_field("v5_tag", "m365_transfert_externe");
  set_field("v5_severite", "ELEVE");
  set_field("v5_mitre", "T1114.003");
  set_field("v5_entite", lowercase(to_string($message.user)));
  set_field("v5_detail", concat(concat(concat(to_string($message.event_action), " sur "), to_string($message.object)), concat(" vers ", to_string($message.fwd_target))));
end'''.replace("__DOMAINES__", DOM_RX_REGLE)

R["omni-v5-m365-regle-boite-suspecte"] = r'''rule "omni-v5-m365-regle-boite-suspecte"
// Règle de boîte créée/modifiée depuis l'étranger, ou au nom typique d'un attaquant (vide, 1-2 caractères, ponctuation).
when
  to_string($message.event_source) == "m365" &&
  (to_string($message.event_action) == "New-InboxRule" || lowercase(to_string($message.event_action)) == "set-inboxrule" ||
   to_string($message.event_action) == "UpdateInboxRules") &&
  ((has_field("src_ip_country_code") && to_string($message.src_ip_country_code) != "FR" && to_string($message.src_ip_country_code) != "") ||
   (to_string($message.event_action) != "UpdateInboxRules" && has_field("object") &&
    regex("\\\\([^A-Za-z0-9]*|.{1,2})$", to_string($message.object)).matches == true))
then
  set_field("v5_tag", "m365_regle_boite_suspecte");
  set_field("v5_severite", "ELEVE");
  set_field("v5_mitre", "T1564.008");
  set_field("v5_entite", lowercase(to_string($message.user)));
  set_field("v5_detail", concat(concat(concat(to_string($message.event_action), " "), to_string($message.object)), concat(" depuis ", to_string($message.src_ip_country_code))));
end'''

R["omni-v5-m365-mfa-defi"] = r'''rule "omni-v5-m365-mfa-defi"
// Défi MFA (50074/50076 = mot de passe accepté, MFA exigée ; 500121 = MFA refusée/échouée). Compté par compte
// (rafale = fatigue MFA). Depuis l'étranger, un 50074 signifie que le mot de passe est connu de l'attaquant.
when
  to_string($message.event_source) == "m365" &&
  to_string($message.m365_type) == "signin" &&
  (to_string($message.m365_fail_code) == "50074" || to_string($message.m365_fail_code) == "50076" || to_string($message.m365_fail_code) == "500121")
then
  set_field("v5_tag", "m365_mfa_defi");
  set_field("v5_severite", "ELEVE");
  set_field("v5_mitre", "T1621");
  set_field("v5_entite", lowercase(to_string($message.user)));
  set_field("v5_detail", concat(concat(concat("Defi MFA ", to_string($message.m365_fail_code)), concat(" depuis ", to_string($message.src_country))), concat(" app ", to_string($message.app))));
  set_field("v5_mfa_etranger", to_string($message.src_country) != "FR" && to_string($message.src_country) != "");
end'''

# ------------------------------------------------------------------ définitions
# (titre, description, priorite, streams, requete, group_by, seuil, fenetre_min, every_min, grace_min, etat)
DEFS = [
 ("OMNI v5 - AD Kerberoasting AES (TGS vers un compte utilisateur à SPN)",
  "ELEVE (T1558.003) - Ticket de service AES vers un COMPTE UTILISATEUR (hors $, krbtgt, ticket vers soi-même). RC4 est désactivé : les détections Kerberoasting existantes (TicketEncryptionType 0x17) ne peuvent plus rien voir. 0 sur 30 j au 27/11/2026. Agir : identifier le demandeur (v5_entite) et le poste (IpAddress), vérifier le compte visé et changer son mot de passe s'il n'est pas un gMSA.",
  2, ["OMNI - Windows Security"], "v5_tag:kerberoast_aes", ["v5_entite"], 1, 10, 5, 60, "ENABLED"),
 (f"OMNI v5 - AD Compte leurre {LEURRE} touché",
  f"CRITIQUE (T1558.003) - Toute authentification, ticket (Kerberoast de son SPN factice) ou modification du compte leurre {LEURRE}. Aucun usage légitime (ne jamais modifier le compte). 0 sur 30 j. Complète l'alerte locale des contrôleurs de domaine sur ce compte. Agir : isoler la source (IpAddress / poste), chercher l'outil (Rubeus, GetUserSPNs).",
  3, ["OMNI - Windows Security"], f"v5_tag:{TAG_LEURRE}", ["v5_entite"], 1, 5, 5, 30, "ENABLED"),
 ("OMNI v5 - AD Préparation AS-REP roasting (pré-authentification retirée)",
  "ELEVE (T1558.004) - Un compte a reçu « Ne pas exiger la pré-authentification Kerberos » (4738 %%2096 ou userAccountControl 0x400000). La détection AS-REP existante (PreAuthType 0) ne voit que l'étape suivante. 0 sur 30 j. Agir : retirer le drapeau, identifier l'auteur (v5_entite).",
  2, ["OMNI - Windows Security"], "v5_tag:asrep_preparation", ["v5_entite"], 1, 10, 5, 60, "ENABLED"),
 ("OMNI v5 - AD DCSync par un compte machine non-DC ou un compte MSOL_ inconnu",
  "CRITIQUE (T1003.006) - Droits de réplication d'annuaire exercés (4662) par un compte autre que les contrôleurs de domaine et le compte Entra Connect exact (site.json). Complète « OMNI - DCSync suspect » qui exclut TOUT compte $ et TOUT MSOL_* (et dont le 3e GUID est erroné) : la requête exclut ce que l'existante signale déjà. 0 sur 30 j (65 440 réplications légitimes écartées). Agir : isoler la machine, réinitialiser krbtgt 2 fois si confirmé.",
  3, ["OMNI - Windows Security"], "v5_tag:dcsync AND NOT alert_tag:dcsync", ["v5_entite"], 1, 5, 5, 30, "ENABLED"),
 ("OMNI v5 - AD Shadow Credentials par SYSTEM ou un compte MSOL_ inconnu",
  "CRITIQUE (T1556) - msDS-KeyCredentialLink modifié par un autre acteur que le compte Entra Connect exact (écriture WHfB d'Entra Connect). Complète « OMNI - Shadow Credentials » qui exclut SYSTEM et tout MSOL_* : la requête exclut ce que l'existante signale déjà. 0 sur 30 j (6 écritures Entra Connect écartées). Agir : vider l'attribut ajouté, chercher pyWhisker/Whisker.",
  3, ["OMNI - Windows Security"], "v5_tag:shadow_credentials AND NOT alert_tag:shadow_credentials", ["v5_entite"], 1, 5, 5, 30, "ENABLED"),
 ("OMNI v5 - AD CS : demande de certificat avec SAN différent du demandeur (ESC1/ESC6)",
  "CRITIQUE (T1649) - Demande (4886) avec un SAN de type UPN ou un attribut SAN:, ou certificat émis (4887) dont l'UPN ne correspond pas au demandeur. Aucun cas légitime sur 30 j (115 demandes : auto-inscription sans SAN demandé, OMS-WebServer en noms DNS). Agir : révoquer le certificat (RequestId), chercher Certify/Certipy, vérifier le modèle.",
  3, ["OMNI - Windows Security"], "v5_tag:adcs_san AND NOT alert_tag:adcs_abuse", ["v5_entite"], 1, 30, 5, 60, "ENABLED"),
 ("OMNI v5 - AD CS : modèle de certificat ou configuration de la CA modifiés",
  "ELEVE (T1649) - Modèle de certificat (4899/4900, 5136), sécurité (4882) ou configuration (4885/4890/4892) de la CA, ou CN=Public Key Services modifiés. ATTENTION : au 27/11/2026 ces événements ne sont PAS journalisés (filtre d'audit CA partiel, pas de SACL sur la partition Configuration) ; script Activer-Audit-ADCS.ps1 préparé (décision jmorin).",
  2, ["OMNI - Windows Security"], "v5_tag:adcs_modele_ca", ["v5_entite"], 1, 30, 5, 60, "ENABLED"),
 ("OMNI v5 - AD Service installé sur un contrôleur de domaine ou une PKI",
  "ELEVE (T1543.003) - Service installé (7045) sur un contrôleur de domaine ou une PKI (site.json, hotes_tier0), hors agents connus à leur chemin d'installation (Veeam par gMSA, ESET, NinjaOne, VMware, Sysmon, Winlogbeat, Defender). Complète « Nouveau service installé (7045) » (2 393 événements parc en 30 j). Agir : vérifier le binaire (ImagePath) et le compte d'installation.",
  2, ["OMNI - Windows autres"], "v5_tag:service_tier0", ["v5_entite"], 1, 10, 5, 60, "ENABLED"),
 ("OMNI v5 - AD GPO sensible : lien sur domaine/DC ou GPO modifiée par SYSTEM",
  "ELEVE (T1484.001) - gPLink modifié sur la racine du domaine ou l'OU Domain Controllers, ou GPO modifiée par SYSTEM / un compte machine (cas exclus par « Modification de GPO par un humain »), hors GPO de déploiement réécrite par l'agent RMM. Agir : comparer la GPO à la sauvegarde hebdomadaire.",
  2, ["OMNI - Windows Security"], "v5_tag:gpo_sensible", ["v5_entite"], 1, 10, 5, 60, "ENABLED"),
 ("OMNI v5 - AD Accès mémoire LSASS hors liste stricte",
  "CRITIQUE (T1003.001) - Accès à lsass.exe avec lecture mémoire (bit 0x10) par un binaire hors liste stricte (chemin complet + masque). Complète « Accès mémoire LSASS » (masques en liste fermée, exclusion large *NinjaOne*/*WerFaultSecure*) : la requête exclut ce que l'existante signale déjà. Agir : isoler le poste, analyser le binaire source.",
  3, ["OMNI - Sysmon"], "v5_tag:lsass_lecture AND NOT (alert_tag:lsass_access AND NOT winlogbeat_winlog_event_data_SourceImage:(*njbinarymetering* OR *NinjaOne* OR *WerFaultSecure*))", ["v5_entite"], 1, 10, 5, 60, "ENABLED"),
 ("OMNI v5 - AD Fichier canari ouvert",
  "CRITIQUE (T1083) - Ouverture d'un fichier canari (Poser-Canaris-Fichiers.ps1). DÉSACTIVÉE : les fichiers ne sont pas posés (décision jmorin), à activer après la pose et la vérification de l'audit 4663.",
  3, ["OMNI - Windows Security"], "v5_tag:canari_fichier", ["v5_entite"], 1, 10, 5, 60, "DISABLED"),
 ("OMNI v5 - M365 Transfert de messagerie vers une adresse externe",
  "ELEVE (T1114.003) - Transfert ou redirection vers une adresse externe (Set-Mailbox ForwardingSmtpAddress, règle ForwardTo/RedirectTo). Fenêtre de 5 h car l'audit Exchange arrive avec 85 min de retard médian (max 279 min) : la définition existante (15 min) n'a jamais déclenché. Agir : vérifier l'accord du titulaire et de la direction, retirer le transfert sinon.",
  2, ["OMNI - M365"], "v5_tag:m365_transfert_externe", ["v5_entite"], 1, 300, 15, 300, "ENABLED"),
 ("OMNI v5 - M365 Règle de boîte suspecte (étranger ou nom anormal)",
  "ELEVE (T1564.008) - Règle de boîte créée/modifiée depuis une IP hors de France, ou nommée comme un attaquant (vide, 1-2 caractères, ponctuation). Fenêtre de 5 h (retard d'audit Exchange). 0 sur 30 j. Agir : lire la règle (Get-InboxRule), vérifier la connexion d'origine.",
  2, ["OMNI - M365"], "v5_tag:m365_regle_boite_suspecte", ["v5_entite"], 1, 300, 15, 300, "ENABLED"),
 ("OMNI v5 - M365 Rafale de défis MFA (fatigue MFA)",
  "ELEVE (T1621) - Au moins 10 défis MFA (50074/50076/500121) pour un même compte sur la fenêtre. Fenêtre de 5 h : les connexions arrivent avec jusqu'à 3 h de retard ; l'existante (500121 seul, 10 min) ne peut pas déclencher. 1 cas bénin sur 30 j. Agir : appeler l'utilisateur, ne jamais lui faire approuver ; si refus non initiés, changer le mot de passe.",
  2, ["OMNI - M365"], "v5_tag:m365_mfa_defi", ["v5_entite"], 10, 300, 15, 300, "ENABLED"),
 ("OMNI v5 - M365 Mot de passe validé depuis l'étranger (MFA exigée)",
  "ELEVE (T1078.004) - Défi MFA déclenché depuis une IP hors de France : le mot de passe a été accepté, seule la MFA a arrêté la connexion. 0 sur 30 j. Agir : changer le mot de passe, vérifier les connexions réussies du compte.",
  2, ["OMNI - M365"], "v5_tag:m365_mfa_defi AND v5_mfa_etranger:true", ["v5_entite"], 1, 300, 15, 300, "ENABLED"),
]

# ------------------------------------------------------------------ outils
def streams_ids(): return {s["title"]: s["id"] for s in api("GET", "/streams")["streams"]}

def def_body(d, sid):
    titre, desc, prio, streams, q, gb, seuil, fen, every, grace, etat = d
    return {"title": titre, "description": desc, "priority": prio, "alert": True,
            "config": {"type": "aggregation-v1", "query": q, "query_parameters": [], "filters": [], "streams": [sid[s] for s in streams],
                       "stream_categories": [], "group_by": gb, "series": [{"type": "count", "id": "count()", "field": None}],
                       "conditions": {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"}, "right": {"expr": "number", "value": seuil}}},
                       "search_within_ms": fen * 60000, "execute_every_ms": every * 60000, "use_cron_scheduling": False, "event_limit": 50},
            "field_spec": {}, "key_spec": [], "notification_settings": {"grace_period_ms": grace * 60000, "backlog_size": 10},
            "notifications": [{"notification_id": N_TEAMS, "notification_parameters": None}, {"notification_id": N_TRIAGE, "notification_parameters": None}],
            "storage": [{"type": "persist-to-streams-v1", "streams": ["000000000000000000000002"]}], "state": etat}

def pipe_src():
    return 'pipeline "' + PIPE_TITLE + '"\nstage 45 match either\n' + "".join(f'rule "{n}"\n' for n in R) + "end"

def mesure(echantillons=4):
    """Durée de traitement (gl2_processing_duration_ms) 15 min par index + tampons/journal Graylog (plusieurs relevés)."""
    out = {"horodatage": time.strftime("%Y-%m-%d %H:%M:%S"), "index": {}, "tampons": []}
    for idx in ["omni-winsec", "omni-winother", "omni-sysmon", "omni-m365"]:
        q = {"size": 0, "query": {"range": {"gl2_processing_timestamp": {"gte": "now-15m"}}},
             "aggs": {"d": {"avg": {"field": "gl2_processing_duration_ms"}}, "p": {"percentiles": {"field": "gl2_processing_duration_ms", "percents": [50, 99]}}}}
        r = osq(f"/{idx}_deflector/_search", q)
        v = r["aggregations"]["p"]["values"]
        out["index"][idx] = {"messages_15min": total(r), "moy_ms": round(r["aggregations"]["d"]["value"] or 0, 2),
                             "p50_ms": round(v.get("50.0") or 0, 1), "p99_ms": round(v.get("99.0") or 0, 1)}
    for i in range(echantillons):
        b = {}
        try:
            j = api("GET", "/system/journal"); b["journal_non_commite"] = j.get("uncommitted_journal_entries")
        except Exception as e: b["journal"] = str(e)[:80]
        try:
            bu = api("GET", "/system/buffers")["buffers"]
            b.update({k + "_pct": round(bu[k]["utilization_percent"], 2) for k in ("input", "process", "output") if k in bu})
        except Exception as e: b["tampons"] = str(e)[:80]
        out["tampons"].append(b)
        if i < echantillons - 1: time.sleep(15)
    return out

# ------------------------------------------------------------------ rejeu 30 jours (logique Python = règles)
def low(x): return str(x or "").lower()
def g(d, n): return str(d.get("winlogbeat_winlog_event_data_" + n) or "")
def eid(d): return str(d.get("winlogbeat_winlog_event_id") or "")
def P_kerb(d):
    s = g(d, "ServiceName"); u = g(d, "TargetUserName").split("@")[0]
    return eid(d) == "4769" and g(d, "Status") == "0x0" and s and "$" not in s and not low(s).startswith("krbtgt") and low(s) != LEURRE and low(s) != low(u)
def P_leurre(d):
    return low(g(d, "TargetUserName")) == LEURRE or low(g(d, "TargetUserName")).startswith(LEURRE + "@") or low(g(d, "ServiceName")) == LEURRE or \
        low(g(d, "SubjectUserName")) == LEURRE or f"cn={LEURRE}," in low(g(d, "ObjectDN"))
def P_asrep(d):
    if eid(d) == "4738": return bool(re.search(r"(?i)(%%2096|pr[ée]-?auth[^\n]*(activ|enabl))", g(d, "UserAccountControl")))
    if eid(d) == "5136" and g(d, "AttributeLDAPDisplayName") == "userAccountControl" and g(d, "OperationType") == "%%14674":
        try: return (int(g(d, "AttributeValue")) // 4194304) % 2 == 1
        except ValueError: return False
    return False
def P_dcsync(d):
    p = low(g(d, "Properties"))
    return eid(d) == "4662" and any(x in p for x in ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")) \
        and low(g(d, "SubjectUserName")) not in DC_ALLOW
def P_shadow(d):
    s = g(d, "SubjectUserName")
    return eid(d) == "5136" and low(g(d, "AttributeLDAPDisplayName")) == "msds-keycredentiallink" and low(s) != ENTRA and \
        not (s.endswith("$") and low(g(d, "ObjectDN")).startswith("cn=" + low(s[:-1]) + ","))
def P_adcs_san(d):
    e = eid(d); san = g(d, "SubjectAlternativeName")
    if e == "4886" and re.search(r"(?i)(nom principal|principal name|autre nom|other name|upn=)", san): return True
    if e in ("4886", "4887") and re.search(r"(?i)(^|\n)\s*san:", g(d, "Attributes")): return True
    m = re.search(r"(?i)(?:nom principal|principal name)=([^@\s]+)@", san)
    r = re.search(r"([^\\]+)$", g(d, "Requester"))
    return e == "4887" and bool(m) and low(m.group(1)) != low(r.group(1) if r else "")
def P_adcs_mod(d):
    e = eid(d)
    if d.get("winlogbeat_winlog_channel") == "Security" and e in ("4882", "4885", "4890", "4892", "4899", "4900"): return True
    return e == "5136" and (low(g(d, "ObjectClass")) in ("pkicertificatetemplate", "pkienrollmentservice", "certificationauthority") or "cn=public key services," in low(g(d, "ObjectDN"))) \
        and not (low(g(d, "SubjectUserName")) == CA_MACHINE and g(d, "AttributeLDAPDisplayName") == "cACertificateDN" and ",cn=aia,cn=public key services," in low(g(d, "ObjectDN")))
def P_service(d):
    if eid(d) != "7045" or low(d.get("source")) not in TIER0: return False
    i = low(g(d, "ImagePath")); n = g(d, "ServiceName")
    if n == "VeeamVssSupport" and "c:\\windows\\veeamvsssupport\\veeamguesthelper.exe" in i and low(d.get("winlogbeat_winlog_user_name")).startswith(GMSA_SAUV): return False
    for p in ('"c:\\program files\\eset\\', '"c:\\programdata\\eset\\remoteadministrator\\', '"c:\\program files (x86)\\ninjaone\\', '"c:\\program files\\ninjaremote\\',
              '"c:\\program files\\vmware\\vmware tools\\', '"c:\\program files\\winlogbeat\\winlogbeat.exe"', '"c:\\programdata\\microsoft\\windows defender\\platform\\'):
        if i.startswith(p): return False
    if re.search(r"^(\\systemroot\\)?system32\\drivers\\(eamonm|ehdrv|eelam|epfw|epfwwfp)\.sys$", i): return False
    if re.search(r'^"c:\\program files \(x86\)\\' + re.escape(RMM_DOSSIER) + r'-[0-9.]+\\(njvmagent|nmsmanager|ninjarmmagent|ninjarmmagentpatcher)\.exe"', i): return False
    if re.search(r"^(\\systemroot\\)?system32\\(drivers|driverstore\\filerepository\\vm3d\.inf_amd64_[0-9a-f]+)\\(vm[a-z0-9_-]*|vsock|vmci)\.sys$", i): return False
    if i == "c:\\windows\\system32\\dllhost.exe /processid:{480b4670-6610-4465-b6c5-e9b5c4e0da31}": return False
    if i in ("c:\\windows\\sysmon64.exe", "c:\\windows\\sysmondrv.sys"): return False
    if re.search(r"^system32\\drivers\\(wd\\[a-z0-9]+|ksld)\.sys$", i): return False
    return True
def P_gpo(d):
    if eid(d) != "5136": return False
    a, c, dn = low(g(d, "AttributeLDAPDisplayName")), low(g(d, "ObjectClass")), low(g(d, "ObjectDN"))
    if a == "gplink" and (c == "domaindns" or dn.startswith("ou=domain controllers,")): return True
    return c == "grouppolicycontainer" and (g(d, "SubjectUserSid") == "S-1-5-18" or g(d, "SubjectUserName").endswith("$")) and GPO_AGENT not in dn
def P_lsass(d):
    si, ga = low(g(d, "SourceImage")), g(d, "GrantedAccess")
    if eid(d) != "10" or not low(g(d, "TargetImage")).endswith("\\lsass.exe") or not re.match(r"^0x[0-9a-fA-F]*[13579bdfBDF][0-9a-fA-F]$", ga): return False
    if si in ("c:\\program files (x86)\\ninjaone\\ninjarmmagent.exe", "c:\\program files\\ninjaone\\ninjarmmagent.exe", "c:\\program files (x86)\\ninjaone\\njbinarymetering.exe",
              "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe") and ga == "0x1410": return False
    if si in ("c:\\windows\\system32\\csrss.exe", "c:\\windows\\system32\\wininit.exe"): return False
    if (re.match(r"^c:\\programdata\\microsoft\\windows defender\\platform\\[0-9.\-]+\\msmpeng\.exe$", si) or si in ("c:\\program files\\windows defender\\msmpeng.exe", "c:\\windows\\system32\\mrt.exe")) \
            and ga in ("0x1010", "0x1410", "0x1418"): return False
    if si == "c:\\windows\\system32\\msiexec.exe" and "\\perfproc.dll+" in low(g(d, "CallTrace")): return False
    return True
def D_lsass(d):  # exclusion de la requête de définition : ce que l'existante signale déjà
    return d.get("alert_tag") == "lsass_access" and not re.search(r"(?i)(njbinarymetering|ninjaone|werfaultsecure)", g(d, "SourceImage"))
def P_fwd(d):
    return d.get("event_source") == "m365" and (d.get("forward_external") is not None or (d.get("fwd_target") and not DOM_RX.search(
        str(d.get("fwd_target")))))
def P_regle(d):
    a = str(d.get("event_action") or "")
    if d.get("event_source") != "m365" or not (a == "New-InboxRule" or a.lower() == "set-inboxrule" or a == "UpdateInboxRules"): return False
    cc = str(d.get("src_ip_country_code") or "")
    if cc and cc != "FR": return True
    return a != "UpdateInboxRules" and d.get("object") is not None and bool(re.search(r"\\([^A-Za-z0-9]*|.{1,2})$", str(d.get("object"))))
def P_mfa(d): return d.get("event_source") == "m365" and d.get("m365_type") == "signin" and str(d.get("m365_fail_code")) in ("50074", "50076", "500121")
def P_mfa_etr(d): return P_mfa(d) and str(d.get("src_country") or "") not in ("FR", "")

WF = ["timestamp", "gl2_receive_timestamp", "source", "alert_tag", "winlogbeat_winlog_event_id", "winlogbeat_winlog_channel", "winlogbeat_winlog_user_name", "winlogbeat_winlog_event_data_*"]
MF = ["timestamp", "gl2_receive_timestamp", "event_source", "event_action", "m365_type", "m365_fail_code", "user", "object", "fwd_target", "forward_external", "src_ip_country_code", "src_country", "src_ip", "app", "m365_id"]
def wild(f, v): return {"wildcard": {f: {"value": v, "case_insensitive": True}}}
REJEU = [  # (titre court, index, requete candidate (DSL), champs, predicat, exclusion_def, entite)
 ("kerberoast_aes", "omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:4769 AND winlogbeat_winlog_event_data_Status:0x0 AND NOT winlogbeat_winlog_event_data_ServiceName:*$*"}}, WF, P_kerb, None, lambda d: low(g(d, "TargetUserName"))),
 (TAG_LEURRE, "omni-winsec_*", {"bool": {"should": [wild("winlogbeat_winlog_event_data_TargetUserName", LEURRE + "*"), wild("winlogbeat_winlog_event_data_ServiceName", LEURRE),
     wild("winlogbeat_winlog_event_data_SubjectUserName", LEURRE), wild("winlogbeat_winlog_event_data_ObjectDN", f"*cn={LEURRE},*")], "minimum_should_match": 1}}, WF, P_leurre, None, lambda d: LEURRE),
 ("asrep_preparation", "omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:4738 OR (winlogbeat_winlog_event_id:5136 AND winlogbeat_winlog_event_data_AttributeLDAPDisplayName:userAccountControl)"}}, WF, P_asrep, None, lambda d: low(g(d, "SubjectUserName"))),
 ("dcsync", "omni-winsec_*", {"bool": {"filter": [{"term": {"winlogbeat_winlog_event_id": "4662"}}, {"query_string": {"query": "winlogbeat_winlog_event_data_Properties:(*1131f6aa* OR *1131f6ad* OR *89e95b76*)"}}],
     "must_not": [{"terms": {"winlogbeat_winlog_event_data_SubjectUserName": list(REPLICATION)}}]}}, WF, P_dcsync, lambda d: d.get("alert_tag") == "dcsync", lambda d: low(g(d, "SubjectUserName"))),
 ("shadow_credentials", "omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:5136 AND winlogbeat_winlog_event_data_AttributeLDAPDisplayName:msDS-KeyCredentialLink"}}, WF, P_shadow, lambda d: d.get("alert_tag") == "shadow_credentials", lambda d: low(g(d, "SubjectUserName"))),
 ("adcs_san", "omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:(4886 OR 4887)"}}, WF, P_adcs_san, lambda d: d.get("alert_tag") == "adcs_abuse", lambda d: low(g(d, "Requester"))),
 ("adcs_modele_ca", "omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:(4882 OR 4885 OR 4890 OR 4892 OR 4899 OR 4900) OR (winlogbeat_winlog_event_id:5136 AND (winlogbeat_winlog_event_data_ObjectClass:(pKICertificateTemplate OR pKIEnrollmentService OR certificationAuthority) OR winlogbeat_winlog_event_data_ObjectDN:*Public\\ Key\\ Services*))"}}, WF, P_adcs_mod, None, lambda d: low(g(d, "SubjectUserName") or d.get("source"))),
 ("service_tier0", "omni-winother_*", {"query_string": {"query": "winlogbeat_winlog_event_id:7045"}}, WF, P_service, None, lambda d: low(d.get("source"))),
 ("gpo_sensible", "omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:5136 AND (winlogbeat_winlog_event_data_AttributeLDAPDisplayName:gPLink OR winlogbeat_winlog_event_data_ObjectClass:groupPolicyContainer)"}}, WF, P_gpo, None, lambda d: low(g(d, "SubjectUserName"))),
 ("lsass_lecture", "omni-sysmon_*", {"bool": {"filter": [{"term": {"winlogbeat_winlog_event_id": "10"}}, {"wildcard": {"winlogbeat_winlog_event_data_TargetImage": {"value": "*lsass.exe", "case_insensitive": True}}},
     {"regexp": {"winlogbeat_winlog_event_data_GrantedAccess": "0x[0-9a-fA-F]*[13579bdfBDF][0-9a-fA-F]"}}],
     "must_not": [{"bool": {"filter": [{"terms": {"winlogbeat_winlog_event_data_SourceImage": ["C:\\Program Files (x86)\\NinjaOne\\NinjaRMMAgent.exe", "C:\\Program Files (x86)\\NinjaOne\\njbinarymetering.exe"]}}, {"term": {"winlogbeat_winlog_event_data_GrantedAccess": "0x1410"}}]}}]}}, WF, P_lsass, D_lsass, lambda d: low(d.get("source"))),
 ("m365_transfert_externe", "omni-m365_*", {"query_string": {"query": "_exists_:forward_external OR _exists_:fwd_target"}}, MF, P_fwd, None, lambda d: low(d.get("user"))),
 ("m365_regle_boite_suspecte", "omni-m365_*", {"query_string": {"query": "event_action:(New-InboxRule OR Set-InboxRule OR set-InboxRule OR UpdateInboxRules)"}}, MF, P_regle, None, lambda d: low(d.get("user"))),
 ("m365_mfa_defi", "omni-m365_*", {"query_string": {"query": "m365_type:signin AND m365_fail_code:(50074 OR 50076 OR 500121)"}}, MF, P_mfa, None, lambda d: low(d.get("user"))),
 ("m365_mfa_etranger", "omni-m365_*", {"query_string": {"query": "m365_type:signin AND m365_fail_code:(50074 OR 50076 OR 500121)"}}, MF, P_mfa_etr, None, lambda d: low(d.get("user"))),
]
TAG2DEF = {"kerberoast_aes": 0, TAG_LEURRE: 1, "asrep_preparation": 2, "dcsync": 3, "shadow_credentials": 4, "adcs_san": 5, "adcs_modele_ca": 6,
           "service_tier0": 7, "gpo_sensible": 8, "lsass_lecture": 9, "m365_transfert_externe": 11, "m365_regle_boite_suspecte": 12, "m365_mfa_defi": 13, "m365_mfa_etranger": 14}

def pts(s):
    s = str(s).replace("T", " ").replace("Z", "")
    return dt.datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()

def fetch(idx, q, fields, days=30, maxdocs=200000):
    out, after = [], None
    body = {"size": 5000, "sort": [{"timestamp": "asc"}, {"gl2_message_id": "asc"}], "_source": fields,
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}, q]}}}
    while len(out) < maxdocs:
        if after: body["search_after"] = after
        r = osq(f"/{idx}/_search", body)
        h = r["hits"]["hits"]
        if not h: break
        out += [x["_source"] for x in h]; after = h[-1]["sort"]
        if len(h) < 5000: break
    return out

def ordonnance(docs, entite, seuil, fen, every, grace, days=30, latence=True):
    """Simule le planificateur Graylog : exécution toutes les `every` min sur (T-fen, T], message visible si reçu <= T ;
    événement si count >= seuil par entité ; notification si la dernière pour cette entité date de plus de `grace`."""
    ev = [(pts(d["timestamp"]), pts(d.get("gl2_receive_timestamp") or d["timestamp"]) if latence else pts(d["timestamp"]), entite(d)) for d in docs]
    if not ev: return 0, 0, {}
    now = time.time(); start = now - days * 86400
    E, W, G = every * 60, fen * 60, grace * 60
    T = start - (start % E) + E; derniere = {}; nb_ev = nb_notif = 0; par_jour = collections.Counter()
    ev.sort()
    while T <= now + E:
        c = collections.Counter(k for ts, rc, k in ev if T - W < ts <= T and rc <= T)
        for k, n in c.items():
            if n >= seuil:
                nb_ev += 1
                if k not in derniere or T - derniere[k] >= G:
                    nb_notif += 1; derniere[k] = T; par_jour[time.strftime("%Y-%m-%d", time.gmtime(T))] += 1
        T += E
    return nb_ev, nb_notif, dict(par_jour)

def rejeu():
    res = {}
    for nom, idx, q, fields, pred, excl, ent in REJEU:
        t0 = time.time()
        docs = fetch(idx, q, fields)
        pos = [d for d in docs if pred(d)]
        apres = [d for d in pos if not (excl and excl(d))]
        d = DEFS[TAG2DEF[nom]]
        nb_ev, nb_notif, pj = ordonnance(apres, ent, d[6], d[7], d[8], d[9], latence=nom.startswith("m365"))
        ex = [{k: (v[:160] if isinstance(v, str) else v) for k, v in x.items() if k in ("timestamp", "source", "user", "event_action", "object", "fwd_target", "src_country", "app", "m365_fail_code")
               or k.endswith(("SubjectUserName", "TargetUserName", "ServiceName", "ImagePath", "SourceImage", "GrantedAccess", "ObjectDN", "Requester", "SubjectAlternativeName", "AttributeLDAPDisplayName"))} for x in apres[:5]]
        res[nom] = {"candidats": len(docs), "correspondances_regle": len(pos), "apres_exclusion_definition": len(apres), "evenements": nb_ev,
                    "notifications_30j": nb_notif, "max_par_jour": max(pj.values()) if pj else 0, "par_jour": pj, "exemples": ex, "duree_s": round(time.time() - t0, 1),
                    "definition": d[0], "etat_prevu": d[10]}
        print(f"{nom:<28} candidats={len(docs):>6} regle={len(pos):>5} def={len(apres):>5} notif30j={nb_notif:>3} max/j={res[nom]['max_par_jour']}")
    # variantes de seuil pour la rafale MFA (aide à la décision)
    docs = fetch("omni-m365_*", REJEU[12][2], MF); pos = [x for x in docs if P_mfa(x)]
    res["m365_mfa_defi"]["seuils"] = {s: ordonnance(pos, REJEU[12][6], s, 300, 15, 300)[1] for s in (3, 5, 8, 10, 15, 20)}
    print("  seuils MFA (notifications 30 j) :", res["m365_mfa_defi"]["seuils"])
    json.dump(res, open("/root/omni-v5-ad/rejeu.json", "w"), indent=1, ensure_ascii=False)
    print("rejeu -> /root/omni-v5-ad/rejeu.json")

# ------------------------------------------------------------------ simuler / appliquer / retour
def verifier():
    for n, src in R.items():
        try: api("POST", "/system/pipelines/rule/parse", {"title": n, "description": "", "source": src})
        except RuntimeError as e: sys.exit(f"ERREUR SYNTAXE {n} : {e}")
    print(f"syntaxe OK : {len(R)} regles")
    sid = streams_ids(); manq = {s for d in DEFS for s in d[3] if s not in sid} | {s for s in PIPE_STREAMS if s not in sid}
    if manq: sys.exit(f"streams introuvables : {manq}")
    for d in DEFS:
        assert d[0].startswith(("OMNI v5 - AD ", "OMNI v5 - M365 ")), d[0]
    print(f"{len(DEFS)} definitions preparees ({sum(1 for d in DEFS if d[10] == 'ENABLED')} actives, {sum(1 for d in DEFS if d[10] != 'ENABLED')} desactivee(s)) ; streams OK")
    return sid

def appliquer():
    sid = verifier()
    os.makedirs(SAUV, mode=0o700, exist_ok=True)
    uri = [l.split("=", 1)[1].strip() for l in open("/etc/graylog/server/server.conf") if l.startswith("mongodb_uri")][0]
    for c in ["event_definitions", "pipeline_processor_rules", "pipeline_processor_pipelines", "pipeline_processor_pipelines_streams"]:
        subprocess.run(["mongoexport", "--quiet", f"--uri={uri}", f"--collection={c}", f"--out={SAUV}/{c}.json"], check=True)
    json.dump(mesure(), open(f"{SAUV}/perf-avant.json", "w"), indent=1)
    print(f"sauvegarde + mesure avant : {SAUV}")
    crees = []
    exist = {r["title"]: r for r in api("GET", "/system/pipelines/rule")}
    for n, src in R.items():
        if n in exist:
            if exist[n]["source"].strip() != src.strip():
                api("PUT", f"/system/pipelines/rule/{exist[n]['id']}", {"title": n, "description": DESC_REGLE, "source": src}); crees.append(("regle-maj", exist[n]["id"], n))
            continue
        r = api("POST", "/system/pipelines/rule", {"title": n, "description": DESC_REGLE, "source": src}); crees.append(("regle", r["id"], n))
    pipes = {p["title"]: p for p in api("GET", "/system/pipelines/pipeline")}
    if PIPE_TITLE in pipes:
        pid = pipes[PIPE_TITLE]["id"]
        if pipes[PIPE_TITLE]["source"].strip() != pipe_src().strip():
            api("PUT", f"/system/pipelines/pipeline/{pid}", {"title": PIPE_TITLE, "description": pipes[PIPE_TITLE].get("description", ""), "source": pipe_src()}); crees.append(("pipeline-maj", pid, PIPE_TITLE))
    else:
        p = api("POST", "/system/pipelines/pipeline", {"title": PIPE_TITLE, "description": "SIEM v5 chantier 1 (27/11/2026) : detections AD et M365. Etape 45, apres tous les enrichissements (5-41).", "source": pipe_src()})
        pid = p["id"]; crees.append(("pipeline", pid, PIPE_TITLE))
    api("POST", "/system/pipelines/connections/to_pipeline", {"pipeline_id": pid, "stream_ids": [sid[s] for s in PIPE_STREAMS]})
    print(f"{len(R)} regles + pipeline {pid} connecte a {len(PIPE_STREAMS)} streams")
    edefs = {d["title"]: d for d in api("GET", "/events/definitions?per_page=1000")["event_definitions"]}
    for d in DEFS:
        if d[0] in edefs:
            print(f"  definition deja presente : {edefs[d[0]]['id']} {d[0]}"); continue
        e = api("POST", "/events/definitions?schedule=" + ("true" if d[10] == "ENABLED" else "false"), {"entity": def_body(d, sid)})
        crees.append(("definition", e["id"], d[0])); print(f"  definition {e['id']} [{d[10]}] {d[0]}")
    with open("/root/omni-v5-ad/retour.sh", "w") as f:
        f.write("#!/bin/bash\n# Retour SIEM v5 chantier 1 (27/11/2026) : supprime PAR NOM le pipeline « OMNI v5 - Detections AD et M365 »,\n"
                "# les regles omni-v5-ad-* / omni-v5-m365-* et les definitions « OMNI v5 - AD » / « OMNI v5 - M365 ». Rien d'autre.\n"
                "# A blanc : bash retour.sh --simuler\ncd /root/omni-v5-ad || exit 1\nif [ \"$1\" = \"--simuler\" ]; then python3 -I v5_ad_build.py --retour-simuler; else python3 -I v5_ad_build.py --retour; fi\n")
    os.chmod("/root/omni-v5-ad/retour.sh", 0o700)
    subprocess.run(["cp", "-p", "/root/omni-v5-ad/retour.sh", "/root/omni-v5-ad/v5_ad_build.py", "/root/omni-v5-ad/v5_lib.py", SAUV], check=True)
    json.dump(crees, open(f"{SAUV}/objets-crees.json", "w"), indent=1, ensure_ascii=False)
    print(f"retour : bash /root/omni-v5-ad/retour.sh (copie dans {SAUV}) ; objets crees/maj a ce passage : {len(crees)}")

def a_supprimer():
    defs = [(d["id"], d["title"]) for d in api("GET", "/events/definitions?per_page=1000")["event_definitions"] if d["title"].startswith(("OMNI v5 - AD ", "OMNI v5 - M365 "))]
    pipes = [(p["id"], p["title"]) for p in api("GET", "/system/pipelines/pipeline") if p["title"] == PIPE_TITLE]
    rules = [(r["id"], r["title"]) for r in api("GET", "/system/pipelines/rule") if r["title"].startswith(("omni-v5-ad-", "omni-v5-m365-"))]
    return defs, pipes, rules

def retour(simuler):
    defs, pipes, rules = a_supprimer()
    print(f"{'A BLANC : ' if simuler else ''}{len(defs)} definitions, {len(pipes)} pipeline, {len(rules)} regles")
    for i, t in defs + pipes + rules: print(f"   {i}  {t}")
    if simuler: return
    for i, _ in defs: api("DELETE", f"/events/definitions/{i}")
    for i, _ in pipes:
        api("POST", "/system/pipelines/connections/to_pipeline", {"pipeline_id": i, "stream_ids": []})
        api("DELETE", f"/system/pipelines/pipeline/{i}")
    for i, _ in rules: api("DELETE", f"/system/pipelines/rule/{i}")
    print("retour termine")

if __name__ == "__main__":
    if MODE == "--mesure": print(json.dumps(mesure(), indent=1)); sys.exit(0)
    if MODE == "--rejeu": rejeu(); sys.exit(0)
    if MODE == "--retour-simuler": retour(True); sys.exit(0)
    if MODE == "--retour": retour(False); sys.exit(0)
    if MODE == "--appliquer": appliquer(); sys.exit(0)
    if MODE == "--source": [print(s + "\n") for s in R.values()]; print(pipe_src()); sys.exit(0)
    verifier(); print("SIMULATION : rien n'a ete cree")
