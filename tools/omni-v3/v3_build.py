#!/usr/bin/env python3
# OMNITECH 11/11/2026 - Couche de détection « OMNI v3 » (agent Détection & Corrélation, go jmorin).
# Usage (root, sur BX-IT-GRAYLOG-VM) :  python3 v3_build.py --simuler   (vérifie la syntaxe des règles, ne crée rien)
#                                       python3 v3_build.py --appliquer (sauvegarde, crée, écrit le script de retour)
# Idempotent : un objet déjà présent (même titre/nom) n'est pas recréé. Aucun secret affiché ni écrit.
import json, os, re, ssl, subprocess, sys, time, urllib.request, urllib.error

MODE = sys.argv[1] if len(sys.argv) > 1 else "--simuler"
VARS = "/root/omnitech-siem-setup/00-vars.env"
env = {}
for l in open(VARS, encoding="utf-8"):
    m = re.match(r'^(?:export\s+)?([A-Z_]+)=["\']?([^"\'\n]*)', l)
    if m: env[m.group(1)] = m.group(2)
TOKEN = env.get("GRAYLOG_API_TOKEN", "")
API = "https://127.0.0.1:9000/api"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
import base64
# Jeton API s'il est renseigné, sinon le compte admin des scripts de déploiement (GRAYLOG_ADMIN_PASS), jamais affiché
_ident = f"{TOKEN}:token" if TOKEN else f"admin:{env.get('GRAYLOG_ADMIN_PASS', '')}"
AUTH = "Basic " + base64.b64encode(_ident.encode()).decode()
TOKEN = TOKEN or env.get("GRAYLOG_ADMIN_PASS", "")
TS = time.strftime("%Y%m%d-%H%M")
SAUV = f"/var/backups/siem/v3-avant-{TS}"
CREES = []  # (type, id, nom) pour le retour

def api(meth, path, body=None):
    req = urllib.request.Request(API + path, method=meth, data=(json.dumps(body).encode() if body is not None else None),
                                 headers={"Authorization": AUTH, "Content-Type": "application/json", "Accept": "application/json", "X-Requested-By": "omni-v3"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            t = r.read().decode(); return json.loads(t) if t else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{meth} {path} -> {e.code} {e.read().decode()[:400]}")

# ---------------- objets ----------------
ACTIFS_CSV = """cle,valeur
bx-ad-01-it-vm,tier0 - Controleur de domaine (PDC)
bx-ad02-it-vm,tier0 - Controleur de domaine
iv-it-ad-vm,tier0 - Controleur de domaine Ivry
bx-pki2022,tier0 - Autorite de certification
bx-veeam-it-sv,tier0 - Serveur de sauvegarde Veeam
bx-veeam-prx1,tier1 - Proxy Veeam
bx-veeam-prx2-i,tier1 - Proxy Veeam
bx-veeam-prx3,tier1 - Proxy Veeam
bx-it-graylog-vm,tier0 - SIEM Graylog
bx-seal-omega,tier0 - Controle d'acces physique SEAL (production)
bx-qa-seal-vm,tier1 - SEAL recette
bx-info-eset-vm,tier0 - Console ESET PROTECT
bx-files-it-vm,tier1 - Serveur de fichiers
bx-nps-it-vm,tier0 - NPS / RADIUS
bx-it-ems-vm,tier1 - FortiClient EMS
bx-it-waf-vm,tier1 - WAF BunkerWeb (DMZ)
bx-telephonie-vm,tier1 - Telephonie 3CX
bx-it-wsus-vm,tier1 - WSUS
bx-it-vaultwarden-vm,tier0 - Coffre de mots de passe Vaultwarden
"""
ACTIFS_PATH = "/etc/graylog/lookup/v3-actifs-critiques.csv"

R = {}
R["omni-v3-gmsa-lecture-utilisateur"] = r'''rule "omni-v3-gmsa-lecture-utilisateur"
when
  to_string($message.event_id) == "4662" &&
  contains(to_string($message.winlogbeat_winlog_event_data_Properties), "e362ed86-b728-0842-b27d-2dea7a9df218", true) &&
  !ends_with(to_string($message.winlogbeat_winlog_event_data_SubjectUserName), "$")
then
  set_field("v3_tag", "gmsa_lecture_utilisateur");
  set_field("v3_severite", "CRITIQUE");
  set_field("v3_mitre", "T1003");
end'''
R["omni-v3-kerberos-chiffrement-faible"] = r'''rule "omni-v3-kerberos-chiffrement-faible"
when
  (to_string($message.event_id) == "4768" &&
    (to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x17" ||
     to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x18" ||
     to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x1" ||
     to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x3")) ||
  (to_string($message.event_id) == "4769" &&
    (to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x1" ||
     to_string($message.winlogbeat_winlog_event_data_TicketEncryptionType) == "0x3"))
then
  set_field("v3_tag", "kerberos_chiffrement_faible");
  set_field("v3_severite", "ELEVE");
  set_field("v3_mitre", "T1558");
end'''
R["omni-v3-logon-admin"] = r'''rule "omni-v3-logon-admin"
when
  to_string($message.event_id) == "4624" &&
  to_string($message.account_class) == "admin" &&
  (to_string($message.winlogbeat_winlog_event_data_LogonType) == "2" ||
   to_string($message.winlogbeat_winlog_event_data_LogonType) == "10" ||
   to_string($message.winlogbeat_winlog_event_data_LogonType) == "11")
then
  let m = regex("^([^.]+)", to_string($message.host), ["h"]);
  set_field("v3_host", lowercase(to_string(m["h"])));
  set_field("v3_kind", "admin_logon");
end'''
R["omni-v3-eset-menace"] = r'''rule "omni-v3-eset-menace"
when
  to_string($message.eset_event_type) == "Threat_Event"
then
  let m = regex("^([^.]+)", to_string($message.eset_hostname), ["h"]);
  set_field("v3_host", lowercase(to_string(m["h"])));
  set_field("v3_kind", "eset_threat");
end'''
R["omni-v3-eset-non-remediee"] = r'''rule "omni-v3-eset-non-remediee"
when
  to_string($message.eset_event_type) == "Threat_Event" &&
  to_string($message.eset_outcome) == "non_remediee"
then
  set_field("v3_tag", "eset_non_remediee");
  set_field("v3_severite", "ELEVE");
  set_field("v3_mitre", "T1204");
end'''
R["omni-v3-fg-admin-local"] = r'''rule "omni-v3-fg-admin-local"
when
  to_string($message.user) == "admin" &&
  (to_string($message.logdesc) == "Admin login successful" ||
   to_string($message.logdesc) == "Action performed" ||
   to_string($message.logdesc) == "Object attribute configured" ||
   to_string($message.logdesc) == "Admin performed an action from GUI")
then
  set_field("v3_tag", "fg_admin_local");
  set_field("v3_severite", "ELEVE");
  set_field("v3_mitre", "T1078.003");
  set_field("v3_src", to_string($message.ui));
end'''
R["omni-v3-fg-admin-ip-publique"] = r'''rule "omni-v3-fg-admin-ip-publique"
when
  (to_string($message.logdesc) == "Admin login successful" ||
   to_string($message.logdesc) == "Admin login failed" ||
   to_string($message.logdesc) == "Object attribute configured" ||
   to_string($message.logdesc) == "Admin performed an action from GUI") &&
  regex("\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)", to_string($message.ui)).matches == true &&
  !cidr_match("10.0.0.0/8", to_ip(regex("\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)", to_string($message.ui), ["ip"])["ip"])) &&
  !cidr_match("172.16.0.0/12", to_ip(regex("\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)", to_string($message.ui), ["ip"])["ip"])) &&
  !cidr_match("192.168.0.0/16", to_ip(regex("\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)", to_string($message.ui), ["ip"])["ip"]))
then
  set_field("v3_tag", "fg_admin_ip_publique");
  set_field("v3_severite", "CRITIQUE");
  set_field("v3_mitre", "T1133");
  set_field("v3_src", to_string($message.ui));
end'''
R["omni-v3-fg-admin-echec"] = r'''rule "omni-v3-fg-admin-echec"
when
  to_string($message.logdesc) == "Admin login failed"
then
  set_field("v3_tag", "fg_admin_echec");
  set_field("v3_severite", "ELEVE");
  set_field("v3_mitre", "T1110");
  set_field("v3_src", to_string($message.ui));
end'''
R["omni-v3-veeam-restauration-inattendue"] = r'''rule "omni-v3-veeam-restauration-inattendue"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup" &&
  to_string($message.event_id) == "40210" &&
  regex("(?i)initiated by '[^']*(adm-[a-z0-9.-]+|gmsa-veeamtest\\$|Syst.me|SYSTEM)'", to_string($message.message)).matches == false
then
  set_field("v3_tag", "veeam_restauration_inattendue");
  set_field("v3_severite", "ELEVE");
  set_field("v3_mitre", "T1005");
end'''
R["omni-v3-veeam-suppression"] = r'''rule "omni-v3-veeam-suppression"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup" &&
  contains(to_string($message.message), "has been deleted", true) &&
  regex("(?i)(virtual lab|surebackup|application group|jobs has been deleted from)", to_string($message.message)).matches == false
then
  set_field("v3_tag", "veeam_suppression");
  set_field("v3_severite", "ELEVE");
  set_field("v3_mitre", "T1490");
end'''
# --- Champs demandés par l'agent DASHBOARDS (11/11/2026) ---
R["omni-v3-cert-template"] = r'''rule "omni-v3-cert-template"
when
  (to_string($message.event_id) == "4886" || to_string($message.event_id) == "4887" || to_string($message.event_id) == "4888") &&
  has_field("winlogbeat_winlog_event_data_CertificateTemplate")
then
  set_field("cert_template", to_string($message.winlogbeat_winlog_event_data_CertificateTemplate));
end'''
R["omni-v3-veeam-resultat"] = r'''rule "omni-v3-veeam-resultat"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup" &&
  regex("(?i)finished with '?(Success|Warning|Failed|Error)", to_string($message.message)).matches == true
then
  let r = regex("(?i)finished with '?(Success|Warning|Failed|Error)", to_string($message.message), ["res"]);
  set_field("veeam_result", lowercase(to_string(r["res"])));
end'''
R["omni-v3-veeam-job"] = r'''rule "omni-v3-veeam-job"
when
  to_string($message.winlogbeat_winlog_channel) == "Veeam Backup" &&
  regex("(?i)job '([^']+)'", to_string($message.message)).matches == true
then
  let j = regex("(?i)job '([^']+)'", to_string($message.message), ["job"]);
  set_field("veeam_job", to_string(j["job"]));
end'''
R["omni-v3-actif-critique"] = r'''rule "omni-v3-actif-critique"
when
  has_field("v3_host") &&
  to_string(lookup_value("omni-v3-actifs-critiques", to_string($message.v3_host), "")) != ""
then
  set_field("v3_actif", to_string(lookup_value("omni-v3-actifs-critiques", to_string($message.v3_host), "")));
end'''

PIPE_TITLE = "OMNI v3 - Detections et correlation"
PIPE_SRC = 'pipeline "' + PIPE_TITLE + '"\nstage 40 match either\n' + \
    "".join(f'rule "{n}"\n' for n in R if n != "omni-v3-actif-critique") + \
    'stage 41 match either\nrule "omni-v3-actif-critique"\nend'
PIPE_STREAMS = ["OMNI - Windows Security", "OMNI - Windows autres", "OMNI - ESET", "OMNI - FortiGate"]

N_TEAMS, N_TRIAGE = "6a2abf7265bc77613c83880e", "6a3fd983b5993e874b5d518e"
def ms(v): return v
DEFS = [
 # titre, description, priorite, streams, requete, group_by, series, seuil, fenetre_min, grace_min, etat
 ("OMNI v3 - Lecture du mot de passe d'un gMSA par un compte utilisateur",
  "CRITIQUE (T1003) - Un compte NON machine a lu msDS-ManagedPassword (4662). Seuls les serveurs autorises lisent un gMSA : vol d'identifiant de service probable. 0 occurrence sur 30 j au 11/11/2026. Agir : identifier le compte (SubjectUserName) et le poste, le desactiver, changer le mot de passe du gMSA (Reset-ADServiceAccountPassword).",
  3, ["OMNI - Windows Security"], "v3_tag:gmsa_lecture_utilisateur", [], "count", 1, 5, 10, "ENABLED"),
 ("OMNI v3 - Kerberos : chiffrement faible (RC4/DES) reapparu",
  "ELEVE (T1558) - Ticket Kerberos 4768 en RC4/DES ou 4769 en DES alors que RC4 est desactive sur le domaine. Degradation volontaire (AS-REP roasting, outil offensif) ou poste/compte mal configure. 0 occurrence sur 30 j au 11/11/2026.",
  2, ["OMNI - Windows Security"], "v3_tag:kerberos_chiffrement_faible", [], "count", 1, 5, 60, "ENABLED"),
 ("OMNI v3 - FortiGate : administration depuis une IP publique",
  "CRITIQUE (T1133) - Connexion ou modification d'administration FortiGate depuis une adresse non privee. L'administration doit venir du DC (API), des postes IT ou du VPN. 0 occurrence sur 30 j au 11/11/2026. Agir : verifier trusthost des admins et l'origine.",
  3, ["OMNI - FortiGate"], "v3_tag:fg_admin_ip_publique", [], "count", 1, 5, 10, "ENABLED"),
 ("OMNI v3 - FortiGate : usage du compte local admin",
  "ELEVE (T1078.003) - Le compte local partage « admin » a ete utilise (connexion, console, modification). Les admins doivent utiliser leur compte nominatif (SSO/LDAPS). ~10 sessions/mois au 11/11/2026 (Lancon 10.13.10.2, 10.33.120.10, 10.33.10.9) : a reduire puis a passer en CRITIQUE.",
  2, ["OMNI - FortiGate"], "v3_tag:fg_admin_local", ["v3_src"], "count", 1, 5, 480, "ENABLED"),
 ("OMNI v3 - FortiGate : echecs de connexion admin repetes (>=5 / source / 10 min)",
  "ELEVE (T1110) - Au moins 5 echecs de connexion admin depuis la meme source en 10 min. Rappel : un script du DC (10.33.50.250) envoie parfois un jeton comme nom d'utilisateur (17 echecs isoles sur 30 j, sous le seuil).",
  2, ["OMNI - FortiGate"], "v3_tag:fg_admin_echec", ["v3_src"], "count", 5, 10, 60, "ENABLED"),
 ("OMNI v3 - ESET : menace NON remediee",
  "ELEVE (T1204) - ESET a detecte une menace sans pouvoir la nettoyer (eset_outcome=non_remediee). 6 cas sur 30 j au 11/11/2026. Agir : analyse complete du poste, isoler si besoin.",
  2, ["OMNI - ESET"], "v3_tag:eset_non_remediee", ["v3_host"], "count", 1, 5, 240, "ENABLED"),
 ("OMNI v3 - ESET : menace NON remediee sur un actif critique",
  "CRITIQUE (T1204) - Menace non nettoyee sur un serveur Tier 0/1 (table omni-v3-actifs-critiques : DC, PKI, Veeam, SIEM, SEAL, ESET, NPS, Vaultwarden...). Isoler et investiguer immediatement.",
  3, ["OMNI - ESET"], "v3_tag:eset_non_remediee AND _exists_:v3_actif", ["v3_host"], "count", 1, 5, 60, "ENABLED"),
 ("OMNI v3 - Veeam : restauration lancee par un compte inattendu",
  "ELEVE (T1005) - Session de restauration Veeam (40210) lancee par un compte autre que adm-*, gmsa-veeamtest$ ou SYSTEM : exfiltration possible via restauration. 0 occurrence sur 30 j au 11/11/2026.",
  2, ["OMNI - Windows autres"], "v3_tag:veeam_restauration_inattendue", [], "count", 1, 5, 60, "ENABLED"),
 ("OMNI v3 - Veeam : suppression de job ou de sauvegarde",
  "ELEVE (T1490) - Un job, une sauvegarde ou un depot Veeam a ete supprime (hors laboratoires SureBackup). Precurseur classique de rancongiciel. 0 occurrence sur 30 j au 11/11/2026 (14 suppressions de labos ecartees).",
  2, ["OMNI - Windows autres"], "v3_tag:veeam_suppression", [], "count", 1, 5, 30, "ENABLED"),
 ("OMNI v3 - Correlation : menace ESET + connexion admin sur le meme poste (1 h)",
  "CRITIQUE (T1078 + T1204) - Sur le meme hote, une menace ESET ET une ouverture de session interactive/RDP d'un compte admin dans la meme heure : risque de vol d'identifiant privilegie sur un poste compromis. 0 occurrence sur 30 j au 11/11/2026.",
  3, ["OMNI - Windows Security", "OMNI - ESET"], "_exists_:v3_kind", ["v3_host"], "card", 2, 60, 120, "ENABLED"),
 ("OMNI v3 - Connexion admin RDP vers un actif critique depuis un segment utilisateurs",
  "ELEVE (T1078.002) - Session RDP d'un compte admin vers un actif Tier 0/1 depuis le LAN utilisateurs (10.33.10/20). DESACTIVEE au 11/11/2026 : ~70 connexions admin RDP/mois hors VLAN 81 (pilote). A activer quand le VLAN 81 admin sera generalise.",
  2, ["OMNI - Windows Security"], "v3_kind:admin_logon AND winlogbeat_winlog_event_data_LogonType:10 AND _exists_:v3_actif AND winlogbeat_winlog_event_data_IpAddress:(10.33.10.* OR 10.33.20.*)", ["v3_host"], "count", 1, 5, 240, "DISABLED"),
]

def streams_ids():
    return {s["title"]: s["id"] for s in api("GET", "/streams")["streams"]}

def def_body(d, sid):
    titre, desc, prio, streams, q, gb, serie, seuil, fen, grace, etat = d
    if serie == "card":
        series = [{"type": "card", "id": "card(v3_kind)", "field": "v3_kind"}]; ref = "card(v3_kind)"
    else:
        series = [{"type": "count", "id": "count()", "field": None}]; ref = "count()"
    return {"title": titre, "description": desc, "priority": prio, "alert": True,
            "config": {"type": "aggregation-v1", "query": q, "query_parameters": [], "filters": [], "streams": [sid[s] for s in streams],
                       "stream_categories": [], "group_by": gb, "series": series,
                       "conditions": {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": ref}, "right": {"expr": "number", "value": seuil}}},
                       "search_within_ms": fen * 60000, "execute_every_ms": 300000, "use_cron_scheduling": False, "event_limit": 50},
            "field_spec": {}, "key_spec": [], "notification_settings": {"grace_period_ms": grace * 60000, "backlog_size": 10},
            "notifications": [{"notification_id": N_TEAMS, "notification_parameters": None}, {"notification_id": N_TRIAGE, "notification_parameters": None}],
            "storage": [{"type": "persist-to-streams-v1", "streams": ["000000000000000000000002"]}],
            "state": etat}

def mesure():
    """Débit et durée moyenne de traitement (gl2_processing_duration_ms) sur 15 min, par flux concerné."""
    out = {}
    for idx in ["omni-winsec", "omni-fortigate", "omni-winother", "omni-eset"]:
        q = {"size": 0, "query": {"range": {"timestamp": {"gte": "now-15m"}}}, "aggs": {"d": {"avg": {"field": "gl2_processing_duration_ms"}}, "p": {"percentiles": {"field": "gl2_processing_duration_ms", "percents": [99]}}}}
        req = urllib.request.Request(f"http://127.0.0.1:9200/{idx}_*/_search", data=json.dumps(q).encode(), headers={"Content-Type": "application/json"})
        r = json.loads(urllib.request.urlopen(req, timeout=60).read())
        out[idx] = {"messages_15min": r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"],
                    "duree_moy_ms": round(r["aggregations"]["d"]["value"] or 0, 3), "p99_ms": round(list(r["aggregations"]["p"]["values"].values())[0] or 0, 2)}
    return out

def main():
    if not TOKEN: sys.exit("jeton API absent de 00-vars.env")
    # 1. Vérification de syntaxe par Graylog (aucune création)
    for n, src in R.items():
        try: api("POST", "/system/pipelines/rule/parse", {"title": n, "description": "", "source": src})
        except RuntimeError as e: sys.exit(f"ERREUR SYNTAXE {n} : {e}")
    print(f"syntaxe OK : {len(R)} regles")
    try: api("POST", "/system/pipelines/pipeline/parse", {"title": PIPE_TITLE, "description": "", "source": PIPE_SRC}); print("syntaxe pipeline OK")
    except RuntimeError as e:
        # le parse du pipeline échoue tant que les règles n'existent pas : on le signale seulement
        print(f"parse pipeline (avant creation des regles) : {str(e)[:160]}")
    sid = streams_ids(); manq = [s for d in DEFS for s in d[3] if s not in sid] + [s for s in PIPE_STREAMS if s not in sid]
    if manq: sys.exit(f"streams introuvables : {set(manq)}")
    print(f"{len(DEFS)} definitions preparees ; streams OK")
    if MODE != "--appliquer":
        print("SIMULATION : rien n'a ete cree"); return
    # 2. Sauvegarde
    os.makedirs(SAUV, mode=0o700, exist_ok=True)
    uri = [l.split("=", 1)[1].strip() for l in open("/etc/graylog/server/server.conf") if l.startswith("mongodb_uri")][0]
    for c in ["event_definitions", "pipeline_processor_rules", "pipeline_processor_pipelines", "pipeline_processor_pipelines_streams", "lut_tables", "lut_caches", "lut_data_adapters"]:
        subprocess.run(["mongoexport", "--quiet", f"--uri={uri}", f"--collection={c}", f"--out={SAUV}/{c}.json"], check=True)
    json.dump(mesure(), open(f"{SAUV}/perf-avant.json", "w"), indent=1)
    print(f"sauvegarde + mesure avant : {SAUV}")
    # 3. Lookup actifs critiques
    with open(ACTIFS_PATH, "w", encoding="utf-8") as f: f.write(ACTIFS_CSV)
    os.chmod(ACTIFS_PATH, 0o644)
    adp = {a["name"]: a for a in api("GET", "/system/lookup/adapters?per_page=500")["data_adapters"]}
    if "omni-v3-actifs-critiques-adapter" not in adp:
        a = api("POST", "/system/lookup/adapters", {"name": "omni-v3-actifs-critiques-adapter", "title": "OMNI v3 - Actifs critiques (CSV)", "description": "Hote court -> tier et role. Fichier " + ACTIFS_PATH,
              "config": {"type": "csvfile", "path": ACTIFS_PATH, "separator": ",", "quotechar": "\"", "key_column": "cle", "value_column": "valeur", "check_interval": 60, "case_insensitive_lookup": True, "cidr_lookup": False}})
        CREES.append(("adapters", a["id"], a["name"])); adp_id = a["id"]
    else: adp_id = adp["omni-v3-actifs-critiques-adapter"]["id"]
    cac = {c["name"]: c for c in api("GET", "/system/lookup/caches?per_page=500")["caches"]}
    if "omni-v3-actifs-critiques-cache" not in cac:
        c = api("POST", "/system/lookup/caches", {"name": "omni-v3-actifs-critiques-cache", "title": "OMNI v3 - Actifs critiques (cache)", "description": "",
              "config": {"type": "guava_cache", "max_size": 1000, "expire_after_access": 300, "expire_after_access_unit": "SECONDS", "expire_after_write": 300, "expire_after_write_unit": "SECONDS", "ignore_null": False, "ttl_empty": 60, "ttl_empty_unit": "SECONDS"}})
        CREES.append(("caches", c["id"], c["name"])); cac_id = c["id"]
    else: cac_id = cac["omni-v3-actifs-critiques-cache"]["id"]
    tab = {t["name"]: t for t in api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"]}
    if "omni-v3-actifs-critiques" not in tab:
        t = api("POST", "/system/lookup/tables", {"name": "omni-v3-actifs-critiques", "title": "OMNI v3 - Actifs critiques", "description": "Utilisee par la regle omni-v3-actif-critique (champ v3_actif)",
              "cache_id": cac_id, "data_adapter_id": adp_id, "default_single_value": "", "default_single_value_type": "NULL", "default_multi_value": "", "default_multi_value_type": "NULL"})
        CREES.append(("tables", t["id"], t["name"]))
    print("lookup omni-v3-actifs-critiques OK")
    # 4. Règles + pipeline + connexion
    exist = {r["title"]: r for r in api("GET", "/system/pipelines/rule")}
    for n, src in R.items():
        if n in exist: continue
        r = api("POST", "/system/pipelines/rule", {"title": n, "description": "OMNITECH v3 11/11/2026", "source": src})
        CREES.append(("rule", r["id"], n))
    pipes = {p["title"]: p for p in api("GET", "/system/pipelines/pipeline")}
    if PIPE_TITLE in pipes:
        pid = pipes[PIPE_TITLE]["id"]
        if pipes[PIPE_TITLE]["source"].strip() != PIPE_SRC.strip():
            api("PUT", f"/system/pipelines/pipeline/{pid}", {"title": PIPE_TITLE, "description": pipes[PIPE_TITLE].get("description", ""), "source": PIPE_SRC})
            print("pipeline mis a jour (nouvelles regles)")
    else:
        p = api("POST", "/system/pipelines/pipeline", {"title": PIPE_TITLE, "description": "Detections et correlation v3 (11/11/2026). Etapes 40-41, apres tous les enrichissements.", "source": PIPE_SRC})
        pid = p["id"]; CREES.append(("pipeline", pid, PIPE_TITLE))
    api("POST", "/system/pipelines/connections/to_pipeline", {"pipeline_id": pid, "stream_ids": [sid[s] for s in PIPE_STREAMS]})
    print(f"{len(R)} regles + pipeline connecte a {len(PIPE_STREAMS)} streams")
    # 5. Définitions
    edefs = {d["title"] for d in api("GET", "/events/definitions?per_page=500")["event_definitions"]}
    for d in DEFS:
        if d[0] in edefs: continue
        e = api("POST", "/events/definitions?schedule=" + ("true" if d[10] == "ENABLED" else "false"), {"entity": def_body(d, sid)})
        CREES.append(("definition", e["id"], d[0]))
    print(f"definitions creees : {sum(1 for c in CREES if c[0]=='definition')}")
    # 6. Script de retour (suppression PAR NOM : couvre tous les passages)
    with open("/root/omni-v3/retour.sh", "w") as f:
        f.write("#!/bin/bash\n# Retour couche OMNI v3 (11/11/2026) : supprime tous les objets « OMNI v3 - » / omni-v3-*\ncd /root/omni-v3 && python3 -I v3_build.py --retour\n")
    os.chmod("/root/omni-v3/retour.sh", 0o700)
    json.dump(CREES, open(f"{SAUV}/objets-crees.json", "w"), indent=1, ensure_ascii=False)
    print(f"retour : /root/omni-v3/retour.sh ; objets crees a ce passage : {len(CREES)}")
    print("MESURE_AVANT", json.dumps(json.load(open(f"{SAUV}/perf-avant.json"))))

def retour():
    n = 0
    for d in api("GET", "/events/definitions?per_page=500")["event_definitions"]:
        if d["title"].startswith("OMNI v3 - "): api("DELETE", f"/events/definitions/{d['id']}"); n += 1
    for p in api("GET", "/system/pipelines/pipeline"):
        if p["title"] == PIPE_TITLE: api("DELETE", f"/system/pipelines/pipeline/{p['id']}"); n += 1
    for r in api("GET", "/system/pipelines/rule"):
        if r["title"].startswith("omni-v3-"): api("DELETE", f"/system/pipelines/rule/{r['id']}"); n += 1
    for t in api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"]:
        if t["name"] == "omni-v3-actifs-critiques": api("DELETE", f"/system/lookup/tables/{t['id']}"); n += 1
    for c in api("GET", "/system/lookup/caches?per_page=500")["caches"]:
        if c["name"] == "omni-v3-actifs-critiques-cache": api("DELETE", f"/system/lookup/caches/{c['id']}"); n += 1
    for a in api("GET", "/system/lookup/adapters?per_page=500")["data_adapters"]:
        if a["name"] == "omni-v3-actifs-critiques-adapter": api("DELETE", f"/system/lookup/adapters/{a['id']}"); n += 1
    if os.path.exists(ACTIFS_PATH): os.remove(ACTIFS_PATH)
    print(f"retour : {n} objets supprimes")

if __name__ == "__main__":
    if MODE == "--mesure": print(json.dumps(mesure())); sys.exit(0)
    if MODE == "--retour": retour(); sys.exit(0)
    main()
