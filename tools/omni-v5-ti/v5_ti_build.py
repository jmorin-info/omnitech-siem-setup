#!/usr/bin/env python3
# OMNITECH 27/11/2026 - SIEM v5 chantier 3 « Threat intelligence » (go jmorin).
# Usage (root, BX-IT-GRAYLOG-VM) :
#   python3 -I v5_ti_build.py --simuler            syntaxe des règles par Graylog, rien n'est créé
#   python3 -I v5_ti_build.py --appliquer          sauvegarde, crée tables/règles/pipeline/définitions (NON planifiées sans rodage)
#   python3 -I v5_ti_build.py --planifier          planifie les définitions (seulement si le rodage est posé : --rodage-ok)
#   python3 -I v5_ti_build.py --test               simulateur de pipeline (messages synthétiques)
#   python3 -I v5_ti_build.py --mesure             latence de traitement (15 min) + métriques des tables/règles v5-ti
#   python3 -I v5_ti_build.py --retour [--simuler] supprime PAR NOM tout ce qui commence par omni-v5-ti / « OMNI v5 - TI »
# Idempotent. Aucun secret affiché ni écrit.
import base64, http.client, json, os, re, ssl, subprocess, sys, time, urllib.error, urllib.request
http.client._MAXHEADERS = 10000

ARGS = sys.argv[1:]
MODE = ARGS[0] if ARGS else "--simuler"
env = {}
for l in open("/root/omnitech-siem-setup/00-vars.env", encoding="utf-8"):
    m = re.match(r'^(?:export\s+)?([A-Z_]+)=["\']?([^"\'\n]*)', l)
    if m: env[m.group(1)] = m.group(2)
API = "https://127.0.0.1:9000/api"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
_tok = env.get("GRAYLOG_API_TOKEN", "")
AUTH = "Basic " + base64.b64encode((f"{_tok}:token" if _tok else f"admin:{env.get('GRAYLOG_ADMIN_PASS', '')}").encode()).decode()
TS = time.strftime("%Y%m%d-%H%M")
SAUV = f"/var/backups/siem/v5-ti-avant-{TS}"
BASE = "/root/omni-v5-ti"
LOOKUP = "/etc/graylog/lookup/ti"
NODE_ID = open("/etc/graylog/server/node-id").read().strip()
CREES = []

def api(meth, path, body=None, timeout=60):
    req = urllib.request.Request(API + path, method=meth, data=(json.dumps(body).encode() if body is not None else None),
                                 headers={"Authorization": AUTH, "Content-Type": "application/json", "Accept": "application/json", "X-Requested-By": "omni-v5-ti"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            t = r.read().decode(); return json.loads(t) if t else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{meth} {path} -> {e.code} {e.read().decode()[:500]}")

# ------------------------------------------------------------------ tables
TABLES = {  # nom court -> (fichier, description)
    "ip": ("ip.csv", "IP -> source|type|malware|confiance|ports|date|ref (Feodo, ThreatFox ip:port, URLhaus IP, Tor)"),
    "domaine": ("domaine.csv", "Domaine -> ThreatFox (domaines + hotes d'URL hors infra partagee)"),
    "urlhaus-hote": ("urlhaus-hote.csv", "Hote -> URLhaus (URL online 30 j, hors infra partagee)"),
    "urlhaus-url": ("urlhaus-url.csv", "URL exacte -> URLhaus (URL online 30 j)"),
    "hachage": ("hachage.csv", "Hachage sha256/sha1/md5 -> MalwareBazaar (30 j) / ThreatFox"),
}

# ------------------------------------------------------------------ règles
PARSE = r'regex("^([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|(.*)$", to_string(lookup_value("%(t)s", %(k)s)), ["s","t","m","c","p","f","r"])'
def corps(table, key, extra):
    p = PARSE % {"t": table, "k": key}
    return f'''  let v = {p};
  set_field("ti_match", {key});
  set_field("ti_source", v["s"]);
  set_field("ti_type", v["t"]);
  set_field("ti_malware", v["m"]);
  set_field("ti_confiance", v["c"]);
  set_field("ti_ioc_date", v["f"]);
  set_field("ti_ref", v["r"]);
  set_field("ti_tag", "omni_v5_ti");
{extra}'''

R = {}
def regle(nom, cond, table, key, extra=""):
    R[nom] = f'rule "{nom}"\nwhen\n{cond} &&\n  !is_null(lookup_value("{table}", {key}))\nthen\n{corps(table, key, extra)}end'

FG = 'to_string($message.event_source) == "fortigate"'
DEST = 'to_string($message.dest_ip)'; SRC = 'to_string($message.src_ip)'
regle("omni-v5-ti-fg-ip-dest", f'  {FG} &&\n  has_field("dest_ip") &&\n  to_string($message.dst_priv) == "false"', "omni-v5-ti-ip", DEST,
      '  set_field("ti_direction", "sortant");\n  set_field("ti_ioc_ports", v["p"]);\n'
      '  set_field("ti_port_match", contains(to_string(v["p"]), concat(concat(";", to_string($message.dest_port)), ";")));\n')
regle("omni-v5-ti-fg-ip-src", f'  {FG} &&\n  has_field("src_ip") &&\n  to_string($message.src_priv) == "false"', "omni-v5-ti-ip", SRC,
      '  set_field("ti_direction", "entrant");\n  set_field("ti_ioc_ports", v["p"]);\n')
QN = 'lowercase(to_string($message.qname))'
regle("omni-v5-ti-fg-dns-domaine", f'  {FG} &&\n  to_string($message.subtype) == "dns" &&\n  has_field("qname")', "omni-v5-ti-domaine", QN, '  set_field("ti_contexte", "dns");\n')
regle("omni-v5-ti-fg-dns-urlhaus", f'  {FG} &&\n  to_string($message.subtype) == "dns" &&\n  has_field("qname")', "omni-v5-ti-urlhaus-hote", QN, '  set_field("ti_contexte", "dns");\n')
HN = 'lowercase(to_string($message.hostname))'
WEB = f'  {FG} &&\n  to_string($message.type) == "utm" &&\n  to_string($message.subtype) != "dns" &&\n  has_field("hostname")'
regle("omni-v5-ti-fg-web-domaine", WEB, "omni-v5-ti-domaine", HN, '  set_field("ti_contexte", "web");\n')
regle("omni-v5-ti-fg-web-urlhaus", WEB, "omni-v5-ti-urlhaus-hote", HN, '  set_field("ti_contexte", "web");\n')
regle("omni-v5-ti-fg-web-url", f'  {FG} &&\n  to_string($message.type) == "utm" &&\n  has_field("url")', "omni-v5-ti-urlhaus-url", 'to_string($message.url)', '  set_field("ti_contexte", "web");\n')
SY = 'to_string($message.event_source) == "sysmon"'
DQ = 'lowercase(to_string($message.dns_query))'
SY22 = f'  {SY} &&\n  to_string($message.winlogbeat_winlog_event_id) == "22" &&\n  has_field("dns_query")'
regle("omni-v5-ti-sysmon-dns-domaine", SY22, "omni-v5-ti-domaine", DQ, '  set_field("ti_contexte", "dns");\n')
regle("omni-v5-ti-sysmon-dns-urlhaus", SY22, "omni-v5-ti-urlhaus-hote", DQ, '  set_field("ti_contexte", "dns");\n')
HX = 'to_string(regex("SHA256=([0-9A-Fa-f]{64})", to_string($message.winlogbeat_winlog_event_data_Hashes), ["h"])["h"])'
HX15 = 'to_string(regex("SHA256=([0-9A-Fa-f]{64})", to_string($message.winlogbeat_winlog_event_data_Hash), ["h"])["h"])'
regle("omni-v5-ti-sysmon-hash-exec", f'  {SY} &&\n  (to_string($message.winlogbeat_winlog_event_id) == "1" || to_string($message.winlogbeat_winlog_event_id) == "7") &&\n  has_field("winlogbeat_winlog_event_data_Hashes")',
      "omni-v5-ti-hachage", HX, '  set_field("ti_contexte", "execution");\n')
regle("omni-v5-ti-sysmon-hash-fichier", f'  {SY} &&\n  (to_string($message.winlogbeat_winlog_event_id) == "6" || to_string($message.winlogbeat_winlog_event_id) == "23" || to_string($message.winlogbeat_winlog_event_id) == "26" || to_string($message.winlogbeat_winlog_event_id) == "29") &&\n  has_field("winlogbeat_winlog_event_data_Hashes")',
      "omni-v5-ti-hachage", HX, '  set_field("ti_contexte", "fichier");\n')
regle("omni-v5-ti-sysmon-hash-ads", f'  {SY} &&\n  to_string($message.winlogbeat_winlog_event_id) == "15" &&\n  has_field("winlogbeat_winlog_event_data_Hash")',
      "omni-v5-ti-hachage", HX15, '  set_field("ti_contexte", "fichier");\n')
ES = 'to_string($message.event_source) == "eset"'
regle("omni-v5-ti-eset-hash", f'  {ES} &&\n  has_field("eset_hash")', "omni-v5-ti-hachage", 'lowercase(to_string($message.eset_hash))', '  set_field("ti_contexte", "eset");\n')
EH = 'lowercase(to_string(regex("^[a-zA-Z]+://([^/:?#]+)", to_string($message.eset_object_uri), ["h"])["h"]))'
EU = f'  {ES} &&\n  starts_with(to_string($message.eset_object_uri), "http", true)'
regle("omni-v5-ti-eset-url-urlhaus", EU, "omni-v5-ti-urlhaus-hote", EH, '  set_field("ti_contexte", "eset_web");\n')
regle("omni-v5-ti-eset-url-domaine", EU, "omni-v5-ti-domaine", EH, '  set_field("ti_contexte", "eset_web");\n')
regle("omni-v5-ti-eset-url-exacte", EU, "omni-v5-ti-urlhaus-url", 'to_string($message.eset_object_uri)', '  set_field("ti_contexte", "eset_web");\n')

PIPE_TITLE = "OMNI v5 - TI enrichissement"
STAGE = 19  # après Exposition reseau (14-17 : src_priv/dst_priv) et Threat Intel IOC (18), avant v3 (40)
PIPE_SRC = f'pipeline "{PIPE_TITLE}"\nstage {STAGE} match either\n' + "".join(f'rule "{n}"\n' for n in R) + 'end'
PIPE_STREAMS = ["OMNI - FortiGate", "OMNI - Sysmon", "OMNI - ESET"]

# ------------------------------------------------------------------ définitions
N_TRIAGE = "6a3fd983b5993e874b5d518e"   # « OMNI - Triage (mail critique) » : le rodage (chantier 2) route « OMNI v5 - » au récapitulatif
AUT = r'action:(accept OR close OR timeout OR start OR server\-rst OR client\-rst)'
DEFS = [
 # titre, description, priorité, streams, requête, group_by, seuil, fenêtre (min), grâce (min)
 ("OMNI v5 - TI : connexion sortante AUTORISEE vers un C2 Feodo",
  "CRITIQUE (T1071) - Le FortiGate a laisse passer une connexion d'un poste/serveur vers une IP de C2 botnet Feodo Tracker (liste recommandee = haute confiance, ou liste standard). Agir : identifier src_ip (DHCP), isoler le poste, analyse ESET complete. Table omni-v5-ti-ip (ti_source=feodo).",
  3, ["OMNI - FortiGate"], f"ti_source:feodo AND ti_direction:sortant AND type:traffic AND {AUT}", ["src_ip"], 1, 10, 60),
 ("OMNI v5 - TI : connexion vers un C2 Feodo BLOQUEE par le FortiGate",
  "ATTENTION (T1071) - Tentative de connexion vers un C2 Feodo refusee par le FortiGate (deny/ip-conn). Pas d'echange, mais le poste source peut etre infecte : verifier src_ip.",
  2, ["OMNI - FortiGate"], r"ti_source:feodo AND ti_direction:sortant AND type:traffic AND action:(deny OR ip\-conn)", ["src_ip"], 1, 60, 240),
 ("OMNI v5 - TI : connexion sortante autorisee vers une IP:port malveillante (ThreatFox/URLhaus, port identique)",
  "ATTENTION (T1071/T1105) - Connexion autorisee vers une IP:port publiee par ThreatFox (C2, distribution) ou URLhaus (URL sur IP), sur le MEME port que l'indicateur, confiance haute ou moyenne. Un port different est ecarte (hebergement partage).",
  2, ["OMNI - FortiGate"], f"ti_source:(threatfox OR urlhaus) AND ti_direction:sortant AND ti_port_match:true AND ti_confiance:(haute OR moyenne) AND type:traffic AND {AUT}", ["src_ip"], 1, 60, 240),
 ("OMNI v5 - TI : resolution DNS d'un domaine ThreatFox",
  "ATTENTION (T1071.004) - Un poste a resolu un domaine (ou hote d'URL) publie par ThreatFox dans les 30 derniers jours (Sysmon 22 ou journal DNS FortiGate). Verifier le processus (Sysmon Image) et la suite (connexion).",
  2, ["OMNI - Sysmon", "OMNI - FortiGate"], "ti_source:threatfox AND ti_contexte:dns AND ti_confiance:(haute OR moyenne)", ["ti_match"], 1, 60, 240),
 ("OMNI v5 - TI : acces a un hote ou une URL URLhaus en ligne (DNS, web, ESET)",
  "ATTENTION (T1105/T1189) - Resolution DNS, session web FortiGate ou URL vue par ESET vers un site de distribution de logiciel malveillant URLhaus EN LIGNE (30 j, hors infra partagee). Verifier le telechargement et ESET sur le poste.",
  2, ["OMNI - Sysmon", "OMNI - FortiGate", "OMNI - ESET"], "ti_source:urlhaus AND ti_contexte:(dns OR web OR eset_web)", ["ti_match"], 1, 60, 240),
 ("OMNI v5 - TI : hachage malveillant EXECUTE sur un poste (Sysmon 1/7)",
  "CRITIQUE (T1204) - Un processus (Sysmon 1) ou une DLL (Sysmon 7) dont le SHA-256 est publie par MalwareBazaar ou ThreatFox a ete execute/charge. Agir : isoler le poste, analyse ESET, recuperer le binaire (Image / ImageLoaded).",
  3, ["OMNI - Sysmon"], "ti_contexte:execution AND _exists_:ti_source", ["source"], 1, 10, 60),
 ("OMNI v5 - TI : hachage malveillant vu hors execution (fichier Sysmon, ESET)",
  "ATTENTION (T1204) - Hachage MalwareBazaar/ThreatFox vu sur un fichier (Sysmon 6/15/23/26/29) ou dans une detection ESET, sans execution prouvee.",
  2, ["OMNI - Sysmon", "OMNI - ESET"], "ti_contexte:(fichier OR eset) AND _exists_:ti_source", ["ti_match"], 1, 60, 240),
 ("OMNI v5 - TI : trafic sortant autorise vers un noeud de sortie Tor",
  "ATTENTION (T1090.003) - Connexion autorisee d'un hote interne vers une IP de la liste officielle des noeuds de sortie Tor (beaucoup sont aussi des relais : usage de Tor ou d'un service heberge sur un noeud). Verifier le poste et le service. NTP (123) exclu : des noeuds Tor sont aussi serveurs pool.ntp.org (rejeu 27/11 : 50 sessions NTP de 10.33.10.51).",
  2, ["OMNI - FortiGate"], f"ti_source:tor AND ti_direction:sortant AND src_priv:true AND type:traffic AND {AUT} AND NOT dest_port:123", ["src_ip"], 1, 60, 480),
 ("OMNI v5 - TI : trafic entrant accepte depuis un noeud de sortie Tor (INFO)",
  "INFO (T1090.003) - Session entrante acceptee par le FortiGate depuis un noeud de sortie Tor (services publies : WAF, VPN...). Compteur de bruit, pour le recapitulatif uniquement.",
  1, ["OMNI - FortiGate"], f"ti_source:tor AND ti_direction:entrant AND type:traffic AND {AUT}", ["dest_ip"], 1, 60, 720),
]
# rodage : définitions planifiées seulement si C:\DC\SIEM\Graylog\v5\tri\RODAGE-ACTIF.txt existe (contrôlé depuis le DC, --rodage-ok)
RODAGE_OK = "--rodage-ok" in ARGS

def def_body(d, sid, etat):
    titre, desc, prio, streams, q, gb, seuil, fen, grace = d
    return {"title": titre, "description": desc, "priority": prio, "alert": True,
            "config": {"type": "aggregation-v1", "query": q, "query_parameters": [], "filters": [], "streams": [sid[s] for s in streams],
                       "stream_categories": [], "group_by": gb, "series": [{"type": "count", "id": "count()", "field": None}],
                       "conditions": {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"}, "right": {"expr": "number", "value": seuil}}},
                       "search_within_ms": fen * 60000, "execute_every_ms": 300000, "use_cron_scheduling": False, "event_limit": 50},
            "field_spec": {}, "key_spec": [], "notification_settings": {"grace_period_ms": grace * 60000, "backlog_size": 10},
            "notifications": [{"notification_id": N_TRIAGE, "notification_parameters": None}],
            "storage": [{"type": "persist-to-streams-v1", "streams": ["000000000000000000000002"]}],
            "state": etat}

# ------------------------------------------------------------------ routage GELF ti_fetch / ti_retro vers « Interne SIEM »
ROUTAGE = [("OMNI - Interne SIEM", False), ("OMNI - M365", True)]
EVT_SOURCES = ["ti_fetch", "ti_retro"]
RDESC = "omni-v5-ti (chantier 3 SIEM v5, 27/11/2026)"

def streams():
    return {s["title"]: s for s in api("GET", "/streams")["streams"]}

def recharge(rules=(), pipes=()):
    """Rechargement à chaud (cluster_events) au cas où l'API ne l'aurait pas propagé : sans redémarrage."""
    uri = [l.split("=", 1)[1].strip() for l in open("/etc/graylog/server/server.conf") if l.startswith("mongodb_uri")][0]
    ms = int(time.time() * 1000)
    js = ("db.cluster_events.insertOne({timestamp: NumberLong(%d), producer: '%s', consumers: [], event_class: 'org.graylog.plugins.pipelineprocessor.events.RulesChangedEvent', payload: {updated_rules: %s, deleted_rules: []}});"
          "db.cluster_events.insertOne({timestamp: NumberLong(%d), producer: '%s', consumers: [], event_class: 'org.graylog.plugins.pipelineprocessor.events.PipelinesChangedEvent', payload: {updated_pipeline_ids: %s, deleted_pipeline_ids: []}});"
          % (ms, NODE_ID, json.dumps([{"id": i, "title": t} for i, t in rules]), ms, NODE_ID, json.dumps(list(pipes))))
    subprocess.run(["mongosh", "--quiet", uri, "--eval", js], check=True, stdout=subprocess.DEVNULL)

def mesure():
    """Latence moyenne/p99 (gl2_processing_duration_ms) sur 15 min par flux + temps du ProcessBufferProcessor."""
    out = {"horodatage": time.strftime("%Y-%m-%d %H:%M:%S")}
    for idx in ["omni-fortigate", "omni-sysmon", "omni-eset"]:
        q = {"size": 0, "query": {"range": {"timestamp": {"gte": "now-15m"}}}, "track_total_hits": True,
             "aggs": {"d": {"avg": {"field": "gl2_processing_duration_ms"}}, "p": {"percentiles": {"field": "gl2_processing_duration_ms", "percents": [50, 99]}}}}
        req = urllib.request.Request(f"http://127.0.0.1:9200/{idx}_*/_search", data=json.dumps(q).encode(), headers={"Content-Type": "application/json"})
        r = json.loads(urllib.request.urlopen(req, timeout=120).read())
        pv = r["aggregations"]["p"]["values"]
        out[idx] = {"messages_15min": r["hits"]["total"]["value"], "duree_moy_ms": round(r["aggregations"]["d"]["value"] or 0, 3),
                    "p50_ms": round(pv.get("50.0") or 0, 2), "p99_ms": round(pv.get("99.0") or 0, 2)}
    pt = api("GET", "/system/metrics/org.graylog2.shared.buffers.processors.ProcessBufferProcessor.processTime")
    out["processbuffer_moy_ms"] = round(pt["mean"] * 1000, 4); out["processbuffer_p99_ms"] = round(pt["p99"] * 1000, 3)
    out["processbuffer_debit_m1"] = round(pt.get("m1_rate", 0), 1)
    out["tampon_process"] = api("GET", "/system/metrics/org.graylog2.buffers.process.usage")["value"]
    out["journal_non_commite"] = api("GET", "/system/metrics/org.graylog2.shared.journal.KafkaJournal.uncommittedMessages")["value"]
    # métriques propres : temps des tables v5-ti (lookupTime des caches) et exécutions des règles
    tabs = {t["name"]: t for t in api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"] if t["name"].startswith("omni-v5-ti-")}
    for n, t in tabs.items():
        try:
            m = api("GET", f"/system/metrics/org.graylog2.lookup.caches.{t['cache_id']}.lookupTime")
            req_ = api("GET", f"/system/metrics/org.graylog2.lookup.caches.{t['cache_id']}.requests")
            hits = api("GET", f"/system/metrics/org.graylog2.lookup.caches.{t['cache_id']}.hits")
            out[n] = {"requetes": req_.get("count"), "succes_cache": hits.get("count"), "lookup_moy_us": round(m["mean"] * 1e6, 2) if m.get("mean") else None,
                      "lookup_p99_us": round(m["p99"] * 1e6, 2) if m.get("p99") else None, "debit_m1": round(m.get("m1_rate", 0), 1)}
        except RuntimeError: pass
    return out

def sauvegarde():
    os.makedirs(SAUV, mode=0o700, exist_ok=True)
    uri = [l.split("=", 1)[1].strip() for l in open("/etc/graylog/server/server.conf") if l.startswith("mongodb_uri")][0]
    for c in ["event_definitions", "pipeline_processor_rules", "pipeline_processor_pipelines", "pipeline_processor_pipelines_streams",
              "lut_tables", "lut_caches", "lut_data_adapters", "streamrules"]:
        subprocess.run(["mongoexport", "--quiet", f"--uri={uri}", f"--collection={c}", f"--out={SAUV}/{c}.json"], check=True)
    json.dump(api("GET", "/streams"), open(f"{SAUV}/streams.json", "w"), indent=1)
    subprocess.run(f"ls -la /etc/graylog/lookup/ > {SAUV}/lookup-ls.txt; systemctl list-timers --all > {SAUV}/timers.txt", shell=True)
    json.dump(mesure(), open(f"{SAUV}/perf-avant.json", "w"), indent=1)
    print(f"sauvegarde + mesure avant : {SAUV}")

def ensure_lookups():
    adp = {a["name"]: a for a in api("GET", "/system/lookup/adapters?per_page=500")["data_adapters"]}
    cac = {c["name"]: c for c in api("GET", "/system/lookup/caches?per_page=500")["caches"]}
    tab = {t["name"]: t for t in api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"]}
    for n, (f, desc) in TABLES.items():
        an, cn, tn = f"omni-v5-ti-{n}-adapter", f"omni-v5-ti-{n}-cache", f"omni-v5-ti-{n}"
        if an not in adp:
            a = api("POST", "/system/lookup/adapters", {"name": an, "title": f"OMNI v5 TI - {n} (CSV)", "description": f"{desc}. Fichier {LOOKUP}/{f}, timer omni-v5-ti-fetch.",
                    "config": {"type": "csvfile", "path": f"{LOOKUP}/{f}", "separator": ",", "quotechar": "\"", "key_column": "cle", "value_column": "valeur",
                               "check_interval": 120, "case_insensitive_lookup": True, "cidr_lookup": False}})
            CREES.append(("adapter", a["id"], an)); aid = a["id"]
        else: aid = adp[an]["id"]
        if cn not in cac:
            c = api("POST", "/system/lookup/caches", {"name": cn, "title": f"OMNI v5 TI - {n} (cache)", "description": "Cache positif et NEGATIF (presque toutes les cles sont absentes)",
                    "config": {"type": "guava_cache", "max_size": 20000, "expire_after_access": 600, "expire_after_access_unit": "SECONDS",
                               "expire_after_write": 1800, "expire_after_write_unit": "SECONDS", "ignore_null": False, "ttl_empty": 600, "ttl_empty_unit": "SECONDS"}})
            CREES.append(("cache", c["id"], cn)); cid = c["id"]
        else: cid = cac[cn]["id"]
        if tn not in tab:
            t = api("POST", "/system/lookup/tables", {"name": tn, "title": f"OMNI v5 TI - {n}", "description": desc, "cache_id": cid, "data_adapter_id": aid,
                    "default_single_value": "", "default_single_value_type": "NULL", "default_multi_value": "", "default_multi_value_type": "NULL"})
            CREES.append(("table", t["id"], tn))
    print(f"tables omni-v5-ti-* : {len(TABLES)} OK")

def ensure_routage():
    st = streams()
    for titre, inv in ROUTAGE:
        s = st[titre]
        exist = {(r["field"], r["value"], r["inverted"]) for r in s["rules"]}
        for ev in EVT_SOURCES:
            if ("event_source", ev, inv) in exist: continue
            r = api("POST", f"/streams/{s['id']}/rules", {"field": "event_source", "type": 1, "value": ev, "inverted": inv, "description": RDESC})
            CREES.append(("streamrule", f"{s['id']}/{r.get('streamrule_id')}", f"{titre} event_source {'!=' if inv else '='} {ev}"))
    print("routage ti_fetch/ti_retro -> Interne SIEM (exclus de M365) OK")

def appliquer():
    sauvegarde()
    ensure_lookups()
    exist = {r["title"]: r for r in api("GET", "/system/pipelines/rule")}
    maj = []
    for n, src in R.items():
        if n in exist:
            if exist[n]["source"].strip() != src.strip():
                api("PUT", f"/system/pipelines/rule/{exist[n]['id']}", {"title": n, "description": exist[n].get("description", ""), "source": src}); maj.append((exist[n]["id"], n))
            continue
        r = api("POST", "/system/pipelines/rule", {"title": n, "description": "OMNITECH SIEM v5 TI 27/11/2026", "source": src})
        CREES.append(("rule", r["id"], n)); maj.append((r["id"], n))
    pipes = {p["title"]: p for p in api("GET", "/system/pipelines/pipeline")}
    if PIPE_TITLE in pipes:
        pid = pipes[PIPE_TITLE]["id"]
        if pipes[PIPE_TITLE]["source"].strip() != PIPE_SRC.strip():
            api("PUT", f"/system/pipelines/pipeline/{pid}", {"title": PIPE_TITLE, "description": pipes[PIPE_TITLE].get("description", ""), "source": PIPE_SRC})
    else:
        p = api("POST", "/system/pipelines/pipeline", {"title": PIPE_TITLE, "description": "SIEM v5 chantier 3 (27/11/2026) : enrichissement TI ti_* (Feodo, ThreatFox, URLhaus, MalwareBazaar, Tor). Etape 19.", "source": PIPE_SRC})
        pid = p["id"]; CREES.append(("pipeline", pid, PIPE_TITLE))
    sid = {t: s["id"] for t, s in streams().items()}
    api("POST", "/system/pipelines/connections/to_pipeline", {"pipeline_id": pid, "stream_ids": [sid[s] for s in PIPE_STREAMS]})
    recharge(maj, [pid])
    print(f"{len(R)} regles + pipeline « {PIPE_TITLE} » (etape {STAGE}) connecte a {PIPE_STREAMS}")
    ensure_routage()
    edefs = {d["title"]: d for d in api("GET", "/events/definitions?per_page=500")["event_definitions"]}
    for d in DEFS:
        if d[0] in edefs: continue
        e = api("POST", "/events/definitions?schedule=" + ("true" if RODAGE_OK else "false"), {"entity": def_body(d, sid, "ENABLED" if RODAGE_OK else "DISABLED")})
        CREES.append(("definition", e["id"], d[0]))
    print(f"definitions creees : {sum(1 for c in CREES if c[0]=='definition')} ({'planifiees' if RODAGE_OK else 'NON planifiees (rodage absent)'})")
    with open(f"{BASE}/retour.sh", "w") as f:
        f.write("#!/bin/bash\n# Retour SIEM v5 chantier 3 (TI) : supprime PAR NOM tout objet omni-v5-ti-* / « OMNI v5 - TI » + timer + fichiers.\n"
                "# Usage : bash /root/omni-v5-ti/retour.sh [--simuler]   (la cle /etc/omni-v5-ti/threatfox.key, propriete de jmorin, est CONSERVEE)\n"
                "cd /root/omni-v5-ti || exit 1\npython3 -I v5_ti_build.py --retour \"$@\"\n"
                "if [ \"$1\" = \"--simuler\" ]; then\n  echo '[simulation] systemctl disable --now omni-v5-ti-fetch.timer ; rm unites, /usr/local/sbin/omni-v5-ti-fetch, /etc/default/omni-v5-ti-fetch, /etc/graylog/lookup/ti/, /var/lib/omni-v5-ti/, /var/log/omni-v5-ti/'\n"
                "  ls -la /etc/omni-v5-ti/ /etc/graylog/lookup/ti/ 2>/dev/null; exit 0\nfi\n"
                "systemctl disable --now omni-v5-ti-fetch.timer 2>/dev/null\n"
                "rm -f /etc/systemd/system/omni-v5-ti-fetch.timer /etc/systemd/system/omni-v5-ti-fetch.service /usr/local/sbin/omni-v5-ti-fetch /etc/default/omni-v5-ti-fetch\n"
                "systemctl daemon-reload\nrm -rf /etc/graylog/lookup/ti /var/lib/omni-v5-ti /var/log/omni-v5-ti\n"
                "find /etc/omni-v5-ti -mindepth 1 ! -name threatfox.key -delete 2>/dev/null\n"
                "echo 'retour v5-ti termine (cle threatfox.key conservee)'\n")
    os.chmod(f"{BASE}/retour.sh", 0o700)
    json.dump(CREES, open(f"{SAUV}/objets-crees.json", "w"), indent=1, ensure_ascii=False)
    print("OBJETS", json.dumps(CREES, ensure_ascii=False))
    print(f"retour : bash {BASE}/retour.sh")

def planifier():
    if not RODAGE_OK: sys.exit("refus : rodage non confirme (--rodage-ok apres controle de RODAGE-ACTIF.txt)")
    for d in api("GET", "/events/definitions?per_page=500")["event_definitions"]:
        if d["title"].startswith("OMNI v5 - TI "):
            api("PUT", f"/events/definitions/{d['id']}/schedule"); print("planifiee", d["id"], d["title"])

def retour(simuler):
    n = 0
    def rm(path, quoi):
        nonlocal n
        print(("[simulation] " if simuler else "") + "suppression " + quoi)
        if not simuler: api("DELETE", path)
        n += 1
    for d in api("GET", "/events/definitions?per_page=500")["event_definitions"]:
        if d["title"].startswith("OMNI v5 - TI "): rm(f"/events/definitions/{d['id']}", f"definition {d['id']} {d['title']}")
    for p in api("GET", "/system/pipelines/pipeline"):
        if p["title"] == PIPE_TITLE: rm(f"/system/pipelines/pipeline/{p['id']}", f"pipeline {p['id']} {p['title']}")
    for r in api("GET", "/system/pipelines/rule"):
        if r["title"].startswith("omni-v5-ti-"): rm(f"/system/pipelines/rule/{r['id']}", f"regle {r['id']} {r['title']}")
    for t in api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"]:
        if t["name"].startswith("omni-v5-ti-"): rm(f"/system/lookup/tables/{t['id']}", f"table {t['name']}")
    for c in api("GET", "/system/lookup/caches?per_page=500")["caches"]:
        if c["name"].startswith("omni-v5-ti-"): rm(f"/system/lookup/caches/{c['id']}", f"cache {c['name']}")
    for a in api("GET", "/system/lookup/adapters?per_page=500")["data_adapters"]:
        if a["name"].startswith("omni-v5-ti-"): rm(f"/system/lookup/adapters/{a['id']}", f"adaptateur {a['name']}")
    for t, s in streams().items():
        for r in s["rules"]:
            if r.get("description") == RDESC: rm(f"/streams/{s['id']}/rules/{r['id']}", f"regle de stream {t} {r['field']}={r['value']}")
    print(f"retour : {n} objets {'a supprimer (simulation)' if simuler else 'supprimes'}")

# ------------------------------------------------------------------ simulateur
def test():
    sid = {t: s["id"] for t, s in streams().items()}
    def first(path):
        with open(path, encoding="utf-8") as f:
            next(f)
            for l in f:
                k, v = l.rstrip("\n").split(",", 1)
                yield k, v
    def pick(fichier, pred):
        for k, v in first(f"{LOOKUP}/{fichier}"):
            if pred(v): return k
    feodo = pick("ip.csv", lambda v: v.startswith("feodo|"))
    feodo_port = next(v for k, v in first(f"{LOOKUP}/ip.csv") if k == feodo).split("|")[4].strip(";").split(";")[0] or "443"
    tor = pick("ip.csv", lambda v: v.startswith("tor|"))
    tfip = None
    for k, v in first(f"{LOOKUP}/ip.csv"):
        if v.startswith("threatfox|ip_port|") and "|haute|" in v: tfip = (k, v.split("|")[4].strip(";").split(";")[0]); break
    dom = pick("domaine.csv", lambda v: True); uh = pick("urlhaus-hote.csv", lambda v: True); h = pick("hachage.csv", lambda v: v.startswith("malwarebazaar|"))
    # champs FortiGate déjà normalisés (src_ip/dest_ip/dest_port) : l'étape 0 key=value ne s'applique pas à un message synthétique
    CAS = [  # (nom, stream, champs, attendu {champ: valeur} ou None = aucun ti_*)
        ("FG sortant Feodo autorise", "OMNI - FortiGate", {"event_source": "fortigate", "type": "traffic", "subtype": "forward", "src_ip": "10.33.10.50", "dest_ip": feodo, "dest_port": feodo_port, "action": "accept"}, {"ti_source": "feodo", "ti_direction": "sortant", "ti_port_match": True}),
        ("FG sortant ThreatFox port identique", "OMNI - FortiGate", {"event_source": "fortigate", "type": "traffic", "subtype": "forward", "src_ip": "10.33.10.50", "dest_ip": tfip[0], "dest_port": tfip[1], "action": "accept"}, {"ti_source": "threatfox", "ti_port_match": True}),
        ("FG sortant ThreatFox port different", "OMNI - FortiGate", {"event_source": "fortigate", "type": "traffic", "subtype": "forward", "src_ip": "10.33.10.50", "dest_ip": tfip[0], "dest_port": "1", "action": "accept"}, {"ti_source": "threatfox", "ti_port_match": False}),
        ("FG entrant Tor", "OMNI - FortiGate", {"event_source": "fortigate", "type": "traffic", "subtype": "forward", "src_ip": tor, "dest_ip": "10.33.50.102", "dest_port": "443", "action": "deny"}, {"ti_source": "tor", "ti_direction": "entrant"}),
        ("FG interne (negatif)", "OMNI - FortiGate", {"event_source": "fortigate", "type": "traffic", "subtype": "forward", "src_ip": "10.33.10.50", "dest_ip": "10.33.220.10", "dest_port": "5044", "action": "accept"}, None),
        ("FG public inconnu (negatif)", "OMNI - FortiGate", {"event_source": "fortigate", "type": "traffic", "subtype": "forward", "src_ip": "10.33.10.50", "dest_ip": "193.252.117.141", "dest_port": "443", "action": "accept"}, None),
        ("FG DNS domaine ThreatFox", "OMNI - FortiGate", {"event_source": "fortigate", "type": "utm", "subtype": "dns", "src_ip": "10.33.50.250", "dest_ip": "86.54.11.1", "qname": dom.upper(), "action": "pass"}, {"ti_source": "threatfox", "ti_contexte": "dns"}),
        ("FG web hote URLhaus", "OMNI - FortiGate", {"event_source": "fortigate", "type": "utm", "subtype": "ssl", "src_ip": "10.33.10.50", "dest_ip": "86.54.11.1", "hostname": uh, "action": "pass"}, {"ti_source": "urlhaus", "ti_contexte": "web"}),
        ("Sysmon 22 domaine ThreatFox", "OMNI - Sysmon", {"event_source": "sysmon", "winlogbeat_winlog_event_id": "22", "dns_query": dom}, {"ti_source": "threatfox", "ti_contexte": "dns"}),
        ("Sysmon 22 microsoft (negatif)", "OMNI - Sysmon", {"event_source": "sysmon", "winlogbeat_winlog_event_id": "22", "dns_query": "login.microsoftonline.com"}, None),
        ("Sysmon 1 hachage MalwareBazaar", "OMNI - Sysmon", {"event_source": "sysmon", "winlogbeat_winlog_event_id": "1", "winlogbeat_winlog_event_data_Hashes": f"SHA256={h.upper()},IMPHASH=68E4D30565D823574F8F067C0E3B4490"}, {"ti_source": "malwarebazaar", "ti_contexte": "execution"}),
        ("Sysmon 15 hachage (fichier)", "OMNI - Sysmon", {"event_source": "sysmon", "winlogbeat_winlog_event_id": "15", "winlogbeat_winlog_event_data_Hash": f"SHA256={h.upper()}"}, {"ti_contexte": "fichier"}),
        ("Sysmon 1 hachage sain (negatif)", "OMNI - Sysmon", {"event_source": "sysmon", "winlogbeat_winlog_event_id": "1", "winlogbeat_winlog_event_data_Hashes": "SHA256=B9845539AFFBB9C8346BF56FCC28F57FCC5A9E8F7DDC67B20FAD6EBCC663418E,IMPHASH=68E4D30565D823574F8F067C0E3B4490"}, None),
        ("ESET hachage", "OMNI - ESET", {"event_source": "eset", "eset_event_type": "Threat_Event", "eset_hash": h.upper()}, {"ti_contexte": "eset", "ti_source": "malwarebazaar"}),
        ("ESET site web URLhaus", "OMNI - ESET", {"event_source": "eset", "eset_event_type": "FilteredWebsites_Event", "eset_object_uri": f"https://{uh}/x/y.exe"}, {"ti_contexte": "eset_web", "ti_source": "urlhaus"}),
    ]
    ok = 0
    for i, (nom, st, champs, att) in enumerate(CAS):
        msg = {"_id": f"v5ti-test-{i}", "message": "bx-qa-seal-vm test omni-v5-ti", "source": "bx-qa-seal-vm-test", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), **champs}
        r = api("POST", "/system/pipelines/simulate", {"stream_id": sid[st], "message": msg, "input_id": None})
        out = (r.get("messages") or [{}])[0].get("message", {})
        ti = {k: v for k, v in out.items() if k.startswith("ti_")}
        if att is None: bon = not ti.get("ti_source")
        else: bon = all(out.get(k) == v for k, v in att.items())
        ok += bon
        print(f"{'OK ' if bon else 'KO '} {nom} -> {json.dumps({k: ti[k] for k in sorted(ti) if k in ('ti_source','ti_type','ti_direction','ti_port_match','ti_contexte','ti_confiance','ti_malware')}, ensure_ascii=False)}")
    print(f"SIMULATEUR {ok}/{len(CAS)}")

def simuler():
    for n, src in R.items():
        try: api("POST", "/system/pipelines/rule/parse", {"title": n, "description": "", "source": src})
        except RuntimeError as e: sys.exit(f"ERREUR SYNTAXE {n} : {e}")
    print(f"syntaxe OK : {len(R)} regles ; {len(DEFS)} definitions ; {len(TABLES)} tables")
    st = streams(); manq = [s for d in DEFS for s in d[3] if s not in st] + [s for s in PIPE_STREAMS + [t for t, _ in ROUTAGE] if s not in st]
    if manq: sys.exit(f"streams introuvables : {set(manq)}")
    print("streams OK ; SIMULATION : rien n'a ete cree")

if __name__ == "__main__":
    if MODE == "--simuler": simuler()
    elif MODE == "--appliquer": simuler(); appliquer()
    elif MODE == "--planifier": planifier()
    elif MODE == "--test": test()
    elif MODE == "--mesure": print(json.dumps(mesure(), ensure_ascii=False))
    elif MODE == "--retour": retour("--simuler" in ARGS)
    elif MODE == "--regles": print("\n\n".join(R.values()))
    else: sys.exit(__doc__)
