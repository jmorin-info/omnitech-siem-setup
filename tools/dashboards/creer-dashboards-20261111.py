#!/usr/bin/env python3
"""Création de 4 dashboards Graylog OMNITECH (11/11/2026) : Vue SOC direction, Identités et AD, Réseau FortiGate VPN, Santé du SIEM.
Chaque widget porte son propre filtre de stream (requêtes ciblées, pas de balayage global). Idempotent : un dashboard dont le
titre existe déjà n'est pas recréé (passer --remplacer pour le supprimer puis le recréer).
Usage (root) : set -a; . /root/omnitech-siem-setup/00-vars.env; set +a; python3 creer-dashboards-20261111.py [--simuler] [--remplacer]
Retour : retour-dashboards-20261111.py --supprimer-nouveaux"""
import sys, json, os, ssl, base64, secrets, uuid, urllib.request

SIMULER, REMPLACER = "--simuler" in sys.argv, "--remplacer" in sys.argv
CTX = ssl._create_unverified_context()
AUTH = base64.b64encode(("admin:" + os.environ["GRAYLOG_ADMIN_PASS"]).encode()).decode()
API = "https://127.0.0.1:9000/api"

def call(m, p, c=None):
    r = urllib.request.Request(API + p, data=json.dumps(c).encode() if c is not None else None, method=m, headers={
        "Authorization": "Basic " + AUTH, "Accept": "application/json", "Content-Type": "application/json", "X-Requested-By": "oms-dashboards"})
    try:
        with urllib.request.urlopen(r, context=CTX) as rep:
            t = rep.read(); return json.loads(t) if t else None
    except urllib.error.HTTPError as e:
        raise SystemExit(f"ERREUR {m} {p} : {e.code} {e.read().decode(errors='replace')[:800]}")

STREAMS = {s["title"]: s["id"] for s in call("GET", "/streams")["streams"]}
def sid(*titres):
    return [STREAMS[t] for t in titres]

def tr(sec):
    return {"type": "relative", "range": sec} if sec else None

class Onglet:
    def __init__(self, titre):
        self.titre, self.widgets, self.types, self.mapping, self.positions, self.titres = titre, [], [], {}, {}, {}
        self.col, self.row, self.hligne = 1, 1, 0

    def _place(self, wid, larg, haut):
        if self.col + larg - 1 > 12:
            self.col, self.row, self.hligne = 1, self.row + self.hligne, 0
        self.positions[wid] = {"col": self.col, "row": self.row, "height": haut, "width": larg}
        self.col += larg; self.hligne = max(self.hligne, haut)

    def nouvelle_ligne(self):
        if self.col > 1:
            self.col, self.row, self.hligne = 1, self.row + self.hligne, 0

    def _ajout(self, titre, desc, q, streams, temps, config, st_extra, larg, haut, wtype="AGGREGATION", st_type="pivot"):
        wid, stid = str(uuid.uuid4()), str(uuid.uuid4())
        query = {"type": "elasticsearch", "query_string": q}
        self.widgets.append({"id": wid, "type": wtype, "filter": None, "filters": [], "timerange": tr(temps), "query": query,
                             "streams": streams, "stream_categories": [], "config": config, "description": desc, "context": None})
        st = {"id": stid, "type": st_type, "timerange": tr(temps), "query": query, "streams": streams, "stream_categories": [],
              "filter": None, "filters": []}
        st.update(st_extra); self.types.append(st)
        self.mapping[wid] = [stid]; self.titres[wid] = titre; self._place(wid, larg, haut)

    @staticmethod
    def _series(series):
        cfg, st = [], []
        for f in series:
            nom = f.split("(")[0]; champ = f[f.index("(") + 1:-1] or None
            cfg.append({"config": {}, "function": f}); st.append({"type": nom, "id": f, "field": champ})
        return cfg, st

    def nombre(self, titre, q, streams, temps=None, serie="count()", desc=None, tendance="LOWER", larg=3, haut=2):
        cs, ss = self._series([serie])
        self._ajout(titre, desc, q, streams, temps,
                    {"visualization": "numeric", "event_annotation": False, "row_pivots": [], "column_pivots": [], "series": cs,
                     "sort": [], "rollup": True, "visualization_config": {"trend": True, "trend_preference": tendance}},
                    {"name": "chart", "series": ss, "sort": [], "rollup": True, "row_groups": [], "column_groups": []}, larg, haut)

    def agreg(self, titre, q, streams, champs, temps=None, series=("count()",), vis="table", limite=10, col=None, desc=None, larg=6, haut=4, tri=None):
        cs, ss = self._series(list(series))
        rp = [{"type": "values", "fields": champs, "config": {"limit": limite, "skip_empty_values": True}}]
        rg = [{"type": "values", "fields": champs, "limit": limite, "skip_empty_values": True}]
        cp, cg = [], []
        if col:
            cp = [{"type": "values", "fields": [col], "config": {"limit": 6, "skip_empty_values": True}}]
            cg = [{"type": "values", "fields": [col], "limit": 6, "skip_empty_values": True}]
        sort = [{"type": "series", "field": tri or series[0], "direction": "Descending"}]
        self._ajout(titre, desc, q, streams, temps,
                    {"visualization": vis, "event_annotation": False, "row_pivots": rp, "column_pivots": cp, "series": cs, "sort": sort, "rollup": True},
                    {"name": "chart", "series": ss, "sort": sort, "rollup": True, "row_groups": rg, "column_groups": cg}, larg, haut)

    def courbe(self, titre, q, streams, temps=None, col=None, vis="line", desc=None, larg=12, haut=3):
        cs, ss = self._series(["count()"])
        rp = [{"type": "time", "fields": ["timestamp"], "config": {"interval": {"type": "auto", "scaling": 1}}}]
        rg = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}]
        cp, cg = [], []
        if col:
            cp = [{"type": "values", "fields": [col], "config": {"limit": 6, "skip_empty_values": True}}]
            cg = [{"type": "values", "fields": [col], "limit": 6, "skip_empty_values": True}]
        self._ajout(titre, desc, q, streams, temps,
                    {"visualization": vis, "event_annotation": False, "row_pivots": rp, "column_pivots": cp, "series": cs, "sort": [], "rollup": True},
                    {"name": "chart", "series": ss, "sort": [], "rollup": True, "row_groups": rg, "column_groups": cg}, larg, haut)

    def messages(self, titre, q, streams, champs, temps=None, desc=None, larg=12, haut=5, limite=50):
        self._ajout(titre, desc, q, streams, temps,
                    {"fields": champs, "show_message_row": False, "sort": [{"type": "pivot", "field": "timestamp", "direction": "Descending"}], "decorators": []},
                    {"name": "messages", "limit": limite, "offset": 0, "sort": [{"field": "timestamp", "order": "DESC"}], "fields": [], "decorators": []},
                    larg, haut, wtype="MESSAGES", st_type="messages")

def dashboard(titre, resume, description, temps, onglets):
    queries, state = [], {}
    for o in onglets:
        qid = str(uuid.uuid4())
        queries.append({"id": qid, "timerange": tr(temps), "filter": None, "filters": [], "query": {"type": "elasticsearch", "query_string": ""}, "search_types": o.types})
        state[qid] = {"selected_fields": None, "static_message_list_id": None, "titles": {"tab": {"title": o.titre}, "widget": o.titres},
                      "widgets": o.widgets, "widget_mapping": o.mapping, "positions": o.positions, "formatting": {"highlighting": []},
                      "display_mode_settings": {"positions": {}}}
    return titre, {"id": secrets.token_hex(12), "queries": queries, "parameters": []}, {
        "type": "DASHBOARD", "title": titre, "summary": resume, "description": description, "properties": [], "requires": {}, "state": state}

J7, J1, J30 = 604800, 86400, 2592000
EV, INT, WS, WO, FG, ESET = sid("All events"), sid("OMNI - Interne SIEM"), sid("OMNI - Windows Security"), sid("OMNI - Windows autres"), sid("OMNI - FortiGate"), sid("OMNI - ESET")
ADMIN = "user:adm\\-*"
GROUPES = "event_action:(membre_ajoute_groupe_global OR membre_ajoute_groupe_local OR membre_retire_groupe_global OR membre_retire_groupe_local OR groupe_global_cree OR groupe_local_cree OR groupe_local_securite_supprime OR groupe_global_securite_supprime)"
DASHBOARDS = []

# 1. Vue SOC direction (7 jours)
o = Onglet("Semaine")
o.nombre("Alertes déclenchées (7 j)", "*", EV, desc="Toutes les définitions d'événements déclenchées.")
o.nombre("Alertes haute priorité (7 j)", "priority:3", EV, desc="Événements de priorité 3 (haute).")
o.nombre("Incidents corrélés (7 j)", "event_source:xdr_incident", INT, desc="Incidents XDR (corrélation kill-chain).")
o.nombre("IP bloquées par le SOAR (7 j)", "event_source:siem_soar AND event_action:ip_bloquee", INT, desc="Blocages appliqués sur les FortiGate BX et IV.")
o.nombre("Connexions comptes admin (7 j)", f"event_action:connexion_reussie AND {ADMIN}", WS, tendance="NEUTRAL")
o.nombre("Changements de groupes AD (7 j)", GROUPES, WS, desc="Ajouts/retraits de membres, créations/suppressions de groupes.")
o.nombre("Détections ESET (7 j)", "*", ESET)
o.nombre("Sources silencieuses (24 h)", "event_source:collecte_sla", INT, temps=J1, desc="Machines ou sources qui n'envoient plus de journaux (go-dark).")
o.nouvelle_ligne()
o.courbe("Alertes par jour et par priorité", "*", EV, col="priority", vis="bar", larg=8)
o.agreg("Incidents par gravité", "event_source:xdr_incident", INT, ["severity"], vis="pie", larg=4, haut=3)
o.agreg("Alertes les plus fréquentes (définition)", "*", EV, ["event_definition_id"], limite=12, larg=6, haut=5,
        desc="Identifiant de la définition d'événement (le titre, champ texte, n'est pas agrégeable) : voir la liste ci-dessous pour les titres.")
o.agreg("Blocages SOAR par pays et motif", "event_source:siem_soar AND event_action:ip_bloquee", INT, ["soar_pays", "soar_motif"], limite=12, larg=6, haut=5)
o.agreg("Comptes admin : connexions par compte", f"event_action:connexion_reussie AND {ADMIN}", WS, ["user"], limite=12, larg=4)
o.agreg("Sources silencieuses (heures de silence)", "event_source:collecte_sla", INT, ["dark_host", "sla_type"], temps=J1, series=("max(hours_silent)", "count()"), limite=15, larg=4)
o.agreg("ESET : détections par poste", "*", ESET, ["eset_hostname", "eset_event_type"], limite=12, larg=4)
o.messages("Dernières alertes haute priorité", "priority:3", EV, ["timestamp", "priority", "message", "key"], haut=4)
o.messages("Sauvegardes Veeam : événements des jobs", 'winlogbeat_event_provider:"Veeam Backup"', WO, ["timestamp", "source", "event_id", "message"], haut=4)
DASHBOARDS.append(dashboard("OMNI - Vue SOC direction", "KPI de la semaine pour la direction",
    "Indicateurs hebdomadaires : alertes par priorité, incidents, SOAR, comptes à privilèges, sources silencieuses, ESET, Veeam. Créé le 11/11/2026.", J7, [o]))

# 2. Identités et AD (24 h)
o = Onglet("Identités")
o.nombre("Connexions admin réussies", f"event_action:connexion_reussie AND {ADMIN}", WS, tendance="NEUTRAL")
o.nombre("Échecs de connexion", "event_action:echec_connexion", WS)
o.nombre("Comptes verrouillés", "event_id:4740", WS)
o.nombre("Changements de groupes", GROUPES, WS)
o.courbe("Échecs de connexion dans le temps (par machine)", "event_action:echec_connexion", WS, col="host")
o.agreg("Comptes en échec de connexion", "event_action:echec_connexion", WS, ["user", "src_ip"], limite=15)
o.agreg("Comptes verrouillés (7 j)", "event_id:4740 OR event_id:4767", WS, ["user", "event_id"], temps=J7, limite=15)
o.courbe("Connexions des comptes admin (par compte)", f"event_action:connexion_reussie AND {ADMIN}", WS, col="user", larg=8)
o.agreg("Authentification : Kerberos / NTLM", "event_id:4624", WS, ["winlogbeat_winlog_event_data_AuthenticationPackageName"], vis="pie", larg=4, haut=3)
o.agreg("NTLM : machines sources (à réduire)", "event_id:4624 AND winlogbeat_winlog_event_data_AuthenticationPackageName:NTLM", WS,
        ["winlogbeat_winlog_event_data_WorkstationName", "host"], limite=15, desc="Postes/serveurs qui s'authentifient encore en NTLM.")
o.agreg("Kerberos : tickets de service par compte", "event_action:demande_ticket_service_kerberos", WS, ["user"], limite=15)
o.messages("Changements de groupes (7 j)", GROUPES, WS, ["timestamp", "event_action", "user", "host", "message"], temps=J7)
DASHBOARDS.append(dashboard("OMNI - Identités et AD", "Comptes, groupes, authentifications AD",
    "Authentifications admin, échecs, verrouillages, changements de groupes, Kerberos/NTLM. Créé le 11/11/2026.", J1, [o]))

# 3. Réseau FortiGate VPN (24 h)
o = Onglet("Réseau et VPN")
o.nombre("Tunnels VPN IPsec montés", "subtype:vpn AND action:tunnel-up", FG, tendance="NEUTRAL")
o.nombre("Erreurs VPN", "subtype:vpn AND action:error", FG)
o.nombre("Flux refusés", "action:deny", FG)
o.nombre("IP bloquées par le SOAR", "event_source:siem_soar AND event_action:ip_bloquee", INT)
o.agreg("Utilisateurs VPN IPsec (EMS)", "subtype:vpn AND action:tunnel-up", FG, ["xauthuser", "vpntunnel"], limite=20, larg=6, haut=5)
o.agreg("Refus par site", "action:deny", FG, ["fortigate_site"], vis="bar", larg=6, haut=5)
o.courbe("Refus dans le temps par site", "action:deny", FG, col="fortigate_site")
o.agreg("Refus : pays d'origine (hors réseaux internes)", "action:deny AND NOT src_priv:true", FG, ["src_country"], limite=15, larg=4)
o.agreg("Refus : IP sources les plus actives", "action:deny AND NOT src_priv:true", FG, ["src_ip", "src_country"], limite=15, larg=4)
o.agreg("SOAR : IP bloquées", "event_source:siem_soar AND event_action:ip_bloquee", INT, ["soar_ip", "soar_pays", "soar_motif"], temps=J7, limite=20, larg=4)
o.agreg("Segmentation : refus entre zones internes", "action:deny AND src_priv:true AND dst_priv:true", FG, ["srcintf", "dstintf"], limite=20, larg=6, haut=5,
        desc="Flux internes refusés par le pare-feu (segmentation VLAN).")
o.agreg("VPN : erreurs et négociations par tunnel", "subtype:vpn AND action:(error OR tunnel-down)", FG, ["vpntunnel", "action"], limite=15, larg=6, haut=5)
DASHBOARDS.append(dashboard("OMNI - Réseau FortiGate VPN", "FortiGate BX/IV/LC, VPN IPsec EMS, SOAR, segmentation",
    "VPN IPsec (EMS), refus par site et pays, SOAR, segmentation interne. Créé le 11/11/2026.", J1, [o]))

# 4. Santé du SIEM (24 h)
o = Onglet("Santé")
o.nombre("Contrôles de santé en échec", "event_source:siem_health AND health_fail:>0", INT)
o.nombre("Sources silencieuses", "event_source:collecte_sla", INT)
o.nombre("Alertes internes du SIEM", "event_source:(siem_drift OR siem_integrity OR siem_backup OR siem_cert OR siem_vuln)", INT)
o.nombre("Événements système Graylog", "*", sid("All system events"))
o.courbe("Débit de collecte par input (messages)", "*", [], col="gl2_source_input", desc="Volume reçu toutes sources, réparti par input Graylog.")
o.agreg("Volume par machine émettrice (1 h)", "*", [], ["source"], temps=3600, limite=20, larg=6, haut=5)
o.agreg("Contrôles de santé (dernier état)", "event_source:siem_health", INT, ["health_job", "health_type"], series=("max(health_fail)", "max(health_age_s)", "count()"), limite=20, larg=6, haut=5, tri="max(health_fail)")
o.agreg("Sources silencieuses (heures)", "event_source:collecte_sla", INT, ["dark_host", "sla_type"], series=("max(hours_silent)",), limite=20, larg=6, haut=5)
o.messages("Alertes internes du SIEM", "event_source:(siem_drift OR siem_integrity OR siem_backup OR siem_cert OR siem_vuln OR siem_health)", INT,
           ["timestamp", "event_source", "health_job", "message"], larg=6)
o.messages("Événements système Graylog (erreurs d'indexation, notifications)", "*", sid("All system events"), ["timestamp", "source", "message"], temps=J7, haut=4)
DASHBOARDS.append(dashboard("OMNI - Santé du SIEM", "Collecte, contrôles de santé, alertes internes",
    "Débit par input et par machine, contrôles omni-self-health, sources silencieuses, alertes internes. Créé le 11/11/2026.", J1, [o]))

existants = {v["title"]: v["id"] for v in call("GET", "/views?per_page=200")["views"]}
for titre, recherche, vue in DASHBOARDS:
    nw = sum(len(s["widgets"]) for s in vue["state"].values())
    if titre in existants and not REMPLACER:
        print(f"existe déjà, ignoré : {titre} ({existants[titre]})"); continue
    if SIMULER:
        print(f"SIMULATION : {titre} : {nw} widgets"); continue
    if titre in existants:
        call("DELETE", "/views/" + existants[titre])
    r = call("POST", "/views/search", recherche)
    vue["search_id"] = r["id"]
    v = call("POST", "/views", {"entity": vue})
    print(f"créé : {titre} : {nw} widgets : https://bx-it-graylog-vm.omnitech.security/dashboards/{v['id']}")
