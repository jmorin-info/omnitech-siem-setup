#!/usr/bin/env bash
# ==============================================================================
# 14-graylog-dashboards.sh (v4) - Dashboard SOC multi-pages "OMNI - SOC" (19 pages)
#   Architecture en 3 niveaux (cohérence de lecture, sans redondance) :
#     1. PILOTAGE   : Direction (posture executive, tendances J/J-1, score de risque)
#     2. TRIAGE     : Alertes (file de detections), Sante collecte (etat des sources)
#     3. PROFONDEUR : Identite AD, M365, M365 Activite, Endpoint, Reseau, vSphere,
#                     Hunting, Comptes & conformite, Cartographie, Comptes a privileges,
#                     VPN & Exposition, Sauvegardes, Certificats, Vulnerabilites, ATT&CK
#     + Investigation (page libre pilotee par la barre de recherche).
#   Chaque KPI porte une infobulle ⓘ (sens du chiffre + ce qu'un pic implique).
#   La page "Synthese" (redondante avec Direction) a ete retiree en v4.
#
#   Capacites "expert" du generateur (DSL python, stdlib, 1 search + 1 view) :
#     - KPIs avec TENDANCE vs periode precedente (dir=LOWER/HIGHER pour la couleur)
#     - tables MULTI-METRIQUES (metrics=[...]) : count + card(champ) + sum(champ)...
#     - pivots secondaires (pivot2), graphes AIRE (area), annotations d'evenements
#       (events=True) sur les chronologies.
#   Remplace les anciens dashboards mono-page (supprimes par titre).
# Idempotent : supprime/recree "OMNI - SOC" a chaque execution (les anciens
# IDs changent -> refaire les favoris navigateur le cas echeant).
# Prerequis : 10 + 12 (+16 pour la page M365 complete).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }
export GRAYLOG_ADMIN_PASS SIEM_FQDN

python3 - <<'PY'
import json, os, ssl, uuid, base64, urllib.request

API = f"https://{os.environ['SIEM_FQDN']}:9000/api"
CTX = ssl.create_default_context(cafile="/etc/graylog/certs/omnitech-rootca.crt")
AUTH = base64.b64encode(f"admin:{os.environ['GRAYLOG_ADMIN_PASS']}".encode()).decode()

def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Basic {AUTH}", "Content-Type": "application/json",
                 "X-Requested-By": "14-dashboards"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            d = r.read()
            return json.loads(d) if d else {}
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_body": e.read().decode()[:400]}

def post_entity(path, body):
    r = api("POST", path, body)
    if isinstance(r, dict) and "entity cannot be null" in str(r.get("_body", "")):
        r = api("POST", path, {"entity": body, "share_request": {"selected_grantee_capabilities": {}}})
    return r

streams = {s["title"]: s["id"] for s in api("GET", "/streams")["streams"]}
S = lambda *titles: [streams[t] for t in titles if t in streams]
WINSEC, SYSMON, WINOTH, FORTI, M365 = ("OMNI - Windows Security", "OMNI - Sysmon",
    "OMNI - Windows autres", "OMNI - FortiGate", "OMNI - M365")
VS = "OMNI - vSphere"
ESET, BW = "OMNI - ESET", "OMNI - BunkerWeb"   # sources externes (antivirus / WAF)
ARUBA, LINUX, EMS = "OMNI - Aruba", "OMNI - Linux", "OMNI - FortiClient EMS"   # sources on-prem ajoutees

# ---------------------------------------------------------------- suppression
OLD = ["OMNI - SOC", "OMNI - Windows Securite", "OMNI - Endpoint", "OMNI - FortiGate",
       "OMNI - Detections", "OMNI - Authentification AD", "OMNI - Microsoft 365"]
views = api("GET", "/views?page=1&per_page=100&query=")
for v in (views.get("views") or views.get("elements") or []):
    if v["title"] in OLD:
        api("DELETE", f"/views/{v['id']}")
        print(f"    [-] ancien dashboard supprime : {v['title']}")

# ------------------------------------------------------------------- helpers
def _series(w):
    """(series_search_type, series_widget) selon metrics=[...] | card=field | count.
    metrics : liste de 'count' ou (fn, champ[, libelle]) ; fn in card/avg/max/min/sum."""
    specs = w.get("metrics")
    if specs:
        st, wd = [], []
        for sp in specs:
            if sp in ("count", "count()"):
                st.append({"id": "count()", "type": "count"})
                wd.append({"config": {"name": None}, "function": "count()"})
            else:
                fn, field = sp[0], sp[1]
                label = sp[2] if len(sp) > 2 else None
                fid = f"{fn}({field})"
                st.append({"id": fid, "type": fn, "field": field})
                wd.append({"config": {"name": label}, "function": fid})
        return st, wd
    if w.get("card"):
        fid = f"card({w['card']})"
        return ([{"id": fid, "type": "card", "field": w["card"]}],
                [{"config": {"name": w.get("name")}, "function": fid}])
    return ([{"id": "count()", "type": "count"}],
            [{"config": {"name": w.get("name")}, "function": "count()"}])

def _tr(w):
    """Plage temporelle PROPRE au widget (override). w['range'] = secondes.
    Absente -> None -> le widget herite de la plage de la page (24h)."""
    return {"type": "relative", "range": w["range"]} if w.get("range") else None

def st_pivot(w):
    st_series, _ = _series(w)
    rg, cg = [], []
    if w.get("time"):
        rg = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}]
    elif w.get("pivot"):
        rg = [{"type": "values", "fields": [w["pivot"]], "limit": w.get("limit", 10)}]
        if w.get("pivot2"):
            rg.append({"type": "values", "fields": [w["pivot2"]], "limit": w.get("limit2", 5)})
    if w.get("coltime"):
        cg = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}]
    elif w.get("columns"):
        cg = [{"type": "values", "fields": [w["columns"]], "limit": w.get("col_limit", 5)}]
    if w.get("pivot") and not w.get("time"):
        sf = w.get("sort_on", st_series[0]["id"])
        sort = [{"type": "series", "field": sf,
                 "direction": "Ascending" if w.get("sort_asc") else "Descending"}]
    else:
        sort = []
    return {"id": w["stid"], "name": "chart", "type": "pivot",
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
            "timerange": _tr(w),
            "streams": [], "filters": [], "row_groups": rg, "column_groups": cg,
            "series": st_series, "sort": sort, "rollup": True}

def st_messages(w):
    return {"id": w["stid"], "name": "messages", "type": "messages",
            "limit": w.get("limit", 20), "offset": 0,
            "sort": [{"field": "timestamp", "order": "DESC"}],
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
            "timerange": _tr(w),
            "streams": [], "filters": []}

def widget(w):
    if w["viz"] == "messages":
        return {"id": w["wid"], "type": "MESSAGES", "filter": None, "timerange": _tr(w),
                "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
                "streams": [], "filters": [], "description": w.get("desc"),
                "config": {"fields": w.get("fields", ["timestamp", "source", "message"]),
                           "show_message_row": w.get("show_message", False),
                           "sort": [{"type": "pivot", "field": "timestamp", "direction": "Descending"}],
                           "decorators": []}}
    _, wd_series = _series(w)
    rp, cp = [], []
    if w.get("time"):
        rp = [{"type": "time", "fields": ["timestamp"], "config": {"interval": {"type": "auto", "scaling": 1}}}]
    elif w.get("pivot"):
        rp = [{"type": "values", "fields": [w["pivot"]],
               "config": {"limit": w.get("limit", 10), "skip_empty_values": False}}]
        if w.get("pivot2"):
            rp.append({"type": "values", "fields": [w["pivot2"]],
                       "config": {"limit": w.get("limit2", 5), "skip_empty_values": False}})
    if w.get("coltime"):
        cp = [{"type": "time", "fields": ["timestamp"], "config": {"interval": {"type": "auto", "scaling": 1}}}]
    elif w.get("columns"):
        cp = [{"type": "values", "fields": [w["columns"]], "config": {"limit": w.get("col_limit", 5), "skip_empty_values": False}}]
    if w.get("pivot") and not w.get("time"):
        sf = w.get("sort_on", wd_series[0]["function"])
        sort = [{"type": "series", "field": sf,
                 "direction": "Ascending" if w.get("sort_asc") else "Descending"}]
    else:
        sort = []
    # visualisation_config selon le type de viz
    vc = None
    if w["viz"] == "bar":
        vc = {"barmode": w.get("barmode", "stack"), "axis_type": "linear"}
    elif w["viz"] == "area":
        vc = {"interpolation": "linear"}
    elif w["viz"] == "heatmap":
        vc = {"color_scale": "Viridis", "reverse_scale": False, "auto_scale": True,
              "z_min": None, "z_max": None, "use_smallest_as_default": False, "default_value": None}
    elif w["viz"] == "numeric":
        # tendance vs periode precedente sur TOUS les KPIs (dir : LOWER/HIGHER/NEUTRAL)
        vc = {"trend": True, "trend_preference": w.get("dir", "NEUTRAL")}
    return {"id": w["wid"], "type": "AGGREGATION", "filter": None, "timerange": _tr(w),
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
            "streams": [], "filters": [], "description": w.get("desc"),
            "config": {"visualization": w["viz"], "event_annotation": bool(w.get("events")),
                       "row_pivots": rp, "column_pivots": cp,
                       "series": wd_series,
                       "sort": sort, "rollup": True, "formatting_settings": None,
                       "visualization_config": vc}}

def build(title, pages):
    queries, state = [], {}
    for p in pages:
        qid = str(uuid.uuid4())
        for w in p["widgets"]:
            w["wid"], w["stid"] = str(uuid.uuid4()), str(uuid.uuid4())
        queries.append({"id": qid, "query": {"type": "elasticsearch", "query_string": p.get("query_string", "")},
            "timerange": {"type": "relative", "range": p.get("page_range", 86400)},
            "filter": {"type": "or", "filters": [{"type": "stream", "id": s} for s in p["streams"]]},
            "filters": [],
            "search_types": [st_messages(w) if w["viz"] == "messages" else st_pivot(w) for w in p["widgets"]]})
        state[qid] = {"selected_fields": None, "static_message_list_id": None,
            "titles": {"tab": {"title": p["title"]}, "widget": {w["wid"]: w["title"] for w in p["widgets"]}},
            "widgets": [widget(w) for w in p["widgets"]],
            "widget_mapping": {w["wid"]: [w["stid"]] for w in p["widgets"]},
            "positions": {w["wid"]: {"col": w["pos"][0], "row": w["pos"][1],
                                     "width": w["pos"][2], "height": w["pos"][3]} for w in p["widgets"]},
            "formatting": {"highlighting": p.get("highlight", COMMON_HL)}, "display_mode_settings": {"positions": {}}}
    search = post_entity("/views/search", {"queries": queries, "parameters": PARAMS})
    sid = search.get("id")
    if not sid:
        print("    [!] search REFUSE:", str(search)[:300]); return
    view = post_entity("/views", {"type": "DASHBOARD", "title": title, "summary": "",
        "description": "Provisionne par 14-graylog-dashboards.sh", "search_id": sid,
        "properties": [], "state": state})
    vid = view.get("id")
    print(f"    [+] dashboard '{title}' ({vid}) - {len(pages)} pages" if vid
          else f"    [!] view REFUSEE: {str(view)[:300]}")

# =========================================================== definition SOC
EVENTS = "000000000000000000000002"   # stream systeme "All events" (alertes declenchees)
INT = "OMNI - Interne SIEM"           # auto-surveillance (backup config, disque)
def KPI(t, q, col, row=1, **kw): return dict(title=t, q=q, viz="numeric", pos=(col, row, 3, 2), **kw)
def W(t, q, viz, col, row, w=4, h=4, **kw): return dict(title=t, q=q, viz=viz, pos=(col, row, w, h), **kw)
# Fenetres elargies pour les DETECTEURS D'EVENEMENTS RARES (sinon vides en 24h) :
# range=D7 (7 j) / D30 (30 j). A poser widget par widget (override de la page).
D7, D30 = 604800, 2592000

# --- Code-couleur conditionnel (highlighting) ------------------------------
# Colore les cellules/lignes des TABLEAUX et LISTES de messages quand un champ
# matche. Applique globalement (une regle n'a d'effet que sur les pages ou le
# champ est present). Precedence : la DERNIERE regle qui matche gagne -> on met
# l'ORANGE avant le ROUGE pour que le rouge l'emporte sur les seuils critiques.
RED, ORANGE, YELLOW = "#d64550", "#e09f3e", "#e6c200"
def _hl(field, cond, value, color):
    return {"field": field, "value": value, "condition": cond,
            "color": {"type": "static", "color": color}}
COMMON_HL = [
  # Expiration certificats : <=30j orange, <=15j rouge (rouge en dernier = gagne)
  _hl("cert_days", "less_equal", 30, ORANGE), _hl("cert_days", "less_equal", 15, RED),
  # Detections a surveiller (orange)
  _hl("alert_tag", "equal", "powershell_suspect", ORANGE),
  _hl("alert_tag", "equal", "vsphere_auth_fail", ORANGE),
  _hl("alert_tag", "equal", "fortigate_utm", ORANGE),
  _hl("alert_tag", "equal", "m365_etranger", ORANGE),
  _hl("alert_tag", "equal", "m365_partage_externe", ORANGE),
  _hl("alert_tag", "equal", "m365_mailbox_deleg", ORANGE),
  _hl("alert_tag", "equal", "m365_risque", ORANGE),
  _hl("alert_tag", "equal", "admin_share", ORANGE),
  _hl("alert_tag", "equal", "veeam_job_echec", ORANGE),
  # Detections critiques (rouge)
  _hl("alert_tag", "equal", "dcsync", RED),
  _hl("alert_tag", "equal", "kerberoasting", RED),
  _hl("alert_tag", "equal", "lsass_access", RED),
  _hl("alert_tag", "equal", "sysmon_injection", RED),
  _hl("alert_tag", "equal", "threat_intel", RED),
  _hl("alert_tag", "equal", "winsec_critique", RED),
  _hl("alert_tag", "equal", "vsphere_vm_destroy", RED),
  _hl("alert_tag", "equal", "vsphere_shell_ssh", RED),
  _hl("alert_tag", "equal", "m365_mail_forward", RED),
  _hl("alert_tag", "equal", "m365_role", RED),
  _hl("alert_tag", "equal", "canary", RED),
  _hl("alert_tag", "equal", "defender", RED),
  _hl("alert_tag", "equal", "ransomware_indicator", RED),
  _hl("alert_tag", "equal", "vuln_kev", RED),
  _hl("alert_tag", "equal", "vuln_patch", ORANGE),
  # Correlations cross-source + threat-intel + DNS sensible (rouge)
  _hl("alert_tag", "equal", "m365_authority_drift", RED),
  _hl("alert_tag", "equal", "admin_login_off_segment", RED),
  _hl("alert_tag", "equal", "ip_spray_multisource", RED),
  _hl("alert_tag", "equal", "c2_ioc", RED),
  _hl("alert_tag", "equal", "malware_domain", RED),
  _hl("alert_tag", "equal", "dns_sensitive_change", RED),
  # Nouvelles sources on-prem (orange a surveiller)
  _hl("alert_tag", "equal", "ems_admin_login", ORANGE),
  _hl("alert_tag", "equal", "aruba_admin_login", ORANGE),
  _hl("alert_tag", "equal", "aruba_config_change", ORANGE),
  _hl("alert_tag", "equal", "aruba_auth_fail", ORANGE),
  _hl("alert_tag", "equal", "linux_sudo_root", ORANGE),
  _hl("alert_tag", "equal", "linux_ssh_fail", ORANGE),
  _hl("alert_tag", "equal", "linux_sensitive_tamper", RED),
  _hl("vuln_ransomware", "equal", "oui", RED),
  _hl("risk_severity", "equal", "critique", RED),
  _hl("risk_severity", "equal", "eleve", ORANGE),
  # Pare-feu / VPN / auth
  _hl("action", "equal", "deny", ORANGE),
  _hl("action", "equal", "blocked", ORANGE),
  _hl("status", "equal", "failure", RED),
  _hl("event_action", "equal", "echec_connexion", ORANGE),
  # Sauvegardes / sante systeme
  _hl("winlogbeat_log_level", "equal", "Warning", ORANGE),
  _hl("winlogbeat_log_level", "equal", "Error", RED),
  _hl("event_action", "equal", "backup_config_echec", RED),
  _hl("event_action", "equal", "disk_warn", ORANGE),
  _hl("event_action", "equal", "disk_guard_prune", RED),
  # Supervision collecte : hote go-dark (collecte interrompue)
  _hl("alert_tag", "equal", "host_go_dark", ORANGE),
  _hl("alert_tag", "equal", "siem_job_fail", RED),
  # UEBA / NDR : detections comportementales
  _hl("alert_tag", "equal", "impossible_travel", RED),
  _hl("alert_tag", "equal", "beaconing", RED),
  _hl("alert_tag", "equal", "dns_tunneling", RED),
  _hl("alert_tag", "equal", "gpo_modification", RED),
  _hl("alert_tag", "equal", "asrep_roasting", RED),
  _hl("alert_tag", "equal", "lolbin_suspect", ORANGE),
  _hl("alert_tag", "equal", "persistence_autorun", ORANGE),
  _hl("alert_tag", "equal", "m365_oauth_consent", ORANGE),
  _hl("alert_tag", "equal", "network_scan", ORANGE),
  # Enrichissements lots 1+2 (curated : seulement les signaux FORTS, pas de couleur
  # plate sur service/port_class/admin/NTLM-tout qui inonderaient les tableaux)
  _hl("alert_tag", "equal", "masquerading", RED),
  _hl("alert_tag", "equal", "explicit_cred_use", ORANGE),
  _hl("alert_tag", "equal", "exposition_internet", RED),
  _hl("off_hours", "equal", "oui", ORANGE),
  _hl("expo_internet", "equal", "oui", RED),
  _hl("winlogbeat_winlog_event_data_LmPackageName", "equal", "NTLM V1", RED),
  _hl("m365_fail_label", "equal", "Compte verrouille (trop d'echecs)", RED),
  _hl("m365_fail_label", "equal", "Bloque par Conditional Access", RED),
  _hl("m365_fail_label", "equal", "Identifiants invalides", ORANGE),
  _hl("m365_fail_label", "equal", "MFA requise (Conditional Access)", ORANGE),
  # Lot 3 : detections de profondeur
  _hl("alert_tag", "equal", "data_exfil", RED),
  _hl("alert_tag", "equal", "gpp_creds_access", RED),
  _hl("alert_tag", "equal", "kerberos_rc4", RED),
  _hl("alert_tag", "equal", "local_admin_add", ORANGE),
  _hl("alert_tag", "equal", "local_account_create", ORANGE),
  _hl("alert_tag", "equal", "new_country", ORANGE),
  # Lot 4 : detections AD/identite avancees
  _hl("alert_tag", "equal", "adcs_abuse", RED),
  _hl("alert_tag", "equal", "shadow_credentials", RED),
  _hl("alert_tag", "equal", "wmi_lateral_exec", ORANGE),
  _hl("alert_tag", "equal", "ldap_recon", ORANGE),
  _hl("alert_tag", "equal", "lateral_movement", ORANGE),
  # Nouvelles sources (ESET / BunkerWeb / NPS)
  _hl("alert_tag", "equal", "eset_detection", RED),
  _hl("alert_tag", "equal", "waf_block", ORANGE),
  _hl("event_action", "equal", "acces_reseau_nps_refuse", ORANGE),
  _hl("alert_tag", "equal", "volume_spike", ORANGE),
  _hl("alert_tag", "equal", "volume_drop", ORANGE),
  # Score UEBA eleve (ORANGE avant ROUGE : le rouge >=70 doit l'emporter)
  _hl("ueba_score", "greater_equal", 40, ORANGE),
  _hl("ueba_score", "greater_equal", 70, RED),
  # Incidents correles (kill-chain)
  _hl("incident_severity", "equal", "eleve", ORANGE),
  _hl("incident_severity", "equal", "critique", RED),
  _hl("incident_score", "greater_equal", 40, ORANGE),
  _hl("incident_score", "greater_equal", 70, RED),
]

# Drill-down : les PARAMETRES de dashboard sont une fonctionnalite Graylog
# ENTERPRISE (ils marquent la vue "missing requirement" en OSS). On les laisse
# vides -> sur la page Investigation, l'analyste utilise la BARRE DE RECHERCHE
# native en haut de page (host:..., user:...), qui filtre deja tous les widgets.
PARAMS = []

pages = [
 # ----- OMS-XDR : incidents correles (correlation + LLM local + reponse) --------
 {"title": "OMS-XDR", "streams": S(INT), "query_string": "event_source:xdr_incident", "page_range": D7, "widgets": [
   KPI("Incidents XDR (7j)", "event_source:xdr_incident", 1),
   KPI("Critiques", "event_source:xdr_incident AND severity:critical", 4),
   KPI("High", "event_source:xdr_incident AND severity:high", 7),
   W("Incidents par regle", "event_source:xdr_incident", "table", 1, 3, 6, 4, pivot="rule_id"),
   W("Incidents par severite", "event_source:xdr_incident", "table", 7, 3, 5, 4, pivot="severity"),
   W("Top entites visees", "event_source:xdr_incident", "table", 1, 7, 6, 4, pivot="entities"),
   W("Techniques ATT&CK", "event_source:xdr_incident", "table", 7, 7, 5, 4, pivot="mitre"),
   W("Detail incidents + narration LLM", "event_source:xdr_incident", "messages", 1, 11, 12, 6,
     fields=["timestamp","severity","rule_id","entities","message","full_message"], show_message=True),
 ]},
 # ----- DIRECTION : posture executive, lecture en 10 secondes (tendances J/J-1) -
 {"title": "Direction", "streams": S(WINSEC, SYSMON, WINOTH, FORTI, M365, INT), "widgets": [
   KPI("Événements collectes (24h)", "", 1,
       desc="Volume total de journaux collectes sur 24h. La fleche compare à la veille."),
   KPI("Détections (24h)", "alert_tag:*", 4, dir="LOWER",
       desc="Événements ayant déclenché une regle de détection (tag). En vert si en baisse vs la veille."),
   KPI("Hôtes actifs", "_exists_:host", 7, card="host",
       desc="Nombre d'hôtes distincts ayant émis des logs. Une baisse = des sources qui ne remontent plus."),
   KPI("Comptes en échec d'auth", "event_action:echec_connexion", 10, card="user", dir="LOWER",
       desc="Comptes distincts ayant échoué une authentification (AD + M365). Les échecs VPN portail sont sur la page 'VPN & Exposition'. Pic = brute force possible."),
   KPI("Refus pare-feu", "action:deny", 1, 3, dir="LOWER",
       desc="Connexions bloquées par le FortiGate. Un pic peut traduire un scan ou une exfiltration tentée."),
   KPI("Menaces réseau (UTM / exposition)", "alert_tag:fortigate_utm OR alert_tag:exposition_internet", 4, 3, dir="LOWER",
       desc="Détections virus/IPS de l'UTM FortiGate + services internes exposés a Internet (port à risque accepte en entrant)."),
   KPI("Incidents critiques (kill-chain)", "event_source:incident AND incident_severity:critique", 7, 3,
       card="incident_entity", range=86400, dir="LOWER",
       desc="Entités présentant une chaîne d'attaque CRITIQUE (>=2 tactiques ATT&CK corrélées, techniques graves). Le signal le plus actionnable du tableau. Détail : page Incidents."),
   KPI("Entités à risque (UEBA >=70)", "event_source:ueba_score AND ueba_score:>=70", 10, 3,
       card="ueba_entity", range=2100, dir="LOWER",
       desc="Hôtes/comptes au score comportemental UEBA >=70/100 (détections + vuln + anomalies fusionnées). Détail : page UEBA / NDR."),
   W("Télémétrie globale par source (24h)", "", "area", 1, 5, 8, 4, time=True, columns="event_source", events=True),
   W("Posture : détections par catégorie", "alert_tag:*", "bar", 9, 5, 4, 4, pivot="alert_tag", limit=12),
   W("Hôtes les plus à risque (détections / types / comptes)", "alert_tag:*", "table", 1, 9, 6, 4,
     pivot="host", limit=12, metrics=["count", ("card", "alert_tag", "Types"), ("card", "user", "Comptes")]),
   W("Exposition Internet : pays sources du trafic refusé", "action:deny", "table", 7, 9, 6, 4,
     pivot="src_country", limit=12, metrics=["count", ("card", "src_ip", "IP distinctes")]),
   W("Top hôtes par score de risque (7j)", "_exists_:risk_score", "table", 1, 13, 6, 4,
     pivot="host", limit=12, range=D7, metrics=[("sum", "risk_score", "Score"), "count"],
     desc="Hôtes classes par score de risque cumulé (sévérité pondérée des détections MITRE). Priorise le triage."),
   W("Top comptes par score de risque (7j)", "_exists_:risk_score AND _exists_:user", "table", 7, 13, 6, 4,
     pivot="user", limit=12, range=D7, metrics=[("sum", "risk_score", "Score"), "count"],
     desc="Comptes classes par score de risque cumulé."),
   # --- ajouts audit (signaux joyaux) ---
   KPI("Abus coffre Vaultwarden (7j)", "alert_tag:vault_admin_abuse", 1, 17, dir="LOWER", range=D7,
       desc="Sondes/brute-force sur le panneau admin du coffre de mots de passe (T1110). Tout pic = tentative d'accès au coffre, à investiguer en priorité."),
   KPI("Vulns KEV exploitées (parc)", "alert_tag:vuln_kev", 4, 17, dir="LOWER",
       desc="Hôtes exposés à une CVE activement EXPLOITÉE (catalogue CISA KEV). File de patch prioritaire (détail page Vulnérabilités)."),
   W("Abus coffre Vaultwarden - sources (7j)", "alert_tag:vault_admin_abuse", "table", 7, 17, 6, 3,
     pivot="src_ip", limit=15, range=D7, metrics=["count"],
     desc="IP à l'origine des sondes sur l'admin du coffre. À bloquer si externe / non légitime."),
 ]},
 {"title": "Santé collecte", "streams": S(WINSEC, SYSMON, WINOTH, FORTI, M365, INT, ESET, BW), "widgets": [
   KPI("Hôtes Windows", "event_source:windows* OR event_source:sysmon", 1, card="host",
       desc="Hôtes Windows ayant émis >=1 log sur 24h (Security ou Sysmon)."),
   KPI("Hôtes -> Security", "event_source:windows_security", 4, card="host",
       desc="Hôtes dont l'audit Security remonte. Une chute = GPO d'audit ou Winlogbeat tombe."),
   KPI("Hôtes -> Sysmon", "event_source:sysmon", 7, card="host",
       desc="Hôtes avec agent Sysmon actif. Un écart avec 'Hôtes Security' = Sysmon manquant."),
   KPI("Événements (24h)", "", 10, desc="Volume total ingere, toutes sources confondues."),
   W("Volume par source (24h)", "", "area", 1, 3, 12, 3, time=True, columns="event_source", events=True,
     desc="Télémétrie par source dans le temps. Un décrochage = source qui a cesse d'émettre."),
   W("Dernière activité par hôte - repérer les hôtes muets (7j)", "event_source:windows* OR event_source:sysmon",
     "table", 1, 6, 6, 5, pivot="host", limit=100, range=D7,
     metrics=["count", ("latest", "timestamp", "Dernier log")],
     sort_on="latest(timestamp)", sort_asc=True,
     desc="Hôtes vus sur 7j, TRIES du dernier log le PLUS ANCIEN en haut = hôtes muets (agent arrêté, poste éteint, panne)."),
   W("Hôtes envoyant Security (audit actif)", "event_source:windows_security", "table", 7, 6, 3, 5, pivot="host", limit=50),
   W("Hôtes envoyant Sysmon (agent actif)", "event_source:sysmon", "table", 10, 6, 3, 5, pivot="host", limit=50),
   W("Sources FortiGate", "event_source:fortigate", "table", 1, 11, 3, 4, pivot="host"),
   W("Canaux Windows collectes", "event_source:windows OR event_source:sysmon", "table", 4, 11, 3, 4, pivot="channel"),
   W("Hôtes les plus bavards (volume)", "", "table", 7, 11, 3, 4, pivot="host", limit=50),
   W("Comptes M365 vus", "m365_type:signin", "table", 10, 11, 3, 4, pivot="user"),
   # --- Couverture collecte (SLA) + go-dark (alimente par omni-collect-health) -
   KPI("Couverture collecte (%)", "sla_type:summary", 1, 16, metrics=[("latest", "sla_coverage_pct", "%")],
       range=7200, dir="HIGHER",
       desc="Part des hôtes GÉRÉS (vus < 14j) ayant émis dans les 24h. 100% = parc entièrement supervise. Derive du baseline, sans CMDB."),
   KPI("Hôtes gérés (parc)", "sla_type:summary", 4, 16, metrics=[("latest", "sla_expected", "Hôtes")],
       range=7200, desc="Nombre d'hôtes consideres actifs/gérés (au moins un log dans les 14 derniers jours)."),
   KPI("Hôtes actifs (24h)", "sla_type:summary", 7, 16, metrics=[("latest", "sla_active_24h", "Hôtes")],
       range=7200, desc="Hôtes gérés ayant émis dans les 24h."),
   KPI("Hôtes GO-DARK (>26h)", "sla_type:summary", 10, 16, metrics=[("latest", "sla_go_dark", "Hôtes")],
       range=7200, dir="LOWER",
       desc="Hôtes gérés SILENCIEUX depuis plus de 26h (agent arrêté, poste HS, ou compromission silencieuse). À traiter en priorité : c'est un angle mort."),
   W("Hôtes go-dark - collecte interrompue (détail)", "sla_type:go_dark", "table", 1, 18, 6, 4,
     pivot="dark_host", limit=50, range=7200, metrics=[("max", "hours_silent", "Heures muettes"), ("max", "host_volume_30d", "Vol. 30j")],
     sort_on="max(hours_silent)",
     desc="Hôtes actuellement go-dark (dernier passage horaire), tries du plus longtemps muet en haut. Vol. 30j = volume habituel = importance de l'angle mort."),
   W("Go-dark - dernier passage (qui, depuis quand)", "sla_type:go_dark", "messages", 7, 18, 6, 4,
     range=7200, fields=["timestamp", "dark_host", "last_seen", "hours_silent", "host_volume_30d"],
     desc="Détail du dernier passage : chaque hôte muet, son dernier log et son ancienneté de silence."),
   # --- Auto-supervision : les robots d'analyse tournent-ils ? (omni-self-health)
   KPI("Robots d'analyse en panne", "event_source:siem_health AND alert_tag:siem_job_fail", 1, 22,
       card="health_job", range=86400, dir="LOWER",
       desc="Robots d'analyse (UEBA/NDR/incidents/collecte...) ayant échoué ou cesse de tourner sur 24h. 0 = tout va bien ; >0 = la détection est partiellement aveugle, à corriger vite."),
   W("Robots d'analyse - pannes détectées (détail)", "event_source:siem_health AND health_type:job_fail", "messages", 4, 22, 9, 4,
     range=86400, fields=["timestamp", "health_job", "health_reason", "health_age_s"],
     desc="Quel robot est en panne et pourquoi (échec, ou pas execute depuis trop longtemps = timer mort)."),
   # --- Supervision des nouvelles sources (WAF / ESET / NPS) : detecter un go-dark ---
   W("Télémétrie sources externes WAF/ESET/NPS (24h)",
     "event_source:bunkerweb OR event_source:eset OR event_action:acces_reseau_nps_accorde OR event_action:acces_reseau_nps_refuse",
     "area", 1, 26, 8, 4, time=True, columns="event_source",
     desc="Volume des 3 nouvelles sources dans le temps. Un plat soudain a 0 = source muette (input/agent arrêté) à investiguer."),
   W("Dernière réception par source externe (24h)",
     "event_source:bunkerweb OR event_source:eset", "table", 9, 26, 4, 4,
     pivot="event_source", metrics=[("max", "timestamp", "Dernière réception"), "count"],
     desc="Horodatage du dernier message reçu par source. Si la dernière réception ESET/WAF date de plusieurs heures = collecte interrompue."),
 ]},
 {"title": "Alertes", "streams": S(WINSEC, SYSMON, WINOTH, FORTI, M365, VS) + [EVENTS], "widgets": [
   KPI("Détections (24h)", "alert_tag:*", 1, dir="LOWER",
       desc="Total des événements ayant déclenché une regle de détection sur 24h. Point d'entrée du triage."),
   KPI("Types de détection distincts", "alert_tag:*", 4, card="alert_tag",
       desc="Diversité des détections (nb de tags différents). Beaucoup de types simultanés = activité multi-vecteurs, à prioriser."),
   KPI("Hôtes concernés", "alert_tag:*", 7, card="host", dir="LOWER",
       desc="Hôtes distincts touchés par au moins une détection. À corréler avec le score de risque (page Direction)."),
   KPI("Comptes concernés", "alert_tag:* AND _exists_:user", 10, card="user", dir="LOWER",
       desc="Comptes distincts impliques dans une détection. Un compte récurrent sur plusieurs types = suspect prioritaire."),
   W("Détections dans le temps, par type (24h)", "alert_tag:*", "area", 1, 3, 12, 3,
     time=True, columns="alert_tag", col_limit=10, events=True),
   W("Volume par type de détection", "alert_tag:*", "bar", 1, 6, 4, 5, pivot="alert_tag", limit=20),
   W("Hôtes à risque (détections / types / comptes)", "alert_tag:*", "table", 5, 6, 4, 5,
     pivot="host", limit=20, metrics=["count", ("card", "alert_tag", "Types"), ("card", "user", "Comptes")]),
   W("Comptes à risque (détections / types)", "alert_tag:* AND _exists_:user", "table", 9, 6, 4, 5,
     pivot="user", limit=20, metrics=["count", ("card", "alert_tag", "Types")]),
   W("File de triage - détail de la détection (7j, message brut inclus)", "alert_tag:*", "messages",
     1, 11, 12, 5, limit=60, range=D7, show_message=True,
     fields=["timestamp", "risk_score", "alert_tag", "mitre_technique", "host", "user",
             "src_ip", "dest_ip", "event_action", "event_source"]),
   # (Retire : "Evenements Graylog correles" avec requete vide affichait TOUT le
   #  volume, pas les evenements correles -> trompeur. Le suivi des evenements
   #  declenches se fait dans Alerts & Events de Graylog.)
   W("Quand surviennent les détections : type x heure (24h)", "alert_tag:*", "heatmap", 1, 16, 12, 4,
     pivot="alert_tag", coltime=True, limit=20,
     desc="Lignes = type de détection, colonnes = heure. Les cases chaudes hors heures ouvrées méritent un oeil."),
   # --- ajouts audit : vraie file de triage par gravite (score >=7) ---
   W("File de triage par GRAVITE (risk_score >= 7)", "risk_score:>=7", "table", 1, 21, 8, 4,
     pivot="alert_tag", pivot2="host", limit=25,
     metrics=[("max", "risk_score", "Risque"), "count", ("card", "mitre_technique", "Techniques")],
     sort_on="max(risk_score)",
     desc="LA file de travail de l'analyste : détections les plus graves d'abord (score>=7), par type et hôte. Attaque-toi au haut de la liste."),
   W("Top techniques ATT&CK (alertes graves, 7j)", "risk_score:>=7 AND _exists_:mitre_technique", "bar", 9, 21, 4, 4,
     pivot="mitre_technique", limit=12, range=D7,
     desc="Techniques MITRE des détections graves. Une technique dominante = mode opératoire de l'attaquant."),
 ]},
 {"title": "Identité AD", "streams": S(WINSEC, WINOTH), "widgets": [
   KPI("Connexions réussies (4624)", "event_id:4624", 1,
       desc="Ouvertures de session AD réussies sur 24h (tous types confondus). Base de comparaison du volume normal."),
   KPI("Échecs d'auth (4625)", "event_id:4625", 4, dir="LOWER",
       desc="Échecs d'ouverture de session. Un pic concentre sur un compte ou un hôte = brute force / spraying probable."),
   KPI("Verrouillages (4740)", "event_id:4740", 7, dir="LOWER",
       desc="Comptes verrouillés (seuil de mot de passe atteint). Souvent la conséquence visible d'un spraying."),
   KPI("Comptes en échec distincts", "event_id:4625", 10, card="user", dir="LOWER",
       desc="Nombre de comptes distincts ayant échoué. Beaucoup de comptes pour peu d'IP = spraying ; 1 compte / beaucoup d'essais = brute force cible."),
   W("Authentifications AD : succès vs échec (24h)", "event_id:4624 OR event_id:4625", "area", 1, 3, 12, 3,
     time=True, columns="event_action", events=True,
     desc="Connexions réussies vs échouées au fil du temps. Un pic d'échecs hors heures ouvrées merite un oeil."),
   W("Raisons des échecs", "event_id:4625 AND NOT user:ninjaone AND NOT user:*$", "pie", 1, 6, 3, 4, pivot="failure_reason",
     desc="Pourquoi les connexions échouent (mauvais mot de passe, compte inconnu, compte verrouillé...)."),
   W("Échecs par compte", "event_id:4625", "bar", 4, 6, 3, 4, pivot="user",
     desc="Comptes accumulant le plus d'échecs. Un compte qui domine = cible d'une attaque par mot de passe."),
   W("Types de connexion (4624)", "event_id:4624", "pie", 7, 6, 3, 4, pivot="logon_type_label",
     desc="Comment les sessions s'ouvrent (interactive, réseau, RDP, service...). Un type inhabituel sur un serveur = à vérifier."),
   W("RDP par hôte", "event_id:4624 AND logon_type_label:rdp_interactif_distant", "table", 10, 6, 3, 4, pivot="host",
     desc="Bureaux à distance ouverts par hôte. Du RDP vers un serveur sensible doit être justifie."),
   W("Comptes verrouillés (4740)", "event_id:4740", "table", 1, 10, 3, 4, pivot="user",
     desc="Comptes verrouillés (trop d'échecs). Souvent l'effet visible d'une attaque par essais multiples."),
   W("Kerberos en échec", "event_id:4768 OR event_id:4771", "table", 4, 10, 3, 4, pivot="user",
     desc="Échecs d'authentification Kerberos. Volume anormal = reconnaissance ou attaque sur l'AD."),
   W("Privilèges spéciaux (4672)", "event_id:4672 AND (account_class:admin OR user:adm\\-*)", "table", 7, 10, 3, 4, pivot="user",
     desc="Sessions ayant reçu des droits élevés. Surveiller les comptes inattendus."),
   W("Comptes/tâches de service cassés (échecs / hôtes)", "event_id:4625 AND user:*$", "table", 10, 10, 3, 4,
     pivot="user", metrics=["count", ("card", "host", "Hôtes")],
     desc="Comptes de service dont l'ouverture échoué (mot de passe expire/change) -> service ou tâche plantée. Le nb d'hôtes montre l'ampleur."),
   W("Échecs AD récents (triage)", "event_id:4625", "messages", 1, 14, 12, 4,
     fields=["timestamp", "user", "src_ip", "src_host", "failure_reason", "host"]),
   W("Échecs d'auth : compte x hôte (heatmap, 7j)", "event_id:4625", "heatmap", 1, 18, 12, 5,
     pivot="user", columns="host", col_limit=25, limit=25, range=D7,
     desc="Lignes = compte, colonnes = hôte. Une ligne chaude = compte attaque partout (spraying) ; une colonne chaude = hôte cible."),
   # --- Hygiene d'authentification : NTLM vs Kerberos (T1550) -------------------
   KPI("Auth NTLM (4776, 24h)", "event_id:4776", 1, 23, dir="LOWER",
       desc="Validations NTLM (protocole legacy). Volume élevé = surface d'attaque (relais, pass-thé-hash T1550.002). À faire baisser au profit de Kerberos."),
   KPI("Auth Kerberos (4768/4769)", "event_id:4768 OR event_id:4769", 4, 23,
       desc="Tickets Kerberos (TGT + service). Plus Kerberos domine NTLM, meilleure est l'hygiène."),
   KPI("Comptes humains en NTLM", "event_id:4776 AND NOT winlogbeat_winlog_event_data_TargetUserName:*$", 7, 23,
       card="winlogbeat_winlog_event_data_TargetUserName", dir="LOWER",
       desc="Comptes utilisateurs (hors machines $) encore en NTLM = cibles de migration vers Kerberos."),
   KPI("Sessions NTLM v1 (downgrade)", "event_id:4624 AND winlogbeat_winlog_event_data_LmPackageName:\"NTLM V1\"", 10, 23, dir="LOWER",
       desc="Sessions en NTLM v1 (cassable/relayable). Tout événement est anormal : désactiver NTLMv1 (GPO LmCompatibilityLevel)."),
   W("Top comptes en NTLM (hors machines)", "event_id:4776 AND NOT winlogbeat_winlog_event_data_TargetUserName:*$", "table", 1, 25, 6, 4,
     pivot="winlogbeat_winlog_event_data_TargetUserName", limit=20,
     desc="Comptes s'authentifiant le plus en NTLM. Un compte à privilèges ici = risque pass-thé-hash : forcer Kerberos ou tracer l'appli legacy."),
   W("Connexions admin (adm-*) hors heures ouvrées (7j)", "event_id:4624 AND user:adm\\-* AND off_hours:oui", "table", 7, 25, 6, 4,
     pivot="user", columns="day_period", range=D7,
     desc="Sessions admin hors 7h-20h ou week-end (heure de Paris). Toute connexion ici doit correspondre à une intervention planifiée, sinon compte compromis probable. (Champ pose à l'ingestion -> à partir de maintenant.)"),
 ]},
 {"title": "M365", "streams": S(M365), "widgets": [
   KPI("Connexions cloud (24h)", "m365_type:signin", 1,
       desc="Authentifications Microsoft 365 / Entra ID (Azure AD) sur 24h."),
   KPI("Échecs de connexion", "m365_type:signin AND event_action:echec_connexion", 4, dir="LOWER",
       desc="Connexions M365 en échec. À croiser avec les pays sources : échecs depuis l'étranger = tentative externe."),
   KPI("Utilisateurs actifs", "m365_type:signin", 7, card="user",
       desc="Comptes M365 distincts vus en connexion sur 24h."),
   KPI("Actions admin Entra", "m365_type:audit", 10, dir="LOWER",
       desc="Opérations d'administration du tenant (rôles, applications, conditional access). À surveiller hors fenêtre de change."),
   W("Connexions par pays (24h)", "m365_type:signin", "line", 1, 3, 12, 3, time=True, columns="src_country"),
   W("Pays", "m365_type:signin", "pie", 1, 6, 3, pivot="src_country"),
   W("Échecs par compte", "m365_type:signin AND event_action:echec_connexion", "bar", 4, 6, 3, pivot="user"),
   W("Applications", "m365_type:signin", "table", 7, 6, 3, pivot="app"),
   W("Clients (legacy auth ?)", "m365_type:signin", "table", 10, 6, 3, pivot="client_app"),
   W("OS des appareils", "m365_type:signin", "table", 1, 10, 3, pivot="device_os"),
   W("Actions d'administration Entra", "m365_type:audit", "table", 4, 10, 3, limit=15, pivot="event_action"),
   W("Cibles des actions admin", "m365_type:audit", "table", 7, 10, 3, pivot="target"),
   W("Comptes à risque (30j)", "alert_tag:m365_risque", "table", 10, 10, 3, pivot="user", range=D30),
   W("Hors France / à risque - détail (7j)", "(m365_type:signin AND NOT src_country:FR) OR alert_tag:m365_risque", "messages", 1, 14, 12, 4,
     range=D7, show_message=True, fields=["timestamp", "user", "event_action", "src_ip", "src_country", "src_city", "app", "client_app"]),
   # --- Echecs de connexion M365 ventiles par cause (libelle FR, lookup) --------
   W("Échecs de connexion M365 par cause (24h)", "m365_type:signin AND event_action:echec_connexion", "bar", 1, 18, 6, 4,
     pivot="m365_fail_label", limit=12,
     desc="Échecs ventiles par libelle (compte verrouillé / identifiants invalides / bloqué Conditional Access / MFA requise...). Pose par lookup à l'ingestion. Un pic d'identifiants invalides sur beaucoup de comptes = spraying."),
   W("Échecs M365 par compte et cause (24h)", "m365_type:signin AND event_action:echec_connexion", "table", 7, 18, 6, 4,
     pivot="user", pivot2="m365_fail_label", limit=15, limit2=3,
     desc="Quel compte échoué et pourquoi. 'Compte verrouillé' repete = brute force aboutie au lockout ; 'Bloqué Conditional Access' = tentative depuis contexte non autorise."),
   # --- ajout audit : origine geographique des echecs (spray/attaque externe) ---
   W("Échecs M365 par PAYS / IP source (24h)", "m365_type:signin AND event_action:echec_connexion", "table", 1, 22, 12, 4,
     pivot="src_country", pivot2="src_ip", limit=20,
     metrics=["count", ("card", "user", "Comptes visés")],
     desc="D'ou viennent les échecs de connexion M365. Un pays inhabituel ciblant plusieurs comptes = password spraying externe à bloquer (Conditional Access)."),
 ]},
 {"title": "M365 Activité", "streams": S(M365), "widgets": [
   KPI("Événements activité (24h)", "m365_type:activity", 1,
       desc="Volume d'activité applicative M365 (Exchange, SharePoint, OneDrive, Teams) sur 24h."),
   KPI("Partages externes (7j)", "alert_tag:m365_partage_externe", 4, range=D7,
       desc="Fichiers/dossiers partages vers l'extérieur du tenant. Vecteur classique de fuite de données : à vérifier au cas par cas."),
   KPI("Transferts mail externes (7j)", "alert_tag:m365_mail_forward", 7, dir="LOWER", range=D7,
       desc="Regles de transfert de courrier vers une adresse externe. Indicateur fort de compromission de boîte (exfiltration discrète)."),
   KPI("Accès boîtes (MailItemsAccessed)", "event_action:MailItemsAccessed", 10,
       desc="Accès aux éléments de boîte aux lettres. Un pic sur une boîte sensible apres compromission = lecture de courrier par l'attaquant."),
   W("Activité par charge de travail (24h)", "m365_type:activity", "line", 1, 3, 12, 3, time=True, columns="m365_workload"),
   W("Répartition par charge", "m365_type:activity", "pie", 1, 6, 3, pivot="m365_workload"),
   W("Top opérations Exchange", "m365_workload:Exchange", "table", 4, 6, 3, pivot="event_action"),
   W("Top opérations SharePoint/OneDrive", "m365_workload:SharePoint OR m365_workload:OneDrive", "table", 7, 6, 3, pivot="event_action"),
   W("Accès aux boîtes par compte", "event_action:MailItemsAccessed", "table", 10, 6, 3, pivot="user"),
   W("Partages externes / liens - détail (7j)", "alert_tag:m365_partage_externe", "messages", 1, 10, 12, 4,
     range=D7, show_message=True, fields=["timestamp", "user", "event_action", "share_target", "share_file", "src_ip"]),
   W("Transferts mail / délégations - détail (7j : qui, vers quelle adresse)", "alert_tag:m365_mail_forward OR alert_tag:m365_mailbox_deleg",
     "messages", 1, 14, 12, 4, range=D7, show_message=True,
     fields=["timestamp", "user", "event_action", "fwd_target", "deleg_target", "src_ip"]),
 ]},
 {"title": "Endpoint", "streams": S(SYSMON, WINOTH), "widgets": [
   KPI("Processus créés (24h)", "event_source:sysmon AND event_id:1", 1,
       desc="Volume de créations de processus (Sysmon EventID 1)."),
   KPI("Hôtes Sysmon actifs", "event_source:sysmon", 4, card="host",
       desc="Hôtes remontant Sysmon sur 24h. À comparer au parc total : l'écart = postes sans agent ou agent arrêté."),
   KPI("Connexions réseau", "event_source:sysmon AND event_id:3", 7,
       desc="Connexions réseau observées par Sysmon (EventID 3). Sert de base aux chasses sur destinations inhabituelles."),
   KPI("Détections endpoint (7j)", "alert_tag:(powershell_suspect OR sysmon_injection OR defender OR lsass_access OR persistence_autorun OR explicit_cred_use OR beaconing)", 10, dir="LOWER", range=D7,
       desc="Détections poste de travail (PowerShell suspect, injection de processus, alertes Defender) sur 7j."),
   W("Activité endpoint (24h)", "event_source:(sysmon OR windows OR windows_security)", "area", 1, 3, 12, 3, time=True, columns="event_source", events=True,
     desc="Volume endpoint (Sysmon + journaux Windows) dans le temps. Scope explicite (evite d'agréger tout le SIEM)."),
   W("Top processus créés (volume / hôtes)", "event_source:sysmon AND event_id:1", "table", 1, 6, 4, 4,
     pivot="process_name", limit=15, metrics=["count", ("card", "host", "Hôtes")],
     desc="Processus les plus créés + nb d'hôtes. Un binaire rare présent sur beaucoup d'hôtes = à investiguer."),
   W("Chaînes parent -> enfant", "event_source:sysmon AND event_id:1", "table", 5, 6, 4, 4,
     pivot="parent_process", pivot2="process_name", limit=12, limit2=4,
     desc="Quel processus parent lance quel enfant. Repérer cmd/powershell lances par Office, services inattendus."),
   W("Top lignes de commande", "event_source:sysmon AND event_id:1 AND _exists_:command_line", "table", 9, 6, 4, 4,
     pivot="command_line", limit=15,
     desc="Commandes les plus frequentes. Les arguments inhabituels (-enc, base64, IP) ressortent ici."),
   W("Top requêtes DNS", "event_id:22", "table", 1, 10, 4, 4, pivot="dns_query", limit=15),
   W("Destinations réseau (sessions / hôtes)", "event_source:sysmon AND event_id:3", "table", 5, 10, 4, 4,
     pivot="dest_ip", limit=15, metrics=["count", ("card", "host", "Hôtes")]),
   W("Détections endpoint par type (7j)", "alert_tag:(powershell_suspect OR sysmon_injection OR defender OR lsass_access OR persistence_autorun OR explicit_cred_use OR beaconing)",
     "bar", 9, 10, 4, 4, pivot="alert_tag", range=D7),
   W("Détections endpoint - détail (7j : process + ligne de commande)",
     "alert_tag:(powershell_suspect OR sysmon_injection OR defender OR lsass_access OR persistence_autorun OR explicit_cred_use OR beaconing)",
     "messages", 1, 14, 12, 5, range=D7, show_message=True,
     fields=["timestamp", "host", "user", "alert_tag", "process_name", "command_line", "parent_process"]),
 ]},
 {"title": "Sources externes", "streams": S(ESET, WINSEC, WINOTH), "widgets": [
   KPI("Détections ESET (7j)", "alert_tag:eset_detection", 1, dir="LOWER", range=D7,
       desc="Menaces détectées/bloquées par ESET (Threat_Event, ransomware, quarantaine) sur 7j. Source = console ESET PROTECT en syslog JSON."),
   KPI("Postes touchés (7j)", "alert_tag:eset_detection", 4, card="eset_hostname", range=D7,
       desc="Nombre de postes DISTINCTS ayant déclenché une détection ESET (eset_hostname = vrai poste infecte, pas le serveur ESET)."),
   KPI("Accès NPS refusés (7j)", "event_action:acces_reseau_nps_refuse", 7, dir="LOWER", range=D7,
       desc="Authentifications RADIUS/NPS rejetées (6273) sur 7j. Pics = mauvais identifiants en masse ou tentative d'accès non autorise."),
   KPI("Accès NPS accordes (7j)", "event_action:acces_reseau_nps_accorde", 10, range=D7,
       desc="Authentifications RADIUS/NPS acceptées (6272) sur 7j. Sert de référence au volume normal."),
   # ----- ESET (antivirus) - champs eset_* issus du parsing JSON
   W("ESET - menaces par nom (7j)", "alert_tag:eset_detection", "table", 1, 3, 4, 4,
     pivot="eset_threat_name", limit=20, range=D7, metrics=["count", ("card", "eset_hostname", "Postes")],
     desc="Menaces les plus vues (eset_threat_name) + nb de postes touchés. Une même menace sur plusieurs postes = propagation."),
   W("ESET - postes infectes (7j)", "alert_tag:eset_detection", "table", 5, 3, 4, 4,
     pivot="eset_hostname", limit=20, range=D7, metrics=["count", ("card", "eset_threat_name", "Menaces")],
     desc="Postes accumulant le plus de détections. À isoler/nettoyer en priorité, surtout si plusieurs menaces distinctes."),
   W("ESET - par sévérité (7j)", "alert_tag:eset_detection", "pie", 9, 3, 4, 4,
     pivot="eset_severity", range=D7,
     desc="Répartition par sévérité ESET (Warning, Error, Critical, Fatal). Les Critical/Fatal sont à traiter immédiatement."),
   W("ESET - détections détaillées (7j)", "alert_tag:eset_detection", "messages", 1, 7, 8, 4,
     range=D7, show_message=False,
     fields=["timestamp", "eset_severity", "eset_hostname", "eset_threat_name", "eset_object_uri", "eset_action_taken", "eset_user"],
     desc="Détail structure des menaces : poste, menace, fichier (object_uri), action prise, utilisateur. À corréler avec Sysmon (page Endpoint)."),
   W("ESET - resultat de remédiation (7j)", "alert_tag:eset_detection", "table", 9, 7, 4, 4,
     pivot="eset_action_taken", pivot2="eset_severity", range=D7,
     desc="Action prise par ESET (cleaned/quarantined/blocked vs non remédiée). Les menaces NON nettoyées = vraie priorité SOC (champ eset_non_remediee)."),
   # ----- NPS / RADIUS (en attente de flux : voir doc Winlogbeat 6272-6274)
   W("[NPS en attente] Comptes les plus refusés (7j)", "event_action:acces_reseau_nps_refuse", "table", 1, 11, 4, 4,
     pivot="user", limit=20, range=D7,
     desc="EN ATTENTE DE FLUX NPS (audit 6272-6274 + Winlogbeat canal Security à activer). Comptes accumulant le plus de refus = MDP erroné, verrou, ou bruteforce."),
   W("[NPS en attente] Accorde vs refusé (7j)", "event_action:acces_reseau_nps_accorde OR event_action:acces_reseau_nps_refuse",
     "pie", 5, 11, 4, 4, pivot="event_action", range=D7,
     desc="EN ATTENTE DE FLUX NPS. Ratio accordes / refusés ; bascule vers le refus = panne d'auth ou attaque."),
   W("[NPS en attente] Refus récents (détail)", "event_action:acces_reseau_nps_refuse", "messages", 9, 11, 4, 4,
     range=D7, show_message=True, fields=["timestamp", "user", "src_ip", "message"],
     desc="EN ATTENTE DE FLUX NPS. Détail des refus (compte, source) une fois la collecte 6272/6273 active."),
 ]},
 {"title": "WAF BunkerWeb", "streams": S(BW), "widgets": [
   KPI("Requêtes WAF (24h)", "_exists_:http_status", 1,
       desc="Volume de requêtes HTTP parsees par le WAF sur 24h (count). Le nb d'IP sources distinctes est dans le tableau 'top IP'."),
   KPI("Blocages WAF (24h)", "http_status:(403 OR 429)", 4, dir="LOWER",
       desc="Requêtes bloquées par BunkerWeb (HTTP 403 / ModSecurity / denied) sur 24h. Un pic = scan applicatif ou attaque ciblée."),
   KPI("Erreurs 5xx (24h)", "http_status:(500 OR 502 OR 503 OR 504)", 7, dir="LOWER",
       desc="Erreurs serveur 5xx (backend KO, surcharge). Pic 502/503 = service derrière le WAF indisponible -> incident de prod."),
   KPI("Erreurs 4xx (24h)", "http_status:(400 OR 401 OR 403 OR 404)", 10, dir="LOWER",
       desc="Erreurs client 4xx. Beaucoup de 404/403 depuis une même IP = énumération/scan de chemins."),
   W("WAF - top IP sources (24h)", "_exists_:http_status", "table", 1, 3, 4, 4,
     pivot="src_ip", limit=20, metrics=["count", ("card", "http_url", "URLs")],
     desc="IP les plus actives + nb d'URL distinctes touchées. Beaucoup d'URLs distinctes depuis une IP = balayage/scan applicatif."),
   W("WAF - codes HTTP (24h)", "_exists_:http_status", "pie", 5, 3, 4, 4, pivot="http_status",
     desc="Répartition des codes de réponse. Une forte part de 4xx/5xx vs 2xx revele attaques (4xx) ou pannes (5xx)."),
   W("WAF - sites (vhosts) (24h)", "_exists_:http_status", "table", 9, 3, 4, 4,
     pivot="waf_vhost", limit=15, metrics=["count", ("card", "src_ip", "IP")],
     desc="Trafic par site publie. Permet de voir quel site est le plus sollicite / cible."),
   W("WAF - top URLs (24h)", "_exists_:http_status", "table", 1, 7, 6, 4,
     pivot="http_url", limit=25, metrics=["count", ("card", "src_ip", "IP")],
     desc="URLs les plus demandées. Les chemins sensibles (/admin, /.env, /wp-login) avec beaucoup d'IP = tentatives d'intrusion."),
   W("WAF - user-agents (24h)", "_exists_:http_status", "table", 7, 7, 6, 4,
     pivot="http_user_agent", limit=25, metrics=["count", ("card", "src_ip", "IP")],
     desc="Navigateurs/outils sources. Les UA d'outils (sqlmap, nikto, curl, python-requests, Wget) trahissent des scans automatises."),
   W("WAF - requêtes bloquées / refusées (détail)", "http_status:(403 OR 429)", "messages", 1, 11, 6, 5,
     show_message=False, fields=["timestamp", "src_ip", "waf_vhost", "http_method", "http_url", "http_status", "http_user_agent"],
     desc="Détail des requêtes bloquées (IP, site, méthode, URL, code, UA). Base d'investigation des attaques web bloquées par le WAF."),
   W("WAF - erreurs 5xx (détail)", "http_status:(500 OR 502 OR 503 OR 504)", "messages", 7, 11, 6, 5,
     show_message=False, fields=["timestamp", "src_ip", "waf_vhost", "http_url", "http_status"],
     desc="Détail des erreurs serveur 5xx. Permet d'identifier quel backend/site tombe et depuis quand (incident d'exploitation)."),
   W("WAF - outils offensifs détectés (UA : sqlmap, nikto, nmap...)", "http_user_agent:(*sqlmap* OR *nikto* OR *nmap* OR *nuclei* OR *masscan* OR *dirbuster* OR *gobuster* OR *wpscan* OR *python\\-requests* OR *go\\-http\\-client*)", "table", 1, 16, 6, 4,
     pivot="src_ip", pivot2="http_user_agent", limit=20, metrics=["count", ("card", "http_url", "URLs")],
     desc="IP utilisant un user-agent d'outil offensif (scan/exploit). Signal fort : ces IP font de la reconnaissance ou de l'exploitation active."),
   W("WAF - backend en erreur (5xx) par site", "http_status:(500 OR 502 OR 503 OR 504)", "table", 7, 16, 6, 4,
     pivot="waf_vhost", pivot2="http_status", limit=15, metrics=["count"],
     desc="Sites renvoyant des 5xx (backend KO/surcharge). Incident d'exploitation : le service derrière le WAF est indisponible."),
   W("WAF - activité par classe de code (24h)", "_exists_:http_status_class", "area", 1, 20, 12, 3,
     time=True, columns="http_status_class",
     desc="Volume par classe HTTP (2xx/3xx/4xx/5xx) dans le temps. Une vague de 4xx (scan) ou 5xx (panne) ressort immédiatement."),
   W("WAF - méthodes HTTP (24h)", "_exists_:http_method", "pie", 1, 23, 4, 4, pivot="http_method",
     desc="Répartition des méthodes. Tout POST/PUT/DELETE inhabituel (vs GET/HEAD majoritaires) = vecteur applicatif à surveiller."),
   W("WAF - bande passante servie par URL (24h)", "_exists_:http_bytes", "table", 5, 23, 4, 4,
     pivot="http_url", limit=15, metrics=[("sum", "http_bytes", "Octets servis")], sort_on="sum(http_bytes)",
     desc="URLs consommant le plus de bande passante. Un pic anormal sur une URL = scraping massif ou exfiltration via l'appli."),
   W("WAF - pays sources (anormal hors zone usuelle)", "_exists_:src_ip_country_code", "table", 9, 23, 4, 4,
     pivot="src_ip_country_code", pivot2="src_ip", limit=15, metrics=["count"],
     desc="Pays sources des requêtes WAF. Un pays inattendu en volume (ex. AD/KR) = scan/attaque externe à investiguer (croiser avec les outils offensifs)."),
 ]},
 {"title": "Aruba (switches)", "streams": S(ARUBA), "widgets": [
   KPI("Échecs auth admin (24h)", "alert_tag:aruba_auth_fail", 1, dir="LOWER",
       desc="Tentatives de login admin échouées sur un switch (web-UI/SSH/console). Un pic depuis une même IP = brute force admin."),
   KPI("Logins admin switch (24h)", "alert_tag:aruba_admin_login", 4,
       desc="Sessions d'administration ouvertes sur les switches. À corréler avec le segment d'origine (un admin depuis le VLAN utilisateurs = suspect)."),
   KPI("Changements config (24h)", "alert_tag:aruba_config_change", 7, dir="LOWER",
       desc="Modifications de configuration (running/startup). Hors fenêtre de maintenance = à valider (ticket)."),
   KPI("Port-security / STP (24h)", "alert_tag:(aruba_port_security OR aruba_stp_loop)", 10, dir="LOWER",
       desc="Violations port-security ou boucles STP (lien instable / appareil rogue branché)."),
   W("Détections par switch", "_exists_:alert_tag", "table", 1, 3, 6, 4,
     pivot="aruba_switch_name", limit=15, metrics=["count", ("card", "alert_tag", "types")],
     desc="Volume de détections par switch (nom résolu via l'inventaire). Permet d'isoler un équipement bruyant ou ciblé."),
   W("Top IP clientes (auth/login) + segment", "_exists_:aruba_client_ip", "table", 7, 3, 6, 4,
     pivot="src_ip", limit=15, metrics=["count", ("card", "net_segment", "segments")],
     desc="IP à l'origine des sessions/échecs admin, avec leur segment réseau. Une IP du VLAN utilisateurs sur l'admin switch = contournement de jump host."),
   W("Répartition des détections", "_exists_:alert_tag", "pie", 1, 7, 4, 4, pivot="alert_tag",
     desc="Part de chaque type de détection switch."),
   W("Activité par sous-système", "_exists_:aruba_subsystem", "table", 5, 7, 4, 4, pivot="aruba_subsystem", limit=10,
     desc="Sous-systèmes AOS-S (auth/ports/ssl/update…) : profil d'activité du parc switch."),
   W("Détail événements switch", "*", "messages", 1, 11, 12, 5, show_message=False,
     fields=["timestamp", "aruba_switch_name", "aruba_subsystem", "src_ip", "net_segment", "alert_tag", "message"],
     desc="Flux détaillé des événements switch."),
 ]},
 {"title": "Linux (serveurs)", "streams": S(LINUX), "widgets": [
   KPI("Échecs SSH (24h)", "alert_tag:linux_ssh_fail", 1, dir="LOWER",
       desc="Échecs d'authentification SSH. Un pic depuis une IP = brute force (corrélé à l'alerte agrégée >8/IP)."),
   KPI("sudo → root (24h)", "alert_tag:linux_sudo_root", 4,
       desc="Élévations vers root via sudo. À rapprocher de l'utilisateur et de la commande."),
   KPI("Comptes créés (24h)", "alert_tag:linux_user_added", 7, dir="LOWER",
       desc="Création de compte/groupe local. Hors provisioning déclaré = persistance suspecte."),
   KPI("Fichiers sensibles (24h)", "alert_tag:linux_sensitive_tamper", 10, dir="LOWER",
       desc="Modification surveillée (auditd) de /etc/passwd, shadow, sudoers, clés SSH = manipulation de compte/privilèges."),
   W("Détections par hôte", "_exists_:alert_tag", "table", 1, 3, 6, 4,
     pivot="host", limit=15, metrics=["count", ("card", "alert_tag", "types")],
     desc="Détections par serveur Linux."),
   W("Top IP sources SSH + segment", "_exists_:src_ip", "table", 7, 3, 6, 4,
     pivot="src_ip", limit=15, metrics=["count", ("card", "user", "comptes")],
     desc="IP à l'origine des connexions/échecs SSH, et nb de comptes visés (beaucoup de comptes = spray)."),
   W("Répartition des détections", "_exists_:alert_tag", "pie", 1, 7, 4, 4, pivot="alert_tag",
     desc="Part de chaque détection Linux."),
   W("Comptes (user) en cause", "_exists_:user", "table", 5, 7, 4, 4, pivot="user", limit=12,
     desc="Comptes les plus présents dans les événements Linux."),
   W("Détail événements Linux", "*", "messages", 1, 11, 12, 5, show_message=False,
     fields=["timestamp", "host", "user", "src_ip", "net_segment", "alert_tag", "message"],
     desc="Flux détaillé sshd/sudo/auditd."),
 ]},
 {"title": "FortiClient EMS", "streams": S(EMS), "widgets": [
   KPI("Malware bloqués (24h)", "alert_tag:forticlient_malware", 1, dir="LOWER",
       desc="Malware détecté/bloqué par l'AV FortiClient sur un poste."),
   KPI("Protection désactivée (24h)", "alert_tag:forticlient_av_off", 4, dir="LOWER",
       desc="AV temps-réel désactivé ou FortiClient altéré = précurseur d'attaque (defense evasion)."),
   KPI("Vulnérabilités critiques (24h)", "alert_tag:forticlient_vuln", 7, dir="LOWER",
       desc="Vulnérabilité critique/haute remontée sur un poste."),
   KPI("Login admin console EMS (24h)", "alert_tag:ems_admin_login", 10,
       desc="Connexion admin à la console EMS (gestion du parc). À surveiller : un accès EMS pousse des politiques sur tous les postes."),
   W("Top postes (events)", "_exists_:host", "table", 1, 3, 6, 4,
     pivot="host", limit=15, metrics=["count", ("card", "alert_tag", "types")],
     desc="Postes les plus actifs côté EMS."),
   W("Détections de sécurité", "_exists_:alert_tag", "table", 7, 3, 6, 4,
     pivot="alert_tag", limit=10, metrics=["count", ("card", "host", "postes")],
     desc="Types de détections endpoint et nb de postes concernés."),
   W("Sous-types EMS", "_exists_:subtype", "pie", 1, 7, 4, 4, pivot="subtype",
     desc="Répartition des sous-types d'événements EMS."),
   W("Admins console EMS", "_exists_:ems_msg AND alert_tag:ems_admin_login", "table", 5, 7, 4, 4,
     pivot="user", limit=10, metrics=["count", ("card", "src_ip", "IP")],
     desc="Comptes admin EMS et leurs IP source."),
   W("Détail événements EMS", "*", "messages", 1, 11, 12, 5, show_message=False,
     fields=["timestamp", "host", "user", "subtype", "src_ip", "net_segment", "alert_tag", "ems_msg"],
     desc="Flux détaillé EMS."),
 ]},
 {"title": "Réseau", "streams": S(FORTI), "widgets": [
   KPI("Refus (deny)", "action:deny", 1, dir="LOWER",
       desc="Connexions bloquées par la politique du FortiGate. Un pic = scan entrant ou tentative d'exfiltration sortante."),
   KPI("UTM (virus/IPS)", "alert_tag:fortigate_utm", 4, dir="LOWER",
       desc="Détections du moteur UTM (antivirus, IPS, web filter). Chaque hit merite vérification de l'hôte concerné."),
   KPI("IP malveillantes (TI)", "alert_tag:threat_intel", 7, dir="LOWER",
       desc="Trafic vers/depuis des IP réputées malveillantes (Tor, Spamhaus). Une IP interne qui parle à ces destinations = à isoler."),
   KPI("Sessions VPN", "subtype:vpn", 10,
       desc="Événements VPN (SSL portail + tunnels IPsec). Volume de référence de l'activité VPN."),
   KPI("Volume total (To)", "", 1, 3, metrics=[("sum", "bytes_total_tb", "To")],
       desc="Volume cumulé (entrant + sortant) traverse par le pare-feu, en teraoctets (1 To = 1000 Go). Conversion figée à l'ingestion."),
   KPI("Trafic sortant (Go)", "", 4, 3, metrics=[("sum", "bytes_sent_gb", "Go")], dir="LOWER",
       desc="Volume émis vers l'extérieur (Go). Un pic sortant inexpliqué, surtout hors heures ouvrées = signal d'exfiltration."),
   KPI("Trafic entrant (Go)", "", 7, 3, metrics=[("sum", "bytes_rcvd_gb", "Go")],
       desc="Volume reçu depuis l'extérieur (Go)."),
   KPI("IP sources distinctes", "", 10, 3, card="src_ip",
       desc="Nombre d'adresses sources distinctes vues par le pare-feu."),
   W("Trafic par action dans le temps (24h)", "", "area", 1, 5, 12, 3, time=True, columns="action", events=True,
     desc="Volume de connexions par décision du pare-feu (accept/deny/...) au fil du temps. Un pic de 'deny' = scan ou attaque."),
   W("Bande passante échangée - Go/heure (24h)", "bytes_total:>0", "area", 1, 8, 8, 3, time=True,
     metrics=[("sum", "bytes_total_gb", "Go")],
     desc="Volume total echange par tranche horaire, en Go. Un pic nocturne ou hors-activité merite vérification."),
   W("Top talkers par volume (Go / sessions)", "bytes_total:>0", "table", 9, 8, 4, 3,
     pivot="src_ip", limit=10, metrics=[("sum", "bytes_total_gb", "Go"), "count"],
     desc="IP internes les plus volumineuses (Go). Un poste bureautique en tete de classement = anormal."),
   W("Top sources bloquées (sessions / dest. / pays)", "action:deny OR action:blocked", "table", 1, 11, 6, 4,
     pivot="src_ip", limit=15, metrics=["count", ("card", "dest_ip", "Dest."), ("card", "dest_country", "Pays")]),
   W("Top destinations (sessions / sources / Go)", "", "table", 7, 11, 6, 4,
     pivot="dest_ip", limit=15, metrics=["count", ("card", "src_ip", "Sources"), ("sum", "bytes_total_gb", "Go")]),
   W("Pays de destination", "", "pie", 1, 15, 3, 4, pivot="dest_country", limit=12),
   W("UTM (virus / IPS) par attaque", "alert_tag:fortigate_utm", "table", 4, 15, 3, 4, pivot="attack"),
   W("IP malveillantes (Tor/Spamhaus)", "alert_tag:threat_intel", "table", 7, 15, 3, 4, pivot="dest_ip"),
   W("Applications (sessions / Go)", "_exists_:app", "table", 10, 15, 3, 4, pivot="app",
     limit=15, metrics=["count", ("sum", "bytes_total_gb", "Go")]),
   # (Triage VPN retire ici : il a sa page dediee "VPN & Exposition" -> allege la page.)
   W("Trafic refusé : pays source x pays destination (heatmap)", "action:deny", "heatmap", 1, 19, 12, 5,
     pivot="src_country", columns="dest_country", limit=25, col_limit=25,
     desc="Lignes = pays source, colonnes = pays destination des connexions BLOQUÉES. Reserved = interne. Repère les axes geo anormaux."),
   # --- Est-ouest (mouvement lateral interne) : interne -> interne REFUSE --------
   W("Est-ouest refusé - top services (mouvement latéral)", "action:deny AND src_ip_reserved_ip:true AND dest_ip_reserved_ip:true", "table", 1, 24, 6, 5,
     pivot="service", limit=20, metrics=["count", ("card", "dest_ip", "Cibles"), ("card", "src_ip", "Sources")],
     desc="Connexions INTERNE->INTERNE bloquées par le pare-feu, par service. SMB/RDP/RPC refusés entre VLANs = reconnaissance / propagation latérale. Un service inhabituel inter-segments est à investiguer."),
   W("Est-ouest refusé : source interne x port (heatmap)", "action:deny AND src_ip_reserved_ip:true AND dest_ip_reserved_ip:true", "heatmap", 7, 24, 6, 5,
     pivot="src_ip", columns="dest_port", limit=20, col_limit=20,
     desc="Lignes = source interne, colonnes = port destination refusé. Ligne chaude sur beaucoup de ports = scan interne ; concentre sur 445/3389 = tentative SMB/RDP latérale."),
 ]},
 {"title": "vSphere", "streams": S(VS), "widgets": [
   KPI("Événements vSphere (24h)", "", 1,
       desc="Volume de journaux ESXi / vCenter sur 24h. Référence de l'activité normale de la plateforme."),
   KPI("Échecs auth", "alert_tag:vsphere_auth_fail", 4, dir="LOWER",
       desc="Échecs d'authentification vCenter/ESXi. Répéter depuis une même IP = tentative d'accès à l'hyperviseur."),
   KPI("IP sources d'échec auth (7j)", "alert_tag:vsphere_auth_fail", 7, card="src_ip", dir="LOWER", range=D7,
       desc="Nombre d'IP distinctes en échec d'authentification sur vCenter/ESXi (7j). Un élargissement soudain = balayage de l'hyperviseur."),
   KPI("Snapshots de sauvegarde (24h)", "event_action:snapshot_sauvegarde", 10,
       desc="Snapshots créés (chaîne de sauvegarde des VM). Une chute a 0 = sauvegardes interrompues. NB : la détection des SUPPRESSIONS de VM et de l'activation SSH/Shell ESXi exige un transfert d'événements vCenter structures (le flux syslog brut actuel est noyé dans le debug/perf - cf. doc d'audit, action source-side)."),
   W("Activité vSphere (24h)", "", "line", 1, 3, 12, 3, time=True, columns="event_action"),
   W("Hôtes ESXi / vCenter", "", "table", 1, 6, 3, 4, pivot="host"),
   W("Sources d'échec d'auth", "alert_tag:vsphere_auth_fail", "table", 4, 6, 3, 4, pivot="src_ip"),
   W("Comptes vus", "_exists_:user", "table", 7, 6, 3, 4, pivot="user"),
   W("Actions", "_exists_:event_action", "pie", 10, 6, 3, 4, pivot="event_action"),
   W("Échecs d'authentification vSphere - détail (7j : compte, IP, hôte)", "alert_tag:vsphere_auth_fail", "messages", 1, 10, 6, 4,
     range=D7, show_message=True, fields=["timestamp", "host", "user", "src_ip", "event_action"]),
   W("Snapshots de sauvegarde - détail (7j : hôte, action)", "event_action:snapshot_sauvegarde", "messages", 7, 10, 6, 4,
     range=D7, show_message=True, fields=["timestamp", "host", "user", "event_action"]),
 ]},
 {"title": "Hunting", "streams": S(WINSEC, SYSMON, WINOTH), "widgets": [
   KPI("Accès mémoire LSASS", "event_source:sysmon AND event_id:10 AND winlogbeat_winlog_event_data_TargetImage:*lsass.exe", 1,
       desc="Processus accédant à la mémoire de lsass.exe (vol d'identifiants, T1003). Hors antivirus/EDR légitimes, tout accès est critique."),
   KPI("Office -> shell (7j)", "parent_process:(*winword* OR *excel* OR *outlook*) AND process_name:(cmd.exe OR powershell.exe OR wscript.exe)", 4, range=D7,
       desc="Une application Office qui lance un interpréteur de commandes = signature classique de macro malveillante / phishing."),
   KPI("Exec. AppData/Temp", "event_id:1 AND process_path:(*AppData* OR *Temp*)", 7,
       desc="Binaires executes depuis AppData/Temp (emplacements d'écriture utilisateur privilégiés par les malwares)."),
   KPI("Persistance Run/RunOnce", "event_id:13 AND winlogbeat_winlog_event_data_TargetObject:*Run* AND NOT winlogbeat_winlog_event_data_TargetObject:*Services*", 10,
       desc="Écritures dans les clés Run/RunOnce du registre = mécanisme de persistance au démarrage (T1547)."),
   W("Processus accédant a LSASS (Sysmon 10)", "event_source:sysmon AND event_id:10 AND winlogbeat_winlog_event_data_TargetImage:*lsass.exe",
     "table", 1, 3, 6, pivot="winlogbeat_winlog_event_data_SourceImage"),
   W("Office qui lance un shell (7j)", "parent_process:(*winword* OR *excel* OR *outlook*) AND process_name:(cmd.exe OR powershell.exe OR wscript.exe)",
     "table", 7, 3, 6, pivot="host", range=D7, metrics=["count", ("card", "user", "Comptes")]),
   W("Exécutions depuis AppData/Temp", "event_id:1 AND process_path:(*AppData* OR *Temp*)", "table", 1, 7, 4, pivot="process_name"),
   W("Persistance registre (Run)", "event_id:13 AND winlogbeat_winlog_event_data_TargetObject:*Run* AND NOT winlogbeat_winlog_event_data_TargetObject:*Services*", "table", 5, 7, 4, pivot="host"),
   W("Pipes nommes (Sysmon 17/18, 7j)", "event_source:sysmon AND (event_id:17 OR event_id:18)", "table", 9, 7, 4,
     pivot="winlogbeat_winlog_event_data_PipeName", range=D7),
   W("Connexions sortantes de binaires inhabituels", "event_id:3 AND NOT process_name:(chrome.exe OR msedge.exe OR firefox.exe OR svchost.exe OR Teams.exe OR OUTLOOK.EXE)",
     "table", 1, 11, 6, pivot="process_name"),
   W("ScriptBlocks longs / encodes - détail (7j, script brut inclus)", "event_id:4104 AND (winlogbeat_winlog_event_data_ScriptBlockText:*FromBase64String* OR winlogbeat_winlog_event_data_ScriptBlockText:*-enc*)",
     "messages", 7, 11, 6, 4, range=D7, show_message=True, fields=["timestamp", "host", "user"]),
   # --- Premiere apparition (baselining) : ce qui est NOUVEAU sur 30j ----------
   W("Nouveaux hôtes - 1re apparition récente (30j)", "", "table", 1, 15, 6, 4,
     pivot="host", limit=25, range=D30, metrics=[("min", "timestamp", "1re apparition"), "count"],
     sort_on="min(timestamp)",
     desc="Hôtes tries par PREMIÈRE apparition la plus RÉCENTE en haut. Un hôte jamais vu avant = nouveau matériel légitime... ou poste non inventorie / rogue à vérifier."),
   W("Nouveaux processus - jamais vus avant (30j)", "event_source:sysmon AND event_id:1", "table", 7, 15, 6, 4,
     pivot="process_name", limit=25, range=D30, metrics=[("min", "timestamp", "1re apparition"), ("card", "host", "Hôtes")],
     sort_on="min(timestamp)",
     desc="Binaires dont la 1re exécution est récente. Un processus inédit apparaissant sur plusieurs hôtes en même temps = déploiement... ou propagation."),
   W("Nouveaux comptes admin actifs (30j)", "user:adm\\-* AND event_id:4624", "table", 1, 19, 12, 4,
     pivot="user", limit=25, range=D30, metrics=[("min", "timestamp", "1re apparition"), ("card", "src_ip", "Origines")],
     sort_on="min(timestamp)",
     desc="Comptes d'administration dont la 1re connexion observée est récente. Un compte adm-* nouvellement actif doit correspondre à une habilitation tracée."),
 ]},
 {"title": "Comptes & conformité", "streams": S(WINSEC, WINOTH, M365), "widgets": [
   KPI("Comptes créés (4720, 30j)", "event_id:4720", 1, range=D30,
       desc="Nouveaux comptes AD créés sur 30j. À rapprocher des tickets d'arrivée : un compte créé sans demande = à investiguer."),
   KPI("Comptes désactivés (4725, 30j)", "event_id:4725", 4, range=D30,
       desc="Comptes désactivés sur 30j (départs, comptes dormants). Un creux peut traduire des comptes d'anciens non désactivés."),
   KPI("Comptes supprimés (4726, 30j)", "event_id:4726", 7, dir="LOWER", range=D30,
       desc="Suppressions de comptes. Une suppression de compte privilégié non planifiée = effacement de traces potentiel."),
   KPI("Certificats émis (PKI, 30j)", "event_action:certificat_emis", 10, range=D30,
       desc="Certificats delivres par AD CS sur 30j (vue conformité ; détail complet sur la page Certificats)."),
   W("Cycle de vie des comptes AD (30j)", "event_category:gestion_comptes", "pie", 1, 3, 4, 4, pivot="event_action", range=D30,
     desc="Répartition des opérations sur comptes (création, désactivation, reset MDP, suppression). Profil normal vs pics anormaux."),
   W("Comptes désactivés / réactivés (30j)", "event_id:4725 OR event_id:4722", "table", 5, 3, 4, 4, pivot="user", range=D30,
     desc="Comptes récemment désactivés (4725) ou réactivés (4722). Une réactivation de compte dormant = vecteur d'attaque classique."),
   W("Rôles M365 modifies (30j)", "m365_type:audit AND event_action:*role*", "table", 9, 3, 4, 4, pivot="event_action", range=D30),
   W("Services installés (7j)", "event_id:4697 OR event_action:service_installe", "table", 1, 7, 4, 4, pivot="host", range=D7),
   W("Comptes créés / supprimés (30j)", "event_id:4720 OR event_id:4726", "table", 5, 7, 4, 4, pivot="user", range=D30),
   W("Activité PKI (AD CS, 30j)", "event_category:pki", "table", 9, 7, 4, 4, pivot="event_action", range=D30),
   W("Accès NPS refusés (7j)", "event_action:acces_reseau_nps_refuse", "table", 1, 11, 6, 4, pivot="user", range=D7),
   W("Partages admin accedes (5140, 7j)", "event_id:5140", "table", 7, 11, 6, 4, pivot="user", range=D7,
     desc="Accès aux partages d'administration (C$/ADMIN$/IPC$). Volume anormal par un compte = mouvement latéral possible."),
   W("Accès fichiers sensibles par compte (7j)", "alert_tag:file_sensitive_access", "table", 1, 19, 6, 4,
     pivot="user", range=D7, metrics=["count", ("card", "file_path", "Fichiers"), ("card", "host", "Serveurs")], sort_on="count",
     desc="Accès aux dossiers sensibles audites par SACL (clients/RH/...). Un compte touchant un volume anormal de fichiers = exfiltration possible. (Vide tant que les SACL ne sont pas posées cote serveurs - cf. 59-file-audit.sh.)"),
   W("Suppressions de fichiers sensibles - détail (7j)", "alert_tag:file_delete_sensible", "messages", 7, 19, 6, 4,
     range=D7, fields=["timestamp", "user", "file_path", "host"],
     desc="Suppressions sur les dossiers sensibles (signal ransomware/sabotage). Toute rafale = incident."),
   W("Abus coffre Vaultwarden (7j)", "alert_tag:vault_admin_abuse", "table", 1, 23, 6, 4, pivot="src_ip", range=D7,
     desc="Sondes/brute-force sur l'admin du coffre de mots de passe (joyau). À corréler avec une éventuelle compromission de compte."),
   W("Sabotage de l'audit - détail (30j, message brut)", "event_category:sabotage_audit OR event_id:4719 OR alert_tag:audit_config_change", "messages", 1, 15, 12, 4,
     range=D30, show_message=True, fields=["timestamp", "host", "user", "event_action", "src_ip"]),
 ]},
 {"title": "Cartographie", "streams": S(M365, FORTI), "widgets": [
   KPI("Connexions M365 hors France (7j)", "m365_type:signin AND NOT src_country:FR", 1, dir="LOWER", range=D7,
       desc="Connexions M365 géolocalisées hors France. À confronter aux déplacements légitimes ; un pays jamais vu = alerte."),
   KPI("Échecs VPN portail (7j)", "subtype:vpn AND status:failure", 4, dir="LOWER", range=D7,
       desc="Échecs sur le portail SSL-VPN exposé. La carte ci-dessous localisé l'origine des tentatives."),
   KPI("Pays VPN distincts", "subtype:vpn AND _exists_:remip_country_code", 7, card="remip_country_code",
       desc="Nombre de pays sources d'accès VPN. Un élargissement soudain = pairs/attaquants nouveaux."),
   KPI("Pays M365 distincts", "m365_type:signin", 10, card="src_country",
       desc="Nombre de pays sources de connexions M365 sur 24h."),
   W("Connexions M365 dans le monde", "m365_type:signin", "map", 1, 3, 6, 5, pivot="src_ip_geolocation", limit=500),
   W("Accès VPN dans le monde", "subtype:vpn", "map", 7, 3, 6, 5, pivot="remip_geolocation", limit=500,
     desc="TOUS les accès VPN (SSL + IPsec), vue d'ensemble géographique. Pour l'origine des seules ATTAQUES portail, voir la page 'VPN & Exposition'."),
   W("M365 par pays", "m365_type:signin", "table", 1, 8, 4, 4, pivot="src_country"),
   W("VPN par pays", "subtype:vpn AND _exists_:remip_country_code", "table", 5, 8, 4, 4, pivot="remip_country_code"),
   W("Sources VPN en échec - brute force (7j)", "subtype:vpn AND status:failure", "table", 9, 8, 4, 4, pivot="remip", range=D7),
 ]},
 {"title": "Comptes à privilèges", "streams": S(WINSEC, WINOTH, M365), "widgets": [
   KPI("Connexions admin (adm-*)", "event_id:4624 AND user:adm\\-*", 1,
       desc="Ouvertures de session des comptes d'administration (convention adm-*). À corréler avec 'D'ou se connectent les admins'."),
   KPI("Échecs admin (adm-*)", "event_id:4625 AND user:adm\\-*", 4, dir="LOWER",
       desc="Échecs sur comptes d'administration. Cible privilégiée = priorité de triage élevée."),
   KPI("Privilèges spéciaux (4672)", "event_id:4672 AND (account_class:admin OR user:adm\\-*)", 7,
       desc="Sessions ayant reçu des privilèges spéciaux (hors comptes machine $). Surveiller les comptes inattendus ici."),
   KPI("Groupes privilégiés modifies (30j)", "_exists_:priv_group_label", 10, dir="LOWER", range=D30,
       desc="Modifications d'appartenance aux groupes sensibles (Domain/Enterprise Admins...). Tout changement non planifié = à justifier."),
   W("Connexions admin (24h)", "(event_id:4624 OR event_id:4625) AND user:adm\\-*", "line", 1, 3, 12, 3, time=True, columns="event_action"),
   W("Comptes admin actifs", "event_id:4624 AND user:adm\\-*", "table", 1, 6, 3, 4, pivot="user"),
   W("D'ou se connectent les admins", "event_id:4624 AND user:adm\\-* AND _exists_:src_ip", "table", 4, 6, 3, 4, pivot="src_ip"),
   W("Échecs admin par compte", "event_id:4625 AND user:adm\\-*", "table", 7, 6, 3, 4, pivot="user"),
   W("Privilèges spéciaux par compte", "event_id:4672 AND (account_class:admin OR user:adm\\-*)", "table", 10, 6, 3, 4, pivot="user"),
   W("Modifications de groupes privilégiés (30j)", "_exists_:priv_group_label", "table", 1, 10, 6, 4,
     pivot="priv_group_label", range=D30, metrics=["count", ("card", "user", "Auteurs")]),
   W("Ajouts à un groupe sensible - détail (30j : qui ajoute qui, ou)", "event_id:4728 OR event_id:4732 OR event_id:4756",
     "messages", 7, 10, 6, 4, range=D30, show_message=True,
     fields=["timestamp", "user", "priv_group_label", "winlogbeat_winlog_event_data_TargetUserName",
             "winlogbeat_winlog_event_data_MemberName", "src_ip", "host"]),
   W("Détections sur comptes sensibles - détail (30j)", "alert_tag:dcsync OR alert_tag:kerberoasting OR alert_tag:m365_role",
     "messages", 1, 14, 12, 4, range=D30, show_message=True,
     fields=["timestamp", "host", "user", "alert_tag", "event_action", "src_ip"]),
   W("Répartition par classe de compte (24h)", "_exists_:account_class", "pie", 1, 18, 4, 4, pivot="account_class",
     desc="Classe déduite à l'ingestion (admin/service/machine/user). Donne le poids des comptes à privilèges dans l'activité. (Champ pose à partir de maintenant.)"),
   W("Activité des comptes admin (account_class:admin)", "account_class:admin", "table", 5, 18, 8, 4,
     pivot="user", limit=20, metrics=["count", ("card", "host", "Hôtes"), ("card", "event_action", "Actions")],
     desc="Activité par compte d'administration (classe admin). Un compte admin touchant beaucoup d'hôtes = surveiller (mouvement latéral / usage anormal)."),
 ]},
 {"title": "VPN & Exposition", "streams": S(FORTI, WINSEC), "widgets": [
   KPI("Échecs portail SSL (7j)", "subtype:vpn AND status:failure", 1, dir="LOWER", range=D7,
       desc="Échecs d'authentification sur le portail SSL-VPN. C'est la surface d'attaque exposée a Internet : tout pic est suspect."),
   KPI("IP attaquantes distinctes (7j)", "subtype:vpn AND status:failure", 4, card="remip", dir="LOWER", range=D7,
       desc="IP sources distinctes en échec sur le portail. Beaucoup d'IP = botnet / spraying distribue."),
   KPI("Tunnels IPsec distincts", "subtype:vpn", 7, card="vpntunnel",
       desc="Tunnels IPsec site-a-site negocies (trafic légitime inter-sites). Référence de l'activité normale."),
   KPI("Verrouillages AD (4740, 7j)", "event_id:4740", 10, dir="LOWER", range=D7,
       desc="Comptes AD verrouillés : effet collatéral d'un spraying réussi à atteindre l'AD via le VPN. À corréler avec les échecs portail."),
   W("Activité VPN par action (24h)", "subtype:vpn", "area", 1, 3, 12, 3, time=True, columns="action", events=True),
   # --- Securite : portail SSL-VPN (brute force / spraying) - fenetre 7j ------
   W("Origine des attaques portail (SSL, 7j)", "subtype:vpn AND status:failure", "map", 1, 6, 6, 5,
     pivot="remip_geolocation", limit=500, range=D7,
     desc="Carte des ÉCHECS portail SSL uniquement (origine géographique des attaques). Complémentaire de la carte 'Accès VPN dans le monde' (Cartographie) qui montre TOUS les accès VPN."),
   W("Top IP en échec (SSL, 7j)", "subtype:vpn AND status:failure", "table", 7, 6, 3, 5, pivot="remip", range=D7),
   W("Comptes visés / spraying (SSL, 7j)", "subtype:vpn AND status:failure AND _exists_:user", "table", 10, 6, 3, 5, pivot="user", range=D7),
   # --- Légitime : IPsec site-a-site -----------------------------------------
   W("Tunnels IPsec (négociations / pairs distincts)", "subtype:vpn", "table", 1, 11, 5, 4,
     pivot="vpntunnel", limit=20, metrics=["count", ("card", "remip", "Pairs")]),
   W("Pairs IPsec par pays", "subtype:vpn AND _exists_:remip_country_code", "table", 6, 11, 4, 4, pivot="remip_country_code"),
   W("Comptes AD verrouillés - 7j (effet du spraying)", "event_id:4740", "table", 10, 11, 3, 4, pivot="user", range=D7),
   W("Activité VPN (triage : SSL + IPsec)", "subtype:vpn", "messages", 1, 15, 12, 4,
     fields=["timestamp", "remip", "vpntunnel", "user", "action", "logdesc", "remip_country_code"]),
 ]},
 {"title": "Sauvegardes", "streams": S(WINOTH, VS, INT), "widgets": [
   KPI("Événements Veeam (24h)", "event_source:veeam", 1,
       desc="Volume de journaux Veeam sur 24h. Une chute a 0 = serveur de sauvegarde qui ne remonte plus (à vérifier en priorité)."),
   KPI("Jobs en échec RÉEL (24h)", "alert_tag:veeam_job_echec", 4, dir="LOWER",
       desc="Jobs dont le resultat FINAL est en échec (apres les retries Veeam). 0 = toutes les sauvegardes aboutissent. Les échecs transitoires reessayes avec succès (verrou de point de restauration) sont comptes à part en 'avertissements'."),
   KPI("Snapshots vSphere (sauvegarde)", "event_action:snapshot_sauvegarde", 7,
       desc="Snapshots créés dans le cadre des sauvegardes. Absence prolongée = chaîne de sauvegarde interrompue."),
   KPI("Serveurs Veeam vus", "event_source:veeam", 10, card="host",
       desc="Serveurs Veeam distincts ayant émis des logs."),
   W("Activité Veeam (24h)", "event_source:veeam", "line", 1, 3, 12, 3, time=True, columns="winlogbeat_log_level"),
   W("Sévérité des events Veeam", "event_source:veeam", "pie", 1, 6, 3, 4, pivot="winlogbeat_log_level"),
   W("Retries / avertissements par serveur (24h)", "alert_tag:veeam_job_warn", "table", 4, 6, 3, 4, pivot="host",
     desc="Échecs de tâche TRANSITOIRES que Veeam a reessayes avec succès (souvent un verrou de point de restauration tenu par le job Backup Copy). Récurrent sur un même serveur = contention de planification à revoir, pas un trou de PRA."),
   W("Snapshots de sauvegarde par hôte", "event_action:snapshot_sauvegarde", "table", 7, 6, 3, 4, pivot="host"),
   W("Activité snapshots (24h)", "event_action:snapshot_sauvegarde", "line", 10, 6, 3, 4, time=True),
   W("Jobs en échec / avertissement - triage (24h)", "alert_tag:veeam_job_echec OR alert_tag:veeam_job_warn", "messages", 1, 10, 12, 5,
     show_message=True, fields=["timestamp", "host", "alert_tag", "winlogbeat_log_level"]),
   KPI("Heartbeats supervision (24h)", "event_source:siem_health AND health_type:summary", 1, 15,
       desc="Battements de l'auto-supervision SIEM (omni-self-health). Doivent être réguliers ; une absence = le superviseur lui-même est tombe."),
   KPI("Robots SIEM en panne (24h)", "event_source:siem_health AND health_fail:[1 TO *]", 4, 15, dir="LOWER",
       desc="Battements signalant au moins un robot collecteur/enrichissement en panne. Détail dans le journal ci-dessous."),
   KPI("Jobs robots en échec (24h)", "event_source:siem_health AND health_type:job_fail", 7, 15, dir="LOWER",
       desc="Jobs internes (timers systemd) ayant échoué lors du dernier controle d'auto-supervision."),
   KPI("Veeam jobs en erreur (24h)", "event_source:veeam AND winlogbeat_log_level:erreur", 10, 15, dir="LOWER",
       desc="Jobs de sauvegarde Veeam termines en erreur sur 24h. Toute valeur > 0 = sauvegarde à rejouer (trou de PRA)."),
   W("Auto-supervision SIEM - détail (robots / jobs)", "event_source:siem_health",
     "messages", 1, 17, 12, 4, fields=["timestamp", "health_type", "health_ok", "health_fail", "health_total", "message"]),
 ]},
 {"title": "Certificats", "streams": S(WINSEC, WINOTH, INT), "widgets": [
   KPI("Certs émis (PKI, 30j)", "event_source:adcs AND event_id:4887", 1, range=D30,
       desc="Certificats delivres par l'autorité AD CS sur 30j. Un pic inhabituel = émission de masse à vérifier."),
   KPI("Demandes refusées (30j)", "event_source:adcs AND event_id:4888", 4, dir="LOWER", range=D30,
       desc="Demandes de certificat refusées par la CA. Répétées depuis un même demandeur = mauvaise conf ou tentative d'abus de modèle."),
   KPI("Certs revoques (30j)", "event_source:adcs AND event_id:4870", 7, dir="LOWER", range=D30,
       desc="Certificats revoques. À corréler avec un départ d'employé ou une compromission suspectée."),
   KPI("Parc : proches expiration", "event_source:cert_parc", 10, dir="LOWER",
       desc="Certificats du parc remontes comme proches d'expiration par Get-OmniCertExpiry. Le détail (jours restants) est dans la table en bas."),
   W("Activité d'émission PKI (30j)", "event_source:adcs", "line", 1, 3, 8, 3, time=True, columns="event_action", range=D30),
   KPI("Certs critiques parc (<15j)", "event_source:cert_parc AND cert_days:[0 TO 15]", 9, 3, dir="LOWER"),
   KPI("Cert SIEM (auto-renouv.)", "event_source:siem_cert", 9, 5, card="event_action", range=D30),
   W("Certificats émis par demandeur (30j)", "event_source:adcs AND event_id:4887", "table", 1, 7, 6, 5,
     pivot="cert_requester", range=D30, metrics=["count", ("card", "cert_request_id", "Demandes")]),
   W("Demandes refusées / révocations - 30j (à surveiller)", "event_source:adcs AND (event_id:4888 OR event_id:4870)", "table", 7, 7, 6, 5,
     pivot="cert_requester", range=D30),
   W("Parc : certificats proches d'expiration (triage)", "event_source:cert_parc", "messages", 1, 12, 12, 4,
     fields=["timestamp", "cert_machine", "cert_subject", "cert_days", "cert_expiry", "cert_store"]),
   W("Activité PKI récente - détail (30j : qui, quel modèle, refus/revoc)", "event_source:adcs", "messages", 1, 16, 12, 4,
     range=D30, show_message=True,
     fields=["timestamp", "event_action", "cert_requester", "cert_request_id", "cert_template", "host"]),
   W("Certificats SIEM - état courant (jours restants)", "event_source:siem_cert AND event_action:cert_status", "table", 1, 20, 6, 3,
     pivot="cert", metrics=[("max", "cert_days", "Jours restants")], sort_on="max(cert_days)",
     desc="État courant des certificats du SIEM (console, API, Root CA) - émis a chaque run de cert-check, donc TOUJOURS visible même apres une purge. Vert = ok, sinon à renouveler via AD CS."),
   W("Certificat SIEM - détail / renouvellement", "event_source:siem_cert", "messages", 7, 20, 6, 3,
     show_message=True, fields=["timestamp", "cert", "cert_days", "cert_state", "event_action"]),
 ]},
 # ----- VULNERABILITES : KEV + anciennete patch (alimente par omni-vuln-scan) -
 {"title": "Vulnérabilités", "streams": S(INT), "page_range": 100800, "widgets": [
   KPI("Hôtes exposés (KEV)", "event_source:vuln AND vuln_type:kev", 1, card="host", dir="LOWER",
       desc="Hôtes exécutant un produit a CVE ACTIVEMENT EXPLOITÉE (CISA KEV). Reflete le dernier scan quotidien."),
   KPI("Produits a CVE exploitée", "event_source:vuln AND vuln_type:kev", 4, card="vuln_product"),
   KPI("Hôtes non patches (>35j)", "event_source:vuln AND vuln_type:patch_age", 7, card="host", dir="LOWER",
       desc="Hôtes dont le dernier correctif date de plus de 35 jours. C'est le signal le plus FIABLE."),
   KPI("Expositions ransomware", "event_source:vuln AND vuln_ransomware:oui", 10, dir="LOWER",
       desc="Produits a CVE liée à des campagnes de rancongiciel (flag CISA KEV)."),
   W("Risque vulnérabilité cumulé par hôte", "event_source:vuln", "bar", 1, 3, 12, 3, pivot="host", limit=15,
     metrics=[("sum", "risk_score", "Score")],
     desc="Contribution des vulnérabilités au score de risque de chaque hôte (alimente aussi le classement Direction)."),
   W("Exposition KEV par hôte (produits / CVE)", "event_source:vuln AND vuln_type:kev", "table", 1, 6, 6, 5,
     pivot="host", limit=20, metrics=["count", ("card", "vuln_product", "Produits"), ("sum", "vuln_cve_count", "CVE")]),
   W("Produits exposés (hôtes / CVSS max)", "event_source:vuln AND vuln_type:kev", "table", 7, 6, 6, 5,
     pivot="vuln_product", limit=20, metrics=["count", ("card", "host", "Hôtes"), ("max", "vuln_cvss", "CVSS max")]),
   W("Détail exposition KEV (produit / version / CVE)", "event_source:vuln AND vuln_type:kev", "messages", 1, 11, 12, 5,
     show_message=True, fields=["timestamp", "host", "vuln_product", "vuln_version", "vuln_cve_count", "vuln_cves", "vuln_cvss", "vuln_ransomware"]),
   W("Ancienneté des correctifs - hôtes à patcher (jours)", "event_source:vuln AND vuln_type:patch_age", "table", 1, 16, 6, 4,
     pivot="host", limit=20, metrics=[("max", "patch_age_days", "Jours")],
     desc="Hôtes classes par ancienneté du dernier correctif installé."),
   W("Détail correctifs (OS / dernier KB / jours)", "event_source:vuln AND vuln_type:patch_age", "messages", 7, 16, 6, 4,
     show_message=True, fields=["timestamp", "host", "os_caption", "os_build", "patch_age_days", "os_last_kb", "os_last_patch"]),
   # --- ajout audit : file de remediation RANSOMWARE (produits a patcher en priorite) ---
   W("Focus remédiation RANSOMWARE (produits à patcher en 1er)", "event_source:vuln AND vuln_ransomware:oui", "table", 1, 20, 12, 4,
     pivot="vuln_product", limit=25, metrics=[("card", "host", "Hôtes"), ("max", "vuln_cvss", "CVSS max"), ("sum", "vuln_cve_count", "CVE")],
     sort_on="card(host)",
     desc="Produits porteurs d'une CVE exploitée par des RANSOMWARES (KEV ransomware), classes par nb d'hôtes touchés = file de patch prioritaire absolue."),
 ]},
 # ----- INCIDENTS : correlation attack-chain (omni-incident-correlate) -------
 # Recits d'attaque : detections d'une meme entite agregees en kill-chain ATT&CK
 # ordonnee + scorees. Fenetres courtes (1200s) = dernier passage (toutes les 15 min).
 {"title": "Incidents", "streams": S(INT), "widgets": [
   KPI("Incidents CRITIQUES (en cours)", "event_source:incident AND incident_severity:critique", 1,
       card="incident_entity", range=86400, dir="LOWER",
       desc="Entités présentant une chaîne d'attaque critique (>=70/100 : plusieurs tactiques ATT&CK dont des techniques graves). À traiter en priorité absolue."),
   KPI("Incidents élevés", "event_source:incident AND incident_severity:eleve", 4,
       card="incident_entity", range=86400, dir="LOWER",
       desc="Entités avec une chaîne d'attaque de sévérité élevée (40-69/100)."),
   KPI("Entités en incident", "event_source:incident", 7, card="incident_entity", range=86400, dir="LOWER",
       desc="Nombre d'entités (hôtes/comptes) corrélées en incident (>=2 tactiques ATT&CK) sur la fenêtre."),
   KPI("Chaîne la plus longue (tactiques)", "event_source:incident", 10, range=86400,
       metrics=[("max", "incident_tactics", "Tactiques")],
       desc="Nombre maximal de tactiques ATT&CK distinctes enchaînées sur une seule entité. Plus c'est long, plus l'attaque est avancée."),
   W("Incidents en cours - entité / score / tactiques", "event_source:incident", "table", 1, 3, 8, 5,
     pivot="incident_entity", limit=25, range=86400, sort_on="max(incident_score)",
     metrics=[("max", "incident_score", "Score"), ("max", "incident_tactics", "Tactiques")],
     desc="Entités classées par score d'incident (sévérité pondérée + diversité des tactiques). Le détail narratif est en dessous."),
   W("Répartition par sévérité", "event_source:incident", "pie", 9, 3, 4, 5, pivot="incident_severity", range=86400),
   W("Récits d'attaque - kill-chain ordonnée (détail)", "event_source:incident", "messages", 1, 8, 12, 7,
     range=86400, show_message=True,
     fields=["incident_severity", "incident_entity", "incident_score", "incident_tactics",
             "incident_kill_chain", "incident_techniques", "incident_first_seen", "incident_last_seen", "incident_span_h"],
     desc="Chaque incident raconte : l'entité, la séquence de tactiques ATT&CK ordonnée (kill-chain), les techniques, et la fenêtre temporelle. Transforme des alertes éparses en histoire exploitable."),
 ]},
 # ----- ATT&CK : lecture MITRE des detections (mappe par 37-mitre-attack.sh) --
 {"title": "ATT&CK", "streams": S(WINSEC, SYSMON, WINOTH, FORTI, M365, VS), "widgets": [
   KPI("Techniques observées (7j)", "_exists_:mitre_technique", 1, card="mitre_technique", range=D7,
       desc="Techniques MITRE ATT&CK distinctes détectées sur 7 jours."),
   KPI("Tactiques couvertes (7j)", "_exists_:mitre_tactic", 4, card="mitre_tactic", range=D7,
       desc="Tactiques ATT&CK distinctes (étapes de la kill chain) observées."),
   KPI("Score de risque cumulé (7j)", "_exists_:risk_score", 7, range=D7, metrics=[("sum", "risk_score", "Score")],
       desc="Somme des scores de risque (sévérité pondérée) de toutes les détections sur 7j."),
   KPI("Détections critiques (7j)", "risk_severity:critique", 10, dir="LOWER", range=D7,
       desc="Détections de sévérité critique (LSASS, DCSync, injection, sabotage d'audit, canary...)."),
   W("Couverture par tactique (7j)", "_exists_:mitre_tactic", "bar", 1, 3, 12, 3, pivot="mitre_tactic", limit=14, range=D7,
     desc="Volume de détections par tactique ATT&CK : montre ou se concentre l'activité suspecte."),
   W("Carte tactique x technique (7j)", "_exists_:mitre_technique", "heatmap", 1, 6, 8, 5,
     pivot="mitre_tactic", columns="mitre_technique", col_limit=20, range=D7,
     desc="Croisement tactique (lignes) x technique (colonnes). Les cases chaudes = techniques les plus frequentes."),
   W("Détections par sévérité (7j)", "_exists_:risk_severity", "pie", 9, 6, 4, 5, pivot="risk_severity", range=D7),
   W("Techniques (détections / hôtes) (7j)", "_exists_:mitre_technique", "table", 1, 11, 6, 4,
     pivot="mitre_technique", pivot2="mitre_technique_name", limit=20, range=D7, metrics=["count", ("card", "host", "Hôtes")],
     desc="Chaque technique observée, son nom, le volume et le nombre d'hôtes touchés."),
   W("Tactiques par score de risque (7j)", "_exists_:mitre_tactic", "table", 7, 11, 6, 4,
     pivot="mitre_tactic", limit=14, range=D7, metrics=[("sum", "risk_score", "Score"), "count"]),
   W("Détections mappees ATT&CK - détail (7j)", "_exists_:mitre_technique", "messages", 1, 15, 12, 5, range=D7, show_message=True,
     fields=["timestamp", "mitre_tactic", "mitre_technique", "mitre_technique_name", "alert_tag",
             "risk_severity", "risk_score", "host", "user", "src_ip"]),
   # --- ajout audit : techniques par HOTE (chaine technique -> hote -> score) ---
   W("Techniques ATT&CK par HÔTE (7j)", "_exists_:mitre_technique AND _exists_:host", "table", 1, 20, 12, 4,
     pivot="host", pivot2="mitre_technique", limit=30, range=D7,
     metrics=[("max", "risk_score", "Risque"), "count", ("card", "mitre_tactic", "Tactiques")],
     sort_on="max(risk_score)",
     desc="Quel hôte presente quelles techniques, classe par risque. Un hôte cumulant plusieurs tactiques distinctes = compromission probable à investiguer."),
 ]},
 # ----- UEBA / NDR : analytique comportementale "au-dela de Graylog" ----------
 # Alimentee par les collecteurs omni-ueba-* / omni-ndr-* (40-ueba-ndr.sh) qui
 # calculent ce que l'agregation Graylog ne sait pas faire : score d'entite
 # fusionne, impossible travel (geo-velocite), beaconing (regularite temporelle),
 # anomalie de volume (z-score). Fenetres courtes (2100s/25200s) = DERNIER passage.
 {"title": "UEBA / NDR", "streams": S(INT), "widgets": [
   KPI("Entités à risque (>=70)", "event_source:ueba_score AND ueba_score:>=70", 1, card="ueba_entity", range=2100, dir="LOWER",
       desc="Entités (hôte OU compte) au score UEBA fusionne >=70/100 au dernier calcul (30 min). C'est la file de priorité du SOC."),
   KPI("Impossible travel (7j)", "event_source:ueba_geo", 4, card="user", dir="LOWER", range=D7,
       desc="Comptes ayant presente un déplacement géographiquement impossible entre 2 connexions (M365/VPN). Signal fort de compte compromis / session volée."),
   KPI("Balises C2 suspectes (24h)", "event_source:ndr_beacon", 7, card="dest_ip", dir="LOWER", range=86400,
       desc="Destinations externes contactées a intervalle RÉGULIER (faible jitter) = beaconing potentiel. À trier (du SaaS légitime 'bat' aussi)."),
   KPI("Anomalies de volume (24h)", "event_source:ueba_volume", 10, dir="LOWER", range=86400,
       desc="Sources dont le volume horaire devie de >N sigma vs sa baseline même-heure (pic = exfil/scan/boucle ; chute = audit coupe / agent tue)."),
   W("Top HÔTES par score UEBA (0-100)", "event_source:ueba_score AND entity_type:host", "table", 1, 3, 6, 5,
     pivot="ueba_entity", limit=20, range=2100, sort_on="max(ueba_score)",
     metrics=[("max", "ueba_score", "Score"), ("max", "factor_detections", "Détections"),
              ("max", "factor_godark", "Go-dark"), ("max", "factor_beacon", "Beacon")],
     desc="Hôtes classes par score de risque FUSIONNE (détections MITRE/vuln sévérité-distincte + go-dark + beaconing), normalise 0-100. Le facteur dominant explique le score."),
   W("Top COMPTES par score UEBA (0-100)", "event_source:ueba_score AND entity_type:user", "table", 7, 3, 6, 5,
     pivot="ueba_entity", limit=20, range=2100, sort_on="max(ueba_score)",
     metrics=[("max", "ueba_score", "Score"), ("max", "factor_detections", "Détections"),
              ("max", "factor_authfail", "Échecs auth")],
     desc="Comptes classes par score UEBA (détections + impossible travel + échecs d'authentification pondérés)."),
   W("Impossible travel - détail (7j : trajet impossible)", "event_source:ueba_geo", "messages", 1, 8, 12, 4,
     range=D7, show_message=True,
     fields=["timestamp", "user", "geo_from", "geo_to", "geo_km", "geo_hours", "geo_speed_kmh", "geo_from_ip", "geo_to_ip"],
     desc="Chaque déplacement impossible : compte, lieux (ville/pays + source), distance, délai, vitesse requise. Vitesse > avion = compte utilise depuis 2 lieux à la fois."),
   W("Beaconing / C2 - balises à trier (dernier passage)", "event_source:ndr_beacon", "messages", 1, 12, 7, 4,
     range=86400, show_message=True,
     fields=["timestamp", "src_ip", "dest_ip", "dest_country", "beacon_interval_s", "beacon_jitter_cv", "beacon_hits", "beacon_service"],
     desc="Flux internes->externes a intervalle régulier. Jitter (CV) faible = très régulier = suspect. Trier vs SaaS connu (étendre NDR_ALLOW_PREFIX dans 00-vars.env)."),
   W("Anomalies de volume (24h : z-score)", "event_source:ueba_volume", "messages", 8, 12, 5, 4,
     range=86400, show_message=True,
     fields=["timestamp", "anomaly_entity", "alert_tag", "vol_observed", "vol_mean", "vol_zscore"],
     desc="Sources en écart statistique. z-score = nombre d'écarts-types vs la baseline même-heure-du-jour (>=4 = pic, <=-3 = chute)."),
   W("Facteur de risque dominant (entités)", "event_source:ueba_score", "pie", 1, 16, 4, 4,
     pivot="ueba_top_factor", range=2100,
     desc="Répartition du facteur dominant : montre si le risque du parc vient surtout des détections, des échecs d'auth, du go-dark ou du beaconing."),
   W("Distribution des scores UEBA (hôtes)", "event_source:ueba_score AND entity_type:host", "bar", 5, 16, 8, 4,
     pivot="ueba_score", limit=25, range=2100, sort_asc=True, sort_on="ueba_entity",
     desc="Histogramme des scores : la queue droite (scores élevés) = les entités à traiter en priorité."),
   W("Exfiltration / tunneling DNS - domaines suspects (24h)", "event_source:ndr_dns", "table", 1, 20, 6, 4,
     pivot="dns_domain", limit=20, range=86400, sort_on="max(dns_distinct_sub)",
     metrics=[("max", "dns_distinct_sub", "Sous-dom."), ("max", "dns_avg_entropy", "Entropie"), ("max", "dns_avg_len", "Long.")],
     desc="Domaines a beaucoup de sous-domaines a HAUTE ENTROPIE (données encodées) = tunneling/exfil DNS probable. CDN/cloud déjà exclus (allowlist)."),
   W("Tunneling DNS - détail (hôte / domaine)", "event_source:ndr_dns", "messages", 7, 20, 6, 4,
     range=86400, show_message=True,
     fields=["timestamp", "entity_host", "dns_domain", "dns_distinct_sub", "dns_avg_entropy", "dns_avg_len"],
     desc="Quel hôte interroge quel domaine suspect. Entropie >3.6 + sous-domaines longs = charge encodée (base32/64)."),
   W("Scan réseau interne (balayage / reconnaissance)", "event_source:ndr_scan", "messages", 1, 24, 12, 4,
     range=5400, show_message=True,
     fields=["timestamp", "scan_type", "entity_host", "scan_dest_count", "scan_port_count", "scan_top_ports", "scan_deny"],
     desc="Source interne refusée vers BEAUCOUP d'hôtes (horizontal) ou de ports (vertical) = scan / reconnaissance / mouvement latéral. Un serveur d'infra peut être légitime (à allowlister apres revue)."),
   W("Exfiltration par volume - flux sortants suspects (24h)", "event_source:ndr_exfil", "messages", 1, 28, 12, 4,
     range=86400, show_message=True,
     fields=["timestamp", "entity_host", "dest_ip", "dest_country", "exfil_gb", "exfil_sessions", "exfil_dest_ports"],
     desc="Hôte interne ayant televerse un volume SORTANT > seuil (défaut 1 Go/h) vers une IP externe (T1048). 1 seul port + gros volume = upload/exfil ; nombreux ports = sync/backup. Egress légitime (SaaS/backup) à mettre dans EXFIL_ALLOW_DEST."),
 ]},
 # ----- INVESTIGATION : page pilotee par le parametre $filtre$ ---------------
 {"title": "Identité", "streams": S(WINSEC, SYSMON, WINOTH, FORTI, M365, VS, INT),
  "page_range": D7, "widgets": [
   KPI("Événements (identité filtrée)", "_exists_:identity", 1,
       desc="IDENTITÉ UNIFIÉE : tapez 'identity:jmorin' dans la BARRE DE RECHERCHE -> toute la page se filtre sur cette personne, TOUTES sources confondues (AD + M365 + VPN + endpoint + vSphere)."),
   KPI("Sources couvertes", "_exists_:identity", 4, card="event_source",
       desc="Nombre de sources distinctes ou cette identité apparaît. Une identité vue sur beaucoup de sources = forte empreinte."),
   KPI("Hôtes touchés", "_exists_:identity", 7, card="host"),
   KPI("Détections liées", "_exists_:identity AND alert_tag:*", 10, dir="LOWER"),
   W("Activité par source dans le temps", "_exists_:identity", "area", 1, 3, 12, 3, time=True, columns="event_source", events=True,
     desc="Filtrez via 'identity:<compte>' en haut. Visualise la répartition de l'activité d'une personne par source dans le temps."),
   W("Identités les plus actives (empreinte multi-sources)", "_exists_:identity", "table", 1, 6, 6, 5,
     pivot="identity", limit=25, metrics=["count", ("card", "event_source", "Sources"), ("card", "host", "Hôtes"), ("sum", "risk_score", "Risque")],
     sort_on="sum(risk_score)",
     desc="Activité par identité, triée par risque cumulé. Une identité a fort risque sur plusieurs hôtes/sources = priorité d'investigation."),
   W("Comptes regroupes par PERSONNE (adm-/svc- <-> humain)", "_exists_:identity_human", "table", 7, 6, 6, 5,
     pivot="identity_human", limit=25, metrics=["count", ("card", "identity", "Comptes"), ("card", "account_class", "Classes"), ("sum", "risk_score", "Risque")],
     sort_on="card(identity)",
     desc="Regroupe adm-X, svc-X et X sous la même personne. Une personne avec plusieurs comptes ACTIFS (humain + admin) = surface à surveiller (usage du compte admin pour des tâches courantes, etc.)."),
   W("Ouvertures AD (4624) par identité", "event_id:4624 AND _exists_:identity", "table", 1, 11, 3, 4, pivot="identity", metrics=["count", ("card", "host", "Hôtes")]),
   W("Connexions M365 par identité", "m365_type:signin AND _exists_:identity", "table", 4, 11, 3, 4, pivot="identity", metrics=["count", ("card", "src_country", "Pays")]),
   W("Accès VPN par identité", "subtype:vpn AND _exists_:identity", "table", 7, 11, 3, 4, pivot="identity"),
   W("Endpoint (process) par identité", "event_source:sysmon AND event_id:1 AND _exists_:identity", "table", 10, 11, 3, 4, pivot="identity", metrics=["count", ("card", "process_name", "Process")]),
   W("Activité détaillée (identité filtrée : qui, quoi, ou)", "_exists_:identity", "messages", 1, 15, 12, 5,
     fields=["timestamp", "identity", "identity_human", "account_class", "event_source", "host", "event_action", "alert_tag", "src_ip"]),
 ]},
 {"title": "Investigation", "streams": S(WINSEC, SYSMON, WINOTH, FORTI, M365, VS, INT),
  "page_range": D7, "widgets": [
   KPI("Événements (filtre)", "", 1, desc="Total correspondant à la requete tapée dans la barre de recherche de la page."),
   KPI("Hôtes", "", 4, card="host"),
   KPI("Comptes", "", 7, card="user"),
   KPI("Détections", "alert_tag:*", 10, dir="LOWER"),
   W("Activité dans le temps", "", "area", 1, 3, 12, 3, time=True, columns="event_source", events=True,
     desc="DRILL-DOWN : tapez 'host:BX-SRV01', 'user:adm-jmorin' ou 'src_ip:1.2.3.4' dans la BARRE DE RECHERCHE en haut de cette page -> tous les widgets se filtrent."),
   W("Actions / opérations", "_exists_:event_action", "table", 1, 6, 4, 4, pivot="event_action", limit=20),
   W("Détections (type / score)", "alert_tag:*", "table", 5, 6, 4, 4, pivot="alert_tag", limit=20,
     metrics=["count", ("sum", "risk_score", "Score")]),
   W("IP sources", "_exists_:src_ip", "table", 9, 6, 4, 4, pivot="src_ip", limit=20),
   W("Processus (si endpoint)", "event_source:sysmon AND event_id:1", "table", 1, 10, 3, 4, pivot="process_name", limit=20),
   W("Connexions réseau (Sysmon 3)", "event_id:3 AND _exists_:dest_ip", "table", 4, 10, 3, 4, pivot="dest_ip", limit=20),
   W("Requêtes DNS (Sysmon 22)", "event_id:22 AND _exists_:dns_query", "table", 7, 10, 3, 4, pivot="dns_query", limit=20),
   W("Destinations pare-feu", "event_source:fortigate", "table", 10, 10, 3, 4, pivot="dest_ip", limit=20),
   W("Journal brut (détail)", "", "messages", 1, 14, 12, 6, limit=80, show_message=True,
     fields=["timestamp", "event_source", "host", "user", "src_ip", "event_action", "alert_tag", "process_name"]),
 ]},
]
# Ordre de lecture coherent (par theme), sans toucher aux positions internes :
# pilotage -> triage -> menace -> identite -> cloud -> endpoint -> reseau ->
# infra -> vulnerabilites -> investigation (page libre, en dernier).
ORDER = ["Direction", "Alertes", "Incidents", "OMS-XDR", "ATT&CK", "UEBA / NDR", "Santé collecte",
         "Identité AD", "Comptes à privilèges", "Comptes & conformité",
         "M365", "M365 Activité", "Endpoint", "Hunting",
         "Réseau", "Aruba (switches)", "Linux (serveurs)", "FortiClient EMS",
         "VPN & Exposition", "Sources externes", "WAF BunkerWeb", "Cartographie",
         "vSphere", "Sauvegardes", "Certificats",
         "Vulnérabilités", "Identité", "Investigation"]
pages.sort(key=lambda p: ORDER.index(p["title"]) if p["title"] in ORDER else 999)
missing = [p["title"] for p in pages if p["title"] not in ORDER]
if missing:
    print("    [!] pages hors ORDER (mises a la fin):", missing)
build("OMNI - SOC", pages)
PY

echo
echo "=== 14-graylog-dashboards.sh termine. Console : https://${SIEM_FQDN} -> Dashboards -> OMNI - SOC ==="
