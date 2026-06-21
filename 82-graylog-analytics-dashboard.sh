#!/usr/bin/env bash
# ==============================================================================
# 81-graylog-analytics-dashboard.sh - Dashboard AUTONOME "OMNI - Analytics"
#   Surface les signaux ANALYTICS deja produits dans omni-interne (stream
#   "OMNI - Interne SIEM") par les robots ML/UEBA/SLA/sante :
#     - ml_anomaly  : anomalie non-supervisee (IsolationForest) par entite -> ml_score 0-100
#     - ueba_score  : risque comportemental par entite (+ ueba_geo : impossible travel)
#     - collecte_sla: couverture % du parc (summary) + hotes GO-DARK (go_dark)
#     - siem_health : auto-supervision des robots (summary : health_ok/fail/total)
#     - BRUIT D'ALERTES : top alert_tag par volume (reperage des FAUX POSITIFS)
#
#   100% ADDITIF (vues en lecture seule). Ne TOUCHE PAS "OMNI - SOC" (14-) :
#   c'est un dashboard SEPARE, idempotent par suppression/recreation au TITRE
#   "OMNI - Analytics" (comme 14- pour "OMNI - SOC" : les IDs changent a chaque
#   execution -> refaire le favori navigateur le cas echeant).
#
#   Idiome 100% repris de 14-graylog-dashboards.sh (memes helpers
#   st_pivot/st_messages/widget/build, meme enveloppe post_entity DASHBOARD).
#   Reutilise lib-graylog.sh seulement pour resoudre l'ID de stream (get_stream_id).
#
#   MESURES TERRAIN (sonde omni-interne, 2026-06-22) :
#     event_source: ueba_score=2113, collecte_sla=188 (summary=4/go_dark=184),
#       ml_anomaly=120 (account=60/host=60), ueba_geo=35, siem_health=6 (summary).
#     SLA latest: couverture 51.6%, 49/95 actifs, 46 go-dark. Robots: 18/18 OK.
#     Bruit (alert_tag, 11 streams detection, 24h): 13 tags / 1603 evts ; top
#       vsphere_auth_fail=991, malware_domain=287, source_silent=96, fortigate_utm=92.
#   NB: siem_health n'a QUE des docs summary (pas de job_fail/health_job dans les
#   donnees actuelles) -> l'onglet sante s'appuie sur health_ok/fail/total (peuples).
#
# Prerequis : Graylog joignable (10/04), stream "OMNI - Interne SIEM" (21),
#   et au moins une passe des robots 77 (ML) / 40 (UEBA) / 39 (SLA) / 46-61 (sante).
# ==============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

# Resolution de l'ID du stream interne via le helper de la lib (lecture seule).
INT_ID="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${INT_ID}" ]] || die "stream 'OMNI - Interne SIEM' introuvable (lancer 21/77/40)."
ok "stream interne : OMNI - Interne SIEM [${INT_ID}]"

export GRAYLOG_ADMIN_PASS SIEM_FQDN INT_ID

python3 - <<'PY'
import json, os, ssl, uuid, base64, urllib.request

API = f"https://{os.environ['SIEM_FQDN']}:9000/api"
CTX = ssl.create_default_context(cafile="/etc/graylog/certs/omnitech-rootca.crt")
AUTH = base64.b64encode(f"admin:{os.environ['GRAYLOG_ADMIN_PASS']}".encode()).decode()
INT = os.environ["INT_ID"]   # stream "OMNI - Interne SIEM" (resolu en bash)

def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Basic {AUTH}", "Content-Type": "application/json",
                 "X-Requested-By": "81-analytics-dashboard"})
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

# ---------------------------------------------------------------- suppression
# Idempotence : on supprime le(s) dashboard(s) au meme titre avant de recreer.
TITLE = "OMNI - Analytics"
views = api("GET", "/views?page=1&per_page=200&query=")
for v in (views.get("views") or views.get("elements") or []):
    if v.get("title") == TITLE:
        api("DELETE", f"/views/{v['id']}")
        print(f"    [-] ancien dashboard supprime : {v['title']} ({v['id']})")

# ------------------------------------------------------------------- helpers
# (repris a l'IDENTIQUE de 14-graylog-dashboards.sh : meme generateur)
def _series(w):
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
    vc = None
    if w["viz"] == "bar":
        vc = {"barmode": w.get("barmode", "stack"), "axis_type": "linear"}
    elif w["viz"] == "area":
        vc = {"interpolation": "linear"}
    elif w["viz"] == "heatmap":
        vc = {"color_scale": "Viridis", "reverse_scale": False, "auto_scale": True,
              "z_min": None, "z_max": None, "use_smallest_as_default": False, "default_value": None}
    elif w["viz"] == "numeric":
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
    search = post_entity("/views/search", {"queries": queries, "parameters": []})
    sid = search.get("id")
    if not sid:
        print("    [!] search REFUSE:", str(search)[:300]); return
    view = post_entity("/views", {"type": "DASHBOARD", "title": title, "summary": "",
        "description": "Provisionne par 81-graylog-analytics-dashboard.sh", "search_id": sid,
        "properties": [], "state": state})
    vid = view.get("id")
    print(f"    [+] dashboard '{title}' ({vid}) - {len(pages)} onglets" if vid
          else f"    [!] view REFUSEE: {str(view)[:300]}")

# ------------------------------------------------------------- raccourcis viz
def KPI(t, q, col, row=1, **kw): return dict(title=t, q=q, viz="numeric", pos=(col, row, 3, 2), **kw)
def W(t, q, viz, col, row, w=4, h=4, **kw): return dict(title=t, q=q, viz=viz, pos=(col, row, w, h), **kw)
D7, D30 = 604800, 2592000   # fenetres elargies pour signaux rares
SLA_R = 7200                # SLA/go-dark : lire le DERNIER passage horaire (latest)

# --- Code-couleur conditionnel (highlighting) : sous-ensemble analytics ------
RED, ORANGE, YELLOW = "#d64550", "#e09f3e", "#e6c200"
def _hl(field, cond, value, color):
    return {"field": field, "value": value, "condition": cond,
            "color": {"type": "static", "color": color}}
COMMON_HL = [
  # Score ML (ORANGE avant ROUGE : le rouge >=80 doit l'emporter)
  _hl("ml_score", "greater_equal", 60, ORANGE), _hl("ml_score", "greater_equal", 80, RED),
  # Score UEBA
  _hl("ueba_score", "greater_equal", 40, ORANGE), _hl("ueba_score", "greater_equal", 70, RED),
  # Go-dark : plus c'est long, plus c'est grave
  _hl("hours_silent", "greater_equal", 26, ORANGE), _hl("hours_silent", "greater_equal", 72, RED),
  # Couverture collecte : sous 90% orange, sous 70% rouge (less_equal)
  _hl("sla_coverage_pct", "less_equal", 90, ORANGE), _hl("sla_coverage_pct", "less_equal", 70, RED),
  # Robots en panne
  _hl("health_fail", "greater_equal", 1, RED),
  # Severite / tags analytics notables
  _hl("risk_severity", "equal", "eleve", ORANGE), _hl("risk_severity", "equal", "critique", RED),
  _hl("alert_tag", "equal", "host_go_dark", ORANGE),
  _hl("alert_tag", "equal", "impossible_travel", RED),
  _hl("alert_tag", "equal", "ml_anomaly", ORANGE),
]

# Streams de DETECTION (hors interne) pour l'onglet "Bruit d'alertes" : on veut le
# volume d'alert_tag la ou les detections naissent. Resolus via l'API (lecture).
def S(*titles):
    alls = {s["title"]: s["id"] for s in api("GET", "/streams").get("streams", [])}
    return [alls[t] for t in titles if t in alls]
DET = S("OMNI - Windows Security", "OMNI - Sysmon", "OMNI - Windows autres",
        "OMNI - FortiGate", "OMNI - M365", "OMNI - vSphere",
        "OMNI - ESET", "OMNI - BunkerWeb", "OMNI - Vaultwarden")

# ============================================================ definition tabs
pages = [
 # ----- ONGLET 1 : Vue d'ensemble analytics ---------------------------------
 {"title": "Vue d'ensemble", "streams": [INT], "page_range": 86400, "widgets": [
   KPI("Couverture collecte (%)", "event_source:collecte_sla AND sla_type:summary", 1,
       metrics=[("latest", "sla_coverage_pct", "%")], range=SLA_R, dir="HIGHER",
       desc="Part des hotes GERES (vus <14j) ayant emis dans les 24h. Dernier passage du robot SLA (39)."),
   KPI("Hotes GO-DARK", "event_source:collecte_sla AND sla_type:summary", 4,
       metrics=[("latest", "sla_go_dark", "Hotes")], range=SLA_R, dir="LOWER",
       desc="Hotes geres silencieux >26h (angle mort : agent arrete / poste HS / compromission silencieuse)."),
   KPI("Robots d'analyse OK", "event_source:siem_health AND health_type:summary", 7,
       metrics=[("latest", "health_ok", "OK")], range=86400, dir="HIGHER",
       desc="Robots d'analyse (UEBA/NDR/ML/incidents...) en bon etat au dernier controle (46/61)."),
   KPI("Robots en PANNE", "event_source:siem_health AND health_type:summary", 10,
       metrics=[("latest", "health_fail", "Panne")], range=86400, dir="LOWER",
       desc="Robots en echec : >0 = la detection est partiellement aveugle, a corriger vite."),
   KPI("Entites ML anormales (>=80)", "event_source:ml_anomaly AND ml_score:>=80", 1, 3,
       card="entity", range=D7, dir="LOWER",
       desc="Entites (compte/hote) au score d'anomalie ML >=80/100 sur 7j (IsolationForest, oms-ml/77). Onglet 'ML anomalies'."),
   KPI("Entites UEBA a risque (>=70)", "event_source:ueba_score AND ueba_score:>=70", 4, 3,
       card="ueba_entity", range=SLA_R, dir="LOWER",
       desc="Entites au score comportemental UEBA >=70/100 (dernier passage). Onglet 'UEBA'."),
   KPI("Impossible travel (7j)", "event_source:ueba_geo", 7, 3, card="user", range=D7, dir="LOWER",
       desc="Comptes avec deplacement geographique impossible (T1078) detecte sur 7j. Onglet 'UEBA'."),
   KPI("Types d'alertes actifs (24h)", "_exists_:alert_tag", 10, 3, card="alert_tag", range=86400,
       desc="Diversite des tags d'alerte vus dans le flux interne sur 24h. Onglet 'Bruit d'alertes' pour le detail FP."),
   W("Telemetrie analytics par robot (24h)", "_exists_:event_source", "area", 1, 5, 12, 4,
     time=True, columns="event_source", col_limit=10, events=True,
     desc="Volume des signaux analytics par robot dans le temps. Un plat soudain a 0 = robot muet (cf. onglet sante)."),
   W("Repartition des signaux analytics (24h)", "_exists_:event_source", "bar", 1, 9, 6, 4,
     pivot="event_source", limit=12,
     desc="Quel robot produit le plus de signaux. ueba_score domine (scoring de masse) ; ml_anomaly/collecte_sla plus cibles."),
   W("Dernier passage par robot (fraicheur)", "_exists_:event_source", "table", 7, 9, 6, 4,
     pivot="event_source", limit=12, metrics=[("max", "timestamp", "Dernier signal"), "count"],
     sort_on="max(timestamp)", sort_asc=True,
     desc="Horodatage du dernier signal par robot, du plus ANCIEN en haut. Un robot dont le dernier signal est vieux = timer mort (a recouper avec siem_health)."),
 ]},
 # ----- ONGLET 2 : ML anomalies (oms-ml / 77) -------------------------------
 {"title": "ML anomalies", "streams": [INT], "query_string": "event_source:ml_anomaly",
  "page_range": D7, "widgets": [
   KPI("Entites scorees (7j)", "event_source:ml_anomaly", 1, card="entity", range=D7,
       desc="Entites distinctes ayant recu un score d'anomalie ML sur 7j (IsolationForest non-supervise)."),
   KPI("Anormales >=80", "event_source:ml_anomaly AND ml_score:>=80", 4, card="entity", range=D7, dir="LOWER",
       desc="Entites au score ML >=80/100 = forte deviation vs la population. File de revue prioritaire."),
   KPI("Comptes vs Hotes", "event_source:ml_anomaly", 7, card="entity_type", range=D7,
       desc="Nb de TYPES d'entites scorees (compte / hote). Le scoring tourne sur les deux dimensions."),
   KPI("Score ML max (7j)", "event_source:ml_anomaly", 10, metrics=[("max", "ml_score", "Max")], range=D7, dir="LOWER",
       desc="Score d'anomalie le plus eleve observe sur 7j (0-100)."),
   W("Top entites par score d'anomalie ML (7j)", "event_source:ml_anomaly", "table", 1, 3, 8, 5,
     pivot="entity", limit=25, range=D7, sort_on="max(ml_score)",
     metrics=[("max", "ml_score", "Score ML"), ("latest", "entity_type", "Type"), ("latest", "ml_reason", "Raison"), "count"],
     desc="LE classement ML : entites les plus anormales d'abord (max ml_score). 'Raison' = facteurs dominants (z-scores). A trier du haut."),
   W("Anomalies : compte vs hote", "event_source:ml_anomaly", "pie", 9, 3, 4, 5, pivot="entity_type", range=D7,
     desc="Repartition des entites anormales entre comptes et hotes."),
   W("Distribution des scores ML (7j)", "event_source:ml_anomaly", "bar", 1, 8, 6, 4,
     pivot="ml_score", limit=20, range=D7, sort_on="ml_score", sort_asc=True,
     desc="Histogramme des scores : la queue droite (scores eleves) = les entites a traiter en priorite."),
   W("Modeles ML actifs", "event_source:ml_anomaly", "table", 7, 8, 6, 4,
     pivot="ml_model", range=D7, metrics=["count", ("card", "entity", "Entites")],
     desc="Quel(s) modele(s) produisent les scores (isolation_forest). Verifie que la couche ML tourne bien."),
   W("Detail des anomalies ML + raison (7j)", "event_source:ml_anomaly", "messages", 1, 12, 12, 6,
     limit=60, range=D7, show_message=True,
     fields=["timestamp", "ml_score", "entity", "entity_type", "ml_reason", "ml_model", "risk_score"],
     desc="Chaque entite anormale, son score et la RAISON (facteurs deviants). Point de depart de l'investigation."),
 ]},
 # ----- ONGLET 3 : UEBA (40 / ueba_geo) -------------------------------------
 {"title": "UEBA", "streams": [INT], "query_string": "event_source:ueba_score OR event_source:ueba_geo",
  "page_range": 86400, "widgets": [
   KPI("Entites scorees (dernier passage)", "event_source:ueba_score", 1, card="ueba_entity", range=SLA_R,
       desc="Entites distinctes ayant un score comportemental UEBA au dernier cycle."),
   KPI("A risque (>=70)", "event_source:ueba_score AND ueba_score:>=70", 4, card="ueba_entity", range=SLA_R, dir="LOWER",
       desc="Entites au score UEBA >=70/100 (detections + auth + beaconing + geo fusionnes). Priorite de triage."),
   KPI("Score UEBA max", "event_source:ueba_score", 7, metrics=[("max", "ueba_score", "Max")], range=SLA_R, dir="LOWER",
       desc="Score comportemental le plus eleve au dernier passage (0-100)."),
   KPI("Impossible travel (7j)", "event_source:ueba_geo", 10, card="user", range=D7, dir="LOWER",
       desc="Comptes avec un saut geographique impossible (vitesse > seuil) sur 7j = identifiants partages/voles (T1078)."),
   W("Top entites par score UEBA (dernier passage)", "event_source:ueba_score", "table", 1, 3, 8, 5,
     pivot="ueba_entity", limit=25, range=SLA_R, sort_on="max(ueba_score)",
     metrics=[("max", "ueba_score", "Score"), ("latest", "ueba_top_factor", "Facteur dominant"), ("latest", "entity_type", "Type")],
     desc="Classement UEBA : entites les plus a risque d'abord. 'Facteur dominant' = ce qui tire le score (detections/beacon/authfail/geo)."),
   W("Risque par DRIVER (facteur dominant)", "event_source:ueba_score", "pie", 9, 3, 4, 5,
     pivot="ueba_top_factor", range=SLA_R,
     desc="Quel facteur explique le plus de scores eleves (detections, beaconing, echecs d'auth, geo). Aide a comprendre la nature du risque."),
   W("Impossible travel - detail (7j)", "event_source:ueba_geo", "messages", 1, 8, 12, 5,
     limit=40, range=D7, show_message=True,
     fields=["timestamp", "user", "geo_from", "geo_to", "geo_km", "geo_hours", "geo_speed_kmh", "risk_severity", "mitre_technique"],
     desc="Chaque saut geographique impossible : compte, trajet, distance/vitesse. Vitesse aberrante = sessions concurrentes depuis 2 lieux."),
   W("Scores UEBA : entite x heure (heatmap, 7j)", "event_source:ueba_score", "heatmap", 1, 13, 12, 5,
     pivot="ueba_entity", coltime=True, limit=25, range=D7,
     desc="Lignes = entite, colonnes = heure. Une ligne chaude persistante = entite au risque eleve recurrent."),
 ]},
 # ----- ONGLET 4 : Couverture & sante (collecte_sla + siem_health) ----------
 {"title": "Couverture & sante", "streams": [INT], "page_range": 86400, "widgets": [
   KPI("Couverture collecte (%)", "event_source:collecte_sla AND sla_type:summary", 1,
       metrics=[("latest", "sla_coverage_pct", "%")], range=SLA_R, dir="HIGHER",
       desc="Part des hotes geres (vus <14j) ayant emis dans les 24h. 100% = parc entierement supervise (sans CMDB, baseline 14j)."),
   KPI("Hotes geres", "event_source:collecte_sla AND sla_type:summary", 4,
       metrics=[("latest", "sla_expected", "Hotes")], range=SLA_R,
       desc="Nombre d'hotes consideres actifs/geres (>=1 log dans les 14 derniers jours)."),
   KPI("Actifs (24h)", "event_source:collecte_sla AND sla_type:summary", 7,
       metrics=[("latest", "sla_active_24h", "Hotes")], range=SLA_R,
       desc="Hotes geres ayant emis dans les 24h."),
   KPI("GO-DARK (>26h)", "event_source:collecte_sla AND sla_type:summary", 10,
       metrics=[("latest", "sla_go_dark", "Hotes")], range=SLA_R, dir="LOWER",
       desc="Hotes geres SILENCIEUX depuis >26h. A traiter en priorite : c'est un angle mort de detection."),
   W("Couverture collecte dans le temps (%)", "event_source:collecte_sla AND sla_type:summary", "area", 1, 3, 8, 3,
     time=True, metrics=[("max", "sla_coverage_pct", "Couverture %")], events=True,
     desc="Evolution de la couverture. Une chute = vague d'hotes muets (panne reseau, GPO Winlogbeat, etc.)."),
   W("Hotes geres vs actifs (24h)", "event_source:collecte_sla AND sla_type:summary", "table", 9, 3, 4, 3,
     metrics=[("latest", "sla_expected", "Geres"), ("latest", "sla_active_24h", "Actifs"), ("latest", "sla_go_dark", "Go-dark"), ("latest", "sla_decommissioned", "Decommis.")],
     range=SLA_R, desc="Photo du parc au dernier passage."),
   W("Hotes GO-DARK - collecte interrompue (detail)", "event_source:collecte_sla AND sla_type:go_dark", "table", 1, 6, 7, 5,
     pivot="dark_host", limit=50, range=SLA_R, sort_on="max(hours_silent)",
     metrics=[("max", "hours_silent", "Heures muettes"), ("max", "host_volume_30d", "Vol. 30j")],
     desc="Hotes actuellement muets (dernier passage horaire), tries du plus longtemps muet en haut. Vol. 30j = importance de l'angle mort."),
   W("GO-DARK - qui, depuis quand (dernier passage)", "event_source:collecte_sla AND sla_type:go_dark", "messages", 8, 6, 5, 5,
     range=SLA_R, fields=["timestamp", "dark_host", "last_seen", "hours_silent", "host_volume_30d"],
     desc="Detail : chaque hote muet, son dernier log et son anciennete de silence."),
   # --- Auto-supervision des robots (siem_health : summary uniquement) -------
   KPI("Robots OK", "event_source:siem_health AND health_type:summary", 1, 12,
       metrics=[("latest", "health_ok", "OK")], range=86400, dir="HIGHER",
       desc="Robots d'analyse en bon etat au dernier controle d'auto-supervision (46/61)."),
   KPI("Robots en PANNE", "event_source:siem_health AND health_type:summary", 4, 12,
       metrics=[("latest", "health_fail", "Panne")], range=86400, dir="LOWER",
       desc="Robots en echec ou timer mort. 0 = tout va bien ; >0 = detection partiellement aveugle."),
   KPI("Robots surveilles (total)", "event_source:siem_health AND health_type:summary", 7, 12,
       metrics=[("latest", "health_total", "Total")], range=86400,
       desc="Nombre total de robots sous auto-supervision."),
   W("Sante des robots dans le temps (OK vs panne)", "event_source:siem_health AND health_type:summary", "area", 1, 14, 12, 4,
     time=True, metrics=[("max", "health_ok", "OK"), ("max", "health_fail", "Panne")], events=True,
     desc="Suivi OK/panne au fil des controles. Tout decrochage de 'OK' ou pic de 'Panne' = un robot d'analyse a relancer (cf. 46/61)."),
 ]},
 # ----- ONGLET 5 : Bruit d'alertes / FP (reperage faux positifs) ------------
 # Streams de DETECTION (pas interne) : le volume d'alert_tag y est representatif.
 {"title": "Bruit d'alertes / FP", "streams": DET, "query_string": "_exists_:alert_tag",
  "page_range": 86400, "widgets": [
   KPI("Evenements tagues (24h)", "_exists_:alert_tag", 1, dir="LOWER",
       desc="Volume total d'evenements portant un tag d'alerte sur 24h. Un pic global = bruit ou vague d'activite."),
   KPI("Types de tags distincts", "_exists_:alert_tag", 4, card="alert_tag",
       desc="Diversite des tags. Beaucoup de types = surface large ; peu de types tres volumineux = candidats FP."),
   KPI("Tag le plus bruyant (volume)", "_exists_:alert_tag", 7, metrics=[("max", "risk_score", "Risque max")], dir="LOWER",
       desc="Risque max parmi les evenements tagues : permet de distinguer le bruit a faible risque (FP probable) du signal grave."),
   KPI("Hotes concernes", "_exists_:alert_tag", 10, card="host", dir="LOWER",
       desc="Hotes distincts touches. Un tag enorme concentre sur 1-2 hotes = mauvais reglage local a allowlister."),
   W("Top alert_tag par VOLUME (FP candidats)", "_exists_:alert_tag", "bar", 1, 3, 6, 5,
     pivot="alert_tag", limit=25, sort_on="count()",
     desc="Les tags les plus VOLUMINEUX d'abord. En tete on trouve typiquement les FAUX POSITIFS (ex. vsphere_auth_fail, malware_domain) a regler/tuner (cf. 78-detection-tuning)."),
   W("Tags : volume / hotes / risque", "_exists_:alert_tag", "table", 7, 3, 6, 5,
     pivot="alert_tag", limit=25, sort_on="count()",
     metrics=["count", ("card", "host", "Hotes"), ("card", "user", "Comptes"), ("max", "risk_score", "Risque max")],
     desc="Pour chaque tag : volume, dispersion (hotes/comptes) et risque max. VOLUME ELEVE + RISQUE FAIBLE + PEU D'HOTES = FP a tuner en priorite."),
   W("Bruit dans le temps, par tag (24h)", "_exists_:alert_tag", "area", 1, 8, 12, 3,
     time=True, columns="alert_tag", col_limit=10, events=True,
     desc="Evolution du volume par tag. Un tag qui explose soudainement = nouvelle source de bruit (ou debut d'attaque) a qualifier."),
   W("Source du bruit : tag x hote (heatmap, 24h)", "_exists_:alert_tag", "heatmap", 1, 11, 12, 5,
     pivot="alert_tag", columns="host", limit=25, col_limit=25,
     desc="Lignes = tag, colonnes = hote. Une CASE tres chaude = un tag genere massivement par UN hote precis = candidat allowlist/tuning cible."),
   W("Detail des evenements tagues (echantillon)", "_exists_:alert_tag", "messages", 1, 16, 12, 5,
     limit=60, fields=["timestamp", "alert_tag", "risk_score", "risk_severity", "host", "user", "event_source", "mitre_technique"],
     desc="Echantillon brut pour juger sur piece si un tag bruyant est un vrai signal ou un FP a regler."),
 ]},
]

build("OMNI - Analytics", pages)
PY

echo
echo "=== 81-graylog-analytics-dashboard.sh termine."
echo "    Console : https://${SIEM_FQDN} -> Dashboards -> 'OMNI - Analytics' (5 onglets)."
echo "    Onglets : Vue d'ensemble | ML anomalies | UEBA | Couverture & sante | Bruit d'alertes / FP"