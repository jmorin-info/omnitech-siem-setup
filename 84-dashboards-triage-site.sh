#!/usr/bin/env bash
# =============================================================================
# 84-dashboards-triage-site.sh - Dashboard "OMNI - Triage & Multi-site"
#   Onglet 1 "Filtrage triage" : ce que omni-alert-triage laisse passer vs filtre
#     (mails envoyes, alertes droppees, dedup, par tier, top filtrees/mailees,
#      score). Source : event_source:alert_triage.
#   Onglet 2 "Multi-site FortiGate" : repartition BDX/IV/LC (volume, denis, VPN,
#     UTM) via le champ fortigate_site (cf 97-multisite-soar.sh).
#
#   Builder Python repris a l'IDENTIQUE de 82-graylog-analytics-dashboard.sh.
#   Idempotent (supprime le dashboard au meme titre avant recreation).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

TRIAGE_STREAM="$(api_get '/streams?per_page=200' | jq -r '.streams[]|select(.title=="OMNI - M365")|.id')"
# fallback : le stream qui contient effectivement les events alert_triage
[[ -n "$TRIAGE_STREAM" ]] || TRIAGE_STREAM="6a2ac4a165bc77613c83b22a"
FORTI_STREAM="$(get_stream_id 'OMNI - FortiGate')"
[[ -n "$FORTI_STREAM" ]] || die "stream FortiGate introuvable"
ok "streams : triage=${TRIAGE_STREAM} forti=${FORTI_STREAM}"

export GRAYLOG_ADMIN_PASS SIEM_FQDN TRIAGE_STREAM FORTI_STREAM

python3 - <<'PY'
import json, os, ssl, uuid, base64, urllib.request
API = f"https://{os.environ['SIEM_FQDN']}:9000/api"
CTX = ssl.create_default_context(cafile="/etc/graylog/certs/omnitech-rootca.crt")
AUTH = base64.b64encode(f"admin:{os.environ['GRAYLOG_ADMIN_PASS']}".encode()).decode()
TRI = os.environ["TRIAGE_STREAM"]; FGT = os.environ["FORTI_STREAM"]

def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Basic {AUTH}", "Content-Type": "application/json",
                 "X-Requested-By": "84-dash"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            d = r.read(); return json.loads(d) if d else {}
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_body": e.read().decode()[:400]}

def post_entity(path, body):
    r = api("POST", path, body)
    if isinstance(r, dict) and "entity cannot be null" in str(r.get("_body", "")):
        r = api("POST", path, {"entity": body, "share_request": {"selected_grantee_capabilities": {}}})
    return r

TITLE = "OMNI - Triage & Multi-site"
for v in (api("GET", "/views?page=1&per_page=200&query=").get("views") or []):
    if v.get("title") == TITLE:
        api("DELETE", f"/views/{v['id']}"); print(f"    [-] ancien supprime ({v['id']})")

# ---- builder (repris de 82) ----
def _series(w):
    specs = w.get("metrics")
    if specs:
        st, wd = [], []
        for sp in specs:
            if sp in ("count", "count()"):
                st.append({"id": "count()", "type": "count"}); wd.append({"config": {"name": None}, "function": "count()"})
            else:
                fn, field = sp[0], sp[1]; label = sp[2] if len(sp) > 2 else None; fid = f"{fn}({field})"
                st.append({"id": fid, "type": fn, "field": field}); wd.append({"config": {"name": label}, "function": fid})
        return st, wd
    if w.get("card"):
        fid = f"card({w['card']})"
        return ([{"id": fid, "type": "card", "field": w["card"]}], [{"config": {"name": w.get("name")}, "function": fid}])
    return ([{"id": "count()", "type": "count"}], [{"config": {"name": w.get("name")}, "function": "count()"}])

def _tr(w): return {"type": "relative", "range": w["range"]} if w.get("range") else None

def st_pivot(w):
    st_series, _ = _series(w); rg, cg = [], []
    if w.get("time"): rg = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}]
    elif w.get("pivot"):
        rg = [{"type": "values", "fields": [w["pivot"]], "limit": w.get("limit", 10)}]
        if w.get("pivot2"): rg.append({"type": "values", "fields": [w["pivot2"]], "limit": w.get("limit2", 5)})
    if w.get("columns"): cg = [{"type": "values", "fields": [w["columns"]], "limit": w.get("col_limit", 5)}]
    sort = [{"type": "series", "field": w.get("sort_on", st_series[0]["id"]), "direction": "Descending"}] if (w.get("pivot") and not w.get("time")) else []
    return {"id": w["stid"], "name": "chart", "type": "pivot",
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")}, "timerange": _tr(w),
            "streams": [], "filters": [], "row_groups": rg, "column_groups": cg, "series": st_series, "sort": sort, "rollup": True}

def widget(w):
    _, wd_series = _series(w); rp, cp = [], []
    if w.get("time"): rp = [{"type": "time", "fields": ["timestamp"], "config": {"interval": {"type": "auto", "scaling": 1}}}]
    elif w.get("pivot"):
        rp = [{"type": "values", "fields": [w["pivot"]], "config": {"limit": w.get("limit", 10), "skip_empty_values": False}}]
        if w.get("pivot2"): rp.append({"type": "values", "fields": [w["pivot2"]], "config": {"limit": w.get("limit2", 5), "skip_empty_values": False}})
    if w.get("columns"): cp = [{"type": "values", "fields": [w["columns"]], "config": {"limit": w.get("col_limit", 5), "skip_empty_values": False}}]
    sort = [{"type": "series", "field": w.get("sort_on", wd_series[0]["function"]), "direction": "Descending"}] if (w.get("pivot") and not w.get("time")) else []
    vc = None
    if w["viz"] == "bar": vc = {"barmode": w.get("barmode", "stack"), "axis_type": "linear"}
    elif w["viz"] == "numeric": vc = {"trend": True, "trend_preference": w.get("dir", "NEUTRAL")}
    return {"id": w["wid"], "type": "AGGREGATION", "filter": None, "timerange": _tr(w),
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
            "streams": [], "filters": [], "description": w.get("desc"),
            "config": {"visualization": w["viz"], "event_annotation": False, "row_pivots": rp, "column_pivots": cp,
                       "series": wd_series, "sort": sort, "rollup": True, "formatting_settings": None, "visualization_config": vc}}

def build(title, pages):
    queries, state = [], {}
    for p in pages:
        qid = str(uuid.uuid4())
        for w in p["widgets"]: w["wid"], w["stid"] = str(uuid.uuid4()), str(uuid.uuid4())
        queries.append({"id": qid, "query": {"type": "elasticsearch", "query_string": ""},
            "timerange": {"type": "relative", "range": p.get("page_range", 86400)},
            "filter": {"type": "or", "filters": [{"type": "stream", "id": s} for s in p["streams"]]},
            "filters": [], "search_types": [st_pivot(w) for w in p["widgets"]]})
        state[qid] = {"selected_fields": None, "static_message_list_id": None,
            "titles": {"tab": {"title": p["title"]}, "widget": {w["wid"]: w["title"] for w in p["widgets"]}},
            "widgets": [widget(w) for w in p["widgets"]],
            "widget_mapping": {w["wid"]: [w["stid"]] for w in p["widgets"]},
            "positions": {w["wid"]: {"col": w["pos"][0], "row": w["pos"][1], "width": w["pos"][2], "height": w["pos"][3]} for w in p["widgets"]},
            "formatting": {"highlighting": []}, "display_mode_settings": {"positions": {}}}
    search = post_entity("/views/search", {"queries": queries, "parameters": []})
    sid = search.get("id")
    if not sid: print("    [!] search REFUSE:", str(search)[:300]); return
    view = post_entity("/views", {"type": "DASHBOARD", "title": title, "summary": "",
        "description": "Provisionne par 84-dashboards-triage-site.sh", "search_id": sid, "properties": [], "state": state})
    print(f"    [+] dashboard '{title}' cree ({view.get('id')})" if view.get("id") else f"    [!] view REFUSEE: {str(view)[:300]}")

def KPI(t, q, col, **kw): return dict(title=t, q=q, viz="numeric", pos=(col, 1, 3, 2), **kw)
def W(t, q, viz, col, row, w=4, h=4, **kw): return dict(title=t, q=q, viz=viz, pos=(col, row, w, h), **kw)

TRIAGE = "event_source:alert_triage"
pages = [
 {"title": "Filtrage triage", "streams": [TRI], "page_range": 604800, "widgets": [
   KPI("Mails ENVOYES (7j)", f"{TRIAGE} AND triage_decision:mail", 1, dir="NEUTRAL",
       desc="Alertes jugees critiques/pertinentes -> mail effectivement envoye."),
   KPI("Alertes FILTREES", f"{TRIAGE} AND triage_decision:drop", 4, dir="LOWER",
       desc="Bruit ecarte par le triage (n'a PAS genere de mail)."),
   KPI("Dedupliquees", f"{TRIAGE} AND triage_decision:dedup", 7, dir="NEUTRAL",
       desc="Mail evite car meme alerte+entite recente (anti-rafale)."),
   KPI("Echecs envoi", f"{TRIAGE} AND triage_decision:mail_echec", 10, dir="LOWER",
       desc="Mail decide mais SMTP en echec - a surveiller."),
   W("Decisions dans le temps", TRIAGE, "bar", 1, 3, 8, 4, time=True, columns="triage_decision",
     desc="Repartition mail/drop/dedup au fil du temps."),
   W("Par tier", TRIAGE, "bar", 9, 3, 4, 4, pivot="triage_tier", desc="CRITICAL/GRAY/NOISE."),
   W("Top alertes FILTREES (bruit)", f"{TRIAGE} AND triage_decision:drop", "table", 1, 7, 6, 5,
     pivot="alert_title", limit=15, desc="Ce que le triage etouffe le plus."),
   W("Top alertes MAILEES (recues)", f"{TRIAGE} AND triage_decision:mail", "table", 7, 7, 6, 5,
     pivot="alert_title", limit=15, desc="Ce qui arrive reellement en boite mail."),
 ]},
 {"title": "Multi-site FortiGate", "streams": [FGT], "page_range": 86400, "widgets": [
   W("Volume par site", "", "bar", 1, 1, 4, 4, pivot="fortigate_site", desc="BDX / IV / LC."),
   W("Activite par site dans le temps", "", "bar", 5, 1, 8, 4, time=True, columns="fortigate_site"),
   W("Denis par site", "action:deny OR action:blocked OR action:close", "table", 1, 5, 6, 5,
     pivot="fortigate_site", pivot2="src_ip", limit=4, limit2=10, desc="Top IP bloquees par site."),
   W("VPN par site", "subtype:vpn", "table", 7, 5, 6, 5, pivot="fortigate_site", pivot2="action", limit=4, limit2=8),
   W("UTM/IPS par site", "alert_tag:fortigate_utm", "bar", 1, 10, 6, 4, pivot="fortigate_site"),
   W("Top applications bloquees (tous sites)", "action:deny", "table", 7, 10, 6, 4, pivot="app", limit=15),
 ]},
]
build(TITLE, pages)
PY
echo "=== 84 termine : dashboard 'OMNI - Triage & Multi-site' (2 onglets). ==="
