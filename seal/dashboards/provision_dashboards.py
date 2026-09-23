#!/usr/bin/env python3
# =============================================================================
#  provision_dashboards.py - Dashboards SEAL -> Graylog (Views API, idempotent)
#  OMNITECH SECURITY - MISSION_SEAL_GRAYLOG Phase 6
#
#  Cree 3 dashboards (Views type DASHBOARD) via l'API Views/Search de Graylog
#  7.x (2 POST : /views/search puis /views). Idempotent : suppression par titre
#  puis recreation (l'API Views n'a pas d'update-in-place ; l'ID du dashboard
#  change donc a chaque run -> ne pas bookmarker l'URL, ouvrir par titre).
#
#  Widgets limites aux champs REELLEMENT peuples (cf DATA_READINESS.md §2) :
#  PAS de `site` (NULL) ni `identity_upn` (vide en QA). Cle porte = target_object_label.
#
#  Auth : GRAYLOG_API_TOKEN si present, sinon repli admin (GRAYLOG_ADMIN_PASS).
#  Usage : ./provision_dashboards.py            (dry-run : liste ce qui serait cree)
#          ./provision_dashboards.py --apply    (applique)
# =============================================================================
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.request
import uuid

API_URL = os.environ.get("GRAYLOG_API_URL", "https://bx-it-graylog-vm.omnitech.security:9000").rstrip("/")
BASE = API_URL if API_URL.endswith("/api") else API_URL + "/api"
CA = os.environ.get("GRAYLOG_API_CA", "/etc/graylog/certs/omnitech-rootca.crt")
UA = "omni-seal-dashboards"

# Streams SEAL (resolus par titre au runtime ; ces IDs = valeurs actuelles/fallback)
STREAM_TITLES = ["OMNI - SEAL Accès", "OMNI - SEAL Alarmes", "OMNI - SEAL Audit"]

APPLY = False


def _ctx() -> ssl.SSLContext:
    if os.environ.get("GRAYLOG_TLS_INSECURE") == "1":
        return ssl._create_unverified_context()  # noqa: S323
    if os.path.exists(CA):
        return ssl.create_default_context(cafile=CA)
    return ssl.create_default_context()


def _authz() -> str:
    tok = (os.environ.get("GRAYLOG_API_TOKEN") or "").strip()
    if tok:
        return "Basic " + base64.b64encode(f"{tok}:token".encode()).decode()
    pwd = os.environ.get("GRAYLOG_ADMIN_PASS", "")
    if not pwd:
        sys.exit("  [x] ni GRAYLOG_API_TOKEN ni GRAYLOG_ADMIN_PASS")
    return "Basic " + base64.b64encode(f"admin:{pwd}".encode()).decode()


_AUTH = None
_CTX = None


def api(method: str, path: str, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Authorization", _AUTH)
    req.add_header("Accept", "application/json")
    req.add_header("X-Requested-By", UA)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=30, context=_CTX) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"_error": e.code, "_body": e.read().decode()[:300]}


def post_entity(path, body):
    r = api("POST", path, body)
    if isinstance(r, dict) and "entity cannot be null" in str(r.get("_body", "")):
        r = api("POST", path, {"entity": body, "share_request": {"selected_grantee_capabilities": {}}})
    return r


# --- Builder (porte du pattern eprouve du depot : 84-dashboards-triage-site.sh) ---
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
    if w.get("columns"):
        cg = [{"type": "values", "fields": [w["columns"]], "limit": w.get("col_limit", 8)}]
    sort = ([{"type": "series", "field": w.get("sort_on", st_series[0]["id"]), "direction": "Descending"}]
            if (w.get("pivot") and not w.get("time")) else [])
    return {"id": w["stid"], "name": "chart", "type": "pivot",
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")}, "timerange": _tr(w),
            "streams": [], "filters": [], "row_groups": rg, "column_groups": cg,
            "series": st_series, "sort": sort, "rollup": True}


def st_messages(w):
    return {"id": w["stid"], "name": "messages", "type": "messages",
            "limit": w.get("limit", 20), "offset": 0,
            "sort": [{"field": "timestamp", "order": "DESC"}],
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
            "timerange": _tr(w), "streams": [], "filters": []}


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
        rp = [{"type": "values", "fields": [w["pivot"]], "config": {"limit": w.get("limit", 10), "skip_empty_values": False}}]
        if w.get("pivot2"):
            rp.append({"type": "values", "fields": [w["pivot2"]], "config": {"limit": w.get("limit2", 5), "skip_empty_values": False}})
    if w.get("columns"):
        cp = [{"type": "values", "fields": [w["columns"]], "config": {"limit": w.get("col_limit", 8), "skip_empty_values": False}}]
    sort = ([{"type": "series", "field": w.get("sort_on", wd_series[0]["function"]), "direction": "Descending"}]
            if (w.get("pivot") and not w.get("time")) else [])
    vc = None
    if w["viz"] == "bar":
        vc = {"barmode": w.get("barmode", "stack"), "axis_type": "linear"}
    elif w["viz"] == "numeric":
        vc = {"trend": True, "trend_preference": w.get("dir", "NEUTRAL")}
    return {"id": w["wid"], "type": "AGGREGATION", "filter": None, "timerange": _tr(w),
            "query": {"type": "elasticsearch", "query_string": w.get("q", "")},
            "streams": [], "filters": [], "description": w.get("desc"),
            "config": {"visualization": w["viz"], "event_annotation": False, "row_pivots": rp,
                       "column_pivots": cp, "series": wd_series, "sort": sort, "rollup": True,
                       "formatting_settings": None, "visualization_config": vc}}


def build(title, description, pages):
    queries, state = [], {}
    for p in pages:
        qid = str(uuid.uuid4())
        for w in p["widgets"]:
            w["wid"], w["stid"] = str(uuid.uuid4()), str(uuid.uuid4())
        queries.append({"id": qid, "query": {"type": "elasticsearch", "query_string": ""},
                        "timerange": {"type": "relative", "range": p.get("page_range", 86400)},
                        "filter": {"type": "or", "filters": [{"type": "stream", "id": s} for s in p["streams"]]},
                        "filters": [],
                        "search_types": [st_messages(w) if w["viz"] == "messages" else st_pivot(w)
                                         for w in p["widgets"]]})
        state[qid] = {"selected_fields": None, "static_message_list_id": None,
                      "titles": {"tab": {"title": p["title"]},
                                 "widget": {w["wid"]: w["title"] for w in p["widgets"]}},
                      "widgets": [widget(w) for w in p["widgets"]],
                      "widget_mapping": {w["wid"]: [w["stid"]] for w in p["widgets"]},
                      "positions": {w["wid"]: {"col": w["pos"][0], "row": w["pos"][1],
                                               "width": w["pos"][2], "height": w["pos"][3]} for w in p["widgets"]},
                      "formatting": {"highlighting": []}, "display_mode_settings": {"positions": {}}}
    if not APPLY:
        nb = sum(len(p["widgets"]) for p in pages)
        print(f"  [dry-run] creerait '{title}' ({len(pages)} page(s), {nb} widgets)")
        return
    search = post_entity("/views/search", {"queries": queries, "parameters": []})
    sid = search.get("id") if isinstance(search, dict) else None
    if not sid:
        print(f"  [x] search REFUSE pour '{title}': {str(search)[:200]}")
        return
    view = post_entity("/views", {"type": "DASHBOARD", "title": title, "summary": "",
                                  "description": description, "search_id": sid,
                                  "properties": [], "state": state})
    vid = view.get("id") if isinstance(view, dict) else None
    print(f"  [+] dashboard '{title}' cree ({vid})" if vid else f"  [x] view REFUSE '{title}': {str(view)[:200]}")


def resolve_streams():
    data = api("GET", "/streams") or {}
    by_title = {s["title"]: s["id"] for s in data.get("streams", [])}
    ids = [by_title.get(t) for t in STREAM_TITLES]
    if not all(ids):
        sys.exit(f"  [x] streams SEAL introuvables : {list(zip(STREAM_TITLES, ids))}")
    return ids  # [access, alarm, audit]


def delete_by_title(title):
    data = api("GET", "/views?page=1&per_page=500&query=")
    items = (data.get("views") or data.get("elements") or []) if isinstance(data, dict) else []
    for v in items:
        if v.get("title") == title:
            if APPLY:
                api("DELETE", f"/views/{v['id']}")
                print(f"  [=] ancien '{title}' supprime ({v['id']})")


def main():
    global APPLY, _AUTH, _CTX
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    APPLY = ap.parse_args().apply
    _AUTH, _CTX = _authz(), _ctx()

    print("=" * 68)
    print(f" Dashboards SEAL -> Graylog  [{'APPLY' if APPLY else 'DRY-RUN'}]")
    print("=" * 68)
    acc, alm, aud = resolve_streams()
    ALL = [acc, alm, aud]
    EVENTS_STREAM = "000000000000000000000002"   # "All events" (alertes declenchees)
    SEAL_ALERTS_Q = f"source_streams:({acc} OR {alm} OR {aud})"

    F_ACCESS = ["timestamp", "event_outcome", "badge_number", "identity_matricule", "target_object_label", "event_action"]
    F_ALARM = ["timestamp", "event_action", "severity_num", "target_object_label", "event_outcome", "EVEN_LIFESTATUS"]
    F_AUDIT = ["timestamp", "actor_usercode", "actor_login", "event_action", "seal_source_table", "operation_channel", "src_ip"]
    DROITS = ("event_domain:hypervisor_audit AND seal_source_table:(AccessControlPermissionMovements OR "
              "AccountsMovements OR AccountRolesMovements OR ProfilesMovements OR ProfileRoleMovements OR "
              "ProfileAuthorizedObjectsMovements OR TagMovements OR TagGroupMembersMovements)")

    # ---- Vue A : SOC operationnel (24h) -- temps reel + detail evenements ----
    soc = ("SEAL - SOC operationnel",
           "Temps reel exploitant : refus, alarmes, echecs console + detail des evenements bruts.",
           [{"title": "SOC (24h)", "page_range": 86400, "streams": ALL, "widgets": [
               {"title": "Refus d'acces (24h)", "viz": "numeric", "q": "event_domain:access AND event_outcome:deny", "dir": "LOWER", "pos": (1, 1, 3, 2)},
               {"title": "Echecs console (24h)", "viz": "numeric", "q": "event_domain:hypervisor_audit AND event_action:ConnectionFailure", "dir": "LOWER", "pos": (4, 1, 3, 2)},
               {"title": "Alarmes (24h)", "viz": "numeric", "q": "event_domain:alarm", "pos": (7, 1, 3, 2)},
               {"title": "Effraction / panique (24h)", "viz": "numeric", "q": 'event_domain:alarm AND event_action:("Effraction porte" OR "Declencheur manuel percute")', "dir": "LOWER", "pos": (10, 1, 3, 2)},
               {"title": "Badges non enroles (24h)", "viz": "numeric", "q": "event_domain:access AND event_outcome:grant AND NOT _exists_:identity_matricule", "pos": (1, 3, 3, 2)},
               {"title": "Acces hors heures (24h)", "viz": "numeric", "q": "event_domain:access AND event_outcome:grant AND off_hours:true", "pos": (4, 3, 3, 2)},
               {"title": "Alarmes intempestives (24h)", "viz": "numeric", "q": "event_domain:alarm AND IS_INTEMPESTIVE:true", "pos": (7, 3, 3, 2)},
               {"title": "Passe general / immunite (24h)", "viz": "numeric", "q": "event_domain:hypervisor_audit AND seal_source_table:TagMovements AND (seal_MasterKeys:true OR seal_ApbImmunity:true)", "dir": "LOWER", "pos": (10, 3, 3, 2)},
               {"title": "Top badges en refus", "viz": "table", "q": "event_domain:access AND event_outcome:deny", "pivot": "badge_number", "limit": 10, "pos": (1, 5, 4, 4)},
               {"title": "Refus par porte", "viz": "table", "q": "event_domain:access AND event_outcome:deny", "pivot": "target_object_label", "limit": 10, "pos": (5, 5, 4, 4)},
               {"title": "Echecs console (compte / IP distinctes)", "viz": "table", "q": "event_domain:hypervisor_audit AND event_action:ConnectionFailure", "pivot": "actor_login", "metrics": ["count", ("card", "src_ip", "IP")], "limit": 10, "pos": (9, 5, 4, 4)},
               {"title": "Derniers refus d'acces (detail)", "viz": "messages", "q": "event_domain:access AND event_outcome:deny", "fields": F_ACCESS, "limit": 30, "pos": (1, 9, 6, 5)},
               {"title": "Dernieres alarmes (detail)", "viz": "messages", "q": "event_domain:alarm", "fields": F_ALARM, "limit": 30, "pos": (7, 9, 6, 5)},
               {"title": "Derniers echecs de connexion console (detail)", "viz": "messages", "q": "event_domain:hypervisor_audit AND event_action:ConnectionFailure", "fields": ["timestamp", "actor_login", "src_ip", "operation_channel"], "limit": 25, "pos": (1, 14, 12, 4)},
           ]},
           {"title": "Alertes SEAL declenchees", "page_range": 604800, "streams": [EVENTS_STREAM], "widgets": [
               {"title": "Alertes SEAL (7j)", "viz": "numeric", "q": SEAL_ALERTS_Q, "dir": "LOWER", "pos": (1, 1, 3, 2)},
               {"title": "Top detections declenchees", "viz": "table", "q": SEAL_ALERTS_Q, "pivot": "event_definition_title", "limit": 15, "pos": (1, 3, 6, 6)},
               {"title": "Dernieres alertes (detail)", "viz": "messages", "q": SEAL_ALERTS_Q, "fields": ["timestamp", "event_definition_title", "priority", "message"], "limit": 40, "pos": (7, 3, 6, 6)},
           ]}])

    # ---- Vue B : Pilotage & preuve d'audit (30j) -----------------------------
    audit = ("SEAL - Pilotage & audit",
             "RSSI / Bureau Veritas : preuve A.8.15 (journalisation) + A.8.16 (surveillance) + piste d'audit detaillee.",
             [{"title": "Pilotage (30j)", "page_range": 2592000, "streams": ALL, "widgets": [
                 {"title": "Volume par domaine dans le temps (A.8.15)", "viz": "bar", "q": "event_source:seal", "time": True, "columns": "event_domain", "desc": "Continuite de la journalisation", "pos": (1, 1, 12, 3)},
                 {"title": "Acces accordes / refuses dans le temps", "viz": "bar", "q": "event_domain:access AND event_outcome:(grant OR deny)", "time": True, "columns": "event_outcome", "pos": (1, 4, 6, 3)},
                 {"title": "Alarmes par severite dans le temps", "viz": "bar", "q": "event_domain:alarm", "time": True, "columns": "severity_num", "pos": (7, 4, 6, 3)},
                 {"title": "Mouvements de droits par type (A.8.16)", "viz": "table", "q": DROITS, "pivot": "seal_source_table", "limit": 15, "pos": (1, 7, 4, 4)},
                 {"title": "Top comptes operateurs (actions admin)", "viz": "table", "q": "event_domain:hypervisor_audit", "pivot": "actor_usercode", "limit": 15, "pos": (5, 7, 4, 4)},
                 {"title": "Activite par canal console", "viz": "table", "q": "event_domain:hypervisor_audit AND _exists_:operation_channel", "pivot": "operation_channel", "limit": 8, "pos": (9, 7, 4, 4)},
                 {"title": "Piste d'audit - mouvements de droits (detail A.8.16)", "viz": "messages", "q": DROITS, "fields": ["timestamp", "actor_usercode", "event_action", "seal_source_table", "target_login", "target_object_label", "badge_number"], "limit": 50, "pos": (1, 11, 12, 6)},
                 {"title": "Exports de journaux (LogDownload)", "viz": "numeric", "q": "event_domain:hypervisor_audit AND seal_source_table:LogDownload", "pos": (1, 17, 3, 2)},
                 {"title": "Creations / mvts de comptes (30j)", "viz": "numeric", "q": "event_domain:hypervisor_audit AND seal_source_table:(AccountsMovements OR AccountRolesMovements)", "pos": (4, 17, 3, 2)},
                 {"title": "Mvts de badges (30j)", "viz": "numeric", "q": "event_domain:hypervisor_audit AND seal_source_table:TagMovements", "pos": (7, 17, 3, 2)},
             ]}])

    # ---- Vue C : Sante de la collecte (meta) ---------------------------------
    sante = ("SEAL - Sante collecte",
             "RSSI/SOC : surveiller la supervision elle-meme (fraicheur, debit, dernier evenement recu).",
             [{"title": "Sante (24h)", "page_range": 86400, "streams": ALL, "widgets": [
                 {"title": "Debit Acces (1h)", "viz": "numeric", "q": "event_domain:access", "range": 3600, "pos": (1, 1, 3, 2)},
                 {"title": "Debit Alarmes (1h)", "viz": "numeric", "q": "event_domain:alarm", "range": 3600, "pos": (4, 1, 3, 2)},
                 {"title": "Debit Audit (1h)", "viz": "numeric", "q": "event_domain:hypervisor_audit", "range": 3600, "pos": (7, 1, 3, 2)},
                 {"title": "Total SEAL (24h)", "viz": "numeric", "q": "event_source:seal", "pos": (10, 1, 3, 2)},
                 {"title": "Fraicheur & volume par domaine", "viz": "table", "q": "event_source:seal", "pivot": "event_domain", "metrics": ["count", ("max", "timestamp", "Dernier evenement")], "pos": (1, 3, 6, 3)},
                 {"title": "Debit par domaine dans le temps", "viz": "bar", "q": "event_source:seal", "time": True, "columns": "event_domain", "pos": (7, 3, 6, 3)},
                 {"title": "Fraicheur & volume par site (detecter un site muet)", "viz": "table", "q": "event_source:seal", "pivot": "seal_site", "metrics": ["count", ("max", "timestamp", "Dernier evenement")], "limit": 20, "pos": (1, 6, 12, 3)},
                 {"title": "Derniers evenements recus (tous domaines)", "viz": "messages", "q": "event_source:seal", "fields": ["timestamp", "seal_site", "event_domain", "event_action", "event_outcome", "source"], "limit": 30, "pos": (1, 9, 12, 5)},
             ]}])

    # ---- Vue D : Investigation acces & badges (90j) --------------------------
    invest = ("SEAL - Investigation acces & badges",
              "Analyse approfondie des acces physiques : par badge, par porte, motifs de refus, chronologie.",
              [{"title": "Investigation (1 an)", "page_range": 31536000, "streams": [acc, aud], "widgets": [
                  {"title": "Acces total (90j)", "viz": "numeric", "q": "event_domain:access", "pos": (1, 1, 3, 2)},
                  {"title": "Refus (90j)", "viz": "numeric", "q": "event_domain:access AND event_outcome:deny", "dir": "LOWER", "pos": (4, 1, 3, 2)},
                  {"title": "Badges distincts vus", "viz": "numeric", "q": "event_domain:access AND _exists_:badge_number", "card": "badge_number", "pos": (7, 1, 3, 2)},
                  {"title": "Portes distinctes", "viz": "numeric", "q": "event_domain:access AND _exists_:target_object_label", "card": "target_object_label", "pos": (10, 1, 3, 2)},
                  {"title": "Activite par badge (refus / total)", "viz": "table", "q": "event_domain:access", "pivot": "badge_number", "metrics": ["count"], "columns": "event_outcome", "limit": 20, "pos": (1, 3, 6, 5)},
                  {"title": "Motifs de refus (REEV decode)", "viz": "table", "q": "event_domain:access AND event_outcome:deny", "pivot": "event_action", "limit": 15, "pos": (7, 3, 6, 5)},
                  {"title": "Acces accordes / refuses dans le temps", "viz": "bar", "q": "event_domain:access AND event_outcome:(grant OR deny)", "time": True, "columns": "event_outcome", "pos": (1, 8, 12, 3)},
                  {"title": "Derniers acces (detail badge -> porte -> issue)", "viz": "messages", "q": "event_domain:access", "fields": F_ACCESS, "limit": 50, "pos": (1, 11, 12, 6)},
                  {"title": "Mouvements de badges (detail)", "viz": "messages", "q": "event_domain:hypervisor_audit AND seal_source_table:TagMovements", "fields": ["timestamp", "actor_usercode", "event_action", "badge_number", "seal_Status", "seal_StatusOld"], "limit": 30, "pos": (1, 17, 12, 5)},
              ]}])

    # ---- Vue E : Vue multi-site (30j) -- comparaison inter-sites SEAL --------
    #  seal_site est REELLEMENT peuple (bx-qa-seal-vm, bx-seal-omega). On evite
    #  soigneusement site (objet NULL) et identity_upn (vide en QA).
    multisite = ("SEAL - Vue multi-site",
                 "Comparaison inter-sites : volumes, refus, alarmes et fraicheur par seal_site.",
                 [{"title": "Multi-site (30j)", "page_range": 2592000, "streams": ALL, "widgets": [
                     {"title": "Total site BX-QA-SEAL-VM (30j)", "viz": "numeric", "q": "seal_site:bx-qa-seal-vm", "pos": (1, 1, 3, 2)},
                     {"title": "Total site BX-SEAL-OMEGA (30j)", "viz": "numeric", "q": "seal_site:bx-seal-omega", "pos": (4, 1, 3, 2)},
                     {"title": "Sites distincts actifs", "viz": "numeric", "q": "event_source:seal AND _exists_:seal_site", "card": "seal_site", "pos": (7, 1, 3, 2)},
                     {"title": "Alarmes en breche SLA (24h)", "viz": "numeric", "q": "event_domain:alarm AND alert_tag:seal_sla_breach AND NOT _exists_:TEST_SIEM", "card": "EVEN_GROUP_ID", "range": 86400, "desc": "Alarmes severes ouvertes au-dela du SLA (poller oms-seal-sla)", "pos": (10, 1, 3, 2)},
                     {"title": "Total tous sites (30j)", "viz": "numeric", "q": "event_source:seal", "pos": (10, 1, 3, 2)},
                     {"title": "Volume par site et domaine", "viz": "table", "q": "event_source:seal", "pivot": "seal_site", "columns": "event_domain", "limit": 20, "pos": (1, 3, 6, 4)},
                     {"title": "Volume dans le temps par site", "viz": "bar", "q": "event_source:seal", "time": True, "columns": "seal_site", "desc": "Histogramme empile colore par seal_site", "pos": (7, 3, 6, 4)},
                     {"title": "Refus d'acces par site", "viz": "table", "q": "event_domain:access AND event_outcome:deny", "pivot": "seal_site", "limit": 20, "pos": (1, 7, 6, 4)},
                     {"title": "Alarmes par site et severite", "viz": "table", "q": "event_domain:alarm", "pivot": "seal_site", "columns": "severity_num", "limit": 20, "pos": (7, 7, 6, 4)},
                     # --- Backlog SLA (marqueurs seal_sla_breach emis par le poller oms-seal-sla) ---
                     {"title": "Backlog SLA par site et classe (24h)", "viz": "table", "q": "event_domain:alarm AND alert_tag:seal_sla_breach AND NOT _exists_:TEST_SIEM", "pivot": "seal_site", "columns": "sla_class", "metrics": [("card", "EVEN_GROUP_ID", "Alarmes en breche")], "range": 86400, "desc": "Alarmes severes non traitees au-dela du SLA, par site et par classe", "pos": (1, 11, 6, 4)},
                     {"title": "Detail des breches SLA (24h)", "viz": "messages", "q": "event_domain:alarm AND alert_tag:seal_sla_breach AND NOT _exists_:TEST_SIEM", "fields": ["timestamp", "seal_site", "sla_class", "event_action", "REEV_CODE", "age_minutes", "EVEN_GROUP_ID"], "range": 86400, "limit": 30, "pos": (7, 11, 6, 4)},
                     {"title": "Derniers evenements tous sites (detail)", "viz": "messages", "q": "event_source:seal", "fields": ["timestamp", "seal_site", "event_domain", "event_action", "event_outcome"], "limit": 40, "pos": (1, 15, 12, 6)},
                     # --- Repartition par ZONE physique (seal_zone, pose des que la topologie
                     #     est finalisee : 07_vw_SealZone_SIEM + regen_zone_lookup.sh). Vide sinon. ---
                     {"title": "Acces par zone et resultat (30j)", "viz": "table", "q": "event_domain:access AND _exists_:seal_zone", "pivot": "seal_zone", "columns": "event_outcome", "limit": 40, "desc": "Repartition des acces (grant/deny) par zone physique", "pos": (1, 21, 6, 5)},
                     {"title": "Refus d'acces par zone (30j)", "viz": "bar", "q": "event_domain:access AND event_outcome:deny AND _exists_:seal_zone", "pivot": "seal_zone", "limit": 20, "desc": "Zones concentrant le plus de refus (sondage/badge interdit)", "pos": (7, 21, 6, 5)},
                 ]}])

    for title, desc, pages in (soc, audit, sante, invest, multisite):
        delete_by_title(title)
        build(title, desc, pages)

    print("\n  Termine." + ("" if APPLY else "  (relancer avec --apply pour creer)"))


if __name__ == "__main__":
    main()
