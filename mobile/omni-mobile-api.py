#!/usr/bin/env python3
"""omni-mobile-api - Backend de la PWA mobile SIEM OMNITECH.

Sert l'API mobile (lecture alertes/incidents/KPI + abonnement web-push) consommée
par la PWA (servie par nginx sous /m/). Conçu pour un accès VPN-only.

- Auth : déléguée à Graylog (POST /api/system/sessions, backend AD/LDAPS déjà en
  place) -> cookie de session signé HMAC. Aucun code LDAP ici.
- Lecture : OpenSearch local (127.0.0.1:9200), comme les services omni-*.
- Push : web-push VAPID (pywebpush, venv). Déclenché par un webhook Graylog
  (notification HTTP sur les alertes critiques) -> POST /m/api/push (secret local).

Stdlib + pywebpush. Écoute 127.0.0.1:8090 (derrière nginx). Installé par 65-mobile-pwa.sh.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

CONF = {}
for path in ("/etc/default/omni-mobile",):
    try:
        with open(path) as fh:
            for line in fh:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    CONF[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass

LISTEN = ("127.0.0.1", int(CONF.get("MOBILE_PORT", "8090")))
OS_URL = CONF.get("OPENSEARCH", "http://127.0.0.1:9200")
GL_URL = CONF.get("GRAYLOG_API", "https://bx-it-graylog-vm.omnitech.security:9000/api")
GL_CACERT = CONF.get("GRAYLOG_CACERT", "/etc/graylog/certs/omnitech-rootca.crt")
SECRET = CONF.get("MOBILE_SECRET", "change-me").encode()
PUSH_SECRET = CONF.get("MOBILE_PUSH_SECRET", "change-me-push")
SESSION_TTL = int(CONF.get("MOBILE_SESSION_TTL", "43200"))  # 12 h
SUBS_FILE = CONF.get("MOBILE_SUBS_FILE", "/var/lib/omni-mobile/subscriptions.json")
VAPID_PUB = CONF.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIV_FILE = CONF.get("VAPID_PRIVATE_FILE", "/etc/omni-mobile/vapid_private.pem")
VAPID_SUBJECT = CONF.get("VAPID_SUBJECT", "mailto:informatique@omnitech-security.fr")
INTERNAL = ["omni-winsec", "omni-sysmon", "omni-winother", "omni-fortigate",
            "omni-m365", "omni-vsphere", "omni-fortimanager"]

_ssl_ctx = ssl.create_default_context(cafile=GL_CACERT) if os.path.exists(GL_CACERT) else ssl._create_unverified_context()


# --------------------------------------------------------------------------- util
def os_search(index: str, body: dict) -> dict:
    req = urllib.request.Request(f"{OS_URL}/{index}/_search",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.URLError:
        return {}


# ------------------------------------------------- redaction (mode démo / captures)
# Pseudonymise comptes / hôtes / IP de façon cohérente (réel -> pseudo stable) pour
# produire des captures sans données réelles. Activé par MOBILE_REDACT=1 (sinon no-op).
REDACT = CONF.get("MOBILE_REDACT", "") == "1"
_RD_MAP: dict = {}
_RD_REV: dict = {}     # pseudo -> réel (pour que l'Entité-360 fonctionne en mode rédigé)
_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_SID_RE = re.compile(r"S-1-5-21(?:-\d+){1,5}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _pseudo_ip(m):
    return f"10.{int(m.group(2)) % 80 + 10}.{int(m.group(3)) % 80 + 10}.{int(m.group(4)) % 80 + 10}"


def _rd(v):
    """Pseudonymise une entité (compte/hôte/IP) et mémorise la correspondance."""
    if not REDACT or not v:
        return v
    s = str(v)
    if s in _RD_MAP:
        return _RD_MAP[s]
    if _IP_RE.fullmatch(s.strip()):
        out = _IP_RE.sub(_pseudo_ip, s.strip())
    else:
        h = hashlib.md5(s.encode()).hexdigest()[:4]
        if "\\" in s:                       # DOMAINE\compte
            dom, _, _u = s.partition("\\")
            out = f"{dom}\\ent-{h}"
        elif s.endswith("$"):               # compte machine AD
            out = f"HOST-{h.upper()}$"
        else:                               # préfixe neutre (le type est déjà porté par une icône)
            out = f"ent-{h}"
    _RD_MAP[s] = out
    _RD_REV[out] = s
    return out


def _scrub(text):
    """Remplace dans un texte libre les entités connues (carte) + toute IP."""
    if not REDACT or not isinstance(text, str) or not text:
        return text
    for real, pse in _RD_MAP.items():
        if real and real in text:
            text = text.replace(real, pse)
    text = _IP_RE.sub(_pseudo_ip, text)
    text = _SID_RE.sub("S-1-5-21-x-x-x", text)
    text = _EMAIL_RE.sub("user@redacted.local", text)
    return text


def _walk_redact(o):
    """Passe finale récursive sur la réponse : scrube les chaînes (texte libre)."""
    if not REDACT:
        return o
    if isinstance(o, str):
        return _scrub(o)
    if isinstance(o, list):
        return [_walk_redact(x) for x in o]
    if isinstance(o, dict):
        return {k: _walk_redact(v) for k, v in o.items()}
    return o


def sign_session(user: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = f"{user}|{exp}"
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def verify_session(tok: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        user, exp, sig = raw.rsplit("|", 2)
        good = hmac.new(SECRET, f"{user}|{exp}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return user
    except Exception:
        pass
    return None


def graylog_login(user: str, pwd: str) -> bool:
    """Valide les identifiants via la session Graylog (backend AD/LDAPS)."""
    body = json.dumps({"username": user, "password": pwd, "host": ""}).encode()
    req = urllib.request.Request(f"{GL_URL}/system/sessions", data=body,
                                 headers={"Content-Type": "application/json",
                                          "X-Requested-By": "omni-mobile",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx) as r:
            return r.status in (200, 201)
    except urllib.error.HTTPError:
        return False
    except urllib.error.URLError:
        return False


def load_subs() -> list:
    try:
        with open(SUBS_FILE) as fh:
            return json.load(fh)
    except Exception:
        return []


def save_subs(subs: list) -> None:
    os.makedirs(os.path.dirname(SUBS_FILE), exist_ok=True)
    tmp = SUBS_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(subs, fh)
    os.replace(tmp, SUBS_FILE)


# ----------------------------------------------------------------------- requêtes
def get_alerts(limit: int = 50) -> list:
    res = os_search("gl-events*", {
        "size": limit, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"timestamp": {"gte": "now-24h"}}},
        "_source": ["timestamp", "event_definition_title", "message", "priority",
                    "key", "fields", "alert"],
    })
    out = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        out.append({
            "ts": s.get("timestamp"),
            "title": s.get("event_definition_title") or s.get("message"),
            "priority": s.get("priority"),
            "entity": _rd(s.get("key") or ""),
        })
    return out


def get_incidents(limit: int = 30) -> list:
    res = os_search("omni-*", {
        "size": limit, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [{"term": {"event_source": "xdr_incident"}}],
                           "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}},
        "_source": ["timestamp", "short_message", "full_message", "severity",
                    "rule_id", "entities", "mitre", "remediation"],
    })
    out = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        out.append({
            "id": h.get("_id"),
            "ts": s.get("timestamp"),
            "title": s.get("short_message"),
            "severity": s.get("severity"),
            "rule": s.get("rule_id"),
            # `entities` est une chaîne jointe par virgules (oms-xdr ",".join).
            # On scinde et pseudonymise CHAQUE entité pour peupler _RD_MAP par nom :
            # sinon _rd() traite le bloc entier et les hôtes/comptes restent en clair
            # dans la narrative (full_message) au passage _walk_redact. (fuite redaction)
            "entities": ([_rd(e) for e in s["entities"]] if isinstance(s.get("entities"), list)
                         else [_rd(e) for e in str(s.get("entities") or "").split(",") if e]),
            "mitre": s.get("mitre"),
            "narrative": s.get("full_message"),
            "remediation": s.get("remediation"),
        })
    return out


def _count(query: dict) -> int:
    body = {"size": 0, "track_total_hits": True, "query": query}
    res = os_search("omni-*", body)
    return res.get("hits", {}).get("total", {}).get("value", 0)


def get_kpis() -> dict:
    last24 = {"range": {"timestamp": {"gte": "now-24h"}}}
    return {
        "alertes_24h": _count({"bool": {"must": [{"exists": {"field": "alert_tag"}}], "filter": [last24]}}),
        "incidents_critiques_7j": _count({"bool": {"must": [
            {"term": {"event_source": "xdr_incident"}}, {"term": {"severity": "critical"}}],
            "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}}),
        "hotes_risque_ueba": _count({"bool": {"must": [{"term": {"event_source": "ueba_score"}},
            {"range": {"ueba_score": {"gte": 80}}}], "filter": [last24]}}),
        "kev_exposees": _count({"bool": {"must": [{"term": {"alert_tag": "vuln_kev"}}], "filter": [last24]}}),
    }


def get_timeseries():
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": [{"exists": {"field": "alert_tag"}}],
                           "filter": [{"range": {"timestamp": {"gte": "now-24h"}}}]}},
        "aggs": {"h": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}}}})
    return [{"t": b.get("key_as_string"), "n": b.get("doc_count")}
            for b in res.get("aggregations", {}).get("h", {}).get("buckets", [])]


def get_terms(field, gte="now-7d", size=8):
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": [{"exists": {"field": "alert_tag"}}],
                           "filter": [{"range": {"timestamp": {"gte": gte}}}]}},
        "aggs": {"t": {"terms": {"field": field, "size": size}}}})
    return [{"k": b.get("key"), "n": b.get("doc_count")}
            for b in res.get("aggregations", {}).get("t", {}).get("buckets", [])]


def get_attack_matrix():
    rows = []
    try:
        import csv as _csv
        with open("/root/omnitech-siem-setup/lookups/mitre-attack.csv") as f:
            rd = _csv.reader(f); next(rd, None)
            for r in rd:
                if len(r) >= 4 and r[1].startswith("T"):
                    rows.append((r[1], r[2], r[3], r[4] if len(r) > 4 else ""))
    except Exception:
        pass
    res = os_search("omni-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-7d"}}},
        "aggs": {"t": {"terms": {"field": "mitre_technique", "size": 300}}}})
    counts = {b.get("key"): b.get("doc_count") for b in res.get("aggregations", {}).get("t", {}).get("buckets", [])}
    tac = {}
    for tech, name, tactic, sev in rows:
        tac.setdefault(tactic, {}).setdefault(tech, {"id": tech, "name": name, "count": counts.get(tech, 0), "sev": sev})
    ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
             "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
             "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
    out = []
    for t in ORDER:
        if t in tac:
            out.append({"tactic": t, "techniques": sorted(tac[t].values(), key=lambda x: -x["count"])})
    for t, v in tac.items():
        if t not in ORDER:
            out.append({"tactic": t, "techniques": list(v.values())})
    return out


def _tech_tactic_map():
    m = {}
    try:
        import csv as _csv
        with open("/root/omnitech-siem-setup/lookups/mitre-attack.csv") as f:
            rd = _csv.reader(f); next(rd, None)
            for r in rd:
                if len(r) >= 4 and r[1].startswith("T"):
                    m[r[1]] = r[3]
    except Exception:
        pass
    return m


def get_graph():
    tt = _tech_tactic_map()
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": [{"exists": {"field": "alert_tag"}}, {"exists": {"field": "mitre_technique"}},
                                    {"exists": {"field": "user"}}],
                           "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}},
        "aggs": {"e": {"terms": {"field": "user", "size": 15},
                       "aggs": {"t": {"terms": {"field": "mitre_technique", "size": 8}}}}}})
    nodes, edges, seen = [], [], set()
    def add(n):
        if n["id"] not in seen:
            seen.add(n["id"]); nodes.append(n)
    for eb in res.get("aggregations", {}).get("e", {}).get("buckets", []):
        ent = eb.get("key"); eid = "u:" + ent; rent = _rd(ent)
        add({"id": eid, "label": rent.split("\\")[-1], "full": rent, "type": "entity", "weight": eb.get("doc_count", 0)})
        for tb in eb.get("t", {}).get("buckets", []):
            tech = tb.get("key"); tid = "t:" + tech
            add({"id": tid, "label": tech, "type": "technique", "tactic": tt.get(tech, "?"), "weight": 0})
            edges.append({"source": eid, "target": tid, "weight": tb.get("doc_count", 0)})
    return {"nodes": nodes, "edges": edges}


CASES_FILE = CONF.get("MOBILE_CASES_FILE", "/var/lib/omni-mobile/cases.json")
_CASES_LOCK = threading.Lock()   # serialise read-modify-write (ThreadingHTTPServer)


def load_cases():
    try:
        with open(CASES_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_cases(c):
    os.makedirs(os.path.dirname(CASES_FILE), exist_ok=True)
    tmp = CASES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f)
    os.replace(tmp, CASES_FILE)


def get_cases():
    incs = get_incidents(50)
    st = load_cases()
    for i in incs:
        c = st.get(i.get("id") or "", {})
        i["status"] = c.get("status", "new")
        i["assignée"] = c.get("assignée", "")
        i["notes"] = c.get("notes", [])
        i["disposition"] = c.get("disposition", "")
    return incs


def update_case(b, who):
    cid = b.get("id")
    if not cid:
        return {"ok": False}
    import datetime as _dt
    act = b.get("action"); val = b.get("value", "")
    with _CASES_LOCK:                       # verrou : cycle lecture-modif-ecriture atomique
        st = load_cases()
        c = st.setdefault(cid, {"status": "new", "assignée": "", "notes": []})
        if act == "status":
            c["status"] = val if val in ("new", "in_progress", "closed") else "new"
        elif act == "assign":
            c["assignée"] = str(val)[:120]
        elif act == "disposition":
            # Qualification analyste -> label du modèle ML de réduction de FP (oms-ml).
            if val in ("true_positive", "false_positive"):
                c["disposition"] = val
                c["disposition_by"] = who or "?"
                if c.get("status") != "closed":
                    c["status"] = "closed"
            else:
                c.pop("disposition", None)
        elif act == "note":
            txt = str(val).strip()
            if txt:
                c.setdefault("notes", []).append(
                    {"by": who or "?", "ts": _dt.datetime.now().isoformat(timespec="seconds"), "text": txt[:1000]})
        save_cases(st)
    return {"ok": True, "case": c}


def _entity_scores(name):
    """Score ML (ml_anomaly) et UEBA (ueba_score) de CETTE entite (forme complete OU compte nu)."""
    bare = name.split("\\")[-1] if name else name
    forms = [f for f in {name, bare} if f]
    ml = {"score": None, "reason": ""}
    rml = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"term": {"event_source": "ml_anomaly"}},
                                      {"terms": {"entity": forms}},
                                      {"range": {"timestamp": {"gte": "now-7d"}}}]}},
        "aggs": {"s": {"max": {"field": "ml_score"}},
                 "h": {"top_hits": {"size": 1, "_source": ["ml_reason"],
                                    "sort": [{"timestamp": {"order": "desc"}}]}}}})
    aml = rml.get("aggregations", {})
    vml = (aml.get("s", {}) or {}).get("value")
    if vml is not None:
        hit = (((aml.get("h", {}) or {}).get("hits", {}) or {}).get("hits", []) or [{}])[0].get("_source", {})
        ml = {"score": round(vml or 0, 1), "reason": _rd(hit.get("ml_reason", "")) or ""}
    ue = {"score": None, "factor": ""}
    rue = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"term": {"event_source": "ueba_score"}},
                                      {"terms": {"ueba_entity": forms}},
                                      {"range": {"timestamp": {"gte": "now-7d"}}}]}},
        "aggs": {"s": {"max": {"field": "ueba_score"}},
                 "h": {"top_hits": {"size": 1, "_source": ["ueba_top_factor"],
                                    "sort": [{"timestamp": {"order": "desc"}}]}}}})
    aue = rue.get("aggregations", {})
    vue = (aue.get("s", {}) or {}).get("value")
    if vue is not None:
        hit = (((aue.get("h", {}) or {}).get("hits", {}) or {}).get("hits", []) or [{}])[0].get("_source", {})
        ue = {"score": int(vue or 0), "factor": _rd(hit.get("ueba_top_factor", "")) or ""}
    return {"ml": ml, "ueba": ue}


def get_entity(name, size=20, frm=0):
    if not name:
        return {"name": "", "total": 0, "techniques": [], "tactics": [], "events": [],
                "from": 0, "size": size, "loaded": 0, "has_more": False,
                "scores": {"ml": {"score": None, "reason": ""}, "ueba": {"score": None, "factor": ""}}}
    name = _RD_REV.get(name, name)   # mode rédigé : pseudo -> réel pour la requête
    size = max(1, min(int(size), 200))
    frm = max(0, int(frm))
    q = {"bool": {"must": [{"term": {"user": name}}, {"exists": {"field": "alert_tag"}}],
                  "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}}
    res = os_search("omni-*", {"size": size, "from": frm, "track_total_hits": True,
        "sort": [{"timestamp": {"order": "desc"}}], "query": q,
        "_source": ["timestamp", "alert_tag", "mitre_technique", "short_message", "message"],
        "aggs": {"tech": {"terms": {"field": "mitre_technique", "size": 8}},
                 "tac": {"terms": {"field": "mitre_tactic", "size": 8}},
                 "tot": {"value_count": {"field": "alert_tag"}}}})
    ag = res.get("aggregations", {})
    ev = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        ev.append({"ts": s.get("timestamp"), "tag": s.get("alert_tag"), "tech": s.get("mitre_technique"),
                   "msg": s.get("short_message") or s.get("message")})
    th = res.get("hits", {}).get("total", {})
    th = th.get("value", 0) if isinstance(th, dict) else (th or 0)
    return {"name": _rd(name), "total": ag.get("tot", {}).get("value", 0),
            "from": frm, "size": size, "loaded": frm + len(ev), "has_more": (frm + len(ev)) < th,
            "scores": _entity_scores(name),
            "techniques": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("tech", {}).get("buckets", [])],
            "tactics": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("tac", {}).get("buckets", [])],
            "events": ev}


def get_entity_search(q, size=8):
    """Recherche d'entités par sous-chaîne (insensible à la casse) — pour la palette.

    Cherche À LA FOIS les comptes (`user`) ET les hôtes (`source`) afin que le pivot
    d'investigation soit atteignable pour un « pc » comme pour un compte M365.
    """
    q = (q or "").strip()
    if len(q) < 2:
        return []
    wc_u = {"wildcard": {"user": {"value": f"*{q}*", "case_insensitive": True}}}
    wc_h = {"wildcard": {"source": {"value": f"*{q}*", "case_insensitive": True}}}
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-7d"}}}],
                           "minimum_should_match": 1, "should": [wc_u, wc_h]}},
        "aggs": {"u": {"filter": wc_u, "aggs": {"t": {"terms": {"field": "user", "size": size}}}},
                 "h": {"filter": wc_h, "aggs": {"t": {"terms": {"field": "source", "size": size}}}}}})
    ag = res.get("aggregations", {})
    out, seen = [], set()
    for b in ag.get("u", {}).get("t", {}).get("buckets", []):
        k = b.get("key")
        if k:
            out.append({"entity": _rd(k), "n": b["doc_count"], "kind": "user"})
            seen.add(_rd(k))
    for b in ag.get("h", {}).get("t", {}).get("buckets", []):
        k = b.get("key")
        if k and _rd(k) not in seen:
            out.append({"entity": _rd(k), "n": b["doc_count"], "kind": "host"})
    return out[: size * 2]


def get_investigation(name, days=14):
    """Pivot d'investigation par entité (utilisateur M365 / compte AD / hôte).

    Répond à « d'où ça vient » sur un compte ciblé (ex. spray M365 distribué) :
      - profil d'authentification : cartographie géo des sources, chronologie
        succès/échec, IP sources (avec part de réussite), codes de statut ;
      - provenance des détections (alert_tag x source) et présence multi-sources.
    Rédaction : les IP/entités sont pseudonymisées ; pays/codes/volumes conservés.
    """
    if not name:
        return {"entity": "", "days": days, "auth": {}, "detections": [], "sources": []}
    name = _RD_REV.get(name, name)              # pseudo -> réel pour la requête
    days = max(1, min(int(days), 90))
    gte = f"now-{days}d"
    ent = {"bool": {"minimum_should_match": 1, "should": [
        {"term": {"user": name}}, {"match_phrase": {"upn": name}},
        {"term": {"identity": name}}, {"term": {"source": name}}]}}   # source -> entité hôte

    # --- A. Authentification M365 (sign-in) : géo, codes, IP, chronologie -------
    auth = {}
    a = os_search("omni-m365*", {"size": 0, "track_total_hits": True,
        "query": {"bool": {"must": [{"term": {"m365_type": "signin"}}, ent],
                           "filter": [{"range": {"timestamp": {"gte": gte}}}]}},
        "aggs": {
            "ok": {"filter": {"term": {"status_code": 0}}},
            "codes": {"terms": {"field": "status_code", "size": 12}},
            "countries": {"terms": {"field": "src_ip_country_code", "size": 20}},
            "ips": {"terms": {"field": "src_ip", "size": 12}, "aggs": {
                "cc": {"terms": {"field": "src_ip_country_code", "size": 1}},
                "ok": {"filter": {"term": {"status_code": 0}}}}},
            "tl": {"date_histogram": {"field": "timestamp", "calendar_interval": "day", "min_doc_count": 0},
                   "aggs": {"ok": {"filter": {"term": {"status_code": 0}}}}}}})
    aa = a.get("aggregations", {})
    at = a.get("hits", {}).get("total", {})
    at = at.get("value", 0) if isinstance(at, dict) else (at or 0)
    if at:
        ok = aa.get("ok", {}).get("doc_count", 0)
        def _cc(b):
            bk = b.get("cc", {}).get("buckets", [])
            return bk[0]["key"] if bk else ""
        auth = {
            "total": at, "success": ok, "fail": at - ok,
            "codes": [{"k": b["key"], "n": b["doc_count"]} for b in aa.get("codes", {}).get("buckets", [])],
            "countries": [{"k": b["key"], "n": b["doc_count"]} for b in aa.get("countries", {}).get("buckets", [])],
            "ips": [{"ip": _rd(b["key"]), "cc": _cc(b), "n": b["doc_count"],
                     "ok": b.get("ok", {}).get("doc_count", 0)} for b in aa.get("ips", {}).get("buckets", [])],
            "timeline": [{"t": (b.get("key_as_string") or "")[:10],
                          "ok": b.get("ok", {}).get("doc_count", 0),
                          "ko": b["doc_count"] - b.get("ok", {}).get("doc_count", 0)}
                         for b in aa.get("tl", {}).get("buckets", [])]}

    # --- A2. Authentification Windows (logons 4624/4625) — pour les HÔTES --------
    # Profil d'auth d'un poste/serveur : succès/échec, IP sources (part de réussite),
    # types de logon (3=réseau, 10=RDP…), motifs d'échec, chronologie. Symétrique du
    # profil M365 mais côté Windows -> le pivot d'investigation marche aussi sur « pc ».
    winauth = {}
    w = os_search("omni-*", {"size": 0, "track_total_hits": True,
        "query": {"bool": {"must": [{"term": {"event_source": "windows_security"}},
                                    {"terms": {"event_id": ["4624", "4625"]}},
                                    {"term": {"source": name}}],
                           "filter": [{"range": {"timestamp": {"gte": gte}}}]}},
        "aggs": {
            "ok": {"filter": {"term": {"event_id": "4624"}}},
            "ips": {"terms": {"field": "src_ip", "size": 12},
                    "aggs": {"ok": {"filter": {"term": {"event_id": "4624"}}}}},
            "ltype": {"terms": {"field": "winlogbeat_winlog_event_data_LogonType", "size": 8}},
            "reason": {"filter": {"term": {"event_id": "4625"}},
                       "aggs": {"r": {"terms": {"field": "failure_reason", "size": 8}}}},
            "tl": {"date_histogram": {"field": "timestamp", "calendar_interval": "day", "min_doc_count": 0},
                   "aggs": {"ok": {"filter": {"term": {"event_id": "4624"}}}}}}})
    wa = w.get("aggregations", {})
    wt = w.get("hits", {}).get("total", {})
    wt = wt.get("value", 0) if isinstance(wt, dict) else (wt or 0)
    if wt:
        wok = wa.get("ok", {}).get("doc_count", 0)
        winauth = {
            "total": wt, "success": wok, "fail": wt - wok,
            "logon_types": [{"k": b["key"], "n": b["doc_count"]} for b in wa.get("ltype", {}).get("buckets", [])],
            "reasons": [{"k": b["key"], "n": b["doc_count"]} for b in wa.get("reason", {}).get("r", {}).get("buckets", [])],
            "ips": [{"ip": _rd(b["key"]), "n": b["doc_count"], "ok": b.get("ok", {}).get("doc_count", 0)}
                    for b in wa.get("ips", {}).get("buckets", [])],
            "timeline": [{"t": (b.get("key_as_string") or "")[:10],
                          "ok": b.get("ok", {}).get("doc_count", 0),
                          "ko": b["doc_count"] - b.get("ok", {}).get("doc_count", 0)}
                         for b in wa.get("tl", {}).get("buckets", [])]}

    # --- B. Provenance des détections + présence multi-sources ------------------
    bq = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": [ent], "filter": [{"range": {"timestamp": {"gte": gte}}}]}},
        "aggs": {
            "sources": {"terms": {"field": "event_source", "size": 12}},
            "prov": {"filter": {"exists": {"field": "alert_tag"}}, "aggs": {
                "tags": {"terms": {"field": "alert_tag", "size": 12}, "aggs": {
                    "src": {"terms": {"field": "event_source", "size": 1}},
                    "last": {"max": {"field": "timestamp"}}}}}}}})
    bb = bq.get("aggregations", {})
    def _src(t):
        bk = t.get("src", {}).get("buckets", [])
        return bk[0]["key"] if bk else ""
    dets = [{"tag": t["key"], "n": t["doc_count"], "source": _src(t),
             "last": (t.get("last", {}).get("value_as_string") or "")[:19]}
            for t in bb.get("prov", {}).get("tags", {}).get("buckets", [])]
    sources = [{"k": b["key"], "n": b["doc_count"]} for b in bb.get("sources", {}).get("buckets", [])]
    return {"entity": _rd(name), "days": days, "auth": auth, "winauth": winauth,
            "detections": dets, "sources": sources}


_GUIDANCE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lookups", "alert-guidance.json")
_GUIDANCE = {"mtime": -1.0, "data": {}}


def get_guidance():
    """Aide à la décision par détection (`alert_tag`) : ce que c'est, à vérifier
    (triage), remédiation, correction durable. Connaissance STATIQUE (aucune PII) ;
    rechargée à chaud si le fichier change. Sert le triage/réponse côté console+PWA."""
    try:
        m = os.path.getmtime(_GUIDANCE_PATH)
        if m != _GUIDANCE["mtime"]:
            with open(_GUIDANCE_PATH, encoding="utf-8") as fh:
                _GUIDANCE["data"] = json.load(fh)
            _GUIDANCE["mtime"] = m
    except Exception:
        pass
    return _GUIDANCE["data"]


def get_detections(tactic="", source="", tag="", technique=""):
    must = [{"exists": {"field": "alert_tag"}}]
    if tactic:
        must.append({"term": {"mitre_tactic": tactic}})
    if source:
        must.append({"term": {"event_source": source}})
    if tag:
        must.append({"term": {"alert_tag": tag}})
    if technique:
        must.append({"term": {"mitre_technique": technique}})
    res = os_search("omni-*", {"size": 60, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must, "filter": [{"range": {"timestamp": {"gte": "now-24h"}}}]}},
        "_source": ["timestamp", "alert_tag", "mitre_technique", "mitre_tactic", "event_source",
                    "user", "key", "short_message", "message", "priority", "risk_severity", "risk_score"],
        "aggs": {"tac": {"terms": {"field": "mitre_tactic", "size": 14}},
                 "src": {"terms": {"field": "event_source", "size": 15}}}})
    items = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        items.append({"ts": s.get("timestamp"), "tag": s.get("alert_tag"), "tech": s.get("mitre_technique"),
                      "tactic": s.get("mitre_tactic"), "source": s.get("event_source"),
                      "entity": _rd(s.get("user") or s.get("key")), "priority": s.get("priority"),
                      "sev": s.get("risk_severity"), "score": s.get("risk_score"),
                      "msg": s.get("short_message") or s.get("message")})
    ag = res.get("aggregations", {})
    return {"items": items,
            "tactics": [b["key"] for b in ag.get("tac", {}).get("buckets", [])],
            "sources": [b["key"] for b in ag.get("src", {}).get("buckets", [])]}


def _leak_cat(source, tag, repo, account, breaches):
    """Classe une fuite : github / creds / extortion (defaut)."""
    src = (source or "").lower()
    if repo or src == "github":
        return "github"
    if src in ("hibp", "dehashed") or account or breaches:
        return "creds"
    return "extortion"


def get_leaks_v2():
    """Version enrichie de get_leaks : items categorises + anonymises (_rd) + compteurs."""
    res = os_search("omni-*", {"size": 60, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [{"term": {"event_source": "leak_intel"}}],
                           "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}]}},
        "_source": ["timestamp", "leak_source", "alert_tag", "leak_victim", "leak_account",
                    "leak_breaches", "leak_repo", "leak_url", "short_message"],
        "aggs": {"src": {"terms": {"field": "leak_source", "size": 10}}}})
    items = []
    cats = {"extortion": 0, "creds": 0, "github": 0}
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        source = s.get("leak_source"); tag = s.get("alert_tag")
        repo = s.get("leak_repo"); account = s.get("leak_account")
        breaches = s.get("leak_breaches"); victim = s.get("leak_victim")
        cat = _leak_cat(source, tag, repo, account, breaches)
        if cat in cats:
            cats[cat] += 1
        raw = victim or account or repo or ""
        items.append({"ts": s.get("timestamp"), "source": source, "tag": tag,
                      "cat": cat, "label": _rd(raw) if raw else "—",
                      "msg": s.get("short_message"), "url": s.get("leak_url"),
                      "breaches": _rd(breaches) if breaches else None})
    counts = [{"k": b["key"], "n": b["doc_count"]} for b in res.get("aggregations", {}).get("src", {}).get("buckets", [])]
    return {"items": items, "sources": counts, "cats": cats, "total": len(items)}


def _trend(cur: int, prev: int) -> dict:
    # delta en % vs fenetre précédente ; dir = sens (up/down/flat), bad = defavorable.
    if prev <= 0:
        pct = 100 if cur > 0 else 0
    else:
        pct = int(round((cur - prev) * 100.0 / prev))
    if cur > prev:
        d = "up"
    elif cur < prev:
        d = "down"
    else:
        d = "flat"
    return {"cur": cur, "prev": prev, "pct": abs(pct), "dir": d, "bad": cur > prev}


def get_kpi_trend() -> dict:
    prev24 = {"range": {"timestamp": {"gte": "now-48h", "lt": "now-24h"}}}
    prev7d = {"range": {"timestamp": {"gte": "now-14d", "lt": "now-7d"}}}
    cur = get_kpis()
    prev_alertes = _count({"bool": {"must": [{"exists": {"field": "alert_tag"}}], "filter": [prev24]}})
    prev_inc = _count({"bool": {"must": [
        {"term": {"event_source": "xdr_incident"}}, {"term": {"severity": "critical"}}],
        "filter": [prev7d]}})
    prev_ueba = _count({"bool": {"must": [{"term": {"event_source": "ueba_score"}},
        {"range": {"ueba_score": {"gte": 80}}}], "filter": [prev24]}})
    prev_kev = _count({"bool": {"must": [{"term": {"alert_tag": "vuln_kev"}}], "filter": [prev24]}})
    return {
        "alertes_24h": _trend(cur["alertes_24h"], prev_alertes),
        "incidents_critiques_7j": _trend(cur["incidents_critiques_7j"], prev_inc),
        "hotes_risque_ueba": _trend(cur["hotes_risque_ueba"], prev_ueba),
        "kev_exposees": _trend(cur["kev_exposees"], prev_kev),
    }


def get_report():
    cov = get_attack_matrix()
    src = get_health()
    return {"kpis": get_kpis(),
            "coverage": {"techniques": sum(len(c["techniques"]) for c in cov), "tactics": len(cov)},
            "top_detections": get_terms("alert_tag", "now-7d", 10),
            "incidents": get_incidents(12),
            "ml_top": _top_ml(size=6), "ueba_top": _top_ueba(size=6),
            "sla": src.get("sla", {}), "robots": src.get("robots", {}),
            "dark_hosts": src.get("dark_hosts", [])[:8],
            "sources": src.get("sources", []), "cluster": src.get("cluster"),
            "events_24h": src.get("events_24h")}


def get_geo_threats():
    out = {"countries": []}
    for field in ("src_ip_country_code", "srcip_country_code", "src_country"):
        res = os_search("omni-fortigate*", {"size": 0,
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}},
            "aggs": {"c": {"terms": {"field": field, "size": 14}}}})
        cc = [{"k": b["key"], "n": b["doc_count"]}
              for b in res.get("aggregations", {}).get("c", {}).get("buckets", [])
              if b.get("key") and b["key"] not in ("Reserved", "Private", "-", "")]
        if cc:
            out["countries"] = cc
            out["field"] = field
            break
    return out


def _top_ml(minutes=180, size=8):
    """Top entités par score d'anomalie ML (event_source=ml_anomaly, oms-ml)."""
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"term": {"event_source": "ml_anomaly"}},
                                      {"range": {"timestamp": {"gte": f"now-{minutes}m"}}}]}},
        "aggs": {"e": {"terms": {"field": "entity", "size": size, "order": {"s": "desc"}},
                       "aggs": {"s": {"max": {"field": "ml_score"}},
                                "h": {"top_hits": {"size": 1, "_source": ["ml_reason", "entity_type"],
                                                   "sort": [{"timestamp": {"order": "desc"}}]}}}}}})
    out = []
    for b in res.get("aggregations", {}).get("e", {}).get("buckets", []):
        hit = (((b.get("h", {}) or {}).get("hits", {}) or {}).get("hits", []) or [{}])[0].get("_source", {})
        out.append({"entity": _rd(b["key"]), "score": round((b.get("s", {}) or {}).get("value", 0) or 0, 1),
                    "reason": hit.get("ml_reason", ""), "type": hit.get("entity_type", "")})
    return out


def _top_ueba(hours=24, size=8):
    """Top entités par score UEBA statistique (event_source=ueba_score, 40-ueba-ndr)."""
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"term": {"event_source": "ueba_score"}},
                                      {"range": {"timestamp": {"gte": f"now-{hours}h"}}}]}},
        "aggs": {"e": {"terms": {"field": "ueba_entity", "size": size, "order": {"s": "desc"}},
                       "aggs": {"s": {"max": {"field": "ueba_score"}},
                                "h": {"top_hits": {"size": 1, "_source": ["ueba_top_factor"],
                                                   "sort": [{"timestamp": {"order": "desc"}}]}}}}}})
    out = []
    for b in res.get("aggregations", {}).get("e", {}).get("buckets", []):
        hit = (((b.get("h", {}) or {}).get("hits", {}) or {}).get("hits", []) or [{}])[0].get("_source", {})
        out.append({"entity": _rd(b["key"]), "score": int((b.get("s", {}) or {}).get("value", 0) or 0),
                    "factor": hit.get("ueba_top_factor", "")})
    return out


def get_risk():
    k = get_kpis()
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": [{"exists": {"field": "alert_tag"}}, {"exists": {"field": "user"}}],
                           "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}},
        "aggs": {"u": {"terms": {"field": "user", "size": 8},
                       "aggs": {"t": {"cardinality": {"field": "mitre_technique"}}}}}})
    ents = [{"k": _rd(b["key"]), "n": b["doc_count"], "tech": (b.get("t", {}) or {}).get("value", 0)}
            for b in res.get("aggregations", {}).get("u", {}).get("buckets", [])]
    ml_top = _top_ml()
    ueba_top = _top_ueba()
    crit = k.get("incidents_critiques_7j", 0)
    ueba = k.get("hotes_risque_ueba", 0)
    kev = k.get("kev_exposees", 0)
    ml_hi = sum(1 for m in ml_top if m["score"] >= 70)   # entités très anormales (ML)
    if crit >= 3:
        lvl = "CRITIQUE"
    elif crit >= 1:
        lvl = "ELEVE"
    elif ueba > 0 or kev > 0 or ml_hi > 0:
        lvl = "SURVEILLE"
    else:
        lvl = "NOMINAL"
    return {"threat_level": lvl, "critical_incidents": crit, "ueba": ueba, "kev": kev,
            "top_entities": ents, "ml_top": ml_top, "ueba_top": ueba_top, "ml_high": ml_hi}


def get_health():
    ch = {}
    try:
        ch = json.load(urllib.request.urlopen(OS_URL + "/_cluster/health", timeout=10))
    except Exception:
        ch = {}
    res = os_search("omni-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-24h"}}},
        "aggs": {"src": {"terms": {"field": "event_source", "size": 30},
                         "aggs": {"last": {"max": {"field": "timestamp"}}}},
                 "tot": {"value_count": {"field": "event_source"}}}})
    ag = res.get("aggregations", {})
    sources = [{"k": b["key"], "n": b["doc_count"], "last": (b.get("last", {}) or {}).get("value_as_string")}
               for b in ag.get("src", {}).get("buckets", [])]

    def _latest(flt, fields):  # dernier doc d'un robot interne (siem_health / collecte_sla)
        r = os_search("omni-*", {"size": 1, "sort": [{"timestamp": {"order": "desc"}}],
                                 "query": {"bool": {"filter": flt}}, "_source": fields})
        h = r.get("hits", {}).get("hits", [])
        return h[0].get("_source", {}) if h else {}

    robots = _latest([{"term": {"event_source": "siem_health"}}, {"term": {"health_type": "summary"}}],
                     ["health_ok", "health_fail", "health_total"])
    sla = _latest([{"term": {"event_source": "collecte_sla"}}, {"term": {"sla_type": "summary"}}],
                  ["sla_coverage_pct", "sla_active_24h", "sla_go_dark", "sla_expected"])
    dres = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"term": {"alert_tag": "host_go_dark"}},
                                      {"range": {"timestamp": {"gte": "now-26h"}}}]}},
        "aggs": {"h": {"terms": {"field": "dark_host", "size": 40},
                       "aggs": {"hrs": {"max": {"field": "hours_silent"}}}}}})
    dark = [{"host": _rd(b["key"]), "hours": round((b.get("hrs", {}) or {}).get("value", 0) or 0, 1)}
            for b in dres.get("aggregations", {}).get("h", {}).get("buckets", []) if b.get("key")]
    dark.sort(key=lambda d: -d["hours"])
    return {"cluster": ch.get("status", "?"), "nodes": ch.get("number_of_nodes"),
            "shards": ch.get("active_shards"), "events_24h": ag.get("tot", {}).get("value", 0),
            "sources": sources, "robots": robots, "sla": sla, "dark_hosts": dark}


def get_leaks():
    res = os_search("omni-*", {"size": 40, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [{"term": {"event_source": "leak_intel"}}],
                           "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}]}},
        "_source": ["timestamp", "leak_source", "alert_tag", "leak_victim", "leak_account",
                    "leak_breaches", "leak_repo", "leak_url", "short_message"],
        "aggs": {"src": {"terms": {"field": "leak_source", "size": 10}}}})
    items = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        items.append({"ts": s.get("timestamp"), "source": s.get("leak_source"), "tag": s.get("alert_tag"),
                      "label": s.get("leak_victim") or s.get("leak_account") or s.get("leak_repo") or "—",
                      "msg": s.get("short_message"), "url": s.get("leak_url"),
                      "breaches": s.get("leak_breaches")})
    counts = [{"k": b["key"], "n": b["doc_count"]} for b in res.get("aggregations", {}).get("src", {}).get("buckets", [])]
    return {"items": items, "sources": counts}


# --- anti brute-force login (par IP, en mémoire) ---
LOGIN_FAILS = {}
LOGIN_MAX = int(CONF.get("MOBILE_LOGIN_MAX", "5"))
LOGIN_WINDOW = int(CONF.get("MOBILE_LOGIN_WINDOW", "900"))  # 15 min


def login_locked(ip):
    rec = LOGIN_FAILS.get(ip)
    if not rec:
        return False
    if time.time() - rec[1] > LOGIN_WINDOW:
        LOGIN_FAILS.pop(ip, None)
        return False
    return rec[0] >= LOGIN_MAX


def login_fail(ip):
    now = time.time()
    rec = LOGIN_FAILS.get(ip)
    if not rec or now - rec[1] > LOGIN_WINDOW:
        LOGIN_FAILS[ip] = [1, now]
    else:
        rec[0] += 1


# ------------------------------------------------------------------------- handler
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencieux
        pass

    def _json(self, obj, code=200, cookie=None):
        body = json.dumps(_walk_redact(obj)).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _user(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        tok = c["oms_session"].value if "oms_session" in c else ""
        return verify_session(tok)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/m/api/vapid":
            return self._json({"publicKey": VAPID_PUB})
        if p == "/m/api/me":
            u = self._user()
            return self._json({"user": u} if u else {"user": None}, 200 if u else 401)
        if not self._user():
            return self._json({"error": "auth"}, 401)
        if p == "/m/api/alerts":
            return self._json({"alerts": get_alerts()})
        if p == "/m/api/incidents":
            return self._json({"incidents": get_incidents()})
        if p == "/m/api/cases":
            return self._json({"cases": get_cases()})
        if p == "/m/api/kpis":
            return self._json({"kpis": get_kpis()})
        if p == "/m/api/timeseries":
            return self._json({"series": get_timeseries()})
        if p == "/m/api/by-tactic":
            return self._json({"data": get_terms("mitre_tactic")})
        if p == "/m/api/top-detections":
            return self._json({"data": get_terms("alert_tag")})
        if p == "/m/api/top-sources":
            return self._json({"data": get_terms("event_source")})
        if p == "/m/api/attack-matrix":
            return self._json({"matrix": get_attack_matrix()})
        if p == "/m/api/leaks":
            return self._json(get_leaks())
        if p == "/m/api/health":
            return self._json(get_health())
        if p == "/m/api/risk":
            return self._json(get_risk())
        if p == "/m/api/geo":
            return self._json(get_geo_threats())
        if p == "/m/api/report":
            return self._json(get_report())
        if p == "/m/api/detections":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._json(get_detections(qs.get("tactic", [""])[0], qs.get("source", [""])[0], qs.get("tag", [""])[0], qs.get("technique", [""])[0]))
        if p == "/m/api/graph":
            return self._json(get_graph())
        if p == "/m/api/entity":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            def _qi(k, d):
                try:
                    return max(0, int(qs.get(k, [str(d)])[0]))
                except (ValueError, TypeError):
                    return d
            return self._json(get_entity(qs.get("u", [""])[0], _qi("size", 20), _qi("from", 0)))
        if p == "/m/api/investigate":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            try:
                _days = max(1, min(90, int(qs.get("days", ["14"])[0])))
            except (ValueError, TypeError):
                _days = 14
            return self._json(get_investigation(qs.get("u", [""])[0], _days))
        if p == "/m/api/guidance":
            return self._json({"guidance": get_guidance()})
        if p == "/m/api/entity-search":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._json({"results": get_entity_search(qs.get("q", [""])[0])})
        if p == "/m/api/kpi-trend":
            return self._json({"trend": get_kpi_trend()})
        if p == "/m/api/leaks2":
            return self._json(get_leaks_v2())
        if p == "/m/api/stream":
            return self._sse()
        self._json({"error": "not found"}, 404)

    def _sse(self):
        import time as _t
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last = None
        try:
            while True:
                rng = {"gt": last} if last else {"gte": "now-2m"}
                res = os_search("omni-*", {"size": 20, "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {"bool": {"must": [{"exists": {"field": "alert_tag"}}],
                                       "filter": [{"range": {"timestamp": rng}}]}},
                    "_source": ["timestamp", "alert_tag", "mitre_technique", "user", "short_message",
                                "message", "priority", "key", "risk_severity"]})
                for h in reversed(res.get("hits", {}).get("hits", [])):
                    s = h.get("_source", {}); ts = s.get("timestamp")
                    if ts:
                        last = ts
                    ev = {"ts": ts, "tag": s.get("alert_tag"), "tech": s.get("mitre_technique"),
                          "user": _rd(s.get("user")), "entity": _rd(s.get("key")), "priority": s.get("priority"),
                          "sev": s.get("risk_severity"),
                          "msg": _scrub(s.get("short_message") or s.get("message"))}
                    self.wfile.write(("data: " + json.dumps(ev) + "\n\n").encode()); self.wfile.flush()
                self.wfile.write(b": hb\n\n"); self.wfile.flush()
                _t.sleep(4)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def do_POST(self):
        p = self.path.split("?")[0]
        b = self._body()
        if p == "/m/api/login":
            ip = self.headers.get("X-Real-IP") or self.client_address[0]
            if login_locked(ip):
                return self._json({"ok": False, "error": "rate_limited"}, 429)
            if graylog_login(str(b.get("username", "")), str(b.get("password", ""))):
                LOGIN_FAILS.pop(ip, None)
                tok = sign_session(str(b.get("username")))
                ck = f"oms_session={tok}; Path=/m; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}"
                return self._json({"ok": True, "user": b.get("username")}, cookie=ck)
            login_fail(ip)
            return self._json({"ok": False}, 401)
        if p == "/m/api/logout":
            return self._json({"ok": True}, cookie="oms_session=; Path=/m; Max-Age=0")
        if p == "/m/api/case":
            if not self._user():
                return self._json({"error": "auth"}, 401)
            return self._json(update_case(b, self._user()))
        if p == "/m/api/subscribe":
            if not self._user():
                return self._json({"error": "auth"}, 401)
            sub = b.get("subscription")
            if sub and sub.get("endpoint"):
                subs = [s for s in load_subs() if s.get("endpoint") != sub["endpoint"]]
                subs.append(sub)
                save_subs(subs)
                return self._json({"ok": True})
            return self._json({"ok": False}, 400)
        if p == "/m/api/push":
            # webhook Graylog (localhost) : secret partagé (query ?secret=, body ou header)
            import urllib.parse as _up
            qsec = _up.parse_qs(self.path.split("?", 1)[1]).get("secret", [""])[0] if "?" in self.path else ""
            if PUSH_SECRET not in (qsec, b.get("secret"), self.headers.get("X-Push-Secret")):
                return self._json({"error": "forbidden"}, 403)
            # accepte un payload {title,body} OU le format de notification Graylog
            title = b.get("title") or b.get("event_definition_title") or "Alerte SIEM critique"
            ev = b.get("event") or {}
            body = b.get("body") or ev.get("message") or ev.get("key") or "Ouvrir l'app pour le détail"
            sent = push_all(str(title)[:90], str(body)[:140])
            return self._json({"sent": sent})
        self._json({"error": "not found"}, 404)


def push_all(title: str, body: str) -> int:
    """Envoie un web-push minimal à tous les abonnés (payload non sensible)."""
    try:
        from pywebpush import webpush, WebPushException  # type: ignore
    except ImportError:
        return -1
    if not os.path.exists(VAPID_PRIV_FILE):
        return -1
    priv = open(VAPID_PRIV_FILE).read()
    payload = json.dumps({"title": title, "body": body})[:300]
    subs = load_subs()
    ok, dead = 0, []
    for s in subs:
        try:
            webpush(subscription_info=s, data=payload, vapid_private_key=priv,
                    vapid_claims={"sub": VAPID_SUBJECT}, timeout=10)
            ok += 1
        except WebPushException as e:
            if getattr(e, "response", None) is not None and e.response.status_code in (404, 410):
                dead.append(s.get("endpoint"))
        except Exception:
            pass
    if dead:
        save_subs([s for s in subs if s.get("endpoint") not in dead])
    return ok


# =========================================================== micro-cache mémoire
# Cache mémoire à TTL, thread-safe. But (perf) : ne pas relancer la même agrégation
# lourde (terms 300 de la matrice ATT&CK, fan-out de /report, kpi_trend = 8 _count,
# health, geo) à chaque client/cycle de poll. Clé = nom + args + état REDACT (sinon
# on servirait une réponse rédigée à un client non-rédigé). TTL court (25-45 s) :
# fraîcheur quasi temps réel acceptable sur des agrégats. Jamais le SSE ni les POST.
import functools as _functools

_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
CACHE_TTL = int(CONF.get("MOBILE_CACHE_TTL", "30"))   # secondes ; 0 = désactivé


def _cache_key(name, args, kwargs):
    return (name, "1" if REDACT else "0", repr(args), repr(tuple(sorted(kwargs.items()))))


def cached(ttl=None):
    """Décorateur : mémorise le retour pendant `ttl` s. Signature inchangée."""
    def deco(fn):
        @_functools.wraps(fn)
        def wrap(*args, **kwargs):
            t = CACHE_TTL if ttl is None else ttl
            if t <= 0:
                return fn(*args, **kwargs)
            key = _cache_key(fn.__name__, args, kwargs)
            now = time.monotonic()
            with _CACHE_LOCK:
                hit = _CACHE.get(key)
                if hit is not None and hit[0] > now:
                    return hit[1]
            val = fn(*args, **kwargs)   # calcul hors verrou
            with _CACHE_LOCK:
                _CACHE[key] = (time.monotonic() + t, val)
            return val
        return wrap
    return deco


# Ré-assignation APRÈS définition : get_report()/get_kpi_trend()/get_risk() appellent
# alors les versions enveloppées. NON enveloppés : _sse, flux vivants, écritures.
get_kpis          = cached()(get_kpis)
get_kpi_trend     = cached()(get_kpi_trend)
get_terms         = cached()(get_terms)
get_attack_matrix = cached()(get_attack_matrix)
get_health        = cached()(get_health)
get_geo_threats   = cached()(get_geo_threats)
get_report        = cached()(get_report)
get_timeseries    = cached(20)(get_timeseries)


if __name__ == "__main__":
    ThreadingHTTPServer(LISTEN, H).serve_forever()
