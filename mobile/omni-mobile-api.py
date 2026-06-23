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

LISTEN = (CONF.get("MOBILE_BIND", "127.0.0.1"), int(CONF.get("MOBILE_PORT", "8090")))
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
            # contexte structure (qui/ou/quoi) issu du field_spec de l'event definition
            "fields": {k: _rd(v) for k, v in (s.get("fields") or {}).items() if v not in (None, "", "null")},
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


def get_terms(field, gte="now-7d", size=8, tagged=True):
    # tagged=False : compte TOUTE l'activite (pas seulement les detections) -> rend les
    # sources benignes (aruba/linux/dns : ports/STP/CADownload) visibles dans top-sources.
    must = [{"exists": {"field": "alert_tag"}}] if tagged else []
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": must,
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
    _SR = {"critique": 4, "critical": 4, "eleve": 3, "élevé": 3, "high": 3,
           "moyen": 2, "medium": 2, "faible": 1, "low": 1}
    tac = {}
    for tech, name, tactic, sev in rows:
        d = tac.setdefault(tactic, {})
        if tech not in d:
            d[tech] = {"id": tech, "name": name, "count": counts.get(tech, 0), "sev": sev}
        elif _SR.get((sev or "").lower(), 0) > _SR.get((d[tech]["sev"] or "").lower(), 0):
            d[tech]["sev"] = sev          # technique mappée par N tags -> garder la sévérité MAX
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


# --- Watchlist : entités à surveiller (compromission suspectée, suivi) ----------
WATCH_FILE = CONF.get("MOBILE_WATCH_FILE", "/var/lib/omni-mobile/watchlist.json")
_WATCH_LOCK = threading.Lock()


def load_watch():
    try:
        with open(WATCH_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_watch(w):
    os.makedirs(os.path.dirname(WATCH_FILE), exist_ok=True)
    tmp = WATCH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(w, f)
    os.replace(tmp, WATCH_FILE)


def _watch_key(ent):
    return ((_identity_key(ent) or ent) if ent else "").lower()


def is_watched(ent):
    return _watch_key(ent) in load_watch() if ent else False


def get_watchlist():
    """Entités sous surveillance, triées par date d'ajout, avec leur risque fusionné réévalué."""
    w = load_watch()
    out = []
    for key, e in sorted(w.items(), key=lambda kv: kv[1].get("ts", ""), reverse=True):
        ent = e.get("entity", key)
        try:
            r = (get_entity(ent) or {}).get("risk", {}) or {}
        except Exception:
            r = {}
        out.append({"entity": _rd(ent), "by": _rd(e.get("by", "")), "ts": e.get("ts", ""),
                    "note": _rd(e.get("note", "")),
                    "risk": {"score": r.get("score"), "label": r.get("label")}})
    return out


def update_watch(b, who):
    ent = (b.get("entity") or "").strip()
    if not ent:
        return {"ok": False}
    ent = _RD_REV.get(ent, ent)            # mode rédigé : pseudo -> réel
    import datetime as _dt
    key, act = _watch_key(ent), b.get("action", "toggle")
    with _WATCH_LOCK:
        w = load_watch()
        if act == "remove" or (act == "toggle" and key in w):
            w.pop(key, None); watched = False
        else:
            w[key] = {"entity": ent, "by": who or "?", "note": str(b.get("note", ""))[:300],
                      "ts": _dt.datetime.now().isoformat(timespec="seconds")}
            watched = True
        save_watch(w)
    return {"ok": True, "watched": watched, "count": len(w)}


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


_SEVMAP = {"critical": 92, "critique": 92, "high": 72, "eleve": 72, "élevé": 72, "eleve ": 72,
           "medium": 48, "moyen": 48, "low": 22, "faible": 22, "info": 12, "informational": 12}

def _det_score(sc):
    """Sévérité des détections en score : une CRITIQUE pose un plancher haut (rare + grave) ;
    les 'hautes' comptent par CONCENTRATION (une règle qui tire est courante, une RAFALE est
    un signal) — sinon le max-de-sévérité rendrait toute entité active « critique »."""
    crit = high = med = 0
    for sev, n in (sc or {}).items():
        v = _SEVMAP.get(str(sev).strip().lower(), 30)
        if v >= 90:
            crit += n
        elif v >= 72:
            high += n
        elif v >= 40:
            med += n
    return (min(96, 86 + min(10, crit)) if crit else
            66 if high >= 10 else 52 if high >= 3 else 40 if high >= 1 else 28 if med else 12)


def _fused_risk(scores, sev_all, total_det, sev_recent=None):
    """Score de risque FUSIONNÉ d'une entité : combine 3 signaux INDÉPENDANTS — anomalie ML
    (oms-ml), comportement UEBA, et sévérité des détections. Le signal dominant fixe le
    plancher ; la CORROBORATION (≥2 signaux élevés) ajoute un bonus borné. **RÉCENCE** : si
    la sévérité RÉCENTE (72 h) est fournie, elle DOMINE le composant détection (l'historique
    7 j ne pèse qu'à 55 %) → le score reflète le risque ACTUEL, pas un pic ancien/purgé."""
    ml = round((scores.get("ml") or {}).get("score") or 0)
    ueba = round((scores.get("ueba") or {}).get("score") or 0)
    det = (_det_score(sev_all) if sev_recent is None
           else max(_det_score(sev_recent), round(0.55 * _det_score(sev_all))))
    comps = {"ml": ml, "ueba": ueba, "detection": det}
    base = max(comps.values())
    elevated = sum(1 for v in comps.values() if v >= 50)
    boost = min(15, (elevated - 1) * 8) if elevated >= 2 else 0   # corroboration
    fused = min(100, round(base + boost))
    label = ("critical" if fused >= 80 else "high" if fused >= 60 else
             "moderate" if fused >= 35 else "low" if fused >= 15 else "minimal")
    return {"score": fused, "label": label, "components": comps,
            "corroboration": elevated, "n_detections": int(total_det or 0)}


# --- Corrélation d'identité : unifier les représentations d'un même humain -----
# DOMAINE\user, user@dom, ADM-user, user-adm -> même identité logique. CONSERVATEUR :
# les comptes machine ($) ne sont JAMAIS fusionnés ; un humain et son compte admin
# (adm-X) sont reconnus comme la même personne (convention de nommage du parc).
_ID_PREFIX = re.compile(r"^(adm|admin|a)[-_.]", re.I)
_ID_SUFFIX = re.compile(r"[-_.](adm|admin)$", re.I)


def _identity_key(name):
    s = str(name or "").strip()
    if not s:
        return ""
    if "\\" in s:
        s = s.rsplit("\\", 1)[-1]
    if "@" in s:
        s = s.split("@", 1)[0]
    s = s.strip().lower()
    if not s or s.endswith("$"):          # compte machine -> identité = lui-même
        return s
    s = _ID_PREFIX.sub("", s)
    s = _ID_SUFFIX.sub("", s)
    return s


def _linked_accounts(name, days=14):
    """Comptes réels partageant l'identité logique de `name` (variantes domaine/admin)."""
    real = _RD_REV.get(name, name)
    key = _identity_key(real)
    if not key or key.endswith("$") or len(key) < 3:
        return [real] if real else []
    try:
        res = os_search("omni-*", {"size": 0,
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}],
                               "must": [{"wildcard": {"user": {"value": f"*{key}*", "case_insensitive": True}}}]}},
            "aggs": {"u": {"terms": {"field": "user", "size": 50}}}})
        out = [b["key"] for b in res.get("aggregations", {}).get("u", {}).get("buckets", [])
               if b.get("key") and _identity_key(b["key"]) == key]
    except Exception:
        out = []
    if real and real not in out:
        out.append(real)
    return out or [real]


def get_entity(name, size=20, frm=0):
    if not name:
        return {"name": "", "total": 0, "techniques": [], "tactics": [], "events": [], "linked": [],
                "from": 0, "size": size, "loaded": 0, "has_more": False,
                "scores": {"ml": {"score": None, "reason": ""}, "ueba": {"score": None, "factor": ""}}}
    name = _RD_REV.get(name, name)   # mode rédigé : pseudo -> réel pour la requête
    size = max(1, min(int(size), 200))
    frm = max(0, int(frm))
    linked = _linked_accounts(name, 7)   # vue UNIFIÉE : tous les comptes de la personne
    q = {"bool": {"must": [{"terms": {"user": linked}}, {"exists": {"field": "alert_tag"}}],
                  "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}}
    res = os_search("omni-*", {"size": size, "from": frm, "track_total_hits": True,
        "sort": [{"timestamp": {"order": "desc"}}], "query": q,
        "_source": ["timestamp", "alert_tag", "mitre_technique", "short_message", "message"],
        "aggs": {"tech": {"terms": {"field": "mitre_technique", "size": 8}},
                 "tac": {"terms": {"field": "mitre_tactic", "size": 8}},
                 "sev": {"terms": {"field": "risk_severity", "size": 6}},
                 "sev_recent": {"filter": {"range": {"timestamp": {"gte": "now-72h"}}},
                                "aggs": {"s": {"terms": {"field": "risk_severity", "size": 6}}}},
                 "tot": {"value_count": {"field": "alert_tag"}}}})
    ag = res.get("aggregations", {})
    ev = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        ev.append({"ts": s.get("timestamp"), "tag": s.get("alert_tag"), "tech": s.get("mitre_technique"),
                   "msg": s.get("short_message") or s.get("message")})
    th = res.get("hits", {}).get("total", {})
    th = th.get("value", 0) if isinstance(th, dict) else (th or 0)
    scores = _entity_scores(name)
    sev_counts = {b["key"]: b["doc_count"] for b in ag.get("sev", {}).get("buckets", [])}
    sev_recent = {b["key"]: b["doc_count"] for b in ag.get("sev_recent", {}).get("s", {}).get("buckets", [])}
    return {"name": _rd(name), "total": ag.get("tot", {}).get("value", 0),
            "from": frm, "size": size, "loaded": frm + len(ev), "has_more": (frm + len(ev)) < th,
            "scores": scores, "risk": _fused_risk(scores, sev_counts, th, sev_recent), "watched": is_watched(name),
            "linked": [_rd(u) for u in linked] if len(linked) > 1 else [],
            "techniques": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("tech", {}).get("buckets", [])],
            "tactics": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("tac", {}).get("buckets", [])],
            "events": ev}


def get_entity_network(name, days=14):
    """Activité réseau/infra d'une entité pour le dossier 360° : sessions/échecs admin
    switch (Aruba), SSH/sudo (Linux), où l'entité = une IP (src_ip/aruba_client_ip) ou un
    hôte (source). Relie une IP brute-forçant l'admin switch a son dossier. Lecture seule.
    Ne renvoie 'found' que si l'entité a une activité réseau/infra."""
    name = (name or "").strip()
    if not name:
        return {"found": False}
    name = _RD_REV.get(name, name)
    short = name.split("\\")[-1].split("@")[0]
    cands = list({name, short})
    q = {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{int(days)}d"}}}],
                  "minimum_should_match": 1,
                  "should": [{"terms": {"src_ip": cands}},
                             {"terms": {"aruba_client_ip": cands}},
                             {"terms": {"source": cands}}]}}
    res = os_search("omni-aruba*,omni-linux*,omni-fortiems*", {
        "size": 12, "sort": [{"timestamp": {"order": "desc"}}], "track_total_hits": True, "query": q,
        "aggs": {"tags": {"filter": {"exists": {"field": "alert_tag"}},
                          "aggs": {"t": {"terms": {"field": "alert_tag", "size": 8}}}},
                 "src": {"terms": {"field": "event_source", "size": 4}}},
        "_source": ["timestamp", "event_source", "source", "aruba_switch_name", "aruba_subsystem",
                    "src_ip", "net_segment", "alert_tag", "message"]})
    hits = res.get("hits", {})
    total = hits.get("total", {})
    total = total.get("value", 0) if isinstance(total, dict) else (total or 0)
    if not total:
        return {"found": False, "entity": short}
    ag = res.get("aggregations", {})
    events = [{"ts": s.get("timestamp"), "src": s.get("event_source"),
               "host": _rd(s.get("aruba_switch_name") or s.get("source")),
               "sub": s.get("aruba_subsystem"), "tag": s.get("alert_tag"),
               "ip": s.get("src_ip"), "seg": s.get("net_segment"), "msg": _scrub(s.get("message"))}
              for s in (h.get("_source", {}) for h in hits.get("hits", []))]
    return {"found": True, "entity": short, "total": total,
            "sources": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("src", {}).get("buckets", [])],
            "tags": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("tags", {}).get("t", {}).get("buckets", [])],
            "events": events}


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
    wc_i = {"wildcard": {"src_ip": {"value": f"*{q}*", "case_insensitive": True}}}
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-7d"}}}],
                           "minimum_should_match": 1, "should": [wc_u, wc_h, wc_i]}},
        "aggs": {"u": {"filter": wc_u, "aggs": {"t": {"terms": {"field": "user", "size": size}}}},
                 "h": {"filter": wc_h, "aggs": {"t": {"terms": {"field": "source", "size": size}}}},
                 "i": {"filter": wc_i, "aggs": {"t": {"terms": {"field": "src_ip", "size": size}}}}}})
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
            seen.add(_rd(k))
    for b in ag.get("i", {}).get("t", {}).get("buckets", []):
        k = b.get("key")
        if k and _rd(k) not in seen:
            out.append({"entity": _rd(k), "n": b["doc_count"], "kind": "ip"})
            seen.add(_rd(k))
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
    # vue UNIFIÉE : on agrège sur TOUS les comptes de la personne (DOMAINE\X, ADM-X…)
    linked = _linked_accounts(name, days)
    key = _identity_key(name)
    ent = {"bool": {"minimum_should_match": 1, "should": (
        [{"term": {"user": u}} for u in linked]
        + [{"match_phrase": {"upn": key or name}}, {"term": {"identity": name}},
           {"term": {"source": name}}])}}   # + upn (email par base), identity, source (hôte)

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
            "detections": dets, "sources": sources,
            "linked": [_rd(u) for u in linked] if len(linked) > 1 else []}


def get_entity_timeline(name, days=14, limit=60):
    """Chronologie UNIFIÉE d'une entité (tous comptes liés) : le RÉCIT — détections,
    échecs d'authentification Windows (4625) et sign-ins M365 fusionnés et triés par
    date. On exclut les logons Windows RÉUSSIS (4624) = bruit routinier ; on garde le
    signal (détections + échecs + auth cloud) pour raconter ce qui s'est passé."""
    if not name:
        return {"items": [], "linked": []}
    name = _RD_REV.get(name, name)
    days = max(1, min(int(days), 90))
    limit = max(10, min(int(limit), 200))
    linked = _linked_accounts(name, days)
    key = _identity_key(name)
    ent = {"bool": {"minimum_should_match": 1, "should": (
        [{"term": {"user": u}} for u in linked]
        + [{"match_phrase": {"upn": key or name}}, {"term": {"source": name}}])}}
    sig = {"bool": {"minimum_should_match": 1, "should": [
        {"exists": {"field": "alert_tag"}},                 # détections
        {"term": {"event_id": "4625"}},                     # logon Windows échoué
        {"term": {"m365_type": "signin"}}]}}                # sign-in M365 (succès/échec)
    res = os_search("omni-*", {"size": limit, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [ent, sig], "filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]}},
        "_source": ["timestamp", "alert_tag", "mitre_technique", "risk_severity", "event_source",
                    "short_message", "message", "m365_type", "status_code", "m365_fail_label",
                    "event_id", "src_ip", "src_ip_country_code"]})
    out = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        tag, eid = s.get("alert_tag"), str(s.get("event_id") or "")
        if tag:
            out.append({"ts": s.get("timestamp"), "kind": "detection", "sev": s.get("risk_severity") or "",
                        "label": tag, "tech": s.get("mitre_technique") or "", "src": s.get("event_source") or "",
                        "detail": (s.get("short_message") or s.get("message") or "")[:140]})
        elif s.get("m365_type") == "signin":
            ok = str(s.get("status_code")) == "0"
            out.append({"ts": s.get("timestamp"), "kind": "m365", "ok": ok, "label": "M365 sign-in",
                        "ip": _rd(s.get("src_ip") or ""), "cc": s.get("src_ip_country_code") or "",
                        "code": s.get("status_code"), "detail": s.get("m365_fail_label") or ""})
        elif eid == "4625":
            out.append({"ts": s.get("timestamp"), "kind": "winlogon", "ok": False, "label": "Windows logon",
                        "ip": _rd(s.get("src_ip") or ""), "detail": ""})
    return {"items": out, "linked": [_rd(u) for u in linked] if len(linked) > 1 else []}


def get_entities_browse(days=7):
    """Page Entités : top COMPTES et top MACHINES, classés par SCORE DE RISQUE FUSIONNÉ
    (ML + UEBA + sévérité détections) — point de départ priorisé. Efficient : 2 cartes de
    score (ml/ueba par nom nu) + 2 requêtes top avec sous-agg sévérité, pas de boucle/entité."""
    days = max(1, min(int(days), 90))
    gte = f"now-{days}d"

    def _bare(s):
        return str(s or "").split("\\")[-1].split("@")[0].strip().lower()

    def _scoremap(src, score_field, key_field):
        r = os_search("omni-*", {"size": 0,
            "query": {"bool": {"filter": [{"term": {"event_source": src}},
                                          {"range": {"timestamp": {"gte": gte}}}]}},
            "aggs": {"e": {"terms": {"field": key_field, "size": 80},
                           "aggs": {"s": {"max": {"field": score_field}}}}}})
        m = {}
        for b in r.get("aggregations", {}).get("e", {}).get("buckets", []):
            k, v = _bare(b.get("key")), (b.get("s", {}) or {}).get("value")
            if k and v is not None:
                m[k] = max(m.get(k, 0), v)
        return m
    ml_map = _scoremap("ml_anomaly", "ml_score", "entity")
    ue_map = _scoremap("ueba_score", "ueba_score", "ueba_entity")
    wk = set(load_watch().keys())          # entités sous surveillance (1 lecture)

    def _top(field, is_user):
        r = os_search("omni-*", {"size": 0,
            "query": {"bool": {"must": [{"exists": {"field": "alert_tag"}}, {"exists": {"field": field}}],
                               "filter": [{"range": {"timestamp": {"gte": gte}}}]}},
            "aggs": {"e": {"terms": {"field": field, "size": 18},
                           "aggs": {"sev": {"terms": {"field": "risk_severity", "size": 6}},
                                    "sev_recent": {"filter": {"range": {"timestamp": {"gte": "now-72h"}}},
                                                   "aggs": {"s": {"terms": {"field": "risk_severity", "size": 6}}}}}}}})
        out = []
        for b in r.get("aggregations", {}).get("e", {}).get("buckets", []):
            if not b.get("key"):
                continue
            sev = {x["key"]: x["doc_count"] for x in (b.get("sev", {}) or {}).get("buckets", [])}
            sevr = {x["key"]: x["doc_count"] for x in (b.get("sev_recent", {}) or {}).get("s", {}).get("buckets", [])}
            bare = _bare(b["key"])
            sc = {"ml": {"score": ml_map.get(bare) if is_user else None},
                  "ueba": {"score": ue_map.get(bare) if is_user else None}}
            fr = _fused_risk(sc, sev, b["doc_count"], sevr)
            out.append({"entity": _rd(b["key"]), "n": b["doc_count"],
                        "risk": {"score": fr["score"], "label": fr["label"]},
                        "watched": _watch_key(b["key"]) in wk})
        out.sort(key=lambda e: -e["risk"]["score"])
        return out
    return {"users": _top("user", True), "machines": _top("source", False)}


_LOOKDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lookups")
_GUIDANCE_PATH = os.path.join(_LOOKDIR, "alert-guidance.json")
_MITRE_PATH = os.path.join(_LOOKDIR, "mitre-attack.csv")
_GUIDANCE = {"mtime": -1.0, "data": {}}
_MITRE = {"mtime": -1.0, "data": {}}


def _load_mitre():
    try:
        m = os.path.getmtime(_MITRE_PATH)
        if m != _MITRE["mtime"]:
            import csv
            d = {}
            with open(_MITRE_PATH, encoding="utf-8") as fh:
                for r in csv.DictReader(fh):
                    d[r["alert_tag"]] = {"technique": r.get("technique", ""), "name": r.get("technique_name", ""),
                                         "tactic": r.get("tactic", ""), "severity": r.get("severity", "")}
            _MITRE["data"] = d
            _MITRE["mtime"] = m
    except Exception:
        pass
    return _MITRE["data"]


def get_guidance():
    """Aide à la décision par détection (`alert_tag`) : ce que c'est, à vérifier
    (triage), remédiation, correction durable + contexte MITRE (tactique/technique).
    Connaissance STATIQUE (aucune PII) ; rechargée à chaud. Triage/réponse + Playbooks."""
    try:
        m = os.path.getmtime(_GUIDANCE_PATH)
        if m != _GUIDANCE["mtime"]:
            with open(_GUIDANCE_PATH, encoding="utf-8") as fh:
                _GUIDANCE["data"] = json.load(fh)
            _GUIDANCE["mtime"] = m
    except Exception:
        pass
    mit = _load_mitre()
    return {tag: {**g, **mit.get(tag, {})} for tag, g in _GUIDANCE["data"].items()}


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
    net = get_network()
    ems = get_fortiems()
    return {"kpis": get_kpis(),
            "coverage": {"techniques": sum(len(c["techniques"]) for c in cov), "tactics": len(cov)},
            "top_detections": get_terms("alert_tag", "now-7d", 10),
            "incidents": get_incidents(12),
            "ml_top": _top_ml(size=6), "ueba_top": _top_ueba(size=6),
            "sla": src.get("sla", {}), "robots": src.get("robots", {}),
            "dark_hosts": src.get("dark_hosts", [])[:8],
            "sources": src.get("sources", []), "cluster": src.get("cluster"),
            "events_24h": src.get("events_24h"),
            "integrations": src.get("integrations", []),
            "network": {"switches": net.get("aruba", {}).get("switches_seen", 0),
                        "aruba": net.get("aruba", {}).get("total", 0),
                        "linux": net.get("linux", {}).get("total", 0),
                        "dns": net.get("dns", {}).get("total", 0)},
            "endpoint_ems": {"malware": ems.get("malware", 0), "vuln": ems.get("vuln", 0),
                             "av_off": ems.get("av_off", 0), "total": ems.get("total", 0)}}


OMS_GEO = {"lat": 45.5853, "lng": 5.2741, "label": "OMNITECH · Bourgoin (FR)"}
_MENACE = {"bool": {"minimum_should_match": 1, "should": [
    {"exists": {"field": "alert_tag"}},
    {"term": {"event_action": "echec_connexion"}},
    {"bool": {"filter": [{"term": {"event_source": "bunkerweb"}}, {"range": {"http_status": {"gte": 400, "lt": 500}}}]}},
    {"bool": {"filter": [{"term": {"event_source": "fortigate"}}, {"terms": {"action": ["deny", "blocked", "dropped", "drop"]}}]}},
]}}


def get_geo_flows(hours=3, top=150):
    """Flux geolocalises monde -> OMNITECH (carte/globe 3D facon attack-map).
    Agrege par coordonnee (src_ip_geolocation, top N), separe menace/trafic, +
    detail des derniers evenements de menace + top pays attaquants. Donnees REELLES
    (GeoIP DB-IP sur les IP publiques : fortigate/m365/bunkerweb)."""
    since = f"now-{int(hours)}h"
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"exists": {"field": "src_ip_geolocation"}},
                                       {"range": {"timestamp": {"gte": since}}}]}},
        "aggs": {"loc": {"terms": {"field": "src_ip_geolocation", "size": int(top)},
                         "aggs": {"men": {"filter": _MENACE},
                                  "cc": {"terms": {"field": "src_ip_country_code", "size": 1}},
                                  "src": {"terms": {"field": "event_source", "size": 1}}}}}})
    arcs = []
    for b in res.get("aggregations", {}).get("loc", {}).get("buckets", []):
        try:
            lat, lng = (float(x) for x in str(b["key"]).split(","))
        except (ValueError, TypeError):
            continue
        n = b["doc_count"]
        men = b.get("men", {}).get("doc_count", 0)
        cc = (b.get("cc", {}).get("buckets") or [{}])[0].get("key", "?")
        src = (b.get("src", {}).get("buckets") or [{}])[0].get("key", "")
        arcs.append({"lat": round(lat, 3), "lng": round(lng, 3), "n": n, "threat": men,
                     "cc": cc, "src": src, "kind": "menace" if men > 0 else "trafic"})
    # detail des derniers evenements de MENACE (geolocalises)
    rd = os_search("omni-*", {"size": 16, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [{"exists": {"field": "src_ip_geolocation"}},
                                      {"range": {"timestamp": {"gte": since}}}], "must": [_MENACE]}},
        "_source": ["timestamp", "src_ip", "src_ip_country_code", "src_ip_city_name", "user",
                    "event_source", "event_action", "alert_tag", "http_status", "src_ip_geolocation"]})
    recent = []
    for h in rd.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        try:
            la, lo = (float(x) for x in str(s.get("src_ip_geolocation", "")).split(","))
        except (ValueError, TypeError):
            la = lo = None
        recent.append({"ts": s.get("timestamp"), "ip": s.get("src_ip"),
                       "cc": s.get("src_ip_country_code"), "city": s.get("src_ip_city_name"),
                       "user": _rd(s.get("user")), "src": s.get("event_source"),
                       "what": s.get("alert_tag") or s.get("event_action") or s.get("event_source"),
                       "lat": la, "lng": lo})
    # top pays attaquants (menace)
    tc = os_search("omni-*", {"size": 0,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": since}}}], "must": [_MENACE]}},
        "aggs": {"c": {"terms": {"field": "src_ip_country_code", "size": 12}}}})
    topc = [{"cc": b["key"], "n": b["doc_count"]}
            for b in tc.get("aggregations", {}).get("c", {}).get("buckets", [])
            if b.get("key") not in (None, "", "Reserved", "Private", "-")]
    return {"oms": OMS_GEO, "hours": int(hours), "arcs": arcs, "recent": recent,
            "top_countries": topc,
            "totals": {"arcs": len(arcs), "menace": sum(a["threat"] for a in arcs),
                       "flux": sum(a["n"] for a in arcs)}}


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
        "aggs": {"u": {"terms": {"field": "user", "size": 18},
                       "aggs": {"t": {"cardinality": {"field": "mitre_technique"}},
                                "sev": {"terms": {"field": "risk_severity", "size": 6}},
                                "sev_recent": {"filter": {"range": {"timestamp": {"gte": "now-72h"}}},
                                               "aggs": {"s": {"terms": {"field": "risk_severity", "size": 6}}}}}}}})
    # Classement par RISQUE FUSIONNÉ (ML+UEBA+sévérité), pas par simple volume de détections.
    def _bare(s):
        return str(s or "").split("\\")[-1].split("@")[0].strip().lower()

    def _smap(src, sf, kf):
        r = os_search("omni-*", {"size": 0,
            "query": {"bool": {"filter": [{"term": {"event_source": src}}, {"range": {"timestamp": {"gte": "now-7d"}}}]}},
            "aggs": {"e": {"terms": {"field": kf, "size": 80}, "aggs": {"s": {"max": {"field": sf}}}}}})
        m = {}
        for b in r.get("aggregations", {}).get("e", {}).get("buckets", []):
            kk, vv = _bare(b.get("key")), (b.get("s", {}) or {}).get("value")
            if kk and vv is not None:
                m[kk] = max(m.get(kk, 0), vv)
        return m
    _mlm, _uem = _smap("ml_anomaly", "ml_score", "entity"), _smap("ueba_score", "ueba_score", "ueba_entity")
    _wk = set(load_watch().keys())
    ents = []
    for b in res.get("aggregations", {}).get("u", {}).get("buckets", []):
        bare = _bare(b.get("key"))
        sev = {x["key"]: x["doc_count"] for x in (b.get("sev", {}) or {}).get("buckets", [])}
        sevr = {x["key"]: x["doc_count"] for x in (b.get("sev_recent", {}) or {}).get("s", {}).get("buckets", [])}
        fr = _fused_risk({"ml": {"score": _mlm.get(bare)}, "ueba": {"score": _uem.get(bare)}}, sev, b["doc_count"], sevr)
        ents.append({"k": _rd(b["key"]), "n": b["doc_count"], "tech": (b.get("t", {}) or {}).get("value", 0),
                     "risk": {"score": fr["score"], "label": fr["label"]}, "watched": _watch_key(b.get("key")) in _wk})
    ents.sort(key=lambda e: -e["risk"]["score"])
    ents = ents[:8]
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
                     ["health_ok", "health_fail", "health_total", "health_maint"])
    # rappel de maintenance (reboot sécurité) — distinct d'une panne de robot.
    # Piloté par le DERNIER run self-health (health_maint, qui re-vérifie needrestart/
    # reboot-required à chaque passage) et NON par un vieil événement reboot_required :
    # sinon la bannière persiste après le reboot qui a pourtant résolu la MAJ (le vieil
    # événement reste dans la fenêtre temporelle). health_maint=0 => plus de bannière.
    maint = None
    if int((robots or {}).get("health_maint", 0) or 0) > 0:
        maint = _latest([{"term": {"event_source": "siem_health"}}, {"term": {"health_type": "reboot_required"}},
                         {"range": {"timestamp": {"gte": "now-3h"}}}],
                        ["message", "short_message", "health_reason"])
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
    # Référentiel des sources ATTENDUES : detecte une integration entiere qui decroche
    # (ok/stale/missing), distinct du go-dark par hote. Seuil de fraicheur par source (min).
    EXPECTED_SOURCES = {"fortigate": 120, "sysmon": 180, "windows_security": 180, "m365": 360,
                        "aruba": 240, "linux": 1440, "dns": 1440, "fortiems": 2880,
                        "fortimanager": 1440, "eset": 1440, "vsphere": 1440}
    ires = os_search("omni-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-30d"}}},
        "aggs": {"src": {"terms": {"field": "event_source", "size": 50},
                         "aggs": {"last": {"max": {"field": "timestamp"}}}}}})
    seen_last = {b["key"]: (b.get("last", {}) or {}).get("value")
                 for b in ires.get("aggregations", {}).get("src", {}).get("buckets", [])}
    now_ms = time.time() * 1000
    integrations = []
    for src, thr in EXPECTED_SOURCES.items():
        last = seen_last.get(src)
        if not last:
            integrations.append({"k": src, "status": "missing", "age_min": None, "threshold_min": thr})
        else:
            age = round((now_ms - last) / 60000.0)
            integrations.append({"k": src, "status": ("ok" if age <= thr else "stale"),
                                 "age_min": age, "threshold_min": thr})
    order = {"missing": 0, "stale": 1, "ok": 2}
    integrations.sort(key=lambda i: (order.get(i["status"], 3), i["k"]))
    return {"cluster": ch.get("status", "?"), "nodes": ch.get("number_of_nodes"),
            "shards": ch.get("active_shards"), "events_24h": ag.get("tot", {}).get("value", 0),
            "sources": sources, "robots": robots, "sla": sla, "dark_hosts": dark,
            "integrations": integrations, "maintenance": maint}


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


ATTACK_GRAPH_FILE = "/var/lib/omni-mobile/attack-graph.json"


def get_attack_graph():
    """Artefact du jumeau d'attaque (oms-graph) : exposition des joyaux, chokepoints,
    rayon de souffle, points uniques, recommandations de leurres. Lecture seule ;
    la redaction est appliquee automatiquement par _json (_walk_redact)."""
    try:
        with open(ATTACK_GRAPH_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"error": "indisponible",
                "hint": "lancer 89-attack-graph.sh puis le timer oms-graph (analyse quotidienne)"}


def get_fortiems(days=7):
    """Télémétrie endpoint FortiClient EMS (event_source=fortiems) : volume, sous-types,
    sévérité, top postes, détections (malware/vuln/AV-off), événements récents."""
    flt = [{"term": {"event_source": "fortiems"}},
           {"range": {"timestamp": {"gte": f"now-{int(days)}d"}}}]
    res = os_search("omni-*", {
        "size": 18, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": flt}},
        "aggs": {
            "subtypes": {"terms": {"field": "subtype", "size": 12}},
            "hosts": {"terms": {"field": "host", "size": 12}},
            "tags": {"filter": {"exists": {"field": "alert_tag"}},
                     "aggs": {"t": {"terms": {"field": "alert_tag", "size": 10}}}},
        },
        "_source": ["timestamp", "type", "subtype", "level", "host", "user", "ems_msg",
                    "alert_tag", "virus", "threat", "action", "risk_severity"]})
    ag = res.get("aggregations", {})
    def _b(k, sub=None):
        node = ag.get(k, {})
        node = node.get(sub, {}) if sub else node
        return [{"k": b["key"], "n": b["doc_count"]} for b in node.get("buckets", [])]
    hits = res.get("hits", {})
    events = [{"ts": s.get("timestamp"), "subtype": s.get("subtype"), "level": s.get("level"),
              "host": _rd(s.get("host")), "user": _rd(s.get("user")),
              "tag": s.get("alert_tag"), "sev": s.get("risk_severity"),
              "threat": s.get("virus") or s.get("threat"), "action": s.get("action"),
              "msg": _scrub(s.get("ems_msg"))}
             for s in (h.get("_source", {}) for h in hits.get("hits", []))]
    tags = {b["k"]: b["n"] for b in _b("tags", "t")}
    return {"total": hits.get("total", {}).get("value", 0), "days": int(days),
            "subtypes": _b("subtypes"),
            "hosts": [{"host": _rd(b["k"]), "n": b["n"]} for b in _b("hosts")],
            "malware": tags.get("forticlient_malware", 0),
            "vuln": tags.get("forticlient_vuln", 0),
            "av_off": tags.get("forticlient_av_off", 0),
            "events": events}


def get_entity_ems(name, days=30):
    """État FortiClient EMS d'un hôte, pour enrichir son dossier 360° : malware/vuln/
    protection-off + événements récents. Ne renvoie 'found' que si le poste a des events EMS."""
    name = (name or "").strip()
    if not name:
        return {"found": False}
    short = name.split("\\")[-1].split("@")[0]
    res = os_search("omni-*", {
        "size": 6, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {
            "filter": [{"term": {"event_source": "fortiems"}},
                       {"range": {"timestamp": {"gte": f"now-{int(days)}d"}}}],
            "must": [{"terms": {"host": list({name, short})}}]}},
        "aggs": {"tags": {"filter": {"exists": {"field": "alert_tag"}},
                          "aggs": {"t": {"terms": {"field": "alert_tag", "size": 6}}}}},
        "_source": ["timestamp", "subtype", "alert_tag", "risk_severity", "virus",
                    "threat", "action", "ems_msg"]})
    hits = res.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    if not total:
        return {"found": False, "entity": short}
    tags = {b["key"]: b["doc_count"] for b in
            res.get("aggregations", {}).get("tags", {}).get("t", {}).get("buckets", [])}
    events = [{"ts": s.get("timestamp"), "subtype": s.get("subtype"), "tag": s.get("alert_tag"),
              "sev": s.get("risk_severity"), "threat": s.get("virus") or s.get("threat"),
              "action": s.get("action"), "msg": _scrub(s.get("ems_msg"))}
             for s in (h.get("_source", {}) for h in hits.get("hits", []))]
    return {"found": True, "entity": short, "total": total,
            "malware": tags.get("forticlient_malware", 0),
            "vuln": tags.get("forticlient_vuln", 0),
            "av_off": tags.get("forticlient_av_off", 0), "events": events}


def get_network(days=7):
    """Synthèse Réseau & Infra (sources on-prem ajoutées) : switches Aruba (sécurité +
    activité), serveurs Linux, DNS (DC). Volumes, top hôtes, détections par source,
    sous-systèmes & IP clientes côté Aruba, événements de sécurité récents.
    Alimente la page /soc « Réseau & Infra »."""
    since = f"now-{int(days)}d"

    def _summary(filt_term, index="omni-*"):
        flt = [filt_term, {"range": {"timestamp": {"gte": since}}}]
        r = os_search(index, {"size": 0, "query": {"bool": {"filter": flt}},
            "aggs": {"hosts": {"terms": {"field": "source", "size": 10}},
                     "tags": {"filter": {"exists": {"field": "alert_tag"}},
                              "aggs": {"t": {"terms": {"field": "alert_tag", "size": 12}}}}}})
        ag = r.get("aggregations", {})
        return {"total": r.get("hits", {}).get("total", {}).get("value", 0),
                "hosts": [{"k": _rd(b["key"]), "n": b["doc_count"]} for b in ag.get("hosts", {}).get("buckets", [])],
                "tags": [{"k": b["key"], "n": b["doc_count"]} for b in ag.get("tags", {}).get("t", {}).get("buckets", [])]}

    aruba = _summary({"term": {"event_source": "aruba"}}, "omni-aruba*")
    # Aruba : sous-systèmes + IP clientes + événements récents (TOUTE l'activité ;
    # les détections taggées sont mises en évidence côté front).
    ar = os_search("omni-aruba*", {
        "size": 16, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": since}}}]}},
        "aggs": {"subs": {"terms": {"field": "aruba_subsystem", "size": 10}},
                 "clients": {"terms": {"field": "aruba_client_ip", "size": 8}}},
        "_source": ["timestamp", "source", "aruba_switch_name", "aruba_subsystem",
                    "aruba_event_id", "aruba_client_ip", "aruba_port", "alert_tag", "message"]})
    aag = ar.get("aggregations", {})
    aruba["subsystems"] = [{"k": b["key"], "n": b["doc_count"]} for b in aag.get("subs", {}).get("buckets", [])]
    aruba["clients"] = [{"k": b["key"], "n": b["doc_count"]} for b in aag.get("clients", {}).get("buckets", [])]
    aruba["events"] = [{"ts": s.get("timestamp"),
                        "sw": _rd(s.get("aruba_switch_name") or s.get("source")),
                        "sub": s.get("aruba_subsystem"), "tag": s.get("alert_tag"),
                        "client": s.get("aruba_client_ip"), "port": s.get("aruba_port"),
                        "msg": _scrub(s.get("message"))}
                       for s in (h.get("_source", {}) for h in ar.get("hits", {}).get("hits", []))]
    # nb de switches distincts vus (tous events, pas que sécurité)
    swc = os_search("omni-aruba*", {"size": 0, "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {"sw": {"cardinality": {"field": "source"}}}})
    aruba["switches_seen"] = swc.get("aggregations", {}).get("sw", {}).get("value", 0)

    return {"days": int(days), "aruba": aruba,
            "linux": _summary({"term": {"event_source": "linux"}}),
            "dns": _summary({"term": {"event_category": "dns"}})}


KIT_DIR = "/var/www/siem-kit"


def get_deploy():
    """Centre de déploiement : artefacts servis sous /kit/ (nom + taille + sha256
    depuis SHA256SUMS, genere par 95-kit-deploy.sh), hotes deja enroles par OS
    (Windows/Linux/Aruba via leur derniere activite), coordonnees du SIEM.
    Lecture seule ; alimente la page /soc « Deploiement »."""
    import os
    siem = {"fqdn": "bx-it-graylog-vm.omnitech.security", "ip": "10.33.220.10",
            "ports": {"windows": 5044, "linux": 1519, "aruba": 1520, "console": 443}}
    # artefacts + checksums (lus depuis SHA256SUMS)
    sums = {}
    try:
        with open(os.path.join(KIT_DIR, "SHA256SUMS"), encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    sums[parts[1]] = parts[0]
    except OSError:
        pass
    artifacts = []
    for name, h in sorted(sums.items()):
        try:
            sz = os.path.getsize(os.path.join(KIT_DIR, name))
        except OSError:
            sz = 0
        artifacts.append({"name": name, "sha256": h, "size": sz})

    def _hosts(index, filt):
        r = os_search(index, {"size": 0, "query": {"bool": {"filter": filt}},
            "aggs": {"h": {"terms": {"field": "source", "size": 60},
                           "aggs": {"last": {"max": {"field": "timestamp"}}}}}})
        return [{"host": _rd(b["key"]), "n": b["doc_count"],
                 "last": b.get("last", {}).get("value_as_string")}
                for b in r.get("aggregations", {}).get("h", {}).get("buckets", [])]
    since = {"range": {"timestamp": {"gte": "now-30d"}}}
    return {"siem": siem, "artifacts": artifacts, "enrolled": {
        "windows": _hosts("omni-*", [{"terms": {"event_source": ["windows_security", "sysmon"]}}, since]),
        "linux": _hosts("omni-linux*", [since]),
        "aruba": _hosts("omni-aruba*", [since])}}


OMS_GRAPH_DIR = "/root/omnitech-siem-setup/oms-graph"
OMS_GRAPH_PY = OMS_GRAPH_DIR + "/.venv/bin/python"
OMS_GRAPH_CFG = "/etc/oms-graph/config.yaml"


def get_entity_exposure(name):
    """Exposition (jumeau d'attaque) d'une entité, pour enrichir son dossier 360° :
    est-elle un chokepoint / quel rayon de souffle / quels joyaux atteint-elle ?
    Ne renvoie 'found' que si l'entité figure parmi les nœuds notables (top exposition)."""
    name = (name or "").strip()
    if not name:
        return {"found": False}
    short = name.split("\\")[-1].split("@")[0]
    art = get_attack_graph()
    if art.get("error"):
        return {"found": False}
    cands = {name.lower(), short.lower()}
    bl = next((b for b in art.get("blast_radius", []) if str(b.get("entity", "")).lower() in cands), None)
    chk = next((c for c in art.get("chokepoints", []) if str(c.get("entity", "")).lower() in cands), None)
    if not bl and not chk:
        return {"found": False, "entity": short}
    return {"found": True, "entity": short,
            "hosts_reached": (bl or {}).get("hosts_reached", 0),
            "jewels_reached": (bl or {}).get("jewels_reached", []),
            "kind": (bl or {}).get("kind", "host"),
            "on_paths": (chk or {}).get("on_paths", 0),
            "is_chokepoint": chk is not None}


def get_sentinel_sim(entity):
    """Aperçu de réponse graduée (Pilier 3) pour une entité : délègue à
    `oms-graph respond --simulate --json` (SOURCE UNIQUE de la logique de grade/plan).
    Lecture seule, AUCUNE exécution (pas de --execute)."""
    import re
    import subprocess
    entity = (entity or "").strip()[:80]
    if not entity or not re.match(r"^[\w.\-$@\\ ]+$", entity):
        return {"error": "entité invalide"}
    try:
        r = subprocess.run(
            [OMS_GRAPH_PY, "-m", "oms_graph.run", "respond", "--simulate", entity,
             "--json", "--config", OMS_GRAPH_CFG],
            cwd=OMS_GRAPH_DIR, capture_output=True, text=True, timeout=25)
        plans = json.loads((r.stdout or "[]").strip() or "[]")
        return plans[0] if plans else {"error": "aucun plan", "entity": entity}
    except (subprocess.SubprocessError, ValueError, OSError) as exc:
        return {"error": "simulation indisponible", "detail": str(exc)[:120]}


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
        if p == "/m/api/watchlist":
            return self._json({"watchlist": get_watchlist()})
        if p == "/m/api/kpis":
            return self._json({"kpis": get_kpis()})
        if p == "/m/api/timeseries":
            return self._json({"series": get_timeseries()})
        if p == "/m/api/by-tactic":
            return self._json({"data": get_terms("mitre_tactic")})
        if p == "/m/api/top-detections":
            return self._json({"data": get_terms("alert_tag")})
        if p == "/m/api/top-sources":
            return self._json({"data": get_terms("event_source", size=16, tagged=False)})
        if p == "/m/api/attack-matrix":
            return self._json({"matrix": get_attack_matrix()})
        if p == "/m/api/leaks":
            return self._json(get_leaks())
        if p == "/m/api/health":
            return self._json(get_health())
        if p == "/m/api/risk":
            return self._json(get_risk())
        if p == "/m/api/attack-graph":
            return self._json(get_attack_graph())
        if p == "/m/api/fortiems":
            return self._json(get_fortiems())
        if p == "/m/api/network":
            return self._json(get_network())
        if p == "/m/api/deploy":
            return self._json(get_deploy())
        if p == "/m/api/sentinel-sim":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._json(get_sentinel_sim(qs.get("entity", [""])[0]))
        if p == "/m/api/entity-exposure":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._json(get_entity_exposure(qs.get("u", [""])[0]))
        if p == "/m/api/entity-ems":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._json(get_entity_ems(qs.get("u", [""])[0]))
        if p == "/m/api/entity-network":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._json(get_entity_network(qs.get("u", [""])[0]))
        if p == "/m/api/geo":
            return self._json(get_geo_threats())
        if p == "/m/api/geo-flows":
            return self._json(get_geo_flows())
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
        if p == "/m/api/entity-timeline":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            try:
                _days = max(1, min(90, int(qs.get("days", ["14"])[0])))
            except (ValueError, TypeError):
                _days = 14
            return self._json(get_entity_timeline(qs.get("u", [""])[0], _days))
        if p == "/m/api/entities":
            return self._json(get_entities_browse())
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
        if p == "/m/api/watch":
            if not self._user():
                return self._json({"error": "auth"}, 401)
            return self._json(update_watch(b, self._user()))
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
get_entity        = cached()(get_entity)          # vue entité (unifiée, plus lourde)
get_investigation = cached()(get_investigation)   # pivot d'investigation (multi-requêtes)
get_entity_timeline = cached()(get_entity_timeline)   # chronologie unifiée
get_entities_browse = cached()(get_entities_browse)   # page Entités (top comptes/machines)


if __name__ == "__main__":
    ThreadingHTTPServer(LISTEN, H).serve_forever()
