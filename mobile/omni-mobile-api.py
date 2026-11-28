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
import html as _eh
import http.client
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

CONF = {}
for path in (os.environ.get("MOBILE_CONFIG", "/etc/default/omni-mobile"),):
    try:
        with open(path) as fh:
            for line in fh:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    CONF[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass

def _setting(name, default):
    """Fichier de configuration d'abord, puis environnement, puis valeur par défaut."""
    return CONF.get(name) or os.environ.get(name) or default


# Clone du dépôt de référence (lookups, oms-graph). Ancienne valeur codée en dur :
# /root/omnitech-siem-setup ; le service doit être repointé vers ce clone.
OMNI_REPO_DIR = _setting("OMNI_REPO_DIR", "/opt/omni-siem/repository").rstrip("/")
LISTEN = (CONF.get("MOBILE_BIND", "127.0.0.1"), int(CONF.get("MOBILE_PORT", "8090")))
OS_URL = CONF.get("OPENSEARCH", "http://127.0.0.1:9200")
GL_URL = CONF.get("GRAYLOG_API", "http://127.0.0.1:9000/api")
GL_CACERT = CONF.get("GRAYLOG_CACERT", "/etc/graylog/certs/omnitech-rootca.crt")
SECRET = CONF.get("MOBILE_SECRET", "change-me").encode()
PUSH_SECRET = CONF.get("MOBILE_PUSH_SECRET", "change-me-push")
# Fail-closed : un secret par defaut = n'importe qui forge une session -> refus de demarrer.
if SECRET == b"change-me" or PUSH_SECRET == "change-me-push":
    sys.exit("FATAL omni-mobile: MOBILE_SECRET/MOBILE_PUSH_SECRET sur la valeur par defaut "
             "-> definir un vrai secret dans /etc/default/omni-mobile.")
SESSION_TTL = int(CONF.get("MOBILE_SESSION_TTL", "43200"))  # 12 h
SUBS_FILE = _setting("MOBILE_SUBS_FILE", "/var/lib/omni-mobile/subscriptions.json")
VAPID_PUB = CONF.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIV_FILE = CONF.get("VAPID_PRIVATE_FILE", "/etc/omni-mobile/vapid_private.pem")
VAPID_SUBJECT = CONF.get("VAPID_SUBJECT", "mailto:informatique@omnitech-security.fr")
INTERNAL = ["omni-winsec", "omni-sysmon", "omni-winother", "omni-fortigate",
            "omni-m365", "omni-vsphere", "omni-fortimanager"]


def log_index_patterns(value):
    """Accept explicit site index prefixes, never all indices or system indices."""
    patterns = [part.strip() for part in value.split(",")]
    if not patterns or len(patterns) > 20:
        raise ValueError("SOC_LOG_INDICES must list explicit site log index patterns")
    for pattern in patterns:
        if (not re.fullmatch(r"[a-z][a-z0-9_-]{1,100}\*?", pattern)
                or pattern.startswith(("gl-", "gl_", "system", "security", "failed", "failure"))
                or not re.search(r"[-_]", pattern.rstrip("*"))
                or pattern in ("graylog*", "omni*")):
            raise ValueError("SOC_LOG_INDICES contains an unsupported or system index pattern")
    return ",".join(dict.fromkeys(patterns))


LOG_INDICES = log_index_patterns(CONF.get("SOC_LOG_INDICES", "omni-*,graylog_*"))

LEGACY_EXPECTED_SOURCES = {"fortigate": 120, "sysmon": 180, "windows_security": 180, "m365": 360,
                           "aruba": 240, "linux": 1440, "dns": 1440, "fortiems": 2880,
                           "fortimanager": 1440, "eset": 1440, "vsphere": 1440}


def expected_source_thresholds(value):
    """An absent setting preserves legacy sites; an explicit empty list expects none."""
    if value is None:
        return dict(LEGACY_EXPECTED_SOURCES)
    if not isinstance(value, str):
        raise ValueError("SOC_EXPECTED_SOURCES must list source:minutes pairs")
    if any(character in value for character in "\r\n\x00"):
        raise ValueError("SOC_EXPECTED_SOURCES must be a single CSV line")
    if not value.strip():
        return {}
    result = {}
    for entry in value.split(","):
        pair = entry.strip().split(":")
        if len(pair) != 2:
            raise ValueError("SOC_EXPECTED_SOURCES must list source:minutes pairs")
        name, minutes = (part.strip() for part in pair)
        if (not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
                or not re.fullmatch(r"[0-9]{1,5}", minutes)
                or not 1 <= int(minutes) <= 43200 or name in result):
            raise ValueError("SOC_EXPECTED_SOURCES contains an invalid or duplicate source threshold")
        result[name] = int(minutes)
    return result


EXPECTED_SOURCES = expected_source_thresholds(CONF.get("SOC_EXPECTED_SOURCES"))


def _make_ssl_ctx():
    """Fail-closed : JAMAIS de TLS non verifie — les creds AD de l'utilisateur transitent
    vers Graylog. Refuse de demarrer plutot que d'exposer au MITM (audit P1-4)."""
    if GL_URL.startswith("https://"):
        if not os.path.exists(GL_CACERT):
            sys.exit(f"FATAL omni-mobile: CA Graylog introuvable ({GL_CACERT}) -> refus de "
                     "demarrer (TLS non verifie = MITM sur les identifiants AD).")
        return ssl.create_default_context(cafile=GL_CACERT)
    host = GL_URL.split("://", 1)[-1].split("/")[0].split(":")[0]
    docker_internal = host == "graylog" and CONF.get("MOBILE_ALLOW_HTTP_DOCKER") == "1"
    if host not in ("127.0.0.1", "localhost", "::1") and not docker_internal:
        sys.exit(f"FATAL omni-mobile: GRAYLOG_API en HTTP clair vers {host} -> refus "
                 "(les identifiants AD transiteraient en clair). Utiliser https.")
    return None
_ssl_ctx = _make_ssl_ctx()


# --------------------------------------------------------------------------- util
class SearchBackendError(RuntimeError):
    """An unavailable or incomplete search is never evidence of zero events."""
    def __init__(self, status=503):
        self.status = status
        super().__init__("search backend unavailable" if status == 503 else "search backend returned an invalid or incomplete response")


def os_search(index: str, body: dict) -> dict:
    # Shared business-log queries include native Content Packs, which inherit
    # Graylog's default index set instead of an omni-* source-specific index.
    if index == "omni-*":
        index = LOG_INDICES
    req = urllib.request.Request(f"{OS_URL}/{index}/_search",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        # Error bodies and URLs can contain query text or credentials.
        raise SearchBackendError(503 if exc.code in (429, 502, 503, 504) else 502) from None
    except (urllib.error.URLError, OSError):
        raise SearchBackendError(503) from None
    except (ValueError, UnicodeError):
        raise SearchBackendError(502) from None
    except http.client.HTTPException:
        raise SearchBackendError(502) from None
    if not isinstance(result, dict) or not isinstance(result.get("hits"), dict):
        raise SearchBackendError(502)
    hits = result["hits"]
    total = hits.get("total")
    count = total.get("value") if isinstance(total, dict) else total
    if isinstance(count, bool) or not isinstance(count, int) or count < 0 or not isinstance(hits.get("hits"), list):
        raise SearchBackendError(502)
    if isinstance(total, int):
        hits["total"] = {"value": total, "relation": "eq"}
    shards = result.get("_shards", {})
    if result.get("error") or result.get("timed_out") or not isinstance(shards, dict) or shards.get("failed", 0):
        raise SearchBackendError(502)
    aggregations = body.get("aggs") or body.get("aggregations")
    # Optional product integrations may have no index at all on a site. Treat
    # only a fully empty, zero-shard response as an empty aggregation result;
    # partial responses, shard failures and errors remain unavailable.
    optional_indices = {"omni-aruba*", "omni-linux*", "omni-fortiems*"}
    if (index in optional_indices and shards.get("total") == 0
            and shards.get("successful") == 0 and shards.get("failed") == 0
            and count == 0 and hits.get("hits") == [] and aggregations
            and "aggregations" not in result):
        def empty_aggregation(spec):
            if "terms" in spec:
                return {"buckets": [], "doc_count_error_upper_bound": 0, "sum_other_doc_count": 0}
            if "cardinality" in spec:
                return {"value": 0}
            if "filter" in spec:
                children = spec.get("aggs") or spec.get("aggregations") or {}
                return {"doc_count": 0, **{key: empty_aggregation(value) for key, value in children.items()}}
            if any(kind in spec for kind in ("max", "min", "avg")):
                return {"value": None}
            if "sum" in spec or "value_count" in spec:
                return {"value": 0}
            raise SearchBackendError(502)

        result["aggregations"] = {key: empty_aggregation(value) for key, value in aggregations.items()}
    if aggregations and (not isinstance(result.get("aggregations"), dict)
                         or not set(aggregations).issubset(result["aggregations"])):
        raise SearchBackendError(502)
    return result


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


# ------------------------------------------------------- capacités du site (socle)
# Catalogue du dépôt (integrations/sources.json) + configuration du site (clé « site » de
# /etc/omni-siem/integrations.json) : la console masque les pages des sources absentes et
# signale les données non configurées au lieu d'afficher un faux zéro. Sans clé « site »
# (ou catalogue illisible), tout reste visible : comportement historique.
SITE_CONFIG_FILE = _setting("SOC_SITE_CONFIG", "/etc/omni-siem/integrations.json")
_SITE_CACHE = {"key": None, "data": None}
_SITE_LOCK = threading.Lock()


def _socle_module():
    for root in (os.path.dirname(os.path.dirname(os.path.realpath(__file__))), OMNI_REPO_DIR):
        if os.path.isfile(os.path.join(root, "omni_integrations", "socle.py")):
            if root not in sys.path:
                sys.path.insert(0, root)
            import importlib
            return importlib.import_module("omni_integrations.socle")
    raise FileNotFoundError("omni_integrations/socle.py")


def site_profile():
    with _SITE_LOCK:
        try:
            socle = _socle_module()
            mtime = os.path.getmtime(SITE_CONFIG_FILE) if os.path.exists(SITE_CONFIG_FILE) else 0
            key = (SITE_CONFIG_FILE, mtime, os.path.getmtime(socle.SOURCES_FILE))
            if _SITE_CACHE["key"] == key:
                return _SITE_CACHE["data"]
            capabilities = socle.load_capabilities()
            data = {"caps": capabilities, "profile": socle.load_site_profile(SITE_CONFIG_FILE, capabilities), "error": None}
        except Exception as exc:   # configuration invalide : historique, erreur affichée dans /m/api/site
            key, data = None, {"caps": None, "profile": None, "error": f"configuration du site illisible ({type(exc).__name__})"}
        _SITE_CACHE.update(key=key, data=data)
        return data


def site_enabled(*capabilities):
    profile = site_profile()["profile"]
    return profile is None or profile["legacy"] or bool(set(capabilities) & profile["enabled"])


def _alerts_seen(days=30):
    """Des événements d'alerte Graylog existent-ils ? (une définition ajoutée sans mise à jour du site)"""
    try:
        res = os_search("gl-events*", {"size": 0, "track_total_hits": True,
                                       "query": {"range": {"timestamp": {"gte": f"now-{int(days)}d"}}}})
        return res["hits"]["total"]["value"] > 0
    except SearchBackendError:
        return False


def get_site():
    data = site_profile()
    caps, profile = data["caps"] or {}, data["profile"]
    detections = site_enabled("detections") or _alerts_seen()
    pages = {}
    for page, spec in caps.get("console_pages", {}).items():
        visible = not spec.get("requires_any") or site_enabled(*spec["requires_any"])
        needs = spec.get("notice_unless_any", [])
        configured = site_enabled(*needs) or ("detections" in needs and detections)
        pages[page] = {"visible": visible, "notice": None if (not needs or configured) else spec.get("notice")}
    location = (profile or {}).get("location") or None
    return {"legacy": profile is None or profile["legacy"], "error": data["error"],
            "sources": [{"id": key, "title": caps["sources"][key]["title"]} for key in (profile or {}).get("sources", [])],
            "features": (profile or {}).get("features", []), "pages": pages,
            "detections": {"configured": bool(detections)},
            "kpis_unavailable": [k for k, needs in caps.get("kpis", {}).items() if not site_enabled(*needs)],
            "location": location}


def _site_expected_sources():
    """Seuils de fraîcheur : SOC_EXPECTED_SOURCES, complété par les sources que le site active."""
    expected = dict(EXPECTED_SOURCES)
    data = site_profile()
    if data["profile"] and not data["profile"]["legacy"]:
        for key in data["profile"]["sources"]:
            spec = data["caps"]["sources"][key]
            for value in spec.get("event_source", []):
                expected.setdefault(value, int(spec.get("expected_minutes", 1440)))
    return expected


def get_inputs_collect():
    """Toutes les données reçues, par entrée Graylog : volume, dernier message, émetteurs, champs.
    Couvre aussi les messages non normalisés (sans event_source) et les entrées arrêtées."""
    res = os_search("omni-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-7d"}}},
        "aggs": {"inp": {"terms": {"field": "gl2_source_input", "size": 40},
                         "aggs": {"last": {"max": {"field": "timestamp"}},
                                  "d1": {"filter": {"range": {"timestamp": {"gte": "now-24h"}}}},
                                  "src": {"terms": {"field": "source", "size": 5}},
                                  "es": {"terms": {"field": "event_source", "size": 4}},
                                  "raw": {"filter": {"bool": {"must_not": [{"exists": {"field": "event_source"}}]}}},
                                  "doc": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "desc"}}]}}}}}})
    labels = (site_profile()["profile"] or {}).get("inputs", {})
    hidden = {"message", "full_message", "timestamp", "streams", "source"}
    out = []
    for b in res.get("aggregations", {}).get("inp", {}).get("buckets", []):
        hit = ((((b.get("doc") or {}).get("hits") or {}).get("hits")) or [{}])[0].get("_source", {})
        fields = sorted(k for k in hit if k not in hidden and not k.startswith("gl2_"))
        out.append({"id": b["key"], "label": labels.get(b["key"], ""), "n_7d": b["doc_count"],
                    "n_24h": (b.get("d1") or {}).get("doc_count", 0),
                    "last": (b.get("last") or {}).get("value_as_string"),
                    "unnormalized_7d": (b.get("raw") or {}).get("doc_count", 0),
                    "sources": [{"k": _rd(x["key"]), "n": x["doc_count"]} for x in b.get("src", {}).get("buckets", [])],
                    "event_sources": [x["key"] for x in b.get("es", {}).get("buckets", [])],
                    "fields": fields[:24], "fields_total": len(fields)})
    return out


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
    caps = site_profile()["caps"] or {}
    kpis = _kpis_raw()
    # Fonction absente du site : null (« non configuré »), jamais un zéro mesuré.
    for key, needs in caps.get("kpis", {}).items():
        if key in kpis and not site_enabled(*needs):
            kpis[key] = None
    return kpis


# Détection posée par un pipeline : alert_tag (historique) ou v5_tag (détections du socle par site).
DETECTED = {"bool": {"minimum_should_match": 1, "should": [{"exists": {"field": "alert_tag"}},
                                                          {"exists": {"field": "v5_tag"}}]}}


def _kpis_raw() -> dict:
    last24 = {"range": {"timestamp": {"gte": "now-24h"}}}
    return {
        "alertes_24h": _count({"bool": {"must": [DETECTED], "filter": [last24]}}),
        "correspondances_ti_24h": _count({"bool": {"must": [{"exists": {"field": "ti_source"}}], "filter": [last24]}}),
        "incidents_critiques_7j": _count({"bool": {"must": [
            {"term": {"event_source": "xdr_incident"}}, {"term": {"severity": "critical"}}],
            "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}}),
        "hotes_risque_ueba": _count({"bool": {"must": [{"term": {"event_source": "ueba_score"}},
            {"range": {"ueba_score": {"gte": 80}}}], "filter": [last24]}}),
        "kev_exposees": _count({"bool": {"must": [{"term": {"alert_tag": "vuln_kev"}}], "filter": [last24]}}),
    }


def get_timeseries():
    res = os_search("omni-*", {"size": 0,
        "query": {"bool": {"must": [DETECTED],
                           "filter": [{"range": {"timestamp": {"gte": "now-24h"}}}]}},
        "aggs": {"h": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}}}})
    return [{"t": b.get("key_as_string"), "n": b.get("doc_count")}
            for b in res.get("aggregations", {}).get("h", {}).get("buckets", [])]


def get_terms(field, gte="now-7d", size=8, tagged=True):
    # tagged=False : compte TOUTE l'activite (pas seulement les detections) -> rend les
    # sources benignes (aruba/linux/dns : ports/STP/CADownload) visibles dans top-sources.
    must = [DETECTED] if tagged else []
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
        with open(_setting("MITRE_LOOKUP", OMNI_REPO_DIR + "/lookups/mitre-attack.csv")) as f:
            rd = _csv.reader(f); next(rd, None)
            for r in rd:
                if len(r) >= 4 and r[1].startswith("T"):
                    rows.append((r[1], r[2], r[3], r[4] if len(r) > 4 else ""))
    except Exception:
        pass
    res = os_search("omni-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-7d"}}},
        "aggs": {"t": {"terms": {"field": "mitre_technique", "size": 300}},
                 "v5": {"terms": {"field": "v5_mitre", "size": 300}}}})
    counts = {b.get("key"): b.get("doc_count") for b in res.get("aggregations", {}).get("t", {}).get("buckets", [])}
    known = {r[0] for r in rows}
    for b in res.get("aggregations", {}).get("v5", {}).get("buckets", []):
        # Détections du socle (v5_mitre) : sous-technique comptée sur sa technique si elle n'est pas au référentiel.
        tech = b.get("key") or ""
        tech = tech if tech in known else tech.split(".")[0]
        counts[tech] = counts.get(tech, 0) + b.get("doc_count", 0)
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
        with open(_setting("MITRE_LOOKUP", OMNI_REPO_DIR + "/lookups/mitre-attack.csv")) as f:
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


CASES_FILE = _setting("MOBILE_CASES_FILE", "/var/lib/omni-mobile/cases.json")
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
        # Indicateurs SOC (MTTR) : historique daté (avec décalage horaire) des changements de statut,
        # d'assignation et de qualification, et horodatage de la dernière clôture. Ajout seul.
        if act in ("status", "assign", "disposition"):
            now = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
            value = {"status": c.get("status", ""), "assign": c.get("assignée", ""),
                     "disposition": c.get("disposition", "")}[act]
            c.setdefault("history", []).append({"ts": now, "by": who or "?", "action": act, "value": value})
            del c["history"][:-50]
            if c.get("status") == "closed":
                c.setdefault("closed_ts", now)
            else:
                c.pop("closed_ts", None)
        save_cases(st)
    return {"ok": True, "case": c}


# --- Boucle faux positifs : l'analyste marque une alerte FP -> le triage eteint le
#     mail futur pour (entite [+ titre]). Scope + TTL cote service ; JAMAIS un CRITICAL.
def triage_fp_add(entity, title_sub, by, tag=""):
    entity = (entity or "").strip()
    if not entity:
        return {"ok": False, "error": "entité requise"}
    tok = ""
    try:
        for line in open("/etc/omni-alert-triage.env"):
            if line.startswith("TRIAGE_TOKEN="):
                tok = line.split("=", 1)[1].strip()
    except OSError:
        pass
    data = json.dumps({"entity": entity, "tag": (tag or "")[:60],
                       "title_sub": (title_sub or "")[:80],
                       "by": (by or "soc")[:60], "ttl_days": 30}).encode()
    req = urllib.request.Request("http://127.0.0.1:8089/fp", data=data,
        headers={"Content-Type": "application/json", "X-Triage-Token": tok})
    try:
        return json.load(urllib.request.urlopen(req, timeout=8))
    except Exception as ex:
        return {"ok": False, "error": type(ex).__name__}


def quick_verify(action, entity, tag, exp, sig):
    """Valide un lien d'action signé (mail) : HMAC(QUICK_SECRET) + non expire."""
    qs = CONF.get("QUICK_SECRET", "")
    if not qs or not sig:
        return False
    try:
        if int(exp) < int(time.time()):
            return False
    except Exception:
        return False
    good = hmac.new(qs.encode(), f"{action}|{entity}|{tag}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(good, sig)


def soar_block(ip, by):
    """Bloque une IP au pare-feu via omni-soar (mode manuel ; SOAR refuse les IP non publiques)."""
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "ip requise"}
    data = json.dumps({"ip": ip, "manual": True, "by": (by or "mail-link")[:60]}).encode()
    req = urllib.request.Request("http://127.0.0.1:8088/block", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=8))
    except Exception as ex:
        return {"ok": False, "error": type(ex).__name__}


# --- Watchlist : entités à surveiller (compromission suspectée, suivi) ----------
WATCH_FILE = _setting("MOBILE_WATCH_FILE", "/var/lib/omni-mobile/watchlist.json")
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
    except SearchBackendError:
        raise
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


def get_search(q, frm=0, size=25, days=2):
    """Recherche plein-texte serveur sur les logs BRUTS du site (SOC_LOG_INDICES) :
    query_string OpenSearch (analyze_wildcard), fenetre par defaut 2j, retourne les
    champs cles. Permet de pivoter d'une alerte vers les evenements correles (Ctrl+K)."""
    q = (q or "").strip()
    if len(q) < 2:
        return {"q": q, "total": 0, "results": []}
    frm = max(0, min(int(frm), 2000))
    size = max(1, min(int(size), 50))
    try:
        res = os_search(LOG_INDICES, {
            "size": size, "from": frm, "track_total_hits": True,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": [{"query_string": {"query": q, "analyze_wildcard": True,
                                                          "default_operator": "AND"}}],
                               "filter": [{"range": {"timestamp": {"gte": f"now-{int(days)}d"}}}]}},
            "_source": ["timestamp", "source", "event_source", "message", "short_message",
                        "user", "src_ip", "alert_tag", "event_action", "net_segment"]})
    except SearchBackendError:
        raise
    except Exception:
        return {"q": q, "total": 0, "results": [], "error": "requete invalide"}
    hits = res.get("hits", {})
    total = hits.get("total", {})
    total = total.get("value", 0) if isinstance(total, dict) else (total or 0)
    out = []
    for h in hits.get("hits", []):
        s = h.get("_source", {})
        out.append({"ts": s.get("timestamp"), "src": s.get("event_source") or _rd(s.get("source")),
                    "host": _rd(s.get("source")), "user": _rd(s.get("user")), "ip": s.get("src_ip"),
                    "seg": s.get("net_segment"), "tag": s.get("alert_tag"), "act": s.get("event_action"),
                    "msg": _scrub(s.get("short_message") or s.get("message"))})
    return {"q": q, "total": total, "from": frm, "size": size, "results": out}


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


_MITRE_PATH = _setting("MITRE_LOOKUP", os.path.join(OMNI_REPO_DIR, "lookups", "mitre-attack.csv"))
_LOOKDIR = os.path.dirname(_MITRE_PATH)
_GUIDANCE_PATH = os.path.join(_LOOKDIR, "alert-guidance.json")
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
    def either(a, b, value):
        return {"bool": {"minimum_should_match": 1, "should": [{"term": {a: value}}, {"term": {b: value}}]}}
    must = [DETECTED]
    if tactic:
        must.append({"term": {"mitre_tactic": tactic}})
    if source:
        must.append({"term": {"event_source": source}})
    if tag:
        must.append(either("alert_tag", "v5_tag", tag))
    if technique:
        must.append(either("mitre_technique", "v5_mitre", technique))
    res = os_search("omni-*", {"size": 60, "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must, "filter": [{"range": {"timestamp": {"gte": "now-24h"}}}]}},
        "_source": ["timestamp", "alert_tag", "mitre_technique", "mitre_tactic", "event_source",
                    "user", "key", "short_message", "message", "priority", "risk_severity", "risk_score",
                    "v5_tag", "v5_severite", "v5_mitre", "v5_entite", "v5_detail"],
        "aggs": {"tac": {"terms": {"field": "mitre_tactic", "size": 14}},
                 "src": {"terms": {"field": "event_source", "size": 15}}}})
    try:
        tactic_of = _tech_tactic_map()
    except Exception:
        tactic_of = {}
    items = []
    for h in res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        tech = s.get("mitre_technique") or s.get("v5_mitre")
        items.append({"ts": s.get("timestamp"), "tag": s.get("alert_tag") or s.get("v5_tag"), "tech": tech,
                      "tactic": s.get("mitre_tactic") or tactic_of.get(tech) or tactic_of.get((tech or "").split(".")[0]),
                      "source": s.get("event_source"),
                      "entity": _rd(s.get("user") or s.get("v5_entite") or s.get("key")), "priority": s.get("priority"),
                      "sev": s.get("risk_severity") or s.get("v5_severite"), "score": s.get("risk_score"),
                      "msg": s.get("v5_detail") or s.get("short_message") or s.get("message")})
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
    {"bool": {"filter": [{"term": {"event_source": "watchguard"}}, {"terms": {"event_action": ["deny", "drop", "block"]}}]}},
]}}


def _site_geo():
    """Point d'arrivée des flux de la carte : site.location, sinon nom de la console."""
    location = (site_profile()["profile"] or {}).get("location")
    if location:
        return {"lat": location["lat"], "lng": location["lng"], "label": location.get("label") or _site_name()}
    if site_profile()["profile"] and not site_profile()["profile"]["legacy"]:
        return {"lat": 46.6, "lng": 2.4, "label": _site_name()}
    return OMS_GEO


def _site_name():
    try:
        return appearance_public().get("name") or APPEARANCE_NAME_DEFAULT
    except Exception:
        return APPEARANCE_NAME_DEFAULT


def get_geo_flows(hours=3, top=150):
    """Flux geolocalises monde -> OMNITECH (carte/globe 3D facon attack-map).
    Agrege par coordonnee (src_ip_geolocation, top N), separe menace/trafic, +
    detail des derniers evenements de menace + top pays attaquants. Donnees REELLES
    (GeoIP DB-IP sur les IP publiques : fortigate/m365/bunkerweb)."""
    if type(hours) is not int or hours not in (3, 12, 24, 48, 72):
        raise ValueError("unsupported map time window")
    end_ms = int(time.time() * 1000)
    window = {"gte": end_ms - hours * 3600000, "lte": end_ms, "format": "epoch_millis"}
    res = os_search("omni-*", {"size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [{"exists": {"field": "src_ip_geolocation"}},
                                       {"range": {"timestamp": window}}]}},
        "aggs": {"threat_total": {"filter": _MENACE},
                 "loc": {"terms": {"field": "src_ip_geolocation", "size": int(top)},
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
                                      {"range": {"timestamp": window}}], "must": [_MENACE]}},
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
        "query": {"bool": {"filter": [{"exists": {"field": "src_ip_geolocation"}},
                                      {"range": {"timestamp": window}}], "must": [_MENACE]}},
        "aggs": {"c": {"terms": {"field": "src_ip_country_code", "size": 12}}}})
    topc = [{"cc": b["key"], "n": b["doc_count"]}
            for b in tc.get("aggregations", {}).get("c", {}).get("buckets", [])
            if b.get("key") not in (None, "", "Reserved", "Private", "-")]
    return {"oms": _site_geo(), "hours": hours, "window": window, "arcs": arcs, "recent": recent,
            "top_countries": topc,
            "coverage": {"locations_limit": int(top), "recent_limit": 16,
                         "omitted_flows": res["aggregations"]["loc"].get("sum_other_doc_count", 0)},
            "totals": {"arcs": len(arcs), "menace": res["aggregations"]["threat_total"]["doc_count"],
                       "flux": res["hits"]["total"]["value"]}}


def get_geo_threats():
    out = {"countries": []}
    caps = site_profile()["caps"] or {}
    # Pare-feu du site autres que FortiGate (WatchGuard…) : pays d'origine des blocages.
    for key, spec in caps.get("sources", {}).items():
        if key == "fortigate" or not spec.get("firewall") or not site_enabled(key) or not spec.get("country_field"):
            continue
        field = spec["country_field"]
        res = os_search("omni-*", {"size": 0,
            "query": {"bool": {"filter": [{"terms": {"event_source": spec.get("event_source", [key])}},
                                          {"terms": {"event_action": ["deny", "drop", "block"]}},
                                          {"range": {"timestamp": {"gte": "now-7d"}}}]}},
            "aggs": {"c": {"terms": {"field": field, "size": 14}}}})
        cc = [{"k": b["key"], "n": b["doc_count"]}
              for b in res.get("aggregations", {}).get("c", {}).get("buckets", [])
              if b.get("key") and b["key"] not in ("Reserved", "Private", "-", "")]
        if cc:
            return {"countries": cc, "field": field, "source": key}
    if not site_enabled("fortigate"):
        return out
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
    crit = k.get("incidents_critiques_7j") or 0   # null = fonction non configurée sur le site
    ueba = k.get("hotes_risque_ueba") or 0
    kev = k.get("kev_exposees") or 0
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
    ires = os_search("omni-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-30d"}}},
        "aggs": {"src": {"terms": {"field": "event_source", "size": 50},
                         "aggs": {"last": {"max": {"field": "timestamp"}}}}}})
    seen_last = {b["key"]: (b.get("last", {}) or {}).get("value")
                 for b in ires.get("aggregations", {}).get("src", {}).get("buckets", [])}
    now_ms = time.time() * 1000
    integrations = []
    for src, thr in _site_expected_sources().items():
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
            "integrations": integrations, "maintenance": maint, "inputs": get_inputs_collect()}


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
    siem = {"fqdn": CONF.get("SIEM_FQDN", "").strip(), "ip": CONF.get("SIEM_IP", "").strip(),
            "ports": {"windows": 5044, "linux": 1519, "aruba": 1520, "console": 443}}
    siem["identity_configured"] = bool(siem["fqdn"] and siem["ip"])
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


OMS_GRAPH_DIR = _setting("OMS_GRAPH_DIR", OMNI_REPO_DIR + "/oms-graph")
OMS_GRAPH_PY = _setting("OMS_GRAPH_PY", OMS_GRAPH_DIR + "/.venv/bin/python")
OMS_GRAPH_CFG = _setting("OMS_GRAPH_CFG", "/etc/oms-graph/config.yaml")


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

# =============================================================================
# OMNITECH-SOC-20261111 : SOAR, exploitation du SIEM et actions /soc
# =============================================================================
import ipaddress as _ipa, subprocess as _sp, uuid as _uuid, glob as _glob
_SOAR_STATE = "/var/lib/omni-soar/blocklist.json"
_SOAR_META = "/var/lib/omni-soar/blocklist-meta.json"
_SOAR_EXCL = "/var/lib/omni-soar/exclusions.json"
_SOAR_FIX = "/etc/omni-soar/exclusions-statiques.txt"
_SOAR_FEED = "/var/www/siem-kit/soar/blocklist.txt"
_SOAR_DEC = "/var/log/omni-soar/decisions.log"
SOC_REQ_DIR = _setting("SOC_REQ_DIR", "/var/lib/omni-mobile/soc-requests")
SOC_ADMINS = {u.strip().lower() for u in CONF.get("SOC_ADMINS", "").split(",") if u.strip()}
_SITE_ORIGINS = ",".join(filter(None, (CONF.get("SIEM_FQDN", ""), CONF.get("SIEM_IP", ""),
                                     urllib.parse.urlparse(GL_URL).hostname)))
SOC_ORIGINS = {h.strip().lower() for h in CONF.get("SOC_ORIGINS", _SITE_ORIGINS).split(",") if h.strip()}

def _jl(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def _tail_jsonl(path, n=300):
    out = []
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); size = f.tell(); f.seek(max(0, size - 200000))
            for line in f.read().decode("utf-8", "replace").splitlines()[-n:]:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out

def origin_ok(headers):
    """Defense en profondeur CSRF (le cookie est deja SameSite=Strict) : Origin/Referer du meme hote."""
    o = headers.get("Origin") or headers.get("Referer") or ""
    if not o:
        return True   # client non navigateur (curl local) : la session reste exigee
    import urllib.parse as _uparse
    host = _uparse.urlparse(o).netloc.split(":")[0].lower()
    return host in SOC_ORIGINS

def soc_is_admin(user):
    """Administrateur SOC : SOC_ADMINS (configuration) ou rôle attribué depuis la console."""
    return bool(user) and role_of(user) == "administrateur"

def get_soar():
    now = time.time()
    bl = _jl(_SOAR_STATE, {}); meta = _jl(_SOAR_META, {})
    dec = _tail_jsonl(_SOAR_DEC, 400)
    lastb = {}
    for e in dec:
        a = str(e.get("action", ""))
        if "bloq" in a and "debloq" not in a and e.get("ip"):
            lastb[e["ip"]] = e
    active = []
    for ip, until in bl.items():
        try:
            until = float(until)
        except Exception:
            continue
        if until <= now:
            continue
        m = dict(meta.get(ip, {})); b = lastb.get(ip, {})
        active.append({"ip": ip, "until": int(until), "remaining_h": round((until - now) / 3600, 1),
                       "since": b.get("t"), "detection": m.get("detection") or b.get("detection") or "",
                       "pays": m.get("pays") or b.get("pays") or "", "hits": m.get("hits") or b.get("hits"),
                       "motif": b.get("motif") or ""})
    active.sort(key=lambda x: -x["until"])
    excl = _jl(_SOAR_EXCL, {})
    fix = 0
    try:
        fix = sum(1 for l in open(_SOAR_FIX) if l.strip() and not l.lstrip().startswith("#"))
    except Exception:
        pass
    try:
        feed_age = int(now - os.path.getmtime(_SOAR_FEED))
    except Exception:
        feed_age = None
    reqs = []
    for st in ("pending", "done"):
        for p in sorted(_glob.glob(os.path.join(SOC_REQ_DIR, st, "*.json")), key=os.path.getmtime, reverse=True)[:15]:
            r = _jl(p, {}); r["status"] = r.get("status") or st; reqs.append(r)
    hist = [e for e in reversed(dec)][:40]
    return {"active": active, "count": len(active), "history": hist,
            "exclusions": {"dynamic_stats": excl.get("stats", {}), "dynamic_generated": excl.get("genere"),
                           "dynamic_days": excl.get("jours"), "static": fix},
            "feed_age_s": feed_age, "requests": reqs[:20], "is_admin": None}

def soc_soar_request(body, user):
    if not soc_is_admin(user):
        return {"ok": False, "error": "action réservée aux administrateurs SOC"}
    ip = str(body.get("ip", "")).strip()
    try:
        ipo = _ipa.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "adresse IP invalide"}
    if not ipo.is_global:
        return {"ok": False, "error": "seules les IP publiques sont gérées par le SOAR"}
    exclure = bool(body.get("exclure"))
    motif = " ".join(str(body.get("motif", "")).replace("#", " ").split())[:80]
    if exclure and len(motif) < 4:
        return {"ok": False, "error": "motif obligatoire (4 caractères min.) pour une exclusion définitive"}
    try:
        rid = _queue_soar_unblock(str(ipo), user, exclure, motif)
    except AdminError as ex:
        return {"ok": False, "error": str(ex)}
    audit_append(user, "execution", "soar_unblock" + ("_exclusion" if exclure else ""), str(ipo), motif,
                 "bloquée", "non bloquée", "transmise (page SOAR)", rid)
    return {"ok": True, "id": rid, "message": "Demande enregistrée : déblocage appliqué sous 1 min, effet sur les FortiGate sous 2 min."}

def _run(cmd, timeout=8):
    try:
        return _sp.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""

def _readf(path, n=4000):
    try:
        with open(path, errors="replace") as f:
            return f.read()[-n:]
    except Exception:
        return ""

def get_siem_ops():
    now = time.time(); items = []
    def add(k, label, status, value, detail=""):
        items.append({"k": k, "label": label, "status": status, "value": value, "detail": detail})
    # mises a jour automatiques
    log = _readf("/var/log/oms-maj-siem.log", 20000).splitlines()
    res = [l for l in log if "RESULTAT" in l]
    last = res[-1] if res else ""
    nxt = _run(["systemctl", "show", "oms-maj-siem.timer", "-p", "NextElapseUSecRealtime", "--value"])
    st = "ok" if ("OK" in last or "rien a faire" in last) else ("warn" if not last else ("crit" if ("ECHEC" in last or "VERIFIER" in last or "ANNULE" in last) else "ok"))
    add("maj", "Mises à jour automatiques", st, (last[:19] if last else "pas encore exécutée"),
        (last[20:] if last else "") + (f" · prochaine : {nxt}" if nxt else ""))
    rb = os.path.exists("/var/run/reboot-required")
    add("reboot", "Redémarrage en attente", "warn" if rb else "ok", "oui" if rb else "non",
        _readf("/var/run/reboot-required.pkgs", 300).replace("\n", " ") if rb else "")
    # snapshots OpenSearch
    def _dt(v):
        v = v.strip()
        return time.strftime("%d/%m/%Y %H:%M", time.localtime(int(v))) if v.isdigit() else v
    snap = _dt(_readf("/var/lib/oms-snap-siem/dernier-snapshot-ok", 100))
    test = _dt(_readf("/var/lib/oms-snap-siem/dernier-test-ok", 100))
    def age_h(p):
        try:
            return (now - os.path.getmtime(p)) / 3600
        except Exception:
            return None
    a = age_h("/var/lib/oms-snap-siem/dernier-snapshot-ok")
    add("snap", "Snapshot des index (quotidien)", "ok" if a is not None and a < 30 else ("crit" if a is None else "warn"),
        snap or "aucun", f"il y a {a:.0f} h" if a is not None else "")
    at = age_h("/var/lib/oms-snap-siem/dernier-test-ok")
    add("snaptest", "Test de restauration (hebdo)", "ok" if at is not None and at < 8 * 24 else "warn",
        test or "aucun", f"il y a {at / 24:.0f} j" if at is not None else "")
    # sauvegarde chiffree de la configuration
    bk = sorted(_glob.glob("/var/backups/siem/omni-siem-config_*.tar.gz.enc"), key=os.path.getmtime)
    if bk:
        ab = (now - os.path.getmtime(bk[-1])) / 3600
        add("backup", "Sauvegarde configuration (quotidienne)", "ok" if ab < 30 else "warn",
            os.path.basename(bk[-1]).replace("omni-siem-config_", "").replace(".tar.gz.enc", ""),
            f"{os.path.getsize(bk[-1]) // 1048576} Mo · il y a {ab:.0f} h")
    else:
        add("backup", "Sauvegarde configuration (quotidienne)", "crit", "aucune", "")
    # disques
    for mp in ("/", "/var", "/data", "/home"):
        try:
            s = os.statvfs(mp); tot = s.f_blocks * s.f_frsize; free = s.f_bavail * s.f_frsize
            pct = round(100 * (tot - free) / tot) if tot else 0
            add("disk" + mp, f"Disque {mp}", "crit" if pct >= 90 else ("warn" if pct >= 80 else "ok"),
                f"{pct} %", f"{free // 1073741824} Go libres sur {tot // 1073741824} Go")
        except Exception:
            pass
    # unites en echec
    failed = [l.split()[0] for l in _run(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines() if l.strip()]
    add("failed", "Services en échec", "crit" if failed else "ok", str(len(failed)), ", ".join(failed[:8]))
    # certificat de la console
    end = _run(["openssl", "x509", "-enddate", "-noout", "-in", "/etc/nginx/ssl/graylog.crt"]).replace("notAfter=", "")
    try:
        days = int((time.mktime(time.strptime(end, "%b %d %H:%M:%S %Y %Z")) - now) / 86400)
        add("cert", "Certificat de la console", "crit" if days < 15 else ("warn" if days < 45 else "ok"), f"{days} j", end)
    except Exception:
        pass
    vers = _run(["dpkg-query", "-W", "-f", "${Package} ${Version}\n", "graylog-server", "opensearch", "mongodb-org-server", "logstash"])
    sev = {"ok": 0, "warn": 1, "crit": 2}
    worst = max((sev.get(i["status"], 0) for i in items), default=0)
    return {"items": items, "status": ["ok", "warn", "crit"][worst], "versions": vers.splitlines(),
            "kernel": os.uname().release, "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

# =============================================================================
# ESPACE ADMINISTRATION SOC (21/11/2026)
#   Rôles (lecteur < analyste < administrateur), journal d'audit chaîné en ajout
#   seul, actions d'administration avec simulation préalable et, pour les actions
#   à fort impact, validation par un second administrateur (approbation à deux
#   temps). Les actions réutilisent les mécanismes existants :
#     - faux positifs   : API du triage (127.0.0.1:8089 /fp) ;
#     - blocage SOAR    : API omni-soar (127.0.0.1:8088 /block, mode manuel) ;
#     - déblocage SOAR  : file soc-requests traitée par omni-soc-actions ;
#     - détections      : API Graylog schedule/unschedule (jeton dédié, optionnel) ;
#     - paramètres, exclusions fixes, redémarrages : file « exec » traitée par
#       l'exécuteur privilégié omni-soc-admin-exec (le backend est confiné et
#       n'écrit que dans son répertoire de données).
#   Aucune commande shell n'est construite à partir d'une entrée utilisateur.
# =============================================================================
import fcntl as _fcntl
import ipaddress as _ipa2

CONSOLE_BUILD = "2026112101"
ROLE_RANK = {"lecteur": 1, "analyste": 2, "administrateur": 3}
ROLE_LABEL = {"lecteur": "Lecteur", "analyste": "Analyste", "administrateur": "Administrateur"}
_DATA_DIR = os.path.dirname(SUBS_FILE) or "/var/lib/omni-mobile"
SOC_ADMIN_DIR = _setting("SOC_ADMIN_DIR", os.path.join(_DATA_DIR, "admin"))
# Apparence de la console (nom, logo, couleurs) : fichier JSON + logo, modifiables par un administrateur.
SOC_APPEARANCE_DIR = _setting("SOC_APPEARANCE_DIR", os.path.join(_DATA_DIR, "appearance"))
SOC_MODULES_DIR = _setting("SOC_MODULES_DIR", os.path.join(_DATA_DIR, "modules"))
SOC_DEFAULT_ROLE = CONF.get("SOC_DEFAULT_ROLE", "analyste").strip().lower()
if SOC_DEFAULT_ROLE not in ("lecteur", "analyste"):
    SOC_DEFAULT_ROLE = "lecteur"          # jamais administrateur par défaut
SOC_ADMIN_INTERNAL_ONLY = CONF.get("SOC_ADMIN_INTERNAL_ONLY", "1") != "0"
_DEFAULT_ADMIN_NETS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7"


def _parse_nets(value):
    nets = []
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(_ipa2.ip_network(part, strict=False))
        except ValueError:
            sys.exit(f"FATAL omni-mobile: SOC_ADMIN_NETS contient une plage invalide ({part[:40]}).")
    return nets


SOC_ADMIN_NETS = _parse_nets(CONF.get("SOC_ADMIN_NETS", _DEFAULT_ADMIN_NETS))
SOC_ADMIN_SELF_APPROVE = CONF.get("SOC_ADMIN_SELF_APPROVE", "0") == "1"
SOC_ADMIN_APPROVAL_TTL = max(600, min(int(CONF.get("SOC_ADMIN_APPROVAL_TTL", "86400") or 86400), 7 * 86400))
SOC_ADMIN_DRY_RUN = CONF.get("SOC_ADMIN_DRY_RUN", "0") == "1"
SOC_ADMIN_GELF_URL = CONF.get("SOC_ADMIN_GELF_URL", os.environ.get("SOC_ADMIN_GELF_URL", "http://127.0.0.1:12201/gelf"))
SOC_ADMIN_WRITES_PER_5MIN = int(CONF.get("SOC_ADMIN_WRITES_PER_5MIN", "30") or 30)
SOC_GRAYLOG_TOKEN_FILE = CONF.get("SOC_GRAYLOG_TOKEN_FILE", "")
SOC_TRIAGE_URL = CONF.get("SOC_TRIAGE_URL", "http://127.0.0.1:8089").rstrip("/")
SOC_TRIAGE_ENV = CONF.get("SOC_TRIAGE_ENV", "/etc/omni-alert-triage.env")
SOC_SOAR_URL = CONF.get("SOC_SOAR_URL", "http://127.0.0.1:8088").rstrip("/")
SOC_SOAR_ENV = CONF.get("SOC_SOAR_ENV", "/etc/omni-soar/soar.env")
SOC_SYSTEMCTL = CONF.get("SOC_SYSTEMCTL", "systemctl")
SOC_ADMIN_RESTARTABLE = [u.strip() for u in CONF.get("SOC_ADMIN_RESTARTABLE", "").split(",") if u.strip()]
# chemins SOAR : surchargeables (tests, autre installation) ; valeurs historiques par défaut
_SOAR_STATE = CONF.get("SOC_SOAR_STATE", _SOAR_STATE)
_SOAR_META = CONF.get("SOC_SOAR_META", _SOAR_META)
_SOAR_EXCL = CONF.get("SOC_SOAR_EXCL", _SOAR_EXCL)
_SOAR_FIX = CONF.get("SOC_SOAR_FIX", _SOAR_FIX)
_SOAR_DEC = CONF.get("SOC_SOAR_DEC", _SOAR_DEC)

# Garde-fou des tests (OMNI_TEST_MODE=1) : aucun chemin d'état ne doit viser la production,
# et aucune copie GELF n'est émise. Refus de démarrer plutôt qu'écrire au mauvais endroit.
_PROD_PREFIXES = ("/var/lib", "/etc", "/var/www", "/var/log", "/usr", "/opt/oms-")


def state_paths():
    return {"MOBILE_SUBS_FILE": SUBS_FILE, "MOBILE_CASES_FILE": CASES_FILE, "MOBILE_WATCH_FILE": WATCH_FILE,
            "SOC_REQ_DIR": SOC_REQ_DIR, "SOC_ADMIN_DIR": SOC_ADMIN_DIR,
            "SOC_APPEARANCE_DIR": SOC_APPEARANCE_DIR, "SOC_MODULES_DIR": SOC_MODULES_DIR}


def enforce_test_isolation():
    if os.environ.get("OMNI_TEST_MODE") != "1":
        return
    bad = [k for k, v in state_paths().items()
           if any(os.path.realpath(v) == p or os.path.realpath(v).startswith(p + "/") for p in _PROD_PREFIXES)]
    if bad:
        sys.exit("FATAL omni-mobile (OMNI_TEST_MODE=1) : chemin d'état de production refusé : " + ", ".join(bad))
    global SOC_ADMIN_GELF_URL
    SOC_ADMIN_GELF_URL = ""


enforce_test_isolation()
ADMIN_ROLES_FILE = os.path.join(SOC_ADMIN_DIR, "roles.json")
ADMIN_AUDIT_FILE = os.path.join(SOC_ADMIN_DIR, "audit.jsonl")
ADMIN_REQ_DIR = os.path.join(SOC_ADMIN_DIR, "requests")
ADMIN_EXEC_DIR = os.path.join(SOC_ADMIN_DIR, "exec")
ADMIN_FP_META = os.path.join(SOC_ADMIN_DIR, "fp-meta.json")
_ADMIN_LOCK = threading.RLock()
_ADMIN_RATE: dict = {}

# Paramètres modifiables : liste blanche fermée + bornes. Doit rester identique à
# celle de l'exécuteur (omni-soc-admin-exec), qui revalide tout (test dédié).
_EMAIL_ONE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
TRIAGE_PARAMS = {
    "MAIL_SCORE_THRESHOLD": {"type": "int", "min": 50, "max": 100, "label": "Seuil de score pour l'envoi d'un mail"},
    "GRAY_SCORE_THRESHOLD": {"type": "int", "min": 30, "max": 95, "label": "Seuil de score de la zone grise"},
    "TRIAGE_DEDUP_SECONDS": {"type": "int", "min": 300, "max": 86400, "label": "Fenêtre de déduplication (secondes)"},
    "FP_DEFAULT_TTL_DAYS": {"type": "int", "min": 1, "max": 90, "label": "Durée par défaut d'un faux positif (jours)"},
    "KILLCHAIN_COUNT": {"type": "int", "min": 2, "max": 10, "label": "Types d'alertes distincts pour une kill-chain"},
    "KILLCHAIN_WINDOW": {"type": "int", "min": 300, "max": 7200, "label": "Fenêtre de kill-chain (secondes)"},
    "MAIL_RECIPIENTS": {"type": "emails", "max_items": 10, "label": "Destinataires des mails d'alerte"},
}
SOAR_PARAMS = {
    "SOAR_MODE": {"type": "enum", "values": ["actif", "simulation"], "label": "Mode du moteur SOAR"},
    "SOAR_MIN_HITS": {"type": "int", "min": 1, "max": 100, "label": "Occurrences minimales avant blocage"},
    "SOAR_MIN_HITS_PAYS_NORMAL": {"type": "int", "min": 1, "max": 200, "label": "Occurrences minimales (pays habituel)"},
    "SOAR_TTL_HOURS": {"type": "int", "min": 1, "max": 168, "label": "Durée d'un blocage (heures)"},
    "SOAR_MAX": {"type": "int", "min": 10, "max": 2000, "label": "Nombre maximal d'IP bloquées"},
}
_UNIT_RE = re.compile(r"^(omni|oms)-[A-Za-z0-9@._-]{1,80}\.(service|timer)$")
_USER_RE2 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@\\-]{0,63}$")
_FP_KEYS = ("src_ip", "user", "host", "upn", "dest_ip", "srcip", "source")
_GL_ID_RE = re.compile(r"^[0-9a-f]{24}$")


class AdminError(Exception):
    def __init__(self, message, code=400):
        super().__init__(message)
        self.code = code


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _clean_text(value, max_len, min_len=0, what="texte"):
    s = " ".join(str(value if value is not None else "").split())
    if any(ord(c) < 32 for c in s):
        raise AdminError(f"{what} : caractères de contrôle refusés")
    if len(s) < min_len:
        raise AdminError(f"{what} obligatoire ({min_len} caractères minimum)")
    if len(s) > max_len:
        raise AdminError(f"{what} trop long ({max_len} caractères maximum)")
    return s


def _atomic_write_json(path, data, mode=0o640):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, "." + os.path.basename(path) + "." + _uuid.uuid4().hex[:8] + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_env_keys(path, keys):
    """Lit uniquement les clés demandées d'un fichier KEY=VALUE (jamais les autres : secrets)."""
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*([A-Z_][A-Z0-9_]*)=(.*)", line)
                if m and m.group(1) in keys:
                    out[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError:
        return None
    return out


# ------------------------------------------------------------------ rôles
def _load_roles():
    data = _jl(ADMIN_ROLES_FILE, {})
    users = data.get("users") if isinstance(data, dict) else None
    return users if isinstance(users, dict) else {}


def role_of(user):
    u = (user or "").strip().lower()
    if not u:
        return None
    if u in SOC_ADMINS:
        return "administrateur"
    r = (_load_roles().get(u) or {}).get("role")
    return r if r in ROLE_RANK else SOC_DEFAULT_ROLE


def role_at_least(user, role):
    r = role_of(user)
    return bool(r) and ROLE_RANK.get(r, 0) >= ROLE_RANK[role]


def admin_users():
    """Liste des comptes ayant un rôle explicite (configuration + console)."""
    out = [{"user": u, "role": "administrateur", "source": "configuration", "modifiable": False,
            "by": "", "ts": ""} for u in sorted(SOC_ADMINS)]
    for u, rec in sorted(_load_roles().items()):
        if u in SOC_ADMINS:
            continue
        out.append({"user": u, "role": rec.get("role"), "source": "console", "modifiable": True,
                    "by": rec.get("by", ""), "ts": rec.get("ts", ""), "motif": rec.get("motif", "")})
    admins = sum(1 for x in out if x["role"] == "administrateur")
    return {"users": out, "default_role": SOC_DEFAULT_ROLE, "admins": admins,
            "roles": [{"id": k, "label": ROLE_LABEL[k]} for k in ROLE_RANK],
            "note": "Tout compte authentifié par Graylog sans rôle explicite reçoit le rôle par défaut."}


# ------------------------------------------------------------------ audit
def _audit_last_hash(fh):
    fh.seek(0, 2)
    size = fh.tell()
    if not size:
        return "0" * 64, 0
    fh.seek(max(0, size - 65536))
    lines = [l for l in fh.read().decode("utf-8", "replace").splitlines() if l.strip()]
    for line in reversed(lines):
        try:
            e = json.loads(line)
            return str(e.get("hash", "0" * 64)), int(e.get("seq", 0))
        except Exception:
            continue
    return "0" * 64, 0


def _audit_hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def audit_append(actor, event, action, target="", motif="", before=None, after=None, result="",
                 request_id="", ip="", extra=None):
    """Ajoute une entrée au journal d'audit (ajout seul, chaînage SHA-256, verrou fichier)."""
    entry = {"ts": _now_iso(), "actor": str(actor or "?")[:64], "role": role_of(actor) or "",
             "ip": str(ip or "")[:45], "event": event, "action": action, "target": str(target)[:200],
             "motif": str(motif or "")[:300], "before": before, "after": after,
             "result": str(result or "")[:500], "request_id": request_id}
    if extra:
        entry["extra"] = extra
    os.makedirs(SOC_ADMIN_DIR, exist_ok=True)
    with _ADMIN_LOCK:
        fd = os.open(ADMIN_AUDIT_FILE, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(fd, "rb+") as fh:
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
            try:
                prev, seq = _audit_last_hash(fh)
                entry["seq"] = seq + 1
                entry["prev"] = prev
                entry["hash"] = _audit_hash(entry)
                fh.seek(0, 2)
                fh.write((json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
    if SOC_ADMIN_GELF_URL:
        threading.Thread(target=_audit_gelf, args=(entry,), daemon=True).start()
    return entry


def _audit_gelf(entry):
    try:
        msg = {"version": "1.1", "host": "omni-soc-console",
               "short_message": f"SOC admin {entry['event']} {entry['action']} {entry['target']} par {entry['actor']}",
               "_event_source": "soc_admin", "_soc_user": entry["actor"], "_soc_event": entry["event"],
               "_soc_action": entry["action"], "_soc_target": entry["target"], "_soc_result": entry["result"][:200],
               "_soc_request_id": entry["request_id"], "_soc_audit_seq": entry["seq"]}
        req = urllib.request.Request(SOC_ADMIN_GELF_URL, data=json.dumps(msg).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3).close()
    except Exception:
        pass


def audit_read(limit=200):
    """Dernières entrées + vérification complète de la chaîne."""
    entries, ok, broken_at, prev = [], True, None, "0" * 64
    try:
        with open(ADMIN_AUDIT_FILE, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    ok, broken_at = False, broken_at or n
                    continue
                if ok and (e.get("prev") != prev or _audit_hash(e) != e.get("hash")):
                    ok, broken_at = False, n
                prev = e.get("hash", "")
                entries.append(e)
                if len(entries) > 5000:
                    entries = entries[-limit:]
    except OSError:
        pass
    return {"entries": list(reversed(entries[-limit:])), "chain_ok": ok, "broken_at_line": broken_at,
            "total": entries[-1]["seq"] if entries and isinstance(entries[-1].get("seq"), int) else 0}


# ------------------------------------------------------------------ réseau / débit
def admin_client_ip(handler):
    peer = handler.client_address[0] if handler.client_address else ""
    if peer in ("127.0.0.1", "::1") and handler.headers.get("X-Real-IP"):
        return handler.headers.get("X-Real-IP").strip()   # posé par nginx ($remote_addr)
    return peer


def admin_ip_internal(ip):
    try:
        a = _ipa2.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in SOC_ADMIN_NETS)


def admin_rate_ok(user):
    now = time.time()
    with _ADMIN_LOCK:
        hist = [t for t in _ADMIN_RATE.get(user, []) if now - t < 300]
        if len(hist) >= SOC_ADMIN_WRITES_PER_5MIN:
            _ADMIN_RATE[user] = hist
            return False
        hist.append(now)
        _ADMIN_RATE[user] = hist
    return True


def csrf_token(session_token):
    return hmac.new(SECRET, b"csrf|" + (session_token or "").encode(), hashlib.sha256).hexdigest()[:40]


# ------------------------------------------------------------------ services locaux
def _http_json(method, url, payload=None, headers=None, timeout=8):
    data = json.dumps(payload).encode() if payload is not None else None
    h = {"Accept": "application/json"}
    if data is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx if url.startswith("https://") else None) as r:
        raw = r.read()
    return json.loads(raw or b"null")


def _triage_token():
    v = _read_env_keys(SOC_TRIAGE_ENV, {"TRIAGE_TOKEN"}) or {}
    return v.get("TRIAGE_TOKEN", "")


def _graylog_token():
    if not SOC_GRAYLOG_TOKEN_FILE:
        return ""
    try:
        with open(SOC_GRAYLOG_TOKEN_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def _graylog(method, path, timeout=15):
    tok = _graylog_token()
    if not tok:
        raise AdminError("jeton Graylog non configuré (SOC_GRAYLOG_TOKEN_FILE)", 503)
    auth = base64.b64encode(f"{tok}:token".encode()).decode()
    return _http_json(method, GL_URL + path, None,
                      {"Authorization": "Basic " + auth, "X-Requested-By": "omni-soc-admin"}, timeout)


# ------------------------------------------------------------------ lectures
def admin_fp_list():
    rules, err = [], ""
    try:
        rules = _http_json("GET", SOC_TRIAGE_URL + "/fp") or []
    except Exception as ex:
        err = f"service de triage injoignable ({type(ex).__name__})"
    meta = _jl(ADMIN_FP_META, {})
    out = []
    for r in rules if isinstance(rules, list) else []:
        k = f"{r.get('entity', '')}|{r.get('tag', '')}"
        m = meta.get(k, {})
        out.append({"entity": r.get("entity", ""), "tag": r.get("tag", ""), "title_sub": r.get("title_sub", ""),
                    "until": int(float(r.get("until", 0) or 0)), "by": r.get("by", ""),
                    "justification": m.get("justification", ""), "added": m.get("ts", "")})
    out.sort(key=lambda x: x["until"])
    return {"rules": out, "error": err,
            "note": "Les alertes critiques et les kill-chains ne sont jamais masquées par le triage."}


def _static_exclusions():
    out = []
    try:
        with open(_SOAR_FIX, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                parts = line.split("#", 1)
                val = parts[0].strip()
                if not val:
                    continue
                out.append({"value": val, "motif": parts[1].strip() if len(parts) > 1 else "", "line": n})
    except OSError:
        return None
    return out


def _soar_excluded(ip):
    """Même logique que omni-soar.motif_exclusion (whitelist d'environnement exceptée si absente)."""
    a = _ipa2.ip_address(ip)
    dyn = (_jl(_SOAR_EXCL, {}) or {}).get("ips") or {}
    if ip in dyn:
        return f"exclusion automatique : {dyn[ip]}"
    for e in _static_exclusions() or []:
        try:
            if a in _ipa2.ip_network(e["value"], strict=False):
                return f"exclusion fixe : {e['motif'] or e['value']}"
        except ValueError:
            continue
    wl = (_read_env_keys(SOC_SOAR_ENV, {"SOAR_WHITELIST"}) or {}).get("SOAR_WHITELIST", "")
    if ip in {x.strip() for x in wl.split(",") if x.strip()}:
        return "SOAR_WHITELIST"
    return None


def admin_soar():
    base = get_soar()
    params = _read_env_keys(SOC_SOAR_ENV, set(SOAR_PARAMS))
    return {"active": base.get("active", []), "count": base.get("count", 0),
            "requests": base.get("requests", []), "history": base.get("history", [])[:20],
            "static_exclusions": _static_exclusions(), "params": params,
            "param_spec": SOAR_PARAMS, "mode": (params or {}).get("SOAR_MODE", "actif") if params is not None else None,
            "env_readable": params is not None}


def admin_settings():
    vals = _read_env_keys(SOC_TRIAGE_ENV, set(TRIAGE_PARAMS))
    return {"triage": vals, "triage_readable": vals is not None, "triage_spec": TRIAGE_PARAMS,
            "soar": _read_env_keys(SOC_SOAR_ENV, set(SOAR_PARAMS)), "soar_spec": SOAR_PARAMS,
            "note": "Les secrets des fichiers de configuration ne sont jamais lus ni affichés."}


def admin_detections():
    if not _graylog_token():
        return {"available": False, "definitions": [],
                "error": "Jeton Graylog non configuré : renseigner SOC_GRAYLOG_TOKEN_FILE (voir la documentation)."}
    defs, page = [], 1
    while page <= 20:
        d = _graylog("GET", f"/events/definitions?per_page=100&page={page}") or {}
        batch = d.get("event_definitions") or d.get("elements") or []
        for x in batch:
            defs.append({"id": x.get("id"), "title": x.get("title", ""), "priority": x.get("priority"),
                         "state": x.get("state") or "?", "description": str(x.get("description") or "")[:240],
                         "updated_at": x.get("updated_at", "")})
        if not batch or page * 100 >= int(d.get("total") or 0):
            break
        page += 1
    defs.sort(key=lambda x: (x["state"] != "DISABLED", x["title"].lower()))
    return {"available": True, "definitions": defs,
            "enabled": sum(1 for x in defs if x["state"] == "ENABLED"),
            "disabled": sum(1 for x in defs if x["state"] == "DISABLED")}


def _systemctl(args, timeout=10):
    return _run([SOC_SYSTEMCTL] + list(args), timeout)


def admin_services():
    listing = _systemctl(["list-units", "--all", "--plain", "--no-legend", "--no-pager",
                          "--type=service,timer", "omni-*", "oms-*"])
    units = []
    for line in listing.splitlines():
        name = (line.split() or [""])[0]
        if _UNIT_RE.match(name) and name not in units:
            units.append(name)
    units = units[:300]
    props = "Id,Description,ActiveState,SubState,UnitFileState,Result,ExecMainStartTimestamp,ExecMainStatus,LastTriggerUSec,NextElapseUSecRealtime"
    raw = _systemctl(["show", "-p", props, "--"] + units, 20) if units else ""
    rows, cur = [], {}
    for line in raw.splitlines() + [""]:
        if not line.strip():
            if cur.get("Id"):
                rows.append(cur)
            cur = {}
            continue
        k, _, v = line.partition("=")
        cur[k] = v
    out = []
    for r in rows:
        uid = r.get("Id", "")
        if not _UNIT_RE.match(uid):
            continue
        st = r.get("ActiveState", "")
        res = r.get("Result", "")
        level = "crit" if st == "failed" or res not in ("", "success") else ("ok" if st in ("active", "activating") or uid.endswith(".service") and st == "inactive" and res == "success" else "warn")
        out.append({"unit": uid, "description": r.get("Description", "")[:120], "active": st, "sub": r.get("SubState", ""),
                    "enabled": r.get("UnitFileState", ""), "result": res, "level": level,
                    "started": r.get("ExecMainStartTimestamp", ""), "exit_status": r.get("ExecMainStatus", ""),
                    "last_trigger": r.get("LastTriggerUSec", ""), "next": r.get("NextElapseUSecRealtime", ""),
                    "restartable": uid in SOC_ADMIN_RESTARTABLE and uid.endswith(".service")})
    out.sort(key=lambda x: ({"crit": 0, "warn": 1, "ok": 2}[x["level"]], x["unit"]))
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            backend_sha = hashlib.sha256(f.read()).hexdigest()[:16]
    except OSError:
        backend_sha = ""
    hb = os.path.join(ADMIN_EXEC_DIR, "executor-heartbeat")
    try:
        hb_age = int(time.time() - os.path.getmtime(hb))
    except OSError:
        hb_age = None
    return {"units": out, "failed": sum(1 for x in out if x["level"] == "crit"),
            "versions": {"console_build": CONSOLE_BUILD, "backend_sha256": backend_sha,
                         "backend_path": os.path.abspath(__file__), "python": sys.version.split()[0]},
            "restartable": SOC_ADMIN_RESTARTABLE, "executor_heartbeat_age_s": hb_age,
            "generated": _now_iso()}


# ------------------------------------------------------------------ validation des actions
def _v_ip(value, public=True):
    s = str(value or "").strip()
    try:
        a = _ipa2.ip_address(s)
    except ValueError:
        raise AdminError("adresse IP invalide")
    if public and not (a.version == 4 and a.is_global):
        raise AdminError("seules les IPv4 publiques sont gérées par le SOAR")
    return str(a)


def _v_net(value):
    s = str(value or "").strip()
    if len(s) > 43:
        raise AdminError("valeur trop longue")
    try:
        n = _ipa2.ip_network(s, strict=False)
    except ValueError:
        raise AdminError("adresse IP ou réseau CIDR invalide")
    if n.version != 4 or not n.network_address.is_global or n.prefixlen < 16:
        raise AdminError("réseau IPv4 public attendu, préfixe /16 au minimum")
    return str(n.network_address) if n.num_addresses == 1 else str(n)


def _v_param(spec_table, key, value):
    if key not in spec_table:
        raise AdminError("paramètre non modifiable depuis la console")
    spec = spec_table[key]
    if spec["type"] == "int":
        try:
            iv = int(str(value).strip())
        except ValueError:
            raise AdminError("valeur entière attendue")
        if not spec["min"] <= iv <= spec["max"]:
            raise AdminError(f"valeur hors bornes ({spec['min']} à {spec['max']})")
        return str(iv)
    if spec["type"] == "enum":
        v = str(value).strip().lower()
        if v not in spec["values"]:
            raise AdminError("valeur non autorisée")
        return v
    if spec["type"] == "emails":
        items = [x.strip() for x in str(value).replace(";", ",").split(",") if x.strip()]
        if not items or len(items) > spec["max_items"]:
            raise AdminError(f"entre 1 et {spec['max_items']} adresses")
        for x in items:
            if not _EMAIL_ONE.match(x):
                raise AdminError("adresse électronique invalide")
        return ",".join(items)
    raise AdminError("type de paramètre inconnu")


def _v_entity(value):
    s = str(value or "").strip()
    if any(ord(c) < 32 for c in s) or len(s) > 200:
        raise AdminError("entité invalide")
    if "=" in s:
        k, _, v = s.partition("=")
        if k not in _FP_KEYS or len(v.strip()) < 3:
            raise AdminError("entité attendue sous la forme clé=valeur (src_ip, user, host, upn, dest_ip, source), valeur de 3 caractères minimum")
        return f"{k}={v.strip()}"
    if len(s) < 6:
        raise AdminError("entité trop courte : une règle trop large masquerait d'autres alertes")
    return s


def _a_role_set(p, actor):
    user = str(p.get("user", "")).strip().lower()
    if not _USER_RE2.match(user):
        raise AdminError("identifiant de compte invalide")
    role = str(p.get("role", "")).strip().lower()
    if role not in ROLE_RANK and role != "aucun":
        raise AdminError("rôle inconnu")
    if user in SOC_ADMINS:
        raise AdminError("compte administrateur défini par la configuration (SOC_ADMINS) : non modifiable depuis la console")
    if user == (actor or "").lower():
        raise AdminError("un administrateur ne modifie pas son propre rôle")
    return {"user": user, "role": role}


def _p_role_set(c):
    cur = (_load_roles().get(c["user"]) or {}).get("role")
    eff_before = cur or f"{SOC_DEFAULT_ROLE} (par défaut)"
    eff_after = f"{SOC_DEFAULT_ROLE} (par défaut)" if c["role"] == "aucun" else c["role"]
    fort = "administrateur" in (cur, c["role"])
    return {"before": eff_before, "after": eff_after, "impact": "fort" if fort else "normal",
            "effects": [f"Rôle de {c['user']} : {eff_before} -> {eff_after}"], "refus": "" if eff_before != eff_after else "aucun changement"}


def _x_role_set(c, actor, motif, rid):
    with _ADMIN_LOCK:
        data = _jl(ADMIN_ROLES_FILE, {})
        users = data.get("users") if isinstance(data, dict) and isinstance(data.get("users"), dict) else {}
        if c["role"] == "aucun":
            users.pop(c["user"], None)
        else:
            users[c["user"]] = {"role": c["role"], "by": actor, "ts": _now_iso(), "motif": motif, "request_id": rid}
        _atomic_write_json(ADMIN_ROLES_FILE, {"users": users, "updated": _now_iso()})
    return {"ok": True, "message": "Rôle mis à jour."}


def _a_fp_add(p, actor):
    ttl = p.get("ttl_days")
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        raise AdminError("durée de validité obligatoire (jours)")
    if not 1 <= ttl <= 90:
        raise AdminError("durée de validité : 1 à 90 jours")
    return {"entity": _v_entity(p.get("entity")), "tag": _clean_text(p.get("tag", ""), 60, what="étiquette"),
            "title_sub": _clean_text(p.get("title_sub", ""), 80, what="extrait de titre"), "ttl_days": ttl,
            "justification": _clean_text(p.get("justification", ""), 300, 10, "justification")}


def _p_fp_add(c):
    cur = [r for r in admin_fp_list()["rules"] if r["entity"] == c["entity"]]
    until = time.strftime("%d/%m/%Y", time.localtime(time.time() + c["ttl_days"] * 86400))
    scope = f"détection {c['tag']}" if c["tag"] else (f"titres contenant « {c['title_sub']} »" if c["title_sub"] else "toutes les détections non critiques")
    return {"before": [f"{r['entity']} | {r['tag'] or r['title_sub'] or '*'}" for r in cur],
            "after": f"{c['entity']} | {c['tag'] or c['title_sub'] or '*'} jusqu'au {until}",
            "impact": "normal", "refus": "",
            "effects": [f"Sourdine des mails non critiques pour {c['entity']} ({scope}) jusqu'au {until}.",
                        "Les alertes restent indexées et visibles dans la console ; les critiques ne sont jamais masquées."],
            "warnings": [] if c["tag"] or c["title_sub"] else ["Portée large : préciser une étiquette de détection si possible."]}


def _x_fp_add(c, actor, motif, rid):
    tok = _triage_token()
    res = _http_json("POST", SOC_TRIAGE_URL + "/fp",
                     {"entity": c["entity"], "tag": c["tag"], "title_sub": c["title_sub"],
                      "by": f"soc-admin:{actor}"[:60], "ttl_days": c["ttl_days"]},
                     {"X-Triage-Token": tok})
    if not (isinstance(res, dict) and res.get("ok")):
        return {"ok": False, "error": "le service de triage a refusé la règle"}
    with _ADMIN_LOCK:
        meta = _jl(ADMIN_FP_META, {})
        meta[f"{c['entity']}|{c['tag']}"] = {"justification": c["justification"], "by": actor, "ts": _now_iso(),
                                             "ttl_days": c["ttl_days"], "request_id": rid}
        _atomic_write_json(ADMIN_FP_META, meta)
    return {"ok": True, "message": "Faux positif enregistré.",
            "rollback": {"action": "fp_remove", "params": {"entity": c["entity"]}}}


def _a_fp_remove(p, actor):
    return {"entity": _v_entity(p.get("entity"))}


def _p_fp_remove(c):
    cur = [r for r in admin_fp_list()["rules"] if r["entity"] == c["entity"]]
    return {"before": [f"{r['entity']} | {r['tag'] or r['title_sub'] or '*'}" for r in cur], "after": [],
            "impact": "normal", "refus": "" if cur else "aucune règle active pour cette entité",
            "effects": [f"Retrait de {len(cur)} règle(s) : le service de triage retire toutes les règles de l'entité."]}


def _x_fp_remove(c, actor, motif, rid):
    tok = _triage_token()
    res = _http_json("DELETE", SOC_TRIAGE_URL + "/fp?entity=" + urllib.parse.quote(c["entity"], safe=""),
                     None, {"X-Triage-Token": tok})
    with _ADMIN_LOCK:
        meta = _jl(ADMIN_FP_META, {})
        for k in [k for k in meta if k.split("|", 1)[0] == c["entity"]]:
            meta.pop(k, None)
        _atomic_write_json(ADMIN_FP_META, meta)
    return {"ok": bool(isinstance(res, dict) and res.get("ok")), "message": "Règles retirées."}


def _a_soar_block(p, actor):
    return {"ip": _v_ip(p.get("ip"))}


def _p_soar_block(c):
    ip, now = c["ip"], time.time()
    bl = _jl(_SOAR_STATE, {})
    params = _read_env_keys(SOC_SOAR_ENV, set(SOAR_PARAMS)) or {}
    active = sum(1 for v in bl.values() if isinstance(v, (int, float)) and v > now)
    excl = _soar_excluded(ip)
    warnings = []
    if params.get("SOAR_MODE", "actif") == "simulation":
        warnings.append("Le moteur SOAR est en mode simulation pour les blocages automatiques ; un blocage manuel approuvé reste appliqué.")
    if isinstance(bl.get(ip), (int, float)) and bl[ip] > now:
        warnings.append("IP déjà bloquée : le blocage serait prolongé.")
    ttl = params.get("SOAR_TTL_HOURS", "24")
    return {"before": "bloquée" if ip in bl and bl[ip] > now else "non bloquée", "after": f"bloquée {ttl} h",
            "impact": "fort", "refus": f"IP exclue ({excl}) : blocage refusé" if excl else "",
            "effects": [f"Ajout de {ip} à la liste lue par les FortiGate (effet sous 2 min), levée automatique après {ttl} h.",
                        f"IP actuellement bloquées : {active}."], "warnings": warnings}


def _x_soar_block(c, actor, motif, rid):
    res = _http_json("POST", SOC_SOAR_URL + "/block", {"ip": c["ip"], "manual": True, "by": f"soc:{actor}"[:60]})
    ok = bool(isinstance(res, dict) and res.get("ok"))
    return {"ok": ok, "message": "IP bloquée." if ok else "", "error": "" if ok else str((res or {}).get("error", "refus du SOAR"))[:200],
            "rollback": {"action": "soar_unblock", "params": {"ip": c["ip"]}} if ok else None}


def _a_soar_unblock(p, actor):
    return {"ip": _v_ip(p.get("ip"))}


def _p_soar_unblock(c):
    bl = _jl(_SOAR_STATE, {})
    blocked = isinstance(bl.get(c["ip"]), (int, float)) and bl[c["ip"]] > time.time()
    return {"before": "bloquée" if blocked else "non bloquée", "after": "non bloquée", "impact": "normal",
            "refus": "" if blocked else "IP non bloquée actuellement",
            "effects": ["Demande déposée pour omni-soc-actions (outil omni-soar-debloquer), traitée sous 1 min."]}


def _queue_soar_unblock(ip, user, exclure=False, motif=""):
    pend = os.path.join(SOC_REQ_DIR, "pending")
    os.makedirs(pend, exist_ok=True)
    if len(_glob.glob(os.path.join(pend, "*.json"))) >= 20:
        raise AdminError("trop de demandes SOAR en attente", 429)
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + _uuid.uuid4().hex[:8]
    req = {"id": rid, "t": _now_iso(), "user": str(user)[:64], "action": "debloquer",
           "ip": ip, "exclure": bool(exclure), "motif": motif[:80], "status": "pending"}
    tmp = os.path.join(pend, "." + rid + ".tmp")
    with open(tmp, "w") as f:
        json.dump(req, f)
    os.replace(tmp, os.path.join(pend, rid + ".json"))
    return rid


def _x_soar_unblock(c, actor, motif, rid):
    qid = _queue_soar_unblock(c["ip"], actor, False, motif)
    return {"ok": True, "queued": qid, "message": "Déblocage transmis (effet sous 2 min sur les FortiGate)."}


def _a_exclusion_add(p, actor):
    return {"value": _v_net(p.get("value"))}


def _p_exclusion_add(c):
    cur = _static_exclusions()
    dup = cur is not None and any(e["value"] == c["value"] for e in cur)
    return {"before": "absente", "after": "exclusion fixe", "impact": "fort",
            "refus": "déjà présente dans la liste fixe" if dup else "",
            "effects": [f"{c['value']} ne sera plus jamais bloquée automatiquement par le SOAR.",
                        "Écriture par l'exécuteur privilégié (sauvegarde du fichier avant modification)."],
            "warnings": [] if cur is not None else ["Liste fixe illisible depuis la console."]}


def _a_exclusion_remove(p, actor):
    return {"value": _v_net(p.get("value"))}


def _p_exclusion_remove(c):
    cur = _static_exclusions() or []
    present = any(e["value"] == c["value"] for e in cur)
    return {"before": "exclusion fixe", "after": "absente", "impact": "fort",
            "refus": "" if present else "valeur absente de la liste fixe",
            "effects": [f"{c['value']} pourra de nouveau être bloquée par le SOAR si une détection la vise."]}


def _a_param(table, kind):
    def validate(p, actor):
        key = str(p.get("key", "")).strip().upper()
        return {"key": key, "value": _v_param(table, key, p.get("value")), "file": kind}
    return validate


def _p_param(table, path, label):
    def preview(c):
        cur = _read_env_keys(path, set(table))
        before = (cur or {}).get(c["key"])
        refus = "" if before != c["value"] else "aucun changement"
        if table is TRIAGE_PARAMS and c["key"] in ("MAIL_SCORE_THRESHOLD", "GRAY_SCORE_THRESHOLD") and cur:
            mail = int(c["value"] if c["key"] == "MAIL_SCORE_THRESHOLD" else cur.get("MAIL_SCORE_THRESHOLD", 80))
            gray = int(c["value"] if c["key"] == "GRAY_SCORE_THRESHOLD" else cur.get("GRAY_SCORE_THRESHOLD", 70))
            if gray >= mail:
                refus = "le seuil de zone grise doit rester inférieur au seuil de mail"
        return {"before": before, "after": c["value"], "impact": "fort", "refus": refus,
                "effects": [f"{label} : {table[c['key']]['label']} {before if before is not None else '(non défini)'} -> {c['value']}",
                            "Écriture par l'exécuteur privilégié avec sauvegarde ; pris en compte à la prochaine alerte."],
                "warnings": [] if cur is not None else ["Fichier de configuration illisible depuis la console."]}
    return preview


def _a_detection(p, actor):
    did = str(p.get("id", "")).strip().lower()
    if not _GL_ID_RE.match(did):
        raise AdminError("identifiant de détection invalide")
    en = p.get("enabled")
    if not isinstance(en, bool):
        raise AdminError("état cible attendu (activer ou désactiver)")
    return {"id": did, "enabled": en}


def _p_detection(c):
    d = _graylog("GET", f"/events/definitions/{c['id']}") or {}
    cur = d.get("state") or "?"
    want = "ENABLED" if c["enabled"] else "DISABLED"
    return {"before": cur, "after": want, "impact": "normal" if c["enabled"] else "fort",
            "refus": "" if cur != want else "la détection est déjà dans cet état",
            "effects": [f"« {str(d.get('title', c['id']))[:120]} » : {cur} -> {want}"],
            "warnings": [] if c["enabled"] else ["Une détection désactivée ne produit plus d'alerte : angle mort tant qu'elle reste coupée."]}


def _x_detection(c, actor, motif, rid):
    _graylog("PUT", f"/events/definitions/{c['id']}/{'schedule' if c['enabled'] else 'unschedule'}")
    return {"ok": True, "message": "Détection " + ("activée." if c["enabled"] else "désactivée."),
            "rollback": {"action": "detection_toggle", "params": {"id": c["id"], "enabled": not c["enabled"]}}}


def _a_restart(p, actor):
    unit = str(p.get("unit", "")).strip()
    if not _UNIT_RE.match(unit) or not unit.endswith(".service"):
        raise AdminError("nom de service invalide")
    if unit not in SOC_ADMIN_RESTARTABLE:
        raise AdminError("service absent de la liste blanche des redémarrages (SOC_ADMIN_RESTARTABLE)", 403)
    return {"unit": unit}


def _p_restart(c):
    st = _systemctl(["show", "-p", "ActiveState", "--value", "--", c["unit"]])
    return {"before": st or "?", "after": "redémarré", "impact": "fort", "refus": "",
            "effects": [f"Redémarrage de {c['unit']} par l'exécuteur privilégié (liste blanche revalidée côté exécuteur)."]}


def _x_exec(kind):
    """Dépôt dans la file de l'exécuteur privilégié (omni-soc-admin-exec)."""
    def execute(c, actor, motif, rid):
        pend = os.path.join(ADMIN_EXEC_DIR, "pending")
        os.makedirs(pend, exist_ok=True)
        if len(_glob.glob(os.path.join(pend, "*.json"))) >= 20:
            raise AdminError("trop d'actions en attente d'exécution", 429)
        job = {"id": rid, "kind": kind, "params": {k: v for k, v in c.items()}, "actor": actor,
               "motif": motif, "t": _now_iso()}
        _atomic_write_json(os.path.join(pend, rid + ".json"), job, 0o640)
        return {"ok": True, "queued": rid, "message": "Action transmise à l'exécuteur (traitement sous 1 min)."}
    return execute


# ------------------------------------------------------------------ apparence de la console
# Nom affiché, sous-titre, logo, couleurs (variables CSS existantes de app-professional.css)
# et thème par défaut. Stockage : SOC_APPEARANCE_DIR/appearance.json (+ logo.<ext>), écrit
# de façon atomique en 0640. Lecture tolérante : fichier absent, illisible ou invalide =
# thème d'origine (la console ne doit jamais être cassée par ce réglage).
APPEARANCE_FILE = os.path.join(SOC_APPEARANCE_DIR, "appearance.json")
APPEARANCE_LOGO_MAX = 512 * 1024                     # octets, après décodage
APPEARANCE_LOGO_DIM = (16, 1024)                     # largeur et hauteur, en pixels
APPEARANCE_MAX_BODY = 720 * 1024                     # corps JSON de la route dédiée (logo en base64)
APPEARANCE_MIN_CONTRAST = 4.5                        # WCAG 2.x niveau AA, texte normal
APPEARANCE_THEMES = ("system", "dark", "light")
APPEARANCE_NAME_DEFAULT = "OMNI SOC"
APPEARANCE_SUBTITLE_DEFAULT = "OMNITECH SECURITY"
_APPEARANCE_LOGO_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
# Valeurs d'origine = celles de mobile/soc/app-professional.css (:root et html[data-theme=light]).
APPEARANCE_DEFAULTS = {
    "dark": {"pro-accent": "#447ce2", "cy": "#87b4ff", "bg": "#0c1220", "card": "#151f30",
             "fg": "#eaf0f8", "mut": "#b0bed2", "pro-sidebar": "#101a2c"},
    "light": {"pro-accent": "#285eb8", "cy": "#2859ad", "bg": "#f1f4f9", "card": "#ffffff",
              "fg": "#182740", "mut": "#53647b", "pro-sidebar": "#15253f"},
}
APPEARANCE_LABELS = {
    "pro-accent": "Accent principal (boutons, éléments actifs)", "cy": "Accent du texte (liens, valeurs mises en avant)",
    "bg": "Fond de page", "card": "Fond des cartes et de l'en-tête", "fg": "Texte principal",
    "mut": "Texte secondaire", "pro-sidebar": "Barre latérale",
}
# Paires texte/fond contrôlées. Une valeur commençant par « # » est une couleur fixe de la
# feuille de style (texte blanc des boutons, liens de la barre latérale).
APPEARANCE_PAIRS = [
    ("fg", "bg", "texte principal sur le fond de page"), ("fg", "card", "texte principal sur les cartes"),
    ("mut", "bg", "texte secondaire sur le fond de page"), ("mut", "card", "texte secondaire sur les cartes"),
    ("cy", "bg", "accent du texte sur le fond de page"), ("cy", "card", "accent du texte sur les cartes"),
    ("#ffffff", "pro-accent", "texte blanc des boutons principaux sur l'accent"),
    ("#ffffff", "pro-sidebar", "titre blanc sur la barre latérale"),
    ("#c0cde1", "pro-sidebar", "liens de navigation sur la barre latérale"),
]
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_BIDI_RE = re.compile("[\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def _rel_luminance(hex_color):
    def channel(v):
        c = v / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast_ratio(a, b):
    """Rapport de contraste WCAG entre deux couleurs #rrggbb (1 à 21)."""
    la, lb = sorted((_rel_luminance(a), _rel_luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _v_hex(value, what):
    s = str(value if value is not None else "").strip()
    if not _HEX_RE.match(s):
        raise AdminError(f"{what} : couleur hexadécimale #rrggbb attendue")
    return s.lower()


def appearance_colors(raw):
    """Valide les surcharges de couleurs {mode: {variable: #rrggbb}} (clés en liste blanche)."""
    if raw in (None, ""):
        return {"dark": {}, "light": {}}
    if not isinstance(raw, dict) or set(raw) - set(APPEARANCE_DEFAULTS):
        raise AdminError("couleurs : modes acceptés « dark » et « light »")
    out = {}
    for mode in APPEARANCE_DEFAULTS:
        vals = raw.get(mode) or {}
        if not isinstance(vals, dict):
            raise AdminError(f"couleurs du mode {mode} : objet attendu")
        unknown = set(vals) - set(APPEARANCE_DEFAULTS[mode])
        if unknown:
            raise AdminError("variable de couleur non modifiable : " + ", ".join(sorted(str(k)[:40] for k in unknown)))
        out[mode] = {k: _v_hex(v, f"couleur {k} ({mode})") for k, v in vals.items()
                     if v not in (None, "")}
        # une valeur identique à l'origine n'est pas une surcharge
        out[mode] = {k: v for k, v in out[mode].items() if v != APPEARANCE_DEFAULTS[mode][k]}
    return out


def appearance_contrast_issues(colors):
    """Paires texte/fond sous le seuil, parmi celles qui touchent au moins une couleur modifiée.
    Les paires entièrement d'origine ne sont pas bloquantes (elles ne dépendent pas de l'administrateur)."""
    issues = []
    for mode, defaults in APPEARANCE_DEFAULTS.items():
        over = colors.get(mode) or {}
        eff = dict(defaults, **over)
        for fg, bg, label in APPEARANCE_PAIRS:
            if fg not in over and bg not in over:
                continue
            ratio = contrast_ratio(fg if fg.startswith("#") else eff[fg], eff[bg])
            if ratio < APPEARANCE_MIN_CONTRAST:
                issues.append({"mode": mode, "pair": [fg, bg], "label": label, "ratio": round(ratio, 2)})
    return issues


def _appearance_text(value, max_len, what):
    s = _clean_text(value, max_len, 0, what)
    if _BIDI_RE.search(s):
        raise AdminError(f"{what} : caractères invisibles ou de contrôle refusés")
    return s


def image_info(data):
    """Type et dimensions d'une image PNG, JPEG ou WebP d'après sa signature binaire.
    Renvoie (type MIME, largeur, hauteur) ou lève AdminError. Aucun autre format (SVG compris)."""
    n = len(data)
    if n >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        w, h = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
        return "image/png", w, h
    if n >= 4 and data[:3] == b"\xff\xd8\xff":
        i = 2
        while i + 9 < n:
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            if marker == 0xFF:
                i += 1
                continue
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            seg = int.from_bytes(data[i + 2:i + 4], "big")
            if seg < 2:
                break
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                h, w = int.from_bytes(data[i + 5:i + 7], "big"), int.from_bytes(data[i + 7:i + 9], "big")
                return "image/jpeg", w, h
            if marker in (0xD9, 0xDA):
                break
            i += 2 + seg
        raise AdminError("image JPEG illisible (dimensions introuvables)")
    if n >= 30 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind = data[12:16]
        if kind == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
            w = int.from_bytes(data[26:28], "little") & 0x3FFF
            h = int.from_bytes(data[28:30], "little") & 0x3FFF
            return "image/webp", w, h
        if kind == b"VP8L" and data[20] == 0x2F:
            b0, b1, b2, b3 = data[21:25]
            w = 1 + (b0 | ((b1 & 0x3F) << 8))
            h = 1 + ((b1 >> 6) | (b2 << 2) | ((b3 & 0x0F) << 10))
            return "image/webp", w, h
        if kind == b"VP8X":
            w = 1 + int.from_bytes(data[24:27], "little")
            h = 1 + int.from_bytes(data[27:30], "little")
            return "image/webp", w, h
        raise AdminError("image WebP illisible (en-tête non reconnu)")
    raise AdminError("format de logo refusé : PNG, JPEG ou WebP uniquement (signature binaire contrôlée)")


def appearance_logo(data):
    """Contrôle d'un logo décodé : taille, signature, dimensions. Renvoie ses métadonnées."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise AdminError("logo vide")
    if len(data) > APPEARANCE_LOGO_MAX:
        raise AdminError(f"logo trop volumineux ({len(data) // 1024} Ko, {APPEARANCE_LOGO_MAX // 1024} Ko maximum)")
    mime, w, h = image_info(bytes(data))
    lo, hi = APPEARANCE_LOGO_DIM
    if not (lo <= w <= hi and lo <= h <= hi):
        raise AdminError(f"dimensions du logo refusées ({w} x {h} px ; {lo} à {hi} px de côté)")
    return {"type": mime, "width": w, "height": h, "size": len(data),
            "sha256": hashlib.sha256(bytes(data)).hexdigest()}


def _appearance_defaults():
    return {"name": "", "subtitle": "", "theme_default": "system", "colors": {"dark": {}, "light": {}}, "logo": None}


def load_appearance():
    """Configuration en vigueur, revalidée à chaque lecture. Toute anomalie = valeurs d'origine
    pour le champ concerné (fichier corrompu : tout d'origine)."""
    cfg = _appearance_defaults()
    raw = _jl(APPEARANCE_FILE, None)
    if not isinstance(raw, dict):
        return cfg
    for key, max_len in (("name", 40), ("subtitle", 60)):
        try:
            cfg[key] = _appearance_text(raw.get(key, ""), max_len, key)
        except AdminError:
            pass
    if raw.get("theme_default") in APPEARANCE_THEMES:
        cfg["theme_default"] = raw["theme_default"]
    try:
        colors = appearance_colors(raw.get("colors"))
        if not appearance_contrast_issues(colors):
            cfg["colors"] = colors
    except AdminError:
        pass
    logo = raw.get("logo")
    if isinstance(logo, dict) and logo.get("type") in _APPEARANCE_LOGO_EXT and \
            re.fullmatch(r"[0-9a-f]{64}", str(logo.get("sha256", ""))):
        cfg["logo"] = {k: logo.get(k) for k in ("type", "width", "height", "size", "sha256")}
    for key in ("updated_by", "updated_at"):
        if isinstance(raw.get(key), str):
            cfg[key] = raw[key][:64]
    return cfg


def _appearance_logo_path(mime):
    return os.path.join(SOC_APPEARANCE_DIR, "logo." + _APPEARANCE_LOGO_EXT[mime])


def appearance_logo_bytes():
    """(type MIME, octets) du logo personnalisé, ou None. Le fichier est recontrôlé à chaque
    lecture (empreinte enregistrée, signature) : un fichier altéré n'est jamais servi."""
    logo = load_appearance().get("logo")
    if not logo:
        return None
    try:
        with open(_appearance_logo_path(logo["type"]), "rb") as fh:
            data = fh.read(APPEARANCE_LOGO_MAX + 1)
        meta = appearance_logo(data)
    except (OSError, AdminError):
        return None
    if meta["sha256"] != logo["sha256"] or meta["type"] != logo["type"]:
        return None
    return logo["type"], data


def appearance_public():
    """Vue servie à tout utilisateur authentifié : uniquement ce qui est nécessaire à l'affichage."""
    cfg = load_appearance()
    logo = None
    if cfg["logo"] and appearance_logo_bytes():
        logo = {"url": "/m/api/appearance/logo?v=" + cfg["logo"]["sha256"][:16],
                "width": cfg["logo"]["width"], "height": cfg["logo"]["height"]}
    return {"name": cfg["name"], "subtitle": cfg["subtitle"], "theme_default": cfg["theme_default"],
            "colors": cfg["colors"], "logo": logo}


def admin_appearance():
    """Vue d'administration : configuration, valeurs d'origine, libellés et limites."""
    out = appearance_public()
    cfg = load_appearance()
    out.update(updated_by=cfg.get("updated_by", ""), updated_at=cfg.get("updated_at", ""),
               logo_meta=cfg["logo"] if out["logo"] else None,
               defaults={"name": APPEARANCE_NAME_DEFAULT, "subtitle": APPEARANCE_SUBTITLE_DEFAULT,
                         "theme_default": "system", "colors": APPEARANCE_DEFAULTS},
               labels=APPEARANCE_LABELS, themes=list(APPEARANCE_THEMES),
               pairs=[{"fg": a, "bg": b, "label": c} for a, b, c in APPEARANCE_PAIRS],
               limits={"logo_max_bytes": APPEARANCE_LOGO_MAX, "logo_min_px": APPEARANCE_LOGO_DIM[0],
                       "logo_max_px": APPEARANCE_LOGO_DIM[1], "logo_types": sorted(_APPEARANCE_LOGO_EXT),
                       "min_contrast": APPEARANCE_MIN_CONTRAST, "name_max": 40, "subtitle_max": 60},
               file_ok=isinstance(_jl(APPEARANCE_FILE, None), dict) or not os.path.exists(APPEARANCE_FILE))
    return out


def _a_appearance(p, actor):
    if p.get("reset") is True:
        return {"id": "apparence", "reset": True}
    c = {"id": "apparence", "reset": False,
         "name": _appearance_text(p.get("name", ""), 40, "nom de la console"),
         "subtitle": _appearance_text(p.get("subtitle", ""), 60, "sous-titre"),
         "theme_default": str(p.get("theme_default") or "system")}
    if c["theme_default"] not in APPEARANCE_THEMES:
        raise AdminError("thème par défaut : system, dark ou light")
    c["colors"] = appearance_colors(p.get("colors"))
    issues = appearance_contrast_issues(c["colors"])
    if issues:
        raise AdminError("contraste insuffisant (" + str(APPEARANCE_MIN_CONTRAST) + ":1 minimum) : " + "; ".join(
            f"{i['label']} en mode {'sombre' if i['mode'] == 'dark' else 'clair'} = {i['ratio']}:1" for i in issues[:4]))
    logo = p.get("logo", "conserver")
    if logo in (None, "", "conserver"):
        c["logo"] = "conserver"
    elif logo == "origine":
        c["logo"] = "origine"
    elif isinstance(logo, dict) and isinstance(logo.get("data"), str):
        b64 = logo["data"]
        if b64.startswith("data:"):
            b64 = b64.split(",", 1)[-1]
        if len(b64) > (APPEARANCE_LOGO_MAX * 4) // 3 + 8:
            raise AdminError(f"logo trop volumineux ({APPEARANCE_LOGO_MAX // 1024} Ko maximum)")
        try:
            data = base64.b64decode(b64, validate=True)
        except (ValueError, TypeError):
            raise AdminError("logo : encodage base64 invalide") from None
        c["logo"] = "nouveau"
        c["logo_meta"] = appearance_logo(data)
        c["logo_data"] = data
    else:
        raise AdminError("logo : « conserver », « origine » ou {data: base64}")
    return c


def _appearance_summary(cfg):
    logo = cfg.get("logo")
    return {"nom": cfg.get("name") or f"{APPEARANCE_NAME_DEFAULT} (origine)",
            "sous_titre": cfg.get("subtitle") or f"{APPEARANCE_SUBTITLE_DEFAULT} (origine)",
            "theme": cfg.get("theme_default", "system"),
            "couleurs": {m: v for m, v in (cfg.get("colors") or {}).items() if v} or "origine",
            "logo": f"{logo['type']} {logo['width']}x{logo['height']} sha256:{logo['sha256'][:12]}" if logo else "origine"}


def _appearance_target(c):
    cur = load_appearance()
    if c["reset"]:
        return _appearance_defaults()
    new = {k: c[k] for k in ("name", "subtitle", "theme_default", "colors")}
    new["logo"] = None if c["logo"] == "origine" else (c["logo_meta"] if c["logo"] == "nouveau" else cur["logo"])
    return new


def _p_appearance(c):
    before = _appearance_summary(load_appearance())
    after = _appearance_summary(_appearance_target(c))
    effects = ["Mise en forme appliquée à tous les utilisateurs au prochain chargement de la console.",
               "Le choix personnel de thème (clair/sombre) d'un utilisateur reste prioritaire sur le thème par défaut."]
    if c["reset"]:
        effects.insert(0, "Retour au nom, au logo, aux couleurs et au thème d'origine.")
    return {"before": before, "after": after, "impact": "normal", "effects": effects,
            "refus": "" if before != after else "aucun changement"}


def _x_appearance(c, actor, motif, rid):
    with _ADMIN_LOCK:
        os.makedirs(SOC_APPEARANCE_DIR, mode=0o750, exist_ok=True)
        target = _appearance_target(c)
        if c.get("logo") == "nouveau":
            path = _appearance_logo_path(target["logo"]["type"])
            tmp = path + "." + _uuid.uuid4().hex[:8] + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            with os.fdopen(fd, "wb") as fh:
                fh.write(c["logo_data"])
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        _atomic_write_json(APPEARANCE_FILE, dict(target, version=1, updated_by=actor, updated_at=_now_iso(),
                                                 request_id=rid))
        keep = _appearance_logo_path(target["logo"]["type"]) if target.get("logo") else None
        for mime in _APPEARANCE_LOGO_EXT:
            old = _appearance_logo_path(mime)
            if old != keep and os.path.exists(old):
                os.unlink(old)
    return {"ok": True, "message": "Apparence enregistrée : appliquée à tous les utilisateurs au prochain chargement de la console."}


# ------------------------------------------------------------------ modules et widgets du site
# Configuration du site hors du code distribué. Le catalogue Graylog est réservé
# aux administrateurs ; la publication d'une page attribue des droits SOC explicites,
# indépendants des permissions du compte de service Graylog utilisé pour le catalogue.
MODULES_CONFIG_FILE = os.path.join(SOC_MODULES_DIR, "config.json")
MODULES_MAX_BODY = 128 * 1024
_MODULE_SLUG = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
_MODULE_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,99}$")
_MODULE_SOURCE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MODULE_WIDGET_TYPES = frozenset({"count", "timeseries", "terms", "messages"})


def _module_text(value, maximum, label, empty=True):
    if (not isinstance(value, str) or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or (not empty and not value.strip())):
        raise AdminError(label + " invalide")
    return value.strip()


def _module_strings(raw, pattern, maximum, label, nonempty=False):
    if (not isinstance(raw, list) or len(raw) > maximum or (nonempty and not raw)
            or any(not isinstance(x, str) or not pattern.fullmatch(x) for x in raw)
            or len(set(raw)) != len(raw)):
        raise AdminError(label + " invalide")
    return list(raw)


def modules_validate_config(raw):
    if not isinstance(raw, dict) or set(raw) - {"schema_version", "revision", "pages"}:
        raise AdminError("configuration de modules invalide")
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise AdminError("version de configuration de modules non prise en charge")
    revision = raw.get("revision")
    if type(revision) is not int or not 0 <= revision < 2147483647:
        raise AdminError("révision de modules invalide")
    pages = raw.get("pages")
    if not isinstance(pages, list) or len(pages) > 20:
        raise AdminError("vingt pages de modules au maximum")
    normalized, seen = [], set()
    page_keys = {"id", "title", "description", "enabled", "min_role", "stream_ids", "event_sources",
                 "integration_ids", "query", "days", "graylog_dashboard_id", "graylog_dashboard_ids", "widgets"}
    for page in pages:
        if not isinstance(page, dict) or set(page) - page_keys:
            raise AdminError("page de module invalide")
        identifier = page.get("id")
        if not isinstance(identifier, str) or not _MODULE_SLUG.fullmatch(identifier) or identifier in seen:
            raise AdminError("identifiant de page invalide ou en double")
        seen.add(identifier)
        role = page.get("min_role", "analyste")
        if not isinstance(role, str) or role not in ROLE_RANK:
            raise AdminError("rôle minimal du module invalide")
        if type(page.get("enabled", False)) is not bool:
            raise AdminError("activation du module invalide")
        days = page.get("days", 1)
        if type(days) is not int or not 1 <= days <= 30:
            raise AdminError("fenêtre du module : entre 1 et 30 jours")
        dashboard = page.get("graylog_dashboard_id", "")
        if not isinstance(dashboard, str) or (dashboard and not _GL_ID_RE.fullmatch(dashboard)):
            raise AdminError("identifiant de dashboard Graylog invalide")
        dashboards = _module_strings(page.get("graylog_dashboard_ids", []), _GL_ID_RE, 10, "dashboards")
        if dashboard and dashboard not in dashboards:
            dashboards.insert(0, dashboard)
        widgets = page.get("widgets")
        if not isinstance(widgets, list) or not 1 <= len(widgets) <= 12:
            raise AdminError("une à douze widgets sont requis par page")
        output, widget_ids = [], set()
        for widget in widgets:
            if not isinstance(widget, dict) or set(widget) - {"id", "title", "type", "field", "size"}:
                raise AdminError("widget de module invalide")
            wid, kind = widget.get("id"), widget.get("type")
            if not isinstance(wid, str) or not _MODULE_SLUG.fullmatch(wid) or wid in widget_ids:
                raise AdminError("identifiant de widget invalide ou en double")
            widget_ids.add(wid)
            if not isinstance(kind, str) or kind not in _MODULE_WIDGET_TYPES:
                raise AdminError("type de widget non pris en charge")
            field = widget.get("field", "")
            if not isinstance(field, str) or (field and not _MODULE_FIELD.fullmatch(field)) or (kind == "terms" and not field):
                raise AdminError("champ de widget invalide")
            size = widget.get("size", 10)
            if type(size) is not int or not 1 <= size <= 50:
                raise AdminError("taille du widget : entre 1 et 50")
            output.append({"id": wid, "title": _module_text(widget.get("title", ""), 100, "titre du widget", False),
                           "type": kind, "field": field, "size": size})
        normalized.append({"id": identifier, "title": _module_text(page.get("title", ""), 100, "titre de page", False),
            "description": _module_text(page.get("description", ""), 500, "description"),
            "enabled": page.get("enabled", False), "min_role": role,
            "stream_ids": _module_strings(page.get("stream_ids"), _GL_ID_RE, 30, "streams", True),
            "event_sources": _module_strings(page.get("event_sources", []), _MODULE_SOURCE, 30, "sources"),
            "integration_ids": _module_strings(page.get("integration_ids", []), _MODULE_SOURCE, 30, "intégrations"),
            "query": _module_text(page.get("query", ""), 1000, "recherche"), "days": days,
            "graylog_dashboard_id": dashboard, "graylog_dashboard_ids": dashboards, "widgets": output})
    result = {"schema_version": 1, "revision": revision, "pages": normalized}
    if len(json.dumps(result, ensure_ascii=False).encode()) > MODULES_MAX_BODY - 2048:
        raise AdminError("configuration de modules trop volumineuse", 413)
    return result


def load_modules_config():
    if os.path.islink(SOC_MODULES_DIR) or os.path.islink(MODULES_CONFIG_FILE):
        raise AdminError("configuration de modules indisponible", 503)
    try:
        with open(MODULES_CONFIG_FILE, encoding="utf-8") as handle:
            data = handle.read(MODULES_MAX_BODY + 1)
    except FileNotFoundError:
        return {"schema_version": 1, "revision": 0, "pages": []}
    except OSError:
        raise AdminError("configuration de modules illisible", 503) from None
    try:
        if len(data.encode()) > MODULES_MAX_BODY:
            raise ValueError("oversize")
        return modules_validate_config(json.loads(data))
    except (AdminError, ValueError, TypeError):
        raise AdminError("configuration de modules invalide ; conserver le fichier et corriger sa cause", 503) from None


def _a_modules(p, actor):
    config = modules_validate_config(p)
    if config["revision"] != load_modules_config()["revision"]:
        raise AdminError("la configuration a changé ; recharger les modules avant d'enregistrer", 409)
    return {"id": "modules", "config": config}


def _p_modules(c):
    before = load_modules_config()
    after = dict(c["config"], revision=before["revision"] + 1)
    return {"before": before, "after": after, "impact": "normal", "refus": "",
            "effects": ["Configuration de pages et widgets du site uniquement ; aucune écriture dans Graylog.",
                        "Les rôles SOC autorisés voient uniquement les pages explicitement activées."]}


def _x_modules(c, actor, motif, rid):
    with _ADMIN_LOCK:
        if os.path.islink(SOC_MODULES_DIR):
            raise AdminError("répertoire de modules refusé", 503)
        os.makedirs(SOC_MODULES_DIR, mode=0o750, exist_ok=True)
        lock_path = os.path.join(SOC_MODULES_DIR, ".config.lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o640)
        with os.fdopen(fd, "r+") as lock:
            _fcntl.flock(lock, _fcntl.LOCK_EX)
            previous = load_modules_config()
            if c["config"]["revision"] != previous["revision"]:
                raise AdminError("la configuration a changé ; recharger les modules avant d'enregistrer", 409)
            updated = dict(c["config"], revision=previous["revision"] + 1)
            _atomic_write_json(MODULES_CONFIG_FILE, updated)
    return {"ok": True, "revision": updated["revision"], "message": "Pages et widgets enregistrés."}


def _module_public(page):
    return {key: page[key] for key in ("id", "title", "description", "min_role", "days", "stream_ids",
                                        "graylog_dashboard_id", "graylog_dashboard_ids")}


def modules_public(user):
    config = load_modules_config()
    return {"revision": config["revision"], "pages": [_module_public(p) for p in config["pages"]
            if p["enabled"] and role_at_least(user, p["min_role"])]}


def _module_scope(page):
    filters = [{"terms": {"streams": page["stream_ids"]}},
               {"range": {"timestamp": {"gte": "now-" + str(page["days"]) + "d", "lte": "now"}}}]
    if page["event_sources"]:
        filters.append({"terms": {"event_source": page["event_sources"]}})
    if page["integration_ids"]:
        filters.append({"terms": {"omni_integration_id": page["integration_ids"]}})
    if page["query"]:
        filters.append({"query_string": {"query": page["query"], "max_determinized_states": 1000}})
    return {"bool": {"filter": filters}}


def _module_count(value):
    if type(value) is not int or value < 0:
        raise SearchBackendError(502)
    return value


def _module_widget(page, widget):
    kind = widget["type"]
    body = {"query": _module_scope(page), "size": 0, "track_total_hits": True, "timeout": "10s"}
    if kind == "terms":
        body["aggs"] = {"items": {"terms": {"field": widget["field"], "size": widget["size"]}}}
    elif kind == "timeseries":
        body["aggs"] = {"items": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h" if page["days"] <= 2 else "1d",
                                                    "min_doc_count": 1}}}
    elif kind == "messages":
        body.update(size=min(widget["size"], 20), sort=[{"timestamp": {"order": "desc"}}],
                    _source=["timestamp", "source", "message", "short_message"])
    result = os_search(LOG_INDICES, body)
    shards = result.get("_shards")
    if not isinstance(shards, dict) or type(shards.get("failed")) is not int or shards["failed"] != 0:
        raise SearchBackendError(502)
    if kind == "count":
        total = result["hits"]["total"]
        if not isinstance(total, dict) or total.get("relation", "eq") != "eq":
            raise SearchBackendError(502)
        return {"value": _module_count(total.get("value"))}
    if kind == "messages":
        output = []
        for hit in result["hits"]["hits"]:
            source = hit.get("_source") if isinstance(hit, dict) else None
            if not isinstance(source, dict):
                raise SearchBackendError(502)
            output.append({"timestamp": source.get("timestamp"), "source": _rd(source.get("source", "")),
                           "message": _scrub(str(source.get("message") or source.get("short_message") or "")[:4000])})
        return {"messages": output[:20]}
    buckets = result.get("aggregations", {}).get("items", {}).get("buckets")
    if not isinstance(buckets, list) or len(buckets) > (widget["size"] if kind == "terms" else 800):
        raise SearchBackendError(502)
    output = []
    for bucket in buckets:
        if not isinstance(bucket, dict) or "key" not in bucket:
            raise SearchBackendError(502)
        key = bucket.get("key_as_string") if kind == "timeseries" else bucket["key"]
        if kind == "timeseries" and not isinstance(key, str):
            raise SearchBackendError(502)
        if not isinstance(key, (str, int, float)) or isinstance(key, bool):
            raise SearchBackendError(502)
        output.append({"key": _scrub(key) if isinstance(key, str) else key, "count": _module_count(bucket.get("doc_count"))})
    return {"buckets": output}


def modules_page(identifier, user):
    config = load_modules_config()
    page = next((p for p in config["pages"] if p["id"] == identifier and p["enabled"]
                 and role_at_least(user, p["min_role"])), None)
    if page is None:
        raise AdminError("page de module introuvable", 404)
    widgets = []
    for widget in page["widgets"]:
        item = {key: widget[key] for key in ("id", "title", "type")}
        try:
            item.update(status="ok", data=_module_widget(page, widget))
        except (SearchBackendError, ValueError, TypeError, KeyError):
            item.update(status="error", data=None, message="Données indisponibles ; vérifier la source et le champ du widget.")
        widgets.append(item)
    return {"revision": config["revision"], "page": _module_public(page), "widgets": widgets, "generated": _now_iso()}


def _modules_graylog_catalog():
    streams = _graylog("GET", "/streams")
    if not isinstance(streams, dict) or not isinstance(streams.get("streams"), list):
        raise ValueError("invalid stream catalog")
    found = []
    for stream in streams["streams"]:
        if not isinstance(stream, dict) or not _GL_ID_RE.fullmatch(str(stream.get("id", ""))):
            raise ValueError("invalid stream")
        found.append({"id": stream["id"], "title": str(stream.get("title", ""))[:200]})
    dashboards = []
    for number in range(1, 4):
        response = _graylog("GET", "/views?page=" + str(number) + "&per_page=100")
        if not isinstance(response, dict) or not isinstance(response.get("views"), list):
            raise ValueError("invalid dashboard catalog")
        views = response["views"]
        for view in views:
            if not isinstance(view, dict) or not _GL_ID_RE.fullmatch(str(view.get("id", ""))):
                raise ValueError("invalid view")
            if view.get("type") not in (None, "DASHBOARD"):
                continue
            if len(dashboards) >= 100:
                raise ValueError("dashboard catalog exceeds bounds")
            full = _graylog("GET", "/views/" + view["id"])
            state = full.get("state") if isinstance(full, dict) else None
            if not isinstance(state, dict):
                raise ValueError("invalid dashboard")
            count = 0
            for value in state.values():
                if not isinstance(value, dict) or not isinstance(value.get("widgets", []), list):
                    raise ValueError("invalid widgets")
                count += len(value.get("widgets", []))
            dashboards.append({"id": view["id"], "title": str(view.get("title", ""))[:200], "widgets": count})
        total = response.get("total")
        if type(total) is int and total >= 0 and number * 100 >= total:
            break
        if len(views) < 100:
            break
    else:
        raise ValueError("dashboard catalog exceeds bounds")
    return sorted(found, key=lambda i: i["title"].lower()), sorted(dashboards, key=lambda i: i["title"].lower())


def _modules_field_catalog():
    request = urllib.request.Request(OS_URL + "/" + LOG_INDICES + "/_field_caps?fields=*", headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
    fields = result.get("fields") if isinstance(result, dict) else None
    if not isinstance(fields, dict) or result.get("error") or result.get("failures") or result.get("failed_indices"):
        raise ValueError("field inventory unavailable")
    output = []
    for name, types in sorted(fields.items()):
        if not _MODULE_FIELD.fullmatch(name) or not isinstance(types, dict) or not types:
            continue
        if not all(isinstance(info, dict) and type(info.get("aggregatable")) is bool for info in types.values()):
            raise ValueError("invalid field metadata")
        output.append({"name": name, "type": next(iter(types)) if len(types) == 1 else "conflict",
                       "aggregatable": len(types) == 1 and all(info["aggregatable"] for info in types.values())})
    return output[:500]


def admin_modules():
    catalog = {"streams": [], "dashboards": [], "fields": [], "sources": [], "errors": []}
    try:
        catalog["streams"], catalog["dashboards"] = _modules_graylog_catalog()
        if not catalog["streams"]:
            catalog["errors"].append("Aucun stream visible avec le jeton de service ; vérifier les droits et les partages du compte Graylog.")
        if not catalog["dashboards"]:
            catalog["errors"].append("Aucun dashboard visible avec le jeton de service ; vérifier les droits et les partages du compte Graylog.")
    except Exception:
        catalog["errors"].append("Catalogue Graylog indisponible ; vérifier le jeton et ses permissions de lecture.")
    try:
        catalog["fields"] = _modules_field_catalog()
    except Exception:
        catalog["errors"].append("Inventaire des champs indisponible ; vérifier OpenSearch.")
    try:
        result = os_search(LOG_INDICES, {"size": 0, "query": {"range": {"timestamp": {"gte": "now-30d"}}},
                                        "aggs": {"sources": {"terms": {"field": "event_source", "size": 100}}}})
        buckets = result.get("aggregations", {}).get("sources", {}).get("buckets")
        shards = result.get("_shards")
        if (not isinstance(buckets, list) or not isinstance(shards, dict)
                or type(shards.get("failed")) is not int or shards["failed"] != 0):
            raise ValueError("invalid source catalog")
        catalog["sources"] = [{"source": str(b["key"]), "count": _module_count(b["doc_count"])} for b in buckets]
    except Exception:
        catalog["errors"].append("Sources observées indisponibles ; aucune absence ne peut être conclue.")
    return {"config": load_modules_config(), "catalog": catalog}


# ------------------------------------------------------------------ mise à jour de l'environnement
# Le backend ne lance aucune commande : il lit l'état publié par omni-console-update
# (SOC_ADMIN_DIR/update/status.json et run.json, écrits par root), dépose un fichier de
# déclenchement pour « Rechercher maintenant » (unité omni-console-update-check.path) et
# transmet les demandes confirmées à l'exécuteur privilégié, qui les revalide puis les
# confie à omni-console-update.service. Impact « eleve » : libre-service (un seul
# administrateur, révision courte saisie), seule exception à la double validation.
SOC_UPDATE_DIR = os.path.join(SOC_ADMIN_DIR, "update")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA12_RE = re.compile(r"^[0-9a-f]{12}$")
_MODULE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,40}$")
_RUN_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$")
UPDATE_STATUS_MAX_AGE = 24 * 3600
UPDATE_CHECK_COOLDOWN = 120


def _update_status():
    d = _jl(os.path.join(SOC_UPDATE_DIR, "status.json"), None)
    return d if isinstance(d, dict) else None


def _update_run():
    d = _jl(os.path.join(SOC_UPDATE_DIR, "run.json"), None)
    return d if isinstance(d, dict) else None


def _update_last_apply():
    d = _jl(os.path.join(SOC_UPDATE_DIR, "last_apply.json"), None)
    return d if isinstance(d, dict) else None


def _update_in_progress():
    """Mise à jour en cours : service démarré, ou demande transmise pas encore prise en charge (2 h max)."""
    run = _update_run() or {}
    if run.get("status") == "en_cours":
        return True
    for r in _list_requests(50):
        if r.get("action") not in ("update_apply", "update_rollback") or r.get("status") != "transmise":
            continue
        if time.time() - int(r.get("requested_ts", 0) or 0) > 7200:
            continue
        ex = r.get("execution")
        if not ex or (ex.get("status") == "faite" and run.get("id") != r.get("id")):
            return True
    return False


def admin_update():
    st, run = _update_status(), _update_run()
    req = os.path.join(SOC_UPDATE_DIR, "check-request")
    try:
        check_pending_since = int(time.time() - os.path.getmtime(req))
    except OSError:
        check_pending_since = None
    age = None
    if st and st.get("generated_ts"):
        try:
            age = int(time.time() - float(st["generated_ts"]))
        except (TypeError, ValueError):
            age = None
    return {"status": st, "run": run, "last_apply": _update_last_apply(), "status_age_s": age,
            "check_pending_since_s": check_pending_since,
            "in_progress": _update_in_progress(), "configured": st is not None, "generated": _now_iso()}


def update_banner():
    st = _update_status() or {}
    av = st.get("available") or {}
    return {"update_available": bool(st.get("update_available")), "update_short": str(av.get("short", ""))[:12],
            "update_can_apply": bool(st.get("can_apply"))}


def _a_update_check(p, actor):
    return {}


def _p_update_check(c):
    st = _update_status() or {}
    req = os.path.join(SOC_UPDATE_DIR, "check-request")
    refus = ""
    if os.path.exists(req) and time.time() - os.path.getmtime(req) < 600:
        refus = "une recherche est déjà demandée (traitement en cours)"
    elif st.get("generated_ts") and time.time() - float(st.get("generated_ts") or 0) < UPDATE_CHECK_COOLDOWN:
        refus = "recherche effectuée il y a moins de 2 minutes"
    elif _update_in_progress():
        refus = "une mise à jour est en cours"
    return {"before": (st.get("installed") or {}).get("short", "inconnue"), "after": "recherche demandée", "impact": "normal",
            "refus": refus, "effects": ["git fetch de la branche suivie sur le remote attendu (lecture seule, arbre de travail intact).",
                                       "Recalcul du plan, des vérifications et, pour une nouvelle révision, de la suite de tests hors ligne (quelques minutes)."]}


def _x_update_check(c, actor, motif, rid):
    os.makedirs(SOC_UPDATE_DIR, exist_ok=True)
    _atomic_write_json(os.path.join(SOC_UPDATE_DIR, "check-request"), {"by": actor, "t": _now_iso(), "id": rid}, 0o640)
    return {"ok": True, "message": "Recherche demandée : le résultat s'affiche dans quelques minutes."}


def _a_update_apply(p, actor):
    target = str(p.get("target", "")).strip()
    if not _SHA40_RE.match(target):
        raise AdminError("révision cible invalide (SHA complet attendu)")
    confirm = str(p.get("confirm", "")).strip().lower()
    if confirm and not _SHA12_RE.match(confirm):
        raise AdminError("confirmation : saisir les 12 premiers caractères de la révision")
    mods = p.get("modules") or []
    if not isinstance(mods, list) or len(mods) > 10 or not all(isinstance(m, str) and _MODULE_RE.match(m) for m in mods):
        raise AdminError("liste de modules invalide")
    return {"target": target, "confirm": confirm, "console": p.get("console") is not False,
            "restart": p.get("restart") is not False, "modules": sorted(set(mods)), "plan_read": p.get("plan_read") is True}


def _p_update_apply(c):
    st = _update_status()
    refus = ""
    if not st:
        refus = "aucun état de mise à jour publié (omni-console-update-check jamais exécuté)"
    elif not st.get("update_available") or (st.get("available") or {}).get("rev") != c["target"]:
        refus = "la révision demandée n'est pas la mise à jour disponible : relancer la recherche"
    elif time.time() - float(st.get("generated_ts") or 0) > UPDATE_STATUS_MAX_AGE:
        refus = "plan de plus de 24 h : relancer la recherche"
    elif not st.get("can_apply"):
        refus = "vérifications bloquantes : " + "; ".join(st.get("blocking") or [])[:400]
    elif _update_in_progress():
        refus = "une mise à jour ou un retour arrière est déjà en cours"
    opts = st.get("options") if st else {}
    if not refus:
        mods = {m.get("id"): m for m in (opts or {}).get("modules", [])}
        bad = [m for m in c["modules"] if not (mods.get(m) or {}).get("installable")]
        if bad:
            refus = "module non installable depuis la console : " + ", ".join(bad)
    effects = ["Revalidation complète par le service privilégié (git fetch, vérifications, tests) avant toute modification.",
               "Sauvegarde de la révision installée, puis git merge --ff-only vers " + c["target"][:12] + ".",
               "Déploiement transactionnel des robots, unités et préférences APT (omni-deploy).",
               ("Publication de la console." if c["console"] and (opts or {}).get("console", {}).get("available")
                else "Console non publiée."),
               ("Redémarrage limité à : " + ", ".join(st.get("restarts") or []) if c["restart"] and st and st.get("restarts")
                else "Aucun redémarrage de service par la mise à jour."),
               "Contrôle de santé final ; en cas d'échec : retour arrière automatique complet."]
    if c["modules"]:
        effects.append("Installation des modules cochés après la mise à jour : " + ", ".join(c["modules"])
                       + " (une installation en échec n'annule pas la mise à jour du code).")
    warnings = [x.get("label", "") + " : " + x.get("detail", "") for x in (st or {}).get("checks", [])
                if x.get("status") == "avertissement"]
    return {"before": ((st or {}).get("installed") or {}).get("short", "?"), "after": c["target"][:12], "impact": "eleve",
            "refus": refus, "effects": effects, "warnings": warnings[:10],
            "confirmation": {"expected": c["target"][:12], "label": "Saisir la révision courte de la cible"}}


def _confirm_update_apply(c):
    if c.get("plan_read") is not True:
        raise AdminError("cocher « J'ai lu le plan et les vérifications »")
    if c.get("confirm") != c["target"][:12]:
        raise AdminError("confirmation incorrecte : saisir les 12 premiers caractères de la révision cible")


def _a_update_rollback(p, actor):
    run_id = str(p.get("run_id", "")).strip()
    if not _RUN_ID_RE.match(run_id):
        raise AdminError("identifiant de mise à jour invalide")
    confirm = str(p.get("confirm", "")).strip().lower()
    if confirm and not _SHA12_RE.match(confirm):
        raise AdminError("confirmation : saisir les 12 premiers caractères de la révision à restaurer")
    return {"run_id": run_id, "confirm": confirm}


def _p_update_rollback(c):
    run = _update_last_apply() or {}
    refus = ""
    prev = str(run.get("prev_rev") or "")
    if run.get("id") != c["run_id"] or run.get("kind") != "apply":
        refus = "seule la dernière mise à jour peut être annulée"
    elif run.get("status") not in ("terminee", "terminee_avec_avertissements", "interrompue") or not prev:
        refus = "dernière mise à jour dans l'état « " + str(run.get("status")) + " » : retour arrière sans objet"
    elif _update_in_progress():
        refus = "une mise à jour ou un retour arrière est en cours"
    return {"before": str(run.get("target") or "")[:12], "after": prev[:12], "impact": "eleve", "refus": refus,
            "effects": ["Retour arrière des transactions omni-deploy de cette mise à jour (fichiers déployés restaurés).",
                        "git reset --keep vers la révision sauvegardée " + prev[:12] + ".",
                        "Redémarrage des services redémarrés par la mise à jour, puis contrôle de santé.",
                        "Les modules d'intégration installés ne sont pas désinstallés (procédure manuelle)."],
            "confirmation": {"expected": prev[:12], "label": "Saisir la révision courte à restaurer"}}


def _confirm_update_rollback(c):
    run = _update_last_apply() or {}
    if c.get("confirm") != str(run.get("prev_rev") or "")[:12]:
        raise AdminError("confirmation incorrecte : saisir les 12 premiers caractères de la révision à restaurer")


ADMIN_ACTIONS = {
    "role_set": {"label": "Rôle d'un utilisateur", "validate": _a_role_set, "preview": _p_role_set, "execute": _x_role_set},
    "fp_add": {"label": "Ajout d'un faux positif", "validate": _a_fp_add, "preview": _p_fp_add, "execute": _x_fp_add},
    "fp_remove": {"label": "Retrait d'un faux positif", "validate": _a_fp_remove, "preview": _p_fp_remove, "execute": _x_fp_remove},
    "soar_block": {"label": "Blocage manuel SOAR", "validate": _a_soar_block, "preview": _p_soar_block, "execute": _x_soar_block},
    "soar_unblock": {"label": "Déblocage SOAR", "validate": _a_soar_unblock, "preview": _p_soar_unblock, "execute": _x_soar_unblock},
    "soar_exclusion_add": {"label": "Ajout d'une exclusion SOAR", "validate": _a_exclusion_add, "preview": _p_exclusion_add, "execute": _x_exec("soar_exclusion_add")},
    "soar_exclusion_remove": {"label": "Retrait d'une exclusion SOAR", "validate": _a_exclusion_remove, "preview": _p_exclusion_remove, "execute": _x_exec("soar_exclusion_remove")},
    "soar_param": {"label": "Paramètre SOAR", "validate": _a_param(SOAR_PARAMS, "soar"),
                   "preview": _p_param(SOAR_PARAMS, SOC_SOAR_ENV, "SOAR"), "execute": _x_exec("soar_param")},
    "triage_param": {"label": "Paramètre de triage", "validate": _a_param(TRIAGE_PARAMS, "triage"),
                     "preview": _p_param(TRIAGE_PARAMS, SOC_TRIAGE_ENV, "Triage"), "execute": _x_exec("triage_param")},
    "detection_toggle": {"label": "Activation d'une détection", "validate": _a_detection, "preview": _p_detection, "execute": _x_detection},
    "service_restart": {"label": "Redémarrage d'un service", "validate": _a_restart, "preview": _p_restart, "execute": _x_exec("service_restart")},
    "appearance_set": {"label": "Apparence de la console", "validate": _a_appearance, "preview": _p_appearance, "execute": _x_appearance},
    "modules_set": {"label": "Pages et widgets du site", "validate": _a_modules, "preview": _p_modules, "execute": _x_modules},
    "update_check": {"label": "Recherche de mise à jour", "validate": _a_update_check, "preview": _p_update_check, "execute": _x_update_check},
    # Libre-service : impact « eleve », exécution sans second administrateur après confirmation
    # explicite (révision courte). Revalidé par l'exécuteur (SELF_SERVICE_KINDS) et par le service.
    "update_apply": {"label": "Mise à jour de l'environnement", "validate": _a_update_apply, "preview": _p_update_apply,
                     "execute": _x_exec("update_apply"), "self_service": True, "confirm": _confirm_update_apply},
    "update_rollback": {"label": "Retour arrière de la mise à jour", "validate": _a_update_rollback, "preview": _p_update_rollback,
                        "execute": _x_exec("update_rollback"), "self_service": True, "confirm": _confirm_update_rollback},
}


def _param_rollback(action, c, before):
    if action in ("soar_param", "triage_param") and before is not None:
        return {"action": action, "params": {"key": c["key"], "value": before}}
    if action == "soar_exclusion_add":
        return {"action": "soar_exclusion_remove", "params": {"value": c["value"]}}
    if action == "soar_exclusion_remove":
        return {"action": "soar_exclusion_add", "params": {"value": c["value"]}}
    if action == "role_set":
        b = str(before or "")
        return {"action": "role_set", "params": {"user": c["user"], "role": b if b in ROLE_RANK else "aucun"}}
    return None


def _req_path(rid):
    if not re.match(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$", rid or ""):
        raise AdminError("identifiant de demande invalide")
    return os.path.join(ADMIN_REQ_DIR, rid + ".json")


def _run_action(name, clean, actor, motif, rid, preview, ip):
    """Exécute (ou simule si SOC_ADMIN_DRY_RUN) puis journalise. Renvoie le résultat."""
    spec = ADMIN_ACTIONS[name]
    if SOC_ADMIN_DRY_RUN:
        audit_append(actor, "simulation", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                     "mode simulation global : aucune modification", rid, ip)
        return {"ok": True, "simulation": True, "message": "Mode simulation global actif : action simulée, rien n'a été modifié.",
                "preview": preview}
    try:
        res = spec["execute"](clean, actor, motif, rid) or {}
    except AdminError:
        raise
    except Exception as ex:
        res = {"ok": False, "error": f"échec de l'exécution ({type(ex).__name__})"}
    rb = res.get("rollback") or _param_rollback(name, clean, preview.get("before"))
    res["rollback"] = rb
    status = "transmise" if res.get("queued") else ("faite" if res.get("ok") else "echec")
    audit_append(actor, "execution", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                 status + (" : " + str(res.get("error")) if res.get("error") else ""), rid, ip,
                 {"rollback": rb} if rb else None)
    res["status"] = status
    return res


def _target(c):
    return c.get("user") or c.get("entity") or c.get("ip") or c.get("value") or c.get("unit") or \
        (f"{c.get('key')}" if c.get("key") else "") or c.get("id") or c.get("target") or c.get("run_id") or ""


def admin_action(body, actor, ip):
    name = str(body.get("action", ""))
    if name not in ADMIN_ACTIONS:
        raise AdminError("action inconnue")
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    simulate = body.get("simulate") is True
    spec = ADMIN_ACTIONS[name]
    clean = spec["validate"](params, actor)
    motif = _clean_text(body.get("motif", ""), 300, 0 if simulate else 4, "motif")
    preview = spec["preview"](clean)
    if simulate:
        audit_append(actor, "simulation", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                     preview.get("refus") or "simulation", "", ip)
        return {"ok": True, "simulation": True, "preview": preview, "impact": preview.get("impact"),
                "label": spec["label"]}
    if preview.get("refus"):
        audit_append(actor, "refus", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                     preview["refus"], "", ip)
        raise AdminError(preview["refus"], 409)
    if spec.get("confirm"):
        try:
            spec["confirm"](clean)
        except AdminError as ex:
            audit_append(actor, "refus", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                         str(ex), "", ip)
            raise
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + _uuid.uuid4().hex[:8]
    if spec.get("self_service"):
        return _self_service_action(name, spec, clean, actor, motif, rid, preview, ip)
    if preview.get("impact") == "fort":
        with _ADMIN_LOCK:
            os.makedirs(ADMIN_REQ_DIR, exist_ok=True)
            pending = [r for r in _list_requests(500) if r.get("status") == "en_attente"]
            if len(pending) >= 50:
                raise AdminError("trop de demandes en attente de validation", 429)
            req = {"id": rid, "action": name, "label": spec["label"], "params": clean, "motif": motif,
                   "requested_by": actor, "requested_at": _now_iso(), "requested_ts": int(time.time()),
                   "expires_ts": int(time.time()) + SOC_ADMIN_APPROVAL_TTL, "status": "en_attente",
                   "preview": preview, "requested_ip": ip}
            _atomic_write_json(_req_path(rid), req)
        audit_append(actor, "demande", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                     "en attente de validation par un second administrateur", rid, ip)
        return {"ok": True, "pending": True, "id": rid, "status": "en_attente",
                "message": "Demande enregistrée : validation par un second administrateur requise."
                if not SOC_ADMIN_SELF_APPROVE else "Demande enregistrée : confirmer dans l'onglet Validations."}
    res = _run_action(name, clean, actor, motif, rid, preview, ip)
    res["id"] = rid
    return res


def _self_service_action(name, spec, clean, actor, motif, rid, preview, ip):
    """Action en libre-service (mise à jour) : demande confirmée par son auteur, enregistrée
    avant transmission (l'exécuteur exige self_service=True et decided_by == requested_by)."""
    if spec is not ADMIN_ACTIONS.get(name) or name not in ("update_apply", "update_rollback"):
        raise AdminError("libre-service réservé à la mise à jour", 403)
    with _ADMIN_LOCK:
        req = {"id": rid, "action": name, "label": spec["label"], "params": clean, "motif": motif,
               "requested_by": actor, "requested_at": _now_iso(), "requested_ts": int(time.time()),
               "expires_ts": int(time.time()) + SOC_ADMIN_APPROVAL_TTL, "status": "transmise", "self_service": True,
               "decided_by": actor, "decided_at": _now_iso(), "decision_motif": "confirmation explicite (libre-service)",
               "preview": preview, "requested_ip": ip, "decided_ip": ip}
        _atomic_write_json(_req_path(rid), req)
    audit_append(actor, "demande", name, _target(clean), motif, preview.get("before"), preview.get("after"),
                 "confirmée par l'administrateur (libre-service, sans second administrateur)", rid, ip)
    res = _run_action(name, clean, actor, motif, rid, preview, ip)
    with _ADMIN_LOCK:
        req = _jl(_req_path(rid), req)
        if res.get("simulation"):
            req["status"] = "simulee"
        elif not res.get("queued"):
            req["status"] = "echec"
        req["result"] = {k: res.get(k) for k in ("ok", "message", "error", "queued", "simulation") if k in res}
        _atomic_write_json(_req_path(rid), req)
    res["id"] = rid
    return res


def _list_requests(limit=100):
    out = []
    for p in sorted(_glob.glob(os.path.join(ADMIN_REQ_DIR, "*.json")), reverse=True)[:limit]:
        r = _jl(p, None)
        if not isinstance(r, dict):
            continue
        if r.get("status") == "en_attente" and int(r.get("expires_ts", 0)) < time.time():
            r["status"] = "expiree"
        if r.get("status") == "transmise":
            done = _jl(os.path.join(ADMIN_EXEC_DIR, "done", r["id"] + ".json"), None)
            if isinstance(done, dict):
                r["execution"] = {k: done.get(k) for k in ("status", "resultat", "before", "after", "t_traitement")}
        out.append(r)
    return out


def admin_requests():
    return {"requests": _list_requests(100), "self_approve": SOC_ADMIN_SELF_APPROVE,
            "approval_ttl_s": SOC_ADMIN_APPROVAL_TTL}


def admin_decide(body, actor, ip):
    rid = str(body.get("id", ""))
    decision = str(body.get("decision", ""))
    if decision not in ("approuver", "rejeter"):
        raise AdminError("décision attendue : approuver ou rejeter")
    motif = _clean_text(body.get("motif", ""), 300, 4 if decision == "rejeter" else 0, "motif")
    with _ADMIN_LOCK:
        path = _req_path(rid)
        req = _jl(path, None)
        if not isinstance(req, dict):
            raise AdminError("demande introuvable", 404)
        if req.get("status") != "en_attente":
            raise AdminError("demande déjà traitée", 409)
        if int(req.get("expires_ts", 0)) < time.time():
            req["status"] = "expiree"
            _atomic_write_json(path, req)
            raise AdminError("demande expirée : la reformuler", 409)
        if decision == "approuver" and req.get("requested_by", "").lower() == actor.lower() and not SOC_ADMIN_SELF_APPROVE:
            audit_append(actor, "refus", req["action"], _target(req.get("params", {})), motif, None, None,
                         "auto-approbation refusée", rid, ip)
            raise AdminError("validation par un second administrateur obligatoire (auto-approbation interdite)", 403)
        if decision == "approuver" and req.get("action") == "role_set" and \
                str((req.get("params") or {}).get("user", "")).lower() == actor.lower():
            raise AdminError("un administrateur ne valide pas une demande qui le concerne", 403)
        req.update(decided_by=actor, decided_at=_now_iso(), decision_motif=motif, decided_ip=ip)
        if decision == "rejeter":
            req["status"] = "rejetee"
            _atomic_write_json(path, req)
            audit_append(actor, "rejet", req["action"], _target(req.get("params", {})), motif, None, None,
                         "demande rejetée", rid, ip)
            return {"ok": True, "status": "rejetee"}
        req["status"] = "approuvee"
        _atomic_write_json(path, req)
    audit_append(actor, "approbation", req["action"], _target(req.get("params", {})), motif, None, None,
                 f"demande de {req.get('requested_by')} approuvée", rid, ip)
    spec = ADMIN_ACTIONS.get(req["action"])
    if not spec:
        raise AdminError("action inconnue", 400)
    # revalidation complète : l'état a pu changer depuis la demande
    clean = spec["validate"](req.get("params") or {}, req.get("requested_by", ""))
    preview = spec["preview"](clean)
    if preview.get("refus"):
        res = {"ok": False, "status": "echec", "error": preview["refus"]}
        audit_append(actor, "execution", req["action"], _target(clean), req.get("motif", ""), preview.get("before"),
                     preview.get("after"), "echec : " + preview["refus"], rid, ip)
    else:
        res = _run_action(req["action"], clean, actor, req.get("motif", ""), rid, preview, ip)
    with _ADMIN_LOCK:
        req = _jl(path, req)
        req["status"] = res.get("status") or ("faite" if res.get("ok") else "echec")
        req["result"] = {k: res.get(k) for k in ("ok", "message", "error", "queued", "simulation") if k in res}
        if res.get("simulation"):
            req["status"] = "simulee"
        _atomic_write_json(path, req)
    res["id"] = rid
    return res


def admin_me(user, session_token, ip):
    role = role_of(user)
    is_admin = role == "administrateur"
    out = {"user": user, "role": role, "role_label": ROLE_LABEL.get(role, role), "is_admin": is_admin}
    if is_admin:
        internal = admin_ip_internal(ip)
        out.update(csrf=csrf_token(session_token), client_ip=ip, client_internal=internal,
                   internal_only=SOC_ADMIN_INTERNAL_ONLY,
                   writes_allowed=internal or not SOC_ADMIN_INTERNAL_ONLY,
                   dry_run=SOC_ADMIN_DRY_RUN, self_approve=SOC_ADMIN_SELF_APPROVE,
                   approval_ttl_s=SOC_ADMIN_APPROVAL_TTL, admins=admin_users()["admins"],
                   detections_available=bool(_graylog_token()), restartable=SOC_ADMIN_RESTARTABLE,
                   actions={k: v["label"] for k, v in ADMIN_ACTIONS.items()}, **update_banner())
    return out



ADMIN_GET_ROUTES = {
    "/m/api/admin/users": lambda q: admin_users(),
    "/m/api/admin/fp": lambda q: admin_fp_list(),
    "/m/api/admin/soar": lambda q: admin_soar(),
    "/m/api/admin/detections": lambda q: admin_detections(),
    "/m/api/admin/settings": lambda q: admin_settings(),
    "/m/api/admin/services": lambda q: admin_services(),
    "/m/api/admin/requests": lambda q: admin_requests(),
    "/m/api/admin/audit": lambda q: audit_read(max(1, min(int((q.get("limit") or ["200"])[0] or 200), 1000))),
    "/m/api/admin/appearance": lambda q: admin_appearance(),
    "/m/api/admin/modules": lambda q: admin_modules(),
    "/m/api/admin/update": lambda q: admin_update(),
}


# ------------------------------------------------------------------ indicateurs SOC (lecture seule)
# Calcul partagé avec l'outil en ligne de commande tools/omni-soc-kpi.py du clone de référence :
# une seule implémentation des définitions (MTTD, MTTR, faux positifs, couverture).
SOC_KPI_TOOL = _setting("SOC_KPI_TOOL", OMNI_REPO_DIR + "/tools/omni-soc-kpi.py")
SOC_KPI_TZ = CONF.get("SOC_KPI_TZ", "Europe/Paris")
_SOC_KPI_MOD: dict = {}


class SocKpiUnavailable(Exception):
    pass


def _soc_kpi_module():
    import importlib.util as _ilu
    try:
        mtime = os.path.getmtime(SOC_KPI_TOOL)
    except OSError:
        raise SocKpiUnavailable("outil d'indicateurs introuvable (SOC_KPI_TOOL)") from None
    if _SOC_KPI_MOD.get("key") != (SOC_KPI_TOOL, mtime):
        spec = _ilu.spec_from_file_location("omni_soc_kpi", SOC_KPI_TOOL)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _SOC_KPI_MOD.update(key=(SOC_KPI_TOOL, mtime), mod=mod)
    return _SOC_KPI_MOD["mod"]


def get_soc_kpi(days=30):
    mod = _soc_kpi_module()
    graylog_get = (lambda path: _graylog("GET", path)) if _graylog_token() else None
    try:
        return mod.compute(os_search, graylog_get, days=days, log_index="omni-*", cases_file=CASES_FILE,
                           admin_dir=SOC_ADMIN_DIR, tz=SOC_KPI_TZ,
                           mitre_csv=_setting("MITRE_LOOKUP", OMNI_REPO_DIR + "/lookups/mitre-attack.csv"))
    except mod.KpiError:
        raise SearchBackendError(502) from None


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

    def _html_page(self, title, inner, code=200):
        page = (f'<!doctype html><html lang="fr"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{_eh.escape(title)}</title></head>'
                f'<body style="margin:0;background:#eef1f4;font-family:Segoe UI,-apple-system,Roboto,Arial,sans-serif">'
                f'<div style="max-width:480px;margin:56px auto;background:#fff;border-radius:12px;padding:28px 26px;box-shadow:0 1px 6px rgba(0,0,0,.1)">'
                f'<div style="font-size:11px;letter-spacing:2px;color:#5f3dc4;text-transform:uppercase;font-weight:700">SIEM OMNITECH</div>'
                f'<h2 style="margin:8px 0 14px;color:#212529;font-size:20px">{_eh.escape(title)}</h2>{inner}</div></body></html>')
        b = page.encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

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
        try:
            return self._get()
        except SearchBackendError as exc:
            return self._json({"error": "search_unavailable", "available": False,
                               "message": "Les données de recherche sont indisponibles. Réessayer après vérification du service."}, exc.status)

    def _get(self):
        p = self.path.split("?")[0]
        if p == "/m/api/quick":          # lien signe depuis un mail -> page de CONFIRMATION (pas d'action en GET)
            import urllib.parse as _up
            q = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            a = q.get("a", [""])[0]; ent = q.get("e", [""])[0]; tag = q.get("tag", [""])[0]
            exp = q.get("exp", [""])[0]; sig = q.get("sig", [""])[0]
            if not quick_verify(a, ent, tag, exp, sig):
                return self._html_page("Lien invalide ou expiré",
                    '<p style="color:#495057">Ce lien n\'est plus valide (expiré ou altéré). Ouvrez la console SOC pour agir.</p>', 403)
            who = _eh.escape(ent.split("=", 1)[-1]); t_h = _eh.escape(tag or "(toutes)")
            payload = json.dumps({"a": a, "e": ent, "tag": tag, "exp": exp, "sig": sig})
            if a == "block":
                title = "Bloquer une IP au pare-feu"
                question = (f'<p style="color:#343a40;line-height:1.5">Bloquer l\'IP <b>{who}</b> au pare-feu '
                            f'(FortiGate) pendant 24&nbsp;h ?</p>'
                            f'<p style="font-size:13px;color:#868e96">Action <b>réversible</b> (expiration automatique). '
                            f'Seules les IP <b>publiques</b> sont acceptées — jamais une IP interne.</p>')
                btn_txt, btn_bg = "Bloquer l'IP", "#c92a2a"
                ok_msg = "IP bloquée au pare-feu (24&nbsp;h)."
            else:
                title = "Marquer faux positif"
                question = (f'<p style="color:#343a40;line-height:1.5">Mettre en sourdine le <b>mail</b> de la détection '
                            f'<b>{t_h}</b> pour <b>{who}</b> pendant 30 jours ?</p>'
                            f'<p style="font-size:13px;color:#868e96">Les alertes critiques / kill-chain ne sont <b>jamais</b> masquées.</p>')
                btn_txt, btn_bg = "Confirmer le faux positif", "#5f3dc4"
                ok_msg = "Faux positif enregistré — vous ne recevrez plus ce mail pour cette entité (30j)."
            inner = (f'{question}'
                     f'<button id="b" style="background:{btn_bg};color:#fff;border:0;font-size:14px;font-weight:700;padding:11px 20px;border-radius:8px;cursor:pointer">{btn_txt}</button>'
                     f'<div id="r" style="margin-top:14px;font-size:14px"></div>'
                     f'<script>var P={payload};document.getElementById("b").onclick=function(){{this.disabled=true;'
                     f'fetch("/m/api/quick",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify(P)}})'
                     f'.then(r=>r.json()).then(r=>{{document.getElementById("r").innerHTML=(r&&r.ok!==false)?'
                     f'"<b style=color:#2b8a3e>{ok_msg}</b>":'
                     f'"<b style=color:#e03131>Erreur : "+((r&&r.error)||"?")+"</b>";document.getElementById("b").style.display="none";}})'
                     f'.catch(function(){{document.getElementById("r").innerHTML="<b style=color:#e03131>Erreur réseau</b>";}});}};</script>')
            return self._html_page(title, inner)
        if p == "/m/api/vapid":
            return self._json({"publicKey": VAPID_PUB})
        if p == "/m/api/me":
            u = self._user()
            return self._json({"user": u, "role": role_of(u)} if u else {"user": None}, 200 if u else 401)
        if not self._user():
            return self._json({"error": "auth"}, 401)
        if p.startswith("/m/api/admin/"):
            return self._admin_get(p)
        if p in ("/m/api/modules", "/m/api/modules/page"):
            try:
                if p == "/m/api/modules":
                    return self._json_raw(modules_public(self._user()))
                params = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                return self._json_raw(modules_page(params.get("id", [""])[0], self._user()))
            except AdminError as ex:
                return self._json_raw({"error": str(ex)}, ex.code)
        if p == "/m/api/appearance":
            return self._json_raw(appearance_public())
        if p == "/m/api/site":
            return self._json(get_site())
        if p == "/m/api/appearance/logo":
            return self._appearance_logo()
        if p == "/m/api/soar":
            d = get_soar(); d["is_admin"] = soc_is_admin(self._user())
            return self._json(d)
        if p == "/m/api/siem-ops":
            return self._json(get_siem_ops())
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
            merged = {}
            for row in get_terms("alert_tag") + get_terms("v5_tag"):
                merged[row["k"]] = merged.get(row["k"], 0) + row["n"]
            return self._json({"data": [{"k": k, "n": n} for k, n in sorted(merged.items(), key=lambda kv: -kv[1])[:8]]})
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
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
            values = qs.get("hours", ["3"])
            if len(values) != 1 or values[0] not in ("3", "12", "24", "48", "72"):
                return self._json({"error": "Période attendue : 3, 12, 24, 48 ou 72 heures"}, 400)
            return self._json(get_geo_flows(int(values[0])))
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
        if p == "/m/api/search":
            import urllib.parse as _up
            qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            def _qi(k, d):
                try:
                    return int(qs.get(k, [str(d)])[0])
                except (ValueError, TypeError):
                    return d
            return self._json(get_search(qs.get("q", [""])[0], _qi("from", 0), _qi("size", 25), _qi("days", 2)))
        if p == "/m/api/kpi-trend":
            return self._json({"trend": get_kpi_trend()})
        if p == "/m/api/leaks2":
            return self._json(get_leaks_v2())
        if p == "/m/api/soc-kpi":
            # Indicateurs SOC : rôle analyste ou administrateur (le lecteur n'y a pas accès).
            if not role_at_least(self._user(), "analyste"):
                return self._json({"error": "indicateurs réservés aux rôles analyste et administrateur"}, 403)
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            try:
                days = max(1, min(90, int(qs.get("days", ["30"])[0])))
            except (ValueError, TypeError):
                days = 30
            try:
                return self._json(get_soc_kpi(days))
            except SocKpiUnavailable as exc:
                return self._json({"error": "kpi_unavailable", "available": False, "message": str(exc)}, 503)
            except SearchBackendError:
                raise
            except Exception as exc:
                return self._json({"error": "kpi_error", "available": False,
                                   "message": f"calcul impossible ({type(exc).__name__})"}, 502)
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
        except SearchBackendError:
            # Headers are already sent: close the event stream after a safe error
            # event instead of writing an invalid second HTTP response.
            try:
                self.wfile.write(b'event: unavailable\ndata: {"error":"search_unavailable","available":false}\n\n')
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    # ------------------------------------------------------------ administration
    def _session_token(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["oms_session"].value if "oms_session" in c else ""

    def _json_raw(self, obj, code=200):
        """Réponse sans pseudonymisation : l'administration agit sur les valeurs réelles."""
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _appearance_logo(self):
        """Logo personnalisé, même origine, type MIME exact et nosniff ; 404 si absent ou altéré."""
        found = appearance_logo_bytes()
        if not found:
            return self._json_raw({"error": "not found"}, 404)
        mime, data = found
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
        self.send_header("Content-Disposition", 'inline; filename="logo.' + _APPEARANCE_LOGO_EXT[mime] + '"')
        self.send_header("Cache-Control", "private, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def _admin_get(self, p):
        u = self._user()
        ip = admin_client_ip(self)
        if p == "/m/api/admin/me":
            return self._json_raw(admin_me(u, self._session_token(), ip))
        if not soc_is_admin(u):
            return self._json_raw({"ok": False, "error": "espace réservé aux administrateurs SOC"}, 403)
        route = ADMIN_GET_ROUTES.get(p)
        if not route:
            return self._json_raw({"error": "not found"}, 404)
        q = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        try:
            return self._json_raw(route(q))
        except AdminError as ex:
            return self._json_raw({"ok": False, "error": str(ex)}, ex.code)
        except Exception as ex:
            return self._json_raw({"ok": False, "error": f"source indisponible ({type(ex).__name__})"}, 502)

    def _admin_post(self, p):
        """Garde commune des écritures d'administration, dans cet ordre :
        session, rôle, méthode/Content-Type JSON, Origin obligatoire, jeton CSRF,
        réseau interne, débit, taille du corps. Tout refus d'un compte authentifié est journalisé."""
        u = self._user()
        if not u:
            return self._json_raw({"error": "auth"}, 401)
        ip = admin_client_ip(self)
        def deny(msg, code):
            if code != 429:
                try:
                    audit_append(u, "refus", p.rsplit("/", 1)[-1], "", "", None, None, msg, "", ip)
                except Exception:
                    pass
            return self._json_raw({"ok": False, "error": msg}, code)
        if not soc_is_admin(u):
            return deny("action réservée aux administrateurs SOC", 403)
        if not (self.headers.get("Content-Type", "").split(";")[0].strip().lower() == "application/json"):
            return deny("Content-Type application/json requis", 415)
        origin = self.headers.get("Origin", "")
        if not origin or urllib.parse.urlparse(origin).hostname not in SOC_ORIGINS:
            return deny("origine absente ou refusée", 403)
        if not hmac.compare_digest(self.headers.get("X-SOC-CSRF", ""), csrf_token(self._session_token())):
            return deny("jeton anti-CSRF absent ou invalide", 403)
        if SOC_ADMIN_INTERNAL_ONLY and not admin_ip_internal(ip):
            return deny("écritures d'administration limitées aux réseaux internes", 403)
        if not admin_rate_ok(u.lower()):
            return deny("trop d'actions d'administration : patienter quelques minutes", 429)
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = -1
        limit = APPEARANCE_MAX_BODY if p == "/m/api/admin/appearance" else (MODULES_MAX_BODY if p == "/m/api/admin/modules" else 16384)
        if n < 0 or n > limit:
            return deny("requête trop volumineuse", 413)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return deny("JSON invalide", 400)
        if not isinstance(body, dict):
            return deny("objet JSON attendu", 400)
        try:
            if p == "/m/api/admin/action":
                r = admin_action(body, u, ip)
            elif p == "/m/api/admin/decide":
                r = admin_decide(body, u, ip)
            elif p == "/m/api/admin/appearance":
                body["action"] = "appearance_set"     # même chaîne que /admin/action : simulation, motif, audit
                r = admin_action(body, u, ip)
            elif p == "/m/api/admin/modules":
                body["action"] = "modules_set"
                if "params" not in body:
                    body["params"] = body.get("config", {})
                if "mode" in body:
                    if body["mode"] not in ("preview", "apply"):
                        raise AdminError("mode de configuration invalide")
                    body["simulate"] = body["mode"] == "preview"
                r = admin_action(body, u, ip)
            else:
                return self._json_raw({"error": "not found"}, 404)
        except AdminError as ex:
            return self._json_raw({"ok": False, "error": str(ex)}, ex.code)
        except Exception as ex:
            return self._json_raw({"ok": False, "error": f"échec ({type(ex).__name__})"}, 502)
        return self._json_raw(r, 200)

    def do_POST(self):
        p = self.path.split("?")[0]
        if p.startswith("/m/api/admin/"):
            return self._admin_post(p)
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
        if p == "/m/api/quick":          # action signée depuis un mail (token, pas de session)
            if not quick_verify(str(b.get("a", "")), str(b.get("e", "")), str(b.get("tag", "")),
                                str(b.get("exp", "")), str(b.get("sig", ""))):
                return self._json({"ok": False, "error": "lien invalide ou expiré"}, 403)
            if b.get("a") == "fp":
                return self._json(triage_fp_add(str(b.get("e", "")), "", "mail-link", str(b.get("tag", ""))))
            if b.get("a") == "block":
                return self._json(soar_block(str(b.get("e", "")), "mail-link"))
            return self._json({"ok": False, "error": "action inconnue"}, 400)
        if p == "/m/api/soar/unblock":
            u = self._user()
            if not u:
                return self._json({"error": "auth"}, 401)
            if not origin_ok(self.headers):
                return self._json({"ok": False, "error": "origine refusée"}, 403)
            r = soc_soar_request(b, u)
            return self._json(r, 200 if r.get("ok") else 403)
        if p in ("/m/api/case", "/m/api/fp", "/m/api/watch"):
            u = self._user()
            if not u:
                return self._json({"error": "auth"}, 401)
            if not origin_ok(self.headers):
                return self._json({"ok": False, "error": "origine refusée"}, 403)
            if not role_at_least(u, "analyste"):
                return self._json({"ok": False, "error": "action réservée aux analystes (rôle lecteur)"}, 403)
            if p == "/m/api/case":
                return self._json(update_case(b, u))
            if p == "/m/api/fp":        # marquer une alerte faux positif -> triage /fp
                return self._json(triage_fp_add(b.get("entity", ""), b.get("title_sub", ""), u, b.get("tag", "")))
            return self._json(update_watch(b, u))
        if p == "/m/api/subscribe":
            u = self._user()
            if not u:
                return self._json({"error": "auth"}, 401)
            if not origin_ok(self.headers):
                return self._json({"ok": False, "error": "origine refusée"}, 403)
            # OMNITECH-SOC-20261112-V4 : notifications réservées aux administrateurs SOC
            if not soc_is_admin(u):
                return self._json({"ok": False, "error": "notifications réservées aux administrateurs SOC"}, 403)
            sub = b.get("subscription")
            if isinstance(sub, dict) and str(sub.get("endpoint", "")).startswith("https://") and isinstance(sub.get("keys"), dict):
                subs = [s for s in load_subs() if s.get("endpoint") != sub["endpoint"]]
                subs.append({"endpoint": sub["endpoint"], "keys": {k: str(v) for k, v in sub["keys"].items() if k in ("p256dh", "auth")},
                             "omni_user": u.lower(), "omni_ts": int(time.time())})
                save_subs(subs)
                return self._json({"ok": True})
            return self._json({"ok": False, "error": "abonnement invalide"}, 400)
        if p in ("/m/api/push-test", "/m/api/unsubscribe"):   # OMNITECH-SOC-20261112
            u = self._user()
            if not u:
                return self._json({"error": "auth"}, 401)
            if not origin_ok(self.headers):
                return self._json({"ok": False, "error": "origine refusée"}, 403)
            ep = str(b.get("endpoint") or "")
            subs = load_subs()
            known = bool(ep) and any(s.get("endpoint") == ep for s in subs)
            if p == "/m/api/unsubscribe":
                if known:
                    save_subs([s for s in subs if s.get("endpoint") != ep])
                return self._json({"ok": True, "removed": known})
            if not known:
                return self._json({"ok": False, "error": "appareil non abonné : réactivez les notifications"}, 404)
            if not soc_is_admin(u):   # OMNITECH-SOC-20261112-V4
                return self._json({"ok": False, "error": "notifications réservées aux administrateurs SOC"}, 403)
            now = time.time()
            if now - _PUSH_TEST.get(ep, 0) < 20:
                return self._json({"ok": False, "error": "patientez 20 s entre deux tests"}, 429)
            _PUSH_TEST[ep] = now
            n = push_all("Test de notification OMNI SOC", f"Les alertes du SIEM arriveront sur cet appareil ({u}).",
                         url="/soc/#p=overview", sev="", tag="omni-soc-test", only=ep)
            return self._json({"ok": n > 0, "sent": n,
                               "error": "" if n > 0 else "échec de l'envoi (abonnement expiré ou service push injoignable)"})
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
            # OMNITECH-SOC-20261112 : lien d'ouverture, gravité, étiquette (une notification par définition)
            url = str(b.get("url") or "")
            if not url.startswith("/soc/"):
                kt = ev.get("key_tuple") or []
                ent = str((kt[0] if kt else "") or ev.get("key") or "").split("|")[0].strip()
                url = "/soc/#p=incidents"
                if ent and len(ent) <= 120:
                    url += "&e=" + _up.quote(ent, safe="")
            try:
                prio = int(ev.get("priority") or b.get("priority") or 0)
            except (TypeError, ValueError):
                prio = 0
            sev = str(b.get("sev") or ("critical" if prio >= 4 else "high" if prio == 3 else "medium" if prio == 2 else ""))
            tag = "omni-" + str(b.get("event_definition_id") or b.get("tag") or "soc")[:40]
            sent = push_all(str(title)[:90], str(body)[:140], url=url, sev=sev, tag=tag)
            return self._json({"sent": sent})
        self._json({"error": "not found"}, 404)


_PUSH_TEST: dict = {}   # OMNITECH-SOC-20261112 : anti-rafale des notifications de test


def push_all(title: str, body: str, url: str = "", sev: str = "", tag: str = "", only: str = "") -> int:
    """Envoie un web-push minimal à tous les abonnés (ou au seul `only`) ; payload non sensible."""
    try:
        from pywebpush import webpush, WebPushException  # type: ignore
    except ImportError:
        return -1
    if not os.path.exists(VAPID_PRIV_FILE):
        return -1
    priv = open(VAPID_PRIV_FILE).read()
    payload = json.dumps({"title": str(title)[:90], "body": str(body)[:140], "url": str(url)[:300],
                          "sev": str(sev)[:12], "tag": str(tag)[:60]}, ensure_ascii=False).encode("utf-8")
    subs = load_subs()
    if only:
        subs = [s for s in subs if s.get("endpoint") == only]
    # OMNITECH-SOC-20261112-V4 : seulement les abonnements d'un administrateur SOC
    subs = [s for s in subs if soc_is_admin(str(s.get("omni_user", "")))]
    ok, dead = 0, []
    for s in subs:
        try:
            webpush(subscription_info={"endpoint": s.get("endpoint"), "keys": s.get("keys") or {}}, data=payload, vapid_private_key=priv,
                    vapid_claims={"sub": VAPID_SUBJECT}, timeout=10)
            ok += 1
        except WebPushException as e:
            if getattr(e, "response", None) is not None and e.response.status_code in (404, 410):
                dead.append(s.get("endpoint"))
        except Exception:
            pass
    if dead:
        save_subs([s for s in load_subs() if s.get("endpoint") not in dead])
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
get_soc_kpi = cached(600)(get_soc_kpi)                 # indicateurs SOC (période longue, ~3 s)


# OMNITECH-SOC-20261111 : pages lentes prechargees en tache de fond (deploy ~17 s, report ~6 s)
get_siem_ops = cached(60)(get_siem_ops)
try:
    get_deploy = cached(300)(get_deploy)
    get_report = cached(300)(get_report)
except NameError:
    pass
def _soc_warm():
    import time as _t
    _t.sleep(20)
    while True:
        for fn in ("get_deploy", "get_report", "get_siem_ops"):
            try:
                globals()[fn]()
            except Exception:
                pass
        _t.sleep(240)
if __name__ == "__main__":
    threading.Thread(target=_soc_warm, daemon=True).start()
    ThreadingHTTPServer(LISTEN, H).serve_forever()
