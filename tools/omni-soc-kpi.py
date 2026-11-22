#!/usr/bin/env python3
"""omni-soc-kpi - Indicateurs SOC vérifiables, calculés sur les données réelles.

Indicateurs produits sur une période paramétrable (médiane, p90, moyenne, min, max) :
  - volume d'alertes Graylog par sévérité, flux d'origine (stream) et détection ;
  - MTTD : délai entre l'horodatage de l'événement source et la création de l'alerte
    (index gl-events*) ; incidents système de Graylog (gl-system-events*) ;
  - MTTR : délai entre l'incident et sa prise en charge ou sa clôture d'après les
    dossiers de la console SOC, délai alerte -> blocage SOAR, journal d'audit ;
  - part des alertes classées faux positifs par le triage (omni-alert-triage) ;
  - couverture ATT&CK des définitions d'événements actives.

LECTURE SEULE, par construction :
  - OpenSearch : uniquement POST <index>/_search (requête de recherche, aucune écriture) ;
  - API Graylog : uniquement GET (facultative ; sinon fichiers JSON exportés) ;
  - fichiers d'état : ouverts en lecture. Seuls --json-out / --md-out écrivent, là où
    l'opérateur le demande.

Une donnée absente n'est jamais inventée : elle est signalée dans « lacunes ». Une
recherche en échec interrompt le calcul (jamais présentée comme un zéro).

Le module est aussi chargé par le backend de la console (GET /m/api/soc-kpi) :
la fonction compute() reçoit la fonction de recherche et l'accès Graylog à utiliser.
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import json
import math
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTS_INDEX = "gl-events*"
SYSTEM_EVENTS_INDEX = "gl-system-events*"
DEFAULT_LOG_INDEX = "omni-*"
DEFAULT_MITRE_CSV = os.path.join(ROOT, "lookups", "mitre-attack.csv")
DEFAULT_CASES_FILE = "/var/lib/omni-mobile/cases.json"
DEFAULT_ADMIN_DIR = "/var/lib/omni-mobile/admin"
DEFAULT_TZ = "Europe/Paris"
# Auteurs de notes considérés comme automatisés (lots de qualification par un agent ou un script).
DEFAULT_AUTO_ACTOR = r"^(agent|robot|script|auto)\b"
PRIORITY_LABELS = {1: "faible", 2: "moyenne", 3: "élevée", 4: "critique"}
TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
           "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
_PROD_PREFIXES = ("/var/lib", "/etc", "/var/www", "/var/log", "/usr", "/opt/oms-")
_INDEX_RE = re.compile(r"^[A-Za-z0-9_*.,-]{1,400}$")
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TAG_RE = re.compile(r'(NOT\s+|-)?alert_tag\s*:\s*(\([^)]*\)|"[^"]*"|[A-Za-z0-9_.*-]+)')


class KpiError(RuntimeError):
    """Erreur de calcul (recherche indisponible, réponse incomplète, paramètre invalide)."""


# ----------------------------------------------------------------------------- outils
def parse_ts(value, naive_tz=None):
    """Horodatage -> datetime UTC conscient du fuseau, ou None.

    - « 2026-11-22 16:55:16.105 » (format Graylog/OpenSearch) : UTC ;
    - ISO 8601 avec décalage ou « Z » : converti en UTC ;
    - ISO 8601 sans décalage (notes de dossier) : interprété dans naive_tz (heure locale) ;
    - nombre : epoch en secondes (ou millisecondes si > 1e11).
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value) / (1000.0 if value > 1e11 else 1.0)
        return dt.datetime.fromtimestamp(v, dt.timezone.utc)
    s = str(value).strip()
    graylog = re.fullmatch(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?)", s)
    if graylog:
        try:
            return dt.datetime.fromisoformat(graylog.group(1) + "T" + graylog.group(2)).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)   # +0100 -> +01:00
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=naive_tz or dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)


def stats(values):
    """Statistiques descriptives en secondes : n, moyenne, médiane, p90, min, max.

    Percentiles par interpolation linéaire entre rangs (méthode par défaut de numpy)."""
    vals = sorted(float(v) for v in values if v is not None and not math.isnan(float(v)))
    n = len(vals)
    if not n:
        return {"n": 0, "moyenne": None, "mediane": None, "p90": None, "min": None, "max": None}

    def pct(p):
        k = (n - 1) * p
        lo, hi = math.floor(k), math.ceil(k)
        return vals[lo] if lo == hi else vals[lo] + (vals[hi] - vals[lo]) * (k - lo)

    r = lambda x: round(x, 1)
    return {"n": n, "moyenne": r(sum(vals) / n), "mediane": r(pct(0.5)), "p90": r(pct(0.9)),
            "min": r(vals[0]), "max": r(vals[-1])}


def fmt_duration(seconds):
    if seconds is None:
        return "n.d."
    s = float(seconds)
    if abs(s) < 120:
        return f"{s:.0f} s"
    if abs(s) < 7200:
        return f"{s / 60:.1f} min".replace(".", ",")
    if abs(s) < 172800:
        return f"{s / 3600:.1f} h".replace(".", ",")
    return f"{s / 86400:.1f} j".replace(".", ",")


def _share(part, total):
    return round(100.0 * part / total, 1) if total else None


def _ms(d):
    return int(d.timestamp() * 1000)


class Window:
    def __init__(self, since, until):
        if since >= until:
            raise KpiError("période invalide : début postérieur ou égal à la fin")
        self.since, self.until = since, until

    def range(self, field="timestamp", pad_before=0):
        return {"range": {field: {"gte": _ms(self.since) - int(pad_before * 1000), "lt": _ms(self.until),
                                  "format": "epoch_millis"}}}

    def contains(self, d):
        return d is not None and self.since <= d < self.until

    def as_dict(self):
        return {"debut": self.since.isoformat(), "fin": self.until.isoformat(),
                "jours": round((self.until - self.since).total_seconds() / 86400, 2)}


def make_window(days=None, since=None, until=None, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    end = parse_ts(until) if until else now
    if until and end is None:
        raise KpiError("date de fin illisible")
    if since:
        start = parse_ts(since)
        if start is None:
            raise KpiError("date de début illisible")
    else:
        d = 30 if days is None else days
        if not 0 < float(d) <= 366:
            raise KpiError("nombre de jours hors bornes (1 à 366)")
        start = end - dt.timedelta(days=float(d))
    return Window(start, end)


def _check_search(res, body):
    if not isinstance(res, dict) or not isinstance(res.get("hits"), dict):
        raise KpiError("réponse de recherche invalide")
    if res.get("timed_out") or (res.get("_shards") or {}).get("failed"):
        raise KpiError("recherche incomplète (délai dépassé ou shard en échec)")
    want = body.get("aggs") or {}
    if want and not set(want).issubset(res.get("aggregations") or {}):
        raise KpiError("agrégations manquantes dans la réponse")
    return res


def _total(res):
    t = res.get("hits", {}).get("total")
    return int(t.get("value", 0)) if isinstance(t, dict) else int(t or 0)


def _buckets(res, name):
    return (res.get("aggregations") or {}).get(name, {}).get("buckets", []) or []


def iter_hits(search, index, query, source, sort, page=5000, max_docs=500000):
    """Pagination search_after ; renvoie (documents, tronqué)."""
    out, after, truncated = [], None, False
    while True:
        body = {"size": page, "query": query, "_source": source, "sort": sort}
        if after is not None:
            body["search_after"] = after
        res = _check_search(search(index, body), body)
        hits = res["hits"].get("hits") or []
        out.extend(h.get("_source") or {} for h in hits)
        if len(out) >= max_docs:
            truncated = True
            break
        if len(hits) < page:
            break
        after = hits[-1].get("sort")
        if not after:
            break
    return out, truncated


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _tz(name):
    if ZoneInfo is None or not name:
        return dt.timezone.utc
    try:
        return ZoneInfo(name)
    except Exception:
        return dt.timezone.utc


# ----------------------------------------------------------------- métadonnées Graylog
def load_graylog_meta(graylog_get=None, definitions=None, streams=None, warnings=None):
    """Définitions d'événements et streams : API (GET) ou exports JSON déjà chargés."""
    warnings = warnings if warnings is not None else []
    meta = {"definitions": None, "streams": None, "source": "indisponible"}
    if definitions is not None:
        meta["definitions"] = list(definitions.get("event_definitions") or definitions.get("elements") or []) \
            if isinstance(definitions, dict) else list(definitions)
        meta["source"] = "export"
    elif graylog_get is not None:
        try:
            defs, page = [], 1
            while page <= 50:
                d = graylog_get(f"/events/definitions?per_page=100&page={page}") or {}
                batch = d.get("event_definitions") or d.get("elements") or []
                defs.extend(batch)
                if not batch or len(defs) >= int(d.get("total") or 0):
                    break
                page += 1
            meta["definitions"], meta["source"] = defs, "api"
        except Exception as exc:   # API facultative : la couverture est alors marquée indisponible
            warnings.append(f"API Graylog indisponible pour les définitions ({type(exc).__name__})")
    if streams is not None:
        meta["streams"] = list(streams.get("streams") or []) if isinstance(streams, dict) else list(streams)
    elif graylog_get is not None and meta["source"] == "api":
        try:
            meta["streams"] = list((graylog_get("/streams") or {}).get("streams") or [])
        except Exception as exc:
            warnings.append(f"API Graylog indisponible pour les streams ({type(exc).__name__})")
    return meta


def title_from_message(message, key=""):
    """Titre de détection déduit du message d'événement (« Titre: clé - count()=N »)."""
    m = str(message or "").strip()
    if key and f": {key}" in m:
        m = m.split(f": {key}", 1)[0]
    m = re.sub(r"\s+-\s+[a-z_]+\([^)]*\)\s*=.*$", "", m)
    return m.strip() or "?"


# ------------------------------------------------------------------- 1. volumes
def compute_alerts(search, win, meta):
    flt = [win.range(), {"term": {"alert": True}}]
    body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": flt}},
            "aggs": {"sev": {"terms": {"field": "priority", "size": 10}},
                     "src": {"terms": {"field": "source_streams", "size": 200}},
                     "det": {"terms": {"field": "event_definition_id", "size": 1000},
                             "aggs": {"ex": {"top_hits": {"size": 1, "_source": ["message", "key"]}}}},
                     "tech": {"terms": {"field": "fields.mitre_technique", "size": 500}},
                     "jour": {"date_histogram": {"field": "timestamp", "calendar_interval": "1d",
                                                 "min_doc_count": 0}}}}
    res = _check_search(search(EVENTS_INDEX, body), body)
    total = _total(res)
    body_na = {"size": 0, "track_total_hits": True,
               "query": {"bool": {"filter": [win.range(), {"term": {"alert": False}}]}}}
    non_alert = _total(_check_search(search(EVENTS_INDEX, body_na), body_na))
    defs = {d.get("id"): d for d in (meta.get("definitions") or [])}
    streams = {s.get("id"): s.get("title") for s in (meta.get("streams") or [])}
    by_det = []
    for b in _buckets(res, "det"):
        d = defs.get(b["key"]) or {}
        ex = ((b.get("ex") or {}).get("hits") or {}).get("hits") or [{}]
        src = ex[0].get("_source") or {}
        title = d.get("title") or title_from_message(src.get("message"), src.get("key"))
        by_det.append({"id": b["key"], "titre": title,
                       "etat": d.get("state") or "inconnu", "alertes": b["doc_count"],
                       "part": _share(b["doc_count"], total)})
    by_sev = [{"priorite": b["key"], "libelle": PRIORITY_LABELS.get(b["key"], str(b["key"])),
               "alertes": b["doc_count"], "part": _share(b["doc_count"], total)}
              for b in sorted(_buckets(res, "sev"), key=lambda x: -int(x["key"]))]
    by_src = [{"id": b["key"], "titre": streams.get(b["key"]) or b["key"], "alertes": b["doc_count"],
               "part": _share(b["doc_count"], total)} for b in _buckets(res, "src")]
    per_day = [{"jour": (parse_ts(b.get("key")) or win.since).date().isoformat(), "alertes": b["doc_count"]}
               for b in _buckets(res, "jour")]
    observed = {b["key"]: b["doc_count"] for b in _buckets(res, "tech") if b.get("key")}
    return {"total": total, "evenements_non_alertes": non_alert, "par_severite": by_sev,
            "par_source": by_src, "par_detection": by_det, "par_jour": per_day,
            "note_source": "source = stream Graylog d'origine (source_streams) ; un événement peut "
                           "en porter plusieurs, la somme peut donc dépasser le total."}, observed


# ------------------------------------------------------------------- 2. MTTD
def mttd_from_events(docs):
    """Délais de détection (secondes) à partir des documents gl-events.

    - événement unitaire (sans fenêtre) : timestamp_processing - timestamp (horodatage
      du message source) : valeur exacte ;
    - agrégation : l'horodatage de l'événement est la fin de fenêtre ; le premier message
      source se situe entre début et fin de fenêtre. On donne deux bornes :
      basse = traitement - fin de fenêtre, haute = traitement - début de fenêtre.
    Les délais négatifs (dérive d'horloge) sont comptés à part et exclus des statistiques."""
    unit, agg_lo, agg_hi, negatives = [], [], [], 0
    per_sev, per_def = {}, {}
    for s in docs:
        proc = parse_ts(s.get("timestamp_processing"))
        ts = parse_ts(s.get("timestamp"))
        if proc is None or ts is None:
            continue
        start, end = parse_ts(s.get("timerange_start")), parse_ts(s.get("timerange_end"))
        if start is None or end is None:
            lo = hi = (proc - ts).total_seconds()
            bucket = unit
        else:
            lo, hi = (proc - end).total_seconds(), (proc - start).total_seconds()
            bucket = None
        if lo < 0:
            negatives += 1
            continue
        if bucket is not None:
            unit.append(lo)
        else:
            agg_lo.append(lo)
            agg_hi.append(hi)
        sv = per_sev.setdefault(s.get("priority"), ([], []))
        sv[0].append(lo)
        sv[1].append(hi)
        dv = per_def.setdefault(s.get("event_definition_id"), ([], []))
        dv[0].append(lo)
        dv[1].append(hi)
    return unit, agg_lo, agg_hi, negatives, per_sev, per_def


def compute_mttd(search, win, alerts, max_docs):
    docs, truncated = iter_hits(
        search, EVENTS_INDEX, {"bool": {"filter": [win.range(), {"term": {"alert": True}}]}},
        ["timestamp", "timestamp_processing", "timerange_start", "timerange_end", "priority",
         "event_definition_id"], [{"timestamp": "asc"}, {"id": "asc"}], max_docs=max_docs)
    unit, agg_lo, agg_hi, negatives, per_sev, per_def = mttd_from_events(docs)
    titles = {d["id"]: d["titre"] for d in alerts.get("par_detection", [])}
    slow = sorted(({"id": k, "titre": titles.get(k, k), "borne_basse": stats(v[0]), "borne_haute": stats(v[1])}
                   for k, v in per_def.items()), key=lambda x: -(x["borne_haute"]["mediane"] or 0))
    sys_body = {"size": 500, "track_total_hits": True, "query": {"bool": {"filter": [win.range()]}},
                "_source": ["message"]}
    sys_res = _check_search(search(SYSTEM_EVENTS_INDEX, sys_body), sys_body)
    types = {}
    for h in sys_res["hits"].get("hits") or []:
        msg = str((h.get("_source") or {}).get("message") or "")
        t = msg.split(":", 1)[0].strip() if ":" in msg else "autre"
        types[t] = types.get(t, 0) + 1
    return {
        "methode": "délai = création de l'alerte (timestamp_processing) - horodatage de l'événement source. "
                   "Exact pour les détections unitaires ; encadré (borne basse = fin de fenêtre, "
                   "borne haute = début de fenêtre) pour les agrégations.",
        "alertes_analysees": len(docs), "tronque": truncated, "delais_negatifs_exclus": negatives,
        "unitaires": stats(unit), "agregations_borne_basse": stats(agg_lo), "agregations_borne_haute": stats(agg_hi),
        "global_borne_basse": stats(unit + agg_lo), "global_borne_haute": stats(unit + agg_hi),
        "par_severite": [{"priorite": k, "libelle": PRIORITY_LABELS.get(k, str(k)), "borne_basse": stats(v[0]),
                          "borne_haute": stats(v[1])} for k, v in sorted(per_sev.items(), key=lambda x: -(x[0] or 0))],
        "detections_les_plus_lentes": slow[:10],
        "evenements_systeme": {"total": _total(sys_res), "par_type_echantillon": types,
                               "note": "gl-system-events : notifications système de Graylog (dont échecs "
                                       "d'exécution de définitions), hors volume d'alertes."},
    }


# ------------------------------------------------------------------- 3. MTTR
def _case_times(case, tz):
    """(première action datée, clôture datée, auteurs) d'un dossier de la console."""
    acts, authors = [], []
    for n in case.get("notes") or []:
        t = parse_ts(n.get("ts"), tz)
        if t:
            acts.append((t, str(n.get("by") or "?")))
    for h in case.get("history") or []:      # enregistré depuis l'ajout de l'historique (voir doc)
        t = parse_ts(h.get("ts"), tz)
        if t:
            acts.append((t, str(h.get("by") or "?")))
    acts.sort(key=lambda x: x[0])
    authors = [a for _, a in acts]
    if case.get("status") != "closed":      # dossier rouvert ou ouvert : pas de clôture en cours
        return acts, None, authors
    closed = parse_ts(case.get("closed_ts"), tz)
    if closed is None:
        for h in case.get("history") or []:
            if (h.get("action") == "status" and h.get("value") == "closed") or (
                    h.get("action") == "disposition" and h.get("value") in ("true_positive", "false_positive")):
                closed = parse_ts(h.get("ts"), tz) or closed
    return acts, closed, authors


def compute_cases(search, win, log_index, cases, tz, auto_re):
    out = {"fichier_lu": cases is not None}
    cases = cases or {}
    body = {"size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": [{"term": {"event_source": "xdr_incident"}}, win.range()]}}}
    inc_total = _total(_check_search(search(log_index, body), body))
    # Les incidents de la période sont lus en une requête (filtre terme + date), puis joints aux
    # dossiers en mémoire : une requête « ids » sur tous les index omni-* est bien plus lente.
    incidents, truncated = {}, False
    if cases:
        q = {"size": 10000, "query": body["query"], "_source": ["timestamp", "severity"],
             "sort": [{"timestamp": "asc"}]}
        res = _check_search(search(log_index, q), q)
        hits = res["hits"].get("hits") or []
        truncated = inc_total > len(hits)
        for h in hits:
            if h.get("_id") in cases:
                incidents[h["_id"]] = h.get("_source") or {}
    status, dispo, first_all, first_human, closing = {}, {}, [], [], []
    closed_without_ts, with_history = 0, 0
    for cid, inc in incidents.items():
        c = cases.get(cid) or {}
        status[c.get("status", "new")] = status.get(c.get("status", "new"), 0) + 1
        d = c.get("disposition") or "non_qualifie"
        dispo[d] = dispo.get(d, 0) + 1
        t0 = parse_ts(inc.get("timestamp"))
        acts, closed, _ = _case_times(c, tz)
        if c.get("history"):
            with_history += 1
        acts = [a for a in acts if t0 and a[0] >= t0]   # action antérieure à l'incident : ignorée
        if t0 and acts:
            first_all.append((acts[0][0] - t0).total_seconds())
            human = [a for a in acts if not auto_re.search(a[1])]
            if human:
                first_human.append((human[0][0] - t0).total_seconds())
        if c.get("status") == "closed":
            if t0 and closed:
                closing.append((closed - t0).total_seconds())
            else:
                closed_without_ts += 1
    qualified = sum(v for k, v in dispo.items() if k != "non_qualifie")
    out.update({
        "incidents_xdr_periode": inc_total, "incidents_tronques": truncated,
        "dossiers_fichier": len(cases), "dossiers_periode": len(incidents),
        "dossiers_avec_historique": with_history, "par_statut": status, "par_qualification": dispo,
        "part_incidents_qualifies": _share(qualified, inc_total),
        "faux_positifs_analyste": dispo.get("false_positive", 0),
        "part_faux_positifs_analyste": _share(dispo.get("false_positive", 0), qualified),
        "prise_en_charge": stats(first_all),
        "prise_en_charge_humaine": stats(first_human),
        "cloture": stats(closing), "clotures_sans_horodatage": closed_without_ts,
        "methode": "prise en charge = première note ou entrée d'historique datée du dossier - horodatage de "
                   "l'incident oms-xdr ; « humaine » exclut les auteurs automatisés (motif configurable). "
                   "Clôture = closed_ts ou historique ; absente des dossiers antérieurs à l'historique.",
    })
    return out


def compute_soar(search, win, log_index, max_docs):
    q = {"bool": {"filter": [{"term": {"event_source": "siem_soar"}}, win.range()]}}
    body = {"size": 0, "track_total_hits": True, "query": q,
            "aggs": {"act": {"terms": {"field": "event_action", "size": 30}}}}
    res = _check_search(search(log_index, body), body)
    actions = {b["key"]: b["doc_count"] for b in _buckets(res, "act")}
    docs, truncated = [], False
    n_blocks = actions.get("ip_bloquee", 0)
    if n_blocks:
        b2 = {"size": min(n_blocks, 10000), "query": {"bool": {"filter": [
            {"term": {"event_source": "siem_soar"}}, {"term": {"event_action": "ip_bloquee"}}, win.range()]}},
              "_source": ["timestamp", "soar_ip", "soar_detection"], "sort": [{"timestamp": "asc"}]}
        r2 = _check_search(search(log_index, b2), b2)
        docs = [h.get("_source") or {} for h in r2["hits"].get("hits") or []]
        truncated = n_blocks > len(docs)
    ips = sorted({str(d.get("soar_ip")) for d in docs if d.get("soar_ip")})
    alerts = {}
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        evs, tr = iter_hits(search, EVENTS_INDEX,
                            {"bool": {"filter": [{"terms": {"key": chunk}}, win.range(pad_before=86400)]}},
                            ["key", "timestamp_processing"], [{"timestamp": "asc"}, {"id": "asc"}], max_docs=max_docs)
        truncated = truncated or tr
        for e in evs:
            t = parse_ts(e.get("timestamp_processing"))
            if t:
                alerts.setdefault(str(e.get("key")), []).append(t)
    delays, unmatched = [], 0
    for d in docs:
        t = parse_ts(d.get("timestamp"))
        cands = [a for a in alerts.get(str(d.get("soar_ip")), []) if t and a <= t and (t - a).total_seconds() <= 86400]
        if cands:
            delays.append((t - max(cands)).total_seconds())
        else:
            unmatched += 1
    return {"actions": actions, "blocages": n_blocks, "delai_alerte_blocage": stats(delays),
            "blocages_sans_alerte_associee": unmatched, "tronque": truncated,
            "methode": "délai = horodatage du blocage (event_source=siem_soar, ip_bloquee) - création de la "
                       "dernière alerte Graylog de même clé (IP) dans les 24 h précédentes."}


def compute_audit(admin_dir, win):
    path = os.path.join(admin_dir, "audit.jsonl") if admin_dir else ""
    if not path or not os.path.isfile(path):
        return {"disponible": False, "fichier": path}
    by_action, n = {}, 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if win.contains(parse_ts(e.get("ts"))):
                n += 1
                k = f"{e.get('event', '?')}:{e.get('action', '?')}"
                by_action[k] = by_action.get(k, 0) + 1
    return {"disponible": True, "fichier": path, "entrees_periode": n, "par_action": by_action}


# ------------------------------------------------------------------- 4. triage
def classify_triage(decision, reason):
    r = str(reason or "")
    if r.startswith(("fp_connu", "fp_soc")):
        return "faux_positif_regle"
    if decision == "drop" and r.startswith("llm:"):
        return "rejet_juge_llm"
    if decision == "drop" and r.startswith("noise("):
        return "bruit_sous_seuil"
    if decision == "drop":
        return "ecarte_autre"
    return "transmis_ou_regroupe"


def compute_triage(search, win, log_index):
    q = {"bool": {"filter": [{"term": {"event_source": "alert_triage"}}, win.range()]}}
    body = {"size": 0, "track_total_hits": True, "query": q,
            "aggs": {"dec": {"terms": {"field": "triage_decision", "size": 30},
                             "aggs": {"r": {"terms": {"field": "triage_reason", "size": 2000}}}},
                     "tier": {"terms": {"field": "triage_tier", "size": 10}}}}
    res = _check_search(search(log_index, body), body)
    decisions, classes, llm_err, llm_ok, fp_add = {}, {}, 0, 0, 0
    for b in _buckets(res, "dec"):
        decisions[b["key"]] = b["doc_count"]
        if b["key"] == "fp_add":
            fp_add += b["doc_count"]
            continue
        for rb in (b.get("r") or {}).get("buckets", []):
            c = classify_triage(b["key"], rb["key"])
            classes[c] = classes.get(c, 0) + rb["doc_count"]
            if "llm_erreur" in rb["key"] or "llm_absent" in rb["key"]:
                llm_err += rb["doc_count"]
            elif str(rb["key"]).startswith("llm:"):
                llm_ok += rb["doc_count"]
    alert_decisions = sum(v for k, v in decisions.items() if k not in ("fp_add",))
    fp = classes.get("faux_positif_regle", 0)
    llm_fp = classes.get("rejet_juge_llm", 0)
    return {
        "decisions_total": alert_decisions, "par_decision": decisions,
        "par_niveau": {b["key"]: b["doc_count"] for b in _buckets(res, "tier")},
        "par_classe": classes,
        "faux_positifs": fp, "part_faux_positifs": _share(fp, alert_decisions),
        "rejets_juge_llm": llm_fp, "part_rejets_juge_llm": _share(llm_fp, alert_decisions),
        "part_bruit_sous_seuil": _share(classes.get("bruit_sous_seuil", 0), alert_decisions),
        "juge_llm_sollicite_ok": llm_ok, "juge_llm_indisponible": llm_err,
        "lots": decisions.get("lot", 0), "recapitulatifs": decisions.get("digest", 0),
        "regles_fp_creees": fp_add,
        "methode": "faux positif = décision du triage motivée par une règle FP (fp_connu : liste statique ; "
                   "fp_soc : règle apprise depuis la console ou un lien de mail). Le bruit écarté sous le "
                   "seuil de score et les rejets du juge LLM sont comptés à part : ce ne sont pas des faux "
                   "positifs qualifiés.",
    }


# ------------------------------------------------------------------- 5. couverture
def load_mitre(path):
    by_tag, by_tech = {}, {}
    try:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                tech = (r.get("technique") or "").strip()
                if not tech.startswith("T"):
                    continue
                row = {"technique": tech, "nom": r.get("technique_name", ""), "tactique": r.get("tactic", "")}
                by_tag[(r.get("alert_tag") or "").strip()] = row
                by_tech.setdefault(tech, row)
    except OSError:
        pass
    return by_tag, by_tech


def extract_alert_tags(query):
    """Tags positifs cités par une requête Graylog (alert_tag:x, alert_tag:(a OR b), "x")."""
    tags = set()
    for neg, val in _TAG_RE.findall(query or ""):
        if neg:
            continue
        for tok in re.split(r"\s+(?:OR|AND)\s+|\s+", val.strip("()")):
            tok = tok.strip().strip('"')
            if tok and "*" not in tok and tok not in ("OR", "AND", "NOT"):
                tags.add(tok)
    return tags


def definition_techniques(defn, by_tag):
    cfg = defn.get("config") or {}
    q = str(cfg.get("query") or "")
    techs = set(_TECH_RE.findall(" ".join([str(defn.get("title") or ""), str(defn.get("description") or ""), q])))
    for tt in defn.get("tactics_techniques") or []:
        techs.update(_TECH_RE.findall(json.dumps(tt)))
    tags = extract_alert_tags(q)
    for t in tags:
        if t in by_tag:
            techs.add(by_tag[t]["technique"])
    return techs, tags


def compute_coverage(meta, mitre_csv, alerts, observed):
    by_tag, by_tech = load_mitre(mitre_csv)
    declared = {r["technique"] for r in by_tag.values()}
    out = {"referentiel": os.path.basename(mitre_csv), "techniques_declarees": len(declared),
           "techniques_observees_alertes": sorted(observed), "source_definitions": meta.get("source")}
    defs = meta.get("definitions")
    if defs is None:
        out.update({"disponible": False,
                    "raison": "définitions d'événements non lues (API Graylog absente) : couverture "
                              "active non calculée ; seules les techniques déclarées et observées sont données."})
        return out
    fired = {d["id"] for d in alerts.get("par_detection", []) if d["alertes"]}
    active, n_enabled, n_disabled, with_tech, silent = {}, 0, 0, 0, 0
    for d in defs:
        if d.get("state", "ENABLED") != "ENABLED":
            n_disabled += 1
            continue
        n_enabled += 1
        if d.get("id") not in fired:
            silent += 1
        techs, _ = definition_techniques(d, by_tag)
        if techs:
            with_tech += 1
        for t in techs:
            row = active.setdefault(t, {"technique": t, "nom": (by_tech.get(t) or {}).get("nom", ""),
                                        "tactique": (by_tech.get(t) or by_tech.get(t.split(".")[0]) or {}).get(
                                            "tactique", "non mappée"),
                                        "definitions": 0, "a_alerte": False})
            row["definitions"] += 1
            row["a_alerte"] = row["a_alerte"] or d.get("id") in fired
    tactics = {}
    for row in active.values():
        tactics[row["tactique"]] = tactics.get(row["tactique"], 0) + 1
    out.update({
        "disponible": True, "definitions_actives": n_enabled, "definitions_desactivees": n_disabled,
        "definitions_actives_avec_technique": with_tech, "definitions_actives_sans_alerte_periode": silent,
        "techniques_actives": len(active),
        "techniques_actives_avec_alerte": sum(1 for r in active.values() if r["a_alerte"]),
        "tactiques_couvertes": sum(1 for t in TACTICS if tactics.get(t)), "tactiques_total": len(TACTICS),
        "par_tactique": [{"tactique": t, "techniques": tactics.get(t, 0)} for t in TACTICS]
        + [{"tactique": t, "techniques": n} for t, n in tactics.items() if t not in TACTICS],
        "declarees_sans_definition_active": sorted(declared - set(active)),
        "techniques": sorted(active.values(), key=lambda r: (r["tactique"], r["technique"])),
        "methode": "technique couverte = citée par une définition d'événement ACTIVE (identifiant T#### dans "
                   "le titre, la description, la requête ou tactics_techniques, ou alert_tag de la requête "
                   "mappé dans lookups/mitre-attack.csv).",
    })
    return out


# ------------------------------------------------------------------- assemblage
def compute(search, graylog_get=None, days=None, since=None, until=None, now=None,
            log_index=DEFAULT_LOG_INDEX, cases_file=DEFAULT_CASES_FILE, admin_dir=DEFAULT_ADMIN_DIR,
            mitre_csv=DEFAULT_MITRE_CSV, tz=DEFAULT_TZ, auto_actor_regex=DEFAULT_AUTO_ACTOR,
            definitions=None, streams=None, max_docs=500000):
    """Calcule tous les indicateurs. `search(index, body) -> dict` (réponse _search OpenSearch) ;
    `graylog_get(path) -> dict` (GET API Graylog) facultatif."""
    win = make_window(days, since, until, now)
    warnings = []
    meta = load_graylog_meta(graylog_get, definitions, streams, warnings)
    tzinfo = _tz(tz)
    auto_re = re.compile(auto_actor_regex or r"^\b$", re.I)
    alerts, observed = compute_alerts(search, win, meta)
    mttd = compute_mttd(search, win, alerts, max_docs)
    cases = _read_json(cases_file, None) if cases_file else None
    if cases is not None and not isinstance(cases, dict):
        warnings.append("fichier des dossiers illisible (objet JSON attendu)")
        cases = None
    mttr = {"dossiers": compute_cases(search, win, log_index, cases, tzinfo, auto_re),
            "soar": compute_soar(search, win, log_index, max_docs),
            "journal_audit": compute_audit(admin_dir, win)}
    triage = compute_triage(search, win, log_index)
    coverage = compute_coverage(meta, mitre_csv, alerts, observed)
    gaps = data_gaps(mttr, triage, coverage, mttd)
    return {"genere_le": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "periode": win.as_dict(), "alertes": alerts, "mttd": mttd, "mttr": mttr,
            "triage": triage, "couverture": coverage, "lacunes": gaps, "avertissements": warnings,
            "sources": {"opensearch": [EVENTS_INDEX, SYSTEM_EVENTS_INDEX, log_index],
                        "graylog": meta["source"], "dossiers": cases_file or "",
                        "journal_audit": mttr["journal_audit"].get("fichier", ""),
                        "referentiel_mitre": os.path.basename(mitre_csv)}}


def data_gaps(mttr, triage, coverage, mttd):
    g = []
    g.append("Acquittement d'alerte : aucune fonction d'acquittement n'existe dans la console ni dans "
             "Graylog tel que déployé ; le délai d'acquittement n'est pas mesurable.")
    d = mttr["dossiers"]
    if d.get("clotures_sans_horodatage"):
        g.append(f"Clôture des dossiers : {d['clotures_sans_horodatage']} dossier(s) clos sans horodatage de "
                 "clôture (statut et qualification enregistrés sans date avant l'ajout de l'historique) : "
                 "MTTR de clôture non mesurable pour ces dossiers.")
    n_all, n_human = d.get("prise_en_charge", {}).get("n", 0), d.get("prise_en_charge_humaine", {}).get("n", 0)
    if d.get("dossiers_periode") and n_human < n_all:
        g.append("Prise en charge : une partie des premières actions datées provient d'auteurs automatisés "
                 "(qualification par lot) ; la valeur « humaine » est seule représentative d'un analyste.")
    if not mttr["journal_audit"].get("disponible"):
        g.append("Journal d'audit de la console absent (" + (mttr["journal_audit"].get("fichier") or "?")
                 + ") : aucune action d'administration datée exploitable sur la période.")
    if mttr["soar"].get("blocages_sans_alerte_associee"):
        g.append(f"SOAR : {mttr['soar']['blocages_sans_alerte_associee']} blocage(s) sans alerte Graylog de même "
                 "clé retrouvée dans les 24 h : délai non calculé pour eux.")
    if triage.get("juge_llm_indisponible") and not triage.get("juge_llm_sollicite_ok"):
        g.append("Triage : le juge LLM n'a rendu aucun verdict sur la période (erreurs ou clé absente) ; "
                 "la zone grise est tranchée par le score seul.")
    if not coverage.get("techniques_observees_alertes"):
        g.append("Techniques observées : le champ fields.mitre_technique des alertes Graylog est vide ou absent "
                 "sur la période ; seules les techniques des définitions ayant alerté sont comptées.")
    if not coverage.get("disponible"):
        g.append("Couverture ATT&CK active : " + coverage.get("raison", "non calculée"))
    if mttd.get("tronque"):
        g.append("MTTD : nombre maximal de documents atteint, statistiques calculées sur un échantillon tronqué.")
    return g


# ------------------------------------------------------------------- Markdown
def _row(cells):
    return "| " + " | ".join(str(c).replace("|", "/") for c in cells) + " |"


def _stat_row(label, st):
    return _row([label, st["n"], fmt_duration(st["mediane"]), fmt_duration(st["p90"]), fmt_duration(st["moyenne"])])


def to_markdown(r):
    p, a, m, t, c = r["periode"], r["alertes"], r["mttd"], r["triage"], r["couverture"]
    d, s = r["mttr"]["dossiers"], r["mttr"]["soar"]
    pct = lambda v: "n.d." if v is None else f"{v:.1f} %".replace(".", ",")
    L = [f"# Indicateurs SOC du {p['debut'][:16].replace('T', ' ')} au {p['fin'][:16].replace('T', ' ')} (UTC)", "",
         f"Généré le {r['genere_le']} par tools/omni-soc-kpi.py (lecture seule). Période : {p['jours']} jours.", "",
         "## Volume d'alertes", "",
         f"- Alertes Graylog (alert=true) : **{a['total']}** ; événements non alertes : {a['evenements_non_alertes']}.",
         "", "| Sévérité | Alertes | Part |", "|---|---:|---:|"]
    L += [_row([x["libelle"], x["alertes"], pct(x["part"])]) for x in a["par_severite"]]
    L += ["", "| Source (stream) | Alertes | Part |", "|---|---:|---:|"]
    L += [_row([x["titre"], x["alertes"], pct(x["part"])]) for x in a["par_source"][:15]]
    L += ["", "| Détection (10 premières) | Alertes | Part |", "|---|---:|---:|"]
    L += [_row([x["titre"], x["alertes"], pct(x["part"])]) for x in a["par_detection"][:10]]
    L += ["", "## MTTD (délai de détection)", "", m["methode"], "",
          "| Mesure | n | Médiane | p90 | Moyenne |", "|---|---:|---:|---:|---:|",
          _stat_row("Détections unitaires (exact)", m["unitaires"]),
          _stat_row("Agrégations, borne basse", m["agregations_borne_basse"]),
          _stat_row("Agrégations, borne haute", m["agregations_borne_haute"]),
          _stat_row("Global, borne basse", m["global_borne_basse"]),
          _stat_row("Global, borne haute", m["global_borne_haute"]), ""]
    L += [f"Délais négatifs exclus (dérive d'horloge) : {m['delais_negatifs_exclus']}. "
          f"Événements système Graylog : {m['evenements_systeme']['total']}.", ""]
    L += ["| Sévérité | n | Médiane basse | Médiane haute | p90 haute |", "|---|---:|---:|---:|---:|"]
    L += [_row([x["libelle"], x["borne_basse"]["n"], fmt_duration(x["borne_basse"]["mediane"]),
                fmt_duration(x["borne_haute"]["mediane"]), fmt_duration(x["borne_haute"]["p90"])])
          for x in m["par_severite"]]
    L += ["", "## MTTR (prise en charge, clôture, réponse)", "", d["methode"], "",
          f"- Incidents oms-xdr sur la période : {d['incidents_xdr_periode']} ; dossiers ouverts dans la console : "
          f"{d['dossiers_periode']} ({pct(d['part_incidents_qualifies'])} des incidents qualifiés).",
          f"- Statuts : {json.dumps(d['par_statut'], ensure_ascii=False)} ; qualification : "
          f"{json.dumps(d['par_qualification'], ensure_ascii=False)}.", "",
          "| Mesure | n | Médiane | p90 | Moyenne |", "|---|---:|---:|---:|---:|",
          _stat_row("Prise en charge (toutes actions)", d["prise_en_charge"]),
          _stat_row("Prise en charge (humaine)", d["prise_en_charge_humaine"]),
          _stat_row("Clôture", d["cloture"]),
          _stat_row("Alerte -> blocage SOAR", s["delai_alerte_blocage"]), "",
          f"Actions SOAR : {json.dumps(s['actions'], ensure_ascii=False)}.", "",
          "## Faux positifs (triage)", "", t["methode"], "",
          f"- Décisions de triage : {t['decisions_total']} ; {json.dumps(t['par_decision'], ensure_ascii=False)}.",
          f"- Faux positifs (règles FP) : **{t['faux_positifs']}** ({pct(t['part_faux_positifs'])}).",
          f"- Rejets du juge LLM : {t['rejets_juge_llm']} ({pct(t['part_rejets_juge_llm'])}) ; "
          f"bruit écarté sous le seuil : {pct(t['part_bruit_sous_seuil'])}.",
          f"- Qualification analyste dans la console : {d['faux_positifs_analyste']} faux positif(s) "
          f"({pct(d['part_faux_positifs_analyste'])} des dossiers qualifiés).", "",
          "## Couverture ATT&CK", ""]
    if c.get("disponible"):
        L += [c["methode"], "",
              f"- Définitions actives : {c['definitions_actives']} (désactivées : {c['definitions_desactivees']}) ; "
              f"avec technique : {c['definitions_actives_avec_technique']} ; sans alerte sur la période : "
              f"{c['definitions_actives_sans_alerte_periode']}.",
              f"- Techniques couvertes par une définition active : **{c['techniques_actives']}** "
              f"(dont {c['techniques_actives_avec_alerte']} avec alerte sur la période) ; tactiques : "
              f"{c['tactiques_couvertes']}/{c['tactiques_total']}.",
              f"- Techniques déclarées dans le référentiel sans définition active : "
              f"{len(c['declarees_sans_definition_active'])}.", "",
              "| Tactique | Techniques |", "|---|---:|"]
        L += [_row([x["tactique"], x["techniques"]]) for x in c["par_tactique"]]
    else:
        L += [c.get("raison", "non calculée"), f"Techniques déclarées : {c['techniques_declarees']}."]
    L += ["", "## Lacunes de données", ""] + [f"- {g}" for g in r["lacunes"]]
    if r.get("avertissements"):
        L += ["", "## Avertissements", ""] + [f"- {w}" for w in r["avertissements"]]
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------- clients CLI
def opensearch_search_factory(base_url, timeout=180, cafile=None):
    """Client de recherche : POST <base>/<index>/_search uniquement (lecture seule)."""
    base = base_url.rstrip("/")
    ctx = ssl.create_default_context(cafile=cafile) if base.startswith("https://") else None

    def search(index, body):
        if not _INDEX_RE.match(index):
            raise KpiError("motif d'index refusé")
        req = urllib.request.Request(f"{base}/{urllib.parse.quote(index, safe='*,')}/_search",
                                     data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            raise KpiError(f"recherche refusée par OpenSearch (HTTP {exc.code})") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise KpiError(f"OpenSearch injoignable ({type(exc).__name__})") from None
    return search


def graylog_get_factory(api_url, token_file, cafile=None, timeout=20):
    """Accès API Graylog en GET uniquement (jeton lu dans un fichier, jamais affiché)."""
    with open(token_file, encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise KpiError("fichier de jeton Graylog vide")
    auth = base64.b64encode(f"{token}:token".encode()).decode()
    base = api_url.rstrip("/")
    ctx = ssl.create_default_context(cafile=cafile) if base.startswith("https://") else None

    def get(path):
        req = urllib.request.Request(base + path, method="GET",
                                     headers={"Accept": "application/json", "Authorization": "Basic " + auth})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.load(r)
    return get


def _refuse_prod_in_tests(paths):
    if os.environ.get("OMNI_TEST_MODE") != "1":
        return
    for p in paths:
        if p and any(os.path.realpath(p) == x or os.path.realpath(p).startswith(x + "/") for x in _PROD_PREFIXES):
            raise KpiError(f"OMNI_TEST_MODE=1 : chemin de production refusé ({p})")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Indicateurs SOC vérifiables (lecture seule).")
    ap.add_argument("--days", type=float, default=30, help="période glissante en jours (défaut 30)")
    ap.add_argument("--since", help="début ISO 8601 (prioritaire sur --days)")
    ap.add_argument("--until", help="fin ISO 8601 (défaut : maintenant)")
    ap.add_argument("--opensearch", default=os.environ.get("OPENSEARCH", "http://127.0.0.1:9200"))
    ap.add_argument("--opensearch-cacert")
    ap.add_argument("--log-index", default=DEFAULT_LOG_INDEX, help="index des journaux (défaut omni-*)")
    ap.add_argument("--cases-file", default=DEFAULT_CASES_FILE)
    ap.add_argument("--admin-dir", default=DEFAULT_ADMIN_DIR)
    ap.add_argument("--mitre-csv", default=DEFAULT_MITRE_CSV)
    ap.add_argument("--graylog-api", help="URL de l'API Graylog (GET uniquement)")
    ap.add_argument("--graylog-token-file", help="fichier contenant un jeton d'accès Graylog")
    ap.add_argument("--graylog-cacert")
    ap.add_argument("--graylog-definitions", help="export JSON de GET /events/definitions")
    ap.add_argument("--graylog-streams", help="export JSON de GET /streams")
    ap.add_argument("--tz", default=DEFAULT_TZ, help="fuseau des horodatages sans décalage (notes de dossier)")
    ap.add_argument("--auto-actor-regex", default=DEFAULT_AUTO_ACTOR)
    ap.add_argument("--max-docs", type=int, default=500000)
    ap.add_argument("--format", choices=("markdown", "json"), default="markdown", help="sortie standard")
    ap.add_argument("--json-out")
    ap.add_argument("--md-out")
    a = ap.parse_args(argv)
    try:
        _refuse_prod_in_tests([a.cases_file, a.admin_dir])
        search = opensearch_search_factory(a.opensearch, cafile=a.opensearch_cacert)
        gl = graylog_get_factory(a.graylog_api, a.graylog_token_file, a.graylog_cacert) \
            if a.graylog_api and a.graylog_token_file else None
        defs = _read_json(a.graylog_definitions, None) if a.graylog_definitions else None
        if a.graylog_definitions and defs is None:
            raise KpiError("export des définitions illisible")
        strm = _read_json(a.graylog_streams, None) if a.graylog_streams else None
        report = compute(search, gl, days=a.days, since=a.since, until=a.until, log_index=a.log_index,
                         cases_file=a.cases_file, admin_dir=a.admin_dir, mitre_csv=a.mitre_csv, tz=a.tz,
                         auto_actor_regex=a.auto_actor_regex, definitions=defs, streams=strm,
                         max_docs=a.max_docs)
    except KpiError as exc:
        print(f"omni-soc-kpi : {exc}", file=sys.stderr)
        return 2
    js = json.dumps(report, ensure_ascii=False, indent=2)
    md = to_markdown(report)
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as fh:
            fh.write(js + "\n")
    if a.md_out:
        with open(a.md_out, "w", encoding="utf-8") as fh:
            fh.write(md)
    print(js if a.format == "json" else md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
