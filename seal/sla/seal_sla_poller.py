#!/usr/bin/env python3
# =============================================================================
# seal_sla_poller.py - SLA d'acquittement des alarmes SEAL severes (multi-site)
#
# PROBLEME METIER
#   Une alarme de surete PHYSIQUE severe (intrusion video, effraction, declencheur
#   manuel...) qui reste OUVERTE sans etre traitee au-dela d'un delai (SLA) est un
#   risque operationnel : personne n'a leve l'alarme. Graylog Open ne sait pas
#   exprimer "un evenement A SANS evenement B de cloture" (anti-jointure) dans une
#   event definition -> ce poller le fait, par CORRELATION D'ETAT par groupe.
#
# MODELE DE DONNEES (verifie sur la collecte reelle QA+OMEGA, 15/07)
#   - Chaque alarme = un EVEN_GROUP_ID ; la vue ALARMES re-emet une ligne (nouveau
#     VERSION/rowversion) a CHAQUE transition de cycle de vie -> plusieurs events
#     Graylog par groupe. Le DERNIER (timestamp max) porte l'etat courant.
#   - EVEN_LIFESTATUS : END = clos/resolu | LIV = actif/en cours | INF = informatif.
#     => RESOLU  = dernier statut END (ou ACK_EVEN_ID present = acquitte console).
#        OUVERT  = dernier statut LIV.  INF = informatif -> hors SLA (ignore).
#     (END_EVEN_ID seul n'est PAS fiable : present meme sur des groupes LIV.)
#   - severity_num est inexploitable comme rang (valeurs = codes, pas un score).
#     La severite SLA vient donc d'un SET de codes REEV securite, cf SEVERE_CODES.
#   - La plupart des "alarmes" sont du bruit maintenance (SEM97 perte module, DOMBOX)
#     ou des evenements ponctuels sans cycle (refus d'acces SEM122... deja couverts
#     par les detections de seuil) -> EXCLUS du SLA pour ne pas noyer l'operateur.
#
# SORTIE
#   Pour chaque alarme severe OUVERTE au-dela de son SLA, emet un marqueur GELF
#   (event_source=seal, event_domain=alarm, alert_tag=seal_sla_breach, seal_site,
#   sla_class, sla_minutes, age_minutes, escalation...) -> route vers le stream
#   SEAL Alarmes, consomme par la detection SLA-001 (notification) et le widget
#   backlog par site. Idempotent : un groupe n'est re-emis qu'a l'ESCALADE (le
#   marqueur ne se repete pas a chaque cycle) ; l'etat vit dans un fichier local.
#
# REGLES D'ENGAGEMENT : lecture OpenSearch local (aucun secret, aucun token), aucune
#   ecriture cote SEAL, aucun impact sur le tenant co-gere. Idempotent, --once (sec).
# =============================================================================
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

log = logging.getLogger("oms-seal-sla")

# --- SET SEVERE par defaut (surchargable via SEAL_SLA_CODES_FILE) ------------
# code REEV -> (classe SLA, delai en minutes avant breche). Seedé depuis l'analyse
# reelle (SEM218 seul code a cycle de vie avec des LIV persistants en QA/OMEGA) +
# le referentiel recon (effraction, declencheur manuel). L'operateur AJUSTE ce set
# selon sa politique ; tout code absent d'ici n'est PAS suivi par le SLA.
DEFAULT_SEVERE: dict[str, dict[str, Any]] = {
    # --- critiques : 15 min ---
    "SEM218": {"cls": "critical", "sla": 15, "label": "Intrusion detectee par la video"},
    "SEM113": {"cls": "critical", "sla": 15, "label": "Effraction porte"},
    "SEM805": {"cls": "critical", "sla": 15, "label": "Declencheur manuel"},
    # --- elevees : 60 min ---
    "SEM118": {"cls": "high", "sla": 60, "label": "Bouton poussoir bloque"},
    "SEM73":  {"cls": "high", "sla": 60, "label": "Base de donnees UTL modifiee"},
}

RESOLVED_STATUS = {"END"}     # dernier statut = clos
OPEN_STATUS = {"LIV"}         # dernier statut = actif/non traite (candidat SLA)
# INF et tout autre statut -> ni ouvert ni breche (informatif / transitoire)


def load_config() -> dict[str, Any]:
    """Config par variables d'environnement (aucun secret : lecture locale)."""
    # SEAL_SLA_CODES_MODE=replace -> repart d'un set VIDE (set 100% custom / tests
    # isoles) ; defaut 'merge' -> complete/ajuste le set severe par defaut.
    codes = {} if os.environ.get("SEAL_SLA_CODES_MODE", "merge") == "replace" else dict(DEFAULT_SEVERE)
    cf = os.environ.get("SEAL_SLA_CODES_FILE", "")
    if cf and os.path.isfile(cf):
        with open(cf, encoding="utf-8") as fh:
            override = json.load(fh)
        # merge : chaque entree DOIT porter cls+sla ; label optionnel
        for code, spec in override.items():
            if "sla" in spec and "cls" in spec:
                codes[code] = {"cls": spec["cls"], "sla": int(spec["sla"]),
                               "label": spec.get("label", code)}
    # multiplicateur de SLA par site (ex. prod plus stricte) : {"bx-seal-omega":1.0}
    site_mult: dict[str, float] = {}
    sm = os.environ.get("SEAL_SLA_SITE_MULT", "")
    if sm:
        site_mult = {k: float(v) for k, v in json.loads(sm).items()}
    return {
        "os_url": os.environ.get("OPENSEARCH_URL", "http://127.0.0.1:9200").rstrip("/"),
        "index": os.environ.get("SEAL_ALARM_INDEX", "omni-seal-alarm_*"),
        "stream": os.environ.get("SEAL_ALARM_STREAM", "6a50faca3411482ad6e00e57"),
        "gelf_host": os.environ.get("GELF_HOST", "127.0.0.1"),
        "gelf_port": int(os.environ.get("GELF_PORT", "12201")),
        "gelf_proto": os.environ.get("GELF_PROTO", "http"),
        "lookback_h": int(os.environ.get("SEAL_SLA_LOOKBACK_HOURS", "48")),
        "state_file": os.environ.get("SEAL_SLA_STATE_FILE", "/var/lib/oms-seal-sla/state.json"),
        "include_test": os.environ.get("SEAL_SLA_INCLUDE_TEST", "0") == "1",
        # escalade : re-emet quand l'age depasse escalation_factor * SLA (cumulatif)
        "escalation_factor": float(os.environ.get("SEAL_SLA_ESCALATION_FACTOR", "4")),
        "codes": codes,
        "site_mult": site_mult,
    }


def os_search(cfg: dict, body: dict) -> dict:
    try:
        r = requests.post(f"{cfg['os_url']}/{cfg['index']}/_search", json=body, timeout=60)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        log.error("Recherche OpenSearch echouee: %s", exc)
        return {}


def scan_groups(cfg: dict) -> list[dict[str, Any]]:
    """Retourne l'etat courant de chaque groupe d'alarme severe sur la fenetre.

    Une seule requete : terms(EVEN_GROUP_ID) + min(timestamp) + dernier hit (etat).
    """
    codes = " OR ".join(sorted(cfg["codes"]))
    query = f"event_source:seal AND event_domain:alarm AND REEV_CODE:({codes}) AND NOT _exists_:alert_tag"
    if not cfg["include_test"]:
        query += " AND NOT _exists_:TEST_SIEM"
    filt: list[dict] = [{"range": {"timestamp": {"gte": f"now-{cfg['lookback_h']}h"}}}]
    if cfg["stream"]:
        filt.append({"term": {"streams": cfg["stream"]}})
    body = {
        "size": 0,
        "query": {"bool": {"must": [{"query_string": {"query": query, "analyze_wildcard": True}}],
                           "filter": filt}},
        "aggs": {"g": {"terms": {"field": "EVEN_GROUP_ID", "size": 5000},
                       "aggs": {
                           "start": {"min": {"field": "timestamp"}},
                           "acked": {"filter": {"exists": {"field": "ACK_EVEN_ID"}}},
                           "last": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "desc"}}],
                                                 "_source": ["EVEN_LIFESTATUS", "REEV_CODE", "seal_site",
                                                             "event_action", "target_object_label"]}}}}},
    }
    buckets = os_search(cfg, body).get("aggregations", {}).get("g", {}).get("buckets", [])
    groups = []
    for b in buckets:
        hits = b.get("last", {}).get("hits", {}).get("hits", [])
        if not hits:
            continue
        src = hits[0].get("_source", {})
        gid = b.get("key")
        try:
            gid_int = int(round(float(gid)))       # EVEN_GROUP_ID stocke en float
        except (TypeError, ValueError):
            gid_int = gid
        groups.append({
            "group_id": gid_int,
            "start_ms": b.get("start", {}).get("value"),
            "start_iso": b.get("start", {}).get("value_as_string"),
            "acked": b.get("acked", {}).get("doc_count", 0) > 0,
            "status": src.get("EVEN_LIFESTATUS"),
            "code": src.get("REEV_CODE"),
            "site": src.get("seal_site") or "inconnu",
            "action": src.get("event_action") or "",
            "target": src.get("target_object_label") or "",
        })
    return groups


def sla_minutes(cfg: dict, code: str, site: str) -> int:
    base = cfg["codes"].get(code, {}).get("sla", 60)
    mult = cfg["site_mult"].get(site, 1.0)
    return max(1, int(round(base * mult)))


def evaluate(cfg: dict, groups: list[dict], now_ms: float) -> list[dict]:
    """Filtre les groupes en BRECHE : ouverts (LIV), non acquittes, age > SLA."""
    breaches = []
    for g in groups:
        if g["acked"] or g["status"] in RESOLVED_STATUS:
            continue                                   # resolu / acquitte
        if g["status"] not in OPEN_STATUS:
            continue                                   # INF / autre -> hors SLA
        if g["start_ms"] is None:
            continue
        age_min = (now_ms - g["start_ms"]) / 60000.0
        sla = sla_minutes(cfg, g["code"], g["site"])
        if age_min < sla:
            continue                                   # dans les temps
        spec = cfg["codes"].get(g["code"], {})
        breaches.append({**g, "age_min": int(age_min), "sla_min": sla,
                         "cls": spec.get("cls", "high"),
                         "label": spec.get("label", g["code"])})
    return breaches


def load_state(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def send_gelf(cfg: dict, payload: dict) -> bool:
    payload.setdefault("version", "1.1")
    payload.setdefault("host", "oms-seal-sla")
    payload.setdefault("timestamp", time.time())
    if cfg["gelf_proto"] == "http":
        try:
            r = requests.post(f"http://{cfg['gelf_host']}:{cfg['gelf_port']}/gelf",
                              json=payload, timeout=10)
            r.raise_for_status()
            return True
        except requests.RequestException as exc:
            log.error("Envoi GELF HTTP echoue %s:%s - %s", cfg["gelf_host"], cfg["gelf_port"], exc)
            return False
    data = (json.dumps(payload) + "\0").encode("utf-8")
    try:
        with socket.create_connection((cfg["gelf_host"], cfg["gelf_port"]), 10) as s:
            s.sendall(data)
        return True
    except OSError as exc:
        log.error("Envoi GELF echoue %s:%s - %s", cfg["gelf_host"], cfg["gelf_port"], exc)
        return False


def breach_gelf(b: dict, escalation: int) -> dict:
    sev = {"critical": 2, "high": 4}.get(b["cls"], 4)     # syslog level
    tgt = f" sur {b['target']}" if b["target"] else ""
    msg = (f"SLA alarme SEAL non traitee ({b['cls']}) : {b['label']}{tgt} "
           f"[{b['site']}] ouverte depuis {b['age_min']} min (SLA {b['sla_min']} min)"
           + (f" - ESCALADE x{escalation}" if escalation > 1 else ""))
    return {
        "short_message": msg, "level": sev,
        "_event_source": "seal", "_event_domain": "alarm",
        "_alert_tag": "seal_sla_breach", "_sla_state": "open",
        "_seal_site": b["site"], "_REEV_CODE": b["code"],
        "_event_action": b["label"], "_sla_class": b["cls"],
        "_sla_minutes": b["sla_min"], "_age_minutes": b["age_min"],
        "_escalation": escalation, "_EVEN_GROUP_ID": b["group_id"],
        "_target_object_label": b["target"],
    }


def run(cfg: dict, apply: bool) -> list[dict]:
    now_ms = time.time() * 1000.0
    groups = scan_groups(cfg)
    breaches = evaluate(cfg, groups, now_ms)
    state = load_state(cfg["state_file"])
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    active_keys = set()
    emitted = 0

    for b in sorted(breaches, key=lambda x: -x["age_min"]):
        key = f"{b['site']}:{b['group_id']}"
        active_keys.add(key)
        prev = state.get(key)
        # niveau d'escalade = combien de fois l'age a franchi escalation_factor * SLA
        tier = 1
        if cfg["escalation_factor"] > 0:
            tier = 1 + int(b["age_min"] // max(1, b["sla_min"] * cfg["escalation_factor"]))
        should_emit = prev is None or tier > prev.get("escalation", 1)
        if should_emit and apply:
            payload = breach_gelf(b, tier)
            if cfg["include_test"]:
                payload["_TEST_SIEM"] = 1     # mode test : marqueur exclu des detections
            if send_gelf(cfg, payload):
                emitted += 1
        if prev is None:
            state[key] = {"first_seen": now_iso, "code": b["code"], "site": b["site"],
                          "escalation": tier, "last_emit": now_iso}
        else:
            prev["escalation"] = max(prev.get("escalation", 1), tier)
            if should_emit:
                prev["last_emit"] = now_iso

    # purge des groupes qui ne sont plus en breche (resolus / sortis de fenetre)
    cleared = [k for k in state if k not in active_keys]
    for k in cleared:
        del state[k]
    if apply:
        save_state(cfg["state_file"], state)

    log.info("SLA SEAL : %d groupe(s) severe(s) scanne(s), %d en breche, %d marqueur(s) emis, %d resolu(s)/purge(s).",
             len(groups), len(breaches), emitted, len(cleared))
    return breaches


def main() -> int:
    ap = argparse.ArgumentParser(description="SLA d'acquittement des alarmes SEAL severes")
    ap.add_argument("--once", action="store_true",
                    help="calcule et affiche les breches SANS emettre ni modifier l'etat")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config()
    breaches = run(cfg, apply=not args.once)
    if args.once:
        if not breaches:
            print("  aucune alarme severe en breche de SLA.")
        for b in sorted(breaches, key=lambda x: -x["age_min"]):
            print(f"  [{b['cls']:>8}] {b['site']:<16} {b['code']:>6} {b['label'][:40]:<40} "
                  f"grp={b['group_id']} age={b['age_min']}min SLA={b['sla_min']}min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
