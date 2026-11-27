# -*- coding: utf-8 -*-
"""SIEM v5 (27/11/2026), chantier 2 « tri des alertes » : fonctions appelées par omni-alert-triage.

  - kev_machines(hotes, e) : CVE exploitées connues (CISA KEV) portées par une machine, d'après l'index omni-vuln
    (veille vulnérabilités, dernier passage de CHAQUE machine). Jamais bloquant (3 s, cache 30 min).
  - juge_local(e, prompt) : juge de la zone grise sur la station d'IA locale (API Ollama /api/chat).
    Délai borné (OMNI_V5_JUGE_DELAI, 20 s par défaut) ; l'appelant gère la pause après échec.

Aucun secret ici. Retour : OMNI_V5_KEV=0, OMNI_V5_JUGE=cloud|off dans /etc/omni-alert-triage.env.
"""
import json, re, time, urllib.request

OS = "http://127.0.0.1:9200"
_KEV = {"t": 0.0, "map": {}, "ok": False}

def _post(url, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

def _court(nom):
    s = str(nom or "").strip().upper()
    if not s or s in ("-", "(EMPTY VALUE)") or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s):
        return ""
    return s.split("\\")[-1].split(".")[0]

def kev_map(e=None, force=False):
    """{MACHINE: [CVE, ...]} pour le dernier passage de chaque machine (7 jours). Rafraîchi toutes les 30 min."""
    ttl = int((e or {}).get("OMNI_V5_KEV_CACHE", "1800") or 1800)
    if not force and time.time() - _KEV["t"] < ttl:
        return _KEV["map"]
    _KEV["t"] = time.time()          # même en échec : pas de nouvelle tentative avant le TTL
    try:
        f = [{"term": {"vuln_type": "constat"}}, {"range": {"timestamp": {"gte": "now-7d"}}}, {"bool": {"must_not": [{"prefix": {"vuln_passage": "TEST"}}]}}]
        r1 = _post(f"{OS}/omni-vuln*/_search", {"size": 0, "query": {"bool": {"filter": f}},
                   "aggs": {"m": {"terms": {"field": "vuln_machine", "size": 2000}, "aggs": {"p": {"max": {"field": "vuln_passage_num"}}}}}}, 3)
        dernier = {b["key"]: b["p"]["value"] for b in r1["aggregations"]["m"]["buckets"]}
        r2 = _post(f"{OS}/omni-vuln*/_search", {"size": 0, "query": {"bool": {"filter": f + [{"term": {"vuln_kev_present": 1}}]}},
                   "aggs": {"m": {"terms": {"field": "vuln_machine", "size": 2000}, "aggs": {"p": {"terms": {"field": "vuln_passage_num", "size": 10},
                            "aggs": {"k": {"terms": {"field": "vuln_kev", "size": 50}}, "pr": {"terms": {"field": "vuln_produit", "size": 10}}}}}}}}, 3)
        m = {}
        for b in r2["aggregations"]["m"]["buckets"]:
            for p in b["p"]["buckets"]:
                if dernier.get(b["key"]) is not None and float(p["key"]) == float(dernier[b["key"]]):
                    cves = []
                    for k in p["k"]["buckets"]:
                        cves += [c.strip() for c in str(k["key"]).split(",") if c.strip().upper().startswith("CVE-")]
                    if cves:
                        m[_court(b["key"])] = {"cves": sorted(set(cves)), "produits": [x["key"] for x in p["pr"]["buckets"]]}
        _KEV["map"], _KEV["ok"] = m, True
    except Exception as ex:
        print(f"[v5] carte KEV indisponible ({ex!r}) -> pas de relevement", flush=True)
        _KEV["ok"] = False
    return _KEV["map"]

def kev_machines(hotes, e=None):
    """Premier hôte de la liste qui porte une CVE KEV : (MACHINE, {cves, produits}) ou (None, None).
    Noms NetBIOS tronqués à 15 caractères dans l'inventaire (BX-SHOW-SEAL-DE) : préfixe accepté dans ce cas."""
    m = kev_map(e)
    if not m: return None, None
    for h in hotes:
        c = _court(h)
        if not c: continue
        if c in m: return c, m[c]
        for k, v in m.items():
            if len(k) == 15 and c.startswith(k): return k, v
    return None, None

def juge_local(e, prompt):
    """Appelle Ollama. Renvoie le texte de la réponse (JSON attendu) ; lève une exception sinon."""
    base = (e.get("OMNI_V5_JUGE_URL") or "").rstrip("/")
    if not base: raise ValueError("OMNI_V5_JUGE_URL absent du .env")
    url = base + "/api/chat"
    body = {"model": e.get("OMNI_V5_JUGE_MODELE") or "qwen3:14b", "stream": False, "format": "json", "think": False,
            "keep_alive": e.get("OMNI_V5_JUGE_KEEPALIVE") or "30m",
            "options": {"temperature": 0, "num_predict": int(e.get("OMNI_V5_JUGE_TOKENS", "400") or 400), "num_ctx": 8192},
            "messages": [{"role": "user", "content": prompt}]}
    r = _post(url, body, float(e.get("OMNI_V5_JUGE_DELAI", "20") or 20))
    txt = ((r.get("message") or {}).get("content") or "").strip()
    txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip()
    if not txt: raise ValueError("reponse vide")
    return txt
