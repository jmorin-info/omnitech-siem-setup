#!/usr/bin/env python3
# Patch v2 (11/11/2026) de omni-alert-triage et omni-alert-digest. Idempotent : chaque bloc n'est applique qu'une fois
# (marqueur "v2-20261111"). Echoue (code 1) sans rien ecrire si un point d'ancrage attendu est introuvable.
import re, sys
T, D = "/usr/local/sbin/omni-alert-triage", "/usr/local/sbin/omni-alert-digest"
t = open(T, encoding="utf-8").read(); d = open(D, encoding="utf-8").read()
def rep(src, old, new, label):
    if new in src: return src
    if src.count(old) != 1: sys.exit(f"ANCRE introuvable ou multiple : {label} ({src.count(old)})")
    return src.replace(old, new, 1)

# ---------- TRIAGE ----------
# 1. fonctions : historique 7 j, routage admin connu, file d'attente du lot ELEVE
FUNCS = r'''
# --- v2-20261111 : historique de l'entite (7 j), routage "admin connu", lot ELEVE regroupe ---------------
_DEC_IDX = "http://127.0.0.1:9200/omni-interne*,omni-m365*/_search"
def hist7(entity):
    """Historique de l'entite sur 7 jours (toutes decisions de tri) : [(titre, n)], total. Jamais bloquant."""
    if not entity or entity in ("-", ""): return [], 0
    try:
        b = {"size": 0, "query": {"bool": {"filter": [{"term": {"event_source": "alert_triage"}},
             {"term": {"triage_entity": entity}}, {"range": {"timestamp": {"gte": "now-7d"}}}]}},
             "aggs": {"t": {"terms": {"field": "alert_title", "size": 6}}}}
        req = urllib.request.Request(_DEC_IDX, data=json.dumps(b).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as r: res = json.load(r)
        rows = [(re.sub(r"^OMNI\s*-\s*", "", x["key"]), x["doc_count"]) for x in res["aggregations"]["t"]["buckets"]]
        return rows, int(res["hits"]["total"]["value"])
    except Exception:
        return [], 0
def admin_connu(e, title, entity):
    """Activite d'administration CONNUE (titre + entite exacts) -> recapitulatif quotidien au lieu d'un mail.
    DIGEST_ENTITY_RULES = "regex_titre|regex_entite;..." . Jamais applique aux CRITIQUE ni aux kill-chains."""
    for part in (e.get("DIGEST_ENTITY_RULES") or "").split(";"):
        if "|" not in part: continue
        rt, ren = part.split("|", 1)
        try:
            if re.search(rt.strip(), title or "", re.I) and re.search(ren.strip(), entity or "", re.I): return True
        except re.error:
            continue
    return False
LOT_FILE = "/var/lib/omni-alert-triage/lot.json"
def lot_enqueue(e, ctx, reason):
    """Alerte ELEVE (zone grise / bruit escalade) mise en file : envoyee groupee chaque heure par omni-alert-lot."""
    import fcntl
    g = guidance(guidance_key(ctx.get("tag", ""), ctx.get("titre", ""))) or {}
    soc = e.get("OMNI_SOC_URL", "https://bx-it-graylog-vm.omnitech.security/soc/")
    item = {"t": time.time(), "titre": re.sub(r"^OMNI\s*-\s*", "", ctx.get("titre", "")), "entite": ctx.get("entite", ""),
            "score": ctx.get("score"), "tier": ctx.get("tier"), "why": rationale(ctx.get("tier"), reason, ctx.get("score")),
            "user": ctx.get("user", ""), "host": ctx.get("host", ""), "src_ip": ctx.get("src_ip", ""), "country": ctx.get("country", ""),
            "count": ctx.get("count", ""), "count_reel": ctx.get("count_reel", False), "ts": ctx.get("ts", ""),
            "mitre": (ctx.get("mitre_tech", "") + (" - " + ctx["mitre_name"] if ctx.get("mitre_name") else "")).strip(" -"),
            "tactique": ctx.get("mitre_tac", ""), "desc": ctx.get("desc", ""), "a_verifier": g.get("a_verifier", ""),
            "remediation": g.get("remediation", ""), "replay": ctx.get("replay", ""),
            "soc": soc + ("#e=" + urllib.parse.quote(ctx["entite"]) if ctx.get("entite") not in ("-", "", None) else ""),
            "fp": quick_fp_link(e, ctx.get("entite", ""), ctx.get("tag", "")) if ctx.get("tier") != "CRITICAL" else "",
            "hist7": ctx.get("hist7") or [], "hist7_total": ctx.get("hist7_total", 0), "corr": ctx.get("corr_rows") or [],
            "extrait": (ctx.get("message") or "")[:300]}
    os.makedirs(os.path.dirname(LOT_FILE), exist_ok=True)
    with open(LOT_FILE + ".lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try: q = json.load(open(LOT_FILE))
        except Exception: q = []
        q.append(item); tmp = LOT_FILE + ".tmp"; json.dump(q[-500:], open(tmp, "w")); os.replace(tmp, LOT_FILE)
'''
t = rep(t, "class Handler(BaseHTTPRequestHandler):", FUNCS.lstrip("\n") + "class Handler(BaseHTTPRequestHandler):", "Handler")
# 2. historique ajoute au contexte
t = rep(t, '        mail_thr = int(e.get("MAIL_SCORE_THRESHOLD","80"))',
        '        ctx["hist7"], ctx["hist7_total"] = hist7(entity)   # v2-20261111\n        mail_thr = int(e.get("MAIL_SCORE_THRESHOLD","80"))', "mail_thr")
# 3. routage admin connu (apres la regle DIGEST_TITLES_REGEX)
t = rep(t, '            decision, reason = "digest", f"recapitulatif(score={score})"\n',
        '            decision, reason = "digest", f"recapitulatif(score={score})"\n'
        '        elif tier == "GRAY" and admin_connu(e, title, entity):   # v2-20261111\n'
        '            decision, reason = "digest", f"admin_connu(score={score})"\n', "digest branch")
# 4. lot ELEVE regroupe
t = rep(t, '                try:\n                    send_mail(e, ctx, reason); decision = "mail"; d[key] = now\n',
        '                try:\n'
        '                    if _gris and str(e.get("GRAY_BATCH", "1")) == "1":   # v2-20261111 : ELEVE -> lot horaire\n'
        '                        lot_enqueue(e, ctx, reason); decision = "lot"; d[key] = now\n'
        '                    else:\n'
        '                        send_mail(e, ctx, reason); decision = "mail"; d[key] = now\n', "send_mail")
# 5. bloc HTML "Historique 7 jours" + texte
HIST_HTML = '''    hist = ""; h7 = ctx.get("hist7") or []   # v2-20261111
    if h7:
        lh = "".join(f'<div style="font-size:12px;color:{BODY};padding:3px 0;border-bottom:1px solid {LINE}"><b style="color:{INK}">{n}&times;</b>&nbsp; {_esc(tt)}</div>' for tt, n in h7)
        hist = (f'<tr><td style="padding:18px 32px 0"><div style="font-size:11px;color:{LAB};font-weight:600;letter-spacing:.4px;text-transform:uppercase;margin-bottom:8px">'
                f'Historique de cette entité sur 7 jours ({_esc(ctx.get("hist7_total", 0))} alertes triées)</div>'
                f'<div style="background:{BOX};border-left:2px solid #98a2b3;border-radius:0 6px 6px 0;padding:9px 14px">{lh}</div></td></tr>')
    guide = ""
    if g:'''
t = rep(t, '    guide = ""\n    if g:', HIST_HTML, "guide html")
t = rep(t, "            f'{corr}{events}{guide}'", "            f'{corr}{hist}{events}{guide}'", "assemblage html")
t = rep(t, '    body += f"  Recu car : {why}\\n\\n"',
        '    body += f"  Recu car : {why}\\n"\n'
        '    if ctx.get("hist7"):   # v2-20261111\n'
        '        body += f"  Historique 7 j ({ctx.get(\'hist7_total\', 0)} alertes) : " + "; ".join(f"{n}x {tt}" for tt, n in ctx["hist7"]) + "\\n"\n'
        '    body += "\\n"', "recu car")

# ---------- DIGEST ----------
d = rep(d, '    return {0: 96, 3: 72}.get(now.weekday(), 84)',
        '    # v2-20261111 : recapitulatif QUOTIDIEN (lundi = depuis vendredi 08:00)\n    return {0: 72}.get(now.weekday(), 24)', "window_hours")
d = rep(d, '''    q = {"bool": {"must": [{"term": {"event_source": "alert_triage"}},
                           {"term": {"triage_decision": "mail"}},
                           {"range": {"timestamp": rng}}]}}
    out, after = [], None''', '''    q = {"bool": {"must": [{"term": {"event_source": "alert_triage"}},
                           {"terms": {"triage_decision": ["mail", "lot"]}},   # v2-20261111 : lot ELEVE inclus
                           {"range": {"timestamp": rng}}]}}
    out, after = [], None''', "collect")
FPREC = '''RECAP = []
FPSIG = []   # v2-20261111 : faux positifs connus ecartes par signature (pipeline omni-fp-26-*)
def collect_fp(hours):
    q = {"bool": {"filter": [{"exists": {"field": "fp_signature"}}, {"range": {"timestamp": {"gte": f"now-{hours}h"}}}]}}
    try:
        req = urllib.request.Request(f"{OS_URL}/omni-winsec*,omni-sysmon*/_search", data=json.dumps({"size": 0, "query": q,
              "aggs": {"s": {"terms": {"field": "fp_signature", "size": 20}, "aggs": {"h": {"cardinality": {"field": "host"}}}}}}).encode(),
              headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r: res = json.load(r)
        return [(b["key"], b["doc_count"], b["h"]["value"]) for b in res["aggregations"]["s"]["buckets"]]
    except Exception:
        return []'''
d = rep(d, "RECAP = []", FPREC, "RECAP global")
FPHTML = '''    if FPSIG:   # v2-20261111
        fl = "".join(f'<tr><td style="padding:6px 0;border-bottom:1px solid {LINE};font-size:12.5px;color:{BODY}">'
                     f'<span style="font-weight:600;color:{INK}">{n}&times;</span>&nbsp; {esc(sig)}'
                     f'<span style="color:{MUT}"> &middot; {nh} machine(s)</span></td></tr>' for sig, n, nh in FPSIG)
        blocks += (f'<tr><td style="padding:18px 32px 0"><div style="font-size:11px;color:{LAB};font-weight:600;'
                   f'letter-spacing:.4px;text-transform:uppercase;margin-bottom:6px">Activité légitime connue écartée (faux positifs)</div>'
                   f'<div style="font-size:11.5px;color:{MUT};margin-bottom:4px">Événements reconnus par signature précise '
                   f'(compte + machine + processus). Recherche Graylog : <code>_exists_:fp_signature</code>.</div>'
                   f'<table width="100%" cellpadding="0" cellspacing="0">{fl}</table></td></tr>')
    html = (
        f'<body style="margin:0;background:{BG};'''
d = rep(d, '''    html = (
        f'<body style="margin:0;background:{BG};''', FPHTML, "html start")
d = rep(d, '''    txt += ["", f"Console SOC : {SOC}"]''', '''    if FPSIG:   # v2-20261111
        txt += ["", "ACTIVITE LEGITIME CONNUE ECARTEE (faux positifs, signatures) :"] + [f"  {n}x  {sig}  ({nh} machine(s))" for sig, n, nh in FPSIG]
    txt += ["", f"Console SOC : {SOC}"]''', "txt soc")
d = rep(d, "    global RECAP\n    RECAP = collect_recap(hours)", "    global RECAP, FPSIG\n    RECAP = collect_recap(hours)\n    FPSIG = collect_fp(hours)", "main recap")
if "import urllib.request" not in d and "urllib.request" not in d.split("def ")[0]:
    d = d.replace("import ", "import urllib.request, ", 1)
open(T + ".v2", "w", encoding="utf-8").write(t); open(D + ".v2", "w", encoding="utf-8").write(d)
print("patch OK ->", T + ".v2", D + ".v2")
