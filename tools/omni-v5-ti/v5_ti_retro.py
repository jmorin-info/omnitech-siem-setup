#!/usr/bin/env python3
# OMNITECH 27/11/2026 - SIEM v5 chantier 3 « Threat intelligence » : rejeu 30 j par définition et recherche rétroactive 90 j.
# Usage (root, BX-IT-GRAYLOG-VM) :
#   python3 -I v5_ti_retro.py --rejeu [--jours 30]          rejeu des 9 définitions « OMNI v5 - TI » avec les tables ACTUELLES
#   python3 -I v5_ti_retro.py --retro [--jours 90] [--gelf]  indicateurs (Feodo, ThreatFox 6 mois, URLhaus 90 j, MalwareBazaar 90 j, Tor)
#                                                            cherchés dans les journaux ; chaque correspondance est qualifiée ;
#                                                            --gelf émet chaque correspondance en GELF (event_source=ti_retro)
# Lecture seule sur OpenSearch (agrégations composites index par index). Aucun secret affiché.
import csv, datetime as dt, http.client, io, ipaddress, json, os, re, socket, sys, time, urllib.parse, urllib.request, zipfile
http.client._MAXHEADERS = 10000
OS = "http://127.0.0.1:9200"
LOOKUP = "/etc/graylog/lookup/ti"; STATE = "/var/lib/omni-v5-ti"; BASE = "/root/omni-v5-ti"
GELF = "http://127.0.0.1:12201/gelf"
ARGS = sys.argv[1:]
MODE = ARGS[0] if ARGS else "--rejeu"
JOURS = int(ARGS[ARGS.index("--jours") + 1]) if "--jours" in ARGS else (30 if MODE == "--rejeu" else 90)
NOW = dt.datetime.now(dt.timezone.utc); DEBUT = NOW - dt.timedelta(days=JOURS)
RUN = time.strftime("%Y%m%d-%H%M")
AUT = ["accept", "close", "timeout", "start", "server-rst", "client-rst"]
BLOQ = ["deny", "ip-conn"]

def osq(path, body=None, timeout=600):
    req = urllib.request.Request(OS + path, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())

def indices(prefix):
    """Index d'un jeu dont la plage peut recouvrir la fenêtre (création >= début - 1 j pour les quotidiens, tous pour les mensuels)."""
    out = []
    for l in urllib.request.urlopen(f"{OS}/_cat/indices/{prefix}_*?h=index,creation.date&s=creation.date", timeout=60).read().decode().split("\n"):
        if not l.strip(): continue
        i, c = l.split()
        if prefix in ("omni-fortigate", "omni-sysmon", "omni-winother"):
            if dt.datetime.fromtimestamp(int(c) / 1000, dt.timezone.utc) < DEBUT - dt.timedelta(days=1): continue
        out.append(i)
    return out

def comp(prefix, filtres, sources, taille=5000, maxb=2000000):
    """Agrégation composite paginée, index par index (charge maîtrisée). Renvoie [(clé dict, doc_count)]."""
    res = []
    rng = {"range": {"timestamp": {"gte": DEBUT.strftime("%Y-%m-%d %H:%M:%S.000"), "lte": NOW.strftime("%Y-%m-%d %H:%M:%S.000")}}}
    for idx in indices(prefix):
        after = None
        while True:
            c = {"size": taille, "sources": sources}
            if after: c["after"] = after
            r = osq(f"/{idx}/_search?request_cache=false", {"size": 0, "query": {"bool": {"filter": [rng] + filtres}}, "aggs": {"c": {"composite": c}}})
            b = r["aggregations"]["c"]["buckets"]
            res += [(x["key"], x["doc_count"]) for x in b]
            if len(b) < taille or len(res) > maxb: break
            after = r["aggregations"]["c"]["after_key"]
    return res

def T(field): return {field: {"terms": {"field": field, "missing_bucket": True}}}
def H(interval): return {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": interval}}}

def termes(field, valeurs, n=20000):
    v = sorted(valeurs)
    return [{"terms": {field: v[i:i + n]}} for i in range(0, len(v), n)] or [{"terms": {field: ["0.0.0.0"]}}]

def lit_table(nom):
    d = {}
    with open(f"{LOOKUP}/{nom}.csv", encoding="utf-8") as f:
        r = csv.reader(f); next(r)
        for k, v in r:
            p = v.split("|")
            d[k] = {"source": p[0], "type": p[1], "malware": p[2], "conf": p[3], "ports": p[4], "date": p[5], "ref": p[6] if len(p) > 6 else ""}
    return d

def multi(prefix, filtre_base, field, valeurs, sources):
    out = []
    for t in termes(field, valeurs): out += comp(prefix, filtre_base + [t], sources)
    return out

# ======================================================================= REJEU 30 j
def rejeu():
    ip = lit_table("ip"); dom = lit_table("domaine"); uh = lit_table("urlhaus-hote"); uu = lit_table("urlhaus-url"); ha = lit_table("hachage")
    sel = lambda tab, f: {k for k, v in tab.items() if f(v)}
    feodo = sel(ip, lambda v: v["source"] == "feodo"); tor = sel(ip, lambda v: v["source"] == "tor")
    tfip = sel(ip, lambda v: v["source"] in ("threatfox", "urlhaus") and v["conf"] in ("haute", "moyenne"))
    tfdom = sel(dom, lambda v: v["conf"] in ("haute", "moyenne"))
    traffic = [{"term": {"type": "traffic"}}]
    R = {}
    def compte(nom, buckets, cle, fenetre_min, filtre=lambda k: True):
        b = [(k, n) for k, n in buckets if filtre(k)]
        msgs = sum(n for _, n in b)
        # déclenchements estimés = paires distinctes (clé de regroupement, fenêtre)
        trig = len({(k.get(cle), k["t"] // (fenetre_min * 60000)) for k, _ in b})
        cles = {}
        for k, n in b: cles[str(k.get(cle))] = cles.get(str(k.get(cle)), 0) + n
        R[nom] = {"messages": msgs, "declenchements": trig, "cles": len(cles), "top": sorted(cles.items(), key=lambda x: -x[1])[:8]}
        print(f"REJEU {nom}: {msgs} messages, ~{trig} declenchements, {len(cles)} cles ; top {R[nom]['top'][:5]}", flush=True)
    # D1 / D2 Feodo
    b = multi("omni-fortigate", traffic + [{"terms": {"action": AUT}}], "dest_ip", feodo, [T("src_ip"), H("10m")])
    compte("D1 Feodo autorise (CRITIQUE)", b, "src_ip", 10)
    b = multi("omni-fortigate", traffic + [{"terms": {"action": BLOQ}}], "dest_ip", feodo, [T("src_ip"), H("60m")])
    compte("D2 Feodo bloque", b, "src_ip", 60)
    # D3 ThreatFox/URLhaus IP:port même port
    b = multi("omni-fortigate", traffic + [{"terms": {"action": AUT}}], "dest_ip", tfip, [T("dest_ip"), T("dest_port"), T("src_ip"), H("60m")])
    compte("D3 IP:port ThreatFox/URLhaus autorise port identique", b, "src_ip", 60,
           lambda k: k.get("dest_port") is not None and f";{k['dest_port']};" in ip.get(k["dest_ip"], {}).get("ports", ""))
    R["D3 detail"] = sorted({(k["dest_ip"], k["dest_port"], ip[k["dest_ip"]]["malware"]) for k, _ in b if k.get("dest_port") is not None and f";{k['dest_port']};" in ip.get(k["dest_ip"], {}).get("ports", "")})[:20]
    # D4 domaine ThreatFox (FG DNS + Sysmon 22)
    b = multi("omni-fortigate", [{"term": {"subtype": "dns"}}], "qname", tfdom, [T("qname"), H("60m")])
    b2 = multi("omni-sysmon", [{"term": {"winlogbeat_winlog_event_id": "22"}}], "dns_query", tfdom, [T("dns_query"), H("60m")])
    compte("D4 domaine ThreatFox resolu", [({"k": k["qname"], "t": k["t"]}, n) for k, n in b] + [({"k": k["dns_query"], "t": k["t"]}, n) for k, n in b2], "k", 60)
    # D5 URLhaus (DNS, web, ESET)
    hotes = set(uh)
    b = multi("omni-fortigate", [{"term": {"subtype": "dns"}}], "qname", hotes, [T("qname"), H("60m")])
    b += [({"qname": k["hostname"], "t": k["t"]}, n) for k, n in multi("omni-fortigate", [{"term": {"type": "utm"}}], "hostname", hotes, [T("hostname"), H("60m")])]
    b += [({"qname": k["url"], "t": k["t"]}, n) for k, n in multi("omni-fortigate", [{"term": {"type": "utm"}}], "url", set(uu), [T("url"), H("60m")])]
    b += [({"qname": k["dns_query"], "t": k["t"]}, n) for k, n in multi("omni-sysmon", [{"term": {"winlogbeat_winlog_event_id": "22"}}], "dns_query", hotes, [T("dns_query"), H("60m")])]
    e = comp("omni-eset", [{"prefix": {"eset_object_uri": "http"}}], [T("eset_object_uri"), H("60m")])
    for k, n in e:
        u = k.get("eset_object_uri") or ""
        h = (urllib.parse.urlsplit(u).hostname or "").lower() if u else ""
        if u.lower() in uu or h in uh: b.append(({"qname": h or u, "t": k["t"]}, n))
    compte("D5 URLhaus en ligne (DNS/web/ESET)", b, "qname", 60)
    # D6 / D7 hachages
    hs = hachages_vus(set(ha))
    ex = [(x, n) for x, n in hs if x["sha"] in ha and x["ctx"] == "execution"]
    nx = [(x, n) for x, n in hs if x["sha"] in ha and x["ctx"] != "execution"]
    compte("D6 hachage execute (CRITIQUE)", [({"k": x["host"], "t": x["t"]}, n) for x, n in ex], "k", 10)
    compte("D7 hachage hors execution", [({"k": x["sha"], "t": x["t"]}, n) for x, n in nx], "k", 60)
    R["D6/D7 detail"] = sorted({(x["sha"][:16], x["host"], x["ctx"], ha[x["sha"]]["source"], ha[x["sha"]]["malware"]) for x, _ in ex + nx})[:20]
    # D8 / D9 Tor
    b = multi("omni-fortigate", traffic + [{"terms": {"action": AUT}}, {"term": {"src_priv": True}}], "dest_ip", tor, [T("src_ip"), T("dest_port"), H("60m")])
    compte("D8 Tor sortant autorise", b, "src_ip", 60)
    R["D8 ports"] = sorted({str(k.get("dest_port")) for k, _ in b})[:30]
    b = multi("omni-fortigate", traffic + [{"terms": {"action": AUT}}], "src_ip", tor, [T("dest_ip"), T("dest_port"), H("60m")])
    compte("D9 Tor entrant accepte (INFO)", b, "dest_ip", 60)
    R["D9 cibles"] = sorted({(str(k.get("dest_ip")), str(k.get("dest_port"))) for k, _ in b})[:30]
    json.dump(R, open(f"{BASE}/rejeu-{RUN}.json", "w"), indent=1, ensure_ascii=False, default=str)
    print(f"REJEU ecrit : {BASE}/rejeu-{RUN}.json")

def hachages_vus(cibles):
    """Phase 1 : valeurs DISTINCTES de hachage Sysmon (1/7 = exécution ; 6/15/23/26/29 = fichier) et ESET sur la fenêtre,
    comparées localement aux indicateurs ; phase 2 : détail (hôte, jour) des seules valeurs qui correspondent."""
    out = []
    rx = re.compile(r"SHA256=([0-9A-Fa-f]{64})")
    for eids, champ, ctx in ((["1", "7"], "winlogbeat_winlog_event_data_Hashes", "execution"),
                             (["6", "23", "26", "29"], "winlogbeat_winlog_event_data_Hashes", "fichier"),
                             (["15"], "winlogbeat_winlog_event_data_Hash", "fichier")):
        base = [{"terms": {"winlogbeat_winlog_event_id": eids}}, {"exists": {"field": champ}}]
        vus = {}
        for k, n in comp("omni-sysmon", base, [T(champ)], taille=10000, maxb=10**8):
            m = rx.search(k.get(champ) or "")
            if m and m.group(1).lower() in cibles: vus[k[champ]] = m.group(1).lower()
        print(f"hachages {ctx} {eids} : {len(vus)} valeurs distinctes correspondantes", flush=True)
        if vus:
            for k, n in multi("omni-sysmon", base, champ, set(vus), [T(champ), T("source"), H("1d")]):
                out.append(({"sha": vus[k[champ]], "host": k.get("source"), "ctx": ctx, "t": k["t"]}, n))
    for k, n in comp("omni-eset", [{"exists": {"field": "eset_hash"}}], [T("eset_hash"), T("eset_hostname"), H("1d")]):
        if k.get("eset_hash") and k["eset_hash"].lower() in cibles: out.append(({"sha": k["eset_hash"].lower(), "host": k.get("eset_hostname"), "ctx": "eset", "t": k["t"]}, n))
    print(f"hachages correspondants (jour/hote) : {len(out)}", flush=True)
    return out
# ======================================================================= RÉTRO 90 j
def cle():
    return open("/etc/omni-v5-ti/threatfox.key").read().strip()

def cdn_reseaux():
    """Plages publiées des CDN / clouds partagés (qualification « partage CDN »)."""
    nets = []
    def add(lst, nom):
        for c in lst:
            try: nets.append((ipaddress.ip_network(c.strip(), strict=False), nom))
            except ValueError: pass
    CF = "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22".split()
    try: CF = urllib.request.urlopen(urllib.request.Request("https://www.cloudflare.com/ips-v4", headers={"User-Agent": "Mozilla/5.0 omni-siem-ti/5.0"}), timeout=30).read().decode().split() or CF
    except Exception as e: print("cloudflare : liste publiee indisponible, plages connues utilisees", e)
    add(CF, "Cloudflare (CDN)")
    try:
        d = json.loads(urllib.request.urlopen("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=60).read())
        add([p["ip_prefix"] for p in d["prefixes"] if p["service"] == "CLOUDFRONT"], "AWS CloudFront (CDN)")
        add([p["ip_prefix"] for p in d["prefixes"] if p["service"] == "EC2"], "AWS EC2 (cloud, IP reattribuable)")
    except Exception as e: print("aws KO", e)
    try:
        d = json.loads(urllib.request.urlopen("https://www.gstatic.com/ipranges/cloud.json", timeout=60).read())
        add([p.get("ipv4Prefix") for p in d["prefixes"] if p.get("ipv4Prefix")], "Google Cloud (cloud, IP reattribuable)")
        d = json.loads(urllib.request.urlopen("https://www.gstatic.com/ipranges/goog.json", timeout=60).read())
        add([p.get("ipv4Prefix") for p in d["prefixes"] if p.get("ipv4Prefix")], "Google (CDN/services)")
    except Exception as e: print("google KO", e)
    try: add(json.loads(urllib.request.urlopen("https://api.fastly.com/public-ip-list", timeout=30).read())["addresses"], "Fastly (CDN)")
    except Exception as e: print("fastly KO", e)
    print(f"plages CDN/cloud : {len(nets)}")
    return nets

def dans(ip, nets):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return None
    for n, nom in nets:
        if a in n: return nom
    return None

def iocs_retro():
    """Indicateurs pour la rétro : ThreatFox (export complet = 6 mois), URLhaus (export complet = 90 j + en ligne), MalwareBazaar (90 j), Feodo, Tor."""
    IP, DOM, URL, HA = {}, {}, {}, {}
    def put(d, k, v):
        k = k.strip().lower().rstrip(".")
        if k and k not in d: d[k] = v
    fr = json.load(open(f"{STATE}/src/feodo_rec.json"))["rows"]; rec = {r["ip"] for r in fr}
    for r in json.load(open(f"{STATE}/src/feodo.json"))["rows"]:
        put(IP, r["ip"], {"source": "feodo", "type": "c2_botnet", "malware": r["malware"], "conf": "haute" if r["ip"] in rec else ("moyenne" if r["statut"] == "online" else "faible"), "ports": f";{r['port']};", "date": r["first"][:10]})
    for r in json.load(open(f"{STATE}/src/threatfox.json"))["rows"]:
        c = int(r["conf"]) if str(r["conf"]).isdigit() else 0
        conf = "haute" if c >= 90 else ("moyenne" if c >= 75 else "faible")
        base = {"source": "threatfox", "malware": r["malware"], "conf": conf, "date": r["first"][:10], "ref": r["id"]}
        if r["type"] == "ip:port":
            ip, _, port = r["ioc"].rpartition(":")
            if ip in IP and IP[ip]["source"] == "threatfox": IP[ip]["ports"] += f"{port};"
            else: put(IP, ip, {**base, "type": "ip_port", "ports": f";{port};"})
        elif r["type"] == "domain": put(DOM, r["ioc"], {**base, "type": "domaine"})
        elif r["type"] == "url":
            try: h = (urllib.parse.urlsplit(r["ioc"]).hostname or "").lower()
            except ValueError: continue
            put(URL, r["ioc"], {**base, "type": "url"})
            if h and not re.fullmatch(r"[\d.]+", h): put(DOM, h, {**base, "type": "url_hote"})
        elif r["type"].endswith("_hash"): put(HA, r["ioc"], {**base, "type": r["type"].replace("_hash", "")})
    # URLhaus : export complet (90 j + en ligne), téléchargé une fois pour la rétro
    try:
        b = urllib.request.urlopen(urllib.request.Request("https://urlhaus-api.abuse.ch/v2/files/exports/%s/full.csv.zip" % urllib.parse.quote(cle()), headers={"User-Agent": "omni-siem-ti/5.0"}), timeout=300).read()
        z = zipfile.ZipFile(io.BytesIO(b)); t = z.read(z.namelist()[0]).decode("utf-8", "replace")
        n = 0
        for r in csv.reader(io.StringIO("\n".join(l for l in t.splitlines() if not l.startswith("#")))):
            if len(r) < 8: continue
            n += 1
            try: u = urllib.parse.urlsplit(r[2]); h = (u.hostname or "").lower(); port = u.port or (443 if u.scheme == "https" else 80)
            except ValueError: continue
            v = {"source": "urlhaus", "malware": (r[6] or r[5])[:60], "conf": "haute" if r[3] == "online" else "moyenne", "date": r[1][:10], "ref": r[0], "statut": r[3]}
            put(URL, r[2], {**v, "type": "url"})
            if re.fullmatch(r"[\d.]+", h or "x"):
                if h in IP and IP[h]["source"] == "urlhaus": IP[h]["ports"] += f"{port};"
                else: put(IP, h, {**v, "type": "url_ip", "ports": f";{port};"})
            elif h: put(DOM, h, {**v, "type": "url_hote"})
        print(f"URLhaus export complet : {n} URL")
    except Exception as e:
        print("URLhaus complet KO :", str(e).replace(cle(), "<cle>"))
    for r in json.load(open(f"{STATE}/src/malwarebazaar.json"))["rows"]:
        put(HA, r["sha256"], {"source": "malwarebazaar", "type": "sha256", "malware": r["sig"], "conf": "haute", "date": r["first"][:10], "ref": r["type"]})
    for ip in json.load(open(f"{STATE}/src/tor.json"))["rows"]:
        put(IP, ip, {"source": "tor", "type": "tor_sortie", "malware": "Tor exit", "conf": "info", "ports": ";", "date": ""})
    IP = {k: v for k, v in IP.items() if globale(k)}
    print(f"IOC retro : IP {len(IP)}, domaines/hotes {len(DOM)}, URL {len(URL)}, hachages {len(HA)}")
    return IP, DOM, URL, HA

PARTAGE_DNS = re.compile(r"(?i)(^|\.)(microsoft|windows|office|live|azure|msedge|bing|google|gstatic|googleapis|cloudflare|amazonaws|akamai|apple|icloud|github|discord|dropbox|adobe|mozilla|ninjarmm|eset|fortinet|teamviewer)\.")

def globale(v):
    try: return ipaddress.ip_address(v).is_global
    except ValueError: return False

def jour(ms): return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%d")

def retro():
    IP, DOM, URL, HA = iocs_retro()
    nets = cdn_reseaux()
    try: POP = {l.strip() for l in open(f"{STATE}/tranco-top20k.txt") if l.strip()}
    except OSError: POP = set()
    C = []  # correspondances
    # ---- IP sortant / entrant (FortiGate trafic)
    for sens, champ, autre in (("sortant", "dest_ip", "src_ip"), ("entrant", "src_ip", "dest_ip")):
        b = multi("omni-fortigate", [{"term": {"type": "traffic"}}], champ, set(IP), [T(champ), T("dest_port"), T("action"), T(autre), H("1d")])
        agg = {}
        for k, n in b:
            ioc = k[champ]
            if sens == "sortant" and IP[ioc]["source"] == "tor" and not str(k.get(autre) or "").startswith(("10.", "192.168.", "172.")):
                continue
            a = agg.setdefault(ioc, {"n": 0, "act": {}, "ports": {}, "hotes": {}, "j": set()})
            a["n"] += n; a["act"][k["action"]] = a["act"].get(k["action"], 0) + n
            a["ports"][str(k.get("dest_port"))] = a["ports"].get(str(k.get("dest_port")), 0) + n
            a["hotes"][str(k.get(autre))] = a["hotes"].get(str(k.get(autre)), 0) + n; a["j"].add(jour(k["t"]))
        print(f"IP {sens} : {len(agg)} indicateurs vus", flush=True)
        for ioc, a in agg.items():
            C.append({"kind": "ip", "sens": sens, "ioc": ioc, **{f"i_{x}": y for x, y in IP[ioc].items()}, **a})
    # ---- domaines : DNS FortiGate, Sysmon 22, web FortiGate
    for prefix, filtre, champ, hote in (("omni-fortigate", [{"term": {"subtype": "dns"}}], "qname", "src_ip"),
                                        ("omni-sysmon", [{"term": {"winlogbeat_winlog_event_id": "22"}}], "dns_query", "source"),
                                        ("omni-fortigate", [{"term": {"type": "utm"}}, {"bool": {"must_not": [{"term": {"subtype": "dns"}}]}}], "hostname", "src_ip")):
        b = multi(prefix, filtre, champ, set(DOM), [T(champ), T(hote), T("action") if prefix == "omni-fortigate" else T("winlogbeat_winlog_event_data_Image"), H("1d")])
        agg = {}
        for k, n in b:
            ioc = (k[champ] or "").lower()
            if ioc not in DOM: continue
            a = agg.setdefault(ioc, {"n": 0, "act": {}, "ports": {}, "hotes": {}, "j": set(), "proc": {}})
            a["n"] += n; a["hotes"][str(k.get(hote))] = a["hotes"].get(str(k.get(hote)), 0) + n; a["j"].add(jour(k["t"]))
            if "action" in k: a["act"][str(k["action"])] = a["act"].get(str(k["action"]), 0) + n
            else: a["proc"][str(k.get("winlogbeat_winlog_event_data_Image"))] = a["proc"].get(str(k.get("winlogbeat_winlog_event_data_Image")), 0) + n
        print(f"domaines {prefix}/{champ} : {len(agg)} vus", flush=True)
        for ioc, a in agg.items():
            C.append({"kind": "domaine", "sens": champ, "ioc": ioc, **{f"i_{x}": y for x, y in DOM[ioc].items()}, **a})
    # ---- URL exactes (FortiGate url, ESET)
    b = multi("omni-fortigate", [{"term": {"type": "utm"}}], "url", set(URL), [T("url"), T("src_ip"), T("action"), H("1d")])
    for k, n in comp("omni-eset", [{"prefix": {"eset_object_uri": "http"}}], [T("eset_object_uri"), T("eset_hostname"), H("1d")]):
        u = (k.get("eset_object_uri") or "").lower(); h = (urllib.parse.urlsplit(u).hostname or "") if u else ""
        if u in URL: b.append(({"url": u, "src_ip": k.get("eset_hostname"), "action": "eset", "t": k["t"]}, n))
        elif h in DOM: C.append({"kind": "domaine", "sens": "eset_object_uri", "ioc": h, **{f"i_{x}": y for x, y in DOM[h].items()}, "n": n, "act": {"eset": n}, "ports": {}, "hotes": {str(k.get("eset_hostname")): n}, "j": {jour(k["t"])}})
    agg = {}
    for k, n in b:
        ioc = (k.get("url") or "").lower()
        if ioc not in URL: continue
        a = agg.setdefault(ioc, {"n": 0, "act": {}, "ports": {}, "hotes": {}, "j": set()})
        a["n"] += n; a["act"][str(k.get("action"))] = a["act"].get(str(k.get("action")), 0) + n; a["hotes"][str(k.get("src_ip"))] = a["hotes"].get(str(k.get("src_ip")), 0) + n; a["j"].add(jour(k["t"]))
    for ioc, a in agg.items(): C.append({"kind": "url", "sens": "url", "ioc": ioc, **{f"i_{x}": y for x, y in URL[ioc].items()}, **a})
    # ---- hachages
    for x, n in hachages_vus(set(HA)):
        if x["sha"] in HA:
            C.append({"kind": "hachage", "sens": x["ctx"], "ioc": x["sha"], **{f"i_{k}": v for k, v in HA[x["sha"]].items()}, "n": n, "act": {x["ctx"]: n}, "ports": {}, "hotes": {str(x["host"]): n}, "j": {jour(x["t"])}})
    # fusion des hachages (même ioc / contexte)
    F = {}
    for c in C:
        key = (c["kind"], c["sens"], c["ioc"])
        if key not in F: F[key] = c; continue
        f = F[key]; f["n"] += c["n"]; f["j"] |= c["j"]
        for d in ("act", "ports", "hotes"):
            for k, v in c[d].items(): f[d][k] = f[d].get(k, 0) + v
    C = list(F.values())
    # ---- noms DNS associés aux IP sortantes autorisées (partage CDN / hébergement mutualisé)
    for c in C:
        if c["kind"] == "ip" and c["sens"] == "sortant" and any(a in AUT for a in c["act"]) and c["i_source"] != "tor":
            r = osq("/omni-fortigate_*/_search", {"size": 0, "query": {"bool": {"filter": [{"term": {"subtype": "dns"}}, {"term": {"ipaddr": c["ioc"]}},
                    {"range": {"timestamp": {"gte": DEBUT.strftime("%Y-%m-%d %H:%M:%S.000")}}}]}}, "aggs": {"q": {"terms": {"field": "qname", "size": 5}}}})
            c["dns"] = {b["key"]: b["doc_count"] for b in r["aggregations"]["q"]["buckets"]}
    # ---- qualification
    for c in C:
        c["cdn"] = dans(c["ioc"], nets) if c["kind"] == "ip" else None
        acts = set(c["act"]); aut = any(a in AUT for a in acts) or bool(acts & {"pass", "passthrough", "execution", "fichier", "eset"}) or c["kind"] == "domaine" and not acts
        bloque = acts and acts <= set(BLOQ + ["block", "blocked", "redirect"])
        d_ioc = c.get("i_date") or ""
        j = sorted(c["j"]); c["premier"], c["dernier"] = j[0], j[-1]
        avant = bool(d_ioc) and c["dernier"] < d_ioc
        port_ok = None
        if c["kind"] == "ip" and c["sens"] == "sortant" and c.get("i_ports", ";") != ";":
            port_ok = any(f";{p};" in c["i_ports"] for p in c["ports"])
        dns_leg = [q for q in (c.get("dns") or {}) if PARTAGE_DNS.search(q + ".")]
        v = None
        if c["i_source"] == "tor":
            v = ("tor_entrant_bloque" if bloque else "tor_entrant_accepte (service publie)") if c["sens"] == "entrant" else ("tor_sortant_bloque" if bloque else "tor_sortant_autorise - a verifier")
        elif bloque: v = "bloque par le FortiGate (aucun echange)"
        elif c["kind"] == "hachage":
            v = "VRAI POSITIF probable - hachage execute" if c["sens"] == "execution" else ("deja traite par ESET" if c["sens"] == "eset" else "fichier vu - a verifier")
        elif c["kind"] in ("domaine",) and (c["ioc"] in POP or (c["ioc"].startswith("www.") and c["ioc"][4:] in POP)):
            v = "plateforme populaire abusee (Tranco top 20k) - faux positif DNS probable, exclue des tables"
        elif c["cdn"] and "CDN" in c["cdn"]: v = f"partage CDN ({c['cdn']}) - faux positif probable"
        elif dns_leg: v = f"hebergement partage (resolu comme {dns_leg[0]}) - faux positif probable"
        elif avant: v = "trafic anterieur a la publication de l'IOC - faible"
        elif port_ok is False: v = "port different de l'IOC (hebergement partage probable) - faible"
        elif c["kind"] == "ip" and c["sens"] == "entrant": v = "entrant depuis une IP malveillante (" + ("accepte" if aut else "?") + ")"
        elif c["cdn"]: v = f"autorise vers {c['cdn']} - a investiguer"
        else: v = "autorise - A INVESTIGUER"
        c["verdict"] = v
    C.sort(key=lambda c: (0 if "INVESTIGUER" in c["verdict"] or "VRAI" in c["verdict"] else 1 if c["i_source"] != "tor" else 2, -c["n"]))
    # ---- sorties
    out = []
    for c in C:
        out.append({"kind": c["kind"], "sens": c["sens"], "ioc": c["ioc"], "source": c["i_source"], "type": c["i_type"], "malware": c.get("i_malware"),
                    "confiance": c.get("i_conf"), "ioc_date": c.get("i_date"), "ports_ioc": c.get("i_ports"), "n": c["n"], "premier": c["premier"], "dernier": c["dernier"],
                    "jours": len(c["j"]), "actions": c["act"], "ports": dict(sorted(c["ports"].items(), key=lambda x: -x[1])[:5]),
                    "hotes": dict(sorted(c["hotes"].items(), key=lambda x: -x[1])[:5]), "proc": dict(sorted((c.get("proc") or {}).items(), key=lambda x: -x[1])[:3]),
                    "dns": c.get("dns"), "cdn": c["cdn"], "verdict": c["verdict"]})
    json.dump(out, open(f"{BASE}/retro-{RUN}.json", "w"), indent=1, ensure_ascii=False)
    resume = {}
    for o in out:
        k = (o["source"], o["kind"], o["verdict"].split(" (")[0].split(" - ")[0]); resume[k] = resume.get(k, 0) + 1
    print("RESUME", json.dumps({" / ".join(k): v for k, v in sorted(resume.items())}, ensure_ascii=False, indent=0))
    print(f"RETRO {len(out)} correspondances ; ecrit {BASE}/retro-{RUN}.json")
    if "--gelf" in ARGS:
        # Tor : une ligne par IP pour les accepts / sortants, résumé pour les entrants bloqués (bruit Internet)
        env = 0; tor_bloq = [o for o in out if o["verdict"] == "tor_entrant_bloque"]
        for o in out:
            if o["verdict"] == "tor_entrant_bloque": continue
            gelf({"short_message": f"OMNI v5 TI retro {JOURS} j : {o['source']} {o['kind']} {o['ioc'][:80]} -> {o['verdict']}", "_event_source": "ti_retro", "_ti_retro_run": RUN,
                  "_ti_match": o["ioc"][:200], "_ti_source": o["source"], "_ti_type": o["type"], "_ti_malware": str(o["malware"])[:80], "_ti_confiance": o["confiance"],
                  "_ti_retro_sens": o["sens"], "_ti_retro_verdict": o["verdict"], "_ti_retro_n": o["n"], "_ti_retro_premier": o["premier"], "_ti_retro_dernier": o["dernier"],
                  "_ti_retro_actions": json.dumps(o["actions"]), "_ti_retro_hotes": json.dumps(o["hotes"]), "_ti_retro_ports": json.dumps(o["ports"]),
                  "_ti_retro_dns": json.dumps(o["dns"] or {}), "_ti_retro_cdn": o["cdn"] or "", "_ti_ioc_date": o["ioc_date"], "level": 5}); env += 1
        if tor_bloq:
            gelf({"short_message": f"OMNI v5 TI retro {JOURS} j : {len(tor_bloq)} noeuds Tor en entrant BLOQUE ({sum(o['n'] for o in tor_bloq)} sessions)", "_event_source": "ti_retro",
                  "_ti_retro_run": RUN, "_ti_source": "tor", "_ti_retro_verdict": "tor_entrant_bloque (resume)", "_ti_retro_n": sum(o["n"] for o in tor_bloq), "level": 6}); env += 1
        print(f"GELF ti_retro emis : {env}")

def gelf(m):
    m = {"version": "1.1", "host": socket.gethostname(), **m}
    urllib.request.urlopen(urllib.request.Request(GELF, data=json.dumps(m).encode(), headers={"Content-Type": "application/json"}), timeout=10).read()

if __name__ == "__main__":
    t0 = time.time()
    if MODE == "--rejeu": rejeu()
    elif MODE == "--retro": retro()
    else: sys.exit(__doc__)
    print(f"duree {round(time.time() - t0)} s")
