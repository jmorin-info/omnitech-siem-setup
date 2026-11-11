#!/usr/bin/env python3
# Simulation des gains v1+v2 sur les VRAIES decisions de tri des 30 derniers jours (lecture seule).
# Rejoue : FP v2 par signature (entite/titre), recapitulatif v1 (4 heuristiques) + admin connu v2, dedup 24 h zone grise,
# plafond de tempete 3/h, puis regroupement horaire des ELEVE (v2). CRITIQUE et kill-chain : toujours mail immediat.
import json, re, urllib.request, collections, datetime
URL = "http://127.0.0.1:9200/omni-m365*,omni-interne*/_search"
def post(u, b): return json.load(urllib.request.urlopen(urllib.request.Request(u, data=json.dumps(b).encode(), headers={"Content-Type": "application/json"}), timeout=180))
b = {"size": 5000, "_source": ["timestamp", "alert_title", "triage_entity", "triage_tier", "triage_reason"], "query": {"bool": {"filter": [
     {"term": {"event_source": "alert_triage"}}, {"terms": {"triage_decision": ["mail", "dedup"]}}, {"range": {"timestamp": {"gte": "now-30d"}}}]}}}
r = post(URL + "?scroll=2m", b); sid = r["_scroll_id"]; rows = [h["_source"] for h in r["hits"]["hits"]]
while True:
    r = post("http://127.0.0.1:9200/_search/scroll", {"scroll": "2m", "scroll_id": sid}); h = r["hits"]["hits"]
    if not h: break
    rows += [x["_source"] for x in h]; sid = r["_scroll_id"]
mails = [x for x in rows if x.get("triage_reason") and "dedup" not in x["triage_reason"]]
mails.sort(key=lambda x: x["timestamp"])
DIGEST_V1 = re.compile(r"Exfiltration par volume|Service exposé sur Internet|Reconnaissance LDAP|Anomalie de volume", re.I)
# FP v2 : (motif de titre, fonction entite -> True si l'alerte est couverte par une signature)
FP = [
    (r"Tâche planifiée à charge offensive", lambda e: True),
    (r"Zerologon suspecté", lambda e: True),
    (r"Indicateur de ransomware", lambda e: True),
    (r"Accès mémoire LSASS", lambda e: True),
    (r"Injection de processus", lambda e: re.search(r"BX-DEV-TCA", e or "") is not None),
    (r"archiveur ou Outlook", lambda e: True),
    (r"Arrêt service de sécurité", lambda e: "VEEAM" not in (e or "").upper()),
    (r"Tunneling DNS", lambda e: True),
    (r"Login admin hors segment", lambda e: "10.33.50.250" in (e or "")),
    (r"Force brute SUIVIE", lambda e: (e or "").endswith("=jmorin")),
    (r"Usage de credentials explicites", lambda e: (e or "") == "jmorin"),
    (r"Balayage de partages admin", lambda e: "gMSA" in (e or "")),
    (r"Web shell", lambda e: "IV-TECH-FFE" in (e or "")),
]
ADMIN = [(r"Modification de GPO par un humain", r"^user=adm-jmorin$"), (r"Mouvement latéral réussi", r"^adm-jmorin$")]
crit, lot, recap, fp, dd, burst = [], [], 0, collections.Counter(), {}, collections.defaultdict(list)
for x in mails:
    t, e, tier, rs = x.get("alert_title", ""), x.get("triage_entity", ""), x.get("triage_tier", ""), x.get("triage_reason", "")
    ts = datetime.datetime.fromisoformat(x["timestamp"].replace(" ", "T")[:19]).timestamp()
    if any(re.search(p, t) and f(e) for p, f in FP):
        fp[t] += 1; continue
    if tier == "CRITICAL" or "killchain" in rs:
        crit.append(ts); continue
    if DIGEST_V1.search(t) or any(re.search(a, t) and re.search(b_, e or "") for a, b_ in ADMIN):
        recap += 1; continue
    k = t + "|" + (e or "")
    if k in dd and ts - dd[k] < 86400: continue
    bk = [y for y in burst[t] if ts - y < 3600]
    if len(bk) >= 3: recap += 1; dd[k] = ts; continue
    burst[t] = bk + [ts]; dd[k] = ts; lot.append(ts)
jours = 30
heures_lot = len({int(y // 3600) for y in lot})
print(f"Mails reels sur 30 j (hors dedup) : {len(mails)}  ({len(mails)/jours:.0f}/jour)")
print(f"Faux positifs supprimes par signature v2 : {sum(fp.values())}")
for t, n in fp.most_common(): print(f"   {n:4d}  {re.sub(r'^OMNI - ', '', t)}")
print(f"Vers le recapitulatif (heuristiques, admin connu, tempetes) : {recap}")
print(f"CRITIQUE / kill-chain (mail immediat, inchanges) : {len(crit)}  ({len(crit)/jours:.1f}/jour)")
print(f"ELEVE restants : {len(lot)} alertes, regroupees en {heures_lot} mails horaires ({heures_lot/jours:.1f}/jour)")
print(f"=> mails recus/jour : {(len(crit)+heures_lot)/jours:.1f} (+1 recapitulatif quotidien) au lieu de {len(mails)/jours:.0f}")
pj = collections.Counter(datetime.date.fromtimestamp(y) for y in crit) + collections.Counter(datetime.date.fromtimestamp(h * 3600) for h in {int(y // 3600) for y in lot})
print(f"pic journalier apres v2 : {max(pj.values()) if pj else 0}")
