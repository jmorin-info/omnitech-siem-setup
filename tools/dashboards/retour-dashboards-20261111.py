#!/usr/bin/env python3
"""Retour arrière des dashboards Graylog modifiés le 11/11/2026 (OMNITECH).
Remet la recherche et l'état d'origine depuis /var/backups/siem/dashboards-avant-20261111/<view_id>.json,
et supprime les dashboards créés ce jour (titres listés dans NOUVEAUX) si --supprimer-nouveaux est passé.
Usage (root) : set -a; . /root/omnitech-siem-setup/00-vars.env; set +a; python3 retour-dashboards-20261111.py [--supprimer-nouveaux]"""
import sys, json, os, ssl, base64, secrets, urllib.request, re
CTX = ssl._create_unverified_context()
AUTH = base64.b64encode(("admin:" + os.environ["GRAYLOG_ADMIN_PASS"]).encode()).decode()
API = "https://127.0.0.1:9000/api"
B = "/var/backups/siem/dashboards-avant-20261111"
NOUVEAUX = ["OMNI - Vue SOC direction", "OMNI - Identités et AD", "OMNI - Réseau FortiGate VPN", "OMNI - Santé du SIEM"]

def call(m, p, c=None):
    r = urllib.request.Request(API + p, data=json.dumps(c).encode() if c is not None else None, method=m, headers={
        "Authorization": "Basic " + AUTH, "Accept": "application/json", "Content-Type": "application/json", "X-Requested-By": "oms-retour"})
    with urllib.request.urlopen(r, context=CTX) as rep:
        t = rep.read(); return json.loads(t) if t else None

for fic in sorted(os.listdir(B)):
    if not re.fullmatch(r"[0-9a-f]{24}\.json", fic):
        continue
    d = json.load(open(os.path.join(B, fic)))
    vue, recherche = d["view"], d["search"]
    actuelle = call("GET", "/views/" + vue["id"])
    if actuelle["search_id"] == recherche["id"]:
        continue  # jamais modifié
    recherche["id"] = secrets.token_hex(12)
    for k in ("owner", "created_at"): recherche.pop(k, None)
    nouvelle = call("POST", "/views/search", recherche)
    vue["search_id"] = nouvelle["id"]
    for k in ("owner", "created_at", "last_updated_at", "favorite"): vue.pop(k, None)
    call("PUT", "/views/" + vue["id"], {"entity": vue})   # Graylog 7 : CreateEntityRequest
    print("restauré :", vue["title"])
if "--supprimer-nouveaux" in sys.argv:
    for v in call("GET", "/views?per_page=200")["views"]:
        if v["title"] in NOUVEAUX:
            call("DELETE", "/views/" + v["id"]); print("supprimé :", v["title"])
