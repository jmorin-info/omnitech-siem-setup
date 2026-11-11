#!/usr/bin/env python3
"""Réparation ciblée des widgets de dashboards Graylog qui pointent sur des champs inexistants (OMNITECH 11/11/2026).
Usage (root, sur BX-IT-GRAYLOG-VM) : set -a; . /root/omnitech-siem-setup/00-vars.env; set +a; python3 reparer-widgets-20261111.py [--appliquer]
Sans --appliquer : simulation (affiche les remplacements). Sauvegardes : /var/backups/siem/dashboards-avant-20261111/<view_id>.json
Retour : retour-dashboards-20261111.py (remet search + state d'origine)."""
import sys, json, os, ssl, base64, secrets, urllib.request, re, copy

APPLIQUER = "--appliquer" in sys.argv
CTX = ssl._create_unverified_context()
AUTH = base64.b64encode(("admin:" + os.environ["GRAYLOG_ADMIN_PASS"]).encode()).decode()
API = "https://127.0.0.1:9000/api"
B = "/var/backups/siem/dashboards-avant-20261111"

def call(methode, chemin, corps=None):
    data = json.dumps(corps).encode() if corps is not None else None
    r = urllib.request.Request(API + chemin, data=data, method=methode, headers={
        "Authorization": "Basic " + AUTH, "Accept": "application/json",
        "Content-Type": "application/json", "X-Requested-By": "oms-dashboards"})
    try:
        with urllib.request.urlopen(r, context=CTX) as rep:
            t = rep.read()
            return json.loads(t) if t else None
    except urllib.error.HTTPError as e:
        raise SystemExit(f"ERREUR {methode} {chemin} : {e.code} {e.read().decode(errors='replace')[:800]}")

# dashboard -> { widget_id: {"champs": {ancien: nouveau}, "requete": [(ancien, nouveau)], "titre": nouveau titre ou None} }
CORRECTIFS = {
    "OMNI - Triage & Multi-site": {
        "4104d683-446a-49b0-8a56-950ee84bbd35": {"champs": {"srcip": "src_ip"}},
    },
    "OMNI - SOC": {
        "99df9bd8-f548-493b-a4c5-52b04fbc15fb": {"champs": {"_entities": "entities", "_mitre": "mitre", "_tactic": "tactic", "_signals": "signals"}},
        "6036b35f-7a77-4d48-880c-59fe32201279": {"champs": {"fwd_target": "deleg_target"}},
        "44b202b7-5558-40e7-b507-920c82063469": {"champs": {"cert_template": "winlogbeat_winlog_event_data_CertificateTemplate"}},
    },
    "SEAL - SOC operationnel": {
        "51c6e49d-f54a-4bc6-805e-fd1230bb8ac0": {"champs": {"event_definition_title": "event_definition_id"}},  # pivot : message (texte) non agrégeable
        "b451b4b1-8a09-4835-85fc-5222096e3963": {"champs": {"event_definition_title": "message"}},
    },
    "SEAL - Vue multi-site": {
        "4877b23f-da08-41c1-a41a-7fb8dac124dd": {"champs": {"seal_zone": "target_object_id"},
            "requete": [("_exists_:seal_zone", "_exists_:target_object_id")],
            "titre": ("par zone", "par porte / objet SEAL")},
        "cee8490d-8872-4b02-a4be-22ac0d050ed5": {"champs": {"seal_zone": "target_object_id"},
            "requete": [("_exists_:seal_zone", "_exists_:target_object_id")],
            "titre": ("par zone", "par porte / objet SEAL")},
    },
}

def remplacer(obj, champs, requete):
    """Remplace les noms de champs (valeurs exactes, ou dans une fonction de série) et les fragments de requête."""
    n = 0
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str):
                nv = v
                if k == "field" and v in champs:
                    nv = champs[v]
                m = re.fullmatch(r"(\w+)\(([^)]*)\)", v)
                if m and m.group(2) in champs:
                    nv = f"{m.group(1)}({champs[m.group(2)]})"
                if k == "query_string":
                    for a, b in requete:
                        nv = nv.replace(a, b)
                if nv != v:
                    obj[k] = nv; n += 1
            elif isinstance(v, list) and k in ("fields", "selected_fields") :
                nl = [champs.get(x, x) if isinstance(x, str) else x for x in v]
                if nl != v:
                    obj[k] = nl; n += 1
                for x in v:
                    if not isinstance(x, str): n += remplacer(x, champs, requete)
            else:
                n += remplacer(v, champs, requete)
    elif isinstance(obj, list):
        for x in obj:
            n += remplacer(x, champs, requete)
    return n

journal = []
for fic in sorted(os.listdir(B)):
    if not re.fullmatch(r"[0-9a-f]{24}\.json", fic):
        continue
    d = json.load(open(os.path.join(B, fic)))
    vue, recherche = copy.deepcopy(d["view"]), copy.deepcopy(d["search"])
    corr = CORRECTIFS.get(vue["title"])
    if not corr:
        continue
    total = 0
    for qid, st in vue["state"].items():
        for w in st["widgets"]:
            c = corr.get(w["id"])
            if not c:
                continue
            champs, requete = c.get("champs", {}), c.get("requete", [])
            n = remplacer(w, champs, requete)
            for stid in st["widget_mapping"].get(w["id"], []):
                for q in recherche["queries"]:
                    for s in q["search_types"]:
                        if s["id"] == stid:
                            n += remplacer(s, champs, requete)
            if c.get("titre"):
                t = st.get("titles", {}).get("widget", {}).get(w["id"])
                if t and c["titre"][0] in t:
                    st["titles"]["widget"][w["id"]] = t.replace(*c["titre"]); n += 1
            journal.append(f"{vue['title']} | widget {w['id']} | {n} remplacement(s) {champs}")
            total += n
    if not total:
        continue
    if APPLIQUER:
        recherche["id"] = secrets.token_hex(12)
        recherche.pop("owner", None); recherche.pop("created_at", None)
        nouvelle = call("POST", "/views/search", recherche)
        vue["search_id"] = nouvelle["id"]
        for k in ("owner", "created_at", "last_updated_at", "favorite"):
            vue.pop(k, None)
        call("PUT", "/views/" + vue["id"], {"entity": vue})   # Graylog 7 : CreateEntityRequest
        journal.append(f"  -> {vue['title']} mis à jour (nouvelle recherche {nouvelle['id']})")
print("\n".join(journal))
print("MODE :", "APPLIQUÉ" if APPLIQUER else "SIMULATION")
