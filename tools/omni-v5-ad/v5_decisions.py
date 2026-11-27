#!/usr/bin/env python3
# SIEM v5 chantier 1 - décisions jmorin du 27/11 (points 1 et 3), appliquées le 27/11/2026. Aucun secret affiché.
# Version publiée : l'examen en lecture seule d'un poste nominatif est retiré ; le compte Entra Connect vient de
# site.json (v5_ad_build) ; les identifiants de définitions sont ceux de l'instance d'origine (à adapter).
#   --preparer : sauvegarde JSON par ID, rejeu 30 j avant/après
#   --appliquer <dossier> : applique (définitions M365 élargies retenues, règles DCSync/Shadow, requêtes v5), à partir du plan
#   --retour <dossier> : remet chaque objet sauvegardé PAR ID
import collections, json, os, re, sys, time
sys.path.insert(0, "/root/omni-v5-ad")
sys.argv, _a = [sys.argv[0], "--test"], sys.argv
import v5_ad_build as b
from v5_lib import api, osq, total
ARGS = _a[1:]
M365_DEFS = {"6a2ad54465bc77613c83fc50": "transfert", "6a2ad54465bc77613c83fc5b": "delegation", "6a403ddbb5993e874b5db2e4": "mfa_fatigue", "6a2ac4a265bc77613c83b27a": "force_brute"}
REGLES = ["omni-winsec-10-dcsync", "omni-l4-10-shadow-credentials"]
V5_DEFS = {"OMNI v5 - M365 Transfert de messagerie vers une adresse externe": " AND NOT alert_tag:m365_mail_forward",
           "OMNI v5 - M365 Rafale de défis MFA (fatigue MFA)": " AND NOT m365_fail_code:500121"}

def nouvelle_regle(n, s):
    if n == "omni-winsec-10-dcsync":
        s2 = s.replace("89e95b76-6a76-11d0-97d5-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
        s2 = re.sub(r'AND NOT starts_with\(to_string\(\$message\.winlogbeat_winlog_event_data_SubjectUserName\), "MSOL_", true\)',
                    f'AND lowercase(to_string($message.winlogbeat_winlog_event_data_SubjectUserName)) != "{b.ENTRA}"', s2)
    else:
        s2 = re.sub(r'AND NOT starts_with\(to_string\(\$message\.winlogbeat_winlog_event_data_SubjectUserName\), "MSOL_", true\)',
                    f'AND lowercase(to_string($message.winlogbeat_winlog_event_data_SubjectUserName)) != "{b.ENTRA}"', s)
    return "// v5 27/11/2026 (decision jmorin) : compte Entra Connect exact au lieu de MSOL_* ; GUID In-Filtered-Set corrige.\n" + s2 if s2 != s else s

def nouvelle_def(d):
    c = d["config"]; gb = c.get("group_by") or ["user"]
    seuil = 1
    try: seuil = c["conditions"]["expression"]["right"]["value"]
    except Exception: pass
    c.update({"group_by": gb, "series": c.get("series") or [{"type": "count", "id": "count()", "field": None}],
              "conditions": c.get("conditions") if (c.get("conditions") or {}).get("expression") else
              {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"}, "right": {"expr": "number", "value": seuil}}},
              "search_within_ms": 300 * 60000, "execute_every_ms": 15 * 60000})
    d["notification_settings"]["grace_period_ms"] = max(d["notification_settings"].get("grace_period_ms") or 0, 300 * 60000)
    return d

def ent(gb): return lambda x: tuple(str(x.get(f)) for f in gb) if gb else ("*",)

def rejeu_def(d, apres):
    c = d["config"]; q = c["query"]
    gb = (c.get("group_by") or ["user"]) if apres else (c.get("group_by") or [])
    try: seuil = c["conditions"]["expression"]["right"]["value"]
    except Exception: seuil = 1
    fen, ev = (300, 15) if apres else (c["search_within_ms"] // 60000, c["execute_every_ms"] // 60000)
    grace = max((d["notification_settings"].get("grace_period_ms") or 0) // 60000, 300) if apres else (d["notification_settings"].get("grace_period_ms") or 0) // 60000
    docs = b.fetch("omni-m365_*", {"query_string": {"query": q}}, ["timestamp", "gl2_receive_timestamp"] + gb + ["user"])
    if not c.get("series"):  # définition « filtre » : un événement par message et par passage
        n_ev, n_no, pj = b.ordonnance(docs, lambda x: x.get("timestamp") + str(id(x)), 1, fen, ev, grace) if not apres else b.ordonnance(docs, ent(gb), 1, fen, ev, grace)
    else:
        n_ev, n_no, pj = b.ordonnance(docs, ent(gb), seuil, fen, ev, grace)
    return {"messages": len(docs), "fenetre": fen, "pas": ev, "grace": grace, "group_by": gb, "seuil": seuil, "evenements": n_ev, "notifications_30j": n_no, "max_par_jour": max(pj.values()) if pj else 0, "par_jour": pj}

def preparer():
    ts = time.strftime("%Y%m%d-%H%M"); dossier = f"/var/backups/siem/v5-ad-decisions-{ts}"; os.makedirs(dossier, mode=0o700)
    plan = {"dossier": dossier, "definitions": {}, "regles": {}, "v5": {}}
    for i, nom in M365_DEFS.items():
        d = api("GET", f"/events/definitions/{i}"); json.dump(d, open(f"{dossier}/definition-{i}.json", "w"), indent=1, ensure_ascii=False)
        av, ap = rejeu_def(json.loads(json.dumps(d)), False), rejeu_def(json.loads(json.dumps(d)), True)
        retenu = ap["max_par_jour"] <= 2
        plan["definitions"][i] = {"nom": nom, "titre": d["title"], "avant": av, "apres": ap, "elargir": retenu}
        print(f"[{nom}] {d['title']}\n   avant : W={av['fenetre']} pas={av['pas']} gb={av['group_by']} seuil={av['seuil']} msgs={av['messages']} notif30j={av['notifications_30j']} max/j={av['max_par_jour']}"
              f"\n   apres : W=300 pas=15 gb={ap['group_by']} notif30j={ap['notifications_30j']} max/j={ap['max_par_jour']} jours={ap['par_jour']} -> {'ELARGIR' if retenu else 'NE PAS ELARGIR (>2/j)'}")
    rules = {r["title"]: r for r in api("GET", "/system/pipelines/rule")}
    for n in REGLES:
        r = rules[n]; json.dump(r, open(f"{dossier}/regle-{r['id']}.json", "w"), indent=1, ensure_ascii=False)
        s2 = nouvelle_regle(n, r["source"]); api("POST", "/system/pipelines/rule/parse", {"title": n, "description": "", "source": s2})
        plan["regles"][r["id"]] = {"titre": n, "modifiee": s2 != r["source"]}
        print(f"[regle] {n} modifiee={s2 != r['source']} (syntaxe OK)")
    edefs = {d["title"]: d for d in api("GET", "/events/definitions?per_page=1000")["event_definitions"]}
    for t in V5_DEFS:
        d = edefs[t]; json.dump(d, open(f"{dossier}/definition-{d['id']}.json", "w"), indent=1, ensure_ascii=False); plan["v5"][d["id"]] = t
    # rejeu règles avant/après (sujets des 4662 de réplication, écritures msDS-KeyCredentialLink)
    r = osq("/omni-winsec_*/_search", {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-30d"}}}, {"term": {"winlogbeat_winlog_event_id": "4662"}},
            {"query_string": {"query": "winlogbeat_winlog_event_data_Properties:(*1131f6aa* OR *1131f6ad* OR *89e95b76*)"}}]}}, "aggs": {"s": {"terms": {"field": "winlogbeat_winlog_event_data_SubjectUserName", "size": 100}}}})
    subj = [(x["key"], x["doc_count"]) for x in r["aggregations"]["s"]["buckets"]]
    av = sum(c for s, c in subj if not s.endswith("$") and not s.upper().startswith("MSOL_")); ap = sum(c for s, c in subj if not s.endswith("$") and s.lower() != b.ENTRA)
    sh = b.fetch("omni-winsec_*", {"query_string": {"query": "winlogbeat_winlog_event_id:5136 AND winlogbeat_winlog_event_data_AttributeLDAPDisplayName:msDS-KeyCredentialLink"}}, b.WF)
    sav = sum(1 for x in sh if b.g(x, "SubjectUserSid") != "S-1-5-18" and not b.g(x, "SubjectUserName").upper().startswith("MSOL_"))
    sap = sum(1 for x in sh if b.g(x, "SubjectUserSid") != "S-1-5-18" and b.g(x, "SubjectUserName").lower() != b.ENTRA)
    plan["rejeu_regles"] = {"dcsync_sujets": subj, "dcsync_avant": av, "dcsync_apres": ap, "shadow_avant": sav, "shadow_apres": sap}
    print(f"[rejeu regles 30 j] DCSync sujets={subj} -> declenchements avant={av} apres={ap} ; Shadow avant={sav} apres={sap}")
    json.dump(plan, open(f"{dossier}/plan.json", "w"), indent=1, ensure_ascii=False)
    with open(f"{dossier}/retour.sh", "w") as f:
        f.write(f"#!/bin/bash\n# Retour decisions 27/11 (chantier 1) : remet PAR ID les objets sauvegardes dans ce dossier.\ncd /root/omni-v5-ad && python3 -I v5_decisions.py --retour {dossier}\n")
    os.chmod(f"{dossier}/retour.sh", 0o700)
    print(f"PLAN {dossier}")

def put_def(d, sched):
    d = {k: v for k, v in d.items() if k not in ("_scope", "matched_at", "updated_at")}
    try: return api("PUT", f"/events/definitions/{d['id']}?schedule={'true' if sched else 'false'}", {"entity": d})
    except RuntimeError: return api("PUT", f"/events/definitions/{d['id']}?schedule={'true' if sched else 'false'}", d)

def appliquer(dossier):
    plan = json.load(open(f"{dossier}/plan.json"))
    for i, p in plan["definitions"].items():
        if not p["elargir"]: print(f"non elargie : {p['titre']}"); continue
        d = api("GET", f"/events/definitions/{i}"); put_def(nouvelle_def(d), d.get("state") == "ENABLED"); print(f"elargie : {i} {p['titre']}")
    rules = {r["id"]: r for r in api("GET", "/system/pipelines/rule")}
    for i, p in plan["regles"].items():
        r = rules[i]; s2 = nouvelle_regle(r["title"], r["source"])
        if s2 != r["source"]: api("PUT", f"/system/pipelines/rule/{i}", {"title": r["title"], "description": r.get("description", ""), "source": s2}); print(f"regle corrigee : {r['title']}")
    for i, t in plan["v5"].items():
        d = api("GET", f"/events/definitions/{i}")
        if V5_DEFS[t].strip() not in d["config"]["query"]:
            d["config"]["query"] += V5_DEFS[t]; put_def(d, d.get("state") == "ENABLED"); print(f"v5 requete : {t} -> {d['config']['query']}")
    for i in list(plan["definitions"]) + list(plan["v5"]):
        d = api("GET", f"/events/definitions/{i}"); c = d["config"]
        print(f"  verif {i} W={c['search_within_ms']//60000} pas={c['execute_every_ms']//60000} gb={c['group_by']} grace={d['notification_settings']['grace_period_ms']//60000} etat={d.get('state')} q={c['query'][:90]}")

def retour(dossier):
    for f in sorted(os.listdir(dossier)):
        if f.startswith("definition-"):
            d = json.load(open(f"{dossier}/{f}")); put_def(d, d.get("state") == "ENABLED"); print(f"definition remise : {d['id']} {d['title']}")
        elif f.startswith("regle-"):
            r = json.load(open(f"{dossier}/{f}")); api("PUT", f"/system/pipelines/rule/{r['id']}", {"title": r["title"], "description": r.get("description", ""), "source": r["source"]}); print(f"regle remise : {r['title']}")

if __name__ == "__main__":
    if ARGS[0] == "--preparer": preparer()
    elif ARGS[0] == "--appliquer": appliquer(ARGS[1])
    elif ARGS[0] == "--retour": retour(ARGS[1])
