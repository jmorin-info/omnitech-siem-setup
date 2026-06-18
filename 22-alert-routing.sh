#!/usr/bin/env bash
# =============================================================================
# 22-alert-routing.sh - Routage des notifications en 2 tiers (anti-spam mail).
#   Teams = firehose (toutes les alertes). MAIL = critique "reveille-moi"
#   uniquement (compromission confirmee + sante SIEM). Tout le reste : Teams seul.
#   Releve aussi la grace des alertes mail recurrentes a >=60 min.
#   Idempotent. A relancer apres 13-graylog-alerts.sh / 21-alert-hygiene.sh.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
export GRAYLOG_ADMIN_PASS

python3 - <<'PY'
import json, urllib.request, ssl, base64, os
GL="https://127.0.0.1:9000/api"
auth=base64.b64encode(f"admin:{os.environ['GRAYLOG_ADMIN_PASS']}".encode()).decode()
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
def call(m,p,b=None):
    data=json.dumps(b).encode() if b is not None else None
    r=urllib.request.Request(GL+p,data=data,method=m,headers={"Authorization":"Basic "+auth,"Content-Type":"application/json","X-Requested-By":"cli"})
    try:
        with urllib.request.urlopen(r,context=ctx) as resp: return json.load(resp)
    except urllib.error.HTTPError as e:
        print("  HTTP",e.code,p,e.read().decode()[:150]); return None

MAIL="6a2ab29165bc77613c8343c4"
TEAMS="6a2abf7265bc77613c83880e"

# MAIL conserve = critique interrompable (compromission confirmee + sante SIEM).
# Tout le reste -> Teams uniquement. Match par sous-chaine de titre.
KEEP=[
 "Incident critique","Indicateur de ransomware","Force brute SUIVIE","Mouvement lateral reussi",
 "DCSync","CANARI","transfert mail vers domaine externe","ESET : detection","Impossible travel",
 "Robot d'analyse en panne","Disque SIEM >80%","PURGE D'URGENCE","Backup config SIEM en echec",
 "Backup config SIEM absent","Certificat SIEM expire","Rapport hebdomadaire en echec",
 "Silence Winlogbeat","Veeam : job en echec","Certificat du parc expire",
 "coffre Vaultwarden","Contournement UAC","Compte M365 a risque",
 "Acces massif a des fichiers","Suppressions massives de fichiers",
 "Integrite des logs COMPROMISE","Sabotage de l'audit",
]
def keep_mail(title): return any(k in title for k in KEEP)
MIN_GRACE=3600000  # 60 min

defs=call("GET","/events/definitions?per_page=300")["event_definitions"]
n_mail_off=n_teams_add=n_grace=n_unchanged=0
kept=[]
for e in defs:
    full=call("GET",f"/events/definitions/{e['id']}")
    if not full: continue
    if str(full.get("_scope","")).startswith("GRAYLOG"): continue   # def systeme immuable
    title=full.get("title","")
    notifs=full.get("notifications",[]) or []
    changed=False
    # 1) Teams partout (firehose)
    if not any(n.get("notification_id")==TEAMS for n in notifs):
        notifs.append({"notification_id":TEAMS,"notification_parameters":None}); changed=True; n_teams_add+=1
    # 2) Mail : seulement si critique
    has_mail=any(n.get("notification_id")==MAIL for n in notifs)
    if keep_mail(title):
        kept.append(title)
        if not has_mail:
            notifs.append({"notification_id":MAIL,"notification_parameters":None}); changed=True
        # grace mini 60 min pour limiter la repetition par cle
        ns=full.get("notification_settings",{}) or {}
        if (ns.get("grace_period_ms") or 0) < MIN_GRACE:
            ns["grace_period_ms"]=MIN_GRACE
            if not ns.get("backlog_size"): ns["backlog_size"]=ns.get("backlog_size",5)
            full["notification_settings"]=ns; changed=True; n_grace+=1
    else:
        if has_mail:
            notifs=[n for n in notifs if n.get("notification_id")!=MAIL]; changed=True; n_mail_off+=1
    if changed:
        full["notifications"]=notifs; full.pop("_scope",None)
        call("PUT",f"/events/definitions/{e['id']}",full)
    else:
        n_unchanged+=1

print(f"  mail retire (-> Teams) : {n_mail_off}")
print(f"  Teams ajoute (manquant): {n_teams_add}")
print(f"  grace relevee a 60min  : {n_grace}")
print(f"  inchangees             : {n_unchanged}")
print(f"  MAIL conserve sur {len(kept)} alertes critiques :")
for t in sorted(set(kept)): print("    -",t[:60])
PY
echo "=== 22-alert-routing.sh termine. Teams = toutes les alertes ; mail = critique seul. ==="
