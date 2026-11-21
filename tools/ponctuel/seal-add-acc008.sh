#!/usr/bin/env bash
# Cree UNIQUEMENT la detection SEAL ACC-008 "Badge refuse hors plage horaire", modelee sur ACC-007
# (structure) + notifications d'ACC-001 (High : Teams + triage mail). Ne touche a AUCUNE autre def
# (contrairement a provision_detections.py qui fait create-or-update sur tout le catalogue et
# defairait le tri du 18/07). DRY-RUN par defaut ; "apply" en 1er argument pour creer.
set -euo pipefail
cd /root/omnitech-siem-setup
source 00-vars.env
GL="https://bx-it-graylog-vm.omnitech.security/api"
APPLY=0; [ "${1:-}" = "apply" ] && APPLY=1
python3 - "$GL" "$GRAYLOG_ADMIN_PASS" "$APPLY" <<'PY'
import sys, json, ssl, base64, urllib.request, urllib.error
GL, PW, APPLY = sys.argv[1], sys.argv[2], sys.argv[3] == '1'
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def call(method, path, body=None):
    req = urllib.request.Request(GL + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json', 'X-Requested-By': 'cli',
                 'Authorization': 'Basic ' + base64.b64encode(f'admin:{PW}'.encode()).decode()})
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=30)
        return json.load(r) if r.length != 0 else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        # Piege API Graylog 7.x : POST /events/definitions exige parfois un wrapper
        # {entity:..., share_request:...} (message "entity cannot be null"). On enveloppe et on rejoue.
        if method == 'POST' and body is not None and 'entity cannot be null' in detail:
            wrapped = {"entity": body, "share_request": {"selected_grantee_capabilities": {}}}
            req2 = urllib.request.Request(GL + path, method='POST', data=json.dumps(wrapped).encode(),
                headers={'Content-Type': 'application/json', 'X-Requested-By': 'cli',
                         'Authorization': 'Basic ' + base64.b64encode(f'admin:{PW}'.encode()).decode()})
            r2 = urllib.request.urlopen(req2, context=ctx, timeout=30)
            return json.load(r2) if r2.length != 0 else {}
        raise
TITLE = "OMNI - SEAL ACC-008 - Badge refusé hors plage horaire (tentative persistante)"
alld = call('GET', '/events/definitions?per_page=1000')
for e in alld.get('events', alld.get('event_definitions', [])):
    if e.get('title') == TITLE:
        print("ACC-008 existe deja (id=%s) - rien a faire (idempotent)." % e['id']); sys.exit(0)
tpl = call('GET', '/events/definitions/6a575010ef35b1c51c6639e5')      # ACC-007 (structure)
notifs = call('GET', '/events/definitions/6a57500eef35b1c51c6639a9').get('notifications')  # ACC-001 (High)
body = {k: v for k, v in tpl.items() if k not in ('id', '_scope')}
body['title'] = TITLE
body['description'] = "P3 - un meme badge refuse >=3x hors plage horaire en 60 min (tentative persistante). Ajout 18/07/2026 (audit, demande RSSI)."
body['priority'] = 3
body['notifications'] = notifs
c = dict(body['config'])
c['query'] = "event_domain:access AND event_outcome:deny AND off_hours:true AND _exists_:badge_number"
c['group_by'] = ["seal_site", "badge_number"]
c['conditions'] = {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"},
                                  "right": {"expr": "number", "value": 3.0}}}
c['search_within_ms'] = 3600000   # 60 min
c['execute_every_ms'] = 900000    # 15 min
body['config'] = c
if not APPLY:
    print("DRY-RUN - creerait ACC-008 :")
    print("  titre    :", TITLE)
    print("  query    :", c['query'])
    print("  group_by :", c['group_by'], "| cond >=3 | within 60min | every 15min | priorite 3 (High)")
    print("  notifs   :", len(notifs or []), "(Teams + triage mail, comme ACC-001)")
    print("  Relancer avec 'apply' pour creer.")
    sys.exit(0)
r = call('POST', '/events/definitions?schedule=true', body)
print("ACC-008 CREEE - id=%s, state=%s" % (r.get('id'), r.get('state')))
PY
