#!/usr/bin/env bash
# =============================================================================
# 64-m365-fwd-audit.sh - Audit des TRANSFERTS mail M365 EXISTANTS (etat instantane)
#   Enumere les boites (Graph) et liste les REGLES inbox de transfert/redirection
#   vers une adresse EXTERNE (vecteur classique d'exfiltration). Complement de
#   18-m365-activity (qui ne voit que les transferts CREES pendant sa fenetre).
#   Collecteur /usr/local/sbin/omni-m365-fwd-audit (stdlib) -> GELF 12201 ->
#   alert_tag=m365_fwd_existing. Timer hebdomadaire.
#   PERMISSIONS GRAPH REQUISES (application + admin consent) sur OMNI-SIEM-Collector:
#     User.Read.All  +  MailboxSettings.Read
#   (NB : le transfert au niveau BOITE - ForwardingSmtpAddress via Set-Mailbox -
#    n'est pas expose par Graph ; il faudrait Exchange Online PowerShell. Ici on
#    couvre les REGLES inbox, vecteur le plus courant d'exfil par transfert.)
#   Idempotent. Prerequis : 16/17 (input GELF 12201 + /etc/default/omni-m365).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Domaines internes dans /etc/default/omni-m365"
grep -q '^M365_INTERNAL_DOMAINS=' /etc/default/omni-m365 2>/dev/null \
  || echo 'M365_INTERNAL_DOMAINS=omnitech-security.fr,omnitech.security' >> /etc/default/omni-m365
ok "domaines internes presents"

echo "==> [2/4] Collecteur /usr/local/sbin/omni-m365-fwd-audit"
cat > /usr/local/sbin/omni-m365-fwd-audit <<'PYEOF'
#!/usr/bin/env python3
"""Audit des transferts mail M365 (regles inbox forward/redirect vers externe).
Stdlib only. Permissions Graph : User.Read.All + MailboxSettings.Read (app)."""
import json, os, time, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone

ENV = {}
with open("/etc/default/omni-m365") as f:
    for line in f:
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); ENV[k] = v

GRAPH = "https://graph.microsoft.com/v1.0"
INTERNAL = {d.strip().lower() for d in ENV.get("M365_INTERNAL_DOMAINS",
            "omnitech-security.fr,omnitech.security").split(",") if d.strip()}

def log(m): print(f"{datetime.now(timezone.utc).isoformat()} {m}", flush=True)

def token():
    data = urllib.parse.urlencode({
        "client_id": ENV["M365_CLIENT_ID"], "client_secret": ENV["M365_CLIENT_SECRET"],
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}).encode()
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{ENV['M365_TENANT_ID']}/oauth2/v2.0/token", data=data)
    return json.load(urllib.request.urlopen(req, timeout=30))["access_token"]

def graph_get(tok, url):
    req = urllib.request.Request(url.replace(" ", "%20"), headers={"Authorization": f"Bearer {tok}"})
    return json.load(urllib.request.urlopen(req, timeout=60))

def graph_pages(tok, url, cap=200):
    n = 0
    while url and n < cap:
        try:
            doc = graph_get(tok, url)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(int(e.headers.get("Retry-After", "10"))); continue
            if e.code == 403:
                log(f"403 (permission manquante : User.Read.All ?) sur {url.split('?')[0]}"); return
            raise
        yield from doc.get("value", [])
        url = doc.get("@odata.nextLink"); n += 1

def gelf(fields):
    fields.setdefault("version", "1.1"); fields.setdefault("host", "graph.microsoft.com")
    fields.setdefault("timestamp", time.time())
    req = urllib.request.Request(ENV["GELF_URL"], data=json.dumps(fields).encode(),
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()

def is_external(addr):
    return bool(addr) and "@" in addr and addr.rsplit("@", 1)[1].lower() not in INTERNAL

def recipients(lst):
    return [(r.get("emailAddress") or {}).get("address") for r in (lst or [])
            if (r.get("emailAddress") or {}).get("address")]

def main():
    tok = token()
    scanned = found = 0
    for u in graph_pages(tok, GRAPH + "/users?$select=id,userPrincipalName,mail&$top=999"):
        uid = u.get("id"); upn = u.get("userPrincipalName") or u.get("mail")
        if not uid or not u.get("mail"):
            continue
        scanned += 1
        try:
            rules = graph_get(tok, f"{GRAPH}/users/{uid}/mailFolders/inbox/messageRules").get("value", [])
        except urllib.error.HTTPError as e:
            if e.code == 403:
                log("403 : permission MailboxSettings.Read manquante (admin consent ?) - arret."); return
            if e.code in (400, 404):
                continue  # pas de boite / inbox accessible
            raise
        for rule in rules:
            act = rule.get("actions", {}) or {}
            tgts = (recipients(act.get("forwardTo")) + recipients(act.get("redirectTo"))
                    + recipients(act.get("forwardAsAttachmentTo")))
            ext = sorted({t for t in tgts if is_external(t)})
            if ext:
                found += 1
                gelf({
                    "short_message": f"M365 transfert EXISTANT: {upn} -> {', '.join(ext)} "
                                     f"(regle '{rule.get('displayName')}')",
                    "level": 4,
                    "_event_source": "m365_fwd_audit", "_m365_type": "fwd_audit",
                    "_alert_tag": "m365_fwd_existing", "_event_action": "forward_rule_external",
                    "_upn": upn, "_user": (upn.split("@")[0] if upn else None),
                    "_fwd_rule": rule.get("displayName"), "_fwd_to": ", ".join(ext),
                    "_fwd_enabled": bool(rule.get("isEnabled")),
                })
        time.sleep(0.05)  # menagement du throttling Graph
    gelf({"short_message": f"M365 audit transferts: {scanned} boites scannees, {found} transferts externes",
          "level": 6, "_event_source": "siem_m365_fwd_audit", "_event_action": "audit_done",
          "_audit_scanned": scanned, "_audit_found": found})
    log(f"termine: {scanned} boites, {found} transferts externes")

if __name__ == "__main__":
    main()
PYEOF
chmod 755 /usr/local/sbin/omni-m365-fwd-audit
ok "collecteur installe"

echo "==> [3/4] Service + timer hebdomadaire"
cat > /etc/systemd/system/omni-m365-fwd-audit.service <<'EOF'
[Unit]
Description=OMNI - Audit M365 des transferts mail externes existants
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-m365-fwd-audit
EOF
cat > /etc/systemd/system/omni-m365-fwd-audit.timer <<'EOF'
[Unit]
Description=OMNI - Audit M365 transferts (hebdomadaire)
[Timer]
OnCalendar=Mon 06:30
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-m365-fwd-audit.timer >/dev/null 2>&1 && ok "timer hebdo actif (lundi 06:30)"

echo "==> [4/4] MITRE + alerte"
CSV="lookups/mitre-attack.csv"
grep -q '^m365_fwd_existing,' "$CSV" || echo 'm365_fwd_existing,T1114.003,Email Forwarding Rule,Collection,eleve,7' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE m365_fwd_existing (T1114.003)"

ST_M365="$(get_stream_id 'OMNI - M365')"
NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NOTIF_TEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
TITLE="OMNI - M365 : transfert mail externe EXISTANT (audit)"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "$TITLE" '.event_definitions[]|select(.title==$t)' >/dev/null; then
  skip "alerte audit transferts existe"
else
  NOTIFS="$(jq -n --arg m "$NOTIF_MAIL" --arg tm "$NOTIF_TEAMS" \
    '[ {notification_id:$m, notification_parameters:null} ] + (if $tm=="" or $tm=="null" then [] else [{notification_id:$tm, notification_parameters:null}] end)')"
  jq -n --arg t "$TITLE" --arg st "$ST_M365" --argjson n "$NOTIFS" '{
    title:$t, description:"Une regle de transfert mail vers un domaine EXTERNE existe sur une boite (audit hebdo). A verifier : exfiltration ou legitime. Provisionne par 64-m365-fwd-audit.sh",
    priority:3, alert:true,
    config:{type:"aggregation-v1", query:"alert_tag:m365_fwd_existing", query_parameters:[],
      streams:[$st], group_by:[], series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:86400000, execute_every_ms:86400000, use_cron_scheduling:false, event_limit:100},
    field_spec:{}, key_spec:[],
    notification_settings:{grace_period_ms:86400000, backlog_size:20},
    notifications:$n
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte audit transferts creee" || warn "alerte REFUSEE"
fi

echo
echo "=== 64-m365-fwd-audit.sh termine."
echo "    AVANT 1er run : accorder sur OMNI-SIEM-Collector (Entra > API permissions >"
echo "    Microsoft Graph > Application) : User.Read.All + MailboxSettings.Read + admin consent."
echo "    Test : systemctl start omni-m365-fwd-audit.service ; journalctl -u omni-m365-fwd-audit -n 20"
echo "    Resultat : alert_tag:m365_fwd_existing (qui -> quelle adresse externe). Relancer 14 pour le widget. ==="
