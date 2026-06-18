#!/usr/bin/env bash
# ==============================================================================
# 17-m365-fetcher.sh - Collecteur Microsoft Graph -> GELF (input du script 16)
#   Installe :
#     /etc/default/omni-m365            credentials (600, root)
#     /usr/local/sbin/omni-m365-fetch   collecteur Python (stdlib uniquement)
#     timer systemd omni-m365-fetch     toutes les 5 min
#   Collecte (curseurs persistants /var/lib/omni-m365/state.json) :
#     - auditLogs/signIns          -> m365_type=signin (user, src_ip, pays, app,
#                                     MFA, echec/succes, risk_state)
#     - auditLogs/directoryAudits  -> m365_type=audit  (event_action, cible)
#     - identityProtection/riskDetections -> m365_type=risk (403 tolere tant que
#       IdentityRiskEvent.Read.All n'est pas consenti / licence P2)
# Idempotent. Prerequis : 16 (input GELF 12201) + M365_* dans 00-vars.env.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }
[[ -n "${M365_TENANT_ID:-}" && -n "${M365_CLIENT_ID:-}" && -n "${M365_CLIENT_SECRET:-}" ]] \
  || { echo "ERREUR: variables M365_* absentes de 00-vars.env (cf. M365.md)"; exit 1; }

echo "==> [1/3] /etc/default/omni-m365"
cat > /etc/default/omni-m365 <<EOF
M365_TENANT_ID=${M365_TENANT_ID}
M365_CLIENT_ID=${M365_CLIENT_ID}
M365_CLIENT_SECRET=${M365_CLIENT_SECRET}
GELF_URL=http://127.0.0.1:12201/gelf
BACKFILL_HOURS=24
EOF
chmod 600 /etc/default/omni-m365

echo "==> [2/3] /usr/local/sbin/omni-m365-fetch"
cat > /usr/local/sbin/omni-m365-fetch <<'PYEOF'
#!/usr/bin/env python3
"""Collecteur M365 -> GELF (installe par 17-m365-fetcher.sh). Stdlib only."""
import json, os, sys, time, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timedelta, timezone

ENV = {}
with open("/etc/default/omni-m365") as f:
    for line in f:
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); ENV[k] = v

STATE_DIR = "/var/lib/omni-m365"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
os.makedirs(STATE_DIR, exist_ok=True)
GRAPH = "https://graph.microsoft.com/v1.0"

import ipaddress
def clean_ip(raw):
    if not raw: return None
    s = str(raw).strip()
    if s.startswith("["):            # [ipv6]:port
        s = s[1:].split("]")[0]
    elif s.count(":") == 1:          # ipv4:port
        s = s.split(":")[0]
    try:
        ipaddress.ip_address(s); return s
    except ValueError:
        return None


def log(msg): print(f"{datetime.now(timezone.utc).isoformat()} {msg}", flush=True)

def load_state():
    try:
        with open(STATE_FILE) as f: return json.load(f)
    except Exception:
        start = (datetime.now(timezone.utc) - timedelta(hours=int(ENV.get("BACKFILL_HOURS", "24")))).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"signins": start, "audits": start, "risks": start}

def save_state(st):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f: json.dump(st, f)
    os.replace(tmp, STATE_FILE)

def token():
    data = urllib.parse.urlencode({
        "client_id": ENV["M365_CLIENT_ID"], "client_secret": ENV["M365_CLIENT_SECRET"],
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}).encode()
    req = urllib.request.Request(f"https://login.microsoftonline.com/{ENV['M365_TENANT_ID']}/oauth2/v2.0/token", data=data)
    return json.load(urllib.request.urlopen(req, timeout=30))["access_token"]

def graph_pages(tok, url, max_pages=10):
    pages = 0
    while url and pages < max_pages:
        req = urllib.request.Request(url.replace(" ", "%20"), headers={"Authorization": f"Bearer {tok}"})
        try:
            doc = json.load(urllib.request.urlopen(req, timeout=60))
        except urllib.error.HTTPError as e:
            if e.code == 403: log(f"403 (permission manquante) sur {url.split('?')[0]}"); return
            if e.code == 429: time.sleep(int(e.headers.get("Retry-After", "10"))); continue
            raise
        yield from doc.get("value", [])
        url = doc.get("@odata.nextLink"); pages += 1

def gelf_send(fields):
    data = json.dumps(fields).encode()
    req = urllib.request.Request(ENV["GELF_URL"], data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()

def epoch(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def local(u):
    return u.split("@")[0].lower() if u else None

def main():
    st = load_state(); tok = token(); sent = 0

    # ---- 1. signIns -----------------------------------------------------------
    cur = st["signins"]; newest = cur
    url = f"{GRAPH}/auditLogs/signIns?$filter=createdDateTime gt {cur}&$orderby=createdDateTime asc&$top=200"
    for s in graph_pages(tok, url):
        ts = s.get("createdDateTime", cur); newest = max(newest, ts)
        err = (s.get("status") or {}).get("errorCode", 0)
        loc = s.get("location") or {}
        msg = {
            "version": "1.1", "host": "graph.microsoft.com",
            "short_message": f"M365 signin {s.get('userPrincipalName','?')} {'OK' if err == 0 else 'ECHEC ' + str(err)}",
            "timestamp": epoch(ts),
            "_event_source": "m365", "_m365_type": "signin",
            "_user": local(s.get("userPrincipalName")), "_upn": s.get("userPrincipalName"), "_src_ip": clean_ip(s.get("ipAddress")),
            "_src_country": loc.get("countryOrRegion"), "_src_city": loc.get("city"),
            "_app": s.get("appDisplayName"), "_client_app": s.get("clientAppUsed"),
            "_device_os": (s.get("deviceDetail") or {}).get("operatingSystem"),
            "_mfa": s.get("authenticationRequirement"),
            "_event_action": "connexion_reussie" if err == 0 else "echec_connexion",
            "_status_code": str(err),
            "_failure_reason": (s.get("status") or {}).get("failureReason") if err != 0 else None,
            "_risk_state": s.get("riskState"), "_risk_level": s.get("riskLevelAggregated"),
            "_m365_id": s.get("id"),
        }
        gelf_send({k: v for k, v in msg.items() if v is not None}); sent += 1
    st["signins"] = newest

    # ---- 2. directoryAudits ----------------------------------------------------
    cur = st["audits"]; newest = cur
    url = f"{GRAPH}/auditLogs/directoryAudits?$filter=activityDateTime gt {cur}&$orderby=activityDateTime asc&$top=200"
    for a in graph_pages(tok, url):
        ts = a.get("activityDateTime", cur); newest = max(newest, ts)
        ini = (a.get("initiatedBy") or {})
        who = (ini.get("user") or {}).get("userPrincipalName") or (ini.get("app") or {}).get("displayName")
        targets = a.get("targetResources") or [{}]
        target = targets[0].get("userPrincipalName") or targets[0].get("displayName")
        msg = {
            "version": "1.1", "host": "graph.microsoft.com",
            "short_message": f"M365 audit {a.get('activityDisplayName','?')} par {who or '?'}",
            "timestamp": epoch(ts),
            "_event_source": "m365", "_m365_type": "audit",
            "_user": local(who), "_upn": who, "_target": target,
            "_event_action": a.get("activityDisplayName"),
            "_event_category": a.get("category"), "_result": a.get("result"),
            "_m365_id": a.get("id"),
        }
        gelf_send({k: v for k, v in msg.items() if v is not None}); sent += 1
    st["audits"] = newest

    # ---- 3. riskDetections (tolere 403) ----------------------------------------
    cur = st["risks"]; newest = cur
    url = f"{GRAPH}/identityProtection/riskDetections?$filter=detectedDateTime gt {cur}&$orderby=detectedDateTime asc&$top=200"
    for r in graph_pages(tok, url):
        ts = r.get("detectedDateTime", cur); newest = max(newest, ts)
        msg = {
            "version": "1.1", "host": "graph.microsoft.com",
            "short_message": f"M365 risque {r.get('riskEventType','?')} {r.get('userPrincipalName','?')}",
            "timestamp": epoch(ts),
            "_event_source": "m365", "_m365_type": "risk",
            "_user": local(r.get("userPrincipalName")), "_upn": r.get("userPrincipalName"), "_src_ip": clean_ip(r.get("ipAddress")),
            "_event_action": r.get("riskEventType"),
            "_risk_state": r.get("riskState"), "_risk_level": r.get("riskLevel"),
            "_m365_id": r.get("id"),
        }
        gelf_send({k: v for k, v in msg.items() if v is not None}); sent += 1
    st["risks"] = newest

    save_state(st)
    log(f"OK - {sent} message(s) envoye(s) (curseurs: {st})")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"ERREUR: {e}"); sys.exit(1)
PYEOF
chmod 700 /usr/local/sbin/omni-m365-fetch

echo "==> [3/3] Timer systemd (5 min)"
cat > /etc/systemd/system/omni-m365-fetch.service <<'EOF'
[Unit]
Description=Collecte Microsoft 365 -> Graylog (GELF)
After=graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-m365-fetch
EOF
cat > /etc/systemd/system/omni-m365-fetch.timer <<'EOF'
[Unit]
Description=Declencheur collecte M365 (5 min)
[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
RandomizedDelaySec=30
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-m365-fetch.timer
echo
echo "Premiere collecte : systemctl start omni-m365-fetch.service ; journalctl -u omni-m365-fetch -n 5"
echo "=== 17-m365-fetcher.sh termine. Relancer 14 pour le dashboard M365 ==="
