#!/usr/bin/env bash
# =============================================================================
# 36-soar.sh - Active le SOAR-light : service + notification Graylog + alerte
# -----------------------------------------------------------------------------
# 1. demarre omni-soar.service (recoit les webhooks) + omni-soar-expire.timer
# 2. cree la notification HTTP "OMNI - SOAR auto-block" -> 127.0.0.1:8088/block
# 3. l'attache aux alertes VPN / spraying (force brute portail, password spraying)
# 4. cree l'alerte de tracabilite "OMNI - SOAR : IP bloquee automatiquement"
# Cote FortiGate : appliquer fortigate/06-soar-threatfeed.conf.
# Idempotent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
. ./00-vars.env
. ./lib-graylog.sh
require_api

echo "==> [1/4] Service SOAR + timer d'expiration"
# --- binaires + units omni-soar / omni-soar-expire (versionnes AS-IS, cloture AC-2026-06-22-05) ---
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-soar <<'OMNISBIN'
#!/usr/bin/env python3
# =============================================================================
# omni-soar - Service SOAR-light : recoit les webhooks Graylog (alertes VPN /
# spraying), extrait l'IP attaquante et la publie dans une blocklist que le
# FortiGate lit en "Threat Feed" (External Connector IP Address).
#
# Architecture (decouplee, sans credential sur le firewall) :
#   Graylog HTTP notification -> POST http://127.0.0.1:8088/block
#     -> securites (jamais RFC1918, jamais whitelist, seuil de hits, cap, TTL)
#     -> etat /var/lib/omni-soar/blocklist.json {ip: expiry_epoch}
#     -> rend /var/www/siem-kit/soar/blocklist.txt (servi par nginx)
#     -> GELF (event_source=siem_soar) -> alerte "SOAR : IP bloquee"
#   FortiGate poll l'URL et applique une policy deny en entree WAN.
# Expiration : omni-soar-expire (timer). Config : 00-vars.env (SOAR_*).
# =============================================================================
import ipaddress, json, os, re, time, urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

ENVFILE   = "/root/omnitech-siem-setup/00-vars.env"
STATE     = "/var/lib/omni-soar/blocklist.json"
FEED      = "/var/www/siem-kit/soar/blocklist.txt"
GELF_URL  = "http://127.0.0.1:12201/gelf"
LISTEN    = ("127.0.0.1", 8088)

def env():
    e = {}
    try:
        for line in open(ENVFILE):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: e[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return e

def gelf(action, ip, msg):
    try:
        data = json.dumps({"version":"1.1","host":"bx-it-graylog-vm",
            "short_message": f"SOAR {action}: {ip} ({msg})",
            "_event_source":"siem_soar","_event_action":action,"_soar_ip":ip}).encode()
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=data,
            headers={"Content-Type":"application/json"}), timeout=8)
    except Exception: pass

def load():
    try: return json.load(open(STATE))
    except Exception: return {}
def save(d): json.dump(d, open(STATE,"w"))

def render(d):
    now = time.time()
    lines = ["# OMNITECH SIEM SOAR blocklist - auto-genere - ne pas editer"]
    for ip, exp in sorted(d.items()):
        if exp > now:
            lines.append(ip)
    tmp = FEED + ".tmp"
    open(tmp,"w").write("\n".join(lines) + "\n")
    os.replace(tmp, FEED)

def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved)
    except ValueError:
        return False

def extract_ips(payload):
    """Recupere les IP candidates depuis le backlog + l'event de l'alerte Graylog.
    Robuste aux differentes structures du backlog (champs au niveau item, sous
    'fields', ou sous 'message' selon la serialisation MessageSummary)."""
    c = Counter()
    def scan(d):
        if isinstance(d, dict):
            for key in ("remip", "src_ip", "srcip"):
                v = d.get(key)
                if v not in (None, "", "-"):
                    c[str(v)] += 1
    for m in (payload.get("backlog") or []):
        if isinstance(m, dict):
            scan(m)
            scan(m.get("fields"))
            scan(m.get("message"))
    ev = payload.get("event") or {}
    scan(ev.get("fields"))
    for v in (ev.get("key_tuple") or []):
        if isinstance(v, str):
            c[v] += 1
    return c

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self.send_response(400); self.end_headers(); return
        e = env()
        ttl   = int(e.get("SOAR_TTL_HOURS","24")) * 3600
        cap   = int(e.get("SOAR_MAX","500"))
        minh  = int(e.get("SOAR_MIN_HITS","5"))
        wl    = {x.strip() for x in e.get("SOAR_WHITELIST","").split(",") if x.strip()}
        d = load(); now = time.time(); blocked = []
        for ip, hits in extract_ips(payload).most_common():
            if hits < minh:           continue
            if not is_public(ip):     continue          # jamais d'IP interne
            if ip in wl:              continue          # jamais la whitelist
            if ip in d and d[ip] > now:
                d[ip] = now + ttl                       # prolonge
                continue
            if len([1 for x,exp in d.items() if exp>now]) >= cap:
                gelf("cap_atteint", ip, "blocklist pleine"); break
            d[ip] = now + ttl
            blocked.append(ip)
            gelf("ip_bloquee", ip, f"{hits} hits, TTL {ttl//3600}h")
        # purge expirees + rendu
        d = {ip:exp for ip,exp in d.items() if exp > now}
        save(d); render(d)
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({"blocked": blocked, "active": len(d)}).encode())

if __name__ == "__main__":
    render(load())  # regenere le feed au demarrage
    HTTPServer(LISTEN, Handler).serve_forever()
OMNISBIN
chmod 755 /usr/local/sbin/omni-soar
cat > /usr/local/sbin/omni-soar-expire <<'OMNISBIN'
#!/usr/bin/env python3
# omni-soar-expire - retire les IP expirees de la blocklist SOAR (timer horaire)
import json, os, time, urllib.request
STATE="/var/lib/omni-soar/blocklist.json"; FEED="/var/www/siem-kit/soar/blocklist.txt"
try: d=json.load(open(STATE))
except Exception: d={}
now=time.time()
keep={ip:exp for ip,exp in d.items() if exp>now}
removed=len(d)-len(keep)
json.dump(keep, open(STATE,"w"))
lines=["# OMNITECH SIEM SOAR blocklist - auto-genere - ne pas editer"]+[ip for ip,exp in sorted(keep.items()) if exp>now]
open(FEED+".tmp","w").write("\n".join(lines)+"\n"); os.replace(FEED+".tmp", FEED)
if removed:
    try:
        data=json.dumps({"version":"1.1","host":"bx-it-graylog-vm",
            "short_message":f"SOAR expiration: {removed} IP debloquees, {len(keep)} actives",
            "_event_source":"siem_soar","_event_action":"ip_expiree"}).encode()
        urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:12201/gelf",data=data,
            headers={"Content-Type":"application/json"}),timeout=8)
    except Exception: pass
print(f"SOAR expire: {removed} retirees, {len(keep)} actives")
OMNISBIN
chmod 755 /usr/local/sbin/omni-soar-expire
cat > /etc/systemd/system/omni-soar.service <<'OMNIUNIT'
[Unit]
Description=SOAR-light OMNITECH - blocklist d'IP attaquantes (webhook Graylog)
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/sbin/omni-soar
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
OMNIUNIT
cat > /etc/systemd/system/omni-soar-expire.service <<'OMNIUNIT'
[Unit]
Description=Expiration des IP de la blocklist SOAR

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/omni-soar-expire
OMNIUNIT
cat > /etc/systemd/system/omni-soar-expire.timer <<'OMNIUNIT'
[Unit]
Description=Expiration blocklist SOAR (horaire)

[Timer]
OnCalendar=*-*-* *:30:00
Persistent=true

[Install]
WantedBy=timers.target
OMNIUNIT
systemctl daemon-reload
systemctl enable --now omni-soar.service omni-soar-expire.timer
sleep 2
curl -s -o /dev/null -w "  service omni-soar (127.0.0.1:8088) -> HTTP %{http_code}\n" \
  -X POST http://127.0.0.1:8088/block -d '{}' || warn "service injoignable"

echo "==> [2/4] Notification HTTP vers le service SOAR"
NID="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]? | select(.title=="OMNI - SOAR auto-block") | .id')"
if [[ -z "${NID}" || "${NID}" == "null" ]]; then
  NID="$(jq -n '{title:"OMNI - SOAR auto-block",
      description:"Webhook vers omni-soar (blocage auto IP) - provisionne par 36-soar.sh",
      config:{type:"http-notification-v1", url:"http://127.0.0.1:8088/block",
        api_key_as_header:false, api_key:"", api_secret:null, basic_auth:null,
        skip_tls_verification:true}}' \
    | post_entity "/events/notifications" | jqr '.id')"
  [[ -n "${NID}" && "${NID}" != "null" ]] && ok "notification SOAR creee (${NID})" || die "creation notification SOAR REFUSEE"
else skip "notification SOAR existe (${NID})"; fi

echo "==> [3/4] Attachement aux alertes VPN / spraying"
attach() {  # attach <titre_definition>
  local T="$1" DEF ID CUR
  ID="$(api_get "/events/definitions?per_page=300" | jq -r --arg t "$T" '.event_definitions[] | select(.title==$t) | .id')"
  if [[ -z "${ID}" || "${ID}" == "null" ]]; then warn "definition '$T' introuvable"; return; fi
  DEF="$(api_get "/events/definitions/${ID}")"
  if echo "${DEF}" | jq -e --arg n "${NID}" '.notifications[]? | select(.notification_id==$n)' >/dev/null; then
    skip "'$T' deja relie au SOAR"; return
  fi
  echo "${DEF}" | jq --arg n "${NID}" \
    'del(._scope,.matched_at,.updated_at,.scheduler) | .notifications += [{notification_id:$n, notification_parameters:null}] | .notification_settings.backlog_size = (.notification_settings.backlog_size // 10 | if . < 10 then 10 else . end)' \
    | api_put "/events/definitions/${ID}?schedule=true" >/dev/null \
    && ok "'$T' -> SOAR" || warn "'$T' : echec attachement"
}
attach "OMNI - Force brute portail VPN (>=30 échecs / IP / h)"
attach "OMNI - Password spraying (>=8 comptes / IP / 10 min)"

echo "==> [4/4] Alerte de tracabilite (mail)"
ST_INTERNE="$(get_stream_id 'OMNI - Interne SIEM')"
# s'assurer que le stream interne route siem_soar
SID="${ST_INTERNE}"
if [[ -n "${SID}" ]] && ! api_get "/streams/${SID}" | jq -e '.rules[]? | select(.value=="siem_soar")' >/dev/null; then
  echo '{"field":"event_source","type":1,"value":"siem_soar","inverted":false,"description":"evenements SOAR"}' \
    | api_post "/streams/${SID}/rules" >/dev/null && ok "stream interne route desormais siem_soar"
fi
NOTIF_MAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[] | select(.title=="OMNI - Mail equipe IT") | .id')"
TITLE="OMNI - SOAR : IP bloquee automatiquement"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "${TITLE}" '.event_definitions[] | select(.title==$t)' >/dev/null; then
  skip "alerte SOAR existe"
else
  jq -n --arg t "${TITLE}" --arg st "${SID}" --arg n "${NOTIF_MAIL}" '{
    title:$t, description:"P3 SOAR - une IP a ete bloquee automatiquement sur le FortiGate (feed). Verifier la legitimite. Provisionne par 36-soar.sh",
    priority:3, alert:true,
    config:{type:"aggregation-v1", query:"event_action:ip_bloquee", query_parameters:[],
      streams:[$st], group_by:[], series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:600000, execute_every_ms:300000, use_cron_scheduling:false, event_limit:50},
    field_spec:{}, key_spec:[],
    notification_settings:{grace_period_ms:1800000, backlog_size:10},
    notifications:[{notification_id:$n, notification_parameters:null}]
  }' | post_entity "/events/definitions?schedule=true" >/dev/null && ok "alerte SOAR creee" || warn "alerte SOAR REFUSEE"
fi
echo "=== 36-soar.sh termine. Cote FortiGate : appliquer fortigate/06-soar-threatfeed.conf ==="
