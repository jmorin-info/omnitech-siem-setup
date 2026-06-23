#!/usr/bin/env bash
# ==============================================================================
# 18-m365-activity.sh - Audit Exchange / SharePoint / OneDrive (O365 Management
#   Activity API) -> Graylog. Detecte l'exfiltration cloud :
#     - regles de transfert de boite mail vers un domaine EXTERNE (BEC)
#     - delegations de boite (Add-MailboxPermission / RecipientPermission)
#     - partages externes / liens anonymes SharePoint-OneDrive
#
#   Reutilise l'input GELF 12201, le stream et l'index "OMNI - M365" (cf. 16).
#   Pipeline SEPARE "OMNI - M365 Activite" connecte au meme stream (pas de
#   conflit avec le pipeline signin/audit du script 16).
#
#   Le collecteur Python pose des flags semantiques (forward_external,
#   external_share, mailbox_deleg) ; le pipeline les mappe en alert_tag.
#
# Prerequis : 16 (input/stream/index M365) + M365_* dans 00-vars.env.
# Idempotent. Suite : relancer 14 pour les widgets activite.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

ST_M365="$(get_stream_id 'OMNI - M365')"
[[ -n "${ST_M365}" ]] || die "stream 'OMNI - M365' absent (lancer 16-m365-input.sh)"

# ------------------------------------------------------- 1. Regles + pipeline
echo "==> [1/3] Pipeline 'OMNI - M365 Activite'"

ensure_rule "omni-m365act-10-mail-forward-externe" <<'EOF'
rule "omni-m365act-10-mail-forward-externe"
when
  has_field("forward_external")
then
  set_field("alert_tag", "m365_mail_forward");
end
EOF

ensure_rule "omni-m365act-10-delegation-boite" <<'EOF'
rule "omni-m365act-10-delegation-boite"
when
  has_field("mailbox_deleg")
then
  set_field("alert_tag", "m365_mailbox_deleg");
end
EOF

ensure_rule "omni-m365act-10-partage-externe" <<'EOF'
rule "omni-m365act-10-partage-externe"
when
  has_field("external_share")
then
  set_field("alert_tag", "m365_partage_externe");
end
EOF

PL_ACT="$(ensure_pipeline "OMNI - M365 Activite" <<'EOF'
pipeline "OMNI - M365 Activite"
stage 10 match either
rule "omni-m365act-10-mail-forward-externe"
rule "omni-m365act-10-delegation-boite"
rule "omni-m365act-10-partage-externe"
end
EOF
)"
connect_pipeline "${ST_M365}" "${PL_ACT}"

# ----------------------------------------------------------------- 2. Alertes
echo "==> [2/3] Alertes activite M365"
NOTIF_ID="$(api_get "/events/notifications?per_page=100" | jq -r '(.notifications // [])[] | select(.title=="OMNI - Mail equipe IT") | .id')"
TEAMS_ID="$(api_get "/events/notifications?per_page=100" | jq -r '(.notifications // [])[] | select(.title=="OMNI - Teams SOC") | .id')"
NOTIFS="$(jq -n --arg e "${NOTIF_ID}" --arg t "${TEAMS_ID}" '[{notification_id:$e, notification_parameters:null}] + (if $t != "" then [{notification_id:$t, notification_parameters:null}] else [] end)')"

ev_m365() { # titre prio query grace_min within every
  local TITLE="$1" PRIO="$2" QUERY="$3" GRACE="$4" WITHIN="$5" EVERY="$6"
  api_get "/events/definitions?per_page=100" | jq -e --arg t "${TITLE}" '(.event_definitions // .elements // [])[] | select(.title==$t)' >/dev/null 2>&1 \
    && { skip "evenement '${TITLE}' existe"; return 0; }
  jq -n --arg t "${TITLE}" --argjson p "${PRIO}" --arg q "${QUERY}" --arg st "${ST_M365}" \
        --argjson w "$(( WITHIN*60000 ))" --argjson e "$(( EVERY*60000 ))" --argjson g "$(( GRACE*60000 ))" --argjson n "${NOTIFS}" '{
    title:$t, description:("P"+($p|tostring)+" - provisionne par 18-m365-activity.sh"), priority:$p, alert:true,
    config:{ type:"aggregation-v1", query:$q, query_parameters:[], streams:[$st],
      group_by:[], series:[], conditions:{expression:null},
      search_within_ms:$w, execute_every_ms:$e, use_cron_scheduling:false, event_limit:100 },
    field_spec:{}, key_spec:[], notification_settings:{ grace_period_ms:$g, backlog_size:5 }, notifications:$n
  }' | post_entity "/events/definitions?schedule=true" | jqr '.id' \
    | { read -r ID; [[ -n "${ID}" && "${ID}" != "null" ]] && ok "evenement '${TITLE}'" || warn "evenement '${TITLE}' REFUSE"; }
}

ev_m365 "OMNI - M365 transfert mail vers domaine externe" 3 'alert_tag:m365_mail_forward' 30 15 10
ev_m365 "OMNI - M365 délégation de boîte mail" 2 'alert_tag:m365_mailbox_deleg' 60 15 10
ev_m365 "OMNI - M365 partage externe / lien anonyme" 2 'alert_tag:m365_partage_externe' 60 15 10

# -------------------------------------------------- 3. Collecteur + timer
echo "==> [3/3] Collecteur O365 Management Activity"
cat > /usr/local/sbin/omni-m365-activity <<'PYEOF'
#!/usr/bin/env python3
"""Collecteur O365 Management Activity (Exchange/SharePoint) -> GELF.
Installe par 18-m365-activity.sh. Stdlib only."""
import json, os, sys, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timedelta, timezone

ENV = {}
with open("/etc/default/omni-m365") as f:
    for line in f:
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); ENV[k] = v

TENANT = ENV["M365_TENANT_ID"]
GELF = ENV.get("GELF_URL", "http://127.0.0.1:12201/gelf")
INTERNAL = [d.strip().lower() for d in ENV.get("M365_INTERNAL_DOMAINS", "").split(",") if d.strip()]
BASE = f"https://manage.office.com/api/v1.0/{TENANT}/activity/feed"
CONTENT_TYPES = ["Audit.Exchange", "Audit.SharePoint", "Audit.General"]

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

STATE_DIR = "/var/lib/omni-m365"
STATE_FILE = os.path.join(STATE_DIR, "activity-state.json")
os.makedirs(STATE_DIR, exist_ok=True)

def log(m): print(f"{datetime.now(timezone.utc).isoformat()} {m}", flush=True)

def token():
    data = urllib.parse.urlencode({
        "client_id": ENV["M365_CLIENT_ID"], "client_secret": ENV["M365_CLIENT_SECRET"],
        "scope": "https://manage.office.com/.default", "grant_type": "client_credentials"}).encode()
    req = urllib.request.Request(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", data=data)
    return json.load(urllib.request.urlopen(req, timeout=30))["access_token"]

def req(tok, url, method="GET"):
    r = urllib.request.Request(url, method=method, headers={"Authorization": f"Bearer {tok}"})
    if method == "POST":
        r.data = b""  # Content-Length: 0 obligatoire (sinon HTTP 411)
    return urllib.request.urlopen(r, timeout=60)

def ensure_subscriptions(tok):
    try:
        subs = {s["contentType"]: s["status"] for s in json.load(req(tok, f"{BASE}/subscriptions/list"))}
    except Exception:
        subs = {}
    for ct in CONTENT_TYPES:
        if subs.get(ct) != "enabled":
            try: req(tok, f"{BASE}/subscriptions/start?contentType={ct}", "POST"); log(f"abonnement {ct} active")
            except Exception as e: log(f"abonnement {ct} KO: {e}")

def load_state():
    try:
        with open(STATE_FILE) as f: return json.load(f)
    except Exception: return {"seen": []}

def save_state(st):
    st["seen"] = st["seen"][-5000:]
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f: json.dump(st, f)
    os.replace(tmp, STATE_FILE)

def epoch(iso):
    iso = iso.replace("Z", "+00:00")
    if "." in iso and "+" in iso:  # tronque les fractions de seconde variables
        head, tail = iso.split("+"); head = head.split(".")[0]; iso = head + "+" + tail
    return datetime.fromisoformat(iso).timestamp()

def local(u): return u.split("@")[0].lower() if u and "@" in u else u
def is_external(addr):
    if not addr or "@" not in addr: return False
    return addr.rsplit("@", 1)[1].lower() not in INTERNAL

def gelf(fields):
    data = json.dumps({k: v for k, v in fields.items() if v is not None}).encode()
    urllib.request.urlopen(urllib.request.Request(GELF, data=data, headers={"Content-Type": "application/json"}), timeout=10).read()

def params(ev):
    return {p.get("Name"): p.get("Value") for p in (ev.get("Parameters") or [])}

def enrich(ev):
    """Pose les flags semantiques de detection a partir de l'operation."""
    op = (ev.get("Operation") or "")
    out = {}
    # --- Exchange : regle de transfert / forwarding ---
    if op in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox"):
        pr = params(ev)
        targets = []
        for key in ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo",
                    "ForwardingSmtpAddress", "ForwardingAddress"):
            if pr.get(key):
                targets.append(str(pr[key]))
        joined = " ".join(targets)
        # adresses SMTP grossierement extraites
        addrs = [t.strip("[]<> ") for chunk in joined.replace(";", " ").split() for t in [chunk] if "@" in t]
        ext = [a for a in addrs if is_external(a)]
        if ext:
            out["_forward_external"] = 1
            out["_fwd_target"] = ", ".join(ext)[:300]
    # --- Exchange : delegation de boite ---
    if op in ("Add-MailboxPermission", "Add-RecipientPermission"):
        out["_mailbox_deleg"] = 1
        pr = params(ev)
        out["_deleg_target"] = str(pr.get("User") or pr.get("Trustee") or "")[:200] or None
    # --- SharePoint / OneDrive : partage externe / lien anonyme ---
    # NB : 'CompanyLinkCreated/Used' = lien a l'echelle de l'ORG (interne par definition)
    # -> JAMAIS un partage externe. On l'exclut (audit FP : 248/268 FP venaient de la,
    # le domaine du tenant n'etant pas dans M365_INTERNAL_DOMAINS). Le vrai risque
    # (AnonymousLink*) ne genere de toute facon aucun de ces events.
    if op in ("AnonymousLinkCreated", "AnonymousLinkUsed", "SecureLinkCreated",
              "AddedToSecureLink", "SharingInvitationCreated"):
        # externe seulement si invite hors domaine, ou lien anonyme (toujours risque)
        tgt = ev.get("TargetUserOrGroupName") or ev.get("UserId") or ""
        # acteur systeme SharePoint (app@sharepoint) = jamais un partage humain externe
        actor = (ev.get("UserId") or "").lower()
        if (op.startswith("Anonymous") or is_external(tgt)) and actor != "app@sharepoint":
            out["_external_share"] = 1
            out["_share_target"] = str(tgt)[:200] or None
            out["_share_file"] = ev.get("SourceFileName") or ev.get("ObjectId")
    return out

def main():
    tok = token()
    ensure_subscriptions(tok)
    st = load_state(); seen = set(st.get("seen", [])); sent = 0
    now = datetime.now(timezone.utc)
    end = now.strftime("%Y-%m-%dT%H:%M:%S")
    for ct in CONTENT_TYPES:
        # fenetre : depuis le dernier passage -30 min d'overlap, borne a 24h (limite API)
        last = st.get(ct)
        start_dt = (datetime.fromisoformat(last).replace(tzinfo=timezone.utc) - timedelta(minutes=30)) if last else (now - timedelta(hours=24))
        start_dt = max(start_dt, now - timedelta(hours=24))
        start = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
        url = f"{BASE}/subscriptions/content?contentType={ct}&startTime={start}&endTime={end}"
        while url:
            try:
                resp = req(tok, url)
            except urllib.error.HTTPError as e:
                log(f"{ct} list KO {e.code}"); break
            blobs = json.load(resp)
            nxt = resp.headers.get("NextPageUri")
            for b in blobs:
                cid = b.get("contentId")
                if not cid or cid in seen: continue
                seen.add(cid)
                try:
                    events = json.load(req(tok, b["contentUri"]))
                except Exception as e:
                    log(f"blob KO: {e}"); continue
                for ev in events:
                    ts = ev.get("CreationTime")
                    if not ts: continue
                    msg = {
                        "version": "1.1", "host": "manage.office.com",
                        "short_message": f"M365 {ev.get('Workload','?')} {ev.get('Operation','?')} {local(ev.get('UserId'))}",
                        "timestamp": epoch(ts),
                        "_event_source": "m365", "_m365_type": "activity",
                        "_m365_workload": ev.get("Workload"),
                        "_event_action": ev.get("Operation"),
                        "_user": local(ev.get("UserId")), "_upn": ev.get("UserId"),
                        "_src_ip": clean_ip(ev.get("ClientIP") or ev.get("ClientIPAddress") or ev.get("ActorIpAddress")),
                        "_result": ev.get("ResultStatus"),
                        "_object": ev.get("ObjectId"),
                        "_m365_id": ev.get("Id"),
                    }
                    msg.update(enrich(ev))
                    try: gelf(msg); sent += 1
                    except Exception as e: log(f"gelf KO: {e}")
            url = nxt
        st[ct] = end
    st["seen"] = list(seen)
    save_state(st)
    log(f"OK - {sent} evenement(s) d'activite envoye(s)")

if __name__ == "__main__":
    try: main()
    except Exception as e:
        log(f"ERREUR: {e}"); sys.exit(1)
PYEOF
chmod 700 /usr/local/sbin/omni-m365-activity

cat > /etc/systemd/system/omni-m365-activity.service <<'EOF'
[Unit]
Description=Collecte O365 Management Activity (Exchange/SharePoint) -> Graylog
After=graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-m365-activity
EOF
cat > /etc/systemd/system/omni-m365-activity.timer <<'EOF'
[Unit]
Description=Declencheur collecte activite M365 (10 min)
[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
RandomizedDelaySec=60
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-m365-activity.timer >/dev/null 2>&1
echo
echo "Premiere collecte : systemctl start omni-m365-activity.service ; journalctl -u omni-m365-activity -n 5"
echo "=== 18-m365-activity.sh termine. Relancer 14 pour les widgets activite. ==="
