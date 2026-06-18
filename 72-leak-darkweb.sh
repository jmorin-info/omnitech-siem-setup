#!/usr/bin/env bash
# =============================================================================
# 72-leak-darkweb.sh - Module "Fuites & Dark Web" (assemblage inspire BreachRadar)
#   Collecteurs SIEM-natifs -> GELF (event_source=leak_intel) -> alertes + page console :
#     - omni-leak-ransomlook : sites d'extorsion ransomware (OMNITECH/partenaires
#       nommes ?) via RansomLook. GRATUIT, sans cle.
#     - omni-leak-hibp        : comptes @domaine dans des fuites connues (HIBP domain
#       search). PRET-A-BRANCHER (HIBP_API_KEY + domaine verifie).
#     - omni-leak-dehashed    : combolists / dark web (Dehashed). PRET-A-BRANCHER.
#   + GitHub (deja en 70-leak-github.sh). Tout converge en event_source=leak_intel.
#   Idempotent. Egress verifie (ransomlook.io / haveibeenpwned.com / api.dehashed.com).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/5] Config /etc/default/omni-leak (ajout cles fuites/dark web)"
[[ -f /etc/default/omni-leak ]] || { echo 'GELF_URL=http://127.0.0.1:12201/gelf' > /etc/default/omni-leak; chmod 600 /etc/default/omni-leak; }
add_key() { grep -q "^$1=" /etc/default/omni-leak || echo "$1=$2" >> /etc/default/omni-leak; }
add_key RANSOMLOOK_TERMS "omnitech,omnitech-security"
add_key RANSOMLOOK_STATE "/var/lib/omni-leak/ransomlook.json"
add_key HIBP_API_KEY ""
add_key HIBP_DOMAIN "omnitech-security.fr"
add_key DEHASHED_EMAIL ""
add_key DEHASHED_KEY ""
add_key DEHASHED_DOMAIN "omnitech-security.fr"
mkdir -p /var/lib/omni-leak
ok "config /etc/default/omni-leak"

echo "==> [2/5] Collecteur RansomLook (gratuit)"
cat > /usr/local/sbin/omni-leak-ransomlook <<'PYEOF'
#!/usr/bin/env python3
"""RansomLook -> GELF : OMNITECH/partenaires nommes sur un site d'extorsion. Stdlib."""
import json, os, urllib.request
ENV = {}
for l in open("/etc/default/omni-leak"):
    if "=" in l and not l.lstrip().startswith("#"):
        k, v = l.strip().split("=", 1); ENV[k] = v.strip()
GELF = ENV.get("GELF_URL", "http://127.0.0.1:12201/gelf")
TERMS = [t.strip().lower() for t in ENV.get("RANSOMLOOK_TERMS", "omnitech").split(",") if t.strip()]
STATE = ENV.get("RANSOMLOOK_STATE", "/var/lib/omni-leak/ransomlook.json")
def gelf(f):
    f.update({"version": "1.1", "host": "ransomlook.io"})
    urllib.request.urlopen(urllib.request.Request(GELF, data=json.dumps(f).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()
try:
    posts = json.load(urllib.request.urlopen(urllib.request.Request(
        "https://www.ransomlook.io/api/recent", headers={"User-Agent": "omni-siem/1.0"}), timeout=30))
except Exception as e:
    print("ransomlook KO:", e); raise SystemExit(0)
try:
    seen = set(json.load(open(STATE)))
except Exception:
    seen = set()
new = 0
for p in posts:
    blob = ((p.get("post_title") or "") + " " + (p.get("description") or "")).lower()
    if any(t in blob for t in TERMS):
        key = (p.get("post_title") or "") + (p.get("discovered") or "")
        if key in seen:
            continue
        seen.add(key); new += 1
        gelf({"short_message": "RANSOMWARE: '%s' apparait sur un site d'extorsion" % p.get("post_title"),
              "level": 2, "_event_source": "leak_intel", "_leak_source": "ransomlook",
              "_alert_tag": "ransomware_mention", "_leak_victim": p.get("post_title"),
              "_leak_discovered": p.get("discovered"), "_event_action": "ransomware_leak_site"})
os.makedirs(os.path.dirname(STATE), exist_ok=True)
json.dump(sorted(seen), open(STATE + ".tmp", "w")); os.replace(STATE + ".tmp", STATE)
print("ransomlook: %d posts analyses, %d mention(s) OMNITECH" % (len(posts), new))
PYEOF
chmod 755 /usr/local/sbin/omni-leak-ransomlook
/usr/local/sbin/omni-leak-ransomlook && ok "ransomlook OK" || warn "ransomlook KO"

echo "==> [3/5] Collecteurs HIBP + Dehashed (prets-a-brancher)"
cat > /usr/local/sbin/omni-leak-hibp <<'PYEOF'
#!/usr/bin/env python3
"""HIBP domain search -> GELF : comptes @domaine dans des fuites connues. Stdlib."""
import json, urllib.request, urllib.error
ENV = {}
for l in open("/etc/default/omni-leak"):
    if "=" in l and not l.lstrip().startswith("#"):
        k, v = l.strip().split("=", 1); ENV[k] = v.strip()
TOK = ENV.get("HIBP_API_KEY", ""); DOM = ENV.get("HIBP_DOMAIN", "")
GELF = ENV.get("GELF_URL", "http://127.0.0.1:12201/gelf")
if not TOK:
    print("HIBP_API_KEY absent -> arret propre (cle + domaine verifie requis)."); raise SystemExit(0)
def gelf(f):
    f.update({"version": "1.1", "host": "haveibeenpwned.com"})
    urllib.request.urlopen(urllib.request.Request(GELF, data=json.dumps(f).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()
try:
    doc = json.load(urllib.request.urlopen(urllib.request.Request(
        "https://haveibeenpwned.com/api/v3/breacheddomain/%s" % DOM,
        headers={"hibp-api-key": TOK, "User-Agent": "omni-siem"}), timeout=30))
except urllib.error.HTTPError as e:
    print("HIBP HTTP", e.code, "(cle/abonnement/domaine non verifie ?)"); raise SystemExit(0)
n = 0
for alias, breaches in (doc or {}).items():
    n += 1
    gelf({"short_message": "Compte expose: %s@%s dans %d fuite(s)" % (alias, DOM, len(breaches)),
          "level": 4, "_event_source": "leak_intel", "_leak_source": "hibp",
          "_alert_tag": "credential_leak", "_leak_account": "%s@%s" % (alias, DOM),
          "_leak_breaches": ", ".join(breaches), "_event_action": "breached_account"})
print("HIBP: %d compte(s) expose(s) pour %s" % (n, DOM))
PYEOF
cat > /usr/local/sbin/omni-leak-dehashed <<'PYEOF'
#!/usr/bin/env python3
"""Dehashed -> GELF : enregistrements fuites/combolists pour le domaine. Stdlib."""
import base64, json, urllib.request, urllib.error
ENV = {}
for l in open("/etc/default/omni-leak"):
    if "=" in l and not l.lstrip().startswith("#"):
        k, v = l.strip().split("=", 1); ENV[k] = v.strip()
EM = ENV.get("DEHASHED_EMAIL", ""); KEY = ENV.get("DEHASHED_KEY", ""); DOM = ENV.get("DEHASHED_DOMAIN", "")
GELF = ENV.get("GELF_URL", "http://127.0.0.1:12201/gelf")
if not (EM and KEY):
    print("DEHASHED_EMAIL/KEY absents -> arret propre."); raise SystemExit(0)
def gelf(f):
    f.update({"version": "1.1", "host": "dehashed.com"})
    urllib.request.urlopen(urllib.request.Request(GELF, data=json.dumps(f).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()
auth = base64.b64encode(("%s:%s" % (EM, KEY)).encode()).decode()
try:
    doc = json.load(urllib.request.urlopen(urllib.request.Request(
        "https://api.dehashed.com/search?query=domain:%s&size=100" % DOM,
        headers={"Authorization": "Basic " + auth, "Accept": "application/json", "User-Agent": "omni-siem"}), timeout=30))
except urllib.error.HTTPError as e:
    print("Dehashed HTTP", e.code); raise SystemExit(0)
n = 0
for e in (doc.get("entries") or [])[:100]:
    em = e.get("email") or e.get("username")
    if not em:
        continue
    n += 1
    gelf({"short_message": "Fuite dark web: %s (Dehashed)" % em, "level": 4,
          "_event_source": "leak_intel", "_leak_source": "dehashed", "_alert_tag": "credential_leak",
          "_leak_account": em, "_leak_db": e.get("database_name"), "_event_action": "darkweb_record"})
print("Dehashed: %d enregistrement(s) pour %s" % (n, DOM))
PYEOF
chmod 755 /usr/local/sbin/omni-leak-hibp /usr/local/sbin/omni-leak-dehashed
ok "HIBP + Dehashed installes (en attente de cles)"

echo "==> [4/5] Timers quotidiens"
for svc in ransomlook hibp dehashed; do
  cat > /etc/systemd/system/omni-leak-${svc}.service <<EOF
[Unit]
Description=OMNI - Leak intel ${svc}
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-leak-${svc}
EOF
  H=$(( 6 + RANDOM % 2 )); M=$(( RANDOM % 60 ))
  cat > /etc/systemd/system/omni-leak-${svc}.timer <<EOF
[Unit]
Description=OMNI - Leak ${svc} (quotidien)
[Timer]
OnCalendar=*-*-* 0${H}:$(printf %02d $M):00
Persistent=true
[Install]
WantedBy=timers.target
EOF
done
systemctl daemon-reload
systemctl enable --now omni-leak-ransomlook.timer omni-leak-hibp.timer omni-leak-dehashed.timer >/dev/null 2>&1 && ok "timers actifs"

echo "==> [5/5] MITRE + alertes"
CSV="lookups/mitre-attack.csv"
grep -q '^ransomware_mention,' "$CSV" || echo 'ransomware_mention,T1657,Financial Theft,Impact,critique,10' >> "$CSV"
grep -q '^credential_leak,'     "$CSV" || echo 'credential_leak,T1589.001,Gather Victim Identity: Credentials,Reconnaissance,eleve,7' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE ransomware_mention / credential_leak"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
mk_leak_alert() {
  local T="$1" Q="$2" P="$3"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T'"; return; }
  local NF; NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
  jq -n --arg t "$T" --arg q "$Q" --argjson p "$P" --argjson n "$NF" '{title:$t,description:"Module Fuites & Dark Web (72-leak-darkweb.sh)",priority:$p,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:86400000,execute_every_ms:86400000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:86400000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"
}
mk_leak_alert "OMNI - RANSOMWARE : OMNITECH nomme sur un site d'extorsion" "alert_tag:ransomware_mention" 3
mk_leak_alert "OMNI - Comptes/donnees OMNITECH exposes (fuite / dark web)" "alert_tag:credential_leak OR alert_tag:github_leak" 3

echo
echo "=== 72 termine. RansomLook actif (gratuit). Pour HIBP/Dehashed : renseigner les"
echo "    cles dans /etc/default/omni-leak. Page console 'Fuites & Dark Web' a venir. ==="
