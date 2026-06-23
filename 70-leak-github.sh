#!/usr/bin/env bash
# =============================================================================
# 70-leak-github.sh - Surveillance de fuites OMNITECH sur GitHub (public)
#   Collecteur omni-leak-github : interroge la GitHub Code Search API pour des
#   indicateurs OMNITECH (domaines, hotes internes) -> GELF -> alerte. Detecte
#   configs/cles/identifiants fuites en clair dans du code public.
#   Memes patrons que 66-threatintel (collecteur stdlib + timer + alerte).
#   PREREQUIS COTE JULIEN : un token GitHub READ-ONLY (Settings > Developer
#   settings > Fine-grained token, AUCUN scope d'ecriture, "Public repositories")
#   dans /etc/default/omni-leak. Sans token, la code search API refuse (collecteur
#   s'arrete proprement). Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Config /etc/default/omni-leak"
if [[ ! -f /etc/default/omni-leak ]]; then
  cat > /etc/default/omni-leak <<EOF
# Token GitHub READ-ONLY (fine-grained, public repos, aucun scope ecriture).
GITHUB_TOKEN=
# Termes recherches (separes par des virgules). Domaines + hotes internes haute-signal.
LEAK_TERMS=omnitech-security.fr,omnitech.security,bx-it-graylog-vm,bx-ad-01-it-vm
GELF_URL=http://127.0.0.1:12201/gelf
LEAK_STATE=/var/lib/omni-leak/seen.json
EOF
  chmod 600 /etc/default/omni-leak; ok "config creee (ajouter GITHUB_TOKEN)"
else skip "config existe"; fi
mkdir -p /var/lib/omni-leak

echo "==> [2/4] Collecteur /usr/local/sbin/omni-leak-github"
cat > /usr/local/sbin/omni-leak-github <<'PYEOF'
#!/usr/bin/env python3
"""Surveillance fuites OMNITECH sur GitHub (code search) -> GELF. Stdlib only."""
import json, os, time, urllib.request, urllib.parse, urllib.error

ENV = {}
with open("/etc/default/omni-leak") as f:
    for line in f:
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.strip().split("=", 1); ENV[k] = v.strip()

TOK = ENV.get("GITHUB_TOKEN", "").strip()
TERMS = [t.strip() for t in ENV.get("LEAK_TERMS", "").split(",") if t.strip()]
GELF = ENV.get("GELF_URL", "http://127.0.0.1:12201/gelf")
STATE = ENV.get("LEAK_STATE", "/var/lib/omni-leak/seen.json")

def log(m): print(m, flush=True)

if not TOK:
    log("GITHUB_TOKEN absent -> arret propre (ajouter le token read-only dans /etc/default/omni-leak)."); raise SystemExit(0)

def seen_load():
    try:
        with open(STATE) as f: return set(json.load(f))
    except Exception: return set()

def seen_save(s):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f: json.dump(sorted(s), f)
    os.replace(tmp, STATE)

def gelf(fields):
    fields.update({"version": "1.1", "host": "github.com"})
    req = urllib.request.Request(GELF, data=json.dumps(fields).encode(), headers={"Content-Type": "application/json"})
    try: urllib.request.urlopen(req, timeout=10).read()
    except Exception as e: log(f"gelf KO: {e}")

def search(term):
    q = urllib.parse.quote(f'"{term}"')
    url = f"https://api.github.com/search/code?q={q}&per_page=50"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOK}", "Accept": "application/vnd.github+json",
        "User-Agent": "omni-siem-leak/1.0", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=30)).get("items", [])
    except urllib.error.HTTPError as e:
        if e.code == 403:
            log("403 (rate limit / token insuffisant) -> pause"); time.sleep(60); return []
        if e.code == 422:
            return []  # requete invalide / rien
        raise

seen = seen_load(); new = 0
for term in TERMS:
    for it in search(term):
        url = it.get("html_url"); repo = (it.get("repository") or {}).get("full_name")
        if not url or url in seen: continue
        seen.add(url); new += 1
        gelf({"short_message": f"Fuite potentielle GitHub: '{term}' dans {repo} ({it.get('path')})",
              "level": 4, "_event_source": "leak_intel", "_leak_source": "github",
              "_alert_tag": "github_leak", "_event_action": "leak_found",
              "_leak_term": term, "_leak_repo": repo, "_leak_path": it.get("path"), "_leak_url": url})
    time.sleep(3)  # menagement rate limit code search (30/min)
seen_save(seen)
log(f"termine: {new} nouvelle(s) occurrence(s) sur {len(TERMS)} termes")
PYEOF
chmod 755 /usr/local/sbin/omni-leak-github
ok "collecteur installe"
/usr/local/sbin/omni-leak-github || true

echo "==> [3/4] Timer quotidien (06:45)"
cat > /etc/systemd/system/omni-leak-github.service <<'EOF'
[Unit]
Description=OMNI - Surveillance fuites GitHub
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-leak-github
EOF
cat > /etc/systemd/system/omni-leak-github.timer <<'EOF'
[Unit]
Description=OMNI - Fuites GitHub (quotidien)
[Timer]
OnCalendar=*-*-* 06:45:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now omni-leak-github.timer >/dev/null 2>&1 && ok "timer actif"

echo "==> [4/4] MITRE + alerte"
CSV="lookups/mitre-attack.csv"
grep -q '^github_leak,' "$CSV" || echo 'github_leak,T1552.001,Credentials In Files,Credential Access,eleve,7' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
T="OMNI - Fuite potentielle sur GitHub (données OMNITECH)"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null; then
  skip "alerte fuite GitHub existe"
else
  NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
  jq -n --arg t "$T" --argjson n "$NF" '{title:$t,description:"Indicateur OMNITECH trouve dans du code public (70-leak-github.sh). A verifier : config/cle/identifiant fuite.",priority:3,alert:true,
    config:{type:"aggregation-v1",query:"alert_tag:github_leak",query_parameters:[],streams:[],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:86400000,execute_every_ms:86400000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:86400000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte fuite GitHub creee" || warn "alerte KO"
fi

echo
echo "=== 70 termine. Ajouter un token GitHub read-only dans /etc/default/omni-leak,"
echo "    puis : systemctl start omni-leak-github ; journalctl -u omni-leak-github -n 20"
echo "    Pour HIBP/Dehashed (comptes employes fuites), dis-le-moi. ==="
