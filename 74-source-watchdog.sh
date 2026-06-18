#!/usr/bin/env bash
# =============================================================================
# 74-source-watchdog.sh - Detection de SOURCE SILENCIEUSE (SIEM aveugle)
#   Un collecteur qui decroche (agent mort, flux coupe, log desactive par un
#   attaquant) = angle mort. Le watchdog verifie la FRAICHEUR de chaque source
#   (max timestamp) vs un seuil par source ; au-dela -> GELF alert_tag=source_silent.
#   = preuve de surveillance de la journalisation (A.8.15) + anti-impair-defenses.
#   Timer toutes les 15 min. Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/4] Config /etc/default/omni-watchdog (seuils par source, en minutes)"
if [[ ! -f /etc/default/omni-watchdog ]]; then
  cat > /etc/default/omni-watchdog <<'EOF'
# Seuils de silence par source (minutes). Au-dela = alerte. Adapter a la cadence reelle.
WATCHDOG_SOURCES=fortigate:30,sysmon:30,windows_security:30,windows:90,vsphere:90,bunkerweb:240,m365:360,forti_dhcp:180,vaultwarden:1440,inventory:2880,veeam:4320,eset:4320,fortimanager:1440,adcs:2880
OPENSEARCH=http://127.0.0.1:9200
GELF_URL=http://127.0.0.1:12201/gelf
EOF
  chmod 600 /etc/default/omni-watchdog; ok "config creee"
else skip "config existe"; fi

echo "==> [2/4] Collecteur /usr/local/sbin/omni-source-watchdog"
cat > /usr/local/sbin/omni-source-watchdog <<'PYEOF'
#!/usr/bin/env python3
"""Watchdog fraicheur des sources -> GELF si une source decroche. Stdlib."""
import json, time, urllib.request
ENV = {}
for l in open("/etc/default/omni-watchdog"):
    if "=" in l and not l.lstrip().startswith("#"):
        k, v = l.strip().split("=", 1); ENV[k] = v.strip()
OS = ENV.get("OPENSEARCH", "http://127.0.0.1:9200")
GELF = ENV.get("GELF_URL", "http://127.0.0.1:12201/gelf")
TH = {}
for part in ENV.get("WATCHDOG_SOURCES", "").split(","):
    if ":" in part:
        s, m = part.split(":", 1)
        try: TH[s.strip()] = float(m)
        except ValueError: pass

def gelf(f):
    f.update({"version": "1.1", "host": "siem-watchdog"})
    urllib.request.urlopen(urllib.request.Request(GELF, data=json.dumps(f).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()

body = {"size": 0, "query": {"range": {"timestamp": {"gte": "now-30d"}}},
        "aggs": {"src": {"terms": {"field": "event_source", "size": 60},
                         "aggs": {"last": {"max": {"field": "timestamp"}}}}}}
req = urllib.request.Request(OS + "/omni-*/_search", data=json.dumps(body).encode(),
                            headers={"Content-Type": "application/json"})
res = json.load(urllib.request.urlopen(req, timeout=30))
now = time.time() * 1000
seen = {}
for b in res.get("aggregations", {}).get("src", {}).get("buckets", []):
    last = (b.get("last", {}) or {}).get("value")
    if last:
        seen[b["key"]] = last
alerts = 0
for src, thr in TH.items():
    last = seen.get(src)
    if last is None:
        gap = None
    else:
        gap = (now - last) / 60000.0
    if last is None or gap > thr:
        alerts += 1
        gap_txt = ">30j" if last is None else ("%d min" % int(gap))
        gelf({"short_message": "Source de collecte SILENCIEUSE: %s (silence %s, seuil %d min)" % (src, gap_txt, int(thr)),
              "level": 3, "_event_source": "siem_watchdog", "_alert_tag": "source_silent",
              "_silent_source": src, "_silent_gap_min": (-1 if last is None else int(gap)),
              "_silent_threshold_min": int(thr), "_event_action": "collection_gap"})
print("watchdog: %d source(s) surveillee(s), %d silencieuse(s)" % (len(TH), alerts))
PYEOF
chmod 755 /usr/local/sbin/omni-source-watchdog
/usr/local/sbin/omni-source-watchdog && ok "watchdog execute" || warn "watchdog KO"

echo "==> [3/4] Timer (toutes les 15 min)"
cat > /etc/systemd/system/omni-source-watchdog.service <<'EOF'
[Unit]
Description=OMNI - Watchdog fraicheur des sources
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-source-watchdog
EOF
cat > /etc/systemd/system/omni-source-watchdog.timer <<'EOF'
[Unit]
Description=OMNI - Watchdog sources (15 min)
[Timer]
OnCalendar=*:0/15
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now omni-source-watchdog.timer >/dev/null 2>&1 && ok "timer actif"

echo "==> [4/4] MITRE + alerte"
CSV="lookups/mitre-attack.csv"
grep -q '^source_silent,' "$CSV" || echo 'source_silent,T1562.001,Impair Defenses: Disable or Modify Tools,Defense Evasion,eleve,7' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE source_silent (T1562.001)"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
T="OMNI - Source de collecte silencieuse (SIEM aveugle)"
if api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null; then
  skip "alerte watchdog existe"
else
  NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
  jq -n --arg t "$T" --argjson n "$NF" '{title:$t,description:"Une source ne remonte plus dans le delai attendu = angle mort potentiel (74-source-watchdog.sh).",priority:3,alert:true,
    config:{type:"aggregation-v1",query:"alert_tag:source_silent",query_parameters:[],streams:[],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:1800000,execute_every_ms:1800000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:21600000,backlog_size:20},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte watchdog creee" || warn "alerte KO"
fi
echo
echo "=== 74 termine. Watchdog actif (15 min). Ajuster les seuils dans /etc/default/omni-watchdog. ==="
