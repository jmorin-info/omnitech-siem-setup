#!/usr/bin/env bash
# =============================================================================
# 66-threatintel.sh - Renseignement sur les menaces (IOC abuse.ch)
#   Complete le Threat Intel natif (Tor/Spamhaus) par des feeds IOC a jour :
#     - Feodo Tracker  : IP de C2 (botnets) -> lookup ti-c2-ip
#     - URLhaus        : domaines de distribution malware -> lookup ti-mal-domain
#   Collecteur /usr/local/sbin/omni-ti-feeds (stdlib) -> CSV /etc/graylog/lookup,
#   timer quotidien. Pipeline "OMNI - Threat Intel IOC" (FortiGate IP + DNS) ->
#   tags c2_ioc / malware_domain + alertes. MITRE T1071 / T1071.004.
#   Idempotent. Prerequis : 11/12 (pipelines) + 37 (MITRE). Egress SIEM -> abuse.ch.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
LOOKUP_DIR=/etc/graylog/lookup

echo "==> [1/5] Collecteur de feeds /usr/local/sbin/omni-ti-feeds"
cat > /usr/local/sbin/omni-ti-feeds <<'PYEOF'
#!/usr/bin/env python3
"""Telecharge les feeds IOC abuse.ch -> CSV lookups Graylog. Stdlib only."""
import csv, io, os, urllib.request
from urllib.parse import urlparse
LOOKUP = "/etc/graylog/lookup"

def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "omni-siem-ti/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")

def write_csv(path, header, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f); w.writerow(header)
        for r in rows: w.writerow(r)
    os.replace(tmp, path)
    try: os.chmod(path, 0o644)
    except OSError: pass

def feodo():
    out = {}
    try:
        txt = fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
    except Exception as e:
        print("feodo KO:", e); return out
    for row in csv.reader(io.StringIO(txt)):
        if not row or row[0].startswith("#") or row[0] == "first_seen_utc":
            continue
        # first_seen,dst_ip,dst_port,c2_status,last_online,malware
        if len(row) >= 6 and row[1]:
            out[row[1].strip()] = row[5].strip() or "C2"
    return out

def urlhaus():
    out = {}
    try:
        txt = fetch("https://urlhaus.abuse.ch/downloads/text_recent/")
    except Exception as e:
        print("urlhaus KO:", e); return out
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = urlparse(line).hostname
        if host and "." in host and not host.replace(".", "").isdigit():
            out[host.lower()] = "urlhaus"
    return out

c2 = feodo(); dom = urlhaus()
if c2:  write_csv(f"{LOOKUP}/ti-c2-ip.csv", ["ip", "malware"], sorted(c2.items()))
if dom: write_csv(f"{LOOKUP}/ti-mal-domain.csv", ["domain", "source"], sorted(dom.items()))
print(f"IOC: {len(c2)} IP C2 (Feodo), {len(dom)} domaines (URLhaus)")
PYEOF
chmod 755 /usr/local/sbin/omni-ti-feeds
# seed initial (sinon les lookups pointent vers des CSV absents)
[[ -f ${LOOKUP_DIR}/ti-c2-ip.csv ]]     || printf 'ip,malware\n' > ${LOOKUP_DIR}/ti-c2-ip.csv
[[ -f ${LOOKUP_DIR}/ti-mal-domain.csv ]] || printf 'domain,source\n' > ${LOOKUP_DIR}/ti-mal-domain.csv
chown root:graylog ${LOOKUP_DIR}/ti-*.csv 2>/dev/null || true
/usr/local/sbin/omni-ti-feeds && ok "feeds telecharges" || warn "telechargement feeds KO (egress abuse.ch ?)"

echo "==> [2/5] Timer quotidien (refresh 05:15)"
cat > /etc/systemd/system/omni-ti-feeds.service <<'EOF'
[Unit]
Description=OMNI - Refresh feeds threat intel (abuse.ch)
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ti-feeds
EOF
cat > /etc/systemd/system/omni-ti-feeds.timer <<'EOF'
[Unit]
Description=OMNI - Threat intel feeds (quotidien)
[Timer]
OnCalendar=*-*-* 05:15:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now omni-ti-feeds.timer >/dev/null 2>&1 && ok "timer actif"

echo "==> [3/5] Tables de lookup"
ensure_lookup() {  # nom titre csv key val
  local NAME="$1" TITLE="$2" CSV="$3" KEY="$4" VAL="$5" AID CID
  AID="$(api_get "/system/lookup/adapters" | jq -r --arg n "omni-${NAME}-adapter" '.data_adapters[]?|select(.name==$n)|.id')"
  if [[ -z "$AID" ]]; then
    AID="$(jq -n --arg n "omni-${NAME}-adapter" --arg t "$TITLE" --arg p "${LOOKUP_DIR}/${CSV}" --arg k "$KEY" --arg v "$VAL" \
      '{name:$n,title:$t,description:"66-threatintel.sh",config:{type:"csvfile",path:$p,separator:",",quotechar:"\"",key_column:$k,value_column:$v,check_interval:600,case_insensitive_lookup:true,cidr_lookup:false}}' \
      | api_post "/system/lookup/adapters" | jqr '.id')"
  fi
  CID="$(api_get "/system/lookup/caches" | jq -r --arg n "omni-${NAME}-cache" '.caches[]?|select(.name==$n)|.id')"
  if [[ -z "$CID" ]]; then
    CID="$(jq -n --arg n "omni-${NAME}-cache" --arg t "$TITLE" '{name:$n,title:$t,description:"66",config:{type:"guava_cache",max_size:100000,expire_after_access:600,expire_after_access_unit:"SECONDS",expire_after_write:600,expire_after_write_unit:"SECONDS",ignore_null:false,ttl_empty:600,ttl_empty_unit:"SECONDS"}}' \
      | api_post "/system/lookup/caches" | jqr '.id')"
  fi
  if [[ -z "$(api_get "/system/lookup/tables" | jq -r --arg n "omni-${NAME}" '.lookup_tables[]?|select(.name==$n)|.id')" ]]; then
    jq -n --arg n "omni-${NAME}" --arg t "$TITLE" --arg a "$AID" --arg c "$CID" \
      '{name:$n,title:$t,description:"66",data_adapter_id:$a,cache_id:$c,default_single_value:"",default_single_value_type:"NULL",default_multi_value:"",default_multi_value_type:"NULL"}' \
      | api_post "/system/lookup/tables" | jqr '.id' >/dev/null && ok "table omni-${NAME}" || warn "table ${NAME} KO"
  else skip "table omni-${NAME} existe"; fi
}
ensure_lookup "ti-c2-ip"     "TI Feodo C2 IP -> malware"   "ti-c2-ip.csv"     "ip"     "malware"
ensure_lookup "ti-mal-domain" "TI URLhaus domaine -> src"  "ti-mal-domain.csv" "domain" "source"

echo "==> [4/5] Regles de detection (IP C2 + domaine malveillant)"
# Graylog pipeline n'accepte AUCUN conditionnel dans le 'then' (ni ternaire, ni
# if/else bloc) -> une regle PAR condition, la logique va dans le 'when'.
ensure_rule "omni-ti-10-c2-dest" <<'EOF'
rule "omni-ti-10-c2-dest"
when
  to_string($message.event_source) == "fortigate"
  AND ! is_null(lookup_value("omni-ti-c2-ip", to_string($message.dest_ip)))
then
  set_field("ti_c2_ip", to_string($message.dest_ip));
  set_field("ti_c2_malware", to_string(lookup_value("omni-ti-c2-ip", to_string($message.dest_ip))));
  set_field("alert_tag", "c2_ioc");
end
EOF
ensure_rule "omni-ti-10-c2-src" <<'EOF'
rule "omni-ti-10-c2-src"
when
  to_string($message.event_source) == "fortigate"
  AND ! is_null(lookup_value("omni-ti-c2-ip", to_string($message.src_ip)))
then
  set_field("ti_c2_ip", to_string($message.src_ip));
  set_field("ti_c2_malware", to_string(lookup_value("omni-ti-c2-ip", to_string($message.src_ip))));
  set_field("alert_tag", "c2_ioc");
end
EOF
ensure_rule "omni-ti-10-mal-dns" <<'EOF'
rule "omni-ti-10-mal-dns"
when
  has_field("dns_query") AND ! is_null(lookup_value("omni-ti-mal-domain", to_string($message.dns_query)))
then
  set_field("ti_mal_domain", to_string($message.dns_query));
  set_field("alert_tag", "malware_domain");
end
EOF
ensure_rule "omni-ti-10-mal-qname" <<'EOF'
rule "omni-ti-10-mal-qname"
when
  has_field("qname") AND ! is_null(lookup_value("omni-ti-mal-domain", to_string($message.qname)))
then
  set_field("ti_mal_domain", to_string($message.qname));
  set_field("alert_tag", "malware_domain");
end
EOF
PL="$(ensure_pipeline "OMNI - Threat Intel IOC" <<'PIPE'
pipeline "OMNI - Threat Intel IOC"
stage 18 match either
rule "omni-ti-10-c2-dest"
rule "omni-ti-10-c2-src"
rule "omni-ti-10-mal-dns"
rule "omni-ti-10-mal-qname"
end
PIPE
)"
for ST in "OMNI - FortiGate" "OMNI - Sysmon" "OMNI - Windows autres"; do
  SID="$(get_stream_id "$ST")"; [[ -n "$SID" ]] && connect_pipeline "$SID" "$PL"
done

echo "==> [5/5] MITRE + alertes"
CSV="lookups/mitre-attack.csv"
grep -q '^c2_ioc,'         "$CSV" || echo 'c2_ioc,T1071,Application Layer Protocol,Command and Control,critique,9' >> "$CSV"
grep -q '^malware_domain,' "$CSV" || echo 'malware_domain,T1071.004,DNS,Command and Control,eleve,8' >> "$CSV"
install -m 644 "$CSV" /etc/graylog/lookup/mitre-attack.csv; chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "MITRE c2_ioc / malware_domain"
NMAIL="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Mail equipe IT")|.id')"
NTEAMS="$(api_get "/events/notifications?per_page=100" | jq -r '.notifications[]?|select(.title=="OMNI - Teams SOC")|.id')"
mk_ti_alert() {  # titre query
  local T="$1" Q="$2" SID
  SID="$(get_stream_id 'OMNI - FortiGate')"
  api_get "/events/definitions?per_page=300" | jq -e --arg t "$T" '.event_definitions[]|select(.title==$t)' >/dev/null && { skip "alerte '$T' existe"; return; }
  local NF; NF="$(jq -n --arg m "$NMAIL" --arg tm "$NTEAMS" '[{notification_id:$m,notification_parameters:null}]+(if $tm=="" or $tm=="null" then [] else [{notification_id:$tm,notification_parameters:null}] end)')"
  jq -n --arg t "$T" --arg q "$Q" --argjson n "$NF" '{title:$t,description:"Threat intel abuse.ch (66-threatintel.sh)",priority:3,alert:true,
    config:{type:"aggregation-v1",query:$q,query_parameters:[],streams:[],group_by:[],series:[{id:"count()",type:"count"}],
      conditions:{expression:{expr:">=",left:{expr:"number-ref",ref:"count()"},right:{expr:"number",value:1}}},
      search_within_ms:300000,execute_every_ms:300000,use_cron_scheduling:false,event_limit:50},
    field_spec:{},key_spec:[],notification_settings:{grace_period_ms:3600000,backlog_size:10},notifications:$n}' \
    | post_entity "/events/definitions?schedule=true" | jqr '.id' >/dev/null && ok "alerte '$T'" || warn "alerte '$T' KO"
}
mk_ti_alert "OMNI - C2 connu contacte (IP malveillante abuse.ch/Feodo)" "alert_tag:c2_ioc"
mk_ti_alert "OMNI - Domaine malveillant resolu (URLhaus)" "alert_tag:malware_domain"

echo
echo "=== 66-threatintel.sh termine. Feeds rafraichis quotidiennement (05:15)."
echo "    Tags c2_ioc / malware_domain poses des qu'un flux matche un IOC. Relancer 14. ==="
