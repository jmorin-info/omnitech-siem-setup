#!/usr/bin/env bash
# =============================================================================
# 48-ndr-scan.sh - Active la detection de scan reseau interne (omni-ndr-scan)
#   1. mappe network_scan -> MITRE T1046 (CSV 37)
#   2. route event_source=ndr_scan -> INT (+ exclusion M365)
#   3. timer 15 min + premier passage
# Idempotent. Prerequis : 21 + 37. Relance 13 + 14 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

echo "==> [0/3] Detecteur omni-ndr-scan (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo,
# reproductible. + resserrement structurel : on ignore le balayage horizontal dont les
# SEULS ports refuses sont SNMP (161/162) = supervision (NMS/sonde), pas un scan lateral.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-ndr-scan <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ndr-scan - Detection de scan reseau / reconnaissance (FortiGate deny).
#   Agrege les connexions REFUSEES par source INTERNE et mesure la cardinalite des
#   destinations / ports -> balayage HORIZONTAL (1 src -> N hotes) ou scan VERTICAL
#   (1 src -> N ports sur peu d'hotes). Cible les sources INTERNES (mouvement lateral /
#   reconnaissance interne), pas le scan Internet entrant (constant, peu actionnable).
#   Emet GELF event_source=ndr_scan, alert_tag=network_scan (T1046/T1018).
# Lance par timer (15 min). Config 00-vars.env : SCAN_*.
# =============================================================================
import json, os, re, sys, urllib.request

OS_URL = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM = "bx-it-graylog-vm"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
WINDOW_M  = int(ENV.get("SCAN_WINDOW_M", "60"))    # fenetre glissante (scans souvent lents)
HOST_MIN  = int(ENV.get("SCAN_HOST_MIN", "30"))    # dest_ip distincts -> horizontal
PORT_MIN  = int(ENV.get("SCAN_PORT_MIN", "25"))    # dest_port distincts -> vertical
VERT_MAXH = int(ENV.get("SCAN_VERT_MAXHOSTS", "3"))# vertical = ports nombreux sur peu d'hotes
ALLOW_SRC = set(x.strip() for x in (ENV.get("SCAN_ALLOW_SRC", "")).split(",") if x.strip())  # infra de gestion legitime
MON_PORTS = {"161", "162"}                         # SNMP = supervision (NMS/sonde), pas du scan lateral
# Ports d'ADMINISTRATION / mouvement LATERAL. Un balayage HORIZONTAL qui n'en refuse AUCUN
# = trafic poste benin bloque (NetBIOS 137/138, push apps, proxy), PAS de la reconnaissance.
# Mesure : 39/46 sources horizontales ont 0 port lateral (bruit) ; les 7 restantes (dont DC)
# ont du vrai probing lateral. Le scan VERTICAL (multi-ports) reste alerte sans condition.
LATERAL_PORTS = ["445", "139", "3389", "5985", "5986", "22", "23", "135", "1433", "3306", "5432", "389", "636", "88", "21", "5900"]

def es(body):
    req = urllib.request.Request(f"{OS_URL}/omni-fortigate_*/_search", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ndr_scan")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def main():
    agg = es({"size": 0,
        "query": {"bool": {"must": [{"term": {"action": "deny"}},
                                    {"term": {"src_ip_reserved_ip": True}},
                                    {"range": {"timestamp": {"gte": f"now-{WINDOW_M}m"}}}]}},
        "aggs": {"s": {"terms": {"field": "src_ip", "size": 200},
                       "aggs": {"dips": {"cardinality": {"field": "dest_ip"}},
                                "dports": {"cardinality": {"field": "dest_port"}},
                                "lateral": {"filter": {"terms": {"dest_port": LATERAL_PORTS}}},
                                "topports": {"terms": {"field": "dest_port", "size": 6}}}}}})
    found = 0
    for b in agg["aggregations"]["s"]["buckets"]:
        src = b["key"]; ndip = b["dips"]["value"]; ndport = b["dports"]["value"]
        if src in ALLOW_SRC:
            continue                       # source d'infra de gestion legitime (allowlist)
        horizontal = ndip >= HOST_MIN
        vertical = ndport >= PORT_MIN and ndip <= VERT_MAXH
        if not (horizontal or vertical):
            continue
        ports = ",".join(str(p["key"]) for p in b["topports"]["buckets"])
        # Supervision SNMP : balayage horizontal dont les SEULS ports refuses sont SNMP
        # (161/162) = NMS/sonde interrogeant le parc, PAS du scan lateral. Couvre tous les
        # superviseurs sans liste d'IP. (Le scan vertical / multi-ports reste alerte.)
        portset = set(str(p["key"]) for p in b["topports"]["buckets"])
        if horizontal and not vertical and portset and portset <= MON_PORTS:
            continue
        # Balayage HORIZONTAL sans AUCUN port d'admin/lateral refuse = fan-out poste benin
        # (NetBIOS/push/proxy), pas de la recon. Le scan vertical/multi-ports n'est pas concerne.
        nlat = b.get("lateral", {}).get("doc_count", 0)
        if horizontal and not vertical and nlat == 0:
            continue
        stype = "horizontal" if horizontal else "vertical"
        found += 1
        gelf({"event_source": "ndr_scan", "alert_tag": "network_scan",
              "scan_type": stype, "entity_host": src, "scan_dest_count": int(ndip),
              "scan_port_count": int(ndport), "scan_deny": b["doc_count"], "scan_top_ports": ports,
              "scan_lateral_deny": int(nlat),
              "short_message": f"SCAN {stype} depuis {src} : {int(ndip)} hotes / {int(ndport)} ports refuses ({b['doc_count']} deny)"})
        print(f"  [scan {stype}] {src}: dest_ips={int(ndip)} dest_ports={int(ndport)} deny={b['doc_count']}")
    print(f"[ndr-scan] sources_internes_analysees={len(agg['aggregations']['s']['buckets'])} scans={found} (fenetre {WINDOW_M}m)")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ndr-scan KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ndr-scan
ok "detecteur omni-ndr-scan ecrit (versionne + skip SNMP)"

echo "==> [1/3] Mapping MITRE (network_scan -> T1046)"
CSV="lookups/mitre-attack.csv"
grep -q '^network_scan,' "${CSV}" || { echo 'network_scan,T1046,Network Service Discovery,Discovery,eleve,5' >> "${CSV}"; ok "MITRE +network_scan"; }
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/3] Routage event_source=ndr_scan -> INT (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"; [[ -n "${ST}" ]] || die "stream interne introuvable."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "ndr_scan"; then skip "regle ndr_scan deja la"
else jq -n '{field:"event_source",type:1,value:"ndr_scan",inverted:false,description:"detection scan reseau"}' \
  | api_post "/streams/${ST}/rules" >/dev/null && ok "regle ndr_scan ajoutee"; fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "ndr_scan"; then skip "M365 exclut deja ndr_scan"
  else jq -n '{field:"event_source",type:1,value:"ndr_scan",inverted:true,description:"exclusion ndr_scan (anti-dup)"}' \
    | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut ndr_scan"; fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [3/3] Service + timer (15 min) + premier passage"
cat > /etc/systemd/system/omni-ndr-scan.service <<'EOF'
[Unit]
Description=OMNI SIEM - detection de scan reseau interne
After=network-online.target graylog-server.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ndr-scan
Nice=15
EOF
cat > /etc/systemd/system/omni-ndr-scan.timer <<'EOF'
[Unit]
Description=OMNI SIEM - scan reseau (15 min)
[Timer]
OnBootSec=180
OnUnitActiveSec=900
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-ndr-scan.timer >/dev/null 2>&1 || true
systemctl start omni-ndr-scan.service && ok "$(journalctl -u omni-ndr-scan.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"
echo "=== 48-ndr-scan.sh termine. Relancer 13 (alerte) + 14 (widget/couleur). ==="
