#!/usr/bin/env bash
# =============================================================================
# 43-ndr-dns.sh - Active la detection d'exfiltration/tunneling DNS (omni-ndr-dns)
#   1. mappe dns_tunneling -> MITRE T1071.004 (DNS) dans le CSV (risk_score + ATT&CK)
#   2. route event_source=ndr_dns -> "OMNI - Interne SIEM" (+ exclusion M365)
#   3. timer systemd horaire + premier passage
# Idempotent. Prerequis : 21 (stream) + 37 (lookup MITRE). Relance 14 + 13 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
echo "==> [0/3] Detecteur omni-ndr-dns (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-ndr-dns <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ndr-dns - Detection d'exfiltration / tunneling DNS (entropie + structure).
#   Au-dela de Graylog : calcule l'ENTROPIE DE SHANNON et la structure des sous-
#   domaines DNS (Sysmon EID22). Le tunneling/exfil DNS (iodine, dnscat2, data
#   encode en base32) genere BEAUCOUP de sous-domaines LONGS et a HAUTE ENTROPIE
#   sous un meme domaine -> signature que l'agregation Graylog ne sait pas calculer.
#   Emet GELF event_source=ndr_dns, alert_tag=dns_tunneling (entity_host + domaine).
#   HONNETE : CDN/cloud generent aussi des sous-domaines -> allowlist (tunable).
# Lance par timer (toutes les heures). Config 00-vars.env : NDR_DNS_*.
# =============================================================================
import json, math, os, re, sys, urllib.request
from collections import defaultdict

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
WINDOW_H = int(ENV.get("NDR_DNS_WINDOW_H", "6"))
MIN_SUB  = int(ENV.get("NDR_DNS_MIN_SUB", "40"))     # sous-domaines distincts mini
MIN_ENT  = float(ENV.get("NDR_DNS_MIN_ENT", "3.6"))  # entropie moyenne mini (bits/char)
MIN_LEN  = int(ENV.get("NDR_DNS_MIN_LEN", "20"))     # longueur moyenne mini du sous-domaine
AGG_SIZE = int(ENV.get("NDR_DNS_AGG", "40000"))
_DEF_ALLOW = ("in-addr.arpa,ip6.arpa,omnitech.security,googlevideo.com,googlesyndication.com,"
              "google.com,gstatic.com,gvt2.com,gvt1.com,ggpht.com,googleapis.com,googleusercontent.com,"
              "office.net,office.com,office365.com,microsoft.com,windows.net,windowsupdate.com,"
              "azure.com,azureedge.net,azure-dns.com,cloud.microsoft,cloudfront.net,akamaiedge.net,"
              "akamai.net,akadns.net,apple.com,icloud.com,fbcdn.net,doubleclick.net,trafficmanager.net")
ALLOW = tuple(p for p in ENV.get("NDR_DNS_ALLOW", _DEF_ALLOW).split(",") if p)

def es(idx, body):
    req = urllib.request.Request(f"{OS_URL}/{idx}/_search", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ndr_dns")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def reg_domain(q):
    """eTLD+1 approx (2 derniers labels ; 3 pour co.uk / com.au ...)."""
    parts = q.rstrip(".").lower().split(".")
    if len(parts) < 2:
        return None, None
    two = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if len(parts) >= 3 and parts[-2] in two and len(parts[-1]) == 2:
        reg = ".".join(parts[-3:]); sub = ".".join(parts[:-3])
    else:
        reg = ".".join(parts[-2:]); sub = ".".join(parts[:-2])
    return reg, sub

def main():
    rng = {"range": {"timestamp": {"gte": f"now-{WINDOW_H}h"}}}
    agg = es("omni-sysmon_*", {"size": 0,
        "query": {"bool": {"must": [{"term": {"event_id": 22}}, rng]}},
        "aggs": {"q": {"terms": {"field": "dns_query", "size": AGG_SIZE}}}})
    # regroupe par domaine enregistre
    dom = defaultdict(lambda: {"subs": set(), "ents": [], "lens": []})
    for b in agg["aggregations"]["q"]["buckets"]:
        reg, sub = reg_domain(b["key"])
        if not reg or not sub:
            continue
        if reg.endswith(ALLOW) or reg in ALLOW:
            continue
        flat = sub.replace(".", "")
        d = dom[reg]
        d["subs"].add(sub); d["ents"].append(entropy(flat)); d["lens"].append(len(flat))

    suspects = []
    for reg, d in dom.items():
        n = len(d["subs"])
        if n < MIN_SUB:
            continue
        avg_ent = sum(d["ents"]) / len(d["ents"])
        avg_len = sum(d["lens"]) / len(d["lens"])
        if avg_ent >= MIN_ENT and avg_len >= MIN_LEN:
            suspects.append((reg, n, round(avg_ent, 2), round(avg_len, 1)))
    suspects.sort(key=lambda x: -(x[1]))

    found = 0
    for reg, n, ent, avlen in suspects:
        # attribution : quel(s) hote(s) interrogent ce domaine
        hb = es("omni-sysmon_*", {"size": 0,
            "query": {"bool": {"must": [{"term": {"event_id": 22}},
                                        {"range": {"timestamp": {"gte": f"now-{WINDOW_H}h"}}},
                                        {"bool": {"should": [{"term": {"dns_query": reg}},
                                                             {"wildcard": {"dns_query": f"*.{reg}"}}],
                                                  "minimum_should_match": 1}}]}},
            "aggs": {"h": {"terms": {"field": "host", "size": 3}}}})["aggregations"]["h"]["buckets"]
        host = hb[0]["key"] if hb else "?"
        found += 1
        gelf({"event_source": "ndr_dns", "alert_tag": "dns_tunneling",
              "entity_host": host, "dns_domain": reg, "dns_distinct_sub": n,
              "dns_avg_entropy": ent, "dns_avg_len": avlen,
              "short_message": f"DNS TUNNELING ? {host} -> {reg} ({n} sous-domaines, entropie {ent}, long. {avlen})"})
        print(f"  [dns_tunneling] {host} -> {reg} sub={n} entropie={ent} len={avlen}")
    print(f"[ndr-dns] domaines_analyses={len(dom)} suspects={found} (fenetre {WINDOW_H}h)")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ndr-dns KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ndr-dns
require_api

# --- 1. Mapping MITRE dns_tunneling -----------------------------------------
echo "==> [1/3] Mapping MITRE (dns_tunneling -> T1071.004)"
CSV="lookups/mitre-attack.csv"
if grep -q '^dns_tunneling,' "${CSV}"; then skip "dns_tunneling deja dans le CSV"
else
  echo 'dns_tunneling,T1071.004,DNS,Command and Control,eleve,8' >> "${CSV}"
  ok "ligne dns_tunneling ajoutee au CSV"
fi
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true
ok "CSV deploye (adapter recharge sous 60s)"

# --- 2. Routage event_source=ndr_dns ----------------------------------------
echo "==> [2/3] Routage event_source=ndr_dns -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream interne introuvable (lancer 21)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "ndr_dns"; then skip "regle event_source=ndr_dns deja presente"
else
  jq -n '{field:"event_source", type:1, value:"ndr_dns", inverted:false, description:"ndr: tunneling DNS"}' \
    | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=ndr_dns ajoutee"
fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "ndr_dns"; then skip "M365 exclut deja ndr_dns"
  else
    jq -n '{field:"event_source", type:1, value:"ndr_dns", inverted:true, description:"exclusion ndr_dns (anti-dup)"}' \
      | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais ndr_dns"
  fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 3. Service + timer (horaire) + premier passage --------------------------
echo "==> [3/3] Service + timer (horaire) + premier passage"
cat > /etc/systemd/system/omni-ndr-dns.service <<'EOF'
[Unit]
Description=OMNI SIEM - detection exfiltration/tunneling DNS
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ndr-dns
Nice=15
EOF
cat > /etc/systemd/system/omni-ndr-dns.timer <<'EOF'
[Unit]
Description=OMNI SIEM - tunneling DNS (horaire)

[Timer]
OnCalendar=*-*-* *:42:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-ndr-dns.timer >/dev/null 2>&1 || true
systemctl start omni-ndr-dns.service && ok "$(journalctl -u omni-ndr-dns.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"

echo
echo "=== 43-ndr-dns.sh termine. Relancer 14 (widget) + 13 (alerte). ==="
