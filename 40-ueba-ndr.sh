#!/usr/bin/env bash
# =============================================================================
# 40-ueba-ndr.sh - Active la couche UEBA / NDR "au-dela de Graylog" (4 collecteurs)
#   - omni-ueba-volume : anomalie de volume par source (z-score, meme-heure-du-jour)
#   - omni-ueba-geo    : impossible travel (geo-velocite haversine)
#   - omni-ndr-beacon  : beaconing / C2 (regularite temporelle, CV des intervalles)
#   - omni-ueba-score  : score de risque d'entite (UEBA, hote + compte, 0-100)
#   Route les 4 event_source vers "OMNI - Interne SIEM" et les EXCLUT de M365
#   (anti double-comptage). Installe 4 timers systemd echelonnes + 1er passage.
#   Les alert_tag (volume_spike/drop, impossible_travel, beaconing) sont mappes
#   MITRE par le CSV (37) -> risk_score + page ATT&CK + facteur UEBA 'detections'.
# Idempotent. Prerequis : 21 (stream interne) + 12 + 37. Relance 14 + 13 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

echo "==> [0/3] Detecteur omni-ndr-beacon (VERSIONNE ici)"
# Auparavant non versionne (le die-check ci-dessous le supposait present) -> source dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-ndr-beacon <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ndr-beacon - Detection de BEACONING / C2 (regularite temporelle).
#   Au-dela de Graylog : pour chaque flux interne->externe (FortiGate), calcule
#   les intervalles inter-connexion puis leur COEFFICIENT DE VARIATION (ecart-
#   type / moyenne). Un flux a intervalle REGULIER (faible jitter) vers une IP
#   externe = signature d'une balise command & control. L'agregation Graylog ne
#   sait pas analyser la distribution temporelle des evenements.
#   Emet GELF event_source=ndr_beacon, alert_tag=beaconing (src_ip + dest_ip).
#   HONNETE : certains logiciels legitimes "battent" aussi (AV, supervision,
#   telemetrie) -> exposition a TRIER, le dest_ip + l'intervalle aident a juger.
# Lance par timer (toutes les 30 min). Config : NDR_CV_MAX (0.25), NDR_MIN_HITS
#   (8), NDR_MIN_INT (15 s), NDR_MAX_INT (3600 s), NDR_WINDOW_H (24).
# =============================================================================
import json, os, re, sys, statistics, urllib.request
from datetime import datetime

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
CV_MAX    = float(ENV.get("NDR_CV_MAX", "0.25"))     # jitter max pour parler de balise
MIN_HITS  = int(ENV.get("NDR_MIN_HITS", "8"))        # min de connexions pour juger
MIN_INT   = float(ENV.get("NDR_MIN_INT", "15"))      # intervalle median min (s)
MAX_INT   = float(ENV.get("NDR_MAX_INT", "3600"))    # intervalle median max (s)
WINDOW_H  = int(ENV.get("NDR_WINDOW_H", "24"))
MAX_PAIRS = int(ENV.get("NDR_MAX_PAIRS", "80"))      # plafond de couples analyses
MAX_HITS  = int(ENV.get("NDR_MAX_HITS", "5000"))     # au-dela = flux continu, pas balise
SKIP_PORTS = {"53", "123", "67", "68", "137", "138"} # DNS / NTP / DHCP / NetBIOS = battements benins
# Allowlist de prefixes de destination connus-bons (DNS publics, telemetrie MS/
# O365/Teams, Google, Cloudflare). Reduit le bruit ET le cout (on saute le fetch).
# A ETENDRE avec vos egress SaaS legitimes (NDR_ALLOW_PREFIX, separes par ,).
_DEF_ALLOW = ("8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9,142.250.,172.217.,172.253.,"
              "216.58.,74.125.,13.107.,52.112.,52.113.,52.114.,52.120.,52.121.,"
              "52.122.,52.123.,20.190.,40.126.,13.64.,104.16.,104.17.,104.18.,104.19.")
ALLOW = tuple(p for p in ENV.get("NDR_ALLOW_PREFIX", _DEF_ALLOW).split(",") if p)
# Allowlist par IP SOURCE : appareils internes benins connus dont le trafic est
# regulier PAR NATURE (telephonie VoIP SIP/STUN, systeme video) -> faux beaconing.
# Qualifies au prealable. Robuste aux rotations d'IP du fournisseur (vs allowlist dest).
WL_SRC = set(p for p in ENV.get("NDR_BEACON_WHITELIST_SRC", "").split(",") if p.strip())

def es(body, path="/omni-*/_search"):
    req = urllib.request.Request(OS_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ndr_beacon")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

BASE_FILTER = lambda: [
    {"term": {"event_source": "fortigate"}},
    {"range": {"timestamp": {"gte": f"now-{WINDOW_H}h"}}},
    {"term": {"src_ip_reserved_ip": True}},                         # source interne
    {"bool": {"must_not": [{"term": {"dest_ip_reserved_ip": True}}]}}]  # dest externe

def main():
    # 1) couples (src interne -> dest externe) et leur volume
    pairs, after, skipped = [], None, 0
    for _ in range(3):                       # jusqu'a 3 pages de 1000
        comp = {"size": 1000, "sources": [
            {"s": {"terms": {"field": "src_ip"}}},
            {"d": {"terms": {"field": "dest_ip"}}}]}
        if after:
            comp["after"] = after
        r = es({"size": 0, "query": {"bool": {"filter": BASE_FILTER()}},
                "aggs": {"p": {"composite": comp}}})["aggregations"]["p"]
        for b in r["buckets"]:
            n = b["doc_count"]
            dst = b["key"]["d"]
            src = b["key"]["s"]
            if not (MIN_HITS <= n <= MAX_HITS):
                continue
            if src in WL_SRC:                # appareil benin connu (VoIP/video) -> on saute
                skipped += 1; continue
            if dst.startswith(ALLOW):        # connu-bon -> on saute (bruit + cout)
                skipped += 1; continue
            pairs.append((src, dst, n))
        after = r.get("after_key")
        if not after:
            break
    # priorise les couples a fort volume (plus de points = jugement plus fiable)
    pairs.sort(key=lambda x: -x[2])
    pairs = pairs[:MAX_PAIRS]

    found = 0
    for src, dst, n in pairs:
        flt = BASE_FILTER() + [{"term": {"src_ip": src}}, {"term": {"dest_ip": dst}}]
        hits = es({"size": min(n, 800), "query": {"bool": {"filter": flt}},
                   "sort": [{"timestamp": "asc"}], "_source": ["timestamp", "dest_country", "service", "dest_port"]})["hits"]["hits"]
        if hits and str(hits[-1]["_source"].get("dest_port", "")) in SKIP_PORTS:
            skipped += 1; continue           # DNS/NTP/DHCP = battement benin
        ts = [datetime.fromisoformat(h["_source"]["timestamp"].replace("Z", "+00:00")).timestamp() for h in hits]
        if len(ts) < MIN_HITS:
            continue
        intervals = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if len(intervals) < MIN_HITS - 1:
            continue
        mean = statistics.mean(intervals)
        if mean < MIN_INT or mean > MAX_INT:
            continue
        cv = statistics.pstdev(intervals) / mean if mean else 9
        if cv > CV_MAX:
            continue
        meta = hits[-1]["_source"]
        found += 1
        gelf({"event_source": "ndr_beacon", "alert_tag": "beaconing",
              "src_ip": src, "dest_ip": dst, "dest_country": meta.get("dest_country"),
              "beacon_service": meta.get("service"), "beacon_dest_port": meta.get("dest_port"),
              "beacon_interval_s": round(mean, 1), "beacon_jitter_cv": round(cv, 3),
              "beacon_hits": len(ts),
              "short_message": f"BEACONING {src}->{dst} ({meta.get('dest_country')}) toutes les {round(mean)}s (jitter {round(cv*100)}%, {len(ts)} hits)"})
        print(f"  [beaconing] {src}->{dst} int={round(mean)}s cv={round(cv,3)} hits={len(ts)} {meta.get('dest_country')}")
    print(f"[ndr-beacon] couples_analyses={len(pairs)} allowlistes/benins={skipped} beaconing={found}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ndr-beacon KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ndr-beacon

SOURCES=(ueba_volume ueba_geo ndr_beacon ueba_score)
for b in omni-ueba-volume omni-ueba-geo omni-ndr-beacon omni-ueba-score; do
  [[ -x "/usr/local/sbin/${b}" ]] || die "/usr/local/sbin/${b} absent."
done

# --- 1. Routage des 4 event_source -> INT (+ exclusion M365) -----------------
echo "==> [1/3] Routage event_source UEBA/NDR -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream 'OMNI - Interne SIEM' introuvable (lancer 21 d'abord)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
for V in "${SOURCES[@]}"; do
  if echo "${CUR}" | grep -qx "${V}"; then skip "regle event_source=${V} deja presente"
  else
    jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:false,
        description:("ueba/ndr: "+$v)}' \
      | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=${V} ajoutee"
  fi
done

M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  for V in "${SOURCES[@]}"; do
    if echo "${MEX}" | grep -qx "${V}"; then skip "M365 exclut deja event_source=${V}"
    else
      jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:true,
          description:("exclusion ueba/ndr (anti-dup): "+$v)}' \
        | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais event_source=${V}"
    fi
  done
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 2. Services + timers systemd (echelonnes) -------------------------------
echo "==> [2/3] Services + timers systemd (echelonnes)"
# bin : description : OnCalendar
units=(
  "omni-ueba-volume:anomalie de volume (z-score):*-*-* *:12:00"
  "omni-ueba-geo:impossible travel (geo-velocite):*-*-* *:17,47:00"
  "omni-ndr-beacon:beaconing / C2 (toutes les 6h):*-*-* 02,08,14,20:22:00"
  "omni-ueba-score:score d'entite UEBA:*-*-* *:27,57:00"
)
for u in "${units[@]}"; do
  BIN="${u%%:*}"; REST="${u#*:}"; DESC="${REST%%:*}"; CAL="${REST#*:}"
  cat > "/etc/systemd/system/${BIN}.service" <<EOF
[Unit]
Description=OMNI SIEM - ${DESC}
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/${BIN}
Nice=15
EOF
  cat > "/etc/systemd/system/${BIN}.timer" <<EOF
[Unit]
Description=OMNI SIEM - ${DESC} (timer)

[Timer]
OnCalendar=${CAL}
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl enable "${BIN}.timer" >/dev/null 2>&1 || true
done
systemctl daemon-reload
for u in "${units[@]}"; do systemctl start "${u%%:*}.timer" >/dev/null 2>&1 || true; done
ok "4 timers UEBA/NDR actifs (echelonnes)"

# --- 3. Premiers passages -----------------------------------------------------
echo "==> [3/3] Premiers passages (beaconing peut prendre ~15s)"
for BIN in omni-ueba-volume omni-ueba-geo omni-ndr-beacon omni-ueba-score; do
  if systemctl start "${BIN}.service"; then
    echo "    $(journalctl -u "${BIN}.service" -n 1 --no-pager -o cat 2>/dev/null)"
  else warn "${BIN} : 1er passage KO (journalctl -u ${BIN})"; fi
done

echo
echo "=== 40-ueba-ndr.sh termine. Relancer 14 (page UEBA/NDR) + 13 (alertes). ==="
