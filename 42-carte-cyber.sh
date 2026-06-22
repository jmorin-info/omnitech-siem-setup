#!/usr/bin/env bash
# =============================================================================
# 42-carte-cyber.sh - Carte cyber temps reel (arcs de flux animes, hors Graylog)
#   - generateur /usr/local/sbin/omni-geo-flux -> /var/www/siem-kit/flux.json
#   - page canvas /var/www/siem-kit/carte-cyber.html (servie par nginx /kit/)
#   - fond de carte mondial local /var/www/siem-kit/carte-world.geojson
#   - timer systemd : rafraichit flux.json toutes les 30 s
#   100% local au runtime (pas de CDN, pas de fuite). Idempotent.
# Prerequis : nginx servant /kit/ (deja en place), OpenSearch, geoloc active.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }
KIT="/var/www/siem-kit"
ok(){ echo "    [+] $*"; }; warn(){ echo "    [!] $*"; }

echo "==> Detecteur omni-geo-flux (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-geo-flux <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-geo-flux - Genere le JSON des flux geolocalises pour la carte cyber temps
#   reel (au-dela de Graylog : arcs source->entreprise animes, pas des points).
#   Agrege sur une fenetre courte les flux SECURITE geolocalises :
#     - deny pare-feu (FortiGate, source externe)   type=deny
#     - threat intel (IP malveillantes connues)      type=threat
#     - connexions M365 hors France                  type=m365
#     - attaques portail SSL-VPN                      type=vpn
#   Regroupe par (lat,lon arrondis, type) -> arcs ; ecrit /var/www/siem-kit/flux.json.
# Lance par timer (toutes les 30 s). Config 00-vars.env : GEO_HQ_LAT/LON/NAME,
#   GEO_FLUX_WINDOW_MIN (10), GEO_FLUX_MAX (160).
# =============================================================================
import json, os, re, sys, urllib.request
from datetime import datetime, timezone

OS_URL = "http://127.0.0.1:9200"
OUT    = "/var/www/siem-kit/flux.json"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
HQ_LAT  = float(ENV.get("GEO_HQ_LAT", "44.88"))     # Bordeaux / Blanquefort
HQ_LON  = float(ENV.get("GEO_HQ_LON", "-0.55"))
HQ_NAME = ENV.get("GEO_HQ_NAME", "OMNITECH (Bordeaux)")
WINDOW  = int(ENV.get("GEO_FLUX_WINDOW_MIN", "10"))
MAXFLOW = int(ENV.get("GEO_FLUX_MAX", "160"))

def es(idx, body):
    req = urllib.request.Request(f"{OS_URL}/{idx}/_search", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def parse_geo(v):
    try:
        lat, lon = v.split(",")
        return float(lat), float(lon)
    except Exception:
        return None

def gather(idx, query, geo_field, country_field):
    """Agrege par geoloc (arrondi 0.5 deg) -> {(lat,lon,country): count}."""
    body = {"size": 0, "query": query, "aggs": {
        "g": {"terms": {"field": geo_field, "size": 1000},
              "aggs": {"c": {"terms": {"field": country_field, "size": 1}}}}}}
    out = {}
    for b in es(idx, body)["aggregations"]["g"]["buckets"]:
        g = parse_geo(b["key"])
        if not g:
            continue
        lat = round(g[0] * 2) / 2.0
        lon = round(g[1] * 2) / 2.0
        cb = b["c"]["buckets"]
        country = cb[0]["key"] if cb else "?"
        key = (lat, lon, country)
        out[key] = out.get(key, 0) + b["doc_count"]
    return out

def rng(extra):
    return {"bool": {"must": [{"range": {"timestamp": {"gte": f"now-{WINDOW}m"}}}] + extra}}

def main():
    sources = [
        ("deny",   "omni-fortigate_*", rng([{"term": {"action": "deny"}},
                    {"exists": {"field": "src_ip_geolocation"}}]), "src_ip_geolocation", "srccountry"),
        ("threat", "omni-fortigate_*", rng([{"term": {"alert_tag": "threat_intel"}},
                    {"exists": {"field": "src_ip_geolocation"}}]), "src_ip_geolocation", "srccountry"),
        ("m365",   "omni-m365_*",      rng([{"term": {"alert_tag": "m365_etranger"}},
                    {"exists": {"field": "src_ip_geolocation"}}]), "src_ip_geolocation", "src_country"),
        ("vpn",    "omni-fortigate_*", rng([{"term": {"subtype": "vpn"}}, {"term": {"action": "ssl-login-fail"}},
                    {"exists": {"field": "remip_geolocation"}}]), "remip_geolocation", "remip_country_code"),
    ]
    flows, stats = [], {}
    for typ, idx, q, gf, cf in sources:
        try:
            agg = gather(idx, q, gf, cf)
        except Exception as e:
            print(f"  {typ}: KO {e}", file=sys.stderr); agg = {}
        stats[typ] = sum(agg.values())
        for (lat, lon, country), cnt in agg.items():
            # ignore les sources internes/France pile sur le HQ (arcs nuls)
            if abs(lat - HQ_LAT) < 1 and abs(lon - HQ_LON) < 1:
                continue
            flows.append({"lat": lat, "lon": lon, "country": country, "type": typ, "count": cnt})

    flows.sort(key=lambda f: -f["count"])
    flows = flows[:MAXFLOW]
    countries = sorted({f["country"] for f in flows})

    # classement des pays attaquants (somme des flux par pays, top 8)
    by_country = {}
    for f in flows:
        c = by_country.setdefault(f["country"], {"count": 0, "types": {}})
        c["count"] += f["count"]
        c["types"][f["type"]] = c["types"].get(f["type"], 0) + f["count"]
    top_countries = sorted(({"country": k, "count": v["count"],
                             "type": max(v["types"], key=v["types"].get)}  # type DOMINANT (par volume)
                            for k, v in by_country.items()), key=lambda x: -x["count"])[:8]

    doc = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
           "window_min": WINDOW, "hq": {"lat": HQ_LAT, "lon": HQ_LON, "name": HQ_NAME},
           "stats": stats, "countries": len(countries), "flows": flows,
           "top_countries": top_countries}
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f)
    os.replace(tmp, OUT)
    os.chmod(OUT, 0o644)
    print(f"[geo-flux] flux={len(flows)} pays={len(countries)} "
          f"deny={stats.get('deny',0)} threat={stats.get('threat',0)} "
          f"m365={stats.get('m365',0)} vpn={stats.get('vpn',0)} -> {OUT}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-geo-flux KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-geo-flux
[[ -f "${KIT}/carte-cyber.html" ]] || { echo "ERREUR: ${KIT}/carte-cyber.html absent."; exit 1; }

# --- 1. Fond de carte mondial (telecharge une fois, servi en local) ----------
echo "==> [1/3] Fond de carte mondial local"
if [[ -s "${KIT}/carte-world.geojson" ]]; then ok "carte-world.geojson present ($(du -h "${KIT}/carte-world.geojson"|cut -f1))"
else
  for url in \
    "https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson" \
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson"; do
    if curl -s -m 25 -o "${KIT}/carte-world.geojson" "$url" \
       && python3 -c "import json;json.load(open('${KIT}/carte-world.geojson'))" 2>/dev/null; then
      ok "fond de carte recupere"; break
    fi
  done
  [[ -s "${KIT}/carte-world.geojson" ]] || warn "fond de carte indisponible (la page affichera une erreur)"
fi
chmod 644 "${KIT}/carte-world.geojson" "${KIT}/carte-cyber.html" 2>/dev/null || true

# --- 2. Service + timer (rafraichissement 30 s) ------------------------------
echo "==> [2/3] Service + timer (flux.json toutes les 30 s)"
cat > /etc/systemd/system/omni-geo-flux.service <<'EOF'
[Unit]
Description=OMNI SIEM - generation des flux geolocalises (carte cyber)
After=network-online.target graylog-server.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-geo-flux
Nice=15
EOF
cat > /etc/systemd/system/omni-geo-flux.timer <<'EOF'
[Unit]
Description=OMNI SIEM - carte cyber : rafraichissement 30 s

[Timer]
OnBootSec=30
OnUnitActiveSec=30
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-geo-flux.timer >/dev/null 2>&1 || true
ok "timer omni-geo-flux actif (30 s)"

# --- 3. Premier passage + verification nginx ---------------------------------
echo "==> [3/3] Premier passage + verification du service web"
systemctl start omni-geo-flux.service && ok "$(/usr/local/sbin/omni-geo-flux 2>&1 | tail -1)" || warn "1er passage KO"
for f in carte-cyber.html flux.json carte-world.geojson; do
  code=$(curl -s -k -o /dev/null -w "%{http_code}" "https://${SIEM_FQDN}/kit/${f}" 2>/dev/null || echo "000")
  [[ "$code" == "200" ]] && ok "nginx sert /kit/${f} (200)" || warn "nginx /kit/${f} -> ${code}"
done

echo
echo "=== 42-carte-cyber.sh termine. ==="
echo "    >>> Carte cyber : https://${SIEM_FQDN}/kit/carte-cyber.html"
