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
echo "==> Detecteur omni-ueba-volume (VERSIONNE ici, AS-IS)"
cat > /usr/local/sbin/omni-ueba-volume <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ueba-volume - Detection d'anomalie de VOLUME par source (z-score).
#   Au-dela de Graylog : compare le volume de la DERNIERE HEURE COMPLETE de chaque
#   source a sa baseline statistique MEME-HEURE-DU-JOUR sur N jours (moyenne +
#   ecart-type) -> z-score. Capte pics (exfil, scan, boucle) ET chutes (audit
#   coupe, agent tue) que l'agregation Graylog ne sait pas reperer.
#   Emet GELF event_source=ueba_volume, alert_tag=volume_spike|volume_drop.
# Lance par timer horaire. Config : UEBA_VOL_Z (defaut 4), UEBA_VOL_MIN (20).
# =============================================================================
import json, os, re, sys, statistics, urllib.request
from datetime import datetime, timezone

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"
IDX      = "omni-*"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
Z_HIGH   = float(ENV.get("UEBA_VOL_Z", "4"))       # sigmas pour un pic
Z_DROP   = float(ENV.get("UEBA_VOL_ZDROP", "3"))   # sigmas pour une chute
MIN_MEAN = float(ENV.get("UEBA_VOL_MIN", "20"))    # ignore les sources peu actives
# Baseline MEME-HEURE-DU-JOUR : il faut N jours d'historique (1 echantillon/jour).
# Abaisse a 3 car la retention actuelle est courte (~1-5 j selon la source). Le
# detecteur ne couvre que les sources ayant >= MIN_SAMP jours et s'ETEND tout seul
# quand la retention grandit. A remonter (7-14) des que l'historique le permet.
MIN_SAMP = int(ENV.get("UEBA_VOL_MINSAMP", "3"))   # min d'echantillons (jours)
HIST_DAYS = int(ENV.get("UEBA_VOL_HISTDAYS", "21"))

def es(path, body):
    req = urllib.request.Request(OS_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return                      # test a blanc : pas d'emission GELF
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ueba_volume")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def main():
    # sources actives sur la fenetre d historique
    srcs = [b["key"] for b in es(f"/{IDX}/_search", {"size": 0,
        "query": {"range": {"timestamp": {"gte": f"now-{HIST_DAYS}d"}}},
        "aggs": {"s": {"terms": {"field": "event_source", "size": 50}}}})["aggregations"]["s"]["buckets"]]

    now = datetime.now(timezone.utc)
    # heure complete a analyser = [debut_heure_courante - 1h ; debut_heure_courante)
    cur_floor = now.replace(minute=0, second=0, microsecond=0)
    obs_start = cur_floor.timestamp() - 3600
    obs_hod   = datetime.fromtimestamp(obs_start, tz=timezone.utc).hour

    anomalies = 0
    for src in srcs:
        h = es(f"/{IDX}/_search", {"size": 0,
            "query": {"bool": {"must": [{"term": {"event_source": src}},
                                        {"range": {"timestamp": {"gte": f"now-{HIST_DAYS}d"}}}]}},
            "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h",
                                              "min_doc_count": 0}}}})["aggregations"]["t"]["buckets"]
        observed = None
        baseline = []
        for b in h:
            ksec = b["key"] / 1000.0
            hod = datetime.fromtimestamp(ksec, tz=timezone.utc).hour
            if abs(ksec - obs_start) < 1:
                observed = b["doc_count"]
            elif hod == obs_hod and ksec < obs_start:
                baseline.append(b["doc_count"])
        if observed is None or len(baseline) < MIN_SAMP:
            continue
        mean = statistics.mean(baseline)
        std  = statistics.pstdev(baseline)
        if mean < MIN_MEAN or std < 1:
            continue
        z = (observed - mean) / std
        tag = None
        if z >= Z_HIGH:
            tag = "volume_spike"
        elif z <= -Z_DROP and mean >= 50:
            tag = "volume_drop"
        if tag:
            anomalies += 1
            gelf({"event_source": "ueba_volume", "alert_tag": tag,
                  "anomaly_entity": src, "anomaly_kind": "source",
                  "vol_observed": observed, "vol_mean": round(mean, 1),
                  "vol_std": round(std, 1), "vol_zscore": round(z, 2),
                  "short_message": f"{tag} {src}: {observed} vs baseline {round(mean)}+-{round(std)} (z={round(z,1)})"})
            print(f"  [{tag}] {src}: obs={observed} mean={round(mean)} std={round(std)} z={round(z,1)}")
    print(f"[ueba-volume] sources={len(srcs)} heure_analysee={obs_hod}h UTC anomalies={anomalies}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ueba-volume KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ueba-volume
echo "==> Detecteur omni-ueba-geo (VERSIONNE ici, AS-IS)"
cat > /usr/local/sbin/omni-ueba-geo <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ueba-geo - Detection "impossible travel" (geo-velocite).
#   Au-dela de Graylog : correle les connexions REUSSIES d'un meme compte (M365
#   + VPN SSL) et calcule, entre deux connexions consecutives, la distance
#   haversine et la vitesse requise. Si vitesse > seuil (avion) ET distance
#   significative -> deplacement physiquement impossible = compte compromis.
#   Graylog ne calcule ni distance ni vitesse : c'est un vrai cran au-dessus.
#   Emet GELF event_source=ueba_geo, alert_tag=impossible_travel (entite=user).
#   NB : geoloc = centroide pays -> conservateur (intra-pays = distance ~0, pas
#   de faux positif ; ne leve que sur des pays reellement distants).
# Lance par timer (toutes les 30 min). Config : UEBA_GEO_SPEED (900 km/h),
#   UEBA_GEO_MINKM (500), UEBA_GEO_WINDOW_H (24).
# =============================================================================
import json, math, os, re, sys, urllib.request
from datetime import datetime, timezone

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
SPEED_KMH = float(ENV.get("UEBA_GEO_SPEED", "900"))    # > vitesse d'un avion de ligne
# Au-dela de ce plafond, ce n'est plus un deplacement humain mais du JITTER geo-IP
# (egress datacenter O365 : 2 IP Microsoft geolocalisees dans des villes/pays differents
# a quelques secondes -> vitesse absurde). On ecarte ces faux positifs (ex FR->FR 30543 km/h).
MAX_SPEED_KMH = float(ENV.get("UEBA_GEO_MAXSPEED", "4000"))
MIN_KM    = float(ENV.get("UEBA_GEO_MINKM", "500"))    # ignore les petits ecarts (bruit centroide)
WINDOW_H  = int(ENV.get("UEBA_GEO_WINDOW_H", "24"))

def es(path, body):
    req = urllib.request.Request(OS_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ueba_geo")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def haversine(a, b):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians, [a[0], a[1], b[0], b[1]])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
    return 2 * R * math.asin(math.sqrt(h))

def parse_geo(v):
    try:
        lat, lon = v.split(",")
        return (float(lat), float(lon))
    except Exception:
        return None

def collect(query, geo_field, country_field, city_field, ip_field, source_label):
    """Renvoie [(ts_ms, (lat,lon), country, city, ip, source)]"""
    out = []
    body = {"size": 10000, "query": query,
            "sort": [{"timestamp": "asc"}],
            "_source": ["timestamp", "user", geo_field, country_field, city_field, ip_field]}
    for hgt in es("/omni-*/_search", body)["hits"]["hits"]:
        s = hgt["_source"]
        geo = parse_geo(s.get(geo_field, "")) if s.get(geo_field) else None
        if not geo:
            continue
        out.append((s.get("user"), s.get("timestamp"), geo,
                    s.get(country_field), s.get(city_field), s.get(ip_field), source_label))
    return out

def to_ms(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000

def main():
    rng = {"range": {"timestamp": {"gte": f"now-{WINDOW_H}h"}}}
    rows = []
    # M365 : connexions REUSSIES
    rows += collect({"bool": {"must": [{"term": {"m365_type": "signin"}}, rng,
                                       {"exists": {"field": "user"}}],
                              "must_not": [{"term": {"event_action": "echec_connexion"}}]}},
                    "src_ip_geolocation", "src_country", "src_city", "src_ip", "M365")
    # VPN SSL : connexions avec compte
    rows += collect({"bool": {"must": [{"term": {"subtype": "vpn"}}, rng,
                                       {"exists": {"field": "user"}},
                                       {"exists": {"field": "remip_geolocation"}}]}},
                    "remip_geolocation", "remip_country_code", "remip_city_name", "remip", "VPN")

    # regroupe par compte
    by_user = {}
    for user, ts, geo, country, city, ip, srcl in rows:
        if not user or not ts:
            continue
        by_user.setdefault(user, []).append((to_ms(ts), geo, country, city, ip, srcl))

    found = 0
    for user, evs in by_user.items():
        evs.sort()
        for (t1, g1, c1, city1, ip1, s1), (t2, g2, c2, city2, ip2, s2) in zip(evs, evs[1:]):
            if ip1 == ip2:
                continue
            km = haversine(g1, g2)
            if km < MIN_KM:
                continue
            hours = max((t2 - t1) / 3600000.0, 0.001)
            speed = km / hours
            if speed < SPEED_KMH:
                continue
            if speed > MAX_SPEED_KMH:        # jitter geo-IP (egress O365), pas un humain -> FP ecarte
                continue
            found += 1
            gelf({"event_source": "ueba_geo", "alert_tag": "impossible_travel",
                  "user": user, "geo_km": round(km), "geo_hours": round(hours, 2),
                  "geo_speed_kmh": round(speed),
                  "geo_from": f"{city1 or '?'}/{c1 or '?'} ({s1})", "geo_from_ip": ip1,
                  "geo_to": f"{city2 or '?'}/{c2 or '?'} ({s2})", "geo_to_ip": ip2,
                  "short_message": f"IMPOSSIBLE TRAVEL {user}: {c1}->{c2} {round(km)}km en {round(hours,1)}h ({round(speed)}km/h)"})
            print(f"  [impossible_travel] {user}: {c1}->{c2} {round(km)}km / {round(hours,1)}h = {round(speed)}km/h")
    print(f"[ueba-geo] comptes={len(by_user)} connexions={len(rows)} impossible_travel={found}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ueba-geo KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ueba-geo
echo "==> Detecteur omni-ueba-score (VERSIONNE ici, AS-IS)"
cat > /usr/local/sbin/omni-ueba-score <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ueba-score - Score de risque d'ENTITE (UEBA), hote ET compte.
#   Au-dela de Graylog : FUSIONNE plusieurs signaux heterogenes par entite et les
#   NORMALISE en un score 0-100 interpretable (saturation douce), avec le detail
#   des facteurs contributifs. Graylog sait sommer risk_score ; il ne sait pas
#   combiner detections + auth + geo + go-dark en un score borne et explicable,
#   ni emettre un EVENEMENT de score par entite (alertable, suivable dans le temps).
#   Emet GELF event_source=ueba_score (entity_type=host|user, ueba_score 0-100).
# Lance par timer (toutes les 30 min). Fenetre 7j. Poids configurables.
# =============================================================================
import json, math, os, re, sys, urllib.request

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"
IDX      = "/omni-*,graylog_*/_search"   # inclut l'index par defaut (vuln/incidents INT)

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
WINDOW   = ENV.get("UEBA_SCORE_WINDOW", "7d")
K        = float(ENV.get("UEBA_SCORE_K", "20"))     # echelle de saturation (raw->0-100)
MIN_EMIT = int(ENV.get("UEBA_SCORE_MIN", "1"))      # score mini pour emettre
W_GEO    = float(ENV.get("UEBA_W_GEO", "25"))       # poids d'un impossible travel
W_GODARK = float(ENV.get("UEBA_W_GODARK", "15"))    # poids d'un hote go-dark
W_BEACON = float(ENV.get("UEBA_W_BEACON", "12"))    # poids d'une balise C2

def es(body):
    req = urllib.request.Request(OS_URL + IDX, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ueba_score")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def terms_metric(field, query, metric=None, size=500):
    """terms(field) -> {cle: valeur}. metric=None => doc_count ; sinon sum(metric)."""
    aggs = {"t": {"terms": {"field": field, "size": size}}}
    if metric:
        aggs["t"]["aggs"] = {"m": {"sum": {"field": metric}}}
    r = es({"size": 0, "query": query, "aggs": aggs})["aggregations"]["t"]["buckets"]
    if metric:
        return {b["key"]: b["m"]["value"] or 0 for b in r}
    return {b["key"]: b["doc_count"] for b in r}

def distinct_severity(entity_field, size=500):
    """Somme du max(risk_score) PAR alert_tag DISTINCT par entite.
    Recompense la diversite + severite des menaces (pas le volume d'evenements)."""
    body = {"size": 0, "query": rng([{"exists": {"field": "risk_score"}},
                                     {"exists": {"field": entity_field}}, {"exists": {"field": "alert_tag"}}]),
            "aggs": {"e": {"terms": {"field": entity_field, "size": size},
                "aggs": {"tags": {"terms": {"field": "alert_tag", "size": 40},
                    "aggs": {"sev": {"max": {"field": "risk_score"}}}}}}}}
    out = {}
    for b in es(body)["aggregations"]["e"]["buckets"]:
        out[b["key"]] = sum((t["sev"]["value"] or 0) for t in b["tags"]["buckets"])
    return out

def rng(extra):
    return {"bool": {"must": [{"range": {"timestamp": {"gte": f"now-{WINDOW}"}}}] + extra}}

def saturate(raw):
    return round(100 * (1 - math.exp(-raw / K))) if raw > 0 else 0

def emit(entity_type, name, raw, factors):
    score = saturate(raw)
    if score < MIN_EMIT or not name:
        return 0
    top = max(factors.items(), key=lambda x: x[1])[0] if factors else "?"
    gelf({"event_source": "ueba_score", "entity_type": entity_type, "ueba_entity": name,
          **({"user": name} if entity_type == "user" else {"host": name}),
          "ueba_score": score, "ueba_raw": round(raw, 1), "ueba_top_factor": top,
          "factor_detections": round(factors.get("detections", 0), 1),
          "factor_authfail":   round(factors.get("authfail", 0), 1),
          "factor_geo":        round(factors.get("geo", 0), 1),
          "factor_godark":     round(factors.get("godark", 0), 1),
          "factor_beacon":     round(factors.get("beacon", 0), 1),
          "short_message": f"UEBA {entity_type} {name}: score {score}/100 (facteur dominant: {top})"})
    return 1

def main():
    # --- HOTES ---------------------------------------------------------------
    host_risk = distinct_severity("host")
    godark = set(terms_metric("dark_host", {"bool": {"must": [
        {"range": {"timestamp": {"gte": "now-3h"}}},
        {"term": {"event_source": "collecte_sla"}}, {"term": {"sla_type": "go_dark"}}]}}).keys())
    beacon_src = terms_metric("src_ip", rng([{"term": {"event_source": "ndr_beacon"}}]))

    # beacon_src est keye par IP source interne (pas un hostname) : on AJOUTE ces
    # IP comme entites a part entiere pour que le facteur beaconing compte vraiment
    # (sinon .get(hostname) renvoyait toujours 0). Une entite-IP qui beacon ressort
    # ainsi dans le classement, a defaut de resolution IP->hostname.
    hosts = set(host_risk) | godark | set(beacon_src)
    n_host = 0
    for h in hosts:
        f = {"detections": host_risk.get(h, 0),
             "godark": W_GODARK if h in godark else 0,
             "beacon": W_BEACON * beacon_src.get(h, 0)}
        n_host += emit("host", h, sum(f.values()), f)

    # --- COMPTES -------------------------------------------------------------
    user_risk = distinct_severity("user")
    authfail  = terms_metric("user", rng([{"term": {"event_id": "4625"}}]))
    geo       = terms_metric("user", rng([{"term": {"event_source": "ueba_geo"}}]))

    users = set(user_risk) | set(geo)
    n_user = 0
    for u in users:
        if not u or u.endswith("$"):           # ignore comptes machine
            continue
        # NB : impossible_travel est mappe dans le CSV MITRE -> il alimente DEJA
        # 'detections' via le champ user (risk_score). Pas de poids geo separe
        # (sinon double comptage). 'geo' n'est garde que pour l'info/affichage.
        f = {"detections": user_risk.get(u, 0),
             "authfail": min(20, authfail.get(u, 0) / 5.0)}
        n_user += emit("user", u, sum(f.values()), f)

    print(f"[ueba-score] hotes_scores={n_host} comptes_scores={n_user} "
          f"(go-dark={len(godark)}, beacons_src={len(beacon_src)}, impossible_travel={sum(geo.values())})")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ueba-score KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ueba-score

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
