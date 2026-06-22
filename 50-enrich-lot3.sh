#!/usr/bin/env bash
# =============================================================================
# 50-enrich-lot3.sh - Lot 3 (multi-agent) : 3 detections pipeline + 2 collecteurs.
#   Detections (pipeline dedie stage 10, connecte winsec) :
#     - gpp_creds_access  (T1552.006) : lecture creds GPP sur SYSVOL (5145)
#     - kerberos_rc4      (T1558.003) : TGS 4769 RC4 (0x17) sur compte a SPN
#     - local_admin_add   (T1098)     : ajout au groupe admin LOCAL (4732 S-1-5-32-544)
#     - local_account_create (T1136.001) : creation compte LOCAL (4720 hors DC)
#   Collecteurs (ecrits par les agents, deployes ici) :
#     - omni-ndr-exfil          (T1048) : exfiltration par volume (FortiGate)
#     - omni-ueba-geo-newcountry (T1078.004) : nouveau pays par compte (ueba_geo)
# Idempotent. Prerequis : 12 + 37. Relance 13 + 14 ensuite.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }
require_api

echo "==> [0/5] Detecteur omni-ndr-exfil (VERSIONNE ici)"
# Auparavant non versionne (l'en-tete disait "deploye ici" sans l'ecrire) -> source dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-ndr-exfil <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ndr-exfil - Detection d'EXFILTRATION par VOLUME (FortiGate).
#   Au-dela de Graylog : agrege sum(bytes_sent) par couple (src_ip INTERNE,
#   dest_ip EXTERNE) sur la derniere heure et flag les flux SORTANTS dont le
#   volume cumule depasse un seuil (defaut 1 Go). Cible un hote interne qui
#   televerse un volume anormal vers une destination Internet.
#   src interne / dest externe determines par CIDR RFC1918 (PAS reserved_ip cote
#   pipeline) : src_ip via term src_ip_reserved_ip=true (pose par GeoIP, DISPO
#   cote OpenSearch) ; dest externe via must_not terms CIDR sur dest_ip (type ip).
#   Emet GELF event_source=ndr_exfil, alert_tag=data_exfil (MITRE T1048).
# Lance par timer horaire. Config 00-vars.env : EXFIL_* + SOAR_WHITELIST.
# =============================================================================
import json, os, re, sys, urllib.request

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"
PRIVATE  = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
# os.environ a priorite sur 00-vars.env (permet override ponctuel / tests).
ENV = load_env(); ENV.update({k: v for k, v in os.environ.items() if k.startswith("EXFIL_")})
WINDOW_M  = int(ENV.get("EXFIL_WINDOW_M", "60"))                 # fenetre glissante
THRESHOLD = int(float(ENV.get("EXFIL_BYTES_GB", "1")) * (1024 ** 3))  # seuil octets (defaut 1 Go)
TOP_PAIRS = int(ENV.get("EXFIL_TOP", "50"))                      # nb de couples examines
# Destinations connues a ne JAMAIS flaguer (CDN/SaaS/backup/IP entreprise).
# Reutilise SOAR_WHITELIST + un EXFIL_ALLOW_DEST dedie (CSV d'IP/prefixes).
ALLOW = set()
for v in (ENV.get("SOAR_WHITELIST", ""), ENV.get("EXFIL_ALLOW_DEST", "")):
    ALLOW.update(x.strip() for x in v.split(",") if x.strip())
ALLOW_SRC = set(x.strip() for x in ENV.get("EXFIL_ALLOW_SRC", "").split(",") if x.strip())

def es(body):
    req = urllib.request.Request(f"{OS_URL}/omni-fortigate_*/_search",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("EXFIL_DRY"):
        return                          # test a blanc : pas d'emission GELF
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "ndr_exfil")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def main():
    # Couples (src interne, dest externe) tries par volume sortant cumule.
    agg = es({"size": 0,
        "query": {"bool": {
            "must": [
                {"range": {"timestamp": {"gte": f"now-{WINDOW_M}m"}}},
                {"range": {"bytes_sent": {"gt": 0}}},
                {"term": {"src_ip_reserved_ip": True}},     # src INTERNE (RFC1918)
                {"term": {"subtype": "forward"}},           # trafic TRANSIT (evite local/app-ctrl/double compte)
            ],
            "must_not": [
                {"terms": {"dest_ip": PRIVATE}},            # dest EXTERNE (exclut RFC1918)
            ]}},
        "aggs": {"pair": {
            "multi_terms": {"terms": [{"field": "src_ip"}, {"field": "dest_ip"}],
                            "size": TOP_PAIRS, "order": {"vol": "desc"}},
            "aggs": {"vol":  {"sum": {"field": "bytes_sent"}},
                     "ports": {"cardinality": {"field": "dest_port"}}}}}})

    buckets = agg["aggregations"]["pair"]["buckets"]
    found = 0
    for b in buckets:
        src, dst = b["key"][0], b["key"][1]
        sent = int(b["vol"]["value"])
        if sent < THRESHOLD:
            break                       # tries desc : plus rien au-dessus du seuil
        if dst in ALLOW or src in ALLOW_SRC:
            continue                    # destination/source legitime connue
        sessions = b["doc_count"]
        gb = round(sent / (1024 ** 3), 2)
        found += 1
        gelf({"event_source": "ndr_exfil", "alert_tag": "data_exfil",
              "entity_host": src, "src_ip": src, "dest_ip": dst,
              "exfil_bytes_sent": sent, "exfil_gb": gb,
              "exfil_sessions": sessions,
              "exfil_dest_ports": int(b["ports"]["value"]),
              "exfil_window_m": WINDOW_M,
              "short_message": f"EXFIL volume : {src} -> {dst} = {gb} Go sortants "
                               f"en {WINDOW_M}min ({sessions} sessions)"})
        print(f"  [exfil] {src} -> {dst}: sent={gb}Go "
              f"sessions={sessions} ports={int(b['ports']['value'])}")
    print(f"[ndr-exfil] couples_externes={len(buckets)} exfil={found} "
          f"(fenetre {WINDOW_M}m, seuil {round(THRESHOLD/1024/1024/1024,2)}Go)")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ndr-exfil KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ndr-exfil
echo "==> Detecteur omni-ueba-geo-newcountry (VERSIONNE ici, AS-IS)"
cat > /usr/local/sbin/omni-ueba-geo-newcountry <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ueba-geo-newcountry - Detection "NOUVEAU PAYS par compte" (first-seen
#   country / impossible_travel complementaire).
#   Pour chaque compte (M365 signin reussi + SSL VPN tunnel-up), compare les
#   pays vus dans la fenetre RECENTE (dernieres 24h) a une BASELINE historique
#   (7-30j, hors fenetre recente). Tout pays present en recent mais ABSENT de la
#   baseline = premiere apparition pour ce compte -> signal de prise de controle
#   (T1078.004 Valid Accounts: Cloud Accounts).
#   Complementaire d'impossible_travel (qui exige 2 lieux distants quasi
#   simultanes) : ici on leve meme une SEULE connexion depuis un pays jamais vu,
#   sans contrainte de velocite.
#   Emet GELF event_source=ueba_geo, alert_tag=new_country (entite=user).
#   Le routage event_source=ueba_geo -> stream "OMNI - Interne SIEM" existe deja
#   (pose par 40-ueba-ndr.sh) : RIEN a re-router.
# Lance par timer. Config (00-vars.env) :
#   UEBA_NEWGEO_RECENT_H  (24)  fenetre "recent" a evaluer
#   UEBA_NEWGEO_BASELINE_D (30) profondeur de la baseline
#   UEBA_NEWGEO_MIN_BASELINE (3) min de connexions de baseline pour qu'un compte
#                                soit "connu" (sinon trop jeune -> on s'abstient,
#                                anti-faux-positif sur les comptes neufs).
# Champs verifies en live : m365 src_country/src_city/src_ip (m365_type:signin,
#   event_action:connexion_reussie) ; fortigate remip_country_code/remip
#   (subtype:vpn, tunneltype ssl*, user reel, exclut remip_country_code=N/A).
# =============================================================================
import json, os, re, sys, urllib.request
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
RECENT_H     = int(ENV.get("UEBA_NEWGEO_RECENT_H", "24"))
BASELINE_D   = int(ENV.get("UEBA_NEWGEO_BASELINE_D", "30"))
MIN_BASELINE = int(ENV.get("UEBA_NEWGEO_MIN_BASELINE", "3"))

def es(path, body):
    req = urllib.request.Request(OS_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM,
            "short_message": fields.get("short_message", "ueba_geo new_country")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

# ---- Sources : (index, query de base, champ pays, champ ville, champ ip, label)
# M365 : signins REUSSIS avec un pays (src_country pose par GeoIP, valeurs FR/US/CN...).
M365_Q = {"bool": {"must": [
    {"term": {"m365_type": "signin"}},
    {"term": {"event_action": "connexion_reussie"}},
    {"exists": {"field": "user"}},
    {"exists": {"field": "src_country"}}]}}
# VPN : SSL VPN (tunnel-up) avec un compte reel et un pays distant connu.
#   On exclut tunneltype ipsec (sites a sites = pas un humain) et le sentinel "N/A".
#   user reel : on jette les pseudo-users = noms d'interface WAN (xx-WANn).
VPN_Q = {"bool": {"must": [
    {"term": {"subtype": "vpn"}},
    {"terms": {"tunneltype": ["ssl", "ssl-web", "ssl-tunnel"]}},
    {"exists": {"field": "user"}},
    {"exists": {"field": "remip_country_code"}}],
    "must_not": [{"term": {"remip_country_code": "N/A"}}]}}

WAN_USER = re.compile(r"^[A-Za-z]{2,3}-WAN\d+$")  # interfaces VPN site-a-site

def country_map(base_query, gte, lt, country_f, city_f, ip_f, source_label):
    """Renvoie {user: {pays: {'count':n, 'city':..., 'ip':...}}} sur [gte, lt)."""
    q = {"bool": {"must": [base_query,
            {"range": {"timestamp": {"gte": gte, "lt": lt}}}]}}
    body = {"size": 10000, "query": q,
            "_source": ["user", country_f, city_f, ip_f, "timestamp"]}
    out = {}
    for h in es("/omni-*/_search", body)["hits"]["hits"]:
        s = h["_source"]
        user = s.get("user")
        ctry = s.get(country_f)
        if not user or not ctry or ctry == "N/A":
            continue
        if WAN_USER.match(str(user)):       # nom d'interface, pas un compte
            continue
        d = out.setdefault(user, {}).setdefault(ctry,
            {"count": 0, "city": s.get(city_f), "ip": s.get(ip_f), "source": source_label})
        d["count"] += 1
        if not d["city"] and s.get(city_f):
            d["city"] = s.get(city_f)
        if not d["ip"] and s.get(ip_f):
            d["ip"] = s.get(ip_f)
    return out

def merge(dst, src):
    for user, ctrys in src.items():
        du = dst.setdefault(user, {})
        for c, info in ctrys.items():
            if c in du:
                du[c]["count"] += info["count"]
                du[c].setdefault("city", info.get("city"))
                du[c].setdefault("ip", info.get("ip"))
            else:
                du[c] = dict(info)

def main():
    recent_gte   = f"now-{RECENT_H}h"
    baseline_gte = f"now-{BASELINE_D}d"
    baseline_lt  = recent_gte   # baseline = [now-30d, now-24h)

    # --- BASELINE : pays connus par compte (hors fenetre recente)
    baseline = {}
    merge(baseline, country_map(M365_Q, baseline_gte, baseline_lt,
                                "src_country", "src_city", "src_ip", "M365"))
    merge(baseline, country_map(VPN_Q, baseline_gte, baseline_lt,
                                "remip_country_code", "remip_city_name", "remip", "VPN"))

    # --- RECENT : pays vus dans les dernieres RECENT_H heures
    recent = {}
    merge(recent, country_map(M365_Q, recent_gte, "now",
                              "src_country", "src_city", "src_ip", "M365"))
    merge(recent, country_map(VPN_Q, recent_gte, "now",
                              "remip_country_code", "remip_city_name", "remip", "VPN"))

    found = 0
    for user, rctrys in recent.items():
        known = baseline.get(user, {})
        base_total = sum(i["count"] for i in known.values())
        # Compte trop jeune (baseline insuffisante) -> on s'abstient (anti-FP).
        if base_total < MIN_BASELINE:
            continue
        new_countries = [c for c in rctrys if c not in known]
        if not new_countries:
            continue
        for c in sorted(new_countries):
            info = rctrys[c]
            found += 1
            gelf({"event_source": "ueba_geo", "alert_tag": "new_country",
                  "user": user,
                  "geo_new_country": c,
                  "geo_new_city": info.get("city") or "?",
                  "geo_new_ip": info.get("ip") or "?",
                  "geo_new_source": info.get("source"),
                  "geo_new_hits": info["count"],
                  "geo_known_countries": ",".join(sorted(known.keys())),
                  "geo_baseline_days": BASELINE_D,
                  "geo_baseline_hits": base_total,
                  "short_message": (f"NOUVEAU PAYS {user}: {c} "
                                    f"({info.get('city') or '?'}, {info.get('source')}, "
                                    f"{info['count']} conn) - jamais vu sur {BASELINE_D}j "
                                    f"(connus: {','.join(sorted(known.keys())) or '-'})")})
            print(f"  [new_country] {user}: {c} ({info.get('source')}, {info['count']}x) "
                  f"connus={sorted(known.keys())}")
    print(f"[ueba-geo-newcountry] comptes_recents={len(recent)} "
          f"comptes_avec_baseline={sum(1 for u in recent if sum(i['count'] for i in baseline.get(u,{}).values())>=MIN_BASELINE)} "
          f"new_country={found}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ueba-geo-newcountry KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ueba-geo-newcountry
WD="winlogbeat_winlog_event_data"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }

echo "==> [1/5] Mappings MITRE (format corrige)"
add_mitre data_exfil          T1048     "Exfiltration Over Alternative Protocol"        Exfiltration       eleve 6
add_mitre gpp_creds_access    T1552.006 "Unsecured Credentials: Group Policy Preferences" "Credential Access" eleve 8
add_mitre kerberos_rc4        T1558.003 "Kerberoasting"                                 "Credential Access" eleve 7
add_mitre local_admin_add     T1098     "Account Manipulation"                          Persistence        eleve 7
add_mitre local_account_create T1136.001 "Create Account: Local Account"                Persistence        eleve 6
add_mitre new_country         T1078.004 "Valid Accounts: Cloud Accounts"               "Initial Access"    eleve 6
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/5] Regles de detection"
ensure_rule "omni-l3-10-gpp-creds" <<EOF
rule "omni-l3-10-gpp-creds"
when
  to_string(\$message.winlogbeat_winlog_event_id) == "5145"
  AND contains(lowercase(to_string(\$message.${WD}_ShareName)), "sysvol")
  AND ( contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "groups.xml")
     OR contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "scheduledtasks.xml")
     OR contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "services.xml")
     OR contains(lowercase(to_string(\$message.${WD}_RelativeTargetName)), "datasources.xml") )
then
  set_field("alert_tag", "gpp_creds_access");
end
EOF

ensure_rule "omni-l3-10-kerberos-rc4" <<EOF
rule "omni-l3-10-kerberos-rc4"
when
  to_string(\$message.winlogbeat_winlog_event_id) == "4769"
  AND to_string(\$message.${WD}_TicketEncryptionType) == "0x17"
  AND NOT contains(to_string(\$message.${WD}_ServiceName), "\$")
  AND lowercase(to_string(\$message.${WD}_ServiceName)) != "krbtgt"
then
  set_field("alert_tag", "kerberos_rc4");
end
EOF

# Ajout au groupe Administrateurs LOCAL (builtin S-1-5-32-544). 4732 STRICT.
ensure_rule "omni-l3-10-local-admin-add" <<EOF
rule "omni-l3-10-local-admin-add"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_string(\$message.winlogbeat_winlog_event_id) == "4732"
  AND to_string(\$message.${WD}_TargetSid) == "S-1-5-32-544"
then
  set_field("alert_tag", "local_admin_add");
  set_field("event_category", "elevation_privilege");
end
EOF

# Creation de compte LOCAL (4720) hors DC (sur un DC = compte de domaine, deja couvert).
ensure_rule "omni-l3-10-local-account-create" <<EOF
rule "omni-l3-10-local-account-create"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4720
  AND NOT starts_with(lowercase(to_string(\$message.host)), "bx-ad-01")
  AND NOT starts_with(lowercase(to_string(\$message.host)), "bx-ad02")
then
  set_field("alert_tag", "local_account_create");
end
EOF

PL="$(ensure_pipeline "OMNI - Detections Lot3" <<'PIPE'
pipeline "OMNI - Detections Lot3"
stage 10 match either
rule "omni-l3-10-gpp-creds"
rule "omni-l3-10-kerberos-rc4"
rule "omni-l3-10-local-admin-add"
rule "omni-l3-10-local-account-create"
end
PIPE
)"
SID="$(get_stream_id 'OMNI - Windows Security')"
[[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream Windows Security absent"

echo "==> [3/5] Config exfil + routage ndr_exfil -> INT (+ exclusion M365)"
grep -q '^EXFIL_BYTES_GB=' 00-vars.env || cat >> 00-vars.env <<'VARS'

# --- omni-ndr-exfil : exfiltration par VOLUME (FortiGate bytes_sent) ---------
# EXFIL_WINDOW_M (min), EXFIL_BYTES_GB (seuil Go), EXFIL_TOP (couples examines),
# EXFIL_ALLOW_DEST (IP egress legitimes, ex egress HTTPS du SIEM), EXFIL_ALLOW_SRC.
EXFIL_WINDOW_M='60'
EXFIL_BYTES_GB='1'
EXFIL_TOP='50'
EXFIL_ALLOW_DEST='160.79.104.10'
EXFIL_ALLOW_SRC=''
VARS
chmod 600 00-vars.env
ST="$(get_stream_id 'OMNI - Interne SIEM')"
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
echo "${CUR}" | grep -qx "ndr_exfil" && skip "ndr_exfil deja route" || \
  { jq -n '{field:"event_source",type:1,value:"ndr_exfil",inverted:false,description:"exfil volume"}' | api_post "/streams/${ST}/rules" >/dev/null && ok "ndr_exfil route vers INT"; }
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  echo "${MEX}" | grep -qx "ndr_exfil" && skip "M365 exclut deja ndr_exfil" || \
    { jq -n '{field:"event_source",type:1,value:"ndr_exfil",inverted:true,description:"exclusion ndr_exfil"}' | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut ndr_exfil"; }
fi

echo "==> [4/5] Timers (exfil horaire ; new-country toutes les 2h)"
mk_timer() {  # nom desc oncalendar_ou_active
  cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=OMNI SIEM - $2
After=network-online.target graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/$1
Nice=15
EOF
  cat > "/etc/systemd/system/$1.timer" <<EOF
[Unit]
Description=OMNI SIEM - $2 (timer)
[Timer]
$3
Persistent=true
[Install]
WantedBy=timers.target
EOF
}
mk_timer omni-ndr-exfil "exfiltration par volume" "OnBootSec=300
OnUnitActiveSec=3600"
mk_timer omni-ueba-geo-newcountry "nouveau pays par compte" "OnCalendar=*-*-* *:23,53:00"
systemctl daemon-reload
systemctl enable --now omni-ndr-exfil.timer omni-ueba-geo-newcountry.timer >/dev/null 2>&1 || true

echo "==> [5/5] Premiers passages"
systemctl start omni-ndr-exfil.service && ok "$(journalctl -u omni-ndr-exfil -n1 --no-pager -o cat 2>/dev/null)" || warn "exfil KO"
systemctl start omni-ueba-geo-newcountry.service && ok "$(journalctl -u omni-ueba-geo-newcountry -n1 --no-pager -o cat 2>/dev/null)" || warn "new-country KO"
echo "=== 50-enrich-lot3.sh termine. Relancer 13 (alertes) + 14 (widgets/couleurs). ==="
