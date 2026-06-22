#!/usr/bin/env bash
# =============================================================================
# 49-ldap-recon.sh - Active la detection de reconnaissance LDAP / annuaire
#   (BloodHound / SharpHound) via le collecteur omni-ldap-recon.
#   1. mappe ldap_recon -> MITRE T1087.002 / T1069.002 (CSV)
#   2. route event_source=ldap_recon -> stream "OMNI - Interne SIEM" (+ excl M365)
#   3. timer 10 min + premier passage
# Idempotent. Prerequis : collecteur /usr/local/sbin/omni-ldap-recon en place,
#   21 (stream interne) + 37 (CSV MITRE). Relancer 13 (alerte) + 14 (widget).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
echo "==> Detecteur omni-ldap-recon (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-ldap-recon <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-ldap-recon - Detection de reconnaissance LDAP / annuaire (BloodHound /
#   SharpHound, ou tout outil d'enumeration AD de masse).
#
#   POURQUOI un collecteur et pas une regle : l'EventID 4662 (acces a un objet
#   de l'annuaire) est ENORME (~1M evts DS / 24h) et tres bruyant. Une simple
#   regle de pipeline ou une agregation Graylog par compteur echoue car des
#   comptes LEGITIMES generent deja de gros pics (mesure live : owncloud1
#   4790 acces/min, BX-AD-01$ 777/min, BX-FILES$ 453/min). Le VOLUME seul ne
#   discrimine donc PAS l'attaque.
#
#   SIGNATURE SharpHound (ce qui distingue l'enumeration de masse) : un SEUL
#   compte qui, sur une fenetre COURTE (~10 min), touche un NOMBRE ELEVE
#   d'OBJETS DISTINCTS de l'annuaire (utilisateurs, machines, groupes, GPO, OU)
#   ET de TYPES d'objets distincts. Un app legitime (owncloud, replication DC)
#   tape en boucle un jeu d'objets restreint -> faible cardinalite d'objets
#   meme avec un gros volume. On combine donc : volume + cardinalite(ObjectName)
#   + cardinalite(ObjectType), en se limitant a ObjectServer=DS (les 4662 WMI/
#   LSA sont du bruit local, exclus).
#
#   Filet anti-faux-positif : allowlist de comptes connus (DC, apps LDAP,
#   comptes de service) via 00-vars.env::LDAPRECON_ALLOW ; option d'ignorer les
#   comptes machine (se terminant par $) qui sont rarement le vecteur d'un
#   SharpHound interactif (LDAPRECON_SKIP_MACHINE=1).
#
#   Emet GELF event_source=ldap_recon, alert_tag=ldap_recon
#   (MITRE T1087.002 Account Discovery: Domain Account /
#           T1069.002 Permission Groups Discovery: Domain Groups).
# Lance par timer (10 min). Config 00-vars.env : LDAPRECON_*.
# =============================================================================
import json, os, re, sys, urllib.request

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"
IDX      = "omni-winsec_*"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()

# Fenetre courte : SharpHound enumere tout l'annuaire en quelques minutes.
WINDOW_M   = int(ENV.get("LDAPRECON_WINDOW_M", "10"))
# Volume minimal d'acces DS sur la fenetre (porte d'entree, large).
HITS_MIN   = int(ENV.get("LDAPRECON_HITS_MIN", "800"))
# Cardinalite d'objets distincts touches = coeur de la signature d'enumeration.
# Mesure live (24h) : le pic d'objets distincts/10min du parc WORKSTATION
# plafonne a ~199 ; seuls les DC + apps LDAP (allowlist) montent au-dessus.
# SharpHound enumere des MILLIERS d'objets en quelques min -> marge confortable.
OBJ_MIN    = int(ENV.get("LDAPRECON_OBJ_MIN", "250"))
# Types d'objets distincts (user/computer/group/GPO/OU...) : une enum large en
# touche beaucoup ; une app metier en touche peu.
TYPE_MIN   = int(ENV.get("LDAPRECON_TYPE_MIN", "5"))
# Comptes a ne jamais alerter (DC, apps LDAP, comptes de service legitimes).
# Mesure live : owncloud1, BX-AD-01-IT-VM$, BX-AD02-IT-VM$, MSOL_*, svc_intranet.
ALLOW_RAW  = ENV.get("LDAPRECON_ALLOW",
    "owncloud1,svc_intranet,fortigate-svc,BX-AD-01-IT-VM$,BX-AD02-IT-VM$,"
    "BX-FILES-IT-VM$,BX-PKI2022$")
ALLOW      = [a.strip().lower() for a in ALLOW_RAW.split(",") if a.strip()]
# Prefixes de comptes a ignorer (ex: MSOL_ = AAD Connect, qui lit l'annuaire).
ALLOW_PREFIX = [p.strip().lower() for p in
                ENV.get("LDAPRECON_ALLOW_PREFIX", "msol_").split(",") if p.strip()]
# Ignorer les comptes machine ($) : par defaut NON (un poste compromis peut
# lancer SharpHound sous le compte machine via SYSTEM).
SKIP_MACHINE = ENV.get("LDAPRECON_SKIP_MACHINE", "0") == "1"
MAX_ACCOUNTS = int(ENV.get("LDAPRECON_MAX_ACCOUNTS", "300"))

def allowed(user):
    u = (user or "").lower()
    if u in ALLOW:
        return True
    for p in ALLOW_PREFIX:
        if u.startswith(p):
            return True
    if SKIP_MACHINE and u.endswith("$"):
        return True
    return False

def es(body):
    req = urllib.request.Request(f"{OS_URL}/{IDX}/_search",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM,
            "short_message": fields.get("short_message", "ldap_recon")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def main():
    agg = es({"size": 0,
        "query": {"bool": {"must": [
            {"term": {"event_id": "4662"}},
            {"term": {"winlogbeat_winlog_event_data_ObjectServer": "DS"}},
            {"range": {"timestamp": {"gte": f"now-{WINDOW_M}m"}}}]}},
        "aggs": {"u": {"terms": {"field": "user", "size": MAX_ACCOUNTS},
                       "aggs": {
                           "objs":  {"cardinality": {"field": "winlogbeat_winlog_event_data_ObjectName"}},
                           "types": {"cardinality": {"field": "winlogbeat_winlog_event_data_ObjectType"}},
                           "hosts": {"terms": {"field": "host", "size": 3}}}}}})
    buckets = agg["aggregations"]["u"]["buckets"]
    found = 0
    for b in buckets:
        user = b["key"]
        hits = b["doc_count"]
        nobj = b["objs"]["value"]
        ntyp = b["types"]["value"]
        if allowed(user):
            continue
        # Signature : gros volume ET large cardinalite d'objets ET de types.
        if not (hits >= HITS_MIN and nobj >= OBJ_MIN and ntyp >= TYPE_MIN):
            continue
        src_host = b["hosts"]["buckets"][0]["key"] if b["hosts"]["buckets"] else "?"
        found += 1
        gelf({"event_source": "ldap_recon", "alert_tag": "ldap_recon",
              "entity_user": user, "entity_host": src_host,
              "ldap_recon_hits": int(hits), "ldap_recon_objects": int(nobj),
              "ldap_recon_types": int(ntyp), "ldap_recon_window_m": WINDOW_M,
              "short_message": (f"RECONNAISSANCE LDAP (BloodHound/SharpHound) : "
                                f"{user} a touche {int(nobj)} objets distincts "
                                f"({int(ntyp)} types) en {int(hits)} acces annuaire "
                                f"sur {WINDOW_M} min depuis {src_host}")})
        print(f"  [ldap_recon] {user}: hits={hits} objets={int(nobj)} types={int(ntyp)} host={src_host}")
    print(f"[ldap-recon] comptes_analyses={len(buckets)} detections={found} "
          f"(fenetre {WINDOW_M}m, seuils hits>={HITS_MIN} objets>={OBJ_MIN} types>={TYPE_MIN})")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-ldap-recon KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-ldap-recon
require_api

echo "==> [1/3] Mapping MITRE (ldap_recon -> T1087.002 / T1069.002)"
CSV="lookups/mitre-attack.csv"
grep -q '^ldap_recon,' "${CSV}" || { echo 'ldap_recon,T1087.002,Account Discovery: Domain Account,Discovery,eleve,5' >> "${CSV}"; ok "MITRE +ldap_recon (T1087.002)"; }
grep -q '^ldap_recon_groups,' "${CSV}" || { echo 'ldap_recon_groups,T1069.002,Permission Groups Discovery: Domain Groups,Discovery,eleve,5' >> "${CSV}"; ok "MITRE +ldap_recon_groups (T1069.002)"; }
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/3] Routage event_source=ldap_recon -> INT (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"; [[ -n "${ST}" ]] || die "stream interne introuvable."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "ldap_recon"; then skip "regle ldap_recon deja la"
else jq -n '{field:"event_source",type:1,value:"ldap_recon",inverted:false,description:"reconnaissance LDAP (BloodHound/SharpHound)"}' \
  | api_post "/streams/${ST}/rules" >/dev/null && ok "regle ldap_recon ajoutee"; fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "ldap_recon"; then skip "M365 exclut deja ldap_recon"
  else jq -n '{field:"event_source",type:1,value:"ldap_recon",inverted:true,description:"exclusion ldap_recon (anti-dup)"}' \
    | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut ldap_recon"; fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [3/3] Service + timer (10 min) + premier passage"
cat > /etc/systemd/system/omni-ldap-recon.service <<'EOF'
[Unit]
Description=OMNI SIEM - detection reconnaissance LDAP (BloodHound/SharpHound)
After=network-online.target graylog-server.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-ldap-recon
Nice=15
EOF
cat > /etc/systemd/system/omni-ldap-recon.timer <<'EOF'
[Unit]
Description=OMNI SIEM - reconnaissance LDAP (10 min)
[Timer]
OnBootSec=240
OnUnitActiveSec=600
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-ldap-recon.timer >/dev/null 2>&1 || true
systemctl start omni-ldap-recon.service && ok "$(journalctl -u omni-ldap-recon.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"
echo "=== 49-ldap-recon.sh termine. Relancer 13 (alerte) + 14 (widget/couleur). ==="
