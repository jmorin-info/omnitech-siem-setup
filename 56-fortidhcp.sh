#!/usr/bin/env bash
# =============================================================================
# 56-fortidhcp.sh - Attribution DHCP FortiGate : IP <-> MAC <-> hostname.
#   Le FortiGate gere le DHCP et l'inter-VLAN ; il connait donc le nom de chaque
#   machine derriere une IP privee. Ce script :
#     1. installe le collecteur /usr/local/sbin/omni-fortidhcp-fetch (API REST
#        FortiGate /api/v2/monitor/system/dhcp, token lecture seule svc-siem-ro) ;
#     2. cree le timer systemd (toutes les 15 min) ;
#     3. cree le lookup Graylog 'omni-dhcp-attribution' (ip -> hostname) que le
#        pipeline FortiGate (regles omni-forti-06-dhcp-src/dest dans 12) utilise
#        pour poser src_hostname/dest_hostname sur TOUT log FortiGate interne.
#   -> en investigation : "qui se cache derriere 10.33.x.x" repondu directement.
# Idempotent. Prerequis : 00-vars.env (FORTI_DHCP_HOST/PORT/TOKEN), 12 (pipeline).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

LOOKUP_DIR="/etc/graylog/lookup"
SBIN="/usr/local/sbin/omni-fortidhcp-fetch"

[[ -n "${FORTI_DHCP_HOST:-}" && -n "${FORTI_DHCP_TOKEN:-}" ]] \
  || warn "FORTI_DHCP_HOST/TOKEN non definis dans 00-vars.env -> le collecteur ne ramenera rien tant qu'ils ne sont pas renseignes"

echo "==> [1/4] Collecteur ${SBIN}"
install -d -m 755 "$(dirname "$SBIN")"
cat > "$SBIN" <<'PYEOF'
#!/usr/bin/env python3
# =============================================================================
# omni-fortidhcp-fetch - Attribution IP <-> MAC <-> hostname depuis le FortiGate.
#   Interroge l'API REST FortiGate (/api/v2/monitor/system/dhcp) avec un token
#   lecture seule, emet chaque bail en GELF (event_source=forti_dhcp) et tient a
#   jour un lookup CSV (ip -> hostname/mac) reutilisable pour enrichir n'importe
#   quel src_ip/dest_ip en investigation. Lance par timer (15 min). Config 00-vars.env :
#   FORTI_DHCP_HOST (IP mgmt du FortiGate), FORTI_DHCP_TOKEN (cle API svc-siem-ro).
#   Genere par 56-fortidhcp.sh - ne pas editer a la main.
# =============================================================================
import json, os, re, ssl, sys, urllib.request

GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"
LOOKUP   = "/etc/graylog/lookup/dhcp-attribution.csv"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV   = load_env()
HOST  = ENV.get("FORTI_DHCP_HOST", "").strip()
TOKEN = ENV.get("FORTI_DHCP_TOKEN", "").strip()
PORT  = ENV.get("FORTI_DHCP_PORT", "443")

def gelf(fields):
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "forti_dhcp")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def main():
    if not HOST or not TOKEN:
        print("[forti-dhcp] FORTI_DHCP_HOST/TOKEN non configures -> rien a faire.")
        return
    # cert mgmt FortiGate auto-signe -> contexte non verifie (reseau d'admin interne)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{HOST}:{PORT}/api/v2/monitor/system/dhcp"
    # FortiOS recent exige le header Bearer (le ?access_token= renvoie 401)
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        data = json.load(r)
    leases = data.get("results", []) or []
    rows, n = {}, 0
    for l in leases:
        ip   = str(l.get("ip", "")).strip()
        mac  = str(l.get("mac", "")).strip()
        host = str(l.get("hostname", "")).strip()
        if not ip:
            continue
        status = str(l.get("status", ""))
        gelf({"event_source": "forti_dhcp", "event_category": "attribution",
              "dhcp_ip": ip, "dhcp_mac": mac, "dhcp_hostname": host,
              "dhcp_interface": str(l.get("interface", "")), "dhcp_status": status,
              "dhcp_reserved": bool(l.get("reserved", False)),
              "dhcp_expire": l.get("expire_time", 0),
              "short_message": f"DHCP {ip} -> {host or '?'} ({mac}) [{status}]"})
        if host or mac:
            rows[ip] = (host, mac)
        n += 1
    # lookup CSV ip -> hostname,mac (ecrase a chaque run : etat courant des baux)
    try:
        os.makedirs(os.path.dirname(LOOKUP), exist_ok=True)
        with open(LOOKUP, "w") as f:
            f.write("ip,hostname,mac\n")
            for ip, (h, m) in sorted(rows.items()):
                f.write(f'{ip},"{h}","{m}"\n')
        os.chmod(LOOKUP, 0o644)
    except Exception as e:
        print("lookup KO:", e, file=sys.stderr)
    print(f"[forti-dhcp] baux={n} attribution_csv={len(rows)} ({LOOKUP})")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-fortidhcp-fetch KO:", e, file=sys.stderr); sys.exit(1)
PYEOF
chmod 755 "$SBIN"
ok "collecteur installe"

echo "==> [2/4] Timer systemd (15 min)"
cat > /etc/systemd/system/omni-fortidhcp-fetch.service <<'EOF'
[Unit]
Description=OMNI - FortiGate DHCP -> attribution IP/MAC/hostname (GELF + lookup CSV)
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-fortidhcp-fetch
Nice=10
EOF
cat > /etc/systemd/system/omni-fortidhcp-fetch.timer <<'EOF'
[Unit]
Description=OMNI - FortiGate DHCP fetch (toutes les 15 min)
[Timer]
OnBootSec=4min
OnUnitActiveSec=15min
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-fortidhcp-fetch.timer >/dev/null 2>&1 && ok "timer actif" || warn "timer KO"

echo "==> [3/4] Premiere collecte (alimente le CSV avant de creer le lookup)"
"$SBIN" || warn "collecte initiale KO (verifier FORTI_DHCP_HOST/TOKEN et la joignabilite ${FORTI_DHCP_HOST:-?}:${FORTI_DHCP_PORT:-443})"
[[ -f "${LOOKUP_DIR}/dhcp-attribution.csv" ]] || printf 'ip,hostname,mac\n' > "${LOOKUP_DIR}/dhcp-attribution.csv"
chown root:graylog "${LOOKUP_DIR}/dhcp-attribution.csv" 2>/dev/null || true
chmod 644 "${LOOKUP_DIR}/dhcp-attribution.csv" 2>/dev/null || true

echo "==> [4/4] Lookup Graylog 'omni-dhcp-attribution' (ip -> hostname)"
# ensure_lookup canonique (cf. piege : non centralise dans lib-graylog.sh).
ensure_lookup() {
  local NAME="$1" TITLE="$2" CSV="$3" KEY="$4" VAL="$5" AID CID
  AID="$(api_get "/system/lookup/adapters" | jq -r --arg n "omni-${NAME}-adapter" '.data_adapters[]? | select(.name==$n) | .id')"
  if [[ -z "${AID}" ]]; then
    AID="$(jq -n --arg n "omni-${NAME}-adapter" --arg t "${TITLE} (adapter)" --arg p "${LOOKUP_DIR}/${CSV}" --arg k "${KEY}" --arg v "${VAL}" '{
            name:$n,title:$t,description:"56-fortidhcp.sh",
            config:{type:"csvfile",path:$p,separator:",",quotechar:"\"",key_column:$k,value_column:$v,check_interval:60,case_insensitive_lookup:false,cidr_lookup:false}}' \
          | api_post "/system/lookup/adapters" | jqr '.id')"
    [[ -n "${AID}" && "${AID}" != "null" ]] || { warn "adapter ${NAME} refuse"; return 1; }
  fi
  CID="$(api_get "/system/lookup/caches" | jq -r --arg n "omni-${NAME}-cache" '.caches[]? | select(.name==$n) | .id')"
  if [[ -z "${CID}" ]]; then
    CID="$(jq -n --arg n "omni-${NAME}-cache" --arg t "${TITLE} (cache)" '{
            name:$n,title:$t,description:"56-fortidhcp.sh",
            config:{type:"guava_cache",max_size:2000,expire_after_access:300,expire_after_access_unit:"SECONDS",expire_after_write:300,expire_after_write_unit:"SECONDS",ignore_null:true,ttl_empty:60,ttl_empty_unit:"SECONDS"}}' \
          | api_post "/system/lookup/caches" | jqr '.id')"
    [[ -n "${CID}" && "${CID}" != "null" ]] || { warn "cache ${NAME} refuse"; return 1; }
  fi
  if [[ -z "$(api_get "/system/lookup/tables" | jq -r --arg n "omni-${NAME}" '.lookup_tables[]? | select(.name==$n) | .id')" ]]; then
    jq -n --arg n "omni-${NAME}" --arg t "${TITLE}" --arg a "${AID}" --arg c "${CID}" '{
            name:$n,title:$t,description:"56-fortidhcp.sh",data_adapter_id:$a,cache_id:$c,
            default_single_value:"",default_single_value_type:"NULL",default_multi_value:"",default_multi_value_type:"NULL"}' \
      | api_post "/system/lookup/tables" | jqr '.id' >/dev/null && ok "table 'omni-${NAME}'" || warn "table ${NAME} refusee"
  else skip "table 'omni-${NAME}' existe"; fi
}
ensure_lookup "dhcp-attribution" "FortiGate DHCP IP->hostname" "dhcp-attribution.csv" "ip" "hostname"

echo
echo "=== 56-fortidhcp.sh termine."
echo "    Le pipeline FortiGate (12, regles omni-forti-06-dhcp-src/dest) pose deja"
echo "    src_hostname/dest_hostname sur les IP internes. Verifier le timer :"
echo "      systemctl list-timers omni-fortidhcp-fetch.timer ==="
