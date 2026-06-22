#!/usr/bin/env bash
# =============================================================================
# 38-vuln-scan.sh - Active la detection de vulnerabilites (KEV + anciennete patch)
#   1. installe le timer systemd omni-vuln-scan (quotidien 07:15)
#   2. route les resultats (event_source=vuln / siem_vuln) vers le stream
#      "OMNI - Interne SIEM" (idempotent, via API)
#   Le generateur est /usr/local/sbin/omni-vuln-scan (lit l'inventaire pose par
#   Get-OmniInventory.ps1, croise CISA KEV, calcule l'anciennete des correctifs,
#   renvoie en GELF). Se remplit une fois le collecteur deploye sur le parc.
# Idempotent. Prerequis : inventaire (Get-OmniInventory) + 12 (parsing) + 21 (stream).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
echo "==> Detecteur omni-vuln-scan (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-vuln-scan <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-vuln-scan - Detection de vulnerabilites cote SIEM (sans agent dedie).
#   Source : inventaire pose par Get-OmniInventory.ps1 (event_source:inventory).
#   1. CISA KEV (CVE activement EXPLOITEES) : croise les logiciels installes avec
#      le catalogue KEV -> hotes exposes a un produit a vuln exploitee.
#   2. Anciennete des correctifs : hotes non patches depuis > SEUIL jours.
#   3. CVSS (NVD) best-effort pour les CVE retenues (cache, rate-limit, fallback).
#   Resultats renvoyes en GELF (event_source=vuln) -> dashboards + score de risque
#   (alert_tag vuln_kev / vuln_patch, mappes par 37-mitre-attack.sh).
#
#   HONNETE : matching par NOM de produit (pas CPE/version) -> exposition a
#   verifier, pas vuln confirmee. Le signal FIABLE est l'anciennete des correctifs.
# Lance par omni-vuln-scan.timer (quotidien). Robuste : une section qui echoue
# n'empeche pas les autres. Config dans 00-vars.env (VULN_PATCH_MAX_DAYS).
# =============================================================================
import json, os, re, ssl, sys, time, urllib.request
from datetime import datetime, timezone

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
CACHE    = "/var/lib/omni-siem"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
INV_INDEX = "omni-winother_*"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
PATCH_MAX_DAYS = int(ENV.get("VULN_PATCH_MAX_DAYS", "35"))
NVD_KEY = ENV.get("NVD_API_KEY", "")
NVD_MAX = int(ENV.get("VULN_NVD_MAX", "40"))     # plafond d'appels NVD par run
NVD_DEADLINE_S = int(ENV.get("VULN_NVD_DEADLINE_S", "90"))  # temps max consacre au NVD (anti-hang)

os.makedirs(CACHE, exist_ok=True)

def es(path, body):
    req = urllib.request.Request(OS_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    # GELF 'host' = emetteur (-> champ Graylog 'source'). Le host de la decouverte
    # doit donc passer en champ custom (_host -> champ Graylog 'host').
    base = {"version": "1.1", "host": "bx-it-graylog-vm", "short_message": fields.get("short_message", "vuln")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception:
        pass

# --- 1. Catalogue KEV (cache 7 j) --------------------------------------------
def load_kev():
    p = os.path.join(CACHE, "kev.json")
    fresh = os.path.exists(p) and (time.time() - os.path.getmtime(p)) < 7 * 86400
    if not fresh:
        try:
            with urllib.request.urlopen(KEV_URL, timeout=60) as r:
                open(p, "wb").write(r.read())
        except Exception as e:
            print("KEV download KO:", e, file=sys.stderr)
    try:
        return json.load(open(p)).get("vulnerabilities", [])
    except Exception:
        return []

STOP = {"server","and","for","reader","the","suite","manager","client","software",
        "application","system","windows","microsoft","edge","player","pro","plus",
        "enterprise","standard","update","tool","tools","service","runtime","driver",
        "redistributable","framework","visual","studio","corporation","inc","ltd","app"}
def norm(s): return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", (s or "").lower())).strip()
def words(s): return {w for w in norm(s).split() if len(w) >= 4 and w not in STOP}

def build_kev_index(kev):
    # index : mot distinctif -> liste d'entrees ; + jeu de mots requis par entree
    by_word, entries = {}, []
    for v in kev:
        prod = v.get("product", "")
        kw = words(prod)
        if not kw:
            continue
        e = {"cve": v.get("cveID", ""), "product": prod, "name": v.get("vulnerabilityName", ""),
             "ransom": (v.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
             "date": v.get("dateAdded", ""), "kw": kw}
        entries.append(e)
        for w in kw:
            by_word.setdefault(w, []).append(e)
    return by_word, entries

def kev_match(installed_product, by_word):
    """Entrees KEV dont TOUS les mots distinctifs sont presents dans le produit installe."""
    iw = words(installed_product)
    if not iw:
        return []
    cand = {}
    for w in iw:
        for e in by_word.get(w, []):
            cand[e["cve"] + "|" + e["product"]] = e
    return [e for e in cand.values() if e["kw"].issubset(iw)]

# --- 2. CVSS via NVD (best-effort, cache) ------------------------------------
def load_cvss_cache():
    p = os.path.join(CACHE, "nvd-cvss.json")
    try: return json.load(open(p))
    except Exception: return {}
def save_cvss_cache(c):
    try: json.dump(c, open(os.path.join(CACHE, "nvd-cvss.json"), "w"))
    except Exception: pass
def nvd_cvss(cve, cache, budget, deadline=None):
    if cve in cache: return cache[cve]
    if budget[0] <= 0: return None
    if deadline and time.time() > deadline: return None   # deadline NVD atteinte -> on arrete d'enrichir (findings deja emis)
    budget[0] -= 1
    try:
        req = urllib.request.Request(NVD_URL + cve, headers=({"apiKey": NVD_KEY} if NVD_KEY else {}))
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
        m = d["vulnerabilities"][0]["cve"]["metrics"]
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if k in m:
                cache[cve] = m[k][0]["cvssData"]["baseScore"]; break
        else:
            cache[cve] = None
    except Exception:
        cache[cve] = None
    time.sleep(0.6 if NVD_KEY else 6.5)   # respect du rate-limit NVD
    return cache[cve]

# --- collecte de l'inventaire (composite agg : combos distincts) -------------
def inv_software():
    out, after = [], None
    base = {"size": 0, "query": {"bool": {"filter": [
        {"range": {"timestamp": {"gte": "now-26h"}}},
        {"term": {"event_source": "inventory"}},
        {"exists": {"field": "inv_product"}}]}}}
    for _ in range(200):
        comp = {"size": 1000, "sources": [
            {"h": {"terms": {"field": "host"}}},
            {"p": {"terms": {"field": "inv_product"}}},
            {"v": {"terms": {"field": "inv_version"}}}]}
        if after: comp["after"] = after
        body = dict(base); body["aggs"] = {"c": {"composite": comp}}
        try:
            agg = es(f"/{INV_INDEX}/_search", body)["aggregations"]["c"]
        except Exception as e:
            print("inv agg KO:", e, file=sys.stderr); break
        for b in agg["buckets"]:
            out.append((b["key"]["h"], b["key"]["p"], b["key"]["v"]))
        after = agg.get("after_key")
        if not after or not agg["buckets"]: break
    return out

def inv_os():
    body = {"size": 0, "query": {"bool": {"filter": [
        {"range": {"timestamp": {"gte": "now-26h"}}},
        {"term": {"event_source": "inventory"}},
        {"exists": {"field": "os_build"}}]}},
        "aggs": {"h": {"terms": {"field": "host", "size": 2000},
                       "aggs": {"last": {"top_hits": {"size": 1, "sort": [{"timestamp": "desc"}],
                                "_source": ["os_build", "os_caption", "os_last_patch", "os_last_kb"]}}}}}}
    res = {}
    try:
        for b in es(f"/{INV_INDEX}/_search", body)["aggregations"]["h"]["buckets"]:
            src = b["last"]["hits"]["hits"][0]["_source"]
            res[b["key"]] = src
    except Exception as e:
        print("os agg KO:", e, file=sys.stderr)
    return res

# =============================== exécution ===================================
now = datetime.now(timezone.utc)
kev = load_kev()
by_word, kev_entries = build_kev_index(kev)
sw = inv_software()
oss = inv_os()
cvss_cache = load_cvss_cache(); nvd_budget = [NVD_MAX]; nvd_deadline = time.time() + NVD_DEADLINE_S

print(f"KEV={len(kev_entries)} entries | inventaire: {len(sw)} (hote,produit,version) | {len(oss)} OS")

# --- KEV : 1 finding par (hote, produit) -------------------------------------
host_prod = {}
for host, prod, ver in sw:
    matches = kev_match(prod, by_word)
    if not matches: continue
    key = (host, prod)
    d = host_prod.setdefault(key, {"ver": ver, "cves": {}, "ransom": False})
    for e in matches:
        d["cves"][e["cve"]] = e
        d["ransom"] = d["ransom"] or e["ransom"]

kev_findings = 0
for (host, prod), d in host_prod.items():
    cves = list(d["cves"].keys())
    # CVSS max parmi les CVE (best-effort)
    scores = [s for s in (nvd_cvss(c, cvss_cache, nvd_budget, nvd_deadline) for c in cves[:NVD_MAX]) if s is not None]
    cvss_max = max(scores) if scores else None
    sev = "critique" if (d["ransom"] or (cvss_max or 0) >= 9) else "eleve"
    f = {"short_message": f"KEV {prod} sur {host}: {len(cves)} CVE exploitee(s)",
         "event_source": "vuln", "event_action": "kev_exposition", "alert_tag": "vuln_kev",
         "vuln_host": host, "vuln_type": "kev", "vuln_product": prod, "vuln_version": d["ver"],
         "vuln_cve_count": len(cves), "vuln_cves": ", ".join(sorted(cves)[:8]),
         "vuln_ransomware": ("oui" if d["ransom"] else "non"),
         "risk_severity": sev, "risk_score": (10 if sev == "critique" else 7)}
    if cvss_max is not None:           # numerique uniquement (sinon mapping keyword)
        f["vuln_cvss"] = cvss_max
    gelf(f)
    kev_findings += 1

# --- Anciennete des correctifs -----------------------------------------------
patch_findings = 0
for host, src in oss.items():
    lp = src.get("os_last_patch", "")
    try:
        d0 = datetime.strptime(lp, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        age = (now - d0).days
    except Exception:
        age = None
    if age is not None and age > PATCH_MAX_DAYS:
        sev = "critique" if age > 90 else "eleve"
        gelf({"short_message": f"{host} non patche depuis {age} j",
              "event_source": "vuln", "event_action": "patch_age", "alert_tag": "vuln_patch",
              "vuln_host": host, "vuln_type": "patch_age", "patch_age_days": age,
              "os_build": str(src.get("os_build", "")), "os_caption": src.get("os_caption", ""),
              "os_last_kb": src.get("os_last_kb", ""), "os_last_patch": lp,
              "risk_severity": sev, "risk_score": (10 if sev == "critique" else 6)})
        patch_findings += 1

save_cvss_cache(cvss_cache)
gelf({"short_message": f"scan vuln: {kev_findings} expositions KEV, {patch_findings} hotes non patches",
      "event_source": "siem_vuln", "event_action": "scan_termine",
      "kev_findings": kev_findings, "patch_findings": patch_findings,
      "inventory_software": len(sw), "inventory_os": len(oss), "kev_catalog": len(kev_entries)})
print(f"Termine : {kev_findings} expositions KEV, {patch_findings} hotes non patches.")
NDREOF
chmod 755 /usr/local/sbin/omni-vuln-scan
require_api

# --- 1. Routage des resultats vers le stream interne -------------------------
echo "==> [1/3] Routage event_source=vuln/siem_vuln -> 'OMNI - Interne SIEM'"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream 'OMNI - Interne SIEM' introuvable (lancer 21 d'abord)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
for V in vuln siem_vuln; do
  if echo "${CUR}" | grep -qx "${V}"; then skip "regle event_source=${V} deja presente"
  else
    jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:false,
        description:("vuln-scan: "+$v)}' \
      | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=${V} ajoutee"
  fi
done

# Anti-duplication : le stream M365 avale TOUT GELF (matching gl2_source_input).
# On en EXCLUT les resultats vuln (sinon ecrits dans 2 index sets -> double compte).
echo "==> [1bis] Exclusion vuln du stream 'OMNI - M365' (evite le double comptage)"
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  for V in vuln siem_vuln; do
    if echo "${MEX}" | grep -qx "${V}"; then skip "M365 exclut deja event_source=${V}"
    else
      jq -n --arg v "${V}" '{field:"event_source", type:1, value:$v, inverted:true,
          description:("exclusion vuln (anti-dup): "+$v)}' \
        | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais event_source=${V}"
    fi
  done
else warn "stream M365 introuvable (exclusion non posee)"; fi

# --- 2. Service + timer systemd ----------------------------------------------
echo "==> [2/3] Service + timer systemd (quotidien 07:15)"
cat > /etc/systemd/system/omni-vuln-scan.service <<'EOF'
[Unit]
Description=OMNI SIEM - scan de vulnerabilites (KEV + anciennete correctifs)
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-vuln-scan
Nice=10
EOF
cat > /etc/systemd/system/omni-vuln-scan.timer <<'EOF'
[Unit]
Description=OMNI SIEM - scan de vulnerabilites quotidien

[Timer]
OnCalendar=*-*-* 07:15:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-vuln-scan.timer >/dev/null 2>&1 || true
ok "timer omni-vuln-scan actif"

# --- 3. Premier scan ----------------------------------------------------------
echo "==> [3/3] Premier scan (telecharge KEV ; 0 resultat tant que l'inventaire est vide)"
systemctl start omni-vuln-scan.service || warn "scan immediat KO (voir journalctl -u omni-vuln-scan)"
systemctl list-timers omni-vuln-scan.timer --no-pager | sed -n '1,2p'

echo
echo "=== 38-vuln-scan.sh termine. Deployer Get-OmniInventory.ps1 sur le parc"
echo "    (tache quotidienne SYSTEM) + canal OMNI-Inventaire dans winlogbeat.yml. ==="
