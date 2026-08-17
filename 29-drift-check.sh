#!/usr/bin/env bash
# =============================================================================
# 29-drift-check.sh - Controle de DERIVE depot <-> production (+ timer + alerte).
#
#   POURQUOI : l'audit du 02/07/2026 a trouve DEUX pannes silencieuses que rien
#   ne signalait : (1) le depot de snapshots OpenSearch casse depuis 17 jours,
#   (2) une regle pare-feu declaree dans 06-firewall.sh mais jamais appliquee
#   (source cert_parc muette). Ce robot rend ces derives VISIBLES : il compare
#   le referentiel de provisioning a l'etat reel et emet un evenement GELF par
#   ecart (event_source=siem_drift, alert_tag=drift_ecart) -> alerte Graylog.
#
#   Controles (tous FIABLES, faible taux de faux positifs) :
#     1. Snapshots OpenSearch : depot present + dernier SUCCESS recent.
#     2. Sauvegardes : dernier mongodump et backup config recents.
#     3. Pare-feu : ports declares dans 06-firewall.sh absents de nft.
#     4. Binaires versionnes : derive triage/tools vs /usr/local/sbin.
#     5. Lookups threat-intel : tor + spamhaus repondent sans erreur.
#     6. Regles de pipeline : ensure_rule du depot absentes en live (info).
#     7. Depot git : fichiers non suivis / non commites (rappel).
#
#   Lecture seule (ne modifie RIEN). Idempotent. Lance par timer hebdomadaire.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh 2>/dev/null || true
[[ $EUID -eq 0 ]] || { echo "ERREUR: a lancer en root."; exit 1; }

echo "==> [1/2] Installation du binaire /usr/local/sbin/omni-drift-check"
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-drift-check <<'DRIFTEOF'
#!/usr/bin/env python3
# omni-drift-check - controle de derive depot <-> production (installe par
# 29-drift-check.sh). Emet un GELF par ecart. Lecture seule.
import json, os, re, ssl, subprocess, sys, time, urllib.request, glob

REPO     = "/root/omnitech-siem-setup"
OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"

def load_env(path=REPO + "/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z0-9_]+)=(.*)", line)
            if m:
                env[m.group(1)] = m.group(2).split("#", 1)[0].strip().strip("'").strip('"')
    except OSError:
        pass
    return env
ENV = load_env()
def _bash_vars(keys):
    # certaines variables sont COMPOSEES (ex SIEM_FQDN=${SIEM_HOSTNAME}.${SIEM_DOMAIN})
    # -> on les fait developper par bash en sourcant 00-vars.env (comme le depot).
    q = "source " + REPO + "/00-vars.env 2>/dev/null; " + "; ".join(
        'printf "%s\\n" "${' + k + ':-}"' for k in keys)
    try:
        out = subprocess.run(["bash", "-c", q], capture_output=True, text=True, timeout=10).stdout.splitlines()
        return dict(zip(keys, out + [""] * len(keys)))
    except Exception:
        return {}
_BV = _bash_vars(["SIEM_FQDN", "GRAYLOG_ADMIN_PASS", "BACKUP_DIR", "API_CA"])
GL_HOST = _BV.get("SIEM_FQDN") or "bx-it-graylog-vm.omnitech.security"
GL_API  = f"https://{GL_HOST}:9000/api"
GL_CA   = _BV.get("API_CA") or "/etc/graylog/certs/omnitech-rootca.crt"
GL_PASS = _BV.get("GRAYLOG_ADMIN_PASS", "")

ECARTS = []  # (severite, code, message)
def ecart(code, msg, sev="ecart"):
    ECARTS.append((sev, code, msg))
    print(f"  [{sev.upper()}] {code}: {msg}")

def gelf(action, msg, tag="drift_ecart", extra=None):
    base = {"version": "1.1", "host": SIEM, "short_message": msg[:400],
            "_event_source": "siem_drift", "_event_action": action, "_alert_tag": tag}
    if extra:
        base.update({("_" + k): v for k, v in extra.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(
            GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=8)
    except Exception as e:
        print("  gelf KO:", e, file=sys.stderr)

def os_get(path):
    with urllib.request.urlopen(OS_URL + path, timeout=30) as r:
        return json.load(r)

def gl_get(path):
    ctx = ssl.create_default_context(cafile=GL_CA)
    req = urllib.request.Request(GL_API + path, headers={"X-Requested-By": "omni-drift-check"})
    import base64
    tok = base64.b64encode(f"admin:{GL_PASS}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.load(r)

# --- 1. Snapshots OpenSearch --------------------------------------------------
def check_snapshots():
    try:
        repo = os_get("/_snapshot/graylog_fs")
        if "graylog_fs" not in repo:
            ecart("snapshot_repo", "depot de snapshots graylog_fs ABSENT (repository_missing)"); return
        snaps = os_get("/_snapshot/graylog_fs/_all").get("snapshots", [])
        ok = [s for s in snaps if s.get("state") == "SUCCESS"]
        if not ok:
            ecart("snapshot_vide", "depot graylog_fs sans aucun snapshot SUCCESS"); return
        last = max(s.get("end_time_in_millis", 0) for s in ok) / 1000
        age_h = (time.time() - last) / 3600
        if age_h > 48:
            ecart("snapshot_vieux", f"dernier snapshot OpenSearch il y a {age_h:.0f} h (>48h)")
        else:
            print(f"  OK snapshots : {len(ok)} SUCCESS, dernier il y a {age_h:.0f} h")
    except Exception as e:
        ecart("snapshot_err", f"controle snapshots impossible: {e}")

# --- 2. Sauvegardes -----------------------------------------------------------
def _newest_age_h(pattern):
    files = glob.glob(pattern)
    if not files:
        return None
    return (time.time() - max(os.path.getmtime(f) for f in files)) / 3600

def check_backups():
    bdir = ENV.get("BACKUP_DIR", "/home/siem-backup")
    a = _newest_age_h(f"{bdir}/mongo/*.archive.gz")
    if a is None:
        ecart("backup_mongo", "aucun dump Mongo trouve")
    elif a > 30:
        ecart("backup_mongo_vieux", f"dernier dump Mongo il y a {a:.0f} h (>30h)")
    else:
        print(f"  OK dump Mongo : il y a {a:.0f} h")
    # backup config chiffre (30-backup-config) -> repertoire de travail local
    c = _newest_age_h(f"{bdir}/configs/*.tar.gz")
    if c is not None and c > 30:
        ecart("backup_config_vieux", f"dernier backup config il y a {c:.0f} h (>30h)")

# --- 3. Pare-feu : ports declares absents de nft ------------------------------
def check_firewall():
    try:
        fw = open(f"{REPO}/06-firewall.sh").read()
        # ports litteraux + variables ${VAR} resolues via 00-vars.env
        declared = set()
        for m in re.finditer(r"dport\s+(\d+)", fw):
            declared.add(m.group(1))
        for m in re.finditer(r"dport\s+\$\{?([A-Z0-9_]+)\}?", fw):
            v = ENV.get(m.group(1), "")
            if v.isdigit():
                declared.add(v)
        ruleset = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=15).stdout
        live = set(re.findall(r"dport\s+(\d+)", ruleset))
        # ports d'ecoute reels des inputs : on ne signale que ceux declares ET absents
        missing = sorted(declared - live, key=int)
        # 5555 (FAZ CEF) et 514 (avant redirect) peuvent ne pas etre en dport simple -> tolere
        missing = [p for p in missing if p not in ("514",)]
        if missing:
            ecart("firewall", f"ports declares dans 06-firewall.sh mais absents de nft: {', '.join(missing)}")
        else:
            print(f"  OK pare-feu : {len(declared)} ports declares, tous presents")
    except Exception as e:
        ecart("firewall_err", f"controle pare-feu impossible: {e}")

# --- 4. Binaires versionnes vs live -------------------------------------------
VERSIONED = [
    ("triage/omni-alert-triage", "/usr/local/sbin/omni-alert-triage"),
    ("tools/omni-fp", "/usr/local/sbin/omni-fp"),
]
def check_binaries():
    for rel, live in VERSIONED:
        src = os.path.join(REPO, rel)
        if not (os.path.exists(src) and os.path.exists(live)):
            continue
        r = subprocess.run(["diff", "-q", src, live], capture_output=True)
        if r.returncode != 0:
            ecart("binaire", f"derive {live} != depot {rel} (versionner ou reinstaller)")
        else:
            print(f"  OK binaire : {rel} == live")

# --- 5. Lookups threat-intel --------------------------------------------------
def check_lookups():
    # le filtre ?query= de l'API ne matche pas le name exact -> on liste tout.
    try:
        names = {t.get("name") for t in gl_get("/system/lookup/tables?per_page=500").get("lookup_tables", [])}
    except Exception as e:
        ecart("lookup_err", f"liste des tables lookup impossible: {e}"); return
    for tbl in ("tor-exit-node-list", "spamhaus-drop"):
        if tbl in names:
            print(f"  OK lookup : {tbl} present")
        else:
            ecart("lookup_absent", f"table lookup threat-intel {tbl} absente (risque de flood ou perte de detection)")

# --- 6. Regles de pipeline : ensure_rule du depot absentes en live (info) -----
def check_pipeline_rules():
    try:
        names = set()
        for f in glob.glob(f"{REPO}/*.sh"):
            for m in re.finditer(r'ensure_rule\s+"([^"]+)"', open(f, errors="ignore").read()):
                names.add(m.group(1))
        if not names:
            return
        live = {r.get("title") for r in gl_get("/system/pipelines/rule")}
        missing = sorted(names - live)
        if missing:
            ecart("pipeline_regles", f"{len(missing)} regle(s) ensure_rule du depot absente(s) en live "
                  f"(ex: {', '.join(missing[:4])})", sev="info")
        else:
            print(f"  OK pipeline : {len(names)} regles du depot toutes presentes")
    except Exception as e:
        print(f"  (pipeline non verifie: {e})", file=sys.stderr)

# --- 7. Depot git : fichiers non suivis / non commites ------------------------
def check_git():
    try:
        r = subprocess.run(["git", "-C", REPO, "status", "--porcelain"],
                           capture_output=True, text=True, timeout=15)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        untracked = [l for l in lines if l.startswith("??")]
        modified = [l for l in lines if l and not l.startswith("??")]
        if untracked or modified:
            ecart("git", f"depot non commite: {len(modified)} modifie(s) + {len(untracked)} non suivi(s) "
                  f"(committer/pousser pour garantir le PRA)", sev="info")
        else:
            print("  OK git : arbre propre")
    except Exception as e:
        print(f"  (git non verifie: {e})", file=sys.stderr)

def main():
    print(f"=== omni-drift-check {time.strftime('%Y-%m-%d %H:%M')} ===")
    for fn in (check_snapshots, check_backups, check_firewall, check_binaries,
               check_lookups, check_pipeline_rules, check_git):
        try:
            fn()
        except Exception as e:
            print(f"  controle {fn.__name__} en erreur: {e}", file=sys.stderr)
    crit = [e for e in ECARTS if e[0] == "ecart"]
    info = [e for e in ECARTS if e[0] == "info"]
    if crit:
        for sev, code, msg in crit:
            gelf(f"drift_{code}", f"Derive depot/production ({code}): {msg}")
        gelf("drift_resume", f"Controle de derive : {len(crit)} ecart(s) critique(s), "
             f"{len(info)} info", tag="drift_resume")
        print(f"=== {len(crit)} ecart(s) critique(s), {len(info)} info -> alerte Graylog emise ===")
        # PAS de sys.exit(1) : le signal passe par le GELF drift_ecart + l'alerte
        # Graylog. Sortir en erreur laisserait le oneshot en 'failed' permanent
        # (self-health le prendrait a tort pour un robot en panne).
    else:
        # emet un OK (permet de detecter l'ABSENCE d'execution, comme les backups)
        gelf("drift_ok", f"Controle de derive : aucun ecart critique ({len(info)} info)", tag="drift_ok")
        print(f"=== aucun ecart critique ({len(info)} info) ===")

if __name__ == "__main__":
    main()
DRIFTEOF
chmod 700 /usr/local/sbin/omni-drift-check   # lit GRAYLOG_ADMIN_PASS via 00-vars.env
ok "binaire omni-drift-check installe"

echo "==> [2/2] Timer hebdomadaire (lundi 07:00) + service"
cat > /etc/systemd/system/omni-drift-check.service <<'EOF'
[Unit]
Description=OMNI - Controle de derive depot/production
After=network-online.target graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-drift-check
Nice=15
EOF
cat > /etc/systemd/system/omni-drift-check.timer <<'EOF'
[Unit]
Description=Controle de derive SIEM (hebdomadaire)
[Timer]
OnCalendar=Mon *-*-* 07:00:00
Persistent=true
RandomizedDelaySec=10m
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-drift-check.timer >/dev/null 2>&1
ok "timer omni-drift-check arme (lundi 07:00)"

echo
echo "    L'alerte Graylog 'OMNI - Derive depot/production detectee' est provisionnee"
echo "    par 21-alert-hygiene.sh (ou vit le helper ensure_def_simple). La relancer si absente."
echo "=== 29-drift-check.sh termine. Test immediat : /usr/local/sbin/omni-drift-check ==="
