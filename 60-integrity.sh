#!/usr/bin/env bash
# =============================================================================
# 60-integrity.sh - Integrite & preuve d'inalterabilite des logs (ISO A.8.15).
#   Probleme : un admin du SIEM peut supprimer/alterer des logs sans trace (on l'a
#   demontre en purgeant 22,9M docs). Faute d'Enterprise (archivage natif), on pose
#   une TAMPER-EVIDENCE OSS :
#     - registre QUOTIDIEN de l'etat du corpus (par index : docs, taille, uuid),
#       chaine par hachage (chaque manifeste inclut le hash du precedent) et SIGNE
#       (HMAC-SHA256, cle root-only) -> toute reecriture retroactive CASSE la chaine.
#     - copie hors-SIEM (partage SMB) -> un insider ne peut pas reecrire l'historique.
#     - attestation emise dans le SIEM (event_source:siem_integrity) + mode --verify.
#   Complete par : role Graylog LECTURE SEULE (moindre privilege) + procedure
#   forensique (docs/PROCEDURE-INTEGRITE-PREUVE.md). Idempotent.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

KEY=/etc/graylog/omni-integrity.key
SBIN=/usr/local/sbin/omni-integrity

echo "==> [1/4] Cle de signature HMAC (generee une seule fois, root-only)"
if [[ ! -s "$KEY" ]]; then
  openssl rand -hex 32 > "$KEY"; chmod 600 "$KEY"; chown root:root "$KEY"
  ok "cle generee ($KEY, chmod 600)"
else skip "cle deja presente"; fi

echo "==> [2/4] Installation du moteur $SBIN"
cat > "$SBIN" <<'PYEOF'
#!/usr/bin/env python3
# omni-integrity - registre d'integrite haché-en-chaine + signe des logs.
#   defaut : ajoute un maillon quotidien. --verify : re-verifie toute la chaine.
#   Genere par 60-integrity.sh - ne pas editer a la main.
import json, hashlib, hmac, os, sys, urllib.request, datetime

ES      = "http://127.0.0.1:9200"
KEYFILE = "/etc/graylog/omni-integrity.key"
CHAIN   = "/var/lib/omni-integrity/chain.jsonl"
GELF    = "http://127.0.0.1:12201/gelf"
SIEM    = "bx-it-graylog-vm"

def key():
    with open(KEYFILE) as f: return f.read().strip().encode()

def canon(obj):  # JSON canonique (tri des cles) -> hash stable
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def sha(b): return hashlib.sha256(b).hexdigest()
def sign(b): return hmac.new(key(), b, hashlib.sha256).hexdigest()

def gelf(fields):
    base = {"version": "1.1", "host": SIEM, "short_message": fields.pop("short_message", "integrity")}
    base.update({("_" + k): v for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def indices():
    url = (ES + "/_cat/indices/omni-*,graylog*,gl-events*"
           "?format=json&h=index,uuid,docs.count,store.size&bytes=b")
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.load(r)
    rows = [{"index": d["index"], "uuid": d.get("uuid", ""),
             "docs": int(d.get("docs.count") or 0), "bytes": int(d.get("store.size") or 0)}
            for d in data if not d["index"].startswith(".")]
    return sorted(rows, key=lambda x: x["index"])

def read_chain():
    if not os.path.exists(CHAIN): return []
    return [json.loads(l) for l in open(CHAIN) if l.strip()]

def append_link(now_iso):
    os.makedirs(os.path.dirname(CHAIN), exist_ok=True)
    chain = read_chain()
    prev_hash = chain[-1]["manifest_hash"] if chain else ("0" * 64)
    seq = (chain[-1]["seq"] + 1) if chain else 1
    idx = indices()
    manifest = {"seq": seq, "ts": now_iso, "prev_hash": prev_hash,
                "index_count": len(idx),
                "total_docs": sum(i["docs"] for i in idx),
                "total_bytes": sum(i["bytes"] for i in idx),
                "indices": idx}
    mh = sha(canon(manifest))
    rec = dict(manifest); rec["manifest_hash"] = mh; rec["hmac"] = sign(mh.encode())
    with open(CHAIN, "a") as f: f.write(json.dumps(rec) + "\n")
    os.chmod(CHAIN, 0o600)
    gelf({"event_source": "siem_integrity", "event_action": "manifeste_ajoute",
          "integrity_seq": seq, "integrity_total_docs": manifest["total_docs"],
          "integrity_index_count": len(idx), "integrity_hash": mh[:16],
          "short_message": f"Integrite: maillon #{seq} ({manifest['total_docs']} docs, {len(idx)} index) hash {mh[:12]}"})
    print(f"[integrity] maillon #{seq} ajoute - {manifest['total_docs']} docs / {len(idx)} index - hash {mh[:16]}")
    return rec

def verify():
    chain = read_chain(); ok = True; prev = "0" * 64
    for rec in chain:
        body = {k: rec[k] for k in ("seq","ts","prev_hash","index_count","total_docs","total_bytes","indices")}
        mh = sha(canon(body))
        if mh != rec["manifest_hash"]:
            print(f"[!] maillon #{rec['seq']} : HASH ALTERE"); ok = False
        if not hmac.compare_digest(sign(mh.encode()), rec["hmac"]):
            print(f"[!] maillon #{rec['seq']} : SIGNATURE INVALIDE"); ok = False
        if rec["prev_hash"] != prev:
            print(f"[!] maillon #{rec['seq']} : CHAINAGE ROMPU (prev attendu {prev[:12]})"); ok = False
        prev = rec["manifest_hash"]
    msg = f"chaine OK ({len(chain)} maillons)" if ok else "CHAINE COMPROMISE"
    gelf({"event_source": "siem_integrity", "event_action": "verification",
          "integrity_state": "ok" if ok else "compromis", "integrity_links": len(chain),
          "short_message": f"Integrite verification: {msg}"})
    print(f"[integrity] {msg}")
    return 0 if ok else 2

if __name__ == "__main__":
    try:
        if "--verify" in sys.argv: sys.exit(verify())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        append_link(now)
    except Exception as e:
        print("omni-integrity KO:", e, file=sys.stderr); sys.exit(1)
PYEOF
chmod 750 "$SBIN"; ok "moteur installe"

echo "==> [3/4] Timer quotidien + copie hors-SIEM (SMB) + seed initial"
cat > /etc/systemd/system/omni-integrity.service <<EOF
[Unit]
Description=OMNI - Integrite logs : maillon quotidien hache+signe + copie hors-SIEM
After=network-online.target
[Service]
Type=oneshot
ExecStart=${SBIN}
# copie hors-SIEM du registre (best-effort) vers le partage SMB des sauvegardes
ExecStartPost=/bin/bash -c 'M=\$(mktemp -d); mount -t cifs "${SMB_BACKUP_UNC:-//10.33.50.5/Public}" "\$M" -o "credentials=${SMB_CRED_FILE:-/root/.smb-siem.cred},vers=3.0" 2>/dev/null && { mkdir -p "\$M/SIEM/integrity"; cp -f /var/lib/omni-integrity/chain.jsonl "\$M/SIEM/integrity/"; umount "\$M"; }; rmdir "\$M" 2>/dev/null || true'
Nice=10
EOF
cat > /etc/systemd/system/omni-integrity.timer <<'EOF'
[Unit]
Description=OMNI - Integrite logs (quotidien 03:30)
[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
# Verification automatique hebdomadaire : recalcule toute la chaine et emet
# integrity_state=ok/compromis (alerte mail si rompue, cf. 13).
cat > /etc/systemd/system/omni-integrity-verify.service <<EOF
[Unit]
Description=OMNI - Integrite logs : verification hebdomadaire de la chaine
[Service]
Type=oneshot
ExecStart=${SBIN} --verify
EOF
cat > /etc/systemd/system/omni-integrity-verify.timer <<'EOF'
[Unit]
Description=OMNI - Verification integrite (hebdomadaire, lundi 04:00)
[Timer]
OnCalendar=Mon *-*-* 04:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-integrity.timer >/dev/null 2>&1 && ok "timer actif" || warn "timer KO"
systemctl enable --now omni-integrity-verify.timer >/dev/null 2>&1 && ok "timer verify actif" || warn "timer verify KO"
"$SBIN" || warn "seed initial KO"

echo "==> [4/4] Role Graylog LECTURE SEULE (moindre privilege, anti-suppression)"
# Un role sans droit d'admin : les analystes l'utilisent au lieu du compte admin
# (qui seul peut supprimer index/streams). Reduit la surface de tampering.
# NB : la CREATION de role se fait sur l'endpoint LEGACY /roles (le /authz/roles
# est en LECTURE SEULE -> POST = HTTP 405). La verification se lit sur /authz/roles.
if ! api_get "/authz/roles?per_page=200" 2>/dev/null | jq -e '.roles[]?|select(.name=="OMNI - Analyste (lecture seule)")' >/dev/null 2>&1; then
  jq -n '{name:"OMNI - Analyste (lecture seule)",
          description:"SOC : lecture des flux/recherches/dashboards, AUCUN droit admin (ni suppression). Cf. 60-integrity.sh / ISO A.8.2.",
          read_only:false,
          permissions:["streams:read","dashboards:read","views:read","searches:absolute","searches:relative","searches:keyword","eventdefinitions:read"]}' \
    | api_post "/roles" | jqr '.name' >/dev/null && ok "role 'OMNI - Analyste (lecture seule)' cree" || warn "role refuse (creer manuellement)"
else skip "role lecture seule existe"; fi

echo
echo "=== 60 termine. Verifier la chaine a tout moment : ${SBIN} --verify"
echo "    Registre : /var/lib/omni-integrity/chain.jsonl (+ copie SMB /SIEM/integrity)."
echo "    Affecter les comptes analystes au role LECTURE SEULE ; reserver l'admin"
echo "    (seul a pouvoir supprimer) en break-glass. Cf. docs/PROCEDURE-INTEGRITE-PREUVE.md ==="
