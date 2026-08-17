#!/usr/bin/env bash
# =============================================================================
# regen_zone_lookup.sh - Regenere le CSV de resolution ZONE physique
#   depuis SEAL (dbo.vw_SealZone_SIEM, LECTURE SEULE) vers
#   /etc/graylog/lookup/omni-seal-zone.csv (adapter csvfile omni-seal-zone-adapter).
#
#   CLE COMPOSITE seal_site:OBFI_ID (un OBFI_ID peut collisionner entre sites).
#   La regle pipeline 16-seal-zone construit la meme cle -> seal_zone.
#
#   MULTI-SITE : union de tous les SEAL. Chaque site est prefixe par SA valeur
#   seal_site (celle posee par Logstash : QA=bx-qa-seal-vm, OMEGA=bx-seal-omega).
#
#   Idempotent : ecriture atomique + remplacement conditionnel (l'adapter csvfile
#   recharge sous 60 s). Prerequis : vw_SealZone_SIEM deployee (07_) + GRANT svc.
#   Identifiants via env (jamais en clair), comme regen_reev_lookup.sh.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEAL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_PY="${SEAL_DIR}/.venv/bin/python"

LOOKUP_DIR="/etc/graylog/lookup"
DEST="${LOOKUP_DIR}/omni-seal-zone.csv"

# --- Cibles NON secretes ; libelles seal_site (DOIVENT matcher les add_field Logstash)
SEAL_DB_IP="${SEAL_DB_IP:-10.33.120.2}"
SEAL_DB_PORT="${SEAL_DB_PORT:-1433}"
SEAL_DB_HOST="${SEAL_DB_HOST:-bx-qa-seal-vm.omnitech.security}"
SEAL_DB_NAME="${SEAL_DB_NAME:-SEAL}"
SEAL_SITE="${SEAL_SITE:-bx-qa-seal-vm}"
SEAL2_SITE="${SEAL2_SITE:-bx-seal-omega}"

log() { printf '    [%s] %s\n' "$1" "$2"; }

[[ -x "${VENV_PY}" ]] || { echo "ERREUR: venv Python absent (${VENV_PY})" >&2; exit 1; }
: "${SEAL_DB_SVC_USER:?SEAL_DB_SVC_USER absent (compte de service SQL, via env)}"
: "${SEAL_DB_SVC_PWD:?SEAL_DB_SVC_PWD absent (via env, jamais en clair dans le script)}"

mkdir -p "${LOOKUP_DIR}"
TMP="$(mktemp "${LOOKUP_DIR}/.omni-seal-zone.XXXXXX.csv")"
trap 'rm -f "${TMP}"' EXIT

SEAL_DB_IP="${SEAL_DB_IP}" SEAL_DB_PORT="${SEAL_DB_PORT}" SEAL_DB_NAME="${SEAL_DB_NAME}" \
SEAL_DB_HOST="${SEAL_DB_HOST}" SEAL_DB_SVC_USER="${SEAL_DB_SVC_USER}" SEAL_DB_SVC_PWD="${SEAL_DB_SVC_PWD}" \
SEAL_SITE="${SEAL_SITE}" SEAL2_SITE="${SEAL2_SITE}" \
SEAL2_DB_HOST="${SEAL2_DB_HOST:-}" SEAL2_DB_SVC_USER="${SEAL2_DB_SVC_USER:-}" SEAL2_DB_SVC_PWD="${SEAL2_DB_SVC_PWD:-}" \
"${VENV_PY}" - "${TMP}" <<'PY'
import csv, os, sys
import pymssql

dest = sys.argv[1]
# (serveur, user, pwd, libelle seal_site)
sites = [(os.environ.get("SEAL_DB_IP") or os.environ.get("SEAL_DB_HOST"),
          os.environ["SEAL_DB_SVC_USER"], os.environ["SEAL_DB_SVC_PWD"],
          os.environ.get("SEAL_SITE", "bx-qa-seal-vm"))]
if os.environ.get("SEAL2_DB_SVC_PWD"):
    sites.append((os.environ.get("SEAL2_DB_HOST"),
                  os.environ["SEAL2_DB_SVC_USER"], os.environ["SEAL2_DB_SVC_PWD"],
                  os.environ.get("SEAL2_SITE", "bx-seal-omega")))

rows, errors, nsite = {}, [], 0
for server, user, pwd, site in sites:
    if not server:
        continue
    try:
        conn = pymssql.connect(server=server, port=os.environ.get("SEAL_DB_PORT", "1433"),
                               user=user, password=pwd,
                               database=os.environ.get("SEAL_DB_NAME", "SEAL"),
                               login_timeout=15, timeout=60)
        cur = conn.cursor()
        cur.execute("SELECT OBFI_ID, ZONE_PATH FROM dbo.vw_SealZone_SIEM WHERE OBFI_ID IS NOT NULL")
        for obfi, zpath in cur.fetchall():
            if obfi is None:
                continue
            key = f"{site}:{int(obfi)}"          # cle composite = seal_site:OBFI_ID
            rows[key] = "" if zpath is None else str(zpath).strip()
        conn.close(); nsite += 1
    except Exception as exc:
        errors.append(f"{server}: {exc}")

with open(dest, "w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["SITE_OBFI", "ZONE_PATH"])
    for key in sorted(rows):
        w.writerow([key, rows[key]])

if not rows:
    print("ATTENTION: 0 zone extraite (vw_SealZone_SIEM vide ou jointure topologie a "
          "finaliser, cf 07_recon_topology.sql) ; " + "; ".join(errors), file=sys.stderr)
    # on ecrit quand meme l'entete (CSV valide) ; sortie 0 : le lookup reste inerte
else:
    print(f"    [+] {len(rows)} objets->zone (union {nsite} site(s))"
          + (f" ; erreurs: {'; '.join(errors)}" if errors else ""), file=sys.stderr)
PY

# --- Installation atomique + remplacement conditionnel -----------------------
if [[ -f "${DEST}" ]] && cmp -s "${TMP}" "${DEST}"; then
  log "=" "omni-seal-zone.csv inchange"
  exit 0
fi
install -m 644 "${TMP}" "${DEST}"
chown root:graylog "${DEST}" 2>/dev/null || true
log "+" "omni-seal-zone.csv installe (${DEST}) -> recharge par l'adapter csvfile (<=60 s)"
