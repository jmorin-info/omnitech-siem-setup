#!/usr/bin/env bash
# =============================================================================
# regen_reev_lookup.sh - Regenere le CSV de decodage REEV (REEV_CODE -> libelle)
#   depuis SEAL (dbo.REF_EVENEMENT, LECTURE SEULE) et l'installe dans
#   /etc/graylog/lookup/omni-seal-reev.csv (adapter csvfile omni-seal-reev-adapter).
#
#   A executer par cron (ex : toutes les nuits). Idempotent : ecriture atomique
#   (tmp + mv) et remplacement du CSV cible UNIQUEMENT s'il a change -> l'adapter
#   csvfile de Graylog recharge alors le fichier (check_interval=60 s).
#
#   Regles d'engagement :
#     - QA UNIQUEMENT : IP epinglee 10.33.120.2, cert valide sur le FQDN.
#     - AUCUN secret en clair : identifiants via variables d'environnement.
#     - LECTURE SEULE : un seul SELECT sur le referentiel, aucun DDL/DML.
#
#   Variables d'environnement (a fournir hors code, ex : /etc/graylog/seal.env
#   charge par le service cron, mode 600) :
#     SEAL_DB_SVC_USER   login SQL du compte de service (svc_graylog_seal)
#     SEAL_DB_SVC_PWD    mot de passe (JAMAIS en clair dans ce fichier)
#     SEAL_DB_HOST       (optionnel) FQDN cible ; defaut bx-qa-seal-vm.omnitech.security
#     SEAL_DB_NAME       (optionnel) defaut SEAL
#
#   Prerequis : seal/.venv (pymssql installe), droit d'ecriture sur /etc/graylog/lookup.
# =============================================================================
set -euo pipefail

# --- Localisation (script dans seal/graylog/ ; venv dans seal/.venv) ---------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEAL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_PY="${SEAL_DIR}/.venv/bin/python"

LOOKUP_DIR="/etc/graylog/lookup"
DEST="${LOOKUP_DIR}/omni-seal-reev.csv"

# --- Cibles NON secretes (QA, IP epinglee) ----------------------------------
SEAL_DB_IP="${SEAL_DB_IP:-10.33.120.2}"
SEAL_DB_PORT="${SEAL_DB_PORT:-1433}"
SEAL_DB_HOST="${SEAL_DB_HOST:-bx-qa-seal-vm.omnitech.security}"
SEAL_DB_NAME="${SEAL_DB_NAME:-SEAL}"

log() { printf '    [%s] %s\n' "$1" "$2"; }

[[ -x "${VENV_PY}" ]] || { echo "ERREUR: venv Python absent (${VENV_PY})" >&2; exit 1; }
: "${SEAL_DB_SVC_USER:?SEAL_DB_SVC_USER absent (compte de service SQL, via env)}"
: "${SEAL_DB_SVC_PWD:?SEAL_DB_SVC_PWD absent (via env, jamais en clair dans le script)}"

mkdir -p "${LOOKUP_DIR}"
TMP="$(mktemp "${LOOKUP_DIR}/.omni-seal-reev.XXXXXX.csv")"
trap 'rm -f "${TMP}"' EXIT

# --- Extraction (LECTURE SEULE) : pymssql, TLS server-side (ForceEncryption=1),
#     IP epinglee. Le compte de service n'a que SELECT sur les vues/referentiel. -
# MULTI-SITE : union des codes REEV de TOUS les SEAL (QA via SEAL_DB_*, sites
# additionnels via SEAL2_DB_*, SEAL3_DB_*, ...). Un site peut avoir des codes
# absents des autres (OMEGA : ~20 codes en plus) -> sans union, alarmes non
# decodees sur ce site.
SEAL_DB_IP="${SEAL_DB_IP}" SEAL_DB_PORT="${SEAL_DB_PORT}" SEAL_DB_NAME="${SEAL_DB_NAME}" \
SEAL_DB_HOST="${SEAL_DB_HOST}" SEAL_DB_SVC_USER="${SEAL_DB_SVC_USER}" SEAL_DB_SVC_PWD="${SEAL_DB_SVC_PWD}" \
SEAL2_DB_HOST="${SEAL2_DB_HOST:-}" SEAL2_DB_SVC_USER="${SEAL2_DB_SVC_USER:-}" SEAL2_DB_SVC_PWD="${SEAL2_DB_SVC_PWD:-}" \
"${VENV_PY}" - "${TMP}" <<'PY'
import csv, os, sys
import pymssql  # fourni par seal/.venv

dest = sys.argv[1]
sites = [(os.environ.get("SEAL_DB_IP") or os.environ.get("SEAL_DB_HOST"),
          os.environ["SEAL_DB_SVC_USER"], os.environ["SEAL_DB_SVC_PWD"])]
if os.environ.get("SEAL2_DB_SVC_PWD"):
    sites.append((os.environ.get("SEAL2_DB_HOST"),
                  os.environ["SEAL2_DB_SVC_USER"], os.environ["SEAL2_DB_SVC_PWD"]))

pairs, errors, nsite = {}, [], 0
for server, user, pwd in sites:
    if not server:
        continue
    try:
        conn = pymssql.connect(server=server, port=os.environ.get("SEAL_DB_PORT", "1433"),
                               user=user, password=pwd,
                               database=os.environ.get("SEAL_DB_NAME", "SEAL"),
                               login_timeout=15, timeout=60)
        cur = conn.cursor()
        cur.execute("SELECT REEV_CODE, REEV_LIBELLE FROM dbo.vw_SealReev_SIEM WHERE REEV_CODE IS NOT NULL")
        for code, lib in cur.fetchall():
            code = "" if code is None else str(code).strip()
            if not code:
                continue
            pairs.setdefault(code, "" if lib is None else str(lib).strip())  # union, 1re occurrence
        conn.close(); nsite += 1
    except Exception as exc:
        errors.append(f"{server}: {exc}")

with open(dest, "w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["REEV_CODE", "REEV_LIBELLE"])
    for code in sorted(pairs):
        w.writerow([code, pairs[code]])

if not pairs:
    print("ERREUR: 0 code REEV extrait ; " + "; ".join(errors), file=sys.stderr)
    sys.exit(2)
print(f"    [+] {len(pairs)} codes REEV (union {nsite} site(s))"
      + (f" ; erreurs: {'; '.join(errors)}" if errors else ""), file=sys.stderr)
PY

# --- Installation atomique + remplacement conditionnel (idempotence) ---------
if [[ -f "${DEST}" ]] && cmp -s "${TMP}" "${DEST}"; then
  log "=" "omni-seal-reev.csv inchange (aucun rechargement necessaire)"
  exit 0
fi

install -m 644 "${TMP}" "${DEST}"
chown root:graylog "${DEST}" 2>/dev/null || true
log "+" "omni-seal-reev.csv installe (${DEST}) -> recharge par l'adapter csvfile (<=60 s)"
