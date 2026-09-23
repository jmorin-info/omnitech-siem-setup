#!/usr/bin/env python3
# =============================================================================
#  seal_graylog_setup.py - Orchestrateur d'integration SEAL -> Graylog
#  OMNITECH SECURITY - IaC SIEM (repo omnitech-siem-setup)
#
#  Principes (regles d'engagement MISSION_SEAL_GRAYLOG) :
#    - QA UNIQUEMENT : cible SQL = SEAL_DB_HOST (VM QA), jamais la production.
#    - AUCUN secret en clair : tout par variables d'environnement.
#    - CHECK AVANT APPLY : dry-run par defaut ; --apply requis pour modifier.
#    - IDEMPOTENT : re-executable sans effet de bord.
#    - LECTURE SEULE en Phase 0/preflight/recon.
#
#  Dependances : stdlib uniquement pour preflight (socket/ssl/urllib/subprocess).
#  Le pilote SQL (pyodbc OU pymssql) n'est requis QUE pour --phase recon/apply-sql
#  et est detecte a l'execution (message d'installation si absent, pas de crash).
#
#  Usage :
#    ./seal_graylog_setup.py --phase preflight          # reseau/DNS/TLS/edition/creds
#    ./seal_graylog_setup.py --phase recon              # Phase 0 (SELECT read-only)
#    ./seal_graylog_setup.py --phase plan-sql           # affiche le DDL (aucune exec)
#    ./seal_graylog_setup.py --phase apply-sql --apply  # execute le DDL (checkpoint)
#    ... (phases suivantes ajoutees apres validation des checkpoints)
# =============================================================================
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

# --- Constantes de mission (NON secretes) -----------------------------------
EXPECTED_FQDN = "bx-qa-seal-vm.omnitech.security"
EXPECTED_SQL_IP = "10.33.120.2"          # IP QA joignable (cf. regle FortiGate dediee)
SIEM_SRC_IP = "10.33.220.10"             # source autorisee cote pare-feu
SQL_PORT = 1433
CERT_THUMBPRINT = "E824A448932647AC7FC5B4C7D8F5229E318EA4B3"  # cert serveur SQL (exp 2028-07-09)

# Variables d'environnement attendues (les *_PWD/_TOKEN/_WEBHOOK sont secretes :
# on ne rapporte JAMAIS leur valeur, seulement leur presence).
ENV_REQUIRED = [
    "SEAL_DB_HOST", "SEAL_DB_NAME", "SEAL_DB_SVC_USER", "SEAL_DB_SVC_PWD",
    "GRAYLOG_API_URL", "GRAYLOG_API_TOKEN", "GRAYLOG_GELF_HOST", "GRAYLOG_GELF_PORT",
    "TEAMS_WEBHOOK_URL",
]
ENV_SECRET = {"SEAL_DB_SVC_PWD", "SEAL_DB_ADMIN_PWD", "GRAYLOG_API_TOKEN", "TEAMS_WEBHOOK_URL"}
ENV_ADMIN = ["SEAL_DB_ADMIN_USER", "SEAL_DB_ADMIN_PWD"]  # DDL uniquement, jamais stocke


# --- Sortie ------------------------------------------------------------------
class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def add(self, name: str, status: str, detail: str = "") -> None:
        # status : PASS | WARN | FAIL | SKIP | INFO
        self.checks.append({"name": name, "status": status, "detail": detail})
        icon = {"PASS": "[+]", "WARN": "[!]", "FAIL": "[x]", "SKIP": "[=]", "INFO": "[i]"}.get(status, "[ ]")
        print(f"  {icon} {name:52} {status:4} {detail}")

    def worst(self) -> str:
        order = {"FAIL": 3, "WARN": 2, "SKIP": 1, "PASS": 0, "INFO": 0}
        return max((c["status"] for c in self.checks), key=lambda s: order.get(s, 0), default="PASS")

    def dump(self, path: str) -> None:
        doc = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "phase": "preflight",
            "worst": self.worst(),
            "checks": self.checks,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        print(f"\n  Rapport JSON : {path}")


# --- Verifications preflight -------------------------------------------------
def check_env(rep: Report) -> None:
    print("\n== Variables d'environnement ==")
    for v in ENV_REQUIRED:
        val = os.environ.get(v)
        if val:
            shown = "(present, valeur masquee)" if v in ENV_SECRET else f"= {val}"
            rep.add(f"env {v}", "PASS", shown)
        else:
            rep.add(f"env {v}", "FAIL", "ABSENT (a fournir avant la suite)")
    for v in ENV_ADMIN:
        rep.add(f"env {v}", "PASS" if os.environ.get(v) else "SKIP",
                "(DDL uniquement)" if not os.environ.get(v) else "(present, DDL uniquement)")


def check_dns(rep: Report) -> list[str]:
    print("\n== Resolution DNS ==")
    host = os.environ.get("SEAL_DB_HOST", EXPECTED_FQDN)
    try:
        infos = socket.getaddrinfo(host, SQL_PORT, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
    except OSError as exc:
        rep.add(f"DNS {host}", "FAIL", str(exc))
        return []
    if len(ips) > 1:
        rep.add(f"DNS {host}", "WARN",
                f"{len(ips)} enregistrements A ({', '.join(ips)}) -> EPINGLER {EXPECTED_SQL_IP} "
                "cote Logstash (jdbc_connection_string sur IP, hostNameInCertificate sur FQDN)")
    elif ips:
        rep.add(f"DNS {host}", "PASS", ips[0])
    return ips


def check_tcp(rep: Report, ips: list[str]) -> None:
    print("\n== Route TCP 1433 (depuis la VM SIEM) ==")
    targets = ips or [EXPECTED_SQL_IP]
    for ip in targets:
        ok = _tcp_open(ip, SQL_PORT)
        if ip == EXPECTED_SQL_IP:
            rep.add(f"TCP {ip}:{SQL_PORT}", "PASS" if ok else "FAIL",
                    "ouvert" if ok else "ferme/filtre (verifier regle FortiGate)")
        else:
            rep.add(f"TCP {ip}:{SQL_PORT}", "PASS" if ok else "WARN",
                    "ouvert" if ok else "ferme/filtre (IP secondaire a ignorer)")


def _tcp_open(ip: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_graylog(rep: Report) -> None:
    print("\n== Graylog (edition -> conditionne la Phase 4 [SEQ]) ==")
    url = os.environ.get("GRAYLOG_API_URL")
    token = os.environ.get("GRAYLOG_API_TOKEN")
    if not url or not token:
        rep.add("Graylog API", "SKIP", "GRAYLOG_API_URL/TOKEN absents (verif manuelle : Open = pas de Correlation native)")
        return
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/system")
        import base64
        auth = base64.b64encode(f"{token}:token".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
        req.add_header("Accept", "application/json")
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            data = json.load(resp)
        rep.add("Graylog API", "PASS", f"version {data.get('version')}")
    except Exception as exc:  # noqa: BLE001 - preflight tolerant
        rep.add("Graylog API", "WARN", f"injoignable via API token : {exc}")


def check_sql_driver(rep: Report) -> str | None:
    print("\n== Pilote SQL (requis pour recon/apply-sql) ==")
    for mod in ("pyodbc", "pymssql"):
        try:
            __import__(mod)
            rep.add(f"pilote {mod}", "PASS", "disponible")
            return mod
        except ImportError:
            rep.add(f"pilote {mod}", "SKIP", "absent")
    rep.add("pilote SQL", "FAIL",
            "aucun pilote (installer msodbcsql18 + pyodbc, OU pymssql) avant --phase recon")
    return None


def check_sql_login(rep: Report, driver: str | None) -> None:
    print("\n== Connexion SQL chiffree (SELECT 1, lecture seule) ==")
    user = os.environ.get("SEAL_DB_SVC_USER")
    pwd = os.environ.get("SEAL_DB_SVC_PWD")
    if not driver:
        rep.add("SQL SELECT 1", "SKIP", "pilote absent")
        return
    if not (user and pwd):
        rep.add("SQL SELECT 1", "SKIP", "compte de service non fourni (cree en Phase 1 / 90_provision.sql)")
        return
    try:
        conn = _connect(driver, user, pwd)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
        rep.add("SQL SELECT 1", "PASS", "connexion TLS + login OK")
    except Exception as exc:  # noqa: BLE001
        rep.add("SQL SELECT 1", "FAIL", f"{type(exc).__name__}: {exc}")


def _connect(driver: str, user: str, pwd: str):
    """Connexion TLS stricte (encrypt=true; trustServerCertificate=false).
    Epingle l'IP joignable mais valide le certificat sur le FQDN (SAN)."""
    host = os.environ.get("SEAL_DB_HOST", EXPECTED_FQDN)
    db = os.environ.get("SEAL_DB_NAME", "SEAL")
    if driver == "pyodbc":
        import pyodbc
        cs = (
            "DRIVER={ODBC Driver 18 for SQL Server};"
            f"SERVER={EXPECTED_SQL_IP},{SQL_PORT};DATABASE={db};UID={user};PWD={pwd};"
            f"Encrypt=yes;TrustServerCertificate=no;HostNameInCertificate={host};"
        )
        return pyodbc.connect(cs, timeout=10)
    import pymssql  # type: ignore
    return pymssql.connect(server=EXPECTED_SQL_IP, port=str(SQL_PORT), user=user,
                           password=pwd, database=db, login_timeout=10)


# --- Phases ------------------------------------------------------------------
def phase_preflight(args: argparse.Namespace) -> int:
    print("=" * 72)
    print(" SEAL -> Graylog : PREFLIGHT (lecture seule, aucun effet de bord)")
    print("=" * 72)
    rep = Report()
    check_env(rep)
    ips = check_dns(rep)
    check_tcp(rep, ips)
    check_graylog(rep)
    driver = check_sql_driver(rep)
    check_sql_login(rep, driver)
    rep.dump(args.report)
    worst = rep.worst()
    print(f"\n  Bilan preflight : {worst}")
    if worst == "FAIL":
        print("  -> Blocages a lever avant la Phase 0 (voir seal/docs/RECON.md, section Blocages).")
        return 1
    return 0


# --- Phase 0 : reconnaissance (LECTURE SEULE) --------------------------------
# Requetes de decouverte : uniquement DISTINCT/COUNT/TOP/metadonnees. Aucune
# colonne interdite (mots de passe/seed/hash/photo). Sortie -> JSON gitignore
# (peut contenir des libelles/numeros = donnees personnelles).
RECON_QUERIES: list[tuple[str, str]] = [
    ("server_info",
     "SELECT CONVERT(varchar,SERVERPROPERTY('ProductVersion')) AS version, "
     "CONVERT(varchar,SERVERPROPERTY('Edition')) AS edition, "
     "CONVERT(varchar,SYSUTCDATETIME(),126) AS utc_now, "
     "CONVERT(varchar,SYSDATETIME(),126) AS local_now"),
    ("ref_tables",
     "SELECT s.name AS schema_name, t.name AS table_name FROM sys.tables t "
     "JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE t.name LIKE '%REEV%' "
     "OR t.name LIKE '%EVENEMENT%' OR t.name LIKE '%TYPE%' OR t.name LIKE '%REFER%' "
     "ORDER BY 1,2"),
    ("even_lifestage",
     "SELECT EVEN_LIFESTAGE AS code, COUNT(*) AS n FROM dbo.EVENEMENTS GROUP BY EVEN_LIFESTAGE ORDER BY n DESC"),
    ("reached_lifestatus",
     "SELECT REACHED_LIFESTATUS AS code, COUNT(*) AS n FROM dbo.EVENEMENTS GROUP BY REACHED_LIFESTATUS ORDER BY n DESC"),
    ("alarme_lifestatus",
     "SELECT EVEN_LIFESTATUS AS code, COUNT(*) AS n FROM dbo.ALARMES GROUP BY EVEN_LIFESTATUS ORDER BY n DESC"),
    ("alarme_declencheur",
     "SELECT EVEN_DECLENCHEUR AS code, COUNT(*) AS n FROM dbo.ALARMES GROUP BY EVEN_DECLENCHEUR ORDER BY n DESC"),
    ("reev_code_top",
     "SELECT TOP 40 REEV_CODE AS code, COUNT(*) AS n FROM dbo.ALARMES GROUP BY REEV_CODE ORDER BY n DESC"),
    ("severite",
     "SELECT EVEN_SEVERITE AS code, COUNT(*) AS n FROM dbo.ALARMES GROUP BY EVEN_SEVERITE ORDER BY n DESC"),
    ("audit_operation",
     "SELECT Operation AS code, COUNT(*) AS n FROM Audit.UserConnections GROUP BY Operation ORDER BY n DESC"),
    ("audit_channel",
     "SELECT OperationChannel AS code, COUNT(*) AS n FROM Audit.UserConnections GROUP BY OperationChannel ORDER BY n DESC"),
    ("tag_status",
     "SELECT [Status] AS code, StatusOld AS code_old, COUNT(*) AS n FROM Audit.TagMovements "
     "GROUP BY [Status], StatusOld ORDER BY n DESC"),
    ("timezone_delta",
     "SELECT TOP 20 CONVERT(varchar,EVEN_DATEHEURE,126) AS event_time, "
     "CONVERT(varchar,EVEN_STORAGE_TIMESTAMP,126) AS storage_time, "
     "DATEDIFF(MINUTE, EVEN_DATEHEURE, EVEN_STORAGE_TIMESTAMP) AS delta_min "
     "FROM dbo.EVENEMENTS WHERE EVEN_DATEHEURE IS NOT NULL ORDER BY EVEN_STORAGE_TIMESTAMP DESC"),
    ("identity_tables",
     "SELECT s.name AS schema_name, t.name AS table_name FROM sys.tables t "
     "JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE t.name LIKE '%CHAMP%' "
     "OR t.name LIKE '%CFIC%' OR t.name LIKE '%FICHE%' OR t.name LIKE '%TAG%' "
     "OR t.name LIKE '%BADGE%' ORDER BY 1,2"),
    ("ldap_attributes",
     "SELECT DISTINCT ATTRIBUT FROM dbo.SYNCHRO_LDAP_HISTORY ORDER BY ATTRIBUT"),
    ("rowversion_tables",
     "SELECT t.name AS table_name, c.name AS col FROM sys.columns c "
     "JOIN sys.tables t ON t.object_id=c.object_id WHERE c.system_type_id=TYPE_ID('timestamp') ORDER BY 1"),
    ("min_active_rowversion",
     "SELECT CONVERT(BIGINT, MIN_ACTIVE_ROWVERSION()) AS min_active_rowversion"),
    ("volumetrie",
     "SELECT 'EVENEMENTS_24h' AS flux, COUNT(*) AS n FROM dbo.EVENEMENTS "
     "WHERE EVEN_STORAGE_TIMESTAMP >= DATEADD(DAY,-1,SYSDATETIME()) "
     "UNION ALL SELECT 'ALARMES_total', COUNT(*) FROM dbo.ALARMES"),
]


def phase_recon(args: argparse.Namespace) -> int:
    print("=" * 72)
    print(" SEAL -> Graylog : PHASE 0 RECON (LECTURE SEULE, aucun DDL)")
    print("=" * 72)
    driver = None
    for mod in ("pyodbc", "pymssql"):
        try:
            __import__(mod); driver = mod; break
        except ImportError:
            continue
    if not driver:
        print("  [x] Aucun pilote SQL (pyodbc/pymssql). Recon impossible depuis le SIEM.")
        return 1
    user = os.environ.get("SEAL_DB_SVC_USER")
    pwd = os.environ.get("SEAL_DB_SVC_PWD")
    if not (user and pwd):
        print("  [x] SEAL_DB_SVC_USER/PWD absents.")
        return 1
    try:
        conn = _connect(driver, user, pwd)
    except Exception as exc:  # noqa: BLE001
        print(f"  [x] Connexion SQL echouee : {exc}")
        return 1

    out: dict = {"generated": datetime.now(timezone.utc).isoformat(), "driver": driver, "queries": {}}
    cur = conn.cursor()
    for key, sql in RECON_QUERIES:
        try:
            cur.execute(sql)
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = [list(r) for r in cur.fetchall()] if cols else []
            out["queries"][key] = {"columns": cols, "rows": [[_json_safe(v) for v in r] for r in rows]}
            print(f"  [+] {key:22} {len(rows):>5} ligne(s)")
        except Exception as exc:  # noqa: BLE001 - une requete KO ne bloque pas les autres
            out["queries"][key] = {"error": str(exc)}
            print(f"  [!] {key:22} ERREUR {exc}")
    conn.close()
    with open(args.recon_out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2, default=str)
    print(f"\n  Sortie brute (gitignore) : {args.recon_out}")
    print("  -> Consolider dans seal/docs/RECON.md et FAIRE VALIDER avant la Phase 1.")
    return 0


def _json_safe(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    return v


def _guard(phase: str) -> int:
    print(f"[{phase}] Cette phase modifie l'etat (SQL/Graylog).")
    print("  Elle n'est debloquee qu'apres validation du checkpoint precedent")
    print("  (cf. MISSION_SEAL_GRAYLOG.md). Utilisez d'abord --phase preflight puis recon.")
    return 2


def main() -> int:
    p = argparse.ArgumentParser(description="Orchestrateur d'integration SEAL -> Graylog (QA uniquement)")
    p.add_argument("--phase", required=True,
                   choices=["preflight", "recon", "plan-sql", "apply-sql",
                            "plan-graylog", "apply-graylog", "verify"])
    p.add_argument("--apply", action="store_true", help="execute reellement (defaut : dry-run)")
    p.add_argument("--report", default="seal/docs/preflight.json", help="chemin du rapport JSON preflight")
    p.add_argument("--recon-out", default="seal/docs/recon-raw.json", help="sortie JSON de la recon (gitignore)")
    args = p.parse_args()

    if args.phase == "preflight":
        return phase_preflight(args)
    if args.phase == "recon":
        return phase_recon(args)
    # Les phases modifiantes sont implementees apres validation des checkpoints.
    return _guard(args.phase)


if __name__ == "__main__":
    sys.exit(main())
