#!/usr/bin/env python3
# =============================================================================
#  provision_seal.py - Provisioning Graylog de la couche SEAL (collecte + normalisation)
#  OMNITECH SECURITY - IaC SIEM (repo omnitech-siem-setup) - autorite : seal/docs/CONTRACT.md
#
#  Cree (idempotent, recherche-par-titre/prefixe AVANT creation) :
#    - 3 index sets : omni-seal-access (12 mois) / omni-seal-alarm (12 mois) /
#      omni-seal-audit (24 mois), rotation quotidienne + DeletionRetentionStrategy
#      (meme motif que 79-interne-indexset.sh).
#    - 3 streams routes par (event_source==seal AND event_domain==<domaine>) :
#      "OMNI - SEAL Accès" / "OMNI - SEAL Alarmes" / "OMNI - SEAL Audit".
#      Les champs de routage sont poses a l'ingest par le collecteur (GELF) car
#      les regles de stream sont evaluees AVANT le pipeline.
#    - reutilise l'input GELF HTTP existant (aucun nouvel input cree).
#    - lookup table omni-seal-reev (adapter csvfile REEV_CODE -> REEV_LIBELLE),
#      CSV /etc/graylog/lookup/omni-seal-reev.csv (regenere par regen_reev_lookup.sh).
#    - regles + pipelines de normalisation (charges depuis pipelines/*.rule) et
#      connexion pipeline<->stream.
#
#  Regles d'engagement :
#    - AUCUN secret en clair : auth par GRAYLOG_API_TOKEN (env) ; a defaut, repli
#      basic auth admin via GRAYLOG_ADMIN_PASS (env, cf lib-graylog.sh).
#    - DRY-RUN PAR DEFAUT : lecture seule (GET) ; --apply requis pour tout POST/PUT.
#    - IDEMPOTENT : re-executable sans effet de bord (create-or-update).
#
#  Usage :
#    ./provision_seal.py                 # dry-run (montre le plan, aucune ecriture)
#    ./provision_seal.py --apply         # applique
#    GRAYLOG_API_URL=https://siem:9000 GRAYLOG_API_TOKEN=xxxxx ./provision_seal.py --apply
# =============================================================================
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# --- Constantes NON secretes -------------------------------------------------
LOOKUP_DIR = "/etc/graylog/lookup"
REEV_CSV = "omni-seal-reev.csv"                      # regenere par regen_reev_lookup.sh
IDENTITY_CSV = "seal-identity.csv"                   # regenere par regen-seal-identity.sh (matricule->UPN)
DEFAULT_CA = "/etc/graylog/certs/omnitech-rootca.crt"
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pipelines")
UA = "provision_seal.py"

# Pont d'identite badge->matricule->UPN : regle partagee (stage TERMINAL des 3
# pipelines SEAL) + lookup matricule->UPN. Cf 14-seal-identity-upn.rule et
# regen-seal-identity.sh. Resout identity_upn (cle de jointure avec les logons AD).
IDENTITY_RULE_FILE = "14-seal-identity-upn.rule"
IDENTITY_RULE_NAME = "omni-seal-identity-upn"
# Pont CONSOLE SEAL -> compte AD : normalise actor_login en identity_console
# (login seul, minuscules) = cle de jointure fiable avec les logons Windows.
CONSOLE_RULE_FILE = "15-seal-console-identity.rule"
CONSOLE_RULE_NAME = "omni-seal-console-identity"
ZONE_RULE_FILE = "16-seal-zone.rule"
ZONE_RULE_NAME = "omni-seal-zone"
ZONE_CSV = "omni-seal-zone.csv"                      # regenere par regen_zone_lookup.sh (cle seal_site:OBFI_ID -> zone)

# 3 domaines SEAL (cf CONTRACT D0/D4). retention_days ~ mois*30 (rotation P1D).
DOMAINS = [
    {
        "key": "access",
        "domain_value": "access",                    # valeur event_domain (ingest)
        "stream_title": "OMNI - SEAL Accès",
        "index_prefix": "omni-seal-access",
        "index_title": "OMNI - SEAL Accès",
        "retention_days": 365,                        # 12 mois
        "pipeline_title": "OMNI - SEAL Accès",
        "rule_file": "10-seal-access.rule",
        "stages": [["omni-seal-access-normalize"]],   # 1 stage
    },
    {
        "key": "alarm",
        "domain_value": "alarm",
        "stream_title": "OMNI - SEAL Alarmes",
        "index_prefix": "omni-seal-alarm",
        "index_title": "OMNI - SEAL Alarmes",
        "retention_days": 365,                        # 12 mois
        "pipeline_title": "OMNI - SEAL Alarmes",
        "rule_file": "11-seal-alarm.rule",
        "stages": [["omni-seal-alarm-normalize"]],
    },
    {
        "key": "audit",
        "domain_value": "hypervisor_audit",
        "stream_title": "OMNI - SEAL Audit",
        "index_prefix": "omni-seal-audit",
        "index_title": "OMNI - SEAL Audit",
        "retention_days": 730,                        # 24 mois
        "pipeline_title": "OMNI - SEAL Audit",
        "rule_file": "12-seal-audit.rule",
        "stages": [["omni-seal-audit-normalize"],
                   ["omni-seal-audit-outcome-fail"]], # 2 stages (override d'issue)
    },
]


# --- Sortie ------------------------------------------------------------------
def _p(icon: str, msg: str) -> None:
    print(f"    [{icon}] {msg}")


ok = lambda m: _p("+", m)     # noqa: E731
skip = lambda m: _p("=", m)   # noqa: E731
warn = lambda m: _p("!", m)   # noqa: E731
info = lambda m: _p("i", m)   # noqa: E731


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"ERREUR: {msg}", file=sys.stderr)
    sys.exit(1)


# --- Client Graylog (stdlib urllib, comme seal_graylog_setup.py) -------------
class Graylog:
    def __init__(self, apply: bool) -> None:
        self.apply = apply
        url = os.environ.get("GRAYLOG_API_URL")
        if not url:
            die("GRAYLOG_API_URL absent (ex: https://bx-siem.omnitech.security:9000)")
        url = url.rstrip("/")
        self.base = url if url.endswith("/api") else url + "/api"

        token = os.environ.get("GRAYLOG_API_TOKEN", "").strip()
        if token:
            raw = f"{token}:token"
            self.auth_desc = "token de service"
        else:
            pwd = os.environ.get("GRAYLOG_ADMIN_PASS", "")
            if not pwd:
                die("ni GRAYLOG_API_TOKEN ni GRAYLOG_ADMIN_PASS fournis (aucune auth possible)")
            raw = f"admin:{pwd}"
            self.auth_desc = "basic auth admin (repli)"
        self.authz = "Basic " + base64.b64encode(raw.encode()).decode()

        # TLS : CA interne si presente, sinon contexte par defaut. Repli non-verifie
        # explicite via GRAYLOG_API_INSECURE=1 (localhost auto-signe uniquement).
        ca = os.environ.get("GRAYLOG_API_CA", DEFAULT_CA)
        if os.environ.get("GRAYLOG_API_INSECURE") == "1":
            self.ctx = ssl._create_unverified_context()
        elif os.path.exists(ca):
            self.ctx = ssl.create_default_context(cafile=ca)
        else:
            self.ctx = ssl.create_default_context()

    def _req(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | list | None]:
        req = urllib.request.Request(self.base + path, method=method)
        req.add_header("Authorization", self.authz)
        req.add_header("Accept", "application/json")
        req.add_header("X-Requested-By", UA)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data=data, timeout=30, context=self.ctx) as resp:
                txt = resp.read().decode("utf-8") or "null"
                return resp.status, json.loads(txt)
        except urllib.error.HTTPError as exc:
            txt = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(txt)
            except ValueError:
                payload = {"_raw": txt}
            return exc.code, payload

    def get(self, path: str):
        return self._req("GET", path)[1]

    def post(self, path: str, body: dict):
        return self._req("POST", path, body)

    def put(self, path: str, body: dict):
        return self._req("PUT", path, body)

    # POST avec repli enveloppe CreateEntityRequest (Graylog 7.x, cf lib-graylog.sh)
    def post_entity(self, path: str, body: dict):
        code, payload = self.post(path, body)
        if isinstance(payload, dict) and "entity cannot be null" in json.dumps(payload):
            wrapped = {"entity": body, "share_request": {"selected_grantee_capabilities": {}}}
            code, payload = self.post(path, wrapped)
        return code, payload


# --- Idempotence : recherche-par-titre/prefixe -------------------------------
def find_index_set(gl: Graylog, prefix: str) -> str | None:
    data = gl.get("/system/indices/index_sets?skip=0&limit=500") or {}
    for s in data.get("index_sets", []):
        if s.get("index_prefix") == prefix:
            return s.get("id")
    return None


def ensure_index_set(gl: Graylog, d: dict) -> str | None:
    existing = find_index_set(gl, d["index_prefix"])
    if existing:
        skip(f"index set '{d['index_prefix']}' existe ({existing})")
        return existing
    body = {
        "title": d["index_title"],
        "description": f"Provisionne par provision_seal.py (SEAL {d['key']}, retention {d['retention_days']} j)",
        "index_prefix": d["index_prefix"],
        "shards": 1,
        "replicas": 0,
        "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
        "rotation_strategy": {
            "type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",
            "rotation_period": "P1D",
            "rotate_empty_index_set": False,
        },
        "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
        "retention_strategy": {
            "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
            "max_number_of_indices": d["retention_days"],
        },
        "index_analyzer": "standard",
        "index_optimization_max_num_segments": 1,
        "index_optimization_disabled": False,
        "field_type_refresh_interval": 5000,
        "writable": True,
        "creation_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }
    if not gl.apply:
        info(f"[dry-run] creerait index set '{d['index_prefix']}' ({d['retention_days']} j)")
        return None
    code, payload = gl.post("/system/indices/index_sets", body)
    iid = payload.get("id") if isinstance(payload, dict) else None
    if iid:
        ok(f"index set '{d['index_prefix']}' cree ({iid})")
        return iid
    warn(f"index set '{d['index_prefix']}' REFUSE (HTTP {code}) : {payload}")
    return None


def find_stream(gl: Graylog, title: str) -> dict | None:
    data = gl.get("/streams") or {}
    for s in data.get("streams", []):
        if s.get("title") == title:
            return s
    return None


def ensure_stream(gl: Graylog, d: dict, index_set_id: str | None) -> str | None:
    existing = find_stream(gl, d["stream_title"])
    if existing:
        sid = existing.get("id")
        skip(f"stream '{d['stream_title']}' existe ({sid})")
        # realignement index set si necessaire (idempotent)
        if index_set_id and existing.get("index_set_id") != index_set_id and gl.apply:
            body = {
                "title": existing.get("title"),
                "description": existing.get("description") or d["stream_title"],
                "matching_type": existing.get("matching_type", "AND"),
                "remove_matches_from_default_stream": existing.get("remove_matches_from_default_stream", True),
                "index_set_id": index_set_id,
            }
            code, _ = gl.put(f"/streams/{sid}", body)
            ok(f"stream '{d['stream_title']}' reaffecte a l'index set {index_set_id}") if code == 200 \
                else warn(f"reaffectation stream KO (HTTP {code})")
        return sid

    if not index_set_id:
        warn(f"[dry-run] index set '{d['index_prefix']}' non cree -> stream '{d['stream_title']}' non planifiable en dry-run")
    # Regles de routage : event_source==seal AND event_domain==<domaine> (type 1 = exact)
    rules = [
        {"field": "event_source", "type": 1, "value": "seal", "inverted": False},
        {"field": "event_domain", "type": 1, "value": d["domain_value"], "inverted": False},
    ]
    body = {
        "title": d["stream_title"],
        "description": f"SEAL {d['key']} (route event_source=seal, event_domain={d['domain_value']})",
        "matching_type": "AND",
        "remove_matches_from_default_stream": True,
        "index_set_id": index_set_id,
        "rules": rules,
    }
    if not gl.apply:
        info(f"[dry-run] creerait stream '{d['stream_title']}' (AND event_source=seal, event_domain={d['domain_value']})")
        return None
    if not index_set_id:
        warn(f"stream '{d['stream_title']}' non cree : index set absent")
        return None
    code, payload = gl.post_entity("/streams", body)
    sid = None
    if isinstance(payload, dict):
        sid = payload.get("stream_id") or payload.get("id")
    if sid:
        gl.post(f"/streams/{sid}/resume", {})
        ok(f"stream '{d['stream_title']}' cree + demarre ({sid})")
        return sid
    warn(f"stream '{d['stream_title']}' REFUSE (HTTP {code}) : {payload}")
    return None


# --- Input GELF HTTP existant (reutilise, jamais recree) ---------------------
SEAL_GELF_INPUT_TITLE = "OMNI - SEAL (GELF TCP 12202)"
SEAL_GELF_INPUT_TYPE = "org.graylog2.inputs.gelf.tcp.GELFTCPInput"
SEAL_GELF_PORT = 12202


def check_gelf_input(gl: Graylog) -> None:
    """Input GELF TCP DEDIE a SEAL (idempotent, par titre). TCP : livraison fiable
    (le collecteur JDBC produit des lots volumineux -> pas de perte UDP, pas de
    limite de taille sur les payloads audit). Isole la source SEAL (attribution/
    audit). Bind 127.0.0.1 : seul Logstash local emet (pas d'exposition reseau).
    L'output Logstash `gelf` est configure protocol => TCP vers ce port."""
    data = gl.get("/system/inputs") or {}
    for i in data.get("inputs", []):
        if i.get("title") == SEAL_GELF_INPUT_TITLE:
            skip(f"input '{SEAL_GELF_INPUT_TITLE}' existe ({i.get('id')})")
            return
    body = {
        "title": SEAL_GELF_INPUT_TITLE,
        "type": SEAL_GELF_INPUT_TYPE,
        "global": True,
        "configuration": {
            "bind_address": "127.0.0.1",
            "port": SEAL_GELF_PORT,
            "recv_buffer_size": 1048576,
            "number_worker_threads": 2,
            "tls_enable": False,
            "use_null_delimiter": True,
            "max_message_size": 2097152,
            "decompress_size_limit": 8388608,
            "tcp_keepalive": False,
            "charset_name": "UTF-8",
        },
    }
    if not gl.apply:
        info(f"[dry-run] creerait input GELF UDP '{SEAL_GELF_INPUT_TITLE}' (127.0.0.1:{SEAL_GELF_PORT})")
        return
    code, resp = gl.post("/system/inputs", body)
    if code in (200, 201) and isinstance(resp, dict) and resp.get("id"):
        ok(f"input '{SEAL_GELF_INPUT_TITLE}' cree ({resp['id']})")
    else:
        warn(f"echec creation input GELF UDP (HTTP {code})")


# --- Lookup omni-seal-reev (adapter csvfile + cache guava + table) -----------
def ensure_reev_lookup(gl: Graylog) -> None:
    name = "seal-reev"
    csv_path = os.path.join(LOOKUP_DIR, REEV_CSV)
    if not os.path.exists(csv_path):
        warn(f"CSV {csv_path} absent -> lancer regen_reev_lookup.sh d'abord "
             "(la table se creera mais restera vide tant que le CSV n'existe pas)")

    # Adapter
    adapters = gl.get("/system/lookup/adapters") or {}
    aid = next((a.get("id") for a in adapters.get("data_adapters", [])
                if a.get("name") == f"omni-{name}-adapter"), None)
    if aid:
        skip(f"adapter 'omni-{name}-adapter' existe")
    elif not gl.apply:
        info("[dry-run] creerait adapter csvfile 'omni-seal-reev-adapter'")
    else:
        body = {
            "name": f"omni-{name}-adapter",
            "title": "OMNI - SEAL REEV (adapter)",
            "description": "REEV_CODE -> REEV_LIBELLE (regenere par regen_reev_lookup.sh)",
            "config": {
                "type": "csvfile", "path": csv_path, "separator": ",", "quotechar": "\"",
                "key_column": "REEV_CODE", "value_column": "REEV_LIBELLE",
                "check_interval": 60, "case_insensitive_lookup": True, "cidr_lookup": False,
            },
        }
        code, payload = gl.post("/system/lookup/adapters", body)
        aid = payload.get("id") if isinstance(payload, dict) else None
        ok("adapter 'omni-seal-reev-adapter' cree") if aid else \
            warn(f"adapter REEV REFUSE (HTTP {code}) : {payload}")

    # Cache
    caches = gl.get("/system/lookup/caches") or {}
    cid = next((c.get("id") for c in caches.get("caches", [])
                if c.get("name") == f"omni-{name}-cache"), None)
    if cid:
        skip(f"cache 'omni-{name}-cache' existe")
    elif not gl.apply:
        info("[dry-run] creerait cache guava 'omni-seal-reev-cache'")
    else:
        body = {
            "name": f"omni-{name}-cache",
            "title": "OMNI - SEAL REEV (cache)",
            "description": "cache guava pour omni-seal-reev",
            "config": {
                "type": "guava_cache", "max_size": 1000,
                "expire_after_access": 300, "expire_after_access_unit": "SECONDS",
                "expire_after_write": 300, "expire_after_write_unit": "SECONDS",
                "ignore_null": False, "ttl_empty": 60, "ttl_empty_unit": "SECONDS",
            },
        }
        code, payload = gl.post("/system/lookup/caches", body)
        cid = payload.get("id") if isinstance(payload, dict) else None
        ok("cache 'omni-seal-reev-cache' cree") if cid else \
            warn(f"cache REEV REFUSE (HTTP {code}) : {payload}")

    # Table
    tables = gl.get("/system/lookup/tables") or {}
    tid = next((t.get("id") for t in tables.get("lookup_tables", [])
                if t.get("name") == "omni-seal-reev"), None)
    if tid:
        skip("table 'omni-seal-reev' existe")
        return
    if not gl.apply:
        info("[dry-run] creerait table de lookup 'omni-seal-reev'")
        return
    if not (aid and cid):
        warn("table 'omni-seal-reev' non creee : adapter/cache manquant")
        return
    body = {
        "name": "omni-seal-reev", "title": "OMNI - SEAL REEV",
        "description": "Decodage REEV_CODE -> libelle (dbo.REF_EVENEMENT)",
        "data_adapter_id": aid, "cache_id": cid,
        "default_single_value": "", "default_single_value_type": "NULL",
        "default_multi_value": "", "default_multi_value_type": "NULL",
    }
    code, payload = gl.post("/system/lookup/tables", body)
    ok("table 'omni-seal-reev' creee") if isinstance(payload, dict) and payload.get("id") else \
        warn(f"table REEV REFUSEE (HTTP {code}) : {payload}")


# --- Lookup omni-seal-identity (pont matricule -> UPN) -----------------------
def ensure_identity_lookup(gl: Graylog) -> None:
    """Table de lookup matricule -> UPN (adapter csvfile seal-identity.csv), source
    du pont d'identite badge->AD utilise par 14-seal-identity-upn.rule. Le CSV est
    regenere depuis l'AD (LDAPS, lecture seule) par regen-seal-identity.sh.
    Meme motif idempotent que ensure_reev_lookup (adapter + cache + table)."""
    name = "seal-identity"
    csv_path = os.path.join(LOOKUP_DIR, IDENTITY_CSV)
    if not os.path.exists(csv_path):
        warn(f"CSV {csv_path} absent -> lancer regen-seal-identity.sh d'abord "
             "(la table se creera mais restera vide tant que le CSV n'existe pas)")

    # Adapter
    adapters = gl.get("/system/lookup/adapters") or {}
    aid = next((a.get("id") for a in adapters.get("data_adapters", [])
                if a.get("name") == f"omni-{name}-adapter"), None)
    if aid:
        skip(f"adapter 'omni-{name}-adapter' existe")
    elif not gl.apply:
        info("[dry-run] creerait adapter csvfile 'omni-seal-identity-adapter'")
    else:
        body = {
            "name": f"omni-{name}-adapter",
            "title": "OMNI - SEAL Identity (adapter)",
            "description": "matricule -> UPN (regenere par regen-seal-identity.sh, LDAPS)",
            "config": {
                "type": "csvfile", "path": csv_path, "separator": ",", "quotechar": "\"",
                "key_column": "matricule", "value_column": "upn",
                "check_interval": 60, "case_insensitive_lookup": True, "cidr_lookup": False,
            },
        }
        code, payload = gl.post("/system/lookup/adapters", body)
        aid = payload.get("id") if isinstance(payload, dict) else None
        ok("adapter 'omni-seal-identity-adapter' cree") if aid else \
            warn(f"adapter IDENTITY REFUSE (HTTP {code}) : {payload}")

    # Cache
    caches = gl.get("/system/lookup/caches") or {}
    cid = next((c.get("id") for c in caches.get("caches", [])
                if c.get("name") == f"omni-{name}-cache"), None)
    if cid:
        skip(f"cache 'omni-{name}-cache' existe")
    elif not gl.apply:
        info("[dry-run] creerait cache guava 'omni-seal-identity-cache'")
    else:
        body = {
            "name": f"omni-{name}-cache",
            "title": "OMNI - SEAL Identity (cache)",
            "description": "cache guava pour omni-seal-identity",
            "config": {
                "type": "guava_cache", "max_size": 1000,
                "expire_after_access": 300, "expire_after_access_unit": "SECONDS",
                "expire_after_write": 300, "expire_after_write_unit": "SECONDS",
                "ignore_null": False, "ttl_empty": 60, "ttl_empty_unit": "SECONDS",
            },
        }
        code, payload = gl.post("/system/lookup/caches", body)
        cid = payload.get("id") if isinstance(payload, dict) else None
        ok("cache 'omni-seal-identity-cache' cree") if cid else \
            warn(f"cache IDENTITY REFUSE (HTTP {code}) : {payload}")

    # Table
    tables = gl.get("/system/lookup/tables") or {}
    tid = next((t.get("id") for t in tables.get("lookup_tables", [])
                if t.get("name") == "omni-seal-identity"), None)
    if tid:
        skip("table 'omni-seal-identity' existe")
        return
    if not gl.apply:
        info("[dry-run] creerait table de lookup 'omni-seal-identity'")
        return
    if not (aid and cid):
        warn("table 'omni-seal-identity' non creee : adapter/cache manquant")
        return
    body = {
        "name": "omni-seal-identity", "title": "OMNI - SEAL Identity",
        "description": "Pont badge->AD : matricule -> UPN (source regen-seal-identity.sh)",
        "data_adapter_id": aid, "cache_id": cid,
        "default_single_value": "", "default_single_value_type": "NULL",
        "default_multi_value": "", "default_multi_value_type": "NULL",
    }
    code, payload = gl.post("/system/lookup/tables", body)
    ok("table 'omni-seal-identity' creee") if isinstance(payload, dict) and payload.get("id") else \
        warn(f"table IDENTITY REFUSEE (HTTP {code}) : {payload}")


# --- Lookup omni-seal-zone (OBFI_ID -> zone physique, cle composite site:obfi) --
def ensure_zone_lookup(gl: Graylog) -> None:
    """Table de lookup seal_site:OBFI_ID -> zone physique (adapter csvfile
    omni-seal-zone.csv), source de l'enrichissement 16-seal-zone.rule. Le CSV est
    regenere depuis la vue vw_SealZone_SIEM (topologie SEAL, operateur) par
    regen_zone_lookup.sh. Meme motif idempotent (adapter + cache + table). La cle
    est composite (site:obfi) car un OBFI_ID peut collisionner entre sites."""
    name = "seal-zone"
    csv_path = os.path.join(LOOKUP_DIR, ZONE_CSV)
    if not os.path.exists(csv_path):
        warn(f"CSV {csv_path} absent -> lancer regen_zone_lookup.sh apres deploiement "
             "de vw_SealZone_SIEM (la table se cree mais reste vide -> seal_zone non pose)")

    # Adapter
    adapters = gl.get("/system/lookup/adapters") or {}
    aid = next((a.get("id") for a in adapters.get("data_adapters", [])
                if a.get("name") == f"omni-{name}-adapter"), None)
    if aid:
        skip(f"adapter 'omni-{name}-adapter' existe")
    elif not gl.apply:
        info("[dry-run] creerait adapter csvfile 'omni-seal-zone-adapter'")
    else:
        body = {
            "name": f"omni-{name}-adapter",
            "title": "OMNI - SEAL Zone (adapter)",
            "description": "seal_site:OBFI_ID -> zone physique (regen_zone_lookup.sh)",
            "config": {
                "type": "csvfile", "path": csv_path, "separator": ",", "quotechar": "\"",
                "key_column": "SITE_OBFI", "value_column": "ZONE_PATH",
                "check_interval": 60, "case_insensitive_lookup": True, "cidr_lookup": False,
            },
        }
        code, payload = gl.post("/system/lookup/adapters", body)
        aid = payload.get("id") if isinstance(payload, dict) else None
        ok("adapter 'omni-seal-zone-adapter' cree") if aid else \
            warn(f"adapter ZONE REFUSE (HTTP {code}) : {payload}")

    # Cache
    caches = gl.get("/system/lookup/caches") or {}
    cid = next((c.get("id") for c in caches.get("caches", [])
                if c.get("name") == f"omni-{name}-cache"), None)
    if cid:
        skip(f"cache 'omni-{name}-cache' existe")
    elif not gl.apply:
        info("[dry-run] creerait cache guava 'omni-seal-zone-cache'")
    else:
        body = {
            "name": f"omni-{name}-cache",
            "title": "OMNI - SEAL Zone (cache)",
            "description": "cache guava pour omni-seal-zone",
            "config": {
                "type": "guava_cache", "max_size": 5000,
                "expire_after_access": 60, "expire_after_access_unit": "SECONDS",
                "expire_after_write": 0, "expire_after_write_unit": None,
            },
        }
        code, payload = gl.post("/system/lookup/caches", body)
        cid = payload.get("id") if isinstance(payload, dict) else None
        ok("cache 'omni-seal-zone-cache' cree") if cid else \
            warn(f"cache ZONE REFUSE (HTTP {code}) : {payload}")

    # Table
    tables = gl.get("/system/lookup/tables") or {}
    tid = next((t.get("id") for t in tables.get("lookup_tables", [])
                if t.get("name") == "omni-seal-zone"), None)
    if tid:
        skip("table 'omni-seal-zone' existe")
        return
    if not gl.apply:
        info("[dry-run] creerait table de lookup 'omni-seal-zone'")
        return
    if not (aid and cid):
        warn("table 'omni-seal-zone' non creee : adapter/cache manquant")
        return
    body = {
        "name": "omni-seal-zone", "title": "OMNI - SEAL Zone",
        "description": "Resolution zone physique : seal_site:OBFI_ID -> zone (vw_SealZone_SIEM)",
        "data_adapter_id": aid, "cache_id": cid,
        "default_single_value": "", "default_single_value_type": "NULL",
        "default_multi_value": "", "default_multi_value_type": "NULL",
    }
    code, payload = gl.post("/system/lookup/tables", body)
    ok("table 'omni-seal-zone' creee") if isinstance(payload, dict) and payload.get("id") else \
        warn(f"table ZONE REFUSEE (HTTP {code}) : {payload}")


# --- Regles pipeline : chargement depuis les fichiers .rule ------------------
# Terminateur = ligne contenant uniquement "end" (evite de couper sur "ends_with").
_RULE_RE = re.compile(r'(rule\s+"(?P<name>[^"]+)".*?^\s*end\s*$)', re.DOTALL | re.MULTILINE)


def load_rules(rule_file: str) -> dict[str, str]:
    """Extrait {nom_regle: source} d'un fichier .rule (commentaires // ignores
    hors bloc). Un fichier peut contenir plusieurs regles."""
    path = os.path.join(RULES_DIR, rule_file)
    if not os.path.exists(path):
        die(f"fichier de regle introuvable : {path}")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    out: dict[str, str] = {}
    for m in _RULE_RE.finditer(text):
        out[m.group("name")] = m.group(1).strip()
    if not out:
        die(f"aucune regle 'rule \"...\" ... end' trouvee dans {rule_file}")
    return out


def ensure_rule(gl: Graylog, title: str, source: str) -> None:
    current = gl.get("/system/pipelines/rule") or []
    match = next((r for r in current if r.get("title") == title), None)
    desc = "provisionne par provision_seal.py (SEAL)"
    if match is None:
        if not gl.apply:
            info(f"[dry-run] creerait regle '{title}'")
            return
        code, payload = gl.post("/system/pipelines/rule",
                                {"title": title, "description": desc, "source": source})
        ok(f"regle '{title}' creee") if isinstance(payload, dict) and payload.get("id") else \
            warn(f"regle '{title}' REFUSEE (HTTP {code}) : {payload}")
        return
    if match.get("source") == source:
        skip(f"regle '{title}' inchangee")
        return
    if not gl.apply:
        info(f"[dry-run] mettrait a jour la regle '{title}'")
        return
    rid = match.get("id")
    code, _ = gl.put(f"/system/pipelines/rule/{rid}",
                     {"id": rid, "title": title, "description": desc, "source": source})
    ok(f"regle '{title}' mise a jour") if code == 200 else warn(f"MAJ regle '{title}' KO (HTTP {code})")


def build_pipeline_source(title: str, stages: list[list[str]]) -> str:
    lines = [f'pipeline "{title}"']
    for idx, rules in enumerate(stages):
        # 'match pass' : le message traverse TOUJOURS vers le stage suivant, meme
        # si aucune regle du stage n'a matche. Indispensable ici : le stage
        # 'outcome-fail' (audit) ne matche que les ConnectionFailure ; avec 'match
        # either' il bloquait les evenements Connection avant le stage terminal
        # d'identite (identity_upn/identity_console jamais poses). Les actions des
        # regles restent gardees par leur clause 'when'.
        lines.append(f"stage {idx} match pass")
        for rn in rules:
            lines.append(f'rule "{rn}"')
    lines.append("end")
    return "\n".join(lines)


def ensure_pipeline(gl: Graylog, title: str, source: str) -> str | None:
    current = gl.get("/system/pipelines/pipeline") or []
    match = next((p for p in current if p.get("title") == title), None)
    desc = "provisionne par provision_seal.py (SEAL)"
    if match is None:
        if not gl.apply:
            info(f"[dry-run] creerait pipeline '{title}'")
            return None
        code, payload = gl.post("/system/pipelines/pipeline",
                                {"title": title, "description": desc, "source": source})
        pid = payload.get("id") if isinstance(payload, dict) else None
        ok(f"pipeline '{title}' cree ({pid})") if pid else \
            warn(f"pipeline '{title}' REFUSE (HTTP {code}) : {payload}")
        return pid
    pid = match.get("id")
    if match.get("source") != source:
        if gl.apply:
            code, _ = gl.put(f"/system/pipelines/pipeline/{pid}",
                             {"id": pid, "title": title, "description": desc, "source": source})
            ok(f"pipeline '{title}' mis a jour") if code == 200 else warn(f"MAJ pipeline '{title}' KO (HTTP {code})")
        else:
            info(f"[dry-run] mettrait a jour le pipeline '{title}'")
    else:
        skip(f"pipeline '{title}' inchange")
    return pid


def connect_pipeline(gl: Graylog, stream_id: str, pipeline_id: str) -> None:
    cur = gl.get(f"/system/pipelines/connections/{stream_id}") or {}
    ids = set(cur.get("pipeline_ids") or [])
    if pipeline_id in ids:
        skip(f"pipeline deja connecte au stream {stream_id}")
        return
    if not gl.apply:
        info(f"[dry-run] connecterait pipeline {pipeline_id} au stream {stream_id}")
        return
    ids.add(pipeline_id)
    code, _ = gl.post("/system/pipelines/connections/to_stream",
                      {"stream_id": stream_id, "pipeline_ids": sorted(ids)})
    ok(f"pipeline connecte au stream {stream_id}") if code in (200, 201, 202) else \
        warn(f"connexion pipeline KO (HTTP {code})")


# --- Orchestration -----------------------------------------------------------
def ensure_m365_antidup(gl: Graylog) -> None:
    """Anti-dup : SEAL passe par l'input GELF partage (reutilise). Le stream M365
    route par gl2_source_input -> il capterait AUSSI les messages SEAL. On ajoute
    l'exclusion inversee event_source!=seal (motif deja utilise pour toutes les
    sources internes du repo). Idempotent."""
    print("\n== [3b/5] Anti-dup : exclusion SEAL du stream M365 ==")
    m365 = find_stream(gl, "OMNI - M365")
    if not m365:
        skip("stream M365 introuvable (rien a exclure)")
        return
    sid = m365["id"]
    for r in m365.get("rules", []):
        if r.get("field") == "event_source" and r.get("value") == "seal" and r.get("inverted"):
            skip("exclusion event_source!=seal deja presente sur M365")
            return
    if not gl.apply:
        info("[dry-run] ajouterait l'exclusion event_source!=seal au stream M365")
        return
    body = {"field": "event_source", "type": 1, "value": "seal", "inverted": True,
            "description": "Anti-dup : SEAL route vers ses propres streams (input GELF partage)"}
    code, _ = gl.post(f"/streams/{sid}/rules", body)
    ok("exclusion event_source!=seal ajoutee au stream M365") if code in (200, 201) \
        else warn(f"echec ajout exclusion M365 (HTTP {code})")


def main() -> int:
    ap = argparse.ArgumentParser(description="Provisioning Graylog couche SEAL (QA)")
    ap.add_argument("--apply", action="store_true", help="applique (defaut : dry-run)")
    ap.add_argument("--dry-run", action="store_true", help="force le dry-run (defaut)")
    args = ap.parse_args()
    apply = args.apply and not args.dry_run

    print("=" * 72)
    print(f" SEAL -> Graylog : PROVISIONING ({'APPLY' if apply else 'DRY-RUN (lecture seule)'})")
    print("=" * 72)

    gl = Graylog(apply=apply)
    # Sonde API (GET, lecture seule)
    sysinfo = gl.get("/system")
    if not isinstance(sysinfo, dict) or "version" not in sysinfo:
        die(f"API Graylog injoignable via {gl.base} ({gl.auth_desc}) : {sysinfo}")
    info(f"API OK - Graylog {sysinfo.get('version')} ({gl.auth_desc})")

    print("\n== [1/5] Input GELF UDP dedie SEAL (12202) ==")
    check_gelf_input(gl)

    print("\n== [2/5] Lookups omni-seal-reev (REEV) + omni-seal-identity (matricule->UPN) + omni-seal-zone ==")
    ensure_reev_lookup(gl)
    ensure_identity_lookup(gl)
    ensure_zone_lookup(gl)

    print("\n== [3/5] Index sets + streams (routage par event_domain) ==")
    stream_ids: dict[str, str | None] = {}
    for d in DOMAINS:
        iid = ensure_index_set(gl, d)
        sid = ensure_stream(gl, d, iid)
        stream_ids[d["key"]] = sid

    ensure_m365_antidup(gl)

    print("\n== [4/5] Regles de normalisation (pipelines/*.rule) ==")
    for d in DOMAINS:
        rules = load_rules(d["rule_file"])
        for name in [rn for stage in d["stages"] for rn in stage]:
            if name not in rules:
                die(f"regle '{name}' attendue mais absente de {d['rule_file']}")
            ensure_rule(gl, name, rules[name])

    # Regle PARTAGEE du pont d'identite (badge->matricule->UPN), stage terminal
    # commun aux 3 pipelines SEAL. Chargee une seule fois depuis son fichier dedie.
    id_rules = load_rules(IDENTITY_RULE_FILE)
    if IDENTITY_RULE_NAME not in id_rules:
        die(f"regle '{IDENTITY_RULE_NAME}' attendue mais absente de {IDENTITY_RULE_FILE}")
    ensure_rule(gl, IDENTITY_RULE_NAME, id_rules[IDENTITY_RULE_NAME])
    # Pont console SEAL -> AD (meme stage terminal). Gardee par event_domain==audit.
    c_rules = load_rules(CONSOLE_RULE_FILE)
    if CONSOLE_RULE_NAME not in c_rules:
        die(f"regle '{CONSOLE_RULE_NAME}' attendue mais absente de {CONSOLE_RULE_FILE}")
    ensure_rule(gl, CONSOLE_RULE_NAME, c_rules[CONSOLE_RULE_NAME])
    # Enrichissement zone physique (meme stage terminal). Garde par has_field
    # (target_object_id + seal_site) -> inoffensive tant que le lookup est vide.
    z_rules = load_rules(ZONE_RULE_FILE)
    if ZONE_RULE_NAME not in z_rules:
        die(f"regle '{ZONE_RULE_NAME}' attendue mais absente de {ZONE_RULE_FILE}")
    ensure_rule(gl, ZONE_RULE_NAME, z_rules[ZONE_RULE_NAME])

    print("\n== [5/5] Pipelines + connexion aux streams ==")
    for d in DOMAINS:
        # Stage TERMINAL = resolution identity_upn (posee APRES la normalisation qui
        # ne pose qu'un placeholder ""). Appliquee aux 3 pipelines (la regle est
        # gardee par has_field(identity_matricule) -> inoffensive sans matricule).
        stages = d["stages"] + [[IDENTITY_RULE_NAME, CONSOLE_RULE_NAME, ZONE_RULE_NAME]]
        src = build_pipeline_source(d["pipeline_title"], stages)
        pid = ensure_pipeline(gl, d["pipeline_title"], src)
        sid = stream_ids.get(d["key"])
        if pid and sid:
            connect_pipeline(gl, sid, pid)
        elif not apply:
            info(f"[dry-run] connecterait pipeline '{d['pipeline_title']}' au stream '{d['stream_title']}'")
        else:
            warn(f"connexion '{d['pipeline_title']}' <-> '{d['stream_title']}' impossible (pid/sid manquant)")

    print("\n" + "=" * 72)
    if not apply:
        print(" DRY-RUN termine. Aucune ecriture. Relancer avec --apply pour appliquer.")
    else:
        print(" APPLY termine. Rappels : (1) regen_reev_lookup.sh pour peupler le CSV REEV ;")
        print(" (2) regen-seal-identity.sh (cron) pour peupler seal-identity.csv (matricule->UPN) ;")
        print(" (3) le collecteur GELF doit poser event_source=seal + event_domain + timestamp UTC ;")
        print(" (4) 13-identity-mirror.rule s'integre cote pipeline AD (hors SEAL) pour poser")
        print("     identity_upn (forme canonique identique) sur les logons Windows/M365.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
