"""Contrat de module omni-siem (docs/MODULES.md) : chargement, validation, activation par site et cycle de vie.

Un module = ``integrations/<id>/manifest.json``. Les manifestes ``schema_version: 1`` (analyseurs historiques)
sont lus comme des modules ``parser`` qui fournissent la source ``<id>``. Aucune écriture sans ``apply=True`` ;
hors de la racine système, les commandes systemd sont seulement enregistrées (simulation).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "integrations"
SITE_CONFIG = "/etc/omni-siem/integrations.json"
MODULES_DIR = "/etc/omni-siem/modules.d"
STATE_DIR = "/var/lib/omni-siem-modules"
SECRETS_ROOT = "/etc/omni-siem/secrets/"
MODULE_ID = re.compile(r"[a-z][a-z0-9_]{1,31}")
NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
STATUSES = {"stable", "preview", "legacy"}
PARAM_TYPES = {"string": str, "integer": int, "boolean": bool, "list": list, "object": dict}
INPUT_TYPES = {"syslog_udp", "syslog_tcp", "gelf_http", "gelf_udp", "beats", "raw_tcp", "raw_udp"}
CHECK_TYPES = {"secret", "unit", "stream_recent", "input_running", "fields_present", "dashboards", "lookup"}
SEVERITIES = {"critique", "avertissement"}
V2_REQUIRED = ("name", "summary", "revision", "status", "compat", "provides", "checks", "rollback", "uninstall")
COMMON_FIELDS = {"timestamp", "source", "message", "full_message", "streams", "gl2_source_input", "event_source", "host",
                 "alert_tag", "event_id", "event_action", "event_category", "user", "src_ip", "dest_ip"}
# Valeurs qui ressemblent à un secret écrit en clair (jetons, clés, blocs PEM).
SECRET_VALUE = re.compile(r"(-----BEGIN|ghp_[A-Za-z0-9]{20}|xox[abp]-|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{20,}\.|"
                          r"\b[A-Fa-f0-9]{40,}\b|\b[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=]))")
SECRET_KEY = re.compile(r"(?i)^(password|passwd|secret|token|api_key|apikey|client_secret|value)$")


class ModuleError(ValueError):
    pass


# ----------------------------------------------------------------------------- chargement
def module_ids(catalog_root=CATALOG):
    root = Path(catalog_root)
    if not root.is_dir():
        return []
    return sorted(p.parent.name for p in root.glob("*/manifest.json") if MODULE_ID.fullmatch(p.parent.name))


def capabilities(catalog_root=CATALOG):
    path = Path(catalog_root) / "sources.json"
    if not path.is_file():
        return {"sources": {}, "features": {}, "console_pages": {}, "common_fields": []}
    return json.loads(path.read_text(encoding="utf-8"))


def normalize(raw, caps=None):
    """Vue v2 d'un manifeste (v1 : module ``parser`` qui fournit sa source)."""
    caps = caps or {"sources": {}}
    module = dict(raw)
    if raw.get("schema_version") == 1:
        module.setdefault("summary", raw.get("supported_format", ""))
        module.setdefault("compat", {})
        module.setdefault("provides", {"sources": [raw["id"]] if raw["id"] in caps.get("sources", {}) else [],
                                       "features": []})
        module.setdefault("checks", [{"id": "dashboards", "type": "dashboards", "severity": "avertissement"}]
                          if raw.get("dashboards") else [])
        module.setdefault("rollback", {"objects": "by_id", "keeps_data": True})
        module.setdefault("uninstall", {"objects": "by_id", "keeps_data": True})
    for key in ("depends", "conflicts", "secrets", "inputs", "collectors", "console_pages", "fields", "field_prefixes"):
        module.setdefault(key, [])
    for key in ("site_config", "graylog", "derived_fields", "detections", "legacy"):
        module.setdefault(key, {})
    module.setdefault("dashboards", [])
    return module


def load_manifest(module_id, catalog_root=CATALOG, caps=None):
    if not MODULE_ID.fullmatch(module_id or ""):
        raise ModuleError("identifiant de module invalide : " + repr(module_id))
    path = Path(catalog_root) / module_id / "manifest.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("id") != module_id or raw.get("schema_version") not in (1, 2):
        raise ModuleError(module_id + " : identifiant ou schema_version incohérent")
    return normalize(raw, caps if caps is not None else capabilities(catalog_root))


def manifests(catalog_root=CATALOG):
    caps = capabilities(catalog_root)
    return {mid: load_manifest(mid, catalog_root, caps) for mid in module_ids(catalog_root)}


def parse_deploy_manifest(repo_root):
    path = Path(repo_root) / "manifeste-deploye.txt"
    if not path.is_file():
        return {}
    pairs = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#") and line.count("\t") == 1:
            target, source = line.split("\t")
            pairs[target] = source
    return pairs


# ----------------------------------------------------------------------------- champs
def module_fields(module):
    fields = set(module.get("fields", [])) | set(module.get("derived_fields", {})) | COMMON_FIELDS
    if module.get("parser"):
        from omni_integrations.core import produced_fields
        fields |= produced_fields(module)
    return fields


def field_known(field, fields, prefixes):
    return field in fields or any(field.startswith(prefix) for prefix in prefixes)


def collector_targets(module, deploy_pairs=None):
    """Cibles déployées par les collecteurs du module (fichiers, unités, drop-ins)."""
    targets = set()
    for collector in module.get("collectors", []):
        targets |= set(collector.get("files", []))
        for unit in filter(None, (collector.get("unit"), collector.get("timer"))):
            targets.add("/etc/systemd/system/" + unit)
            for target in deploy_pairs or {}:
                if target.startswith("/etc/systemd/system/" + unit + ".d/"):
                    targets.add(target)
    return targets


def _strings(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}" if path else key)
            # Une clé sensible ne peut porter qu'un chemin ou le nom d'un secret déclaré.
            if (SECRET_KEY.match(str(key)) and isinstance(item, str) and item and not item.startswith("/")
                    and not NAME.fullmatch(item)):
                yield path + "." + key, "<clé sensible avec une valeur>"
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def secret_literals(document):
    """Chemins JSON dont la valeur ressemble à un secret en clair (jamais affichée)."""
    found = []
    for path, text in _strings(document):
        if text == "<clé sensible avec une valeur>" or (SECRET_VALUE.search(text) and "expression" not in path
                                                        and ".parser." not in "." + path + "."):
            found.append(path)
    return found


# ----------------------------------------------------------------------------- validation
def validate_manifest(module, *, all_ids=(), caps=None, repo_root=ROOT, raw=None):
    """Liste des défauts (vide = conforme). Hors ligne, utilisée par la CI et par ``modules validate``."""
    caps = caps or capabilities(Path(repo_root) / "integrations")
    problems = []
    mid = module.get("id", "?")

    def bad(message):
        problems.append(f"{mid} : {message}")

    if not MODULE_ID.fullmatch(str(mid)):
        bad("identifiant invalide (attendu [a-z][a-z0-9_]{1,31})")
    v2 = module.get("schema_version") == 2
    if v2:
        for key in V2_REQUIRED:
            if key not in (raw or module):
                bad("clé obligatoire absente : " + key)
        compat = module.get("compat", {})
        if not isinstance(compat, dict) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(compat.get("omni_siem_min", ""))):
            bad("compat.omni_siem_min attendu au format AAAA-MM-JJ")
        if not str(compat.get("graylog", "")).startswith(">="):
            bad("compat.graylog attendu (ex. >=7.0,<8.0)")
        if not module.get("checks"):
            bad("au moins un contrôle post-déploiement (checks) est requis")
        if not module.get("parser") and not module.get("fields"):
            bad("un module sans analyseur doit déclarer ses champs produits (fields)")
    if type(module.get("revision")) is not int or module["revision"] < 1:
        bad("revision doit être un entier >= 1")
    if module.get("status") not in STATUSES:
        bad("status inconnu : " + str(module.get("status")))
    provides = module.get("provides", {})
    unknown_sources = set(provides.get("sources", [])) - set(caps.get("sources", {}))
    unknown_features = set(provides.get("features", [])) - set(caps.get("features", {}))
    if unknown_sources:
        bad("sources inconnues de integrations/sources.json : " + ", ".join(sorted(unknown_sources)))
    if unknown_features:
        bad("fonctions inconnues : " + ", ".join(sorted(unknown_features)))
    for key in ("depends", "conflicts"):
        for other in module.get(key, []):
            if other == mid or other not in all_ids:
                bad(f"{key} : module inconnu ou lui-même : {other}")
    # Paramètres de site.
    schema = module.get("site_config", {}).get("schema", {})
    for name, spec in schema.items():
        if not NAME.fullmatch(name) or spec.get("type") not in PARAM_TYPES:
            bad(f"paramètre {name} : nom ou type invalide")
            continue
        if "default" in spec and spec["default"] is not None and not _typed(spec["default"], spec["type"]):
            bad(f"paramètre {name} : valeur par défaut d'un autre type que {spec['type']}")
        if spec.get("pattern"):
            try:
                re.compile(spec["pattern"])
            except re.error:
                bad(f"paramètre {name} : motif invalide")
        if not spec.get("description"):
            bad(f"paramètre {name} : description manquante")
    # Secrets : déclarés, jamais en clair.
    secret_names = set()
    for secret in module.get("secrets", []):
        name = secret.get("name", "")
        secret_names.add(name)
        if not NAME.fullmatch(name) or "value" in secret:
            bad(f"secret {name!r} : nom invalide ou valeur écrite dans le manifeste")
        path = str(secret.get("default_path", ""))
        if not path.startswith(SECRETS_ROOT + str(mid) + "/") or ".." in PurePosixPath(path).parts:
            bad(f"secret {name} : default_path doit être sous {SECRETS_ROOT}{mid}/")
    for path in secret_literals(raw or module):
        bad("valeur ressemblant à un secret en clair : " + path)
    # Entrées.
    for item in module.get("inputs", []):
        if item.get("type") not in INPUT_TYPES or not NAME.fullmatch(str(item.get("key", ""))):
            bad(f"entrée {item.get('key')} : type ou clé invalide")
        port = item.get("default_port")
        if type(port) is not int or not 1024 <= port <= 65535:
            bad(f"entrée {item.get('key')} : default_port non privilégié attendu")
    # Collecteurs et unités conditionnées.
    deploy_pairs = parse_deploy_manifest(repo_root)
    for collector in module.get("collectors", []):
        for secret in collector.get("secrets", []):
            if secret not in secret_names:
                bad(f"collecteur {collector.get('unit')} : secret non déclaré {secret}")
        for unit in filter(None, (collector.get("unit"), collector.get("timer"))):
            if not re.fullmatch(r"(omni|oms)-[a-z0-9-]+\.(service|timer)", unit):
                bad(f"unité {unit} : nom attendu omni-<id>-<rôle>.service|timer")
                continue
            target = "/etc/systemd/system/" + unit
            source = deploy_pairs.get(target)
            if source is None:
                bad(f"unité {unit} absente de manifeste-deploye.txt")
                continue
            path = Path(repo_root) / source
            if not path.is_file():
                bad(f"unité {unit} : source {source} absente")
                continue
            text = path.read_text(encoding="utf-8")
            if unit.endswith(".service"):
                problems.extend(f"{mid} : {p}" for p in unit_condition_problems(text, mid, unit))
        for target in collector.get("files", []):
            if target not in deploy_pairs:
                bad(f"fichier {target} absent de manifeste-deploye.txt")
    # Cohérence des champs : sources.json, dashboards du module.
    fields, prefixes = module_fields(module), set(module.get("field_prefixes", []))
    for source in provides.get("sources", []):
        spec = caps.get("sources", {}).get(source, {})
        for field in spec.get("fields", []):
            if not field_known(field, fields, prefixes):
                bad(f"champ {field} attendu par la source {source} (sources.json) mais non produit")
    if not module.get("parser"):
        from omni_integrations.core import widget_fields
        for spec in module.get("dashboards", []):
            for page in spec.get("pages", []):
                for widget in page.get("widgets", []):
                    for field in widget_fields(widget) - set():
                        if not field_known(field, fields, prefixes):
                            bad(f"dashboard {spec.get('key')} / {widget.get('title')} : champ {field} jamais produit")
    for page in module.get("console_pages", []):
        if page not in caps.get("console_pages", {}):
            bad("page de console inconnue : " + page)
    # Contrôles.
    seen = set()
    for check in module.get("checks", []):
        if check.get("type") not in CHECK_TYPES or not NAME.fullmatch(str(check.get("id", ""))) or check["id"] in seen:
            bad(f"contrôle {check.get('id')} : type inconnu, identifiant invalide ou en double")
        seen.add(check.get("id"))
        if check.get("severity", "critique") not in SEVERITIES:
            bad(f"contrôle {check.get('id')} : sévérité inconnue")
        if check.get("type") == "secret" and check.get("secret") not in secret_names:
            bad(f"contrôle {check.get('id')} : secret non déclaré")
        if check.get("when") and check["when"] not in schema:
            bad(f"contrôle {check.get('id')} : condition sur un paramètre inconnu {check['when']}")
    # Scripts historiques protégés par la garde d'activation.
    if module.get("status") == "legacy":
        scripts = module.get("legacy", {}).get("scripts", [])
        if not scripts:
            bad("status legacy sans legacy.scripts")
        for script in scripts:
            path = Path(repo_root) / script
            if not path.is_file():
                bad("script historique absent : " + script)
            elif f"omni_module_enabled {mid}" not in path.read_text(encoding="utf-8", errors="replace"):
                bad(f"script {script} sans garde « omni_module_enabled {mid} »")
    return problems


def unit_condition_problems(text, module_id, unit="unité"):
    problems = []
    marker = f"ConditionPathExists=|{MODULES_DIR}/{module_id}.enabled"
    legacy = f"ConditionPathExists=|!{MODULES_DIR}"
    lines = [line.strip() for line in text.splitlines()]
    if marker not in lines or legacy not in lines:
        problems.append(f"{unit} : conditions d'activation absentes ({marker} + {legacy})")
    if re.search(r"(?im)^\s*Environment=.*(pass|secret|token|key)", text):
        problems.append(f"{unit} : secret passé en Environment= (utiliser LoadCredential=)")
    return problems


def _typed(value, kind):
    expected = PARAM_TYPES[kind]
    return isinstance(value, expected) and not (kind == "integer" and isinstance(value, bool))


def dependency_cycles(mods):
    state, cycles = {}, []

    def visit(mid, stack):
        if state.get(mid) == 1:
            cycles.append(" -> ".join(stack + [mid]))
            return
        if state.get(mid) == 2 or mid not in mods:
            return
        state[mid] = 1
        for dep in mods[mid].get("depends", []):
            visit(dep, stack + [mid])
        state[mid] = 2

    for mid in mods:
        visit(mid, [])
    return cycles


def validate_all(catalog_root=CATALOG, repo_root=None):
    repo_root = Path(repo_root) if repo_root else Path(catalog_root).parent
    caps = capabilities(catalog_root)
    problems, report = [], []
    ids = module_ids(catalog_root)
    mods = {}
    for mid in ids:
        raw = json.loads((Path(catalog_root) / mid / "manifest.json").read_text(encoding="utf-8"))
        try:
            module = load_manifest(mid, catalog_root, caps)
        except (ModuleError, KeyError, json.JSONDecodeError) as exc:
            problems.append(f"{mid} : {exc}")
            continue
        mods[mid] = module
        found = validate_manifest(module, all_ids=ids, caps=caps, repo_root=repo_root, raw=raw)
        problems += found
        report.append({"id": mid, "schema_version": module["schema_version"], "revision": module["revision"],
                       "status": module["status"], "sources": module["provides"].get("sources", []),
                       "collectors": len(module["collectors"]), "checks": len(module["checks"]), "defauts": len(found)})
    problems += ["cycle de dépendances : " + c for c in dependency_cycles(mods)]
    return {"modules": report, "problems": problems}


# ----------------------------------------------------------------------------- site
def load_site(path=SITE_CONFIG):
    path = Path(path)
    if not path.is_file():
        return {"schema_version": 1}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ModuleError("schema_version de la configuration de site non pris en charge")
    return data


def _under(root, absolute):
    return Path(root) / str(absolute).lstrip("/")


def resolve_site(site_doc, mods, root="/"):
    """Modules actifs, paramètres effectifs, secrets et défauts bloquants pour un site."""
    site = site_doc.get("site") or {}
    integrations = site_doc.get("integrations") or {}
    legacy = "modules" not in site
    requested = set(mods) if legacy else set(site.get("modules") or [])
    unknown = requested - set(mods)
    if unknown:
        raise ModuleError("site.modules cite des modules inconnus : " + ", ".join(sorted(unknown)))
    resolved = {}
    for mid in sorted(mods):
        module, config = mods[mid], integrations.get(mid) or {}
        entry = {"id": mid, "revision": module["revision"], "enabled": mid in requested, "blockers": [],
                 "warnings": [], "parameters": {}, "secrets": {}}
        if entry["enabled"]:
            for dep in module.get("depends", []):
                if dep not in requested:
                    entry["blockers"].append("dépendance non activée : " + dep)
            for other in module.get("conflicts", []):
                if other in requested:
                    entry["blockers"].append("incompatible avec le module actif " + other)
            values = config.get("parameters") or {}
            schema = module.get("site_config", {}).get("schema", {})
            for name in sorted(set(values) - set(schema)):
                if not (module.get("parser") and name in _parser_parameters(module)):
                    entry["warnings"].append("paramètre inconnu ignoré : " + name)
            for name, spec in schema.items():
                if name in values:
                    value = values[name]
                    if not _typed(value, spec["type"]):
                        entry["blockers"].append(f"paramètre {name} : type {spec['type']} attendu")
                        continue
                    if spec.get("pattern") and isinstance(value, str) and not re.fullmatch(spec["pattern"], value):
                        entry["blockers"].append(f"paramètre {name} : valeur refusée par le motif")
                        continue
                    entry["parameters"][name] = value
                elif "default" in spec:
                    entry["parameters"][name] = spec["default"]
                elif spec.get("required"):
                    entry["blockers"].append(f"paramètre obligatoire absent : integrations.{mid}.parameters.{name}")
            overrides = config.get("secrets") or {}
            for secret in module.get("secrets", []):
                path = overrides.get(secret["name"], secret["default_path"])
                state = secret_state(_under(root, path), system=Path(root) == Path("/"))
                needed = secret.get("required") or _secret_needed(module, secret["name"], entry["parameters"])
                entry["secrets"][secret["name"]] = {"path": path, "state": state, "required": bool(needed)}
                if needed and state != "ok":
                    (entry["warnings"] if legacy else entry["blockers"]).append(
                        f"secret {secret['name']} : {state} ({path})")
        resolved[mid] = entry
    sources = set(site.get("sources") or [])
    for mid, entry in resolved.items():
        if entry["enabled"]:
            sources |= set(mods[mid]["provides"].get("sources", []))
    return {"legacy": legacy, "modules": resolved, "sources": sorted(sources),
            "features": sorted(site.get("features") or [])}


def _parser_parameters(module):
    from omni_integrations.core import site_parameters
    return site_parameters(module)


def _secret_needed(module, name, parameters):
    """Un secret d'un collecteur facultatif n'est requis que si son paramètre d'activation est vrai."""
    for collector in module.get("collectors", []):
        if name in collector.get("secrets", []):
            flag = collector.get("enabled_by")
            return bool(parameters.get(flag)) if flag else True
    return False


def secret_state(path, system=True):
    try:
        info = path.stat()
    except FileNotFoundError:
        return "absent"
    except PermissionError:
        return "illisible"
    if not path.is_file():
        return "pas un fichier"
    if info.st_mode & 0o077:
        return "droits trop ouverts (0600 attendu)"
    if system and info.st_uid != 0:
        return "propriétaire autre que root"
    return "ok"


# ----------------------------------------------------------------------------- plan / apply
def _marker_path(root, mid):
    return _under(root, MODULES_DIR) / (mid + ".enabled")


def params_digest(parameters):
    return hashlib.sha256(json.dumps(parameters, sort_keys=True).encode()).hexdigest()[:16]


def read_marker(root, mid):
    path = _marker_path(root, mid)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"id": mid, "revision": None}


def plan(site_path=SITE_CONFIG, *, root="/", catalog_root=CATALOG, repo_root=None):
    """Lecture seule : ce que ``apply`` ferait pour ce site (déploiement à blanc)."""
    repo_root = Path(repo_root) if repo_root else Path(catalog_root).parent
    mods = manifests(catalog_root)
    site_doc = load_site(site_path)
    resolved = resolve_site(site_doc, mods, root)
    deploy_pairs = parse_deploy_manifest(repo_root)
    has_dir = _under(root, MODULES_DIR).is_dir()
    items, blockers = [], []
    for mid, entry in resolved["modules"].items():
        module, marker = mods[mid], read_marker(root, mid)
        targets = sorted(collector_targets(module, deploy_pairs))
        timers = [c["timer"] for c in module["collectors"] if c.get("timer")
                  and (not c.get("enabled_by") or entry["parameters"].get(c["enabled_by"]))]
        if entry["enabled"]:
            if entry["blockers"]:
                action = "bloqué"
                blockers += [f"{mid} : {b}" for b in entry["blockers"]]
            elif resolved["legacy"]:
                action = "actif (site historique)"
            elif marker is None:
                action = "activer"
            elif marker.get("revision") != module["revision"]:
                action = f"mettre à niveau (rév. {marker.get('revision')} -> {module['revision']})"
            elif marker.get("parameters") != params_digest(entry["parameters"]):
                action = "reconfigurer"
            else:
                action = "à jour"
        else:
            action = "désactiver" if marker is not None else "inactif"
        items.append({
            "id": mid, "revision": module["revision"], "status": module["status"], "action": action,
            "sources": module["provides"].get("sources", []), "parameters": entry["parameters"],
            "secrets": {k: {"path": v["path"], "state": v["state"]} for k, v in entry["secrets"].items()},
            "files": targets if entry["enabled"] else [],
            "files_skipped": [] if entry["enabled"] else targets,
            "timers_enable": timers if entry["enabled"] and not entry["blockers"] else [],
            "timers_disable": [c["timer"] for c in module["collectors"] if c.get("timer")]
            if not entry["enabled"] or len(timers) < len([c for c in module["collectors"] if c.get("timer")]) else [],
            "graylog": module.get("graylog", {}) if entry["enabled"] else {},
            "dashboards": [d.get("key") for d in module.get("dashboards", [])] if entry["enabled"] else [],
            "console_pages": module.get("console_pages", []) if entry["enabled"] else [],
            "detections_sources": module.get("detections", {}).get("sources", []) if entry["enabled"] else [],
            "legacy_scripts": module.get("legacy", {}).get("scripts", []),
            "warnings": entry["warnings"], "blockers": entry["blockers"]})
    if not resolved["legacy"] and not has_dir:
        notes = [f"{MODULES_DIR} sera créé : les unités des modules inactifs ne démarreront plus (conditions)"]
    elif resolved["legacy"]:
        notes = ["site historique (pas de site.modules) : tous les modules restent actifs, aucun marqueur écrit"]
    else:
        notes = []
    return {"mode": "plan", "site_config": str(site_path), "root": str(root), "legacy": resolved["legacy"],
            "effective_sources": resolved["sources"], "features": resolved["features"], "modules": items,
            "enabled": [i["id"] for i in items if i["action"] not in ("inactif", "désactiver")],
            "blockers": blockers, "notes": notes}


class Runner:
    """Exécute systemctl sur la racine système ; ailleurs, enregistre seulement (simulation)."""

    def __init__(self, simulate):
        self.simulate, self.calls = simulate, []

    def __call__(self, argv):
        self.calls.append(list(argv))
        if self.simulate:
            return 0
        return subprocess.run(argv, check=False, capture_output=True, timeout=120).returncode


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_dir(root, state_dir):
    return Path(state_dir) if state_dir else _under(root, STATE_DIR)


def _write_atomic(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def apply(site_path=SITE_CONFIG, *, root="/", catalog_root=CATALOG, repo_root=None, state_dir=None,
          apply=False, runner=None):
    report = plan(site_path, root=root, catalog_root=catalog_root, repo_root=repo_root)
    report["mode"] = "apply" if apply else "simulation"
    if report["legacy"]:
        report["changes"] = []
        return report
    if report["blockers"]:
        report["changes"] = []
        report["refused"] = "défauts bloquants : rien n'est appliqué"
        return report
    changes, journal = [], {"transaction": uuid.uuid4().hex, "date": _now(), "root": str(root),
                            "markers": {}, "timers": [], "created_dir": False}
    for item in report["modules"]:
        mid, marker = item["id"], read_marker(root, item["id"])
        if item["action"] in ("activer", "reconfigurer") or item["action"].startswith("mettre à niveau"):
            changes.append(("marker", mid, "écrire"))
        elif item["action"] == "désactiver":
            changes.append(("marker", mid, "retirer"))
        journal["markers"][mid] = marker
        for timer in item["timers_enable"]:
            changes.append(("timer", timer, "enable"))
        for timer in item["timers_disable"]:
            changes.append(("timer", timer, "disable"))
    report["changes"] = [{"type": t, "objet": o, "action": a} for t, o, a in changes]
    if not apply:
        return report
    runner = runner or Runner(simulate=Path(root) != Path("/"))
    directory = _under(root, MODULES_DIR)
    if not directory.is_dir():
        directory.mkdir(parents=True, mode=0o755)
        journal["created_dir"] = True
    by_id = {item["id"]: item for item in report["modules"]}
    for kind, obj, action in changes:
        if kind == "marker" and action == "écrire":
            item = by_id[obj]
            _write_atomic(_marker_path(root, obj), json.dumps(
                {"id": obj, "revision": item["revision"], "parameters": params_digest(item["parameters"]),
                 "date": journal["date"], "transaction": journal["transaction"]}, sort_keys=True) + "\n")
        elif kind == "marker":
            _marker_path(root, obj).unlink(missing_ok=True)
    for kind, obj, action in changes:
        if kind == "timer" and _under(root, "/etc/systemd/system/" + obj).is_file():
            journal["timers"].append({"timer": obj, "action": action})
            runner(["systemctl", action, "--now", obj])
    state = _state_dir(root, state_dir)
    _write_atomic(state / "transactions" / (journal["transaction"] + ".json"), json.dumps(journal, indent=2) + "\n", 0o600)
    report["transaction"] = journal["transaction"]
    report["commands"] = runner.calls
    return report


def rollback(transaction, *, root="/", state_dir=None, apply=False, runner=None):
    if not re.fullmatch(r"[a-f0-9]{32}", transaction or ""):
        raise ModuleError("identifiant de transaction invalide")
    path = _state_dir(root, state_dir) / "transactions" / (transaction + ".json")
    journal = json.loads(path.read_text(encoding="utf-8"))
    steps = []
    for mid, previous in journal["markers"].items():
        steps.append({"marker": mid, "restore": "absent" if previous is None else f"rév. {previous.get('revision')}"})
    reverse = {"enable": "disable", "disable": "enable"}
    steps += [{"timer": t["timer"], "action": reverse[t["action"]]} for t in journal["timers"]]
    result = {"mode": "rollback" if apply else "simulation", "transaction": transaction, "steps": steps}
    if not apply:
        return result
    runner = runner or Runner(simulate=Path(root) != Path("/"))
    for mid, previous in journal["markers"].items():
        if previous is None:
            _marker_path(root, mid).unlink(missing_ok=True)
        else:
            _write_atomic(_marker_path(root, mid), json.dumps(previous, sort_keys=True) + "\n")
    for item in reversed(journal["timers"]):
        runner(["systemctl", reverse[item["action"]], "--now", item["timer"]])
    if journal.get("created_dir"):
        directory = _under(root, MODULES_DIR)
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    result["commands"] = runner.calls
    return result


def uninstall(module_id, site_path=SITE_CONFIG, *, root="/", catalog_root=CATALOG, state_dir=None, apply=False,
              runner=None):
    """Retire le marqueur et arrête les timers ; les objets Graylog se retirent par ID (``uninstall`` existant)."""
    mods = manifests(catalog_root)
    if module_id not in mods:
        raise ModuleError("module inconnu : " + module_id)
    site = (load_site(site_path).get("site") or {})
    if module_id in (site.get("modules") or []):
        raise ModuleError("retirer d'abord le module de site.modules dans la configuration de site")
    module = mods[module_id]
    timers = [c["timer"] for c in module["collectors"] if c.get("timer")]
    result = {"mode": "uninstall" if apply else "simulation", "module": module_id,
              "marker": str(_marker_path(root, module_id)), "timers_disable": timers,
              "graylog": module.get("uninstall", {}), "keeps_data": module.get("uninstall", {}).get("keeps_data", True)}
    if not apply:
        return result
    runner = runner or Runner(simulate=Path(root) != Path("/"))
    journal = {"transaction": uuid.uuid4().hex, "date": _now(), "root": str(root),
               "markers": {module_id: read_marker(root, module_id)}, "timers": [], "created_dir": False}
    _marker_path(root, module_id).unlink(missing_ok=True)
    for timer in timers:
        if _under(root, "/etc/systemd/system/" + timer).is_file():
            journal["timers"].append({"timer": timer, "action": "disable"})
            runner(["systemctl", "disable", "--now", timer])
    _write_atomic(_state_dir(root, state_dir) / "transactions" / (journal["transaction"] + ".json"),
                  json.dumps(journal, indent=2) + "\n", 0o600)
    result["transaction"], result["commands"] = journal["transaction"], runner.calls
    return result


# ----------------------------------------------------------------------------- verify
def verify(site_path=SITE_CONFIG, *, root="/", catalog_root=CATALOG, client=None, runner=None):
    """Exécute les contrôles des modules actifs. Sans API : contrôles locaux seulement (« non vérifié »)."""
    mods = manifests(catalog_root)
    site_doc = load_site(site_path)
    resolved = resolve_site(site_doc, mods, root)
    results, failures = [], 0
    system = Path(root) == Path("/")
    for mid, entry in resolved["modules"].items():
        module = mods[mid]
        if not entry["enabled"]:
            results.append({"module": mid, "check": "-", "state": "non configuré"})
            continue
        for check in module["checks"]:
            if check.get("when") and not entry["parameters"].get(check["when"]):
                state = "non applicable (paramètre " + check["when"] + " désactivé)"
            else:
                state = _run_check(check, module, entry, site_doc, root, system, client)
            failed = state.startswith("ÉCHEC")
            if failed and check.get("severity", "critique") == "critique":
                failures += 1
            results.append({"module": mid, "check": check["id"], "type": check["type"],
                            "severity": check.get("severity", "critique"), "state": state})
    return {"mode": "verify", "legacy": resolved["legacy"], "results": results, "failures": failures}


def _run_check(check, module, entry, site_doc, root, system, client):
    kind = check["type"]
    if kind == "secret":
        info = entry["secrets"].get(check["secret"], {})
        return "ok" if info.get("state") == "ok" else f"ÉCHEC : secret {info.get('state', 'non déclaré')}"
    if kind == "lookup":
        return "ok" if _under(root, check["path"]).is_file() else "ÉCHEC : table absente " + check["path"]
    if kind == "unit":
        unit = check["unit"]
        if not _under(root, "/etc/systemd/system/" + unit).is_file():
            return "ÉCHEC : unité non déployée"
        if not system:
            return "ok (fichier présent ; état systemd non lu hors racine système)"
        rc = subprocess.run(["systemctl", "is-failed", "--quiet", unit], check=False, timeout=30).returncode
        return "ÉCHEC : unité en échec" if rc == 0 else "ok"
    if client is None:
        return "non vérifié (API Graylog non fournie)"
    try:
        if kind == "input_running":
            return _check_input(check, module, site_doc, client)
        if kind in ("stream_recent", "fields_present"):
            return _check_stream(check, client)
        if kind == "dashboards":
            from omni_integrations.client import check_dashboards, load_site_config
            result = check_dashboards(client, module, load_site_config_doc(site_doc, module["id"], load_site_config))
            return "ok" if not result["failures"] else "ÉCHEC : " + str(len(result["failures"])) + " widget(s)"
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        return "ÉCHEC : " + str(exc)[:160]
    return "non vérifié"


def load_site_config_doc(site_doc, module_id, loader):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(site_doc, handle)
    try:
        return loader(Path(handle.name), module_id)
    finally:
        os.unlink(handle.name)


def _check_input(check, module, site_doc, client):
    config = (site_doc.get("integrations") or {}).get(module["id"]) or {}
    spec = next((i for i in module["inputs"] if i["key"] == check.get("input")), {})
    wanted = (config.get("inputs") or {}).get(check.get("input")) or config.get("source_input")
    inputs = client.call("GET", "/system/inputs").get("inputs", [])
    if not wanted and spec.get("legacy_title"):
        wanted = next((i["id"] for i in inputs if i.get("title") == spec["legacy_title"]), None)
    if not wanted:
        return "ÉCHEC : entrée non désignée (integrations.<id>.inputs) ni trouvée par son titre"
    states = client.call("GET", "/system/inputstates").get("states", [])
    running = any(s.get("id") == wanted and s.get("state") == "RUNNING" for s in states)
    return "ok" if running else "ÉCHEC : entrée arrêtée ou absente"


def _check_stream(check, client):
    streams = client.call("GET", "/streams").get("streams", [])
    stream = next((s for s in streams if s.get("title") == check["stream"]), None)
    if stream is None:
        return "ÉCHEC : stream absent " + check["stream"]
    minutes = int(check.get("minutes", check.get("days", 1) * 1440))
    query = " AND ".join("_exists_:" + f for f in check.get("fields", [])) or "*"
    result = client.call("POST", "/search/aggregate", {
        "query": query, "streams": [stream["id"]], "timerange": {"type": "relative", "range": minutes * 60},
        "metrics": [{"function": "count"}]})
    rows = result.get("datarows", []) if result else []
    count = rows[0][-1] if rows else 0
    return f"ok ({count} message(s))" if count else f"ÉCHEC : aucun message sur {minutes} min"


# ----------------------------------------------------------------------------- outils
def inactive_targets(site_path, repo_root):
    """{cible: module} des fichiers de modules inactifs (vide sur un site historique ou sans catalogue)."""
    catalog_root = Path(repo_root) / "integrations"
    if not module_ids(catalog_root) or not Path(site_path).is_file():
        return {}
    site = load_site(site_path).get("site") or {}
    if "modules" not in site:
        return {}
    mods = manifests(catalog_root)
    pairs = parse_deploy_manifest(repo_root)
    enabled = set(site.get("modules") or [])
    return {target: mid for mid, module in mods.items() if mid not in enabled
            for target in collector_targets(module, pairs)}


def manifest_revision(data):
    """Révision d'un manifeste (octets) ; None si absent ou illisible."""
    if data is None:
        return None
    try:
        return json.loads(data).get("revision")
    except (ValueError, AttributeError):
        return None


def list_modules(site_path=SITE_CONFIG, catalog_root=CATALOG, root="/"):
    mods = manifests(catalog_root)
    resolved = resolve_site(load_site(site_path), mods, root)
    return [{"id": mid, "name": m["name"], "revision": m["revision"], "status": m["status"],
             "schema_version": m["schema_version"], "sources": m["provides"].get("sources", []),
             "enabled": resolved["modules"][mid]["enabled"], "marker": (read_marker(root, mid) or {}).get("revision")}
            for mid, m in mods.items()]
