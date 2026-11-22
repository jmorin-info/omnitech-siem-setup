"""Read-only aggregation of the update state of every layer (JSON schema v1).

Nothing in this module installs, fetches, restarts or writes: commands are
limited to dpkg-query, apt-cache policy, apt list, apt-mark showhold,
apt-config dump, systemctl show/is-active, git (read commands) and pip list;
HTTP calls are GET on loopback services. The JSON document is the stable
interface for the SSH manager and, later, the SOC console (docs/UPDATES.md).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re

from . import pydeps, versions
from .stack import COMPONENTS, CONFIG_BACKUP_GLOB, GRAYLOG_API, OPENSEARCH, PREFERENCES
from .system import json_or_none, read_simple_env

SCHEMA_VERSION = 1
LAYERS = ("code", "os", "stack", "python", "content", "health")
RANK = {"ok": 0, "info": 1, "inconnu": 2, "attention": 3, "action": 4}
TITLES = {"code": "Code du dépôt", "os": "Paquets OS et sécurité", "stack": "Pile Graylog / OpenSearch / MongoDB",
          "python": "Dépendances Python des venvs", "content": "Contenus de détection et intégrations",
          "health": "Pré-requis : santé, disque, sauvegardes"}
REFERENCE_KEYS = {"graylog-server": "GRAYLOG_PACKAGE_VERSION", "opensearch": "OPENSEARCH_PACKAGE_VERSION",
                  "mongodb-org-server": "MONGODB_PACKAGE_VERSION"}
GiB = 1024 ** 3


def worst(statuses):
    statuses = list(statuses) or ["ok"]
    return max(statuses, key=lambda s: RANK.get(s, 2))


def item(name, status, detail, **extra):
    return {"name": name, "status": status, "detail": detail, **extra}


def layer(identifier, items, summary, errors=None):
    return {"id": identifier, "title": TITLES[identifier], "status": worst(i["status"] for i in items),
            "summary": summary, "items": items, "errors": errors or []}


def _age_days(system, path):
    mtime = system.mtime(path)
    return None if mtime is None else (system.now() - mtime) / 86400


def _git(system, repo, *args):
    code, stdout, _ = system.run(["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args], timeout=60,
                                 env={"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    return stdout.strip() if code == 0 else None


# ----------------------------------------------------------------------- code
def collect_code(system, source, updater_state):
    items = []
    head = _git(system, source, "rev-parse", "HEAD")
    if not head:
        return layer("code", [item("dépôt", "inconnu", str(source) + " n'est pas un dépôt Git lisible")], "dépôt illisible")
    branch = _git(system, source, "rev-parse", "--abbrev-ref", "HEAD")
    dirty = _git(system, source, "status", "--porcelain", "--untracked-files=no")
    changed = len(dirty.splitlines()) if dirty else 0
    items.append(item("révision installée", "attention" if changed else "ok",
                      f"{head[:12]} ({branch}) ; " + (f"{changed} fichier(s) suivi(s) modifié(s) localement"
                                                      if changed else "aucune modification locale des fichiers suivis"),
                      installed=head, local_changes=changed))
    upstream = _git(system, source, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if upstream:
        counts = _git(system, source, "rev-list", "--left-right", "--count", "HEAD..." + upstream)
        behind = ahead = None
        if counts and len(counts.split()) == 2:
            ahead, behind = (int(x) for x in counts.split())
        fetched = _age_days(system, Path(source) / ".git" / "FETCH_HEAD")
        detail = f"{upstream} : {behind} commit(s) en retard, {ahead} en avance (selon le dernier fetch"
        detail += f", il y a {fetched:.1f} j)" if fetched is not None else ")"
        items.append(item("suivi de la branche distante", "info" if behind else "ok", detail,
                          behind=behind, ahead=ahead, upstream=upstream))
    current = json_or_none(system.read(Path(updater_state) / "current.json"))
    lock_present = system.exists(Path(updater_state) / "update.lock")
    if lock_present:
        items.append(item("verrou omni-update", "action", "update.lock présent : opération en cours ou interrompue "
                          "(voir docs/UPDATES.md, récupération)"))
    if current:
        items.append(item("transaction omni-update", "ok", "code_revision " + str(current.get("code_revision", ""))[:12]
                          + ", transaction " + str(current.get("transaction", "")), code_revision=current.get("code_revision")))
    cache = Path(updater_state) / "repository.git"
    if system.exists(cache / "HEAD"):
        base = (current or {}).get("code_revision") or head
        refs = _git(system, cache, "for-each-ref", "--sort=-committerdate", "--format=%(objectname)", "refs/omni/candidates")
        candidates = refs.split() if refs else []
        if candidates:
            latest = candidates[0]
            ahead = _git(system, cache, "rev-list", "--count", base + ".." + latest)
            if latest == base or ahead == "0":
                items.append(item("candidat téléchargé", "ok", "le dernier candidat est déjà la révision installée"))
            else:
                items.append(item("candidat téléchargé", "info", f"{latest[:12]} disponible ({ahead or '?'} commit(s)) : "
                                  "omni-update.py plan --target " + latest, available=latest))
    else:
        items.append(item("cache omni-update", "info", "aucun téléchargement : omni-update.py fetch n'a jamais été lancé avec "
                          + str(updater_state)))
    return layer("code", items, f"révision {head[:12]}" + (f", {changed} modification(s) locale(s)" if changed else ""))


# ------------------------------------------------------------------------- os
def collect_os(system):
    items = []
    code, stdout, _ = system.run(["apt", "list", "--upgradable"], timeout=120)
    pending = versions.parse_upgradable(stdout) if code == 0 else None
    if pending is None:
        items.append(item("paquets en attente", "inconnu", "apt list --upgradable indisponible"))
    else:
        security = [p for p in pending if p["security"]]
        stack = {p for c in COMPONENTS.values() for p in c["packages"]}
        stack_pending = [p for p in pending if p["package"] in stack]
        items.append(item("paquets en attente", "attention" if security else ("info" if pending else "ok"),
                          f"{len(pending)} paquet(s) dont {len(security)} de sécurité et {len(stack_pending)} de la pile SIEM",
                          available=len(pending), security=len(security),
                          packages=[f"{p['package']} {p['from']} -> {p['version']}" for p in pending]))
    lists = [system.mtime(p) for p in system.glob("/var/lib/apt/lists/*Packages*")]
    lists = [m for m in lists if m]
    if lists:
        age = (system.now() - max(lists)) / 86400
        items.append(item("listes apt", "action" if age > 7 else ("attention" if age > 2 else "ok"),
                          f"rafraîchies il y a {age:.1f} jour(s) (apt-daily.timer)", age_days=round(age, 1)))
    else:
        items.append(item("listes apt", "inconnu", "aucune liste apt trouvée"))
    code, stdout, _ = system.run(["apt-mark", "showhold"], timeout=30)
    holds = sorted(stdout.split()) if code == 0 else []
    items.append(item("paquets gelés (apt-mark hold)", "info" if holds else "ok",
                      ", ".join(holds) if holds else "aucun", holds=holds))
    if system.exists("/var/run/reboot-required"):
        packages = (system.read("/var/run/reboot-required.pkgs") or "").split()
        items.append(item("redémarrage requis", "attention", "noyau ou bibliothèques : " + (", ".join(packages) or "non précisé")
                          + " ; redémarrage manuel en fenêtre (/data chiffré TPM2)"))
    else:
        items.append(item("redémarrage requis", "ok", "non"))
    code, stdout, _ = system.run(["apt-config", "dump"], timeout=30)
    config = stdout if code == 0 else ""
    auto = 'APT::Periodic::Unattended-Upgrade "1"' in config
    reboot = 'Unattended-Upgrade::Automatic-Reboot "true"' in config
    blacklist = all(f'"{p}"' in config for p in ("graylog-server", "opensearch", "mongodb-org-server"))
    detail = ("activé" if auto else "désactivé") + ", redémarrage automatique " + ("ACTIVÉ" if reboot else "désactivé") \
        + ", pile SIEM " + ("exclue" if blacklist else "NON exclue") + " (52omni-siem.conf)"
    items.append(item("unattended-upgrades", "ok" if auto and not reboot and blacklist else "attention", detail))
    log_age = _age_days(system, "/var/log/unattended-upgrades/unattended-upgrades.log")
    if log_age is not None:
        items.append(item("dernier passage unattended-upgrades", "attention" if log_age > 3 else "ok",
                          f"il y a {log_age:.1f} jour(s)"))
    journal = system.read("/var/log/oms-maj-siem.log")
    if journal is not None:
        results = [line for line in journal.splitlines() if "RESULTAT" in line]
        last = results[-1] if results else ""
        state = "ok" if "RESULTAT : OK" in last or "rien a faire" in last else (
            "action" if "ANNULE" in last else ("attention" if last else "inconnu"))
        _, nxt, _ = system.run(["systemctl", "show", "oms-maj-siem.timer", "-p", "NextElapseUSecRealtime", "--value"], timeout=30)
        items.append(item("mise à jour hebdomadaire oms-maj-siem", state,
                          (last.strip() or "aucun résultat dans /var/log/oms-maj-siem.log")
                          + (" ; prochain passage : " + nxt.strip() if nxt.strip() else "")))
        items.append(weekly_run_freshness(system, journal))
    summary = items[0]["detail"]
    return layer("os", items, summary)


def weekly_run_freshness(system, journal):
    """oms-maj-siem.timer has Persistent=false: a run missed while the host was down
    is never caught up and nothing alerts. Only real runs count, not simulations."""
    runs = re.findall(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) === oms-maj-siem (?:normal|--force)", journal, re.MULTILINE)
    if not runs:
        return item("passage réel d'oms-maj-siem", "attention", "aucun passage réel consigné (seulement des simulations)")
    last = dt.datetime.strptime(runs[-1], "%Y-%m-%d %H:%M:%S")
    days = (dt.datetime.fromtimestamp(system.now()) - last).total_seconds() / 86400
    return item("passage réel d'oms-maj-siem", "attention" if days > 8 else "ok",
                f"dernier passage réel le {runs[-1]} (il y a {days:.1f} j)"
                + (" : passage hebdomadaire manqué, le timer (Persistent=false) ne rattrape pas" if days > 8 else ""),
                age_days=round(days, 1))


# ---------------------------------------------------------------------- stack
def collect_stack(system, source):
    items = []
    reference = read_simple_env(system.read(Path(source) / "stack-versions.env"), set(REFERENCE_KEYS.values()))
    _, holds_text, _ = system.run(["apt-mark", "showhold"], timeout=30)
    holds = set(holds_text.split())
    production_prefs = system.read(PREFERENCES)
    stanzas = versions.parse_preferences(production_prefs)
    gaps = []
    for package in ("graylog-server", "opensearch", "mongodb-org-server", "logstash"):
        _, policy_text, _ = system.run(["apt-cache", "policy", package], timeout=60)
        policy = versions.parse_policy(policy_text)
        installed, candidate = policy["installed"], policy["candidate"]
        ref = reference.get(REFERENCE_KEYS.get(package, ""), None)
        if not installed:
            items.append(item(package, "info", "non installé", reference=ref))
            continue
        notes, status = [], "ok"
        if candidate and versions.compare(candidate, installed) > 0:
            status = "info"
            notes.append(f"{candidate} disponible dans la série autorisée")
            if versions.PRERELEASE_PATTERN.search(candidate):
                notes.append("(pré-version)")
        newer = [v["version"] for v in policy["versions"] if v["priority"] < 0 and versions.compare(v["version"], installed) > 0]
        if newer:
            notes.append(f"versions hors série non autorisées par l'épinglage : jusqu'à {newer[0]}")
        if ref:
            order = versions.compare(installed, ref)
            if order < 0:
                status = worst([status, "attention"])
                notes.append(f"production en retard sur la référence {ref}")
                gaps.append(package)
            elif order > 0:
                status = worst([status, "attention"])
                notes.append(f"production en avance sur la référence {ref} (stack-versions.env à actualiser)")
                gaps.append(package)
            else:
                notes.append("conforme à la référence stack-versions.env")
        group = next((c for c in COMPONENTS.values() if package in c["packages"]), {"packages": [package]})
        held = sorted(holds & set(group["packages"]))
        pin = versions.pinned_pattern(stanzas, package)
        notes.append(("gelé" if held else "non gelé") + (", série épinglée " + pin if pin else ", sans épinglage"))
        items.append(item(package, status, f"installé {installed} ; " + " ; ".join(notes), installed=installed,
                          available=candidate if candidate != installed else None, reference=ref, held=bool(held), pin=pin))
    status, body = system.http_get(OPENSEARCH + "/", timeout=10)
    running = ((json_or_none(body) or {}).get("version") or {}).get("number") if status == 200 else None
    package_os = next((i.get("installed") for i in items if i["name"] == "opensearch"), None)
    if running and package_os:
        same = versions.compare(running, package_os) == 0
        items.append(item("OpenSearch en service", "ok" if same else "attention",
                          f"version en service {running}" + ("" if same else f" différente du paquet {package_os} (redémarrage en attente ?)")))
    mirror = system.read(Path(source) / "deploye/apt/oms-siem-series")
    if production_prefs is not None and mirror is not None:
        same = versions.parse_preferences(mirror) == stanzas
        items.append(item("miroir de l'épinglage dans le dépôt", "ok" if same else "attention",
                          "deploye/apt/oms-siem-series identique à " + PREFERENCES if same else
                          "deploye/apt/oms-siem-series diffère de " + PREFERENCES + " (miroir à resynchroniser)"))
    summary = "conforme à la référence" if not gaps else "écart avec la référence : " + ", ".join(gaps)
    return layer("stack", items, summary)


# --------------------------------------------------------------------- python
def collect_python(system, source):
    try:
        entries = pydeps.load_inventory(source, system)
    except (ValueError, KeyError) as error:
        return layer("python", [item("inventaire", "inconnu", str(error))], "inventaire illisible")
    items = []
    for entry in entries:
        result = pydeps.audit_venv(entry, source, system)
        extra = {k: result[k] for k in ("venv", "missing", "extra", "mismatched", "unpinned_requirements") if result.get(k) is not None}
        detail = result["detail"]
        if result["mismatched"]:
            detail += " ; versions : " + ", ".join(f"{m['name']} {m['locked']} -> {m['installed']}" for m in result["mismatched"][:5])
        if result["missing"]:
            detail += " ; absents : " + ", ".join(result["missing"][:5])
        if result["extra"]:
            detail += " ; non verrouillés : " + ", ".join(result["extra"][:5])
        if result["unpinned_requirements"]:
            detail += " ; dépendances directes à bornes ouvertes : " + ", ".join(result["unpinned_requirements"])
        items.append(item(entry["id"], result["status"], detail, **extra))
    conform = sum(1 for i in items if i["status"] == "ok")
    return layer("python", items, f"{conform}/{len(items)} venv(s) conforme(s) au verrouillage")


# -------------------------------------------------------------------- content
def _sha(system, path):
    data = system.read_bytes(path)
    return hashlib.sha256(data).hexdigest() if data is not None else None


def collect_content(system, source, graylog=None):
    items = []
    catalog = json_or_none(system.read(Path(source) / "integrations/catalog.json")) or {}
    modules = []
    for entry in catalog.get("modules", []):
        manifest = json_or_none(system.read(Path(source) / "integrations" / entry.get("manifest", ""))) or {}
        modules.append({"id": entry.get("id"), "revision": manifest.get("revision"), "status": manifest.get("status")})
    if not modules:
        items.append(item("catalogue d'intégrations", "inconnu", "integrations/catalog.json illisible"))
    for module in modules:
        installed = (graylog or {}).get(module["id"]) if graylog else None
        if graylog is None:
            items.append(item("intégration " + str(module["id"]), "info",
                              f"révision {module['revision']} au catalogue ({module['status']}) ; révision installée non vérifiée "
                              "(relancer avec --graylog et GRAYLOG_API_TOKEN)", available=module["revision"]))
        elif installed is None:
            items.append(item("intégration " + str(module["id"]), "ok",
                              f"révision {module['revision']} au catalogue ; non installée dans Graylog", available=module["revision"]))
        else:
            late = isinstance(installed, int) and isinstance(module["revision"], int) and installed < module["revision"]
            items.append(item("intégration " + str(module["id"]), "info" if late else "ok",
                              f"installée r{installed}, catalogue r{module['revision']}"
                              + (" : mise à jour par omni-integrations.py plan/install" if late else ""),
                              installed=installed, available=module["revision"]))
    manifest_text = system.read(Path(source) / "manifeste-deploye.txt")
    if manifest_text is None:
        items.append(item("code déployé (manifeste)", "inconnu", "manifeste-deploye.txt absent"))
    else:
        identical, different, absent = 0, [], []
        for line in manifest_text.splitlines():
            if not line.strip() or line.startswith("#") or "\t" not in line:
                continue
            deployed, repository = line.split("\t", 1)
            if not system.exists(deployed):
                absent.append(deployed)
                continue
            if _sha(system, deployed) == _sha(system, Path(source) / repository.strip()):
                identical += 1
            else:
                different.append(repository.strip())
        status = "attention" if different else "ok"
        detail = f"{identical} identique(s), {len(different)} différent(s), {len(absent)} absent(s) en service"
        if different:
            detail += " : " + ", ".join(different[:8]) + (" ..." if len(different) > 8 else "")
            detail += " (comparer avec ./synchro-manifeste.sh avant toute publication)"
        items.append(item("code déployé (manifeste)", status, detail, identical=identical, different=different, absent=absent))
    items.extend(threat_intel_feeds(system))
    return layer("content", items, f"{len(modules)} module(s) au catalogue")


SNAPSHOT_CONF = "/etc/oms-snap-siem.conf"


def snapshot_repository(system):
    """Repository written by oms-snap-siem (DEPOT in /etc/oms-snap-siem.conf, graylog_fs by default;
    graylog_fs_data after tools/migrer-depot-snapshots.sh)."""
    for line in (system.read(SNAPSHOT_CONF) or "").splitlines():
        if line.startswith("DEPOT="):
            value = line.split("=", 1)[1].strip().strip('"')
            if re.fullmatch(r"[a-z0-9_-]{1,64}", value):
                return value
    return "graylog_fs"


# Lookup CSV files written by omni-ti-feeds (deploye/sbin/omni-ti-feeds, daily). The
# robot keeps the previous file when a source returns nothing, so a dead feed shows
# up as a stale file rather than an empty one.
TI_FEEDS = {"/etc/graylog/lookup/ti-c2-ip.csv": "Feodo Tracker (IP de C2)",
            "/etc/graylog/lookup/ti-mal-domain.csv": "URLhaus (domaines malveillants)"}
TI_MAX_AGE_DAYS = 3


def threat_intel_feeds(system):
    result = []
    for path, label in TI_FEEDS.items():
        text = system.read(path)
        age = _age_days(system, path)
        if text is None or age is None:
            result.append(item("flux CTI " + label, "inconnu", path + " absent"))
            continue
        entries = max(len([line for line in text.splitlines() if line.strip()]) - 1, 0)
        stale = age > TI_MAX_AGE_DAYS
        result.append(item("flux CTI " + label, "attention" if stale or entries == 0 else "ok",
                           f"{entries} entrée(s), fichier mis à jour il y a {age:.0f} j"
                           + (" : source muette ou en erreur, contenu figé (vérifier omni-ti-feeds)" if stale else ""),
                           age_days=round(age, 1)))
    return result


def graylog_installations(system, token, api=GRAYLOG_API, source=None):
    """Installed content pack revision per catalogue module (GET only)."""
    import base64
    import sys
    sys.path.insert(0, str(source or Path(__file__).resolve().parents[1]))
    from omni_integrations.core import build_pack, catalog
    headers = {"Authorization": "Basic " + base64.b64encode((token + ":token").encode()).decode(),
               "Accept": "application/json", "X-Requested-By": "omni-update-status"}
    result = {}
    for module in catalog():
        pack = build_pack(module)
        status, body = system.http_get(api.rstrip("/") + f"/system/content_packs/{pack['id']}/installations", headers=headers)
        installations = (json_or_none(body) or {}).get("installations") if status == 200 else None
        if installations:
            result[module["id"]] = max(int(i.get("content_pack_revision", 0)) for i in installations)
    return result


# --------------------------------------------------------------------- health
def collect_health(system, source, repository=None):
    items = []
    variables = {}
    for base in [p for p in (repository, source) if p]:
        variables = read_simple_env(system.read(Path(base) / "00-vars.env"), {"BACKUP_DIR", "DATA_MOUNT"}) or variables
    backup_dir = variables.get("BACKUP_DIR", "/home/siem-backup")
    for path, minimum, label in (("/", 2 * GiB, "2 Gio"), ("/var", 3 * GiB, "3 Gio"),
                                 (variables.get("DATA_MOUNT", "/data"), None, "10 %"), (backup_dir, 5 * GiB, "5 Gio")):
        usage = system.disk_free(path)
        if usage is None:
            items.append(item("disque " + path, "inconnu", "volume introuvable"))
            continue
        ok = usage["free"] >= minimum if minimum else usage["free"] >= 0.10 * usage["total"]
        items.append(item("disque " + path, "ok" if ok else "action",
                          "%.1f Gio libres sur %.1f (minimum %s)" % (usage["free"] / GiB, usage["total"] / GiB, label)))
    status, body = system.http_get(OPENSEARCH + "/_cluster/health", timeout=10)
    health = (json_or_none(body) or {}).get("status") if status == 200 else None
    items.append(item("cluster OpenSearch", {"green": "ok", "yellow": "attention"}.get(health, "action"),
                      "état " + (health or "injoignable")))
    status, _ = system.http_get(GRAYLOG_API + "/system/lbstatus", timeout=10)
    items.append(item("API Graylog", "ok" if status == 200 else "action", "lbstatus HTTP " + str(status)))
    archives = [(system.mtime(p), p) for p in system.glob(CONFIG_BACKUP_GLOB)]
    archives = [a for a in archives if a[0]]
    code, result, _ = system.run(["systemctl", "show", "omni-backup-config.service", "-p", "Result", "--value"], timeout=30)
    result = result.strip() if code == 0 else "inconnu"
    if archives:
        mtime, path = max(archives)
        hours = (system.now() - mtime) / 3600
        ok = hours <= 26 and result == "success"
        items.append(item("sauvegarde de configuration vérifiée", "ok" if ok else "action",
                          f"{Path(path).name} il y a {hours:.1f} h ; dernier passage omni-backup-config : {result}",
                          age_hours=round(hours, 1)))
    else:
        items.append(item("sauvegarde de configuration vérifiée", "action", "aucune archive " + CONFIG_BACKUP_GLOB))
    repository = snapshot_repository(system)
    status, body = system.http_get(OPENSEARCH + f"/_cat/snapshots/{repository}?format=json", timeout=20)
    snapshots = json_or_none(body) if status == 200 else None
    if isinstance(snapshots, list):
        success = [s for s in snapshots if s.get("status") == "SUCCESS"]
        if success:
            last = max(success, key=lambda s: int(s.get("end_epoch", 0)))
            hours = (system.now() - int(last.get("end_epoch", 0))) / 3600
            items.append(item("snapshot OpenSearch", "ok" if hours <= 26 else "attention",
                              f"{last.get('id')} il y a {hours:.1f} h (dépôt {repository})"))
        else:
            items.append(item("snapshot OpenSearch", "attention", f"aucun snapshot SUCCESS dans {repository}"))
    else:
        items.append(item("snapshot OpenSearch", "inconnu", f"dépôt {repository} non consultable"))
    dumps = [(system.mtime(p), p) for p in system.glob(str(Path(backup_dir) / "mongo" / "graylog-mongo-*.archive.gz"))]
    dumps = [d for d in dumps if d[0]]
    if dumps:
        mtime, path = max(dumps)
        days = (system.now() - mtime) / 86400
        items.append(item("mongodump natif (08-backup.sh)", "attention" if days > 2 else "ok",
                          f"{Path(path).name} il y a {days:.0f} jour(s)"
                          + (" : planification native arrêtée ; la sauvegarde chiffrée quotidienne contient un mongodump" if days > 2 else "")))
    return layer("health", items, "pré-requis " + ("satisfaits" if all(i["status"] == "ok" for i in items) else "à examiner"))


# ------------------------------------------------------------------ aggregate
def collect(system, source, updater_state, layers=LAYERS, graylog=None, repository=None):
    """source: installed checkout examined by the code layer and holding 00-vars.env.
    repository: checkout providing the reference inventories (stack-versions.env,
    python-locks/, integrations/, manifeste-deploye.txt); defaults to source."""
    source = Path(source)
    repository = Path(repository or source)
    collectors = {"code": lambda: collect_code(system, source, updater_state), "os": lambda: collect_os(system),
                  "stack": lambda: collect_stack(system, repository), "python": lambda: collect_python(system, repository),
                  "content": lambda: collect_content(system, repository, graylog),
                  "health": lambda: collect_health(system, source, repository)}
    results = []
    for identifier in layers:
        try:
            results.append(collectors[identifier]())
        except Exception as error:  # a broken layer must not hide the others
            results.append(layer(identifier, [item("collecte", "inconnu", type(error).__name__ + " : " + str(error)[:200])],
                                 "collecte en échec", errors=[type(error).__name__]))
    return {"schema_version": SCHEMA_VERSION,
            "generated_at": dt.datetime.fromtimestamp(system.now(), dt.timezone.utc).isoformat(timespec="seconds"),
            "host": system.hostname(), "source": str(source), "repository": str(repository), "read_only": True,
            "overall": worst(r["status"] for r in results), "layers": results}


LABELS = {"ok": "OK", "info": "INFO", "inconnu": "INCONNU", "attention": "ATTENTION", "action": "ACTION REQUISE"}


def render_text(report):
    lines = [f"État des mises à jour - {report['host']} - {report['generated_at']}",
             f"Synthèse : {LABELS.get(report['overall'], report['overall'])} (lecture seule, rien n'a été modifié)"]
    for entry in report["layers"]:
        lines.append(f"\n[{LABELS.get(entry['status'], entry['status'])}] {entry['title']} - {entry['summary']}")
        for element in entry["items"]:
            lines.append(f"   - {LABELS.get(element['status'], element['status']):<9} {element['name']} : {element['detail']}")
    return "\n".join(lines)


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
