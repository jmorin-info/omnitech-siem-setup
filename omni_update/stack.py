"""Parameterized Graylog / OpenSearch / MongoDB / Logstash package upgrade.

Generalizes tools/upgrade-graylog-715.sh. The same code path produces the plan
(dry run, default) and performs the upgrade (explicit execute=True), so the plan
lists exactly the commands that would run. Nothing here downgrades a database:
a package rollback is offered, a MongoDB restore stays an explicit operator
decision documented in docs/UPDATES.md.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import time
from urllib.parse import quote

from . import versions
from .system import json_or_none, read_simple_env

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = Path("/var/lib/omni-siem-stack-upgrade")
PREFERENCES = "/etc/apt/preferences.d/oms-siem-series"
SERVER_CONF = "/etc/graylog/server/server.conf"
OPENSEARCH = "http://127.0.0.1:9200"
GRAYLOG_API = "http://127.0.0.1:9000/api"
INGEST_INDICES = "omni-*_deflector,graylog_deflector"
CONFIG_BACKUP_GLOB = "/var/backups/siem/omni-siem-config_*.tar.gz.enc"
BACKUP_MAX_AGE_HOURS = 26
GiB = 1024 ** 3

COMPONENTS = {
    "graylog": {"packages": ["graylog-server"], "primary": "graylog-server",
                "stop": ["graylog-server"], "start": ["graylog-server"],
                "config": ["/etc/graylog", "/etc/default/graylog-server"]},
    "opensearch": {"packages": ["opensearch"], "primary": "opensearch",
                   "stop": ["graylog-server", "opensearch"], "start": ["opensearch", "graylog-server"],
                   "config": ["/etc/opensearch"]},
    "mongodb": {"packages": ["mongodb-org", "mongodb-org-server", "mongodb-org-mongos", "mongodb-org-tools",
                             "mongodb-org-database", "mongodb-org-database-tools-extra", "mongodb-org-shell"],
                "primary": "mongodb-org-server",
                "stop": ["graylog-server", "mongod"], "start": ["mongod", "graylog-server"],
                "config": ["/etc/mongod.conf"]},
    "logstash": {"packages": ["logstash"], "primary": "logstash",
                 "stop": ["logstash"], "start": ["logstash"], "config": ["/etc/logstash"]},
}
PRERELEASE = versions.PRERELEASE_PATTERN
VERSION_SYNTAX = re.compile(r"[0-9][A-Za-z0-9.+~:-]{0,63}")


class StackError(RuntimeError):
    pass


def load_policy(path=None):
    data = json.loads(Path(path or Path(__file__).with_name("compat.json")).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise StackError("Politique de compatibilité : schéma non supporté")
    return data


def _check(name, ok, detail, blocking=True):
    return {"name": name, "ok": bool(ok), "blocking": blocking, "detail": detail}


class StackUpgrade:
    def __init__(self, system, component, target, *, source=ROOT, state_dir=STATE_DIR, backup_dir=None,
                 graylog_api=GRAYLOG_API, opensearch=OPENSEARCH, policy=None, allow_prerelease=False,
                 allow_series_change=False, accept_no_package_rollback=False, wait_scale=1.0):
        if component not in COMPONENTS:
            raise StackError("Composant inconnu : choisir parmi " + ", ".join(sorted(COMPONENTS)))
        if not isinstance(target, str) or not VERSION_SYNTAX.fullmatch(target):
            raise StackError("Version cible invalide")
        self.system, self.component, self.target = system, component, target
        self.definition = COMPONENTS[component]
        self.source, self.state_dir = Path(source), Path(state_dir)
        self.graylog_api, self.opensearch = graylog_api.rstrip("/"), opensearch.rstrip("/")
        self.policy = policy or load_policy()
        self.allow_prerelease, self.allow_series_change = allow_prerelease, allow_series_change
        self.accept_no_package_rollback = accept_no_package_rollback
        self.wait_scale = wait_scale
        variables = read_simple_env(system.read(self.source / "00-vars.env"), {"BACKUP_DIR"})
        self.backup_root = Path(backup_dir or variables.get("BACKUP_DIR") or "/home/siem-backup")
        stamp = dt.datetime.fromtimestamp(system.now(), dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.identifier = component + "-" + stamp
        self.backup_dir = self.backup_root / ("upgrade-" + self.identifier)

    # ------------------------------------------------------------------ inventory
    def installed(self, package):
        code, stdout, _ = self.system.run(["dpkg-query", "-W", "-f=${Status}|${Version}", package], timeout=30)
        if code != 0 or "|" not in stdout:
            return None
        status, version = stdout.split("|", 1)
        return version.strip() if status.strip().endswith("installed") and "not-installed" not in status else None

    def packages(self):
        return [p for p in self.definition["packages"] if self.installed(p)]

    def holds(self):
        code, stdout, _ = self.system.run(["apt-mark", "showhold"], timeout=30)
        return set(stdout.split()) if code == 0 else set()

    def policy_for(self, package):
        _, stdout, _ = self.system.run(["apt-cache", "policy", package], timeout=60)
        return versions.parse_policy(stdout)

    def preferences(self):
        return versions.parse_preferences(self.system.read(PREFERENCES))

    # ------------------------------------------------------------- compatibility
    def compatibility(self, primary_installed, packages):
        checks, rules = [], self.policy["components"][self.component]
        target = self.target
        if primary_installed is None:
            return [_check("paquet installé", False, self.definition["primary"] + " n'est pas installé sur cet hôte")]
        order = versions.compare(target, primary_installed)
        checks.append(_check("sens de la montée", order > 0,
                             f"{primary_installed} -> {target}" if order > 0 else
                             "version cible identique ou inférieure : utiliser rollback pour revenir en arrière"))
        prerelease = bool(PRERELEASE.search(target))
        checks.append(_check("version publiée (ni alpha, ni beta, ni rc)", not prerelease or self.allow_prerelease,
                             "pré-version refusée (option --allow-prerelease pour un environnement de test)" if prerelease
                             else "version finale"))
        same_major = versions.major(target) == versions.major(primary_installed)
        same_series = versions.series(target) == versions.series(primary_installed)
        if not same_major:
            checks.append(_check("version majeure", rules["major_change"] != "refuse",
                                 "changement de version majeure refusé par la politique : " + rules["note"]))
        elif not same_series:
            allowed = rules["series_change"] == "review" and self.allow_series_change
            checks.append(_check("série", allowed,
                                 ("changement de série accepté explicitement (--allow-series-change) : " if allowed
                                  else "changement de série : ") + rules["note"]))
        else:
            checks.append(_check("série", True, "même série " + versions.series(target) + " (correctif)"))
        for package in packages:
            info = self.policy_for(package)
            available = [v for v in info["versions"] if v["version"] == target]
            if not available:
                checks.append(_check("disponibilité " + package, False,
                                     f"{target} absent des dépôts apt connus (apt-cache policy) : vérifier la version ou attendre apt-daily"))
                continue
            pinned = versions.allowed_by_pin(self.preferences(), package, target)
            checks.append(_check("épinglage " + package, available[0]["priority"] > 0 and pinned is not False,
                                 "autorisé par " + PREFERENCES if pinned else
                                 ("aucun épinglage ne gouverne ce paquet" if pinned is None else
                                  "interdit par " + PREFERENCES + " (priorité -1) : modifier la série après revue")))
        combination = self.combination()
        validated = any(all(item.get(k) == v for k, v in combination.items())
                        for item in self.policy["validated_combinations"])
        checks.append(_check("combinaison de versions", validated,
                             ("combinaison déjà validée en production" if validated else
                              "combinaison non validée en production : lire les notes de version avant exécution ("
                              + ", ".join(f"{k} {v}" for k, v in sorted(combination.items())) + ")"),
                             blocking=False))
        return checks

    def combination(self):
        result = {}
        for package in ("graylog-server", "opensearch", "mongodb-org-server", "logstash"):
            version = self.installed(package)
            if version:
                result[package] = version
        result[self.definition["primary"]] = self.target
        return result

    # ------------------------------------------------------------- prerequisites
    def prerequisites(self, packages, execute):
        checks = []
        if execute:
            checks.append(_check("droits root", os.geteuid() == 0 if hasattr(os, "geteuid") else False,
                                 "exécution réservée à root (sudo)"))
        for path, minimum in (("/", 2 * GiB), ("/var", 3 * GiB), (str(self.backup_root), 5 * GiB)):
            usage = self.system.disk_free(path)
            if usage is None:
                checks.append(_check("espace disque " + path, False, "volume introuvable"))
            else:
                checks.append(_check("espace disque " + path, usage["free"] >= minimum,
                                     "%.1f Gio libres (minimum %.0f Gio)" % (usage["free"] / GiB, minimum / GiB)))
        status, body = self.system.http_get(self.opensearch + "/_cluster/health", timeout=10)
        health = (json_or_none(body) or {}).get("status")
        checks.append(_check("santé OpenSearch", health == "green", "cluster " + str(health or "injoignable")))
        status, _ = self.system.http_get(self.graylog_api + "/system/lbstatus", timeout=10)
        checks.append(_check("API Graylog", status == 200, "lbstatus HTTP " + str(status)))
        checks.append(self.backup_check())
        code, stdout, _ = self.system.run(["dpkg", "--audit"], timeout=60)
        checks.append(_check("base dpkg cohérente", code == 0 and not stdout.strip(),
                             "dpkg --audit sans anomalie" if code == 0 and not stdout.strip() else "dpkg --audit signale des paquets à réparer"))
        code, stdout, _ = self.system.run(["systemctl", "is-active", "oms-maj-siem.service"], timeout=30)
        running = stdout.strip() in {"active", "activating", "reloading"}
        checks.append(_check("aucune mise à jour automatique en cours", not running,
                             "oms-maj-siem en cours : attendre sa fin" if running else "oms-maj-siem inactif"))
        lists = [self.system.mtime(p) for p in self.system.glob("/var/lib/apt/lists/*Packages*")]
        lists = [m for m in lists if m]
        age = (self.system.now() - max(lists)) / 86400 if lists else None
        checks.append(_check("fraîcheur des listes apt", age is not None and age <= 2,
                             "listes apt de %.1f jour(s)" % age if age is not None else "listes apt introuvables",
                             blocking=False))
        checks.extend(self.rollback_packages_check(packages))
        return checks

    def backup_check(self):
        archives = [(self.system.mtime(p), p) for p in self.system.glob(CONFIG_BACKUP_GLOB)]
        archives = [item for item in archives if item[0]]
        code, stdout, _ = self.system.run(["systemctl", "show", "omni-backup-config.service", "-p", "Result", "--value"], timeout=30)
        result = stdout.strip() if code == 0 else "inconnu"
        if not archives:
            return _check("sauvegarde récente et vérifiée", False,
                          "aucune archive " + CONFIG_BACKUP_GLOB + " (omni-backup-config)")
        mtime, path = max(archives)
        age = (self.system.now() - mtime) / 3600
        ok = age <= BACKUP_MAX_AGE_HOURS and result == "success"
        return _check("sauvegarde récente et vérifiée", ok,
                      "%s, %.1f h, dernier passage omni-backup-config : %s (la vérification de restaurabilité fait partie du passage)"
                      % (Path(path).name, age, result))

    def deb_name(self, package, version):
        return package + "_" + version.replace(":", "%3a") + "_"

    def rollback_packages_check(self, packages):
        checks = []
        for package in packages:
            version = self.installed(package)
            cached = self.system.glob("/var/cache/apt/archives/" + self.deb_name(package, version) + "*.deb")
            remote = any(v["version"] == version for v in self.policy_for(package)["versions"])
            ok = bool(cached) or remote or self.accept_no_package_rollback
            if cached:
                detail = "présent dans le cache apt"
            elif remote:
                detail = "téléchargeable (apt-get download) avant la montée"
            elif ok:
                detail = "absent : retour arrière du paquet impossible (accepté explicitement)"
            else:
                detail = "absent du cache et des dépôts : retour arrière du paquet impossible"
            checks.append(_check("paquet de retour arrière " + package + " " + version, ok, detail))
        return checks

    # -------------------------------------------------------------- credentials
    def graylog_headers(self):
        token = os.environ.get("GRAYLOG_API_TOKEN")
        if token:
            credentials = token + ":token"
        else:
            password = read_simple_env(self.system.read(self.source / "00-vars.env"), {"GRAYLOG_ADMIN_PASS"}).get("GRAYLOG_ADMIN_PASS")
            if not password:
                return None
            credentials = "admin:" + password
        return {"Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
                "Accept": "application/json", "X-Requested-By": "omni-stack-upgrade"}

    def inputs_running(self):
        headers = self.graylog_headers()
        if not headers:
            return None
        status, body = self.system.http_get(self.graylog_api + "/system/inputstates", headers=headers, timeout=20)
        data = json_or_none(body) if status == 200 else None
        if not isinstance(data, dict):
            return None
        states = data.get("states", [])
        return {"running": sum(1 for s in states if s.get("state") == "RUNNING"), "total": len(states),
                "not_running": sorted({(s.get("message_input") or {}).get("title", "?") for s in states
                                       if s.get("state") != "RUNNING"})}

    def graylog_system(self):
        headers = self.graylog_headers()
        if not headers:
            return None
        status, body = self.system.http_get(self.graylog_api + "/system", headers=headers, timeout=20)
        return json_or_none(body) if status == 200 else None

    def ingest_count(self):
        query = quote("timestamp:[now-5m TO now]", safe="")
        status, body = self.system.http_get(self.opensearch + "/" + INGEST_INDICES + "/_count?ignore_unavailable=true"
                                            "&allow_no_indices=true&q=" + query, timeout=30)
        return (json_or_none(body) or {}).get("count") if status == 200 else None

    # ---------------------------------------------------------------- execution
    def plan(self):
        return self.run(execute=False)

    def run(self, execute=False, confirm=None):
        packages = self.packages()
        primary_installed = self.installed(self.definition["primary"])
        held = self.holds()
        report = {"schema_version": 1, "id": self.identifier, "component": self.component,
                  "target": self.target, "mode": "execute" if execute else "dry-run",
                  "installed": {p: self.installed(p) for p in packages},
                  "held": sorted(held & set(packages)),
                  "compatibility": self.compatibility(primary_installed, packages),
                  "prerequisites": [], "steps": [], "verification": [], "status": "planned",
                  "backup_dir": str(self.backup_dir), "rollback": []}
        if primary_installed:
            report["prerequisites"] = self.prerequisites(packages, execute)
        blocking = [c for c in report["compatibility"] + report["prerequisites"] if c["blocking"] and not c["ok"]]
        report["blocking"] = [c["name"] + " : " + c["detail"] for c in blocking]
        report["rollback"] = self.rollback_commands(report["installed"], report["held"])
        self.describe_steps(report, packages, held)
        if not execute:
            report["status"] = "blocked" if blocking else "ready"
            return report
        expected = self.component + "=" + self.target
        if confirm != expected:
            raise StackError("Confirmation absente ou différente : passer --confirm " + expected)
        if blocking:
            report["status"] = "blocked"
            self.journal(report)
            return report
        return self.execute(report, packages, held)

    def describe_steps(self, report, packages, held):
        services_stop, services_start = self.definition["stop"], self.definition["start"]
        pins = [p + "=" + self.target for p in packages]
        to_hold = sorted(held & set(packages))
        steps = [
            "install -d -m 700 " + str(self.backup_dir),
            "mongodump --config=<fichier 0600 temporaire contenant l'URI de " + SERVER_CONF + "> --gzip --archive="
            + str(self.backup_dir / "mongo.archive.gz"),
            "gzip -t " + str(self.backup_dir / "mongo.archive.gz"),
            "tar -czf " + str(self.backup_dir / "config.tar.gz") + " " + " ".join(self.definition["config"] + ["/etc/apt"]),
            "dpkg -l > " + str(self.backup_dir / "dpkg-l.txt"),
            "apt-get download " + " ".join(p + "=" + report["installed"][p] for p in packages)
            + "   (dans " + str(self.backup_dir) + ", si absent du cache apt)",
            "relevé avant : inputs Graylog RUNNING, documents ingérés sur 5 min",
        ] + ["systemctl stop " + s for s in services_stop]
        if to_hold:
            steps.append("apt-mark unhold " + " ".join(to_hold))
        steps.append("DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y --no-install-recommends "
                     "-o Dpkg::Options::=--force-confold " + " ".join(pins))
        if to_hold:
            steps.append("apt-mark hold " + " ".join(to_hold))
        steps += ["systemctl start " + s for s in services_start]
        steps.append("vérifications : version installée, OpenSearch vert, API Graylog, inputs RUNNING, flux reçu, fichiers .dpkg-dist")
        report["steps"] = steps

    def rollback_commands(self, installed, held):
        packages = list(installed)
        debs = " ".join(str(self.backup_dir / (self.deb_name(p, installed[p]) + "*.deb")) for p in packages)
        commands = ["systemctl stop " + " ".join(self.definition["stop"])]
        commands.append("apt-mark unhold " + " ".join(packages))
        commands.append("dpkg -i " + debs + "   # ou : apt-get install --allow-downgrades "
                        + " ".join(p + "=" + v for p, v in installed.items()))
        if held:
            commands.append("apt-mark hold " + " ".join(held))
        commands += ["systemctl start " + s for s in self.definition["start"]]
        commands.append("# Seulement si les données de configuration Graylog sont altérées (décision explicite) :")
        commands.append("#   systemctl stop graylog-server && mongorestore --config=<fichier URI 0600> --gzip --drop --archive="
                        + str(self.backup_dir / "mongo.archive.gz") + " && systemctl start graylog-server")
        return commands

    def _run(self, report, argv, timeout=600, env=None, cwd_note=None):
        code, _, stderr = self.system.run(argv, timeout=timeout, env=env)
        entry = {"command": " ".join(shlex.quote(a) for a in argv) + (cwd_note or ""), "returncode": code}
        report.setdefault("executed", []).append(entry)
        if code != 0:
            raise StackError("Échec de : " + entry["command"] + " (code " + str(code) + ") " + (stderr or "")[-300:])

    def _wait(self, predicate, seconds, interval=10):
        deadline = self.system.now() + seconds * self.wait_scale
        while True:
            if predicate():
                return True
            if self.system.now() >= deadline:
                return False
            time.sleep(interval * self.wait_scale)

    def backup(self, report, packages):
        self._run(report, ["install", "-d", "-m", "700", str(self.backup_dir)])
        uri = None
        for line in (self.system.read(SERVER_CONF) or "").splitlines():
            if re.match(r"\s*mongodb_uri\s*=", line):
                uri = line.split("=", 1)[1].strip()
        if not uri:
            raise StackError("mongodb_uri introuvable dans " + SERVER_CONF)
        descriptor, config = tempfile.mkstemp(prefix="mongodump-", suffix=".yaml")
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, ("uri: " + json.dumps(uri) + "\n").encode())
            os.close(descriptor)
            archive = str(self.backup_dir / "mongo.archive.gz")
            self._run(report, ["mongodump", "--quiet", "--config=" + config, "--gzip", "--archive=" + archive], timeout=3600)
        finally:
            Path(config).unlink(missing_ok=True)
        self._run(report, ["gzip", "-t", archive])
        self._run(report, ["tar", "-czf", str(self.backup_dir / "config.tar.gz"), *self.definition["config"], "/etc/apt"])
        code, stdout, _ = self.system.run(["dpkg", "-l"], timeout=60)
        if code == 0:
            self.write_private(self.backup_dir / "dpkg-l.txt", stdout)
        for package in packages:
            version = report["installed"][package]
            if not self.system.glob("/var/cache/apt/archives/" + self.deb_name(package, version) + "*.deb"):
                self._run(report, ["bash", "-c", "cd " + shlex.quote(str(self.backup_dir)) + " && apt-get download "
                                   + shlex.quote(package + "=" + version)], timeout=1800)
            else:
                self._run(report, ["bash", "-c", "cp /var/cache/apt/archives/" + shlex.quote(self.deb_name(package, version))
                                   + "*.deb " + shlex.quote(str(self.backup_dir) + "/")])

    def write_private(self, path, text):
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(text)
        except OSError:
            pass

    def execute(self, report, packages, held):
        report["status"] = "running"
        report["started_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.journal(report)
        try:
            self.backup(report, packages)
            report["before"] = {"inputs": self.inputs_running(), "ingest_5min": self.ingest_count()}
            self.journal(report)
            for service in self.definition["stop"]:
                self._run(report, ["systemctl", "stop", service], timeout=600)
            to_hold = sorted(held & set(packages))
            if to_hold:
                self._run(report, ["apt-mark", "unhold", *to_hold])
            try:
                self._run(report, ["apt-get", "install", "-y", "--no-install-recommends", "-o",
                                   "Dpkg::Options::=--force-confold", *[p + "=" + self.target for p in packages]],
                          timeout=3600, env={"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"})
            finally:
                if to_hold:
                    self.system.run(["apt-mark", "hold", *to_hold], timeout=60)
            for service in self.definition["start"]:
                self._run(report, ["systemctl", "start", service], timeout=900)
        except StackError as error:
            report["status"] = "failed"
            report["error"] = str(error)
            report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            self.journal(report)
            return report
        report["verification"] = self.verify(report, packages)
        failed = [c for c in report["verification"] if c["blocking"] and not c["ok"]]
        report["status"] = "verification_failed" if failed else "success"
        report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.journal(report)
        return report

    def verify(self, report, packages):
        checks = []
        for package in packages:
            version = self.installed(package)
            checks.append(_check("version " + package, version == self.target, "installée : " + str(version)))
        green = self._wait(lambda: (json_or_none(self.system.http_get(self.opensearch + "/_cluster/health")[1]) or {})
                           .get("status") == "green", 1800, 15)
        checks.append(_check("OpenSearch vert", green, "cluster vert" if green else "cluster non vert après 30 min"))
        alive = self._wait(lambda: self.system.http_get(self.graylog_api + "/system/lbstatus")[0] == 200, 600, 10)
        checks.append(_check("API Graylog", alive, "lbstatus 200" if alive else "lbstatus indisponible après 10 min"))
        system = self.graylog_system() if alive else None
        if system is not None:
            processing = system.get("lifecycle") == "running" and system.get("is_processing") is True
            checks.append(_check("Graylog en traitement", processing,
                                 "version %s, lifecycle %s, is_processing %s" % (system.get("version"), system.get("lifecycle"),
                                                                                 system.get("is_processing"))))
        else:
            checks.append(_check("Graylog en traitement", False, "API /system non consultable (jeton ou mot de passe absent ?)"))
        before = (report.get("before") or {}).get("inputs")
        after = None
        if alive:
            time.sleep(60 * self.wait_scale)  # laisse aux inputs le temps de démarrer
            after = self.inputs_running()
        if after is None:
            checks.append(_check("inputs RUNNING", False, "état des inputs non consultable"))
        else:
            expected = before["running"] if before else after["total"]
            checks.append(_check("inputs RUNNING", after["running"] >= expected,
                                 "%d/%d RUNNING (avant : %s)%s" % (after["running"], after["total"],
                                                                   before["running"] if before else "inconnu",
                                                                   (" ; arrêtés : " + ", ".join(after["not_running"])) if after["not_running"] else "")))
        flow = self._wait(lambda: (self.ingest_count() or 0) > 0, 600, 30)
        checks.append(_check("flux reçu", flow, "documents ingérés sur les 5 dernières minutes" if flow else "aucun document récent après 10 min"))
        if self.component == "logstash":
            code, stdout, _ = self.system.run(["/usr/share/logstash/bin/logstash-plugin", "list"], timeout=600)
            checks.append(_check("greffon logstash-output-gelf", code == 0 and "logstash-output-gelf" in stdout,
                                 "présent" if "logstash-output-gelf" in stdout else
                                 "absent : réinstaller (logstash-plugin install logstash-output-gelf)", blocking=False))
        dist = [p for path in self.definition["config"] for p in self.system.glob(path.rstrip("/") + "/**/*.dpkg-dist")
                + self.system.glob(path + ".dpkg-dist")]
        checks.append(_check("nouveaux modèles de configuration", True,
                             ("à lire (configuration en place conservée) : " + ", ".join(dist)) if dist else "aucun fichier .dpkg-dist",
                             blocking=False))
        return checks

    def journal(self, report):
        self.write_private(self.state_dir / (self.identifier + ".json"),
                           json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def render(report):
    lines = [f"Montée de version {report['component']} -> {report['target']} ({report['mode']}) : {report['status']}",
             "Installé : " + ", ".join(f"{p} {v}" for p, v in report["installed"].items()) or "aucun paquet"]
    for title, key in (("Compatibilité", "compatibility"), ("Pré-requis", "prerequisites"), ("Vérification", "verification")):
        if report.get(key):
            lines.append("\n" + title + " :")
            for check in report[key]:
                mark = "OK " if check["ok"] else ("KO " if check["blocking"] else "AVERT.")
                lines.append(f"  [{mark}] {check['name']} : {check['detail']}")
    lines.append("\nÉtapes (" + ("exécutées" if report["mode"] == "execute" else "non exécutées, dry-run") + ") :")
    lines += ["  " + str(i) + ". " + step for i, step in enumerate(report["steps"], 1)]
    lines.append("\nRetour arrière documenté :")
    lines += ["  " + command for command in report["rollback"]]
    if report.get("blocking"):
        lines.append("\nBLOQUANT :")
        lines += ["  - " + item for item in report["blocking"]]
    if report.get("error"):
        lines.append("\nErreur : " + report["error"])
    return "\n".join(lines)


def rollback(system, journal_path, *, execute=False, confirm=None):
    """Package-only rollback from the debs saved by a previous run (never MongoDB)."""
    report = json_or_none(system.read(journal_path))
    if not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("component") not in COMPONENTS:
        raise StackError("Journal de montée de version illisible : " + str(journal_path))
    definition = COMPONENTS[report["component"]]
    backup_dir = Path(report["backup_dir"])
    installed, held = report["installed"], report.get("held", [])
    debs = []
    for package, version in installed.items():
        name = package + "_" + version.replace(":", "%3a") + "_"
        found = system.glob(str(backup_dir / name) + "*.deb")
        debs.append(found[0] if found else None)
    plan = {"journal": str(journal_path), "component": report["component"], "restore_versions": installed,
            "mode": "execute" if execute else "dry-run", "missing_packages": [p for p, d in zip(installed, debs) if not d],
            "steps": ["systemctl stop " + s for s in definition["stop"]]
            + ["apt-mark unhold " + " ".join(installed),
               "apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold " + " ".join(d or "?" for d in debs)]
            + (["apt-mark hold " + " ".join(held)] if held else [])
            + ["systemctl start " + s for s in definition["start"]],
            "note": "MongoDB n'est jamais restauré automatiquement : voir docs/UPDATES.md (restauration mongorestore)."}
    if not execute:
        plan["status"] = "blocked" if plan["missing_packages"] else "ready"
        return plan
    expected = "rollback-" + report["component"]
    if confirm != expected:
        raise StackError("Confirmation absente ou différente : passer --confirm " + expected)
    if plan["missing_packages"]:
        raise StackError("Paquets de retour arrière absents de " + str(backup_dir))
    steps = [["systemctl", "stop", s] for s in definition["stop"]]
    steps += [["apt-mark", "unhold", *installed], ["apt-get", "install", "-y", "--allow-downgrades", "-o",
                                                   "Dpkg::Options::=--force-confold", *debs]]
    steps += [["apt-mark", "hold", *held]] if held else []
    steps += [["systemctl", "start", s] for s in definition["start"]]
    plan["executed"] = []
    for argv in steps:
        code, _, stderr = system.run(argv, timeout=3600, env={"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"})
        plan["executed"].append({"command": " ".join(shlex.quote(a) for a in argv), "returncode": code})
        if code != 0:
            plan["status"] = "failed"
            plan["error"] = (stderr or "")[-300:]
            return plan
    plan["status"] = "rolled_back"
    return plan
