"""Déploiement transactionnel des composants maison, piloté par manifeste-deploye.txt.

Sens unique : dépôt -> système. Le plan est en lecture seule ; l'application
sauvegarde chaque fichier remplacé dans une transaction, exécute les actions
associées (daemon-reload, nginx -t puis reload, redémarrage des seuls services
longs déjà actifs) et revient automatiquement en arrière si l'une d'elles échoue.
Une transaction appliquée peut être annulée explicitement (plan puis application).

La racine factice (--root) préfixe toutes les cibles et désactive toute commande
système : elle sert aux tests et aux répétitions hors production.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

DEFAULT_HOME = "/opt/omni-siem/repository"
LEGACY_HOME = "/root/omnitech-siem-setup"
PLACEHOLDER = "${MOT_DE_PASSE_LU_HORS_DEPOT}"
MANIFEST = "manifeste-deploye.txt"
DEFAULT_STATE = "/var/lib/omni-siem-deploy"

# Ordre d'application de « all » : dépendances Python avant le code qui les utilise,
# unités après les fichiers qu'elles exécutent, nginx et la console en dernier.
COMPONENTS = ("venvs", "robots", "etc", "apt", "opt", "logstash", "systemd", "nginx", "console")
# Les préférences APT fixent les séries de paquets : elles relèvent des montées de version
# (tools/omni-update.py) et ne sont déployées que sur demande explicite, jamais par « all ».
EXPLICIT_ONLY = ("apt",)
PREFIXES = (
    ("/usr/local/sbin/", "robots"), ("/usr/local/lib/", "robots"),
    ("/etc/systemd/system/", "systemd"), ("/etc/nginx/", "nginx"), ("/etc/logstash/", "logstash"),
    ("/etc/apt/", "apt"), ("/var/www/siem-soc/", "console"), ("/var/www/siem-mobile/", "console"),
    ("/opt/", "opt"), ("/etc/", "etc"),
)
VENVS = {
    "mobile": {"requirements": "mobile/requirements.txt"},
    "oms-xdr": {"requirements": "oms-xdr/requirements.txt"},
    "oms-graph": {"requirements": "oms-graph/requirements.txt"},
    "oms-ml": {"requirements": "oms-ml/requirements.txt"},
}
# Droits imposés (0644) : unités systemd (un fichier 0600 génère un avertissement à chaque
# chargement), fragments nginx, console publique. Logstash (0640 root:logstash) et APT
# conservent leurs droits actuels.
FIXED_MODE = {"systemd": 0o644, "nginx": 0o644, "console": 0o644}
NOTES = {
    "logstash": "Logstash n'est pas redémarré automatiquement : décider du rechargement après lecture du diff.",
    "apt": "Préférences APT : aucune commande apt n'est lancée ; vérifier que la série épinglée est celle validée par la procédure de mise à jour.",
    "console": "Les routes nginx de /soc/ relèvent de tools/deploy-console.py (installation).",
}
TRANSACTION_RE = re.compile(r"[a-f0-9]{32}")
SETTLE_SECONDS = 5
SECRET_ENV = re.compile(rb"(?im)^\s*Environment=.*(pass|secret|token|key)")


class DeployError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def component_of(target: str) -> str | None:
    return next((name for prefix, name in PREFIXES if target.startswith(prefix)), None)


def parse_manifest(text: str):
    entries, errors = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 2 or not all(fields):
            errors.append(f"ligne {number} : format attendu <cible><TAB><source>")
            continue
        target, source = fields
        pure = PurePosixPath(target)
        if not pure.is_absolute() or ".." in pure.parts or str(pure) != target:
            errors.append(f"ligne {number} : cible non normalisée {target}")
            continue
        if PurePosixPath(source).is_absolute() or ".." in PurePosixPath(source).parts:
            errors.append(f"ligne {number} : source hors du dépôt {source}")
            continue
        if component_of(target) is None:
            errors.append(f"ligne {number} : cible hors des répertoires autorisés {target}")
            continue
        entries.append((target, source))
    seen = set()
    for target, _ in entries:
        if target in seen:
            errors.append("cible en double : " + target)
        seen.add(target)
    return entries, errors


def unit_name(target: str) -> str | None:
    """omni-x.service ou omni-x.service.d/y.conf -> omni-x.service."""
    if not target.startswith("/etc/systemd/system/"):
        return None
    relative = target.removeprefix("/etc/systemd/system/").split("/")
    return relative[0].removesuffix(".d") if len(relative) == 2 else relative[0]


class Runner:
    """Exécute une commande système ; en racine factice, ne fait que la consigner."""

    def __init__(self, simulate=False):
        self.simulate = simulate
        self.calls = []

    def __call__(self, argv, timeout=900):
        self.calls.append(list(argv))
        if self.simulate:
            return 0, ""
        try:
            process = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, type(exc).__name__
        return process.returncode, (process.stdout + process.stderr).strip()


class Deployer:
    def __init__(self, source, *, home=None, root="/", state_dir=None, runner=None, emit=None):
        self.source = Path(source).resolve()
        self.home = Path(home or os.environ.get("OMNI_SIEM_HOME") or DEFAULT_HOME)
        if not self.home.is_absolute() or ".." in self.home.parts:
            raise DeployError("OMNI_SIEM_HOME doit être un chemin absolu normalisé.")
        self.root = Path(root).resolve()
        self.system = self.root == Path("/")
        default_state = Path(DEFAULT_STATE) if self.system else self.root / DEFAULT_STATE.lstrip("/")
        self.state = Path(state_dir).resolve() if state_dir else default_state
        self.run_command = runner or Runner(simulate=not self.system)
        self.emit = emit or (lambda line: None)

    # ------------------------------------------------------------------ entrées
    def physical(self, target: str) -> Path:
        return self.root / target.lstrip("/")

    def render(self, data: bytes) -> bytes:
        if str(self.home) != DEFAULT_HOME:
            data = data.replace(DEFAULT_HOME.encode(), str(self.home).encode())
        return data

    def _console_module(self):
        path = self.source / "tools/deploy-console.py"
        spec = importlib.util.spec_from_file_location("omni_deploy_console", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def entries(self, components):
        manifest = self.source / MANIFEST
        listed, errors = parse_manifest(manifest.read_text(encoding="utf-8"))
        if errors:
            raise DeployError("manifeste invalide : " + " ; ".join(errors[:5]))
        selected = [(t, s, component_of(t)) for t, s in listed if component_of(t) in components]
        if "console" in components:
            # Le manifeste ne suit que la coquille de la console : toutes les ressources
            # publiées par deploy-console.py sont ajoutées pour ne rien oublier.
            console = self._console_module()
            known = {t for t, _, _ in selected}
            for base, target_root in (("mobile/soc", "/var/www/siem-soc"), ("mobile/www", "/var/www/siem-mobile")):
                for path in console.asset_files(self.source / base):
                    target = target_root + "/" + path.relative_to(self.source / base).as_posix()
                    if target not in known:
                        selected.append((target, path.relative_to(self.source).as_posix(), "console"))
                        known.add(target)
            if "/var/www/siem-mobile/chart.min.js" not in known and (self.source / "mobile/soc/chart.min.js").is_file():
                selected.append(("/var/www/siem-mobile/chart.min.js", "mobile/soc/chart.min.js", "console"))

        # Contrat de module : les fichiers d'un module inactif sur ce site ne sont pas posés
        # (un fichier déjà présent reste mis à jour, jamais supprimé par deploy).
        self.module_skipped, self.module_error = [], None
        try:
            from omni_integrations.modules import inactive_targets
            inactive = inactive_targets(self.physical("/etc/omni-siem/integrations.json"), self.source)
        except ImportError:
            inactive = {}
        except (OSError, ValueError) as exc:
            inactive, self.module_error = {}, str(exc)
        if inactive:
            kept = []
            for item in selected:
                if item[0] in inactive and not self.physical(item[0]).exists():
                    self.module_skipped.append({"target": item[0], "module": inactive[item[0]]})
                else:
                    kept.append(item)
            selected = kept
        def order(item):
            target, _, component = item
            # Comme deploy-console.py : la page puis le service worker en dernier.
            rank = 2 if target.endswith("/sw.js") else 1 if target.endswith("/index.html") else 0
            return COMPONENTS.index(component), rank, target
        return sorted(selected, key=order)

    def file_state(self, target, source, component):
        item = {"target": target, "source": source, "component": component}
        path = self.source / source
        if not path.is_file() or path.is_symlink():
            return {**item, "state": "bloque", "reason": "source absente ou lien symbolique"}
        data = self.render(path.read_bytes())
        if PLACEHOLDER.encode() in data:
            return {**item, "state": "bloque", "reason": "source contenant un mot de passe masqué par synchro-manifeste.sh"}
        legacy = LEGACY_HOME.encode() in data
        physical = self.physical(target)
        if self.home in physical.parents or physical == self.home:
            return {**item, "state": "bloque", "reason": "cible située dans le dépôt canonique"}
        item["sha_after"] = sha256(data)
        if physical.is_symlink() or any(p.is_symlink() for p in physical.parents if p != self.root and self.root in p.parents):
            return {**item, "state": "bloque", "reason": "cible ou répertoire parent en lien symbolique"}
        if physical.exists() and not physical.is_file():
            return {**item, "state": "bloque", "reason": "la cible existe et n'est pas un fichier"}
        item["mode"] = self.target_mode(component, path, data, physical)
        if physical.exists():
            before = sha256(physical.read_bytes())
            current_mode = physical.stat().st_mode & 0o7777
            if before == item["sha_after"]:
                item.update(sha_before=before, mode_before=current_mode)
                if legacy:
                    item["note"] = "identique à la production mais référence encore " + LEGACY_HOME
                # Contenu identique, droits non conformes (ex. unités 0600 qui saturent le journal).
                return {**item, "state": "droits" if current_mode != item["mode"] else "identique"}
            item.update(state="remplacer", sha_before=before, mode_before=current_mode)
        else:
            item.update(state="creer", sha_before=None)
        if legacy and component != "systemd":
            # Déployer un fichier qui pointe vers l'ancienne copie la perpétuerait.
            return {**item, "state": "bloque", "reason": "source référençant l'ancien chemin " + LEGACY_HOME}
        if legacy:
            # Unités de base recopiées de la production : leur emplacement est remplacé par
            # les drop-ins 50-depot-reference.conf (plan de cohérence, étape 3).
            item["note"] = "unité de base référençant encore " + LEGACY_HOME
        return item

    @staticmethod
    def target_mode(component, source_path, data, physical):
        """0644 imposé pour les composants à droits fixes, sauf fichier portant un secret
        (Environment=...PASS/SECRET/TOKEN/KEY) dont les droits actuels sont conservés."""
        if component in FIXED_MODE:
            if physical.is_file() and SECRET_ENV.search(data):
                return physical.stat().st_mode & 0o7777
            return FIXED_MODE[component]
        if physical.is_file():
            return physical.stat().st_mode & 0o7777
        return 0o755 if source_path.stat().st_mode & 0o111 else 0o644

    def venv_spec(self, name):
        spec = VENVS[name]
        if "requirements" in spec:
            requirements = self.source / spec["requirements"]
            if not requirements.is_file():
                raise DeployError("fichier de dépendances absent : " + spec["requirements"])
            lines = sorted(line.strip() for line in requirements.read_text(encoding="utf-8").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
            install = ["-r", str(requirements)]
        else:
            raise DeployError("venv sans fichier de dépendances : " + name)
        fingerprint = sha256(json.dumps({"python": sys.version_info[:2], "requirements": lines}).encode())
        return fingerprint, install

    def venv_state(self, name):
        path = self.home / name / ".venv"
        fingerprint, _ = self.venv_spec(name)
        item = {"venv": name, "path": str(path), "component": "venvs", "fingerprint": fingerprint}
        if not (self.home / name).is_dir():
            return {**item, "state": "bloque", "reason": "répertoire absent du dépôt canonique " + str(self.home / name)}
        marker = path / ".omni-deploy.json"
        if path.is_symlink():
            return {**item, "state": "bloque", "reason": "venv en lien symbolique"}
        if not (path / "bin/python").exists():
            return {**item, "state": "construire", "reason": "venv absent"}
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8")).get("fingerprint")
        except (OSError, ValueError):
            recorded = None
        if recorded == fingerprint:
            return {**item, "state": "identique"}
        reason = "venv historique sans empreinte" if recorded is None else "dépendances modifiées"
        return {**item, "state": "reconstruire", "reason": reason + " (l'ancien venv est conservé pour le retour arrière)"}

    # ----------------------------------------------------------- unités systemd
    def units(self):
        """Unités du dépôt : type, texte rendu, et caractère long (non oneshot)."""
        result = {}
        directory = self.source / "deploye/systemd"
        for path in sorted(directory.glob("*.service")) + sorted(directory.glob("*.timer")):
            text = self.render(path.read_bytes()).decode("utf-8", errors="replace")
            for dropin in sorted((directory / (path.name + ".d")).glob("*.conf")):
                text += "\n" + self.render(dropin.read_bytes()).decode("utf-8", errors="replace")
            kind = re.search(r"(?m)^Type=(\S+)", text)
            result[path.name] = {"text": text, "long": path.suffix == ".service" and (kind is None or kind[1] != "oneshot")}
        return result

    def effective_exec(self, unit):
        """ExecStart effectif d'une unité du dépôt : unité de base puis drop-ins par ordre de nom,
        une ligne « ExecStart= » vide remettant la liste à zéro (sémantique systemd)."""
        directory = self.source / "deploye/systemd"
        files = [directory / unit] + sorted((directory / (unit + ".d")).glob("*.conf"))
        result = []
        for path in files:
            if not path.is_file():
                continue
            text = self.render(path.read_bytes()).decode("utf-8", errors="replace")
            for value in re.findall(r"(?m)^\s*ExecStart=(.*)$", text):
                if not value.strip():
                    result = []
                else:
                    result.extend(exec_paths("ExecStart=" + value))
        return result

    def restarts_for(self, changed_targets, rebuilt_venvs):
        units = self.units()
        restarts = set()
        for target in changed_targets:
            unit = unit_name(target)
            if unit and unit in units and (unit.endswith(".timer") or units[unit]["long"]):
                restarts.add(unit)
            if component_of(target) == "robots":
                restarts.update(name for name, info in units.items()
                                if info["long"] and re.search(re.escape(target) + r"(\s|$)", info["text"]))
        for venv in rebuilt_venvs:
            marker = str(self.home / venv / ".venv") + "/"
            restarts.update(name for name, info in units.items() if info["long"] and marker in info["text"])
        return sorted(restarts)

    # --------------------------------------------------------------------- plan
    def plan(self, components, pattern=None):
        components = self.normalize(components)
        files = [self.file_state(t, s, c) for t, s, c in self.entries(components)
                 if pattern is None or fnmatch.fnmatchcase(t, pattern)]
        venvs = [self.venv_state(name) for name in VENVS
                 if pattern is None or fnmatch.fnmatchcase(str(self.home / name / ".venv"), pattern)] if "venvs" in components else []
        blockers, warnings = [], []
        if "console" in components:
            try:
                self._console_module().check_assets(self.source / "mobile/soc")
            except (OSError, ValueError) as exc:
                blockers.append("console : " + str(exc))
        canonical = self.home.exists() and self.source == self.home.resolve()
        if not canonical:
            message = (f"le dépôt source {self.source} n'est pas le dépôt canonique {self.home} "
                       "(lancer l'outil depuis le dépôt canonique ou passer --home)")
            (blockers if self.system else warnings).append(message)
        for item in files + venvs:
            if item["state"] == "bloque":
                blockers.append((item.get("target") or item["path"]) + " : " + item["reason"])
        changed = self._changed(files)
        rebuilt = [item["venv"] for item in venvs if item["state"] in ("construire", "reconstruire")]
        actions = []
        touched = {item["component"] for item in changed}
        content = [item for item in changed if item["state"] != "droits"]
        if "systemd" in touched:
            actions.append("systemctl daemon-reload")
        if "nginx" in {item["component"] for item in content}:
            actions += ["nginx -t (échec : retour arrière automatique)", "systemctl reload nginx"]
        perms = [item for item in changed if item["state"] == "droits"]
        if perms:
            actions.append(f"chmod {len(perms)} fichier(s) à contenu identique vers 0644 (droits non conformes)")
        legacy = [item["target"] for item in files if item.get("note")]
        if legacy:
            warnings.append(f"{len(legacy)} fichier(s) identique(s) à la production référencent encore {LEGACY_HOME} "
                            "(neutralisés par les drop-ins 50-depot-reference.conf ou à migrer)")
        # Contrôle bloquant : l'exécutable de chaque ExecStart modifié doit exister après ce
        # déploiement (fichier présent, créé par ce plan, ou venv construit dans ce plan).
        created = {item["target"] for item in content}
        for unit in sorted({unit_name(item["target"]) for item in content if item["component"] == "systemd"} - {None}):
            for executable in self.effective_exec(unit):
                venv = re.fullmatch(re.escape(str(self.home)) + r"/([A-Za-z0-9_.-]+)/\.venv/bin/[^/]+", executable)
                if venv and venv[1] in rebuilt:
                    continue
                physical = Path(executable) if str(self.home) in executable else self.physical(executable)
                if executable not in created and not physical.exists() and not (not self.system and Path(executable).exists()):
                    hint = " (déployer d'abord le composant venvs)" if venv else ""
                    blockers.append(f"{unit} : exécutable {executable} absent{hint}")
        restarts = self.restarts_for([item["target"] for item in content], rebuilt)
        actions += ["systemctl restart " + unit + " (si actif)" for unit in restarts]
        new_units = sorted({unit_name(item["target"]) for item in changed
                            if item["state"] == "creer" and unit_name(item["target"])
                            and item["target"].count("/") == 4})
        if new_units:
            warnings.append("nouvelles unités non activées automatiquement : " + ", ".join(new_units))
        skipped = getattr(self, "module_skipped", [])
        if skipped:
            warnings.append(f"{len(skipped)} fichier(s) de modules inactifs sur ce site non posés : "
                            + ", ".join(sorted({s['module'] for s in skipped})))
        if getattr(self, "module_error", None):
            warnings.append("configuration de site illisible pour les modules : " + self.module_error)
        notes = [NOTES[c] for c in COMPONENTS if c in touched and c in NOTES]
        counts = {}
        for item in files + venvs:
            counts[item["state"]] = counts.get(item["state"], 0) + 1
        return {"mode": "plan", "source": str(self.source), "home": str(self.home), "root": str(self.root),
                "system": self.system, "components": components, "pattern": pattern, "counts": counts,
                "files": files, "venvs": venvs, "actions": actions, "restarts": restarts,
                "blockers": blockers, "warnings": warnings, "notes": notes,
                "module_skipped": getattr(self, "module_skipped", [])}

    @staticmethod
    def normalize(components):
        requested = list(components or ["all"])
        if "all" in requested:
            requested = [c for c in requested if c != "all"] + [c for c in COMPONENTS if c not in EXPLICIT_ONLY]
        unknown = [c for c in requested if c not in COMPONENTS]
        if unknown:
            raise DeployError("composant inconnu : " + ", ".join(unknown) + " (choix : all, " + ", ".join(COMPONENTS) + ")")
        return [c for c in COMPONENTS if c in requested]

    # ------------------------------------------------------------------ verrous
    @contextlib.contextmanager
    def lock(self):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state.is_symlink() or self.state.stat().st_mode & 0o077:
            raise DeployError(f"le répertoire d'état {self.state} doit être privé (chmod 700)")
        path = self.state / "deploy.lock"
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise DeployError("un déploiement est en cours ou a été interrompu : examiner " + str(path)) from None
        try:
            os.write(descriptor, str(os.getpid()).encode())
            os.close(descriptor)
            yield
        finally:
            path.unlink(missing_ok=True)

    def tx_dir(self, transaction):
        if not isinstance(transaction, str) or not TRANSACTION_RE.fullmatch(transaction):
            raise DeployError("identifiant de transaction invalide")
        return self.state / "transactions" / transaction

    def save(self, journal):
        directory = self.tx_dir(journal["id"])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_atomic(directory / "journal.json", (json.dumps(journal, indent=2, ensure_ascii=False) + "\n").encode(), 0o600)

    def load(self, transaction):
        path = self.tx_dir(transaction) / "journal.json"
        if not path.is_file() or path.is_symlink():
            raise DeployError("transaction introuvable : " + transaction)
        return json.loads(path.read_text(encoding="utf-8"))

    # ---------------------------------------------------------------- appliquer
    def apply(self, components, pattern=None):
        if self.system and os.geteuid() != 0:
            raise DeployError("l'application exige root")
        with self.lock():
            plan = self.plan(components, pattern)
            if plan["blockers"]:
                raise DeployError("déploiement refusé : " + " ; ".join(plan["blockers"][:10]))
            changed = self._changed(plan["files"])
            rebuild = [item for item in plan["venvs"] if item["state"] in ("construire", "reconstruire")]
            if not changed and not rebuild:
                return {**plan, "mode": "apply", "transaction": None, "result": "rien à déployer"}
            journal = {"schema_version": 1, "id": uuid.uuid4().hex, "created_at": now(), "status": "en_cours",
                       "source": plan["source"], "home": plan["home"], "root": plan["root"],
                       "components": plan["components"], "pattern": pattern, "files": [], "venvs": [], "restarts": plan["restarts"]}
            self.save(journal)
            self.emit("transaction " + journal["id"])
            try:
                for item in rebuild:
                    self._build_venv(journal, item)
                for item in changed:
                    self._install_file(journal, item)
                self._post_actions(journal, {i["component"] for i in changed}, plan["restarts"])
            except BaseException as exc:
                journal["status"] = "echec"
                journal["error"] = str(exc) if isinstance(exc, DeployError) else type(exc).__name__
                self.save(journal)
                self.emit("échec : retour arrière automatique de la transaction " + journal["id"])
                problems = self._restore(journal, force=True)
                journal["status"] = "annulee_automatiquement" if not problems else "annulation_incomplete"
                journal["rollback_problems"] = problems
                journal["finished_at"] = now()
                self.save(journal)
                raise DeployError(f"déploiement annulé ({journal['error']}) ; transaction {journal['id']} : "
                                  + ("état antérieur restauré" if not problems else "restauration incomplète, voir le journal")) from None
            journal["status"] = "appliquee"
            journal["finished_at"] = now()
            self.save(journal)
            return {**plan, "mode": "apply", "transaction": journal["id"], "result": "appliqué"}

    def _install_file(self, journal, item):
        target, physical = item["target"], self.physical(item["target"])
        data = self.render((self.source / item["source"]).read_bytes())
        record = {k: item[k] for k in ("target", "source", "component", "sha_before", "sha_after", "mode")}
        record.update(action=item["state"], backup=None, applied=False)
        mode = item["mode"]
        if physical.exists():
            status = physical.stat()
            if sha256(physical.read_bytes()) != item["sha_before"]:
                raise DeployError("la cible a changé depuis le plan : " + target)
            record.update(mode_before=status.st_mode & 0o7777, uid=status.st_uid, gid=status.st_gid)
            owner = (status.st_uid, status.st_gid)
            if item["state"] == "droits":
                journal["files"].append(record)
                self.save(journal)
                physical.chmod(mode)
                record["applied"] = True
                self.save(journal)
                self.emit(f"droits {oct(record['mode_before'])[2:]} -> {oct(mode)[2:]} : {target}")
                return
            backup = self.tx_dir(journal["id"]) / "backup" / target.lstrip("/")
            backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copy2(physical, backup)
            record["backup"] = str(backup.relative_to(self.tx_dir(journal["id"])))
        else:
            owner = None
            created = []
            parent = physical.parent
            while not parent.exists():
                created.append(parent)
                parent = parent.parent
            record["created_dirs"] = [str(p.relative_to(self.root)) for p in created]
            physical.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        journal["files"].append(record)
        self.save(journal)
        write_atomic(physical, data, mode, owner)
        record["applied"] = True
        self.save(journal)
        self.emit(("créé " if record["action"] == "creer" else "remplacé ") + target)

    def _changed(self, files):
        return [item for item in files if item["state"] in ("creer", "remplacer", "droits")]

    def _build_venv(self, journal, item):
        name = item["venv"]
        path = Path(item["path"])
        _, install = self.venv_spec(name)
        previous = path.with_name(".venv.prev-" + journal["id"][:12]) if path.exists() else None
        record = {"venv": name, "path": str(path), "previous": str(previous) if previous else None, "applied": False}
        journal["venvs"].append(record)
        self.save(journal)
        if previous:
            path.rename(previous)
        record["applied"] = True
        self.save(journal)
        for argv in (["python3", "-m", "venv", str(path)],
                     [str(path / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "-q", *install]):
            code, output = self.run_command(argv)
            if code:
                raise DeployError(f"construction du venv {name} en échec (code {code})")
        # Vérification avant tout repointage : interpréteur présent et dépendances cohérentes.
        code, _ = self.run_command([str(path / "bin/python"), "-m", "pip", "check", "--disable-pip-version-check"])
        if code:
            raise DeployError(f"venv {name} incohérent après construction (pip check)")
        if self.system and not (path / "bin/python").exists():
            raise DeployError(f"venv {name} : interpréteur absent après construction")
        if path.is_dir():
            write_atomic(path / ".omni-deploy.json", (json.dumps({"fingerprint": item["fingerprint"],
                         "transaction": journal["id"]}) + "\n").encode(), 0o644)
        self.emit("venv construit : " + str(path))

    def _systemctl_active(self, unit):
        code, output = self.run_command(["systemctl", "is-active", unit])
        return code == 0 and output.strip() == "active"

    def _post_actions(self, journal, touched, restarts, rollback=False):
        done = journal.setdefault("rollback_actions" if rollback else "actions", [])
        if "systemd" in touched:
            self._must(["systemctl", "daemon-reload"], done)
        if "nginx" in touched:
            self._must(["nginx", "-t"], done)
            self._must(["systemctl", "reload", "nginx"], done)
        was_active = journal.setdefault("was_active", [])
        for unit in restarts:
            if rollback:
                # Au retour arrière, un service en échec doit être relancé s'il tournait avant.
                if self.system and unit not in was_active:
                    continue
            elif self.system and not self._systemctl_active(unit):
                done.append("non redémarré (inactif) : " + unit)
                continue
            elif unit not in was_active:
                was_active.append(unit)
                self.save(journal)
            self._must(["systemctl", "restart", unit], done)
            if self.system and not self._settled_active(unit):
                raise DeployError("service inactif après redémarrage : " + unit)
        self.save(journal)

    def _settled_active(self, unit):
        """Actif immédiatement puis encore après un délai (un service qui plante au démarrage
        apparaît brièvement actif)."""
        if not self._systemctl_active(unit):
            return False
        time.sleep(SETTLE_SECONDS)
        return self._systemctl_active(unit)

    def _must(self, argv, done):
        code, _ = self.run_command(argv)
        done.append(" ".join(argv) + ("" if self.system else " (simulé)"))
        if code:
            raise DeployError("commande en échec : " + " ".join(argv))

    # ------------------------------------------------------------ retour arrière
    def rollback_plan(self, transaction, journal=None):
        journal = journal or self.load(transaction)
        if journal.get("root") != str(self.root):
            raise DeployError("la transaction concerne une autre racine : " + str(journal.get("root")))
        steps, conflicts = [], []
        for record in reversed(journal["files"]):
            physical = self.physical(record["target"])
            current = sha256(physical.read_bytes()) if physical.is_file() and not physical.is_symlink() else None
            if record["action"] == "droits":
                if current == record["sha_before"]:
                    steps.append({"target": record["target"], "operation": "restaurer_droits"})
                else:
                    conflicts.append(record["target"] + " : modifié depuis la transaction")
            elif current == record["sha_before"]:
                steps.append({"target": record["target"], "operation": "deja_restaure"})
            elif current == record["sha_after"]:
                steps.append({"target": record["target"], "operation": "restaurer" if record["backup"] else "supprimer"})
            else:
                conflicts.append(record["target"] + " : modifié depuis la transaction")
        for record in reversed(journal["venvs"]):
            if record.get("applied"):
                steps.append({"venv": record["venv"], "operation": "restaurer_venv" if record["previous"] else "supprimer_venv"})
        return {"transaction": journal["id"], "status": journal["status"], "steps": steps, "conflicts": conflicts,
                "restarts": journal.get("restarts", [])}

    def rollback(self, transaction, apply=False, force=False):
        journal = self.load(transaction)
        plan = self.rollback_plan(transaction, journal)
        if not apply:
            return {"mode": "plan", **plan}
        if self.system and os.geteuid() != 0:
            raise DeployError("le retour arrière exige root")
        if journal["status"] in ("restauree", "annulee_automatiquement"):
            raise DeployError("transaction déjà restaurée")
        if plan["conflicts"] and not force:
            raise DeployError("retour arrière refusé, fichiers modifiés depuis : " + " ; ".join(plan["conflicts"][:10]))
        with self.lock():
            problems = self._restore(journal, force=force)
            journal["status"] = "restauree" if not problems else "restauration_incomplete"
            journal["rollback_problems"] = problems
            journal["restored_at"] = now()
            self.save(journal)
        return {"mode": "apply", **plan, "problems": problems, "status": journal["status"]}

    def _restore(self, journal, force=False):
        problems = []
        directory = self.tx_dir(journal["id"])
        for record in reversed(journal["files"]):
            physical = self.physical(record["target"])
            current = sha256(physical.read_bytes()) if physical.is_file() and not physical.is_symlink() else None
            if record["action"] == "droits":
                if record.get("applied") and current == record["sha_before"]:
                    physical.chmod(record["mode_before"])
                    self.emit("droits restaurés " + record["target"])
                elif record.get("applied"):
                    problems.append(record["target"] + " : modifié depuis la transaction")
                continue
            if current == record["sha_before"]:
                continue
            if current != record["sha_after"] and not force:
                problems.append(record["target"] + " : modifié depuis la transaction")
                continue
            try:
                if record["backup"]:
                    owner = (record["uid"], record["gid"]) if "uid" in record else None
                    write_atomic(physical, (directory / record["backup"]).read_bytes(), record["mode_before"], owner)
                else:
                    physical.unlink(missing_ok=True)
                    for relative in record.get("created_dirs", []):
                        with contextlib.suppress(OSError):
                            (self.root / relative).rmdir()
                self.emit("restauré " + record["target"])
            except OSError as exc:
                problems.append(record["target"] + " : " + type(exc).__name__)
        for record in reversed(journal["venvs"]):
            if not record.get("applied"):
                continue
            path = Path(record["path"])
            try:
                if path.exists():
                    shutil.rmtree(path)
                if record["previous"] and Path(record["previous"]).exists():
                    Path(record["previous"]).rename(path)
                self.emit("venv restauré : " + str(path))
            except OSError as exc:
                problems.append(str(path) + " : " + type(exc).__name__)
        touched = {r["component"] for r in journal["files"]}
        restarts = journal.get("restarts", [])
        try:
            self._post_actions(journal, touched, restarts, rollback=True)
        except DeployError as exc:
            problems.append(str(exc))
        return problems

    def history(self, limit=30):
        directory = self.state / "transactions"
        if not directory.is_dir():
            return []
        result = []
        for path in directory.glob("*/journal.json"):
            if path.is_symlink():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            result.append({k: data.get(k) for k in ("id", "created_at", "status", "components", "finished_at", "restored_at")}
                          | {"files": len(data.get("files", [])), "venvs": len(data.get("venvs", []))})
        return sorted(result, key=lambda item: item["created_at"], reverse=True)[:limit]


def exec_paths(unit_text):
    """Exécutables des lignes ExecStart= non vides (préfixes systemd @-:+! retirés)."""
    paths = []
    for value in re.findall(r"(?m)^\s*ExecStart=(.*)$", unit_text):
        words = value.strip().split()
        if words:
            executable = words[0].lstrip("@-:+!")
            if executable.startswith("/"):
                paths.append(executable)
    return paths


def write_atomic(path: Path, data: bytes, mode: int, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".omni-deploy-", delete=False) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    try:
        temporary.chmod(mode)
        if owner and os.geteuid() == 0:
            os.chown(temporary, *owner)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
