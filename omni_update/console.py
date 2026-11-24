"""Mise à jour de l'environnement depuis la console SOC (« en un clic »).

Automatise la procédure manuelle suivie en production pour une mise à jour du dépôt
canonique (contrôle de l'arbre, git fetch, avance rapide, omni-deploy, publication de
la console, redémarrages ciblés, contrôle de santé) en réutilisant les briques
existantes :

- tools/omni-update.py : appels Git sans invite ni recopie de sortie, classement des
  échecs (authentication_required, network_unavailable...), contrôle de l'URL et de la
  référence, règles de « revue manuelle obligatoire » (CORE, requirements, verrous...) ;
- omni_deploy.engine.Deployer : plan et application transactionnelle des robots, des
  unités, des préférences APT et de la console, avec retour arrière par transaction ;
- omni_deploy.health : contrôle de santé de bout en bout (lecture seule) ;
- omni_update.system.System : accès en lecture à l'hôte (HTTP GET, disque) ;
- tools/omni-integrations.py : installation explicite d'un module d'intégration.

Trois points d'entrée, appelés par tools/omni-console-update.py :

- check : git fetch du remote attendu (jamais l'arbre de travail), plan, vérifications et
  tests hors ligne du candidat dans une copie temporaire ; publie status.json pour la console ;
- run_queue : exécute une demande transmise par l'exécuteur privilégié
  (omni-soc-admin-exec) : application avec retour arrière automatique, ou retour arrière
  manuel de la dernière mise à jour ; publie run.json à chaque étape ;
- status : état courant (lecture seule).

Ne modifie jamais 00-vars.env, /etc/default/*, ni un secret ; ne lance jamais de script
numéroté ; ne pousse jamais vers le remote.
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_deploy import engine as deploy_engine  # noqa: E402
from omni_deploy import health as deploy_health  # noqa: E402
from omni_update import stack as stack_mod  # noqa: E402
from omni_update.system import System, json_or_none  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_CONFIG = "/etc/default/omni-console-update"
DEFAULT_REPO = deploy_engine.DEFAULT_HOME
DEFAULT_STATE = "/var/lib/omni-console-update"
DEFAULT_ADMIN_DIR = "/var/lib/omni-mobile/admin"
SHA_RE = re.compile(r"[0-9a-f]{40}")
RUN_ID_RE = re.compile(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{8}")
MODULE_RE = re.compile(r"[a-z][a-z0-9_-]{0,40}")
UNIT_RE = re.compile(r"(omni|oms)-[A-Za-z0-9@._-]{1,80}\.service")
NUMBERED_RE = re.compile(r"[0-9]{2}-[^/]*\.sh")
DEPLOY_COMPONENTS = ["robots", "apt", "systemd"]
NOT_DEPLOYED = ("etc", "opt", "nginx", "logstash")
SELF_UNITS = ("omni-console-update", "omni-soc-admin-exec")
PROD_PREFIXES = ("/var/lib", "/etc", "/var/www", "/var/log", "/usr", "/opt/oms-", "/opt/omni-siem/repository")
LIST_CAP = 200
TESTS_MAX_AGE = 24 * 3600
STATUS_MAX_AGE = 24 * 3600
GiB = 1024 ** 3
FINAL_STATES = ("terminee", "terminee_avec_avertissements", "annulee", "annulation_incomplete", "refusee",
                "restauree", "restauration_incomplete", "echec")


class ConsoleUpdateError(RuntimeError):
    pass


def _load_updater():
    spec = importlib.util.spec_from_file_location("omni_update_cli", ROOT / "tools" / "omni-update.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OU = _load_updater()


def now_iso():
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


# ------------------------------------------------------------------ configuration
def load_config(path=None, environ=None):
    """Fichier KEY=VALUE (sans évaluation shell), surchargé par l'environnement."""
    environ = os.environ if environ is None else environ
    values = {}
    path = path or environ.get("OMNI_CONSOLE_UPDATE_CONFIG") or DEFAULT_CONFIG
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    for key, value in environ.items():
        if key.startswith("UPDATE_") or key == "SOC_ADMIN_DIR":
            values[key] = value

    def get(key, default):
        return values.get(key) or default

    repo = get("UPDATE_REPO", environ.get("OMNI_SIEM_HOME") or DEFAULT_REPO)
    cfg = {
        "repo": Path(repo),
        "branch": get("UPDATE_BRANCH", "main"),
        "remote_name": get("UPDATE_REMOTE_NAME", "origin"),
        "expected_remote": get("UPDATE_EXPECTED_REMOTE", OU.DEFAULT_REMOTE),
        "state": Path(get("UPDATE_STATE_DIR", DEFAULT_STATE)),
        "admin_dir": Path(get("SOC_ADMIN_DIR", DEFAULT_ADMIN_DIR)),
        "deploy_root": Path(get("UPDATE_DEPLOY_ROOT", "/")),
        "deploy_state": get("UPDATE_DEPLOY_STATE", ""),
        "systemctl": get("UPDATE_SYSTEMCTL", "systemctl"),
        "test_python": get("UPDATE_TEST_PYTHON", ""),
        "test_user": get("UPDATE_TEST_USER", "nobody"),
        "test_timeout": int(get("UPDATE_TEST_TIMEOUT", "1800")),
        "git_timeout": int(get("UPDATE_GIT_TIMEOUT", "300")),
        "restart_allow": get("UPDATE_RESTART_ALLOW", ""),
        "opensearch": get("UPDATE_OPENSEARCH", stack_mod.OPENSEARCH).rstrip("/"),
        "graylog_api": get("UPDATE_GRAYLOG_API", stack_mod.GRAYLOG_API).rstrip("/"),
        "backup_glob": get("UPDATE_BACKUP_GLOB", stack_mod.CONFIG_BACKUP_GLOB),
        "integration_api": get("UPDATE_INTEGRATION_API", ""),
        "integration_ca": get("UPDATE_INTEGRATION_CA", ""),
        "integration_bind": get("UPDATE_INTEGRATION_BIND", ""),
        "integration_token_file": get("UPDATE_GRAYLOG_TOKEN_FILE", ""),
        "console_config": Path(get("UPDATE_CONSOLE_CONFIG", "/etc/default/omni-mobile")),
        "nginx_site": Path(get("UPDATE_NGINX_SITE", "/etc/nginx/sites-enabled/graylog")),
        "settle_seconds": float(get("UPDATE_SETTLE_SECONDS", "5")),
        "min_free": {"/": 2 * GiB, "/var": 1 * GiB},
    }
    if get("UPDATE_DISK_PATHS", ""):
        cfg["min_free"] = {p: 1 * GiB for p in get("UPDATE_DISK_PATHS", "").split(",") if p}
    validate_config(cfg, environ)
    return cfg


def validate_config(cfg, environ=None):
    environ = os.environ if environ is None else environ
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,60}", cfg["remote_name"]):
        raise ConsoleUpdateError("UPDATE_REMOTE_NAME invalide")
    OU.validate_ref(cfg["branch"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", cfg["branch"]):
        raise ConsoleUpdateError("UPDATE_BRANCH invalide")
    try:
        OU.validate_remote(cfg["expected_remote"])
    except OU.UpdateError:
        raise ConsoleUpdateError("UPDATE_EXPECTED_REMOTE doit être une URL HTTPS sans identifiant") from None
    for key in ("repo", "state", "admin_dir", "deploy_root", "console_config", "nginx_site"):
        path = cfg[key]
        if not path.is_absolute() or ".." in path.parts:
            raise ConsoleUpdateError(key + " doit être un chemin absolu normalisé")
    if cfg["test_user"] and not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", cfg["test_user"]):
        raise ConsoleUpdateError("UPDATE_TEST_USER invalide")
    if environ.get("OMNI_TEST_MODE") == "1":
        bad = [k for k in ("repo", "state", "admin_dir") if str(os.path.realpath(cfg[k])).startswith(PROD_PREFIXES)]
        if cfg["deploy_root"] == Path("/"):
            bad.append("deploy_root")
        if bad:
            raise ConsoleUpdateError("OMNI_TEST_MODE=1 : chemin de production refusé : " + ", ".join(bad))


def publish_dir(cfg):
    return cfg["admin_dir"] / "update"


# ------------------------------------------------------------------ fichiers
def write_json(path, data, mode=0o600, owner_of=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, prefix=".tmp-", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    try:
        temporary.chmod(mode)
        if owner_of is not None and os.geteuid() == 0:
            with contextlib.suppress(OSError):
                st = os.stat(owner_of)
                os.chown(temporary, st.st_uid, st.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def publish(cfg, name, data):
    """Copie lisible par le backend (répertoire partagé, propriétaire du répertoire admin)."""
    directory = publish_dir(cfg)
    # Répertoire inscriptible par le backend confiné : jamais de lien symbolique suivi (root écrit ici).
    for path in (cfg["admin_dir"], directory):
        if path.is_symlink():
            raise ConsoleUpdateError("répertoire de publication en lien symbolique : refusé")
    directory.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        with contextlib.suppress(OSError):
            st = os.stat(cfg["admin_dir"])
            os.chown(directory, st.st_uid, st.st_gid)
            directory.chmod(0o750)
    write_json(directory / name, data, 0o640, owner_of=cfg["admin_dir"])


# ------------------------------------------------------------------ Git
def git(cfg, *args, check=True, timeout=None, binary=False):
    return OU.git(cfg["repo"], *args, check=check, timeout=timeout or cfg["git_timeout"], binary=binary)


def rev(cfg, name):
    return OU.resolve(cfg["repo"], name)


def upstream_ref(cfg):
    return f"refs/remotes/{cfg['remote_name']}/{cfg['branch']}"


def credential_problems(cfg):
    """URL du remote différente de l'attendue, identifiants dans la configuration Git."""
    problems = []
    configured = git(cfg, "config", "--get", f"remote.{cfg['remote_name']}.url", check=False)
    url = ""
    if configured == 0:
        url = git(cfg, "config", "--get", f"remote.{cfg['remote_name']}.url")
    if url.rstrip("/") != cfg["expected_remote"].rstrip("/"):
        problems.append(f"le remote {cfg['remote_name']} ne pointe pas vers l'URL attendue (UPDATE_EXPECTED_REMOTE) : "
                        "un remote modifié localement ne peut pas servir de source")
    raw = OU.git(cfg["repo"], "config", "--get-regexp", r"^url\.", check=False)
    if raw == 0:
        listing = git(cfg, "config", "--get-regexp", r"^url\.")
        for line in listing.splitlines():
            key = line.split(" ", 1)[0]
            base = key[4:].rsplit(".", 1)[0]
            parts = urlsplit(base)
            if parts.password or (parts.scheme in ("http", "https") and parts.username):
                problems.append("identifiants dans une règle url.*.insteadOf de la configuration Git : refusé "
                                "(ne jamais placer de jeton dans une URL)")
                break
    return problems


def fetch(cfg):
    """git fetch du remote attendu, branche suivie uniquement ; l'arbre de travail n'est pas touché."""
    env_ssh = "GIT_SSH_COMMAND" in os.environ
    if not env_ssh:
        os.environ["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes -o ConnectTimeout=30"
    try:
        git(cfg, "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=60", "-c", "credential.interactive=false",
            "fetch", "--no-tags", "--no-recurse-submodules", "--", cfg["expected_remote"],
            f"+refs/heads/{cfg['branch']}:{upstream_ref(cfg)}")
    finally:
        if not env_ssh:
            os.environ.pop("GIT_SSH_COMMAND", None)
    return rev(cfg, upstream_ref(cfg))


def is_ancestor(cfg, older, newer):
    return git(cfg, "merge-base", "--is-ancestor", older, newer, check=False) == 0


def tree_state(cfg):
    raw = git(cfg, "status", "--porcelain=v1", "-z", "--untracked-files=normal", binary=True)
    tracked, untracked = [], []
    for item in raw.decode("utf-8", "replace").split("\0"):
        if not item:
            continue
        (untracked if item.startswith("??") else tracked).append(item[3:])
    return tracked, untracked


def commits(cfg, base, target):
    out = git(cfg, "log", "--no-merges", f"--max-count={LIST_CAP}", "--format=%H%x1f%an%x1f%aI%x1f%s", f"{base}..{target}")
    rows = []
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 4:
            rows.append({"sha": parts[0], "short": parts[0][:12], "author": parts[1][:80], "date": parts[2],
                         "subject": parts[3][:200]})
    return rows


def changelog_excerpt(cfg, base, target, limit=80):
    out = git(cfg, "diff", "-U0", "--no-color", base, target, "--", "CHANGELOG.md")
    lines = [line[1:] for line in out.splitlines() if line.startswith("+") and not line.startswith("+++")]
    return lines[:limit]


def changed_files(cfg, base, target):
    raw = git(cfg, "diff", "--name-status", "-z", "--no-renames", base, target, binary=True)
    parts = raw.decode("utf-8", "replace").split("\0")
    result = []
    for index in range(0, len(parts) - 1, 2):
        if parts[index]:
            result.append((parts[index][:1], parts[index + 1]))
    return result


def extract(cfg, target, destination):
    """Copie du candidat (fichiers suivis uniquement) via git archive, sans lien symbolique."""
    raw = git(cfg, "archive", "--format=tar", target, binary=True)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive:
            name = member.name.rstrip("/")
            if not name or name.startswith("/") or ".." in PurePosixPath(name).parts:
                raise ConsoleUpdateError("archive du candidat : chemin dangereux")
            path = destination / name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise ConsoleUpdateError("le candidat contient un lien symbolique ou un sous-module : refusé")


# ------------------------------------------------------------------ classement
def manual_review(path):
    """Mêmes règles que omni-update.py (migration_review_required) + préférences APT."""
    name = PurePosixPath(path).name
    return (path in OU.CORE or path.startswith(("migrations/", "docker/migrations/", "deploye/apt/", "python-locks/"))
            or name in {"pyproject.toml", "poetry.lock", "uv.lock"} or bool(re.fullmatch(r"requirements[^/]*\.txt", name))
            or name.startswith("Dockerfile"))


def classify(changes, manifest_sources):
    cats = {k: [] for k in ("code", "robots", "unites", "console", "scripts_numerotes", "revue_manuelle",
                            "non_deployes", "integrations", "documentation_tests", "autres")}
    for status, path in changes:
        component = manifest_sources.get(path)
        label = path if status != "D" else path + " (supprimé)"
        if manual_review(path):
            cats["revue_manuelle"].append(label)
        elif NUMBERED_RE.fullmatch(path):
            cats["scripts_numerotes"].append(label)
        elif component == "robots":
            cats["robots"].append(label)
        elif component == "systemd" or path.startswith("deploye/systemd/"):
            cats["unites"].append(label)
        elif component in NOT_DEPLOYED:
            cats["non_deployes"].append(label)
        elif path.startswith(("mobile/soc/", "mobile/www/")):
            cats["console"].append(label)
        elif path.startswith("integrations/"):
            cats["integrations"].append(label)
        elif path.startswith(("docs/", "tests/")) or "/tests/" in path or path.endswith(".md"):
            cats["documentation_tests"].append(label)
        elif path.endswith((".py", ".sh")) or "/" in path and not path.startswith("deploye/"):
            cats["code"].append(label)
        else:
            cats["autres"].append(label)
    return {k: v[:LIST_CAP] for k, v in cats.items()}


def service_restarts(units, home, changes):
    """Services longs dont le code exécuté vit dans un répertoire du dépôt modifié."""
    projects = {}
    pattern = re.compile(re.escape(str(home).rstrip("/")) + r"/([A-Za-z0-9_.-]+)(/|\s|$)")
    for name, info in units.items():
        if not info["long"] or not UNIT_RE.fullmatch(name):
            continue
        dirs = {m.group(1) for m in pattern.finditer(info["text"])}
        if dirs:
            projects[name] = dirs
    touched = set()
    for _, path in changes:
        parts = PurePosixPath(path).parts
        if len(parts) < 2 or "tests" in parts or path.endswith(".md"):
            continue
        touched.add(parts[0])
    return sorted(name for name, dirs in projects.items() if dirs & touched)


class PreviewDeployer(deploy_engine.Deployer):
    """Plan sur la copie du candidat sans exécuter son code : le module de publication de la
    console (tools/deploy-console.py) est chargé depuis la révision installée, pas du candidat."""

    def _console_module(self):
        path = self.home / "tools/deploy-console.py"
        spec = importlib.util.spec_from_file_location("omni_console_update_deploy_console", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


# ------------------------------------------------------------------ outil principal
class ConsoleUpdater:
    def __init__(self, cfg, system=None, health=None, sleep=time.sleep):
        self.cfg = cfg
        self.system = system or System()
        self.health_fn = health or self._health
        self.sleep = sleep

    # --------------------------------------------------------------- sondes
    def _health(self):
        config = deploy_health.load_site_config(self.cfg["repo"] / "00-vars.env")
        return deploy_health.summarize(deploy_health.evaluate(config, self.cfg["repo"]))

    def systemctl(self, *args, timeout=120):
        try:
            process = subprocess.run([self.cfg["systemctl"], *args], capture_output=True, text=True, timeout=timeout,
                                     stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, type(exc).__name__
        return process.returncode, (process.stdout or "").strip()

    def units_in_state(self, state):
        code, out = self.systemctl("list-units", "--all", "--plain", "--no-legend", "--no-pager", f"--state={state}",
                                   "omni-*", "oms-*", "siem-*")
        if code != 0 and not out:
            return None
        names = [line.split()[0] for line in out.splitlines() if line.strip()]
        return [n for n in names if not n.startswith(SELF_UNITS)]

    def is_active(self, unit):
        code, out = self.systemctl("is-active", unit)
        return code == 0 and out == "active"

    def deployer(self, source, emit=None, preview=False):
        state = self.cfg["deploy_state"] or None
        cls = PreviewDeployer if preview else deploy_engine.Deployer
        return cls(source, home=self.cfg["repo"], root=str(self.cfg["deploy_root"]), state_dir=state, emit=emit)

    def restart_allow(self, units):
        value = self.cfg["restart_allow"].strip()
        if value == "aucun":
            return set()
        if value:
            return {u.strip() for u in value.split(",") if UNIT_RE.fullmatch(u.strip())}
        return {name for name, info in units.items() if info["long"] and UNIT_RE.fullmatch(name)}

    def console_profile_problems(self, changes):
        """Do not publish to a different runtime or web root and claim alignment.

        Paths are read from the actual installed service/site, never from the
        candidate's unit templates. Nonstandard profiles require explicit
        publication; no configuration or local customization is changed here.
        """
        paths = {path for _, path in changes}
        backend_changed = bool(paths & {"mobile/omni-mobile-api.py", "tools/omni-soc-kpi.py"})
        assets_changed = any(p.startswith(("mobile/soc/", "mobile/www/")) for p in paths)
        if not (backend_changed or assets_changed):
            return []
        physical = self.deployer(self.cfg["repo"]).physical
        problems = []
        config = self.system.read(physical(str(self.cfg["console_config"])))
        values = {}
        for line in (config or "").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
        if config is None:
            problems.append("configuration console illisible : publication manuelle requise")
        elif values.get("MOBILE_PORT", "8090") != "8090":
            problems.append("MOBILE_PORT différent de 8090 : sondes de publication non adaptées, publication manuelle requise")
        if backend_changed:
            code, executable = self.systemctl("show", "omni-mobile-api.service", "-p", "ExecStart", "--value")
            expected = str(self.cfg["repo"] / "mobile/omni-mobile-api.py")
            if code or not re.search(re.escape(expected) + r"(?=[\s;\"}]|$)", executable):
                problems.append("backend console exécuté hors du dépôt canonique (copie gérée ou chemin personnalisé) : "
                                "publication explicite du backend et de ses outils requise")
        if assets_changed:
            site = self.system.read(physical(str(self.cfg["nginx_site"])))
            if site is None:
                problems.append("site nginx console illisible : publication manuelle requise")
            else:
                for route, expected in (("soc", "/var/www/siem-soc"), ("m", "/var/www/siem-mobile")):
                    blocks = re.findall(r"location\s+(?:\^~\s+)?/" + route + r"/\s*\{([^{}]*)\}", site)
                    aliases = [re.search(r"\balias\s+([^;]+);", block) for block in blocks]
                    if len(aliases) != 1 or aliases[0] is None or aliases[0][1].strip().strip('"').rstrip("/") != expected:
                        problems.append("racine nginx /" + route + "/ personnalisée ou indéterminée : "
                                        "la publication automatique vise " + expected + ", publication manuelle requise")
        return problems

    # --------------------------------------------------------------- verrous
    @contextlib.contextmanager
    def flock(self, name):
        self.cfg["state"].mkdir(mode=0o700, parents=True, exist_ok=True)
        handle = open(self.cfg["state"] / name, "a+")
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ConsoleUpdateError("une mise à jour ou un retour arrière est déjà en cours (verrou " + name + ")") from None
            handle.seek(0)
            handle.truncate()
            handle.write(str(os.getpid()))
            handle.flush()
            yield
        finally:
            handle.close()

    def update_locked(self):
        path = self.cfg["state"] / "update.lock"
        if not path.exists():
            return False
        with open(path, "a+") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return False

    def last_run(self):
        run = read_json(self.cfg["state"] / "run.json")
        if isinstance(run, dict) and run.get("status") == "en_cours" and not self.update_locked():
            run["status"] = "interrompue"
        return run

    # --------------------------------------------------------------- tests
    def test_python(self):
        if self.cfg["test_python"]:
            return self.cfg["test_python"]
        for candidate in ("oms-ml/.venv/bin/python", ".venv/bin/python", "mobile/.venv/bin/python"):
            path = self.cfg["repo"] / candidate
            if path.exists():
                return str(path)
        return shutil.which("python3") or "python3"

    def run_tests(self, target, directory):
        cache = self.cfg["state"] / "tests" / (target + ".json")
        started = time.time()
        python = self.test_python()
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(directory / ".home"),
               "OMNI_TEST_PYTHON": python, "PYTHONDONTWRITEBYTECODE": "1"}
        (directory / ".home").mkdir(exist_ok=True)
        argv = ["bash", str(directory / "run-tests.sh")]
        if os.geteuid() == 0 and self.cfg["test_user"] != "aucun":
            import pwd
            try:
                account = pwd.getpwnam(self.cfg["test_user"])
            except KeyError:
                raise ConsoleUpdateError("compte d'exécution des tests introuvable (UPDATE_TEST_USER)") from None
            for base, dirs, files in os.walk(directory):
                for name in dirs + files:
                    os.lchown(os.path.join(base, name), account.pw_uid, account.pw_gid)
            os.chown(directory, account.pw_uid, account.pw_gid)
            if directory.parent.name.startswith("omni-console-update-"):
                os.chown(directory.parent, account.pw_uid, account.pw_gid)
            argv = ["setpriv", f"--reuid={account.pw_uid}", f"--regid={account.pw_gid}", "--clear-groups", "--"] + argv
        try:
            process = subprocess.Popen(argv, cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                output, _ = process.communicate(timeout=self.cfg["test_timeout"])
                code = process.returncode
            except subprocess.TimeoutExpired:
                with contextlib.suppress(OSError):
                    os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
                code = 124
        except OSError as exc:
            output, code = ("lancement impossible : " + type(exc).__name__).encode(), 127
        text = output.decode("utf-8", "replace").splitlines()
        result = {"target": target, "status": "ok" if code == 0 else ("delai_depasse" if code == 124 else "echec"),
                  "code": code, "at": now_iso(), "ts": time.time(), "duration_s": round(time.time() - started),
                  "python": python, "tail": [line[:300] for line in text[-40:]]}
        write_json(cache, result)
        return result

    def cached_tests(self, target):
        data = read_json(self.cfg["state"] / "tests" / (target + ".json"))
        if isinstance(data, dict) and data.get("target") == target and time.time() - float(data.get("ts", 0)) < TESTS_MAX_AGE:
            return data
        return None

    # --------------------------------------------------------------- modules
    def integration_token(self):
        path = self.cfg["integration_token_file"]
        if not path:
            return ""
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def modules(self, candidate_dir):
        try:
            data = json.loads((candidate_dir / "integrations" / "catalog.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        from omni_integrations.core import stable_id
        jeton = self.integration_token()
        api = self.cfg["integration_api"].rstrip("/")
        configured = bool(jeton and api and self.cfg["integration_bind"])
        result = []
        for item in data.get("modules", [])[:20]:
            ident = str(item.get("id", ""))
            if not MODULE_RE.fullmatch(ident):
                continue
            manifest = read_json(candidate_dir / "integrations" / ident / "manifest.json", {}) or {}
            entry = {"id": ident, "name": str(manifest.get("name", ident))[:80], "revision": manifest.get("revision"),
                     "default_port": manifest.get("default_port"), "installed": None, "installed_revision": None,
                     "installable": False}
            if jeton and api:
                headers = {"Authorization": "Basic " + base64.b64encode((jeton + ":" + "token").encode()).decode(),
                           "Accept": "application/json", "X-Requested-By": "omni-console-update"}
                status, body = self.system.http_get(f"{api}/system/content_packs/{stable_id(ident, 'pack')}/installations",
                                                    headers=headers)
                installs = (json_or_none(body) or {}).get("installations") if status == 200 else None
                if isinstance(installs, list):
                    entry["installed"] = bool(installs)
                    if installs:
                        entry["installed_revision"] = max(int(i.get("content_pack_revision", 0) or 0) for i in installs)
            if entry["installed"] is None:
                entry["detail"] = "état inconnu : jeton Graylog de lecture non configuré ou API injoignable"
            elif entry["installed"]:
                entry["detail"] = (f"installé (révision {entry['installed_revision']})"
                                   + (" : nouvelle révision disponible, migration préparée requise (non proposée ici)"
                                      if entry["installed_revision"] != entry["revision"] else ""))
            elif not configured:
                entry["detail"] = ("non installé ; installation depuis la console non configurée "
                                   "(UPDATE_GRAYLOG_TOKEN_FILE, UPDATE_INTEGRATION_API, UPDATE_INTEGRATION_BIND)")
            else:
                entry["installable"] = True
                entry["detail"] = (f"non installé ; installable (port UDP {entry['default_port']}, "
                                   f"écoute {self.cfg['integration_bind']}) après la mise à jour du code")
            result.append(entry)
        return result

    # --------------------------------------------------------------- plan
    def plan(self, target, *, run_tests=True, force_tests=False, fetched=None, holding_lock=False):
        """Plan et vérifications, en lecture seule (aucune modification de l'arbre ni du système)."""
        cfg = self.cfg
        checks = []

        def add(ident, label, ok, detail, level="bloquant"):
            checks.append({"id": ident, "label": label, "level": level,
                           "status": "ok" if ok else ("echec" if level == "bloquant" else level), "detail": detail})

        head = rev(cfg, "HEAD")
        branch = git(cfg, "symbolic-ref", "-q", "HEAD", check=False)
        branch_name = git(cfg, "symbolic-ref", "-q", "HEAD") if branch == 0 else ""
        report = {"schema_version": SCHEMA_VERSION, "generated_at": now_iso(), "generated_ts": time.time(),
                  "host": self.system.hostname(), "repository": str(cfg["repo"]), "branch": cfg["branch"],
                  "remote": cfg["expected_remote"], "installed": self.describe(head), "available": None,
                  "update_available": False, "fetch": fetched or {"ok": None}, "checks": checks}
        add("branche", "Branche " + cfg["branch"] + " extraite", branch_name == "refs/heads/" + cfg["branch"],
            "HEAD sur " + (branch_name.removeprefix("refs/heads/") or "aucune branche (HEAD détaché)"))
        for problem in credential_problems(cfg):
            add("remote", "Remote attendu, sans identifiant", False, problem)
        if not any(c["id"] == "remote" for c in checks):
            add("remote", "Remote attendu, sans identifiant", True, cfg["expected_remote"])
        tracked, untracked = tree_state(cfg)
        add("arbre", "Arbre de travail propre", not tracked,
            "aucune modification suivie" if not tracked else f"{len(tracked)} fichier(s) suivi(s) modifié(s) : "
            + ", ".join(tracked[:8]))
        if untracked:
            add("non_suivis", "Fichiers non suivis", False, f"{len(untracked)} fichier(s) non suivi(s) (conservés)",
                "avertissement")
        running = False if holding_lock else self.update_locked()
        add("verrou", "Aucune mise à jour en cours", not running, "verrou détenu par cette exécution" if holding_lock
            else ("verrou libre" if not running else "verrou détenu"))
        last = None if holding_lock else self.last_run()
        interrupted = isinstance(last, dict) and last.get("status") == "interrompue"
        add("interrompue", "Pas de mise à jour interrompue", not interrupted,
            "aucune" if not interrupted else f"mise à jour {last.get('id')} interrompue : lancer le retour arrière")
        if not target:
            report["can_apply"] = False
            report["blocking"] = [c["detail"] for c in checks if c["status"] == "echec"] + ["révision disponible inconnue"]
            return report
        report["available"] = self.describe(target)
        if target == head:
            add("a_jour", "Mise à jour disponible", False, "la révision installée est déjà la dernière de "
                + cfg["branch"], "info")
            report["can_apply"] = False
            report["blocking"] = ["aucune mise à jour disponible"]
            report["dynamic"] = False
            return report
        ff = is_ancestor(cfg, head, target)
        add("avance_rapide", "Avance rapide possible (candidat descendant de la révision installée)", ff,
            "oui" if ff else "historique divergent : la révision installée n'est pas un ancêtre du candidat "
            "(réécriture d'historique ou commit local) ; mise à jour en un clic refusée")
        try:
            on_branch = is_ancestor(cfg, target, upstream_ref(cfg))
        except OU.UpdateError:
            on_branch = False
        add("sur_branche", f"Candidat présent sur {cfg['branch']} du remote attendu", on_branch,
            "oui" if on_branch else "révision absente de " + upstream_ref(cfg))
        if not ff:
            report["can_apply"] = False
            report["blocking"] = [c["detail"] for c in checks if c["status"] == "echec"]
            return report
        report["update_available"] = True
        changes = changed_files(cfg, head, target)
        report["commits"] = commits(cfg, head, target)
        report["commit_count"] = int(git(cfg, "rev-list", "--count", f"{head}..{target}") or 0)
        report["changelog"] = changelog_excerpt(cfg, head, target)
        added = {p for s, p in changes if s == "A"}
        collision = sorted(added & set(untracked))
        if collision:
            add("collision", "Aucun fichier non suivi écrasé", False, "le candidat ajoute des fichiers présents non suivis : "
                + ", ".join(collision[:8]))
        # --- copie du candidat : plan omni-deploy puis tests hors ligne
        with tempfile.TemporaryDirectory(prefix="omni-console-update-") as temporary:
            candidate = Path(temporary) / "candidat"
            candidate.mkdir()
            extract(cfg, target, candidate)
            entries, errors = deploy_engine.parse_manifest((candidate / deploy_engine.MANIFEST).read_text(encoding="utf-8"))
            sources = {s: deploy_engine.component_of(t) for t, s in entries}
            cats = classify(changes, sources)
            report["changes"] = {"total": len(changes), "categories": cats}
            add("manifeste", "Manifeste du candidat valide", not errors, "; ".join(errors[:3]) or "valide")
            add("revue_manuelle", "Aucun changement exigeant une revue manuelle", not cats["revue_manuelle"],
                "aucun" if not cats["revue_manuelle"] else
                "pile, dépendances, verrous Python ou migrations modifiés : appliquer à la main selon docs/UPDATES.md ("
                + ", ".join(cats["revue_manuelle"][:6]) + ")")
            if cats["scripts_numerotes"]:
                add("scripts", "Scripts numérotés modifiés", False, "jamais lancés automatiquement ; à examiner et lancer "
                    "explicitement si nécessaire : " + ", ".join(cats["scripts_numerotes"][:10]), "avertissement")
            if cats["non_deployes"]:
                add("non_deployes", "Composants non déployés par la mise à jour en un clic", False,
                    "etc, opt, nginx, logstash : déploiement manuel (omni-deploy.py) : " + ", ".join(cats["non_deployes"][:8]),
                    "avertissement")
            if any(p.startswith("00-vars.env.example") for p in sum(cats.values(), [])):
                add("variables", "Nouvelles variables de configuration possibles", False,
                    "00-vars.env.example modifié : comparer avec 00-vars.env (jamais modifié automatiquement)", "avertissement")
            profile_problems = self.console_profile_problems(changes)
            add("profil_console", "Profil de publication de la console compatible", not profile_problems,
                "; ".join(profile_problems) or "chemins du service, port et racines web compatibles")
            deploy = self.deploy_preview(candidate, changes, cats)
            report["deploy"] = deploy
            add("plan_deploiement", "Plan omni-deploy sans blocage", not deploy["blockers"],
                "; ".join(deploy["blockers"][:5]) or f"{len(deploy['files'])} fichier(s) à déployer")
            if deploy["drift"]:
                add("ecarts", "Écarts préexistants entre production et dépôt", False,
                    f"{len(deploy['drift'])} fichier(s) de production différent(s) du dépôt seront remplacés "
                    "(sauvegardés dans la transaction) : " + ", ".join(deploy["drift"][:6]), "avertissement")
            units = self.deployer(candidate, preview=True).units()
            restarts = sorted(set(service_restarts(units, cfg["repo"], changes)) | set(deploy["restarts"]))
            allow = self.restart_allow(units)
            report["restarts"] = [u for u in restarts if u in allow]
            report["restarts_manual"] = [u for u in restarts if u not in allow]
            if report["restarts_manual"]:
                add("redemarrages", "Redémarrages hors liste blanche", False, "à redémarrer manuellement : "
                    + ", ".join(report["restarts_manual"]), "avertissement")
            report["options"] = {
                "console": {"available": bool(cats["console"]), "default": bool(cats["console"]),
                            "detail": f"{len(cats['console'])} fichier(s) de la console modifié(s)" if cats["console"]
                            else "console inchangée"},
                "restart": {"available": bool(report["restarts"]), "default": True,
                            "detail": ", ".join(report["restarts"]) or "aucun service à redémarrer"},
                "modules": self.modules(candidate)}
            tests = self.cached_tests(target)
            if run_tests and (force_tests or tests is None):
                tests = self.run_tests(target, candidate)
            report["tests"] = tests or {"status": "non_executee"}
            status = (tests or {}).get("status")
            add("tests", "Suite de tests hors ligne verte sur le candidat (copie temporaire)", status == "ok",
                {"ok": f"verte ({tests.get('duration_s')} s, {tests.get('at')})" if tests else "",
                 None: "non exécutée", "echec": "en échec : voir l'extrait", "delai_depasse": "délai dépassé"}.get(status, str(status)))
        self.dynamic_checks(add)
        report["dynamic"] = True
        report["blocking"] = [c["label"] + " : " + c["detail"] for c in checks if c["status"] == "echec"]
        report["can_apply"] = not report["blocking"]
        return report

    def deploy_preview(self, candidate, changes, cats):
        result = {"files": [], "drift": [], "blockers": [], "warnings": [], "restarts": [], "console_files": 0}
        changed_paths = {p for _, p in changes}
        try:
            plans = [self.deployer(candidate, preview=True).plan(DEPLOY_COMPONENTS)]
            if cats["console"]:
                plans.append(self.deployer(candidate, preview=True).plan(["console"]))
        except (deploy_engine.DeployError, OSError, ValueError) as exc:
            result["blockers"].append("plan omni-deploy impossible : " + str(exc)[:200])
            return result
        for plan in plans:
            # Le contrôle « dépôt canonique » est refait à l'application, une fois la fusion faite.
            result["blockers"] += [b for b in plan["blockers"] if not b.startswith("le dépôt source ")]
            result["warnings"] += [w for w in plan["warnings"] if not w.startswith("le dépôt source ")]
            result["restarts"] += plan["restarts"]
            for item in plan["files"]:
                if item["state"] in ("creer", "remplacer", "droits"):
                    if item["component"] == "console":
                        result["console_files"] += 1
                        continue
                    result["files"].append(f"{item['target']} ({item['state']})")
                    if item["component"] == "apt":
                        result["blockers"].append("préférences APT à modifier (" + item["target"] + ") : revue manuelle")
                    elif item["source"] not in changed_paths and item["state"] != "droits":
                        result["drift"].append(item["target"])
        result["files"] = result["files"][:LIST_CAP]
        result["restarts"] = sorted(set(result["restarts"]))
        return result

    def dynamic_checks(self, add):
        cfg = self.cfg
        activating = self.units_in_state("activating")
        add("activation", "Aucune unité omni-/oms- en cours de démarrage", activating == [],
            "aucune" if activating == [] else ("systemctl indisponible" if activating is None else ", ".join(activating[:10])))
        failed = self.units_in_state("failed") or []
        if failed:
            add("echecs", "Unités en échec avant mise à jour", False, ", ".join(failed[:10]), "avertissement")
        status, body = self.system.http_get(cfg["opensearch"] + "/_cluster/health", timeout=10)
        color = (json_or_none(body) or {}).get("status")
        add("opensearch", "OpenSearch vert", color == "green", "cluster " + str(color or "injoignable"))
        status, _ = self.system.http_get(cfg["graylog_api"] + "/system/lbstatus", timeout=10)
        add("graylog", "API Graylog joignable", status == 200, "lbstatus HTTP " + str(status))
        archives = [(self.system.mtime(p), p) for p in self.system.glob(cfg["backup_glob"])]
        archives = [a for a in archives if a[0]]
        code, result = self.systemctl("show", "omni-backup-config.service", "-p", "Result", "--value")
        if archives:
            mtime, path = max(archives)
            age = (self.system.now() - mtime) / 3600
            ok = age <= stack_mod.BACKUP_MAX_AGE_HOURS and result == "success"
            detail = "%s, %.1f h, dernier passage omni-backup-config : %s" % (Path(path).name, age, result or "inconnu")
        else:
            ok, detail = False, "aucune archive " + cfg["backup_glob"]
        add("sauvegarde", "Sauvegarde de configuration vérifiée de moins de 26 h", ok, detail)
        for path, minimum in cfg["min_free"].items():
            usage = self.system.disk_free(path)
            free = usage["free"] if usage else 0
            add("disque:" + path, "Espace disque " + path, free >= minimum,
                "%.1f Gio libres (minimum %.0f Gio)" % (free / GiB, minimum / GiB))

    def describe(self, revision):
        out = git(self.cfg, "log", "-1", "--format=%H%x1f%aI%x1f%s", revision)
        parts = out.split("\x1f")
        return {"rev": parts[0], "short": parts[0][:12], "date": parts[1] if len(parts) > 1 else "",
                "subject": parts[2][:200] if len(parts) > 2 else ""}

    # --------------------------------------------------------------- check
    def check(self, *, do_fetch=True, run_tests=True, force_tests=False):
        cfg = self.cfg
        with self.flock("check.lock"):
            if self.update_locked():
                status = read_json(cfg["state"] / "status.json", {}) or {}
                status["note"] = "mise à jour en cours : recherche différée"
                return status
            fetched = {"ok": None, "at": now_iso()}
            target = None
            if do_fetch:
                problems = credential_problems(cfg)
                if problems:
                    fetched.update(ok=False, error="remote_refuse", detail=problems[0])
                else:
                    try:
                        target = fetch(cfg)
                        fetched.update(ok=True)
                    except OU.UpdateError as exc:
                        match = re.search(r"\(([a-z_]+)", str(exc))
                        fetched.update(ok=False, error=match.group(1) if match else "git_error", detail=str(exc)[:200])
            if target is None:
                try:
                    target = rev(cfg, upstream_ref(cfg))
                except OU.UpdateError:
                    target = None
            report = self.plan(target, run_tests=run_tests, force_tests=force_tests, fetched=fetched)
            last = self.last_run()
            if isinstance(last, dict) and last.get("status") == "interrompue":
                publish(cfg, "run.json", last)
                if last.get("kind") == "apply" and last.get("prev_rev"):
                    write_json(cfg["state"] / "last_apply.json", last)
                    publish(cfg, "last_apply.json", last)
            report["last_run"] = summary(last)
            write_json(cfg["state"] / "status.json", report)
            publish(cfg, "status.json", report)
            return report

    # --------------------------------------------------------------- file d'attente
    def queue_dir(self):
        return self.cfg["state"] / "queue"

    def run_queue(self):
        queue = self.queue_dir()
        queue.mkdir(mode=0o700, parents=True, exist_ok=True)
        results = []
        for path in sorted(queue.glob("*.json"))[:5]:
            job = read_json(path)
            done = queue / "done"
            done.mkdir(mode=0o700, exist_ok=True)
            os.replace(path, done / path.name)
            try:
                job = self.validate_job(job)
            except ConsoleUpdateError as exc:
                results.append({"id": path.stem, "status": "refusee", "result": str(exc)})
                run = {"id": path.stem[:40], "kind": "inconnu", "status": "refusee", "result": str(exc),
                       "started_at": now_iso(), "finished_at": now_iso(), "steps": []}
                publish(self.cfg, "run.json", run)
                continue
            if job["kind"] == "update_apply":
                results.append(self.apply(job))
            else:
                results.append(self.rollback(job))
        return results

    def validate_job(self, job):
        if not isinstance(job, dict):
            raise ConsoleUpdateError("demande illisible")
        rid, kind, params = str(job.get("id", "")), job.get("kind"), job.get("params")
        if not RUN_ID_RE.fullmatch(rid) or kind not in ("update_apply", "update_rollback") or not isinstance(params, dict):
            raise ConsoleUpdateError("demande invalide")
        request = read_json(self.cfg["admin_dir"] / "requests" / (rid + ".json"))
        if not isinstance(request, dict) or request.get("action") != kind or request.get("params") != params:
            raise ConsoleUpdateError("demande d'origine absente ou différente")
        if request.get("status") != "transmise" or request.get("self_service") is not True or not request.get("requested_by") \
                or str(request.get("decided_by", "")).lower() != str(request.get("requested_by", "")).lower():
            raise ConsoleUpdateError("demande d'origine non confirmée")
        if kind == "update_apply":
            target = str(params.get("target", ""))
            modules = params.get("modules", [])
            if not SHA_RE.fullmatch(target) or params.get("confirm") != target[:12] or params.get("plan_read") is not True:
                raise ConsoleUpdateError("révision cible ou confirmation invalide")
            if not isinstance(modules, list) or len(modules) > 10 or not all(isinstance(m, str) and MODULE_RE.fullmatch(m) for m in modules):
                raise ConsoleUpdateError("liste de modules invalide")
            if not isinstance(params.get("console"), bool) or not isinstance(params.get("restart"), bool):
                raise ConsoleUpdateError("options invalides")
        else:
            if not RUN_ID_RE.fullmatch(str(params.get("run_id", ""))) or not re.fullmatch(r"[0-9a-f]{12}", str(params.get("confirm", ""))):
                raise ConsoleUpdateError("retour arrière : paramètres invalides")
        return {"id": rid, "kind": kind, "params": params, "actor": str(request.get("requested_by"))[:64],
                "motif": str(request.get("motif", ""))[:300]}

    # --------------------------------------------------------------- journal d'exécution
    def _save(self, run):
        write_json(self.cfg["state"] / "runs" / (run["id"] + ".json"), run)
        write_json(self.cfg["state"] / "run.json", run)
        publish(self.cfg, "run.json", run)
        # Dernière mise à jour effective (hors refus) : seule candidate au retour arrière manuel,
        # même si une tentative refusée (sans modification) l'a suivie.
        if run.get("kind") == "apply" and run.get("status") != "refusee" and run.get("prev_rev"):
            write_json(self.cfg["state"] / "last_apply.json", run)
            publish(self.cfg, "last_apply.json", run)

    def _step(self, run, ident, label):
        step = {"id": ident, "label": label, "status": "en_cours", "started": now_iso(), "detail": ""}
        run["steps"].append(step)
        self._save(run)
        return step

    def _end(self, run, step, status="ok", detail=""):
        step.update(status=status, finished=now_iso(), detail=str(detail)[:600])
        self._save(run)

    # --------------------------------------------------------------- application
    def apply(self, job):
        cfg = self.cfg
        params = job["params"]
        target = params["target"]
        run = {"schema_version": SCHEMA_VERSION, "id": job["id"], "kind": "apply", "status": "en_cours",
               "target": target, "options": {k: params[k] for k in ("console", "restart", "modules")},
               "requested_by": job["actor"], "motif": job["motif"], "started_at": now_iso(), "steps": [],
               "deploy_transactions": [], "restarted": [], "modules_result": [], "prev_rev": None}
        try:
            lock = self.flock("update.lock")
            lock.__enter__()
        except ConsoleUpdateError as exc:
            run.update(status="refusee", result=str(exc), finished_at=now_iso())
            publish(cfg, "run.json", run)
            return summary(run)
        try:
            return self._apply_locked(run, params, target)
        finally:
            lock.__exit__(None, None, None)
            with contextlib.suppress(Exception):
                self.check(do_fetch=False, run_tests=False)

    def _apply_locked(self, run, params, target):
        cfg = self.cfg
        self._save(run)
        step = self._step(run, "recherche", "Récupération de " + cfg["branch"] + " sur le remote attendu")
        try:
            problems = credential_problems(cfg)
            if problems:
                raise ConsoleUpdateError(problems[0])
            fetch(cfg)
            self._end(run, step)
        except (OU.UpdateError, ConsoleUpdateError) as exc:
            self._end(run, step, "echec", exc)
            return self._finish(run, "refusee", "récupération impossible : " + str(exc))
        step = self._step(run, "verifications", "Plan et vérifications préalables (dont tests hors ligne)")
        try:
            plan = self.plan(target, run_tests=True, holding_lock=True)
        except (OU.UpdateError, ConsoleUpdateError, deploy_engine.DeployError, OSError) as exc:
            self._end(run, step, "echec", exc)
            return self._finish(run, "refusee", "plan impossible : " + str(exc)[:300])
        run["plan_summary"] = {k: plan.get(k) for k in ("restarts", "restarts_manual", "blocking")}
        if not plan.get("can_apply"):
            self._end(run, step, "echec", "; ".join(plan.get("blocking", []))[:600])
            return self._finish(run, "refusee", "vérifications bloquantes : aucune modification effectuée")
        installable = {m["id"] for m in plan["options"]["modules"] if m.get("installable")}
        bad = [m for m in params["modules"] if m not in installable]
        if bad:
            self._end(run, step, "echec", "modules non installables : " + ", ".join(bad))
            return self._finish(run, "refusee", "option de module refusée : aucune modification effectuée")
        self._end(run, step, "ok", f"{len([c for c in plan['checks'] if c['status'] == 'ok'])} contrôle(s) au vert")
        # ---------------------------------------------------- sauvegarde
        step = self._step(run, "sauvegarde", "Sauvegarde de la révision et de l'état de santé")
        # Les unités dont un fichier déployé change sont déjà redémarrées par omni-deploy (si actives).
        by_deploy = set(plan.get("deploy", {}).get("restarts", []))
        restarts = [u for u in plan["restarts"] if u not in by_deploy] if params["restart"] else []
        try:
            head = rev(cfg, "HEAD")
            git(cfg, "update-ref", "refs/omni-console-update/avant-" + run["id"], head)
            run["prev_rev"] = head
            run["health_before"] = health_digest(self.health_fn())
            run["failed_before"] = self.units_in_state("failed") or []
            run["was_active"] = [u for u in restarts if self.is_active(u)]
        except Exception as exc:  # rien n'est encore modifié : refus simple
            self._end(run, step, "echec", type(exc).__name__)
            return self._finish(run, "refusee", "sauvegarde préalable impossible : aucune modification effectuée")
        self._end(run, step, "ok", "révision " + head[:12] + " conservée (refs/omni-console-update/avant-" + run["id"] + ")")
        try:
            step = self._step(run, "fusion", "Avance rapide vers " + target[:12] + " (git merge --ff-only)")
            git(cfg, "merge", "--ff-only", "--no-edit", target)
            if rev(cfg, "HEAD") != target:
                raise ConsoleUpdateError("HEAD différent de la cible après fusion")
            run["merged"] = True
            self._end(run, step)
            step = self._step(run, "deploiement", "Déploiement des robots, unités et préférences APT (omni-deploy)")
            report = self.deployer(cfg["repo"], emit=lambda line: None).apply(DEPLOY_COMPONENTS)
            if report.get("transaction"):
                run["deploy_transactions"].append(report["transaction"])
            self._end(run, step, "ok", report.get("result", "") + (" ; transaction " + report["transaction"]
                                                                   if report.get("transaction") else ""))
            if params["console"] and plan["options"]["console"]["available"]:
                step = self._step(run, "console", "Publication de la console (omni-deploy, composant console)")
                report = self.deployer(cfg["repo"]).apply(["console"])
                if report.get("transaction"):
                    run["deploy_transactions"].append(report["transaction"])
                self._end(run, step, "ok", report.get("result", ""))
            if restarts:
                step = self._step(run, "redemarrages", "Redémarrage des services dont le code a changé")
                for unit in restarts:
                    if unit not in run["was_active"]:
                        continue
                    code, _ = self.systemctl("restart", "--", unit, timeout=180)
                    run["restarted"].append(unit)
                    self._save(run)
                    if code != 0 or not self.settled(unit):
                        raise ConsoleUpdateError("service inactif après redémarrage : " + unit)
                self._end(run, step, "ok", ", ".join(run["restarted"]) or "aucun service actif concerné")
            step = self._step(run, "sante", "Contrôle de santé final (omni-healthcheck, unités en échec)")
            after = self.health_fn()
            regressions = health_regressions(run["health_before"], after)
            failed_now = self.units_in_state("failed") or []
            new_failed = sorted(set(failed_now) - set(run["failed_before"]))
            run["health_after"] = health_digest(after)
            if regressions or new_failed:
                raise ConsoleUpdateError("régression détectée : " + ", ".join(regressions + new_failed)[:400])
            self._end(run, step, "ok", "aucune régression ({} contrôle(s))".format(len(after.get("checks", []))))
        except BaseException as exc:
            if step.get("status") == "en_cours":
                self._end(run, step, "echec", exc if isinstance(exc, (ConsoleUpdateError, OU.UpdateError,
                                                                      deploy_engine.DeployError)) else type(exc).__name__)
            problems = self._restore(run)
            return self._finish(run, "annulee" if not problems else "annulation_incomplete",
                                ("retour arrière automatique effectué" if not problems else
                                 "retour arrière incomplet : " + "; ".join(problems)[:400])
                                + " (cause : " + str(step.get("detail") or type(exc).__name__)[:200] + ")")
        status, note = "terminee", "mise à jour appliquée"
        for module in params["modules"]:
            step = self._step(run, "module:" + module, "Installation du module " + module)
            ok, detail = self.install_module(module)
            run["modules_result"].append({"id": module, "ok": ok, "detail": detail})
            self._end(run, step, "ok" if ok else "echec", detail)
            if not ok:
                status, note = "terminee_avec_avertissements", ("mise à jour appliquée ; installation de module en échec "
                                                                 "(non annulée automatiquement, voir docs/INTEGRATIONS-MODULAIRES.md)")
        run["rollback_available"] = True
        return self._finish(run, status, note)

    def settled(self, unit):
        if not self.is_active(unit):
            return False
        self.sleep(self.cfg["settle_seconds"])
        return self.is_active(unit)

    def install_module(self, module):
        jeton = self.integration_token()
        if not (jeton and self.cfg["integration_api"] and self.cfg["integration_bind"]):
            return False, "installation non configurée"
        manifest = read_json(self.cfg["repo"] / "integrations" / module / "manifest.json", {}) or {}
        port = manifest.get("default_port")
        if not isinstance(port, int):
            return False, "manifeste du module illisible"
        argv = [sys.executable, str(self.cfg["repo"] / "tools" / "omni-integrations.py"), "install", module,
                "--api", self.cfg["integration_api"], "--bind", self.cfg["integration_bind"], "--port", str(port), "--apply"]
        if self.cfg["integration_ca"]:
            argv += ["--ca", self.cfg["integration_ca"]]
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "GRAYLOG_API_TOKEN": jeton}
        try:
            process = subprocess.run(argv, capture_output=True, text=True, timeout=900, env=env, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, "échec : " + type(exc).__name__
        if process.returncode:
            return False, "échec (code %d) : %s" % (process.returncode, (process.stderr or "").strip().replace(jeton, "***")[-300:])
        data = json_or_none(process.stdout) or {}
        return True, "{} (révision {})".format(data.get("action", "installé"), data.get("revision", "?"))

    # --------------------------------------------------------------- retour arrière
    def _restore(self, run):
        problems = []
        steps = []
        for transaction in reversed(run.get("deploy_transactions", [])):
            step = self._step(run, "rb:deploiement", "Retour arrière de la transaction omni-deploy " + transaction)
            try:
                result = self.deployer(self.cfg["repo"]).rollback(transaction, apply=True, force=True)
                detail = result.get("status", "")
                if result.get("problems"):
                    problems += result["problems"]
                    self._end(run, step, "echec", "; ".join(result["problems"])[:400])
                else:
                    self._end(run, step, "ok", detail)
            except (deploy_engine.DeployError, OSError, ValueError) as exc:
                message = str(exc)
                if "déjà restaurée" in message:
                    self._end(run, step, "ok", "déjà restaurée")
                else:
                    problems.append("transaction " + transaction + " : " + message[:200])
                    self._end(run, step, "echec", message)
            steps.append(step)
        prev = run.get("prev_rev")
        if prev:
            step = self._step(run, "rb:git", "Retour de la révision à " + prev[:12] + " (git reset --keep)")
            try:
                if rev(self.cfg, "HEAD") != prev:
                    git(self.cfg, "reset", "--keep", prev)
                if rev(self.cfg, "HEAD") != prev:
                    raise ConsoleUpdateError("HEAD différent de la révision sauvegardée")
                self._end(run, step, "ok", "HEAD = " + prev[:12])
            except (OU.UpdateError, ConsoleUpdateError) as exc:
                problems.append("git : " + str(exc)[:200])
                self._end(run, step, "echec", exc)
        restarted = [u for u in run.get("restarted", []) if u in run.get("was_active", [])]
        if restarted:
            step = self._step(run, "rb:redemarrages", "Redémarrage des services sur l'ancienne révision")
            bad = []
            for unit in restarted:
                code, _ = self.systemctl("restart", "--", unit, timeout=180)
                if code != 0 or not self.settled(unit):
                    bad.append(unit)
            if bad:
                problems.append("services inactifs après retour arrière : " + ", ".join(bad))
            self._end(run, step, "echec" if bad else "ok", ", ".join(bad) or ", ".join(restarted))
        step = self._step(run, "rb:sante", "Contrôle de santé après retour arrière")
        try:
            after = self.health_fn()
            regressions = health_regressions(run.get("health_before") or {}, after) if run.get("health_before") else []
            self._end(run, step, "ok" if not regressions else "avertissement",
                      "aucune régression" if not regressions else "encore en échec : " + ", ".join(regressions))
        except Exception as exc:  # le contrôle ne doit pas masquer le résultat du retour arrière
            self._end(run, step, "avertissement", type(exc).__name__)
        return problems

    def rollback(self, job):
        cfg = self.cfg
        params = job["params"]
        run = {"schema_version": SCHEMA_VERSION, "id": job["id"], "kind": "rollback", "status": "en_cours",
               "requested_by": job["actor"], "motif": job["motif"], "started_at": now_iso(), "steps": [],
               "of_run": params["run_id"]}
        try:
            lock = self.flock("update.lock")
            lock.__enter__()
        except ConsoleUpdateError as exc:
            run.update(status="refusee", result=str(exc), finished_at=now_iso())
            publish(cfg, "run.json", run)
            return summary(run)
        try:
            original = read_json(cfg["state"] / "runs" / (params["run_id"] + ".json"))
            last = read_json(cfg["state"] / "last_apply.json")
            reason = rollback_refusal(cfg, original, last, params)
            if reason:
                run.update(status="refusee", result=reason, finished_at=now_iso())
                publish(cfg, "run.json", run)
                write_json(cfg["state"] / "runs" / (run["id"] + ".json"), run)
                return summary(run)
            self._save(run)
            step = self._step(run, "verifications", "Vérifications avant retour arrière")
            tracked, _ = tree_state(cfg)
            head = rev(cfg, "HEAD")
            if tracked or head not in (original.get("target"), original.get("prev_rev")):
                self._end(run, step, "echec", "arbre modifié ou révision inattendue")
                return self._finish(run, "refusee", "retour arrière refusé : arbre modifié ou révision changée depuis la mise à jour")
            run["health_before"] = health_digest(self.health_fn())
            self._end(run, step)
            run.update(deploy_transactions=original.get("deploy_transactions", []), prev_rev=original.get("prev_rev"),
                       restarted=original.get("restarted", []), was_active=original.get("was_active", []))
            problems = self._restore(run)
            original["status"] = "restauree" if not problems else "restauration_incomplete"
            original["rollback_available"] = False
            write_json(cfg["state"] / "runs" / (original["id"] + ".json"), original)
            write_json(cfg["state"] / "last_apply.json", original)
            publish(cfg, "last_apply.json", original)
            return self._finish(run, "restauree" if not problems else "restauration_incomplete",
                                "révision " + str(original.get("prev_rev"))[:12] + " restaurée" if not problems else
                                "; ".join(problems)[:400])
        finally:
            lock.__exit__(None, None, None)
            with contextlib.suppress(Exception):
                self.check(do_fetch=False, run_tests=False)

    def _finish(self, run, status, note):
        run.update(status=status, result=note, finished_at=now_iso())
        self._save(run)
        return summary(run)


def rollback_refusal(cfg, original, last, params):
    if not isinstance(original, dict) or original.get("kind") != "apply":
        return "mise à jour d'origine introuvable"
    if not isinstance(last, dict) or last.get("id") != original.get("id"):
        return "seule la dernière mise à jour peut être annulée"
    status = original.get("status")
    if status == "en_cours":
        status = "interrompue"
    if status not in ("terminee", "terminee_avec_avertissements", "interrompue"):
        return "mise à jour dans l'état « " + str(status) + " » : retour arrière sans objet"
    if not original.get("prev_rev") or params.get("confirm") != str(original.get("prev_rev"))[:12]:
        return "confirmation différente de la révision à restaurer"
    return ""


def health_digest(report):
    return {c["name"]: c["status"] for c in (report or {}).get("checks", []) if isinstance(c, dict) and "name" in c}


def health_regressions(before, after):
    now = health_digest(after) if "checks" in (after or {}) else after
    return sorted(name for name, status in now.items() if status == "echec" and before.get(name, "ok") != "echec")


def summary(run):
    if not isinstance(run, dict):
        return None
    return {k: run.get(k) for k in ("id", "kind", "status", "target", "prev_rev", "started_at", "finished_at", "result",
                                    "requested_by", "rollback_available")}


def status(cfg):
    updater = ConsoleUpdater(cfg)
    return {"status": read_json(cfg["state"] / "status.json"), "run": updater.last_run(),
            "locked": updater.update_locked()}
