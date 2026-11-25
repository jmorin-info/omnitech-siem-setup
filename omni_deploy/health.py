"""Contrôle de santé de bout en bout, en lecture seule, réutilisable après une
installation, un déploiement ou un redémarrage.

Aucune écriture : systemctl is-active/is-enabled, ss, GET HTTP. Les secrets lus
dans 00-vars.env servent uniquement à l'authentification et ne sont jamais
affichés. Chaque contrôle est « critique » (échec = verdict KO) ou « avertissement ».
"""
from __future__ import annotations

import base64
import datetime as dt
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
from urllib.parse import urlsplit

CORE_SERVICES = ("mongod", "opensearch", "graylog-server", "nginx", "omni-mobile-api")
CORE_PORTS = {443: "nginx HTTPS", 9000: "API Graylog", 9200: "OpenSearch", 27017: "MongoDB", 8090: "backend console"}
DISK_WARN, DISK_FAIL = 85, 95
DEFAULT_API_CA = "/etc/graylog/certs/omnitech-rootca.crt"
LEGACY_HOME = "/root/omnitech-siem-setup"


class Probes:
    """Accès système en lecture seule ; remplaçable dans les tests."""

    graylog_conf = Path("/etc/graylog/server/server.conf")

    def command(self, argv, timeout=20):
        try:
            process = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return 127, ""
        return process.returncode, process.stdout

    def unit(self, unit):
        _, active = self.command(["systemctl", "is-active", unit])
        _, enabled = self.command(["systemctl", "is-enabled", unit])
        return active.strip() or "unknown", enabled.strip() or "unknown"

    def failed_units(self):
        code, output = self.command(["systemctl", "list-units", "--failed", "--plain", "--no-legend",
                                     "omni-*", "oms-*", "siem-*"])
        return [line.split()[0] for line in output.splitlines() if line.strip()] if code == 0 else []

    def listening(self):
        code, output = self.command(["ss", "-Hltn"])
        ports = set()
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and ":" in fields[3]:
                port = fields[3].rsplit(":", 1)[1]
                if port.isdigit():
                    ports.add(int(port))
        return ports if code == 0 else None

    def http(self, url, *, headers=None, ca=None, server_name=None, verify=True, timeout=10):
        """GET ; renvoie (statut, corps). Ne suit pas les redirections."""
        target = urlsplit(url)
        path = (target.path or "/") + ("?" + target.query if target.query else "")
        if target.scheme == "https":
            if verify:
                context = ssl.create_default_context()  # autorités du système, plus la CA du site si fournie
                if ca:
                    context.load_verify_locations(ca)
            else:
                context = ssl._create_unverified_context()
            connection = _HTTPS(target.hostname, target.port or 443, server_name=server_name or target.hostname,
                                context=context, timeout=timeout)
        else:
            connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=timeout)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read(4 * 1024 * 1024)
        finally:
            connection.close()

    def legacy_references(self, legacy, roots=("/etc/systemd/system", "/usr/local/sbin")):
        """Fichiers en service qui référencent encore l'ancien emplacement du dépôt."""
        found = []
        for root in roots:
            for path in sorted(Path(root).rglob("*")):
                if "__pycache__" in path.parts:
                    continue
                try:
                    if path.is_file() and not path.is_symlink() and path.stat().st_size < 4 * 1024 * 1024 \
                            and legacy.encode() in path.read_bytes():
                        found.append(str(path))
                except OSError:
                    continue
        return found

    def disk(self, path):
        usage = shutil.disk_usage(path)
        return round(100 * usage.used / usage.total, 1)


class _HTTPS(http.client.HTTPSConnection):
    """Connexion à une adresse locale en vérifiant le certificat pour le FQDN servi."""

    def __init__(self, host, port, *, server_name, context, timeout):
        super().__init__(host, port, context=context, timeout=timeout)
        self._server_name = server_name
        self._ctx = context

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self._server_name)


def repo_units(source: Path):
    """Services longs et timers versionnés dans deploye/systemd."""
    directory = source / "deploye/systemd"
    services, timers = [], []
    for path in sorted(directory.glob("*.service")):
        text = path.read_text(encoding="utf-8", errors="replace")
        kind = re.search(r"(?m)^Type=(\S+)", text)
        if (kind is None or kind[1] != "oneshot") and path.stem not in CORE_SERVICES:
            services.append(path.name)
    timers = [path.name for path in sorted(directory.glob("*.timer"))]
    return services, timers


def graylog_api(config, graylog_conf=Path("/etc/graylog/server/server.conf")):
    api = (config.get("GRAYLOG_API_URL") or "").rstrip("/")
    # Même défaut que omni_api_setup (lib-platform.sh).
    ca = config.get("GRAYLOG_API_CA") or DEFAULT_API_CA
    if api and urlsplit(api).path in ("", "/"):
        api += "/api"  # l'API REST de Graylog est servie sous /api
    if not api:
        tls = False
        try:
            tls = re.search(r"(?m)^http_enable_tls\s*=\s*true\s*$", graylog_conf.read_text()) is not None
        except OSError:
            pass
        api = f"https://{config.get('SIEM_FQDN', 'localhost')}:9000/api" if tls else "http://127.0.0.1:9000/api"
    return api, (existing_ca(ca) if api.startswith("https:") else None)


def existing_ca(path):
    """An unreadable parent directory must not abort an entire health report."""
    try:
        return path if path and Path(path).is_file() else None
    except OSError:
        return None


def evaluate(config, source: Path, probes: Probes | None = None):
    probes = probes or Probes()
    checks = []

    def add(name, level, passed, detail=""):
        checks.append({"name": name, "level": level, "status": "ok" if passed else ("echec" if level == "critique" else "avertissement"),
                       "detail": detail})

    def guarded(name, level, operation):
        try:
            operation()
        except Exception as exc:  # une sonde ne doit jamais interrompre le bilan ni divulguer une réponse
            add(name, level, False, "sonde en erreur : " + type(exc).__name__)

    # 1. Services du socle et services longs maison
    for unit in CORE_SERVICES:
        active, _ = probes.unit(unit)
        add("service:" + unit, "critique", active == "active", active)
    services, timers = repo_units(source)
    for unit in services:
        active, enabled = probes.unit(unit)
        if enabled in ("enabled", "static", "alias"):
            add("service:" + unit, "critique", active == "active", f"{active} ({enabled})")
        else:
            add("service:" + unit, "info", True, f"non activé ({enabled}) : non contrôlé")
    # 2. Timers des robots : un timer activé mais arrêté signifie un robot qui ne tourne plus
    inactive_timers, controlled = [], 0
    for unit in timers:
        active, enabled = probes.unit(unit)
        if enabled == "enabled":
            controlled += 1
            if active != "active":
                inactive_timers.append(unit)
    add("timers", "critique", not inactive_timers,
        f"{controlled - len(inactive_timers)}/{controlled} timers activés en marche"
        + (" ; arrêtés : " + ", ".join(inactive_timers) if inactive_timers else ""))
    failed = probes.failed_units()
    add("unites-en-echec", "avertissement", not failed, ", ".join(failed) if failed else "aucune unité omni-/oms-/siem- en échec")
    # 3. Ports d'écoute
    ports = probes.listening()
    if ports is None:
        add("ports", "avertissement", False, "ss indisponible")
    else:
        missing = [f"{port} ({label})" for port, label in CORE_PORTS.items() if port not in ports]
        add("ports", "critique", not missing, "manquants : " + ", ".join(missing) if missing else
            "en écoute : " + ", ".join(str(p) for p in CORE_PORTS))

    # 4. OpenSearch
    def opensearch():
        status, body = probes.http("http://127.0.0.1:9200/_cluster/health")
        color = json.loads(body).get("status") if status == 200 else f"HTTP {status}"
        add("opensearch:sante", "critique", color in ("green", "yellow"), str(color))
    guarded("opensearch:sante", "critique", opensearch)

    # 5. API Graylog : vivacité sans authentification, puis cycle de vie et inputs
    api, ca = graylog_api(config, probes.graylog_conf)
    server_name = urlsplit(api).hostname

    def graylog_get(path, auth=True, accept="application/json"):
        headers = {"Accept": accept, "X-Requested-By": "omni-healthcheck"}
        token, password = config.get("GRAYLOG_API_TOKEN"), config.get("GRAYLOG_ADMIN_PASS")
        if auth and token:
            headers["Authorization"] = "Basic " + base64.b64encode((token + ":token").encode()).decode()
        elif auth and password:
            headers["Authorization"] = "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
        elif auth:
            raise PermissionError("aucun identifiant Graylog disponible")
        return probes.http(api + path, headers=headers, ca=ca, server_name=server_name)

    def graylog_alive():
        status, body = graylog_get("/system/lbstatus", auth=False, accept="text/plain")
        add("graylog:lbstatus", "critique", status == 200, body.decode(errors="replace").strip()[:20] if status == 200 else f"HTTP {status}")
    guarded("graylog:lbstatus", "critique", graylog_alive)

    def graylog_system():
        status, body = graylog_get("/system")
        if status != 200:
            add("graylog:systeme", "critique", False, f"HTTP {status}")
            return
        data = json.loads(body)
        add("graylog:systeme", "critique", data.get("lifecycle") == "running",
            f"lifecycle={data.get('lifecycle')} version={str(data.get('version', '?')).split('+')[0]}")
    guarded("graylog:systeme", "critique", graylog_system)

    def graylog_inputs():
        status, body = graylog_get("/system/inputs")
        status_states, states = graylog_get("/system/inputstates")
        if status != 200 or status_states != 200:
            add("graylog:inputs", "critique", False, f"HTTP {status}/{status_states}")
            return
        configured = {item["id"]: item.get("title", item["id"]) for item in json.loads(body).get("inputs", [])}
        running = {item.get("id") for item in json.loads(states).get("states", []) if item.get("state") == "RUNNING"}
        stopped = [configured[i] for i in configured if i not in running]
        add("graylog:inputs", "critique", bool(configured) and not stopped,
            f"{len(configured) - len(stopped)}/{len(configured)} RUNNING" + (" ; arrêtés : " + ", ".join(sorted(stopped)[:8]) if stopped else ""))
    guarded("graylog:inputs", "critique", graylog_inputs)

    # 6. Console : backend local puis page /soc/ servie par nginx
    def backend():
        status, body = probes.http("http://127.0.0.1:8090/m/api/vapid")
        add("console:backend", "critique", status == 200 and "publicKey" in json.loads(body), f"HTTP {status}")
    guarded("console:backend", "critique", backend)

    def console_page():
        fqdn = config.get("SIEM_FQDN") or "localhost"
        ca_console = config.get("GRAYLOG_API_CA") or DEFAULT_API_CA
        ca_console = existing_ca(ca_console)
        try:
            status, _ = probes.http("https://127.0.0.1/soc/", headers={"Host": fqdn}, server_name=fqdn,
                                    ca=ca_console)
            add("console:/soc/", "critique", status == 200, f"HTTP {status}, certificat vérifié pour {fqdn}")
        except ssl.SSLError:
            status, _ = probes.http("https://127.0.0.1/soc/", headers={"Host": fqdn}, server_name=fqdn, verify=False)
            add("console:/soc/", "critique", status == 200, f"HTTP {status}")
            add("console:certificat", "avertissement", False, f"certificat non approuvé par cette machine pour {fqdn}")
    guarded("console:/soc/", "critique", console_page)

    # 7. Migration vers le dépôt canonique
    def legacy():
        found = probes.legacy_references(LEGACY_HOME)
        add("chemin-canonique", "avertissement", not found,
            f"{len(found)} fichier(s) en service référencent encore {LEGACY_HOME} (voir docs/DEPLOYMENT.md, migration)"
            if found else "aucune référence à l'ancien emplacement " + LEGACY_HOME)
    guarded("chemin-canonique", "avertissement", legacy)

    # 8. Espace disque
    for label, path in (("/", "/"), ("DATA_MOUNT", config.get("DATA_MOUNT")), ("BACKUP_DIR", config.get("BACKUP_DIR"))):
        if not path or not Path(path).is_dir():
            continue
        def disk(label=label, path=path):
            used = probes.disk(path)
            level = "critique" if used >= DISK_FAIL else "avertissement"
            add("disque:" + label, level, used < DISK_WARN, f"{path} occupé à {used} %")
        guarded("disque:" + label, "avertissement", disk)
    return checks


def summarize(checks):
    failed = [c for c in checks if c["status"] == "echec"]
    warned = [c for c in checks if c["status"] == "avertissement"]
    return {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "passed": not failed,
            "failures": len(failed), "warnings": len(warned), "checks": checks}


def render_text(report):
    labels = {"ok": "OK   ", "avertissement": "AVERT", "echec": "ECHEC"}
    lines = [f"{labels[c['status']]} {c['name']:<32} {c['detail']}" for c in report["checks"]]
    verdict = ("VERDICT : plateforme opérationnelle" if report["passed"] else
               f"VERDICT : {report['failures']} contrôle(s) critique(s) en échec")
    if report["warnings"]:
        verdict += f" ; {report['warnings']} avertissement(s)"
    return "\n".join(lines + ["", verdict])


def load_site_config(path: Path):
    """Lit 00-vars.env comme les scripts (shell de confiance), sans rien afficher."""
    if not path.is_file() or path.is_symlink():
        return {}
    command = 'set -a; source "$1" >/dev/null 2>&1; exec python3 -c \'import json,os; print(json.dumps(dict(os.environ)))\''
    process = subprocess.run(["bash", "-c", command, "omni-health", str(path)], capture_output=True, text=True, timeout=30)
    if process.returncode:
        return {}
    try:
        values = json.loads(process.stdout)
    except ValueError:
        return {}
    keys = ("SIEM_FQDN", "GRAYLOG_API_URL", "GRAYLOG_API_CA", "GRAYLOG_ADMIN_PASS", "DATA_MOUNT", "BACKUP_DIR")
    config = {k: values[k] for k in keys if values.get(k)}
    if os.environ.get("GRAYLOG_API_TOKEN"):
        config["GRAYLOG_API_TOKEN"] = os.environ["GRAYLOG_API_TOKEN"]
    return config
