"""Read a trusted site file without executing it; preserve tenant settings on save."""
from __future__ import annotations
import datetime as dt
import ipaddress
import math
import os
from pathlib import Path
import re
import shlex
import tempfile
from urllib.parse import urlsplit
from .storage import lock

FIELDS = {
    "SIEM_HOSTNAME": ("Nom du serveur", "name"), "SIEM_DOMAIN": ("Domaine DNS", "name"),
    "SIEM_FQDN": ("Nom DNS complet", "name"), "SIEM_TIMEZONE": ("Fuseau horaire", "text"),
    "SIEM_IP": ("Adresse IPv4 du SIEM", "ip"), "SIEM_PREFIX": ("Préfixe IPv4", "prefix"),
    "SIEM_GW": ("Passerelle", "ip"), "SIEM_IFACE": ("Interface réseau", "name"),
    "DNS1": ("DNS primaire", "ip"), "DNS2": ("DNS secondaire", "ip"),
    "NTP1": ("Source NTP primaire", "text"), "NTP2": ("Source NTP secondaire", "text"),
    "NET_ADMIN": ("Réseau autorisé pour SSH", "network"), "WEB_NET": ("Réseau autorisé pour HTTPS", "network"),
    "NET_BEATS": ("Réseau des agents Beats", "network"), "VSPHERE_NET": ("Réseau vSphere", "network"),
    "NET_ARUBA": ("Réseau Aruba (facultatif)", "network_optional"),
    "IP_FAZ": ("Adresse FortiAnalyzer", "ip_optional"), "IP_CENTREON": ("Adresse supervision", "ip_optional"),
    "IP_FORTIMANAGER": ("Adresse FortiManager", "ip_optional"),
    "OS_HEAP": ("Heap OpenSearch", "heap"), "GL_HEAP": ("Heap Graylog", "heap"),
    "MONGO_CACHE_GB": ("Cache MongoDB en Go", "positive"), "JOURNAL_SIZE": ("Journal Graylog", "size"),
    "DATA_MOUNT": ("Volume de données déjà préparé", "path"), "BACKUP_DIR": ("Répertoire de sauvegarde", "path"),
    "RETENTION_DAYS": ("Rétention locale des sauvegardes", "positive_integer"),
    "SMTP_RELAY": ("Relais SMTP", "name"), "SMTP_PORT": ("Port SMTP", "port"),
    "SMTP_FROM": ("Adresse d'envoi", "email"), "ALERT_EMAIL": ("Destinataire des alertes", "email"),
    "GRAYLOG_API_URL": ("URL API Graylog (vide : détection)", "api_optional"),
    "GRAYLOG_API_CA": ("Fichier CA de l'API", "path"),
}
SECRETS = {
    "GRAYLOG_ADMIN_PASS": "Mot de passe administrateur Graylog",
    "MONGO_ADMIN_PASS": "Mot de passe administrateur MongoDB",
    "MONGO_GRAYLOG_PASS": "Mot de passe MongoDB du service Graylog",
    "OPENSEARCH_BOOTSTRAP_PASS": "Mot de passe bootstrap OpenSearch",
    "BACKUP_PASSPHRASE": "Passphrase des sauvegardes (à conserver au coffre)",
}
ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$")


def parse(text):
    values = {}
    for line in text.splitlines():
        match = ASSIGNMENT.match(line)
        if not match:
            continue
        try:
            tokens = shlex.split(match[2], comments=True, posix=True)
        except ValueError:
            continue
        if len(tokens) > 1:
            continue
        literal = tokens[0] if tokens else ""
        # Understand only simple, previously defined nonsecret substitutions.
        if not match[2].lstrip().startswith("'"):
            literal = re.sub(r"\$\{([A-Z][A-Z0-9_]*)\}",
                             lambda m: values.get(m[1], m[0]) if m[1] in FIELDS else m[0], literal)
        values[match[1]] = literal
    return values


def validate_values(values, secrets):
    if not isinstance(values, dict) or not isinstance(secrets, dict):
        raise ValueError("Les paramètres doivent être des dictionnaires.")
    if set(values) - FIELDS.keys() or set(secrets) - SECRETS.keys():
        raise ValueError("Paramètre inconnu : modification refusée.")
    for key, value in {**values, **secrets}.items():
        if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Valeur invalide pour " + key)
        if key in SECRETS:
            continue
        kind = FIELDS[key][1]
        try:
            if kind == "name" and not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                raise ValueError()
            if kind in ("ip", "ip_optional") and (value or kind == "ip"):
                if ipaddress.ip_address(value).version != 4:
                    raise ValueError()
            if kind in ("network", "network_optional") and (value or kind == "network"):
                ipaddress.ip_network(value, strict=False)
            if kind == "prefix" and not 0 <= int(value) <= 32:
                raise ValueError()
            if kind == "port" and not 1 <= int(value) <= 65535:
                raise ValueError()
            if kind == "positive" and (not math.isfinite(float(value)) or float(value) <= 0):
                raise ValueError()
            if kind == "positive_integer" and (not value.isdigit() or int(value) < 1):
                raise ValueError()
            if kind == "heap" and not re.fullmatch(r"[1-9][0-9]*[gm]", value):
                raise ValueError()
            if kind == "size" and not re.fullmatch(r"[1-9][0-9]*(?:gb|mb)", value):
                raise ValueError()
            if kind == "path" and (not value.startswith("/") or ".." in Path(value).parts):
                raise ValueError()
            if kind == "email" and ("@" not in value or any(c.isspace() for c in value)):
                raise ValueError()
            if kind == "api_optional" and value:
                url = urlsplit(value)
                if url.username or url.password or url.query or url.fragment or not url.hostname:
                    raise ValueError()
                if url.scheme != "https" and not (url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost", "::1")):
                    raise ValueError()
                if not url.path.rstrip("/").endswith("/api"):
                    raise ValueError()
                if url.scheme == "http" and (url.hostname not in ("127.0.0.1", "localhost") or url.port != 9000 or url.path.rstrip("/") != "/api"):
                    raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Valeur invalide pour " + key) from None


class Configuration:
    def __init__(self, source: Path, state: Path):
        self.source, self.state = Path(source).resolve(), Path(state).resolve()
        self.path = self.source / "00-vars.env"
        if self.path.is_symlink():
            raise ValueError("Le fichier de configuration ne doit pas être un lien symbolique.")

    def defaults(self):
        return {k: v for k, v in parse((self.source / "00-vars.env.example").read_text(encoding="utf-8")).items() if k in FIELDS}

    def read(self):
        if self.path.is_symlink():
            raise ValueError("Lien symbolique de configuration refusé.")
        current = parse(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        values = self.defaults()
        values.update({k: v for k, v in current.items() if k in FIELDS})
        return {"values": values, "secret_status": {k: bool(current.get(k) and "CHANGEME" not in current[k]) for k in SECRETS}}

    def save(self, values: dict, secrets: dict):
        with lock(self.state):
            return self._save(values, secrets)

    def _save(self, values: dict, secrets: dict):
        validate_values(values, secrets)
        if self.path.is_symlink():
            raise ValueError("Lien symbolique de configuration refusé.")
        original = self.path.read_text(encoding="utf-8") if self.path.exists() else (self.source / "00-vars.env.example").read_text(encoding="utf-8")
        updates = dict(values)
        updates.update({k: v for k, v in secrets.items() if v})
        if "SIEM_FQDN" not in updates and {"SIEM_HOSTNAME", "SIEM_DOMAIN"} & updates.keys():
            current = self.read()["values"]
            current.update(values)
            updates["SIEM_FQDN"] = current["SIEM_HOSTNAME"] + "." + current["SIEM_DOMAIN"]
        lines, seen = [], set()
        for line in original.splitlines():
            match = ASSIGNMENT.match(line)
            if match and match[1] in updates:
                lines.append(match[1] + "=" + shlex.quote(updates[match[1]]))
                seen.add(match[1])
            else:
                lines.append(line)
        lines.extend(k + "=" + shlex.quote(v) for k, v in updates.items() if k not in seen)
        self.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.path.exists():
            directory = self.state / "config-backups"
            if directory.is_symlink():
                raise ValueError("Lien symbolique de sauvegarde refusé.")
            directory.mkdir(mode=0o700, exist_ok=True)
            name = directory / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ.env")
            with os.fdopen(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8") as backup:
                backup.write(original)
        with tempfile.NamedTemporaryFile(dir=self.source, delete=False) as candidate:
            candidate.write(("\n".join(lines) + "\n").encode())
            temporary = Path(candidate.name)
        try:
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return self.read()
