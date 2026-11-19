"""Integration menu data and command construction for the local SSH manager.

Only repository manifests are read. This module never runs commands, opens an API
connection, stores a token or mutates an installed module.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from omni_integrations import core
from omni_integrations.client import parameters


ACTIONS = frozenset({"plan", "install", "uninstall"})


def catalogue() -> list[dict]:
    """Present only nonsecret module metadata to the terminal menu."""
    return [
        {key: module[key] for key in (
            "id", "name", "revision", "status", "default_port", "supported_format"
        )}
        for module in core.catalog()
    ]


def validate_api(api: str) -> str:
    if not isinstance(api, str) or any(ord(character) < 33 or ord(character) == 127 for character in api):
        raise ValueError("L'URL API doit être une adresse sans espace ni caractère de contrôle.")
    parsed = urlsplit(api)
    # Accessing .port also validates the port syntax/range.
    _ = parsed.port
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("L'URL API ne doit pas contenir d'identifiant ni de mot de passe.")
    if parsed.query or parsed.fragment or not parsed.path.rstrip("/").endswith("/api"):
        raise ValueError("L'URL Graylog doit se terminer par /api, sans paramètre ni fragment.")
    if parsed.scheme != "https":
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Utiliser HTTPS vérifié ou HTTP sur l'adresse de boucle locale d'un tunnel SSH.")
    return api.rstrip("/")


def build_module_command(
    source_root,
    action: str,
    module_id: str,
    api: str,
    port: int | None = None,
    bind: str = "127.0.0.1",
    installation_id: str | None = None,
    *,
    apply: bool = False,
    ca: str | None = None,
) -> list[str]:
    """Build an argv list; the caller supplies GRAYLOG_API_TOKEN in process env.

    `install` and `uninstall` remain plans unless `apply=True`. An uninstall
    requires its exact installation ID. Never include credentials in `api`.
    """
    if action not in ACTIONS:
        raise ValueError("Action module inconnue : choisir plan, install ou uninstall.")
    if not isinstance(apply, bool) or (apply and action == "plan"):
        raise ValueError("Le mode plan ne peut effectuer aucune modification.")
    source = Path(source_root)
    if not source.is_absolute():
        raise ValueError("Le chemin du dépôt doit être absolu.")
    if not isinstance(module_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]*", module_id):
        raise ValueError("Identifiant de module invalide.")
    known = {item["id"] for item in core.catalog()}
    if module_id not in known:
        raise ValueError("Ce module n'est pas déclaré dans le catalogue.")
    module = core.load_module(module_id)
    argv = [sys.executable, str(source / "tools" / "omni-integrations.py"), action,
            module_id, "--api", validate_api(api)]
    if ca:
        if not isinstance(ca, str) or any(ord(character) < 32 or ord(character) == 127 for character in ca):
            raise ValueError("Chemin de certificat CA invalide.")
        if not Path(ca).is_absolute():
            raise ValueError("Le certificat CA doit être désigné par un chemin absolu.")
        argv.extend(["--ca", ca])
    if action == "uninstall":
        if not isinstance(installation_id, str) or not re.fullmatch(r"[a-f0-9]{24}", installation_id):
            raise ValueError("La désinstallation exige l'identifiant exact de l'installation Graylog.")
        argv.extend(["--installation-id", installation_id])
    else:
        if installation_id is not None:
            raise ValueError("L'identifiant d'installation sert uniquement à la désinstallation.")
        if not isinstance(bind, str):
            raise ValueError("L'adresse d'écoute doit être une adresse IP écrite en texte.")
        values = parameters(module, port, bind)
        argv.extend(["--port", str(values["port"]["@value"]), "--bind", values["bind_address"]["@value"]])
    if apply:
        argv.append("--apply")
    return argv
