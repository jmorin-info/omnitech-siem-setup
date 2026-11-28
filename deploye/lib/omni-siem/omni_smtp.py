"""Messagerie du site pour les robots OMNI : relais, expéditeur, destinataires, STARTTLS.

Aucune valeur propre à une organisation n'est codée ici. Ordre de résolution d'un
paramètre : fichier de configuration du robot (par exemple /etc/omni-alert-triage.env),
puis fichier de site 00-vars.env (SMTP_RELAY, SMTP_PORT, SMTP_FROM, ALERT_EMAIL,
SMTP_STARTTLS). Sans relais ou sans destinataire, l'envoi est refusé avec un message
explicite au lieu de partir vers un relais par défaut.

SMTP_STARTTLS : vide ou 0 = jamais (comportement historique), auto = si le relais
l'annonce, 1 = exigé (échec si le relais ne l'annonce pas). Le certificat du relais
est toujours vérifié quand STARTTLS est utilisé.
"""
from __future__ import annotations

import os
import re
import smtplib
import socket
import ssl

SITE_VARS_CANDIDATES = (
    "{home}/00-vars.env",
    "/opt/omni-siem/repository/00-vars.env",
)

# Paramètre demandé par un robot -> paramètres de site équivalents (dans l'ordre).
FALLBACK = {
    "SMTP_HOST": ("SMTP_RELAY",),
    "REPORT_SMTP": ("SMTP_HOST", "SMTP_RELAY"),
    "REPORT_SMTP_PORT": ("SMTP_PORT",),
    "REPORT_FROM": ("SMTP_FROM",),
    "MAIL_RECIPIENTS": ("ALERT_EMAIL",),
    "LOT_RECIPIENTS": ("MAIL_RECIPIENTS", "ALERT_EMAIL"),
    "REPORT_RECIPIENTS": ("ALERT_EMAIL",),
    "SOAR_MAIL_TO": ("ALERT_EMAIL",),
}

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_CACHE: dict[str, dict[str, str]] = {}


class SmtpConfigError(RuntimeError):
    """Messagerie du site absente ou incomplète."""


_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def parse_env(text: str) -> dict[str, str]:
    """KEY=valeur, valeurs entre guillemets ou suivies d'un commentaire.

    Comme le shell qui lit 00-vars.env, ${CLE} et $CLE sont remplacés par une clé
    définie plus haut (sauf entre apostrophes) ; aucune commande n'est exécutée.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.match(line)
        if not match or line.lstrip().startswith("#"):
            continue
        key, raw = match.group(1), match.group(2).strip()
        literal = raw[:1] == "'"
        if raw[:1] in ("'", '"'):
            end = raw.find(raw[0], 1)
            value = raw[1:end] if end > 0 else raw[1:]
        else:
            value = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        if not literal:
            value = _REF.sub(lambda ref: values.get(ref.group(1) or ref.group(2), ""), value)
        values[key] = value
    return values


def read_env(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as handle:
            return parse_env(handle.read())
    except OSError:
        return {}


def site_vars_path() -> str | None:
    explicit = os.environ.get("OMNI_SITE_VARS")
    if explicit:
        return explicit
    home = os.environ.get("OMNI_SIEM_HOME", "/opt/omni-siem/repository")
    for candidate in SITE_VARS_CANDIDATES:
        path = candidate.format(home=home)
        if os.path.isfile(path):
            return path
    return None


def site_vars() -> dict[str, str]:
    path = site_vars_path()
    if not path:
        return {}
    if path not in _CACHE:
        _CACHE[path] = read_env(path)
    return _CACHE[path]


def value(key: str, env: dict | None = None, site: dict | None = None, default: str = "") -> str:
    env = env or {}
    site = site_vars() if site is None else site
    for name in (key, *FALLBACK.get(key, ())):
        for source in (env, site):
            found = (source.get(name) or "").strip()
            if found:
                return found
    return default


def starttls_mode(raw: str) -> str:
    raw = (raw or "").strip().lower()
    if raw in ("1", "oui", "yes", "true", "required", "exige", "exigé"):
        return "required"
    if raw == "auto":
        return "auto"
    return "off"


def recipients(raw: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,;]", raw or "") if item.strip()]


def settings(env: dict | None = None, *, host: str = "SMTP_HOST", port: str = "SMTP_PORT",
             sender: str = "SMTP_FROM", to: str = "MAIL_RECIPIENTS", site: dict | None = None) -> dict:
    """Paramètres effectifs : clés du robot puis équivalents du fichier de site."""
    site = site_vars() if site is None else site
    port_value = value(port, env, site, "25")
    try:
        port_number = int(port_value)
    except ValueError as error:
        raise SmtpConfigError(f"port SMTP invalide : {port_value!r}") from error
    return {
        "host": value(host, env, site),
        "port": port_number,
        "from": value(sender, env, site),
        "to": recipients(value(to, env, site)),
        "starttls": starttls_mode(value("SMTP_STARTTLS", env, site)),
    }


def public_url(env: dict | None = None, site: dict | None = None) -> str:
    """URL publique de Graylog pour les liens des mails (sans barre finale)."""
    site = site_vars() if site is None else site
    url = value("GRAYLOG_PUBLIC_URL", env, site)
    if not url:
        fqdn = value("SIEM_FQDN", env, site) or socket.getfqdn()
        url = "https://" + fqdn
    return url.rstrip("/")


def send(cfg: dict, message, to: list[str] | None = None, sender: str | None = None, timeout: int = 30) -> list[str]:
    """Envoie un message déjà construit ; refuse plutôt que de partir vers un relais implicite."""
    targets = list(to if to is not None else cfg.get("to") or [])
    origin = sender or cfg.get("from") or message.get("From") or ""
    if not cfg.get("host"):
        raise SmtpConfigError("relais SMTP non configuré (SMTP_RELAY dans 00-vars.env ou SMTP_HOST du robot)")
    if not targets:
        raise SmtpConfigError("aucun destinataire configuré")
    if not origin:
        raise SmtpConfigError("expéditeur non configuré (SMTP_FROM)")
    with smtplib.SMTP(cfg["host"], int(cfg.get("port") or 25), timeout=timeout) as client:
        mode = cfg.get("starttls", "off")
        if mode != "off":
            client.ehlo()
            if client.has_extn("starttls"):
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            elif mode == "required":
                raise smtplib.SMTPNotSupportedError("STARTTLS exigé (SMTP_STARTTLS=1) mais non annoncé par le relais")
        client.send_message(message, from_addr=origin, to_addrs=targets)
    return targets
