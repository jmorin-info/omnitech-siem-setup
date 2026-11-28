"""Messagerie et fonctions optionnelles pilotées par la configuration du site.

Un robot déployé ne doit contenir ni relais SMTP, ni expéditeur, ni destinataire
propres à une organisation : sur une autre installation, ces valeurs par défaut
envoyaient les alertes vers un relais injoignable, et la seule parade était de
modifier les robots en production (modifications perdues au déploiement suivant).
"""
import importlib.util
from email.message import EmailMessage
from pathlib import Path
import re
import smtplib
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("omni_smtp", ROOT / "deploye/lib/omni-siem/omni_smtp.py")
omni_smtp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(omni_smtp)

MAIL_ROBOTS = ["deploye/sbin/omni-alert-lot", "triage/omni-alert-triage", "triage/omni-alert-digest",
               "deploye/sbin/omni-soar-rapport", "deploye/sbin/omni-weekly-report", "deploye/sbin/omni-monthly-report"]
SHELL_ROBOTS = ["deploye/sbin/oms-maj-siem", "deploye/sbin/oms-snap-siem"]
MAIL_KEYS = "SMTP_HOST|SMTP_FROM|MAIL_RECIPIENTS|LOT_RECIPIENTS|REPORT_SMTP|REPORT_FROM|REPORT_RECIPIENTS|SOAR_MAIL_TO"
LITERAL_DEFAULT = re.compile(r"""\.get\(\s*["'](?:%s)["']\s*,\s*["'][^"']*[@.][^"']*["']""" % MAIL_KEYS)
LITERAL_SMTP = re.compile(r"""smtplib\.SMTP\(\s*["']""")
LITERAL_SHELL = re.compile(r"""smtp://[A-Za-z0-9]|^\s*MAIL_(?:A|DE)=["'][^"'$]*@""", re.M)


def deployed_sources():
    sources = []
    for line in (ROOT / "manifeste-deploye.txt").read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0].startswith(("/usr/local/sbin/", "/usr/local/lib/omni-siem/")):
            path = ROOT / parts[1]
            if path.is_file():
                sources.append(path)
    return sources


def test_no_organisation_mail_defaults_in_deployed_robots():
    offenders = []
    for path in deployed_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in (LITERAL_DEFAULT, LITERAL_SMTP, LITERAL_SHELL):
            for match in pattern.finditer(text):
                offenders.append(f"{path.relative_to(ROOT)}: {match.group(0)[:80]}")
    assert offenders == [], "valeur SMTP codée en dur (à lire dans la configuration du site) :\n" + "\n".join(offenders)


@pytest.mark.parametrize("relative", MAIL_ROBOTS)
def test_mail_robots_send_through_site_module(relative):
    text = (ROOT / relative).read_text(encoding="utf-8")
    assert "omni_smtp.send(" in text and "omni_smtp.settings(" in text
    assert "smtplib.SMTP(" not in text


@pytest.mark.parametrize("relative", SHELL_ROBOTS)
def test_shell_robots_read_site_settings(relative, tmp_path):
    text = (ROOT / relative).read_text(encoding="utf-8")
    assert "site_var SMTP_RELAY" in text and '"${CURL_TLS[@]}"' in text
    function = re.search(r"^site_var\(\)\{.*?^\}$", text, re.M | re.S).group(0)
    site = tmp_path / "00-vars.env"
    site.write_text('SMTP_RELAY="relais.example.test"   # commentaire\nSMTP_FROM=\'siem@example.test\'\nALERT_EMAIL=soc@example.test\n')
    out = subprocess.run(["bash", "-c", function + '\nsite_var SMTP_RELAY; site_var SMTP_FROM; site_var ALERT_EMAIL; site_var ABSENT'],
                         env={"OMNI_SITE_VARS": str(site), "PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=True)
    assert out.stdout.splitlines() == ["relais.example.test", "siem@example.test", "soc@example.test"]


def test_site_module_is_published_with_the_robots():
    manifest = (ROOT / "manifeste-deploye.txt").read_text(encoding="utf-8")
    assert "/usr/local/lib/omni-siem/omni_smtp.py\tdeploye/lib/omni-siem/omni_smtp.py" in manifest


def test_parse_env_quotes_and_comments():
    values = omni_smtp.parse_env('A="x y"  # c\nB=\'z\'\nC=w # c\n# D=1\nexport E=5\n'
                                 'F="${C}.$E"\nG=\'${C}\'\nH="${INCONNU}x"\n')
    assert values == {"A": "x y", "B": "z", "C": "w", "E": "5", "F": "w.5", "G": "${C}", "H": "x"}


SITE = {"SMTP_RELAY": "relais.example.test", "SMTP_PORT": "587", "SMTP_FROM": "siem@example.test",
        "ALERT_EMAIL": "soc@example.test; dsi@example.test", "SMTP_STARTTLS": "1"}


def test_settings_fall_back_to_site_file():
    cfg = omni_smtp.settings({}, site=SITE)
    assert cfg == {"host": "relais.example.test", "port": 587, "from": "siem@example.test",
                   "to": ["soc@example.test", "dsi@example.test"], "starttls": "required"}


def test_robot_configuration_takes_precedence():
    cfg = omni_smtp.settings({"SMTP_HOST": "autre.example.test", "MAIL_RECIPIENTS": "a@example.test",
                              "SMTP_STARTTLS": "0"}, site=SITE)
    assert (cfg["host"], cfg["to"], cfg["starttls"]) == ("autre.example.test", ["a@example.test"], "off")


def test_report_keys_use_site_equivalents():
    cfg = omni_smtp.settings({}, host="REPORT_SMTP", port="REPORT_SMTP_PORT", sender="REPORT_FROM",
                             to="REPORT_RECIPIENTS", site=SITE)
    assert (cfg["host"], cfg["port"], cfg["from"]) == ("relais.example.test", 587, "siem@example.test")


def test_nothing_configured_means_no_relay():
    cfg = omni_smtp.settings({}, site={})
    assert (cfg["host"], cfg["from"], cfg["to"], cfg["starttls"]) == ("", "", [], "off")
    with pytest.raises(omni_smtp.SmtpConfigError):
        omni_smtp.send(cfg, EmailMessage())


def test_public_url_from_site():
    assert omni_smtp.public_url({}, site={"SIEM_FQDN": "siem.example.test"}) == "https://siem.example.test"
    assert omni_smtp.public_url({}, site={"GRAYLOG_PUBLIC_URL": "https://g.example.test/"}) == "https://g.example.test"


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return self.advertise and name == "starttls"

    def starttls(self, context=None):
        assert context is not None
        self.calls.append("starttls")

    def send_message(self, message, from_addr=None, to_addrs=None):
        self.calls.append(("send", from_addr, tuple(to_addrs)))


@pytest.mark.parametrize("mode,advertise,expected", [
    ("off", True, ["send"]), ("auto", False, ["ehlo", "send"]), ("auto", True, ["ehlo", "starttls", "ehlo", "send"]),
    ("required", True, ["ehlo", "starttls", "ehlo", "send"]), ("required", False, "erreur")])
def test_starttls_modes(monkeypatch, mode, advertise, expected):
    FakeSMTP.instances.clear()
    FakeSMTP.advertise = advertise
    monkeypatch.setattr(omni_smtp.smtplib, "SMTP", FakeSMTP)
    cfg = {"host": "relais.example.test", "port": 25, "from": "siem@example.test", "to": ["soc@example.test"], "starttls": mode}
    message = EmailMessage()
    if expected == "erreur":
        with pytest.raises(smtplib.SMTPNotSupportedError):
            omni_smtp.send(cfg, message)
        return
    omni_smtp.send(cfg, message)
    calls = [c if isinstance(c, str) else c[0] for c in FakeSMTP.instances[0].calls]
    assert calls == expected
    assert FakeSMTP.instances[0].calls[-1] == ("send", "siem@example.test", ("soc@example.test",))


TOP_LEVEL_SITE_FILE = re.compile(r'^(?:for \w+ in open|with open)\("(/etc/default/[^"]+)"', re.M)


def test_units_skip_cleanly_without_their_site_file():
    missing = []
    for unit in sorted((ROOT / "deploye/systemd").glob("*.service")):
        text = unit.read_text(encoding="utf-8")
        match = re.search(r"^ExecStart=(?:/usr/bin/python3 )?/usr/local/sbin/(\S+)", text, re.M)
        robot = ROOT / "deploye/sbin" / match.group(1) if match else None
        if not robot or not robot.is_file():
            continue
        for path in set(TOP_LEVEL_SITE_FILE.findall(robot.read_text(encoding="utf-8", errors="replace"))):
            if f"ConditionPathExists={path}" not in text:
                missing.append(f"{unit.name}: ConditionPathExists={path}")
    assert missing == [], "unité en échec quand la fonction n'est pas configurée :\n" + "\n".join(missing)
