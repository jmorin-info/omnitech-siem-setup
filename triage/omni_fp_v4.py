# -*- coding: utf-8 -*-
"""Signatures précises des faux positifs du triage, activées par une politique locale.

Aucune exception de site n'est embarquée. Le moteur appelant protège les alertes
critiques et les corrélations ; une signature exige la couverture du volume réel
par le backlog entier. Les décisions restent journalisées, les événements conservés.
"""
import json
import os
from pathlib import Path
import re

W = "winlogbeat_winlog_event_data_"

def _policy():
    """Une politique manquante, illisible ou invalide n'écarte aucune alerte."""
    try:
        path = Path(os.environ.get("OMNI_FP_V4_POLICY", "/etc/omni-alert-triage-fp-v4.json"))
        if path.is_symlink() or path.stat().st_size > 65536:
            return {}
        policy = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(policy, dict) or policy.get("schema") != 1:
            return {}
        clients = policy.get("urlhaus_dns_clients", [])
        jvms = policy.get("jvm_attach", {})
        pdf = policy.get("pdf24_machine_tasks", False)
        if not isinstance(clients, list) or not all(isinstance(v, str) and v for v in clients):
            return {}
        if not isinstance(jvms, dict) or type(pdf) is not bool:
            return {}
        for host, rule in jvms.items():
            if not isinstance(host, str) or not host or host != host.strip().lower():
                return {}
            if not isinstance(rule, dict) or not isinstance(rule.get("users"), list) or not rule["users"]:
                return {}
            if not all(isinstance(v, str) and v.strip() for v in rule["users"]):
                return {}
            if not isinstance(rule.get("binary"), str) or not rule["binary"].strip():
                return {}
        return policy
    except (OSError, ValueError, TypeError):
        return {}


def _g(m, *keys):
    for k in keys:
        v = m.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return ""

def _low(s):
    return str(s or "").strip().lower()

def _host_court(m):
    return _low(_g(m, "host", "winlogbeat_host_name", "source")).split(".")[0]

def _event_id(m):
    return _g(m, "winlogbeat_winlog_event_id", "winlogbeat_event_code", "event_id", "EventID")

def _urlhaus_examplecom_dc(m):
    return (_low(_g(m, "qname", "dns_query", "dns_domain")) == "example.com"
            and _g(m, "src_ip", "srcip") in _policy().get("urlhaus_dns_clients", []))

def _injection_jvm_attach(m):
    if _event_id(m) != "8":
        return False
    h = _low(_g(m, "host", "winlogbeat_host_name"))
    jvms = _policy().get("jvm_attach", {})
    if h not in jvms:
        return False
    comptes = {_low(v) for v in jvms[h]["users"]}
    binaire = _low(jvms[h]["binary"])
    src, tgt = _low(m.get(W + "SourceImage")), _low(m.get(W + "TargetImage"))
    return (src == binaire and tgt == binaire and _low(m.get(W + "SourceUser")) in comptes
            and "lsass" not in tgt)

_RX_PDF24 = re.compile(r"^\\PDF24 Explorer menu (\d+-\d+)$")
_RX_OFFENSIF = re.compile(r"http|powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|-enc|frombase64|\\temp\\", re.I)
def _schtask_pdf24(m):
    if not _policy().get("pdf24_machine_tasks", False):
        return False
    mn = _RX_PDF24.match(_g(m, W + "TaskName"))
    if not mn:
        return False
    sujet = _low(m.get(W + "SubjectUserName"))
    if not sujet.endswith("$") or sujet[:-1] != _host_court(m):
        return False
    tc = str(m.get(W + "TaskContent") or "")
    i = tc.find("<Actions")
    actions = tc[i:] if i >= 0 else ""
    execs = re.findall(r"<Exec>(.*?)</Exec>", actions, re.S)
    if len(execs) != 1 or "<ComHandler" in actions:
        return False
    cmd = re.findall(r"<Command>(.*?)</Command>", execs[0], re.S)
    arg = re.findall(r"<Arguments>(.*?)</Arguments>", execs[0], re.S)
    if cmd != ["C:\\Program Files\\PDF24\\pdf24-ExplorerMenu.exe"]:
        return False
    attendu = 'registerUser -log "C:\\Users\\Public\\pdf24-explorermenu-' + mn.group(1) + '.log"'
    if arg != [attendu] and arg != [attendu.replace('"', "&quot;")]:
        return False
    return not _RX_OFFENSIF.search(actions.replace(cmd[0], "").replace(arg[0], ""))

SIGNATURES = [
    {"id": "urlhaus_examplecom_dc", "tag": "malware_domain", "f": _urlhaus_examplecom_dc,
     "libelle": "Résolution du domaine réservé example.com par un client explicitement autorisé"},
    {"id": "injection_jvm_attach", "tag": "sysmon_injection", "f": _injection_jvm_attach,
     "libelle": "Attache JVM sur le même binaire et compte explicitement autorisés sur cet hôte"},
    {"id": "schtask_pdf24_explorermenu", "tag": "schtask_payload", "f": _schtask_pdf24,
     "libelle": "Tâche PDF24 Explorer menu exactement reconnue, exception activée par le site"},
]
LIBELLES = {s["id"]: s["libelle"] for s in SIGNATURES}

def signature_message(m):
    """Signature reconnue pour UN message (dict de champs) ou None."""
    tag = _low(m.get("alert_tag"))
    for s in SIGNATURES:
        if tag and tag != s["tag"]:
            continue
        try:
            if s["f"](m):
                return s
        except Exception:
            continue
    return None

def signature_alerte(backlog_msgs, count_reel, count_ok):
    """Signature commune à TOUS les messages du backlog, si le backlog couvre tout le volume réel."""
    msgs = [m for m in (backlog_msgs or []) if isinstance(m, dict)]
    if not msgs or not count_ok:
        return None
    try:
        if int(count_reel) > len(msgs) or int(count_reel) < 1:
            return None
    except Exception:
        return None
    ids = set()
    for m in msgs:
        s = signature_message(m)
        if not s:
            return None
        ids.add(s["id"])
    if len(ids) != 1:
        return None
    return next(s for s in SIGNATURES if s["id"] in ids)
