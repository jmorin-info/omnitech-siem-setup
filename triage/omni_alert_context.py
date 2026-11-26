"""Pure, bounded alert context for mail/SOC adapters. No I/O or delivery policy.

Every value retains its field and record. Records are never merged into an
invented user/host/IP relationship. This module is prepared but not wired into
the production mail senders while their independent changes are in progress.
"""
from __future__ import annotations

from datetime import datetime
import html
import ipaddress
import json
import math
import re

SCHEMA_VERSION = 1
MAX_RECORDS = 20
MAX_VALUES = 8
MAX_TEXT = 320
EMPTY = {"", "-", "n/a", "null", "none", "unknown", "?", "(empty value)"}
SECRET = re.compile(r"(?i)(\b(?:password|passwd|pwd|token|api[_-]?key|secret|authorization)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)")
AUTHORIZATION = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
URL_AUTH = re.compile(r"(https?://)[^\s/:@]+:[^\s/@]+@", re.I)

# The collector 'source' is intentionally not a host, destination or environment.
# TargetUserName is a target account, not proof of the process owner/actor.
FIELDS = {
    "account": ("user", "upn", "identity_upn", "eset_username"),
    "identity": ("identity", "identity_console"),
    "actor": ("actor_login", "actor_usercode", "winlogbeat_winlog_event_data_SubjectUserName"),
    "target_account": ("target_login", "winlogbeat_winlog_event_data_TargetUserName"),
    "user_sid": ("user_sid", "winlogbeat_winlog_event_data_TargetUserSid"),
    "host": ("host", "computer", "hostname", "eset_hostname", "entity_host"),
    "source_host": ("src_hostname", "src_host", "srcname"),
    "destination_host": ("dest_hostname", "target_host"),
    "collector": ("source", "logsrc"),
    "source_ip": ("src_ip", "srcip"),
    "destination_ip": ("dest_ip", "dstip"),
    "source_port": ("src_port", "srcport"),
    "destination_port": ("dest_port", "dstport", "dport"),
    "transport": ("protocol", "proto", "network_transport"),
    "site": ("site", "seal_site", "fortigate_site", "winlogbeat_omnitech_site"),
    "environment": ("environment", "env", "deployment_environment"),
    "zone": ("zone", "seal_zone", "network_zone"),
    "object": ("target_object_label", "seal_ObjectLabel"),
    "object_id": ("target_object_id", "target_object_obj_id", "seal_ObjectObfiId"),
    "object_type": ("target_object_type", "seal_ObjectType"),
    "door": ("door_name", "door_label"),
    "door_id": ("door_id", "seal_DoorId"),
    "badge": ("badge_number", "seal_TagId"),
    "trigger": ("trigger_code", "REEV_CODE"),
    "event_source": ("event_source",),
    "event_domain": ("event_domain",),
    "event_id": ("event_id", "winlogbeat_winlog_event_id"),
    "action": ("event_action", "action"),
    "outcome": ("event_outcome",),
    "process": ("process_name", "eset_process_name", "eset_processname", "winlogbeat_winlog_event_data_Image"),
    "process_path": ("process_path", "process_image"),
    "parent_process": ("parent_process", "winlogbeat_winlog_event_data_ParentImage"),
    "tool": ("tool", "tool_name"),
    "risk_score": ("risk_score",),
    "risk_scale": ("risk_score_max", "risk_scale"),
    "risk_severity": ("risk_severity",),
    "severity": ("severity", "severity_num"),
    "priority": ("priority",),
    "rule": ("rule_id", "event_definition_id", "alert_tag"),
    "technique": ("mitre_technique", "mitre"),
    "signals": ("signals",),
    "entities": ("entities",),
    "incident_id": ("incident_id",),
}
LABELS = {
    "account":"Compte observé", "identity":"Identité déclarée", "actor":"Acteur", "target_account":"Compte ciblé",
    "user_sid":"SID du compte", "host":"Machine observée", "source_host":"Machine source",
    "destination_host":"Machine destination", "collector":"Collecteur / origine du journal",
    "source_ip":"IP source", "destination_ip":"IP destination", "source_port":"Port réseau source",
    "destination_port":"Port réseau destination", "transport":"Protocole", "site":"Site",
    "environment":"Environnement", "zone":"Zone", "object":"Objet concerné", "object_id":"Identifiant objet",
    "object_type":"Type d’objet", "door":"Porte physique", "door_id":"Identifiant porte physique",
    "badge":"Badge", "trigger":"Code de déclenchement", "event_source":"Source de collecte",
    "event_domain":"Domaine d’événement", "event_id":"Code événement", "action":"Action observée",
    "outcome":"Résultat observé", "process":"Processus", "process_path":"Chemin du processus",
    "parent_process":"Processus parent", "tool":"Outil déclaré", "risk_score":"Score de risque fourni",
    "risk_scale":"Échelle du score", "risk_severity":"Risque fourni", "severity":"Sévérité source",
    "priority":"Priorité de notification", "rule":"Règle / détection", "technique":"Technique ATT&CK",
    "signals":"Signaux déclarés", "entities":"Entités déclarées", "incident_id":"Identifiant incident",
}


def clean(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    text = re.sub(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]", " ", str(value)).strip()
    if text.casefold() in EMPTY:
        return ""
    text = URL_AUTH.sub(r"\1[identifiants masqués]@", text)
    text = AUTHORIZATION.sub(r"\1 [masqué]", text)
    return SECRET.sub(r"\1[masqué]", text)


def _fact(value, field, record, kind):
    text = clean(value)
    if not text:
        return None
    if kind in ("source_ip", "destination_ip"):
        try:
            text = str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if kind in ("source_port", "destination_port"):
        if not re.fullmatch(r"\d{1,5}", text) or not 0 <= int(text) <= 65535:
            return None
    return {"value":text[:MAX_TEXT], "field":field, "record":record, "truncated":len(text) > MAX_TEXT}


def _facts(message, record, truncations):
    found = {}
    for kind, aliases in FIELDS.items():
        facts = []
        for field in aliases:
            raw = message.get(field)
            values = raw if isinstance(raw, list) else [raw]
            if len(values) > MAX_VALUES:
                truncations.append({"record":record, "field":field, "values_omitted":len(values)-MAX_VALUES})
            for value in values[:MAX_VALUES]:
                fact = _fact(value, field, record, kind)
                if fact and (field, fact["value"]) not in {(f["field"], f["value"]) for f in facts}:
                    facts.append(fact)
        if facts:
            found[kind] = facts
    return found


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 60:
        return {"raw":"", "utc":None, "status":"missing"}
    raw = clean(value)
    try:
        when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if when.tzinfo is None:
            return {"raw":raw, "utc":None, "status":"timezone_missing"}
        from datetime import timezone
        return {"raw":raw, "utc":when.astimezone(timezone.utc).isoformat(), "status":"known"}
    except ValueError:
        return {"raw":raw, "utc":None, "status":"invalid"}


def build_context(payload):
    """Describe supplied observations; do not query, infer ownership or choose mail routing."""
    if not isinstance(payload, dict):
        raise ValueError("alert payload must be an object")
    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    truncations = []
    rows = [{"id":"event", "kind":"aggregation", "timestamp":_timestamp(event.get("timestamp")),
             "facts":_facts(fields, "event", truncations)}]
    backlog = payload.get("backlog")
    backlog = backlog if isinstance(backlog, list) else []
    invalid = 0
    for number, item in enumerate(backlog[:MAX_RECORDS]):
        if not isinstance(item, dict):
            invalid += 1
            continue
        message = item.get("message") if isinstance(item.get("message"), dict) else item
        if not isinstance(message, dict):
            invalid += 1
            continue
        rid = "backlog:" + str(number)
        rows.append({"id":rid, "kind":"observation", "timestamp":_timestamp(message.get("timestamp")),
                     "facts":_facts(message, rid, truncations)})
    # Top-level Graylog event properties retain their distinct semantic role.
    for key, kind in (("priority", "priority"), ("event_definition_id", "rule")):
        fact = _fact(event.get(key), key, "event", kind)
        if fact:
            rows[0]["facts"].setdefault(kind, []).append(fact)
    present = {kind for row in rows for kind in row["facts"]}
    missing = [kind for kind in ("account", "host", "source_ip", "destination_ip", "environment", "action", "outcome") if kind not in present]
    limits = ["La présence dans une même alerte ne prouve ni une session commune ni une causalité.",
              "Un collecteur de journaux ne désigne pas automatiquement la machine impliquée.",
              "Les comptes de domaines distincts et les comptes administrateurs ne sont pas fusionnés.",
              "La gravité fournie ne prouve pas à elle seule une compromission."]
    if not backlog:
        limits.append("Aucun événement déclencheur joint ; seuls les champs d’agrégation sont disponibles.")
    if len(backlog) > MAX_RECORDS or invalid or truncations:
        limits.append("Le contexte présenté est partiel ; consulter les événements d’origine.")
    if any("risk_score" in row["facts"] and "risk_scale" not in row["facts"] for row in rows):
        limits.append("L’échelle du score de risque n’est pas fournie ; aucune conversion sur 10 ou 100 n’est effectuée.")
    replay = event.get("replay_info") if isinstance(event.get("replay_info"), dict) else {}
    window = {key:_timestamp(replay.get(name)) for key, name in (("start", "timerange_start"), ("end", "timerange_end"))}
    ordered = window["start"]["utc"] and window["end"]["utc"] and window["start"]["utc"] <= window["end"]["utc"]
    conditions = event.get("aggregation_conditions")
    count = conditions.get("count") if isinstance(conditions, dict) else None
    valid_count = type(count) in (int, float) and 0 <= count <= 2**63-1
    real_count = count if valid_count else None
    return {"schema_version":SCHEMA_VERSION,
            "title":clean(event.get("event_definition_title") or payload.get("event_definition_title") or "Alerte")[:MAX_TEXT],
            "records":rows, "window":{**window, "status":"known" if ordered else "unknown"},
            "coverage":{"attached":len(backlog), "included":len(rows)-1, "invalid":invalid,
                        "omitted":max(0,len(backlog)-MAX_RECORDS), "value_truncations":truncations},
            "occurrences":{"value":real_count, "origin":"event.aggregation_conditions.count" if real_count is not None else None},
            "missing":missing, "limitations":limits, "causal_chain_proven":False}


def _rows(context):
    yield ("Alerte", context["title"])
    window = context["window"]
    yield ("Fenêtre d’analyse", window["start"]["utc"] + " → " + window["end"]["utc"]
           if window["status"] == "known" else "Non fournie ou non valide")
    coverage = context["coverage"]
    yield ("Échantillon joint", str(coverage["included"]) + " événement(s) présenté(s) sur "
           + str(coverage["attached"]) + " joint(s) ; ce nombre ne décrit pas le volume total détecté")
    count = context["occurrences"]["value"]
    if count is not None:
        yield ("Occurrences agrégées déclarées", str(count) + " [event.aggregation_conditions.count]")
    else:
        yield ("Occurrences agrégées", "Non fournies ; ne pas les déduire de la taille de l’échantillon")
    if coverage["omitted"] or coverage["invalid"]:
        yield ("Échantillon incomplet", str(coverage["omitted"]) + " omis ; " + str(coverage["invalid"]) + " invalide(s)")
    for record in context["records"]:
        label = "Agrégation" if record["kind"] == "aggregation" else "Événement joint"
        stamp = record["timestamp"]
        yield (label + " · " + record["id"], stamp["utc"] or "Horodatage inconnu ou fuseau absent")
        for kind, facts in record["facts"].items():
            for fact in facts:
                yield (LABELS[kind], fact["value"] + " [" + fact["field"] + "; " + fact["record"] + "]"
                       + (" (tronqué)" if fact["truncated"] else ""))
    if context["missing"]:
        yield ("Non renseigné dans les événements fournis", ", ".join(LABELS[k] for k in context["missing"]))
    for limitation in context["limitations"]:
        yield ("Limite", limitation)


def render_text(context):
    return "\n".join(label + " : " + value for label, value in _rows(context)) + "\n"


def render_html(context):
    return '<table role="presentation">' + "".join(
        "<tr><th>" + html.escape(label) + "</th><td>" + html.escape(value) + "</td></tr>"
        for label, value in _rows(context)) + "</table>"


def preview_json(payload):
    return json.dumps(build_context(payload), indent=2, ensure_ascii=False)
