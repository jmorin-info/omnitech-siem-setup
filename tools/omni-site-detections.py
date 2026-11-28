#!/usr/bin/env python3
"""Détections portables pilotées par la configuration du site.

Le catalogue (objets-graylog/detections-site/catalogue.json) décrit des détections
indépendantes de l'organisation. La configuration du site (/etc/omni-siem/detections.json,
hors Git, modèle objets-graylog/detections-site/site.exemple.json) déclare les sources
réellement reçues, leurs streams et les paramètres propres au site.

Commandes :
  valider                 contrôle hors ligne du catalogue (CI) : gabarits, champs lus et
                          interrogés produits par la source ou par la règle, titres, gravités
  plan                    état de chaque détection sur l'instance (créée active, créée
                          désactivée avec la raison, non créée avec la raison)
  appliquer-regles        tables de correspondance, règles et pipelines (aucune définition)
  rejeu                   preuve : exemples synthétiques et vrais messages passés dans le
                          simulateur de pipeline de Graylog, puis planificateur rejoué
  appliquer-definitions   définitions d'événements ; planifiées seulement si la preuve est
                          acquise et le rejeu sous le plafond du catalogue
  verifier                contrôle après déploiement : chaque définition planifiée a un stream
                          actif et une source qui produit ses champs ; chaque table de
                          correspondance lue par une règle connectée existe
  mesure                  durée moyenne de traitement par stream (gl2_processing_duration_ms)
  retour                  suppression par ID des seuls objets créés (fichier d'état)
Bibliothèque standard seule. Aucune donnée de site dans le dépôt.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

http.client._MAXHEADERS = 10000
DEPOT = Path(__file__).resolve().parent.parent
CATALOGUE = DEPOT / "objets-graylog" / "detections-site" / "catalogue.json"
SITE = Path(os.environ.get("OMNI_DETECTIONS_SITE", "/etc/omni-siem/detections.json"))
INTEGRATIONS = Path(os.environ.get("OMNI_INTEGRATIONS_SITE", "/etc/omni-siem/integrations.json"))
ETAT = Path(os.environ.get("OMNI_DETECTIONS_ETAT", "/var/lib/omni-siem/site-detections-etat.json"))
GRAVITES = {"CRITIQUE": 3, "ELEVE": 2, "INFO": 1}
RESEAUX_PRIVES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]
STREAM_EVENTS = "000000000000000000000002"
PIPELINE_DETECTIONS = "OMNI v5 - Detections site"
PIPELINE_TI = "OMNI v5 - TI enrichissement"
ETAPE_TI, ETAPE_DETECTIONS = 19, 45
CHAMPS_GRAYLOG = {"message", "source", "timestamp", "streams", "_id", "full_message"}


# ----------------------------------------------------------------------------- catalogue et gabarits
def charger(chemin):
    with open(chemin, encoding="utf-8") as f:
        return json.load(f)


def parametres(site):
    p = dict(site.get("parametres", {}))
    p.setdefault("reseaux_internes", [])
    return p


def _liste(p, nom):
    v = p.get(nom) or []
    return [str(x).lower() for x in (v if isinstance(v, list) else [v])]


def _q(v):
    return json.dumps(v, ensure_ascii=False)


def rendre(texte, p):
    """Développe $ed. et les gabarits {{...}} d'une règle avec les paramètres du site."""
    texte = texte.replace("$ed.", "$message.winlogbeat_winlog_event_data_")

    def sub(m):
        corps = m.group(1)
        genre, _, reste = corps.partition(":")
        if genre == "interne":
            expr = reste
            reseaux = RESEAUX_PRIVES + [str(x) for x in p.get("reseaux_internes", [])]
            return "(" + " || ".join(f"cidr_match({_q(c)}, to_ip({expr}))" for c in reseaux) + ")"
        expr, _, nom = reste.rpartition(":")
        if genre == "premier":
            v = _liste(p, reste)
            return v[0] if v else "aucun"
        if genre == "lucene":
            v = _liste(p, reste)
            return "(" + " OR ".join(_q(x) for x in v) + ")" if v else '("")'
        valeurs = _liste(p, nom)
        if not valeurs:
            return "false"
        if genre == "dans":
            return "(" + " || ".join(f"{expr} == {_q(v)}" for v in valeurs) + ")"
        if genre == "contient":
            return "(" + " || ".join(f"contains({expr}, {_q(v)})" for v in valeurs) + ")"
        if genre == "commence":
            return "(" + " || ".join(f"starts_with({expr}, {_q(v)})" for v in valeurs) + ")"
        raise ValueError(f"gabarit inconnu : {corps}")

    return re.sub(r"\{\{([^{}]+)\}\}", sub, texte)


def rendre_exemple(ex, p):
    return {k: (rendre(v, p) if isinstance(v, str) else v) for k, v in ex.items()}


def nom_regle(d):
    return "omni-v5-site-" + d["id"]


def tag(d):
    return d["id"].replace("-", "_")


def source_regle(d, p):
    cond = rendre(d["condition"], p)
    ent = rendre(d["entite"], p)
    det = rendre(d["detail"], p)
    return (f'rule "{nom_regle(d)}"\nwhen\n  {cond}\nthen\n'
            f'  set_field("v5_tag", "{tag(d)}");\n  set_field("v5_severite", "{d["gravite"]}");\n'
            f'  set_field("v5_mitre", "{d["mitre"]}");\n  set_field("v5_entite", {ent});\n'
            f'  set_field("v5_detail", {det});\nend')


def source_regle_ti(r, p):
    cle = rendre(r["cle"], p)
    lk = r["lookup"]
    lignes = [f'rule "omni-v5-{r["id"]}"', "when", "  " + rendre(r["condition"], p), "then",
              f'  let v = regex("^([^|]*)\\\\|([^|]*)\\\\|([^|]*)\\\\|([^|]*)\\\\|([^|]*)\\\\|([^|]*)\\\\|(.*)$", '
              f'to_string(lookup_value("{lk}", {cle})), ["s","t","m","c","p","f","r"]);',
              f"  set_field(\"ti_match\", {cle});",
              '  set_field("ti_source", v["s"]);', '  set_field("ti_type", v["t"]);', '  set_field("ti_malware", v["m"]);',
              '  set_field("ti_confiance", v["c"]);', '  set_field("ti_ioc_ports", v["p"]);', '  set_field("ti_ioc_date", v["f"]);',
              '  set_field("ti_ref", v["r"]);', '  set_field("ti_tag", "omni_v5_ti");',
              f'  set_field("ti_direction", "{r["direction"]}");', f'  set_field("ti_contexte", "{r["contexte"]}");']
    if r.get("port"):
        lignes.append(f'  set_field("ti_port_match", contains(to_string(v["p"]), concat(concat(";", to_string({r["port"]})), ";")));')
    lignes.append("end")
    return "\n".join(lignes)


def requete(d):
    if d.get("tag"):
        return f"alert_tag:{d['tag']}"
    if d.get("requete"):
        return d["requete"]
    q = f"v5_tag:{tag(d)}"
    if d.get("requete_supplementaire"):
        q = f"({q}) OR ({d['requete_supplementaire']})"
    return q


def regroupement(d):
    return d.get("regroupement") or ["v5_entite"]


def champs_requete(q):
    texte = re.sub(r'"(?:[^"\\]|\\.)*"', '""', q or "")
    champs = set(re.findall(r"_exists_:([A-Za-z_][A-Za-z0-9_]*)", texte))
    champs |= {n for n in re.findall(r"(?<![\w.\\])([A-Za-z_][A-Za-z0-9_]*):", texte) if n != "_exists_"}
    return champs


def champs_lus(source_rendue):
    return set(re.findall(r"\$message\.([A-Za-z0-9_]+)", source_rendue)) | set(re.findall(r'has_field\("([A-Za-z0-9_]+)"\)', source_rendue))


def correspond(q, doc):
    """Évalue sur un message le sous-ensemble Lucene des définitions TI du catalogue : conjonction (AND) de
    champ:valeur, champ:(a OR b), _exists_:champ, NOT clause ; joker * en fin de valeur ; échappement \\."""
    for c in (x.strip() for x in re.split(r"\s+AND\s+", q.strip())):
        neg = c.startswith("NOT ")
        if neg:
            c = c[4:].strip()
        m = re.fullmatch(r"_exists_:([A-Za-z0-9_]+)", c)
        if m:
            ok = doc.get(m.group(1)) not in (None, "")
        else:
            m = re.fullmatch(r"([A-Za-z0-9_]+):(\((.+)\)|\S+)", c)
            if not m:
                raise ValueError(f"clause non prise en charge : {c}")
            valeurs = [v.strip() for v in re.split(r"\s+OR\s+", m.group(3))] if m.group(3) else [m.group(2)]
            v_doc = doc.get(m.group(1))
            v_doc = "" if v_doc is None else str(v_doc).lower()
            ok = False
            for v in valeurs:
                v = re.sub(r"\\(.)", r"\1", v).strip('"').lower()
                ok |= v_doc.startswith(v[:-1]) if v.endswith("*") else v_doc == v
        if ok == neg:
            return False
    return True


def champ_couvert(champ, motifs):
    return any(champ == m or (m.endswith("*") and champ.startswith(m[:-1])) for m in motifs)


# ----------------------------------------------------------------------------- validation hors ligne
def valider(cat, site_exemple):
    erreurs = []
    p = parametres(site_exemple)
    ids, titres = set(), set()
    produits = set(cat["champs_produits"])
    lookups = {lk["nom"] for lk in cat["lookups"]}
    for d in cat["detections"]:
        i = d.get("id", "?")
        if i in ids:
            erreurs.append(f"{i}: identifiant en double")
        ids.add(i)
        if not d["titre"].startswith(cat["prefixe_titre"]):
            erreurs.append(f"{i}: le titre doit commencer par {cat['prefixe_titre']!r} (rodage du tri)")
        if d["titre"] in titres:
            erreurs.append(f"{i}: titre en double")
        titres.add(d["titre"])
        if d.get("gravite") not in GRAVITES:
            erreurs.append(f"{i}: gravité inconnue")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", d.get("mitre", "")):
            erreurs.append(f"{i}: technique MITRE invalide")
        src = cat["sources"].get(d["source"])
        if not src:
            erreurs.append(f"{i}: source inconnue {d['source']}")
            continue
        motifs = list(src["champs"])
        for s in d.get("sources_tag", []):
            motifs += cat["sources"][s]["champs"]
        if d.get("ti") and d["ti"] not in lookups:
            erreurs.append(f"{i}: table TI inconnue {d['ti']}")
        if d.get("lookup_requis") and d["lookup_requis"] not in lookups:
            erreurs.append(f"{i}: table requise inconnue {d['lookup_requis']}")
        if "condition" in d:
            try:
                src_r = source_regle(d, p)
            except (KeyError, ValueError) as e:
                erreurs.append(f"{i}: gabarit invalide ({e})")
                continue
            if "{{" in src_r:
                erreurs.append(f"{i}: gabarit non développé")
            if src_r.count("(") != src_r.count(")"):
                erreurs.append(f"{i}: parenthèses déséquilibrées")
            for c in champs_lus(src_r):
                if not champ_couvert(c, motifs):
                    erreurs.append(f"{i}: la règle lit {c}, que la source {d['source']} ne produit pas")
            for nom in d.get("parametres", []):
                if nom not in site_exemple.get("parametres", {}):
                    erreurs.append(f"{i}: paramètre {nom} absent du modèle de site")
            for sens in ("positif", "negatif"):
                if sens not in d.get("exemples", {}):
                    erreurs.append(f"{i}: exemple {sens} manquant")
            if not d.get("rejeu", {}).get("prefiltre"):
                erreurs.append(f"{i}: préfiltre de rejeu manquant")
            if not d.get("temoins"):
                erreurs.append(f"{i}: événements témoins manquants")
        elif not d.get("tag") and not d.get("ti"):
            erreurs.append(f"{i}: ni règle, ni étiquette du socle, ni table TI")
        for c in champs_requete(requete(d)) | set(regroupement(d)) | ({d["serie"]["champ"]} if d.get("serie") else set()):
            if c in CHAMPS_GRAYLOG or c in produits or champ_couvert(c, motifs):
                continue
            erreurs.append(f"{i}: la définition interroge {c}, produit ni par la source ni par une règle")
        if d.get("regroupement") is None and "condition" not in d and not d.get("tag"):
            erreurs.append(f"{i}: regroupement requis")
    for r in cat["ti_regles"]:
        src_r = source_regle_ti(r, p)
        for c in champs_lus(src_r):
            if not champ_couvert(c, cat["sources"][r["source"]]["champs"]):
                erreurs.append(f"{r['id']}: la règle TI lit {c}, absent de la source")
        if r["lookup"] not in lookups:
            erreurs.append(f"{r['id']}: table inconnue")
        if not r.get("champs_rejeu"):
            erreurs.append(f"{r['id']}: champs_rejeu manquant (recherche rétroactive)")
    for d in cat["detections"]:
        if d.get("ti"):
            try:
                correspond(requete(d), {})
            except ValueError as e:
                erreurs.append(f"{d['id']}: requête TI non évaluable au rejeu ({e})")
    return erreurs


# ----------------------------------------------------------------------------- accès Graylog / OpenSearch
def vars_env():
    d = {}
    chemin = Path(os.environ.get("OMNI_VARS", str(DEPOT / "00-vars.env")))
    try:
        for ligne in chemin.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^([A-Z_0-9]+)=(.*)$", ligne.strip())
            if m:
                v = m.group(2).strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                d[m.group(1)] = v
    except OSError:
        pass
    return d


class Client:
    def __init__(self):
        v = vars_env()
        self.user = os.environ.get("OMNI_GRAYLOG_USER") or v.get("GRAYLOG_ADMIN_USER") or "admin"
        self.pw = os.environ.get("OMNI_GRAYLOG_PASS") or v.get("GRAYLOG_ADMIN_PASS") or ""
        self.os_url = os.environ.get("OMNI_OPENSEARCH_URL", "http://127.0.0.1:9200")
        self.ctx = ssl._create_unverified_context()
        self.base = os.environ.get("OMNI_GRAYLOG_URL")
        if not self.base:
            for b in ("http://127.0.0.1:9000/api", "https://127.0.0.1:9000/api"):
                try:
                    self.base = b
                    self.api("GET", "/system")
                    break
                except Exception:
                    self.base = None
        if not self.base:
            raise SystemExit("API Graylog injoignable")

    def api(self, methode, chemin, corps=None):
        req = urllib.request.Request(self.base + chemin, method=methode,
                                     data=json.dumps(corps).encode() if corps is not None else None)
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{self.user}:{self.pw}".encode()).decode())
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Requested-By", "omni-site-detections")
        with urllib.request.urlopen(req, context=self.ctx, timeout=120) as r:
            t = r.read()
            return json.loads(t) if t else {}

    def os(self, methode, chemin, corps=None):
        req = urllib.request.Request(self.os_url + chemin, method=methode,
                                     data=json.dumps(corps).encode() if corps is not None else None)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())

    def compter(self, index, q, jours=30, streams=None):
        filtre = [{"query_string": {"query": q}}, {"range": {"timestamp": {"gte": f"now-{jours}d"}}}]
        if streams:
            filtre.append({"terms": {"streams": streams}})
        return self.os("POST", f"/{index}/_count", {"query": {"bool": {"filter": filtre}}})["count"]


def site_charge(args):
    site = charger(args.site)
    p = site.setdefault("parametres", {})
    if "zones_externes" not in p and INTEGRATIONS.exists():
        try:
            wg = charger(INTEGRATIONS)["integrations"]["watchguard"]["parameters"]
            p["zones_externes"] = wg.get("external_zones", [])
        except (KeyError, ValueError):
            pass
    return site


# ----------------------------------------------------------------------------- plan
def inventaire(cl):
    streams = {s["title"]: s for s in cl.api("GET", "/streams")["streams"]}
    regles = cl.api("GET", "/system/pipelines/rule")
    pipelines = cl.api("GET", "/system/pipelines/pipeline")
    connexions = cl.api("GET", "/system/pipelines/connections")
    tables = {t["name"]: t for t in cl.api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"]}
    return streams, regles, pipelines, connexions, tables


def streams_connectes(regle_titre, pipelines, connexions):
    pids = {p["id"] for p in pipelines if re.search(r'rule\s+"%s"' % re.escape(regle_titre), p.get("source", ""))}
    return {c["stream_id"] for c in connexions if pids & set(c.get("pipeline_ids", []))}


def plan(cat, site, cl, jours=30):
    p = parametres(site)
    streams, regles, pipelines, connexions, tables = inventaire(cl)
    actives = {}
    for nom, conf in (site.get("sources") or {}).items():
        if not conf:
            continue
        s = streams.get(conf.get("stream", ""))
        if not s:
            actives[nom] = {"erreur": f"stream « {conf.get('stream')} » introuvable"}
            continue
        idx = cat["sources"][nom]["index"]
        n = cl.compter(idx, f"event_source:{cat['sources'][nom]['event_source']}", 1, [s["id"]])
        actives[nom] = {"stream": s["id"], "titre": s["title"], "desactive": s.get("disabled", False), "messages_24h": n, "index": idx}
    ti_actif = bool((site.get("ti") or {}).get("actif"))
    res = []
    for d in cat["detections"]:
        e = {"id": d["id"], "titre": d["titre"], "source": d["source"], "gravite": d["gravite"]}
        src = actives.get(d["source"])
        if not src:
            e.update(etat="non_creee", raison=f"source {d['source']} non déclarée par le site")
        elif src.get("erreur"):
            e.update(etat="non_creee", raison=src["erreur"])
        elif src["desactive"] or src["messages_24h"] == 0:
            e.update(etat="desactivee", raison=f"source {d['source']} sans message depuis 24 h")
        else:
            e.update(etat="active", streams=[src["stream"]])
        if e["etat"] == "active" and d.get("sources_tag"):
            ids = [actives[s]["stream"] for s in d["sources_tag"] if actives.get(s, {}).get("stream")]
            producteurs = [r for r in regles if re.search(r'set_field\(\s*"alert_tag"\s*,\s*"%s"' % re.escape(d["tag"]), r["source"])]
            connectes = set()
            for r in producteurs:
                connectes |= streams_connectes(r["title"], pipelines, connexions)
            ids = [i for i in ids if i in connectes]
            if not producteurs:
                e.update(etat="non_creee", raison=f"aucune règle du socle ne pose alert_tag:{d['tag']} sur cette instance")
            elif not ids:
                e.update(etat="non_creee", raison=f"règle(s) {', '.join(r['title'] for r in producteurs)} non connectée(s) aux sources du site")
            else:
                e["streams"] = ids
                e["regles_socle"] = [r["title"] for r in producteurs]
        if e["etat"] == "active" and d.get("lookup_requis") and d["lookup_requis"] not in tables:
            e.update(etat="desactivee", raison=f"table {d['lookup_requis']} absente (appliquer-regles la crée)")
        if e["etat"] == "active" and d.get("ti"):
            if not ti_actif:
                e.update(etat="non_creee", raison="threat intel non activée par le site")
            else:
                n = lignes_csv(next(lk for lk in cat["lookups"] if lk["nom"] == d["ti"])["csv"])
                if n == 0:
                    e.update(etat="desactivee", raison=f"table {d['ti']} vide (flux non alimenté : clé abuse.ch absente ou source en échec)")
                e["ti_entrees"] = n
        if e["etat"] == "active":
            manquants = [n for n in d.get("parametres", []) if not _liste(p, n)]
            if manquants:
                e.update(etat="desactivee", raison="paramètre(s) de site non renseigné(s) : " + ", ".join(manquants))
        if e["etat"] == "active" and d.get("temoins"):
            vus = 0
            for champ, valeurs in d["temoins"].items():
                q = f"{champ}:(" + " OR ".join(_q(v) for v in valeurs) + ")"
                vus += cl.compter(src["index"], q, jours)
            e["temoins_vus"] = vus
            if vus == 0:
                e.update(etat="desactivee", raison="aucun événement témoin (" + "; ".join(f"{c}={','.join(v)}" for c, v in d["temoins"].items())
                         + f") reçu en {jours} j : audit ou filtre de collecte à vérifier")
        res.append(e)
    return {"sources": actives, "ti": ti_actif, "detections": res}


def lignes_csv(chemin):
    try:
        with open(chemin, encoding="utf-8") as f:
            return max(0, sum(1 for _ in f) - 1)
    except OSError:
        return 0


# ----------------------------------------------------------------------------- état et objets
def etat_lire():
    try:
        return charger(ETAT)
    except (OSError, ValueError):
        return {"lookups": [], "regles": {}, "pipelines": {}, "connexions": {}, "definitions": {}}


def etat_ecrire(e):
    ETAT.parent.mkdir(parents=True, exist_ok=True)
    t = ETAT.with_suffix(".tmp")
    t.write_text(json.dumps(e, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(t, ETAT)


def assurer_lookup(cl, lk, etat, simuler):
    tables = {t["name"]: t for t in cl.api("GET", "/system/lookup/tables?per_page=500")["lookup_tables"]}
    if lk["nom"] in tables:
        return f"{lk['nom']} existe"
    if simuler:
        return f"{lk['nom']} serait créée ({lk['csv']})"
    csv = Path(lk["csv"])
    if not csv.exists():
        csv.parent.mkdir(parents=True, exist_ok=True)
        csv.write_text(lk["entete"] + "\n", encoding="utf-8")
        os.chmod(csv, 0o640)
        try:
            import grp
            os.chown(csv, 0, grp.getgrnam("graylog").gr_gid)
            os.chown(csv.parent, 0, grp.getgrnam("graylog").gr_gid)
        except (KeyError, OSError):
            pass
    adapters = {a["name"]: a for a in cl.api("GET", "/system/lookup/adapters?per_page=500")["data_adapters"]}
    caches = {c["name"]: c for c in cl.api("GET", "/system/lookup/caches?per_page=500")["caches"]}
    cree = {"nom": lk["nom"]}
    if lk["adaptateur"] in adapters:
        aid = adapters[lk["adaptateur"]]["id"]
    else:
        aid = cl.api("POST", "/system/lookup/adapters", {
            "title": lk["adaptateur"], "description": "omni-site-detections", "name": lk["adaptateur"],
            "custom_error_ttl_enabled": False, "custom_error_ttl": None, "custom_error_ttl_unit": None,
            "config": {"type": "csvfile", "path": lk["csv"], "separator": ",", "quotechar": "\"",
                       "key_column": lk["cle"], "value_column": lk["valeur"], "check_interval": 60,
                       "case_insensitive_lookup": True, "cidr_lookup": False}})["id"]
        cree["adaptateur"] = aid
    if lk["cache"] in caches:
        cid = caches[lk["cache"]]["id"]
    else:
        cid = cl.api("POST", "/system/lookup/caches", {
            "title": lk["cache"], "description": "omni-site-detections", "name": lk["cache"],
            "config": {"type": "guava_cache", "max_size": 20000, "expire_after_access": 600,
                       "expire_after_access_unit": "SECONDS", "expire_after_write": 0, "expire_after_write_unit": None}})["id"]
        cree["cache"] = cid
    cree["table"] = cl.api("POST", "/system/lookup/tables", {
        "title": lk["nom"], "description": "omni-site-detections", "name": lk["nom"], "cache_id": cid, "data_adapter_id": aid,
        "default_single_value": "", "default_single_value_type": "NULL", "default_multi_value": "", "default_multi_value_type": "NULL"})["id"]
    etat["lookups"].append(cree)
    return f"{lk['nom']} créée"


def corps_entree_gelf(ci):
    e = ci["entree"]
    return {"title": e["titre"], "type": "org.graylog2.inputs.gelf.http.GELFHttpInput", "global": True,
            "configuration": {"bind_address": e["bind"], "port": e["port"], "recv_buffer_size": 1048576, "enable_bulk_receiving": True,
                              "enable_cors": False, "max_chunk_size": 65536, "idle_writer_timeout": 60, "override_source": None,
                              "decompress_size_limit": 8388608}}


def corps_index_set(ci):
    i = ci["index_set"]
    return {"title": i["titre"], "description": "omni-site-detections (chaîne interne : tri, robots)", "index_prefix": i["prefixe"],
            "shards": 1, "replicas": 0,
            "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
            "rotation_strategy": {"type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig", "rotation_period": "P1D",
                                  "rotate_empty_index_set": False},
            "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
            "retention_strategy": {"type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
                                   "max_number_of_indices": i["retention_jours"]},
            "index_analyzer": "standard", "index_optimization_max_num_segments": 1, "index_optimization_disabled": False,
            "field_type_refresh_interval": 5000, "writable": True,
            "creation_date": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")}


def corps_stream(ci, index_set_id, entree_id):
    return {"title": ci["stream"]["titre"], "description": "omni-site-detections : messages GELF internes (tri, robots), hors M365",
            "index_set_id": index_set_id, "matching_type": "AND", "remove_matches_from_default_stream": True,
            "rules": [{"field": "gl2_source_input", "type": 1, "value": entree_id, "inverted": False, "description": "entrée GELF interne"},
                      {"field": "event_source", "type": 2, "value": ci["stream"]["exclure_event_source"], "inverted": True,
                       "description": "M365 a son propre stream"}]}


def assurer_chaine_interne(cl, ci, etat, simuler):
    journal = []
    entrees = cl.api("GET", "/system/inputs")["inputs"]
    port = ci["entree"]["port"]
    e = next((x for x in entrees if x["type"].endswith("GELFHttpInput") and int(x.get("attributes", {}).get("port", 0)) == port), None)
    if e:
        eid = e["id"]
        journal.append(f"entrée GELF {port} existe ({e['title']})")
    elif simuler:
        eid = None
        journal.append(f"entrée GELF {ci['entree']['bind']}:{port} serait créée")
    else:
        eid = cl.api("POST", "/system/inputs", corps_entree_gelf(ci))["id"]
        etat.setdefault("chaine", {})["entree"] = eid
        etat_ecrire(etat)
        journal.append(f"entrée GELF {ci['entree']['bind']}:{port} créée")
    sets = cl.api("GET", "/system/indices/index_sets?limit=500")["index_sets"]
    iset = next((x for x in sets if x["index_prefix"] == ci["index_set"]["prefixe"]), None)
    if iset:
        isid = iset["id"]
        journal.append(f"index set {ci['index_set']['prefixe']} existe")
    elif simuler:
        isid = None
        journal.append(f"index set {ci['index_set']['prefixe']} serait créé")
    else:
        isid = cl.api("POST", "/system/indices/index_sets", corps_index_set(ci))["id"]
        etat.setdefault("chaine", {})["index_set"] = isid
        etat_ecrire(etat)
        journal.append(f"index set {ci['index_set']['prefixe']} créé")
    st = next((x for x in cl.api("GET", "/streams")["streams"] if x["title"] == ci["stream"]["titre"]), None)
    if st:
        journal.append(f"stream « {st['title']} » existe")
    elif simuler:
        journal.append(f"stream « {ci['stream']['titre']} » serait créé")
    else:
        # Graylog 7 : création d'entité partageable = enveloppe {"entity": …}
        sid = cl.api("POST", "/streams", {"entity": corps_stream(ci, isid, eid)})["stream_id"]
        etat.setdefault("chaine", {})["stream"] = sid
        etat_ecrire(etat)
        cl.api("POST", f"/streams/{sid}/resume")
        journal.append(f"stream « {ci['stream']['titre']} » créé et démarré")
    return journal


def regles_voulues(cat, site, pl):
    """(titre, source, pipeline, streams) des règles à poser selon le plan."""
    p = parametres(site)
    sorties = []
    for d in cat["detections"]:
        stream = pl["sources"].get(d["source"], {}).get("stream")
        if "condition" in d and stream:
            # La règle est posée même si la définition reste désactivée : elle n'écrit que des champs v5_*.
            sorties.append((nom_regle(d), source_regle(d, p), PIPELINE_DETECTIONS, [stream]))
    if pl["ti"]:
        for r in cat["ti_regles"]:
            s = pl["sources"].get(r["source"], {})
            if s.get("stream"):
                sorties.append((f"omni-v5-{r['id']}", source_regle_ti(r, p), PIPELINE_TI, [s["stream"]]))
    return sorties


def appliquer_regles(cat, site, cl, simuler):
    pl = plan(cat, site, cl)
    etat = etat_lire()
    journal = assurer_chaine_interne(cl, cat["chaine_interne"], etat, simuler)
    for lk in cat["lookups"]:
        if lk.get("toujours") or (lk.get("ti") and pl["ti"]):
            journal.append(assurer_lookup(cl, lk, etat, simuler))
    voulues = regles_voulues(cat, site, pl)
    existantes = {r["title"]: r for r in cl.api("GET", "/system/pipelines/rule")}
    for titre, src, _, _ in voulues:
        verif = cl.api("POST", "/system/pipelines/rule/parse", {"title": titre, "description": "", "source": src})
        if verif.get("errors"):
            raise SystemExit(f"règle {titre} refusée par Graylog : {verif['errors']}")
        if simuler:
            journal.append(f"règle {titre} {'à mettre à jour' if titre in existantes else 'à créer'}")
            continue
        corps = {"title": titre, "description": "omni-site-detections", "source": src}
        if titre in existantes:
            if existantes[titre]["source"].strip() != src.strip():
                if titre not in etat["regles"]:
                    raise SystemExit(f"règle {titre} existante non créée par cet outil : arrêt")
                cl.api("PUT", f"/system/pipelines/rule/{existantes[titre]['id']}", dict(corps, id=existantes[titre]["id"]))
                journal.append(f"règle {titre} mise à jour")
        else:
            etat["regles"][titre] = cl.api("POST", "/system/pipelines/rule", corps)["id"]
            journal.append(f"règle {titre} créée")
        etat_ecrire(etat)
    pipes = {p["title"]: p for p in cl.api("GET", "/system/pipelines/pipeline")}
    for nom_p, etape in ((PIPELINE_TI, ETAPE_TI), (PIPELINE_DETECTIONS, ETAPE_DETECTIONS)):
        titres = [t for t, _, pp, _ in voulues if pp == nom_p]
        if not titres:
            continue
        src = f'pipeline "{nom_p}"\nstage {etape} match either\n' + "".join(f'rule "{t}"\n' for t in titres) + "end"
        streams = sorted({s for t, _, pp, st in voulues if pp == nom_p for s in st})
        if simuler:
            journal.append(f"pipeline {nom_p} : {len(titres)} règle(s), {len(streams)} stream(s)")
            continue
        if nom_p in pipes:
            if nom_p not in etat["pipelines"]:
                raise SystemExit(f"pipeline {nom_p} existant non créé par cet outil : arrêt")
            pid = pipes[nom_p]["id"]
            cl.api("PUT", f"/system/pipelines/pipeline/{pid}", {"id": pid, "title": nom_p, "description": "omni-site-detections", "source": src})
        else:
            pid = cl.api("POST", "/system/pipelines/pipeline", {"title": nom_p, "description": "omni-site-detections", "source": src})["id"]
            etat["pipelines"][nom_p] = pid
        etat_ecrire(etat)
        for sid in streams:
            conn = next((c for c in cl.api("GET", "/system/pipelines/connections") if c["stream_id"] == sid), None)
            ids = list(conn["pipeline_ids"]) if conn else []
            if pid not in ids:
                cl.api("POST", "/system/pipelines/connections/to_stream", {"stream_id": sid, "pipeline_ids": ids + [pid]})
                etat["connexions"].setdefault(sid, []).append(pid)
                etat_ecrire(etat)
        journal.append(f"pipeline {nom_p} : {len(titres)} règle(s) sur {len(streams)} stream(s)")
    return journal


# ----------------------------------------------------------------------------- rejeu
def simuler_message(cl, stream, champs, ident):
    msg = {k: v for k, v in champs.items() if not k.startswith("gl2_") and k not in ("streams",)}
    msg["_id"] = ident
    msg.setdefault("message", "rejeu omni-site-detections")
    msg.setdefault("source", "rejeu")
    r = cl.api("POST", "/system/pipelines/simulate", {"stream_id": stream, "message": msg})
    sortie = {}
    for m in r.get("messages", []):
        # Graylog 7 : {"messages": [{"message": {champs…}, "decoration_stats": …}]}
        sortie.update(m["message"] if isinstance(m.get("message"), dict) else m.get("fields", m))
    return sortie


def planificateur(evenements, d):
    """evenements : [(epoch, entite, valeur_serie)] -> liste des notifications (epoch, entite)."""
    if not evenements:
        return []
    w, pas, grace = d["fenetre_min"] * 60, d["pas_min"] * 60, d["grace_min"] * 60
    seuil = d.get("seuil", 1)
    carte = bool(d.get("serie"))
    evenements.sort()
    t, fin = evenements[0][0], evenements[-1][0] + w
    t = t - (t % pas) + pas
    dernier, notifs, i0 = {}, [], 0
    while t <= fin:
        while i0 < len(evenements) and evenements[i0][0] < t - w:
            i0 += 1
        groupes = {}
        for ts, ent, val in evenements[i0:]:
            if ts >= t:
                break
            groupes.setdefault(ent, []).append(val)
        for ent, vals in groupes.items():
            n = len(set(vals)) if carte else len(vals)
            if n >= seuil and t - dernier.get(ent, -1e18) >= grace:
                dernier[ent] = t
                notifs.append((t, ent))
        t += pas
    return notifs


def resume_notifs(notifs):
    jours = {}
    for t, _ in notifs:
        j = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d")
        jours[j] = jours.get(j, 0) + 1
    return {"notifications": len(notifs), "max_par_jour": max(jours.values()) if jours else 0, "par_jour": jours,
            "exemples": [{"t": dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(), "entite": e} for t, e in notifs[:10]]}


def epoch(ts):
    s = str(ts).replace(" ", "T")
    if not s.endswith("Z") and "+" not in s[10:]:
        s += "+00:00"
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def rejeu(cat, site, cl, jours, plafond_msgs, seulement=None):
    pl = plan(cat, site, cl, jours)
    etats = {e["id"]: e for e in pl["detections"]}
    p = parametres(site)
    sortie = {"date": dt.datetime.now(dt.timezone.utc).isoformat(), "jours": jours, "detections": {}}
    for d in cat["detections"]:
        if seulement and d["id"] not in seulement:
            continue
        e = etats[d["id"]]
        if e["etat"] == "non_creee":
            continue
        src = pl["sources"][d["source"]]
        r = {"etat_plan": e["etat"], "raison_plan": e.get("raison")}
        try:
            if "condition" in d:
                r.update(rejeu_regle(cl, d, p, src, jours, plafond_msgs))
            else:
                r.update(rejeu_requete(cl, d, e, src, jours))
        except Exception as ex:
            r["erreur"] = repr(ex)[:300]
        sortie["detections"][d["id"]] = r
        print(f"{d['id']:<28} {json.dumps({k: r.get(k) for k in ('candidats', 'etiquetes', 'notifications', 'max_par_jour', 'exemples_ok', 'erreur')}, ensure_ascii=False)}", flush=True)
    return sortie


def rejeu_regle(cl, d, p, src, jours, plafond):
    stream, idx = src["stream"], src["index"]
    r = {"exemples_ok": True}
    v5 = tag(d)
    for sens, attendu in (("positif", True), ("negatif", False)):
        out = simuler_message(cl, stream, rendre_exemple(d["exemples"][sens], p), f"omni-site-detections-{d['id']}-{sens}")
        ok = (out.get("v5_tag") == v5) == attendu
        r[f"exemple_{sens}"] = "ok" if ok else f"KO (v5_tag={out.get('v5_tag')!r})"
        r["exemples_ok"] &= ok
    pref = rendre(d["rejeu"]["prefiltre"], p)
    q = {"bool": {"filter": [{"query_string": {"query": pref}}, {"range": {"timestamp": {"gte": f"now-{jours}d"}}}]}}
    total = cl.os("POST", f"/{idx}/_count", {"query": q})["count"]
    r["candidats"] = total
    evts, exemples = [], []
    champ_serie = d.get("serie", {}).get("champ")
    # Couverture : un champ testé par has_field() absent de TOUS les candidats rend la détection muette
    requis = re.findall(r'has_field\("([A-Za-z0-9_]+)"\)', source_regle(d, p))
    absents = dict.fromkeys(requis, 0)
    if total <= plafond:
        docs = cl.os("POST", f"/{idx}/_search", {"size": total, "query": q, "sort": [{"timestamp": "asc"}]})["hits"]["hits"]
        r["mode"] = "message par message"
        for h in docs:
            out = simuler_message(cl, stream, h["_source"], h["_id"])
            for c in requis:
                if out.get(c) in (None, ""):
                    absents[c] += 1
            if out.get("v5_tag") == v5:
                evts.append((epoch(h["_source"]["timestamp"]), out.get("v5_entite"), h["_source"].get(champ_serie) if champ_serie else h["_id"]))
                if len(exemples) < 10:
                    exemples.append({"t": h["_source"]["timestamp"], "entite": out.get("v5_entite"), "detail": out.get("v5_detail")})
    else:
        cles = d["rejeu"].get("echantillon")
        if not cles:
            raise ValueError(f"{total} candidats > plafond {plafond} sans clé d'échantillonnage")
        r["mode"] = "un message par combinaison de " + ", ".join(cles)
        apres = None
        n_buckets = 0
        while True:
            comp = {"size": 500, "sources": [{c: {"terms": {"field": c, "missing_bucket": True}}} for c in cles]}
            if apres:
                comp["after"] = apres
            res = cl.os("POST", f"/{idx}/_search", {"size": 0, "query": q, "aggs": {"c": {"composite": comp, "aggs": {"un": {"top_hits": {"size": 1}}}}}})["aggregations"]["c"]
            for b in res["buckets"]:
                n_buckets += 1
                if n_buckets > plafond:
                    raise ValueError(f"plus de {plafond} combinaisons distinctes")
                h = b["un"]["hits"]["hits"][0]
                out = simuler_message(cl, stream, h["_source"], h["_id"])
                if out.get("v5_tag") != v5:
                    continue
                filtre = [q] + [{"term": {c: v}} for c, v in b["key"].items() if v is not None]
                docs = cl.os("POST", f"/{idx}/_search", {"size": 10000, "_source": ["timestamp"] + ([champ_serie] if champ_serie else []),
                                                         "query": {"bool": {"filter": filtre}}})["hits"]["hits"]
                for x in docs:
                    evts.append((epoch(x["_source"]["timestamp"]), out.get("v5_entite"), x["_source"].get(champ_serie) if champ_serie else x["_id"]))
                if len(exemples) < 10:
                    exemples.append({"t": h["_source"]["timestamp"], "entite": out.get("v5_entite"), "detail": out.get("v5_detail"), "messages": len(docs)})
            apres = res.get("after_key")
            if not apres or not res["buckets"]:
                break
        r["combinaisons"] = n_buckets
    if r["mode"] == "message par message" and total:
        r["champs_absents_partout"] = [c for c, n in absents.items() if n == total]
    r["etiquetes"] = len(evts)
    r["etiquetes_exemples"] = exemples
    r.update(resume_notifs(planificateur(evts, d)))
    return r


def rejeu_requete(cl, d, e, src, jours):
    """Étiquettes du socle ou champs TI déjà présents dans l'index : rejeu direct sur les messages stockés."""
    q = requete(d)
    streams = e.get("streams") or [src["stream"]]
    filtre = {"bool": {"filter": [{"query_string": {"query": q}}, {"range": {"timestamp": {"gte": f"now-{jours}d"}}}, {"terms": {"streams": streams}}]}}
    champ = regroupement(d)[0]
    docs = cl.os("POST", "/*/_search", {"size": 10000, "_source": ["timestamp", champ], "query": filtre})["hits"]["hits"]
    evts = [(epoch(h["_source"]["timestamp"]), str(h["_source"].get(champ)), h["_id"]) for h in docs]
    r = {"mode": "messages stockés", "candidats": len(docs), "etiquetes": len(docs)}
    r.update(resume_notifs(planificateur(evts, d)))
    return r


def charger_cles(chemin):
    try:
        with open(chemin, encoding="utf-8") as f:
            return [ligne.split(",", 1)[0].strip() for i, ligne in enumerate(f) if i and ligne.strip()]
    except OSError:
        return []


def rejeu_ti(cat, site, cl, jours, plafond):
    """Recherche rétroactive : les indicateurs des tables TI sont cherchés dans les messages conservés (champs
    déclarés par champs_rejeu), chaque message trouvé passe dans le simulateur de pipeline (enrichissement réel),
    puis la requête de chaque définition TI est évaluée et le planificateur rejoué."""
    pl = plan(cat, site, cl, jours)
    lk = {x["nom"]: x for x in cat["lookups"]}
    simules, regles = {}, {}
    for r in cat["ti_regles"]:
        src = pl["sources"].get(r["source"], {})
        cles = charger_cles(lk[r["lookup"]]["csv"])
        if not src.get("stream") or not cles:
            continue
        idx = cat["sources"][r["source"]]["index"]
        vus = {}
        for champ in r["champs_rejeu"]:
            for i in range(0, len(cles), 1000):
                lot = cles[i:i + 1000] if champ != "message" else [c.lower() for c in cles[i:i + 1000]]
                q = {"bool": {"filter": [{"terms": {champ: lot}}, {"range": {"timestamp": {"gte": f"now-{jours}d"}}}]}}
                for h in cl.os("POST", f"/{idx}/_search", {"size": plafond, "query": q, "sort": [{"timestamp": "desc"}]})["hits"]["hits"]:
                    vus[h["_id"]] = h
        enrichis = 0
        for h in list(vus.values())[:plafond]:
            out = simuler_message(cl, src["stream"], h["_source"], h["_id"])
            if out.get("ti_tag"):
                enrichis += 1
                simules.setdefault(r["source"], {})[h["_id"]] = (h["_source"]["timestamp"], out)
        regles[r["id"]] = {"messages": len(vus), "simules": min(len(vus), plafond), "enrichis": enrichis}
        print(f"{r['id']:<24} {regles[r['id']]}", flush=True)
    det = {}
    for d in cat["detections"]:
        if not d.get("ti"):
            continue
        msgs = simules.get(d["source"], {})
        champ = regroupement(d)[0]
        retenus = [(ts, out) for ts, out in msgs.values() if correspond(requete(d), out)]
        evts = [(epoch(ts), str(out.get(champ)), i) for i, (ts, out) in enumerate(retenus)]
        r = {"mode": "rétro TI (simulateur)", "candidats": len(msgs), "etiquetes": len(evts), "exemples_ok": True,
             "etiquetes_exemples": [{"t": ts, "ti_match": o.get("ti_match"), "ti_source": o.get("ti_source"), "ti_malware": o.get("ti_malware"),
                                     "ti_confiance": o.get("ti_confiance"), "action": o.get("action"), "src_ip": o.get("src_ip"),
                                     "dest_ip": o.get("dest_ip"), "dest_port": o.get("dest_port"), "source": o.get("source")} for ts, o in retenus[:15]]}
        r.update(resume_notifs(planificateur(evts, d)))
        det[d["id"]] = r
        print(f"{d['id']:<24} {json.dumps({k: r[k] for k in ('candidats', 'etiquetes', 'notifications', 'max_par_jour')})}", flush=True)
    return {"date": dt.datetime.now(dt.timezone.utc).isoformat(), "jours": jours, "regles_ti": regles, "detections": det}


# ----------------------------------------------------------------------------- définitions
def entite_definition(cat, d, e, notif_id, raison=None, preuve=None):
    serie = d.get("serie")
    sid = f"{serie['type']}({serie['champ']})" if serie else "count()"
    desc = f"{d['gravite']} ({d['mitre']}) - {d['description']}"
    if preuve:
        desc += f" Rejeu : {preuve}."
    if raison:
        desc += f" DÉSACTIVÉE : {raison}."
    desc += " Déployée par tools/omni-site-detections.py."
    return {
        "title": d["titre"], "description": desc[:2000], "priority": GRAVITES[d["gravite"]], "alert": True,
        "config": {"type": "aggregation-v1", "query": requete(d), "query_parameters": [], "filters": [], "streams": e["streams"],
                   "group_by": regroupement(d),
                   "series": [{"id": sid, "type": serie["type"] if serie else "count", "field": serie["champ"] if serie else None}],
                   "conditions": {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": sid},
                                                 "right": {"expr": "number", "value": float(d.get("seuil", 1))}}},
                   "search_within_ms": d["fenetre_min"] * 60000, "execute_every_ms": d["pas_min"] * 60000,
                   "use_cron_scheduling": False, "cron_expression": None, "cron_timezone": None, "event_limit": 100},
        "field_spec": {}, "key_spec": [],
        "notification_settings": {"grace_period_ms": d["grace_min"] * 60000, "backlog_size": 10},
        "notifications": [{"notification_id": notif_id, "notification_parameters": None}],
        "storage": [{"type": "persist-to-streams-v1", "streams": [STREAM_EVENTS]}],
    }


def decision(cat, d, e, rj, plafond=None):
    """(planifier: bool, raison|None, preuve|None). plafond : déclenchements par jour (défaut : catalogue)."""
    plafond = plafond if plafond is not None else cat["plafond_par_jour"]
    if e["etat"] != "active":
        return False, e.get("raison"), None
    r = (rj or {}).get("detections", {}).get(d["id"])
    if not r:
        return False, "rejeu absent", None
    if r.get("erreur"):
        return False, f"rejeu en erreur ({r['erreur'][:120]})", None
    if "condition" in d and not r.get("exemples_ok"):
        return False, "exemples synthétiques en échec au simulateur", None
    preuve = f"{r.get('candidats', 0)} candidats, {r.get('etiquetes', 0)} étiquetés, {r.get('notifications', 0)} notifications en {rj['jours']} j (max {r.get('max_par_jour', 0)}/jour)"
    if r.get("champs_absents_partout"):
        return False, ("champ(s) " + ", ".join(r["champs_absents_partout"]) + " absent(s) de tous les événements candidats : "
                       "la source ne les produit pas, la détection serait muette"), preuve
    if r.get("max_par_jour", 0) > plafond:
        return False, f"plus de {plafond} déclenchements par jour au rejeu", preuve
    return True, None, preuve


def appliquer_definitions(cat, site, cl, rj, simuler, seulement=None, plafond=None):
    pl = plan(cat, site, cl)
    etat = etat_lire()
    notif = next((n for n in cl.api("GET", "/events/notifications?per_page=200")["notifications"] if n["title"] == site["notification"]), None)
    if not notif:
        raise SystemExit(f"notification « {site['notification']} » introuvable")
    existantes = {x["title"]: x for x in cl.api("GET", "/events/definitions?per_page=1000")["event_definitions"]}
    journal = []
    for d, e in zip(cat["detections"], pl["detections"]):
        if seulement and d["id"] not in seulement:
            continue
        if e["etat"] == "non_creee":
            journal.append(f"NON CRÉÉE  {d['titre']} : {e['raison']}")
            continue
        if not e.get("streams"):
            e["streams"] = [pl["sources"][d["source"]]["stream"]]
        planif, raison, preuve = decision(cat, d, e, rj, plafond)
        corps = entite_definition(cat, d, e, notif["id"], raison, preuve)
        libelle = ("PLANIFIÉE  " if planif else "DÉSACTIVÉE ") + d["titre"] + (f" : {raison}" if raison else "")
        if simuler:
            journal.append(libelle)
            continue
        if d["titre"] in existantes:
            did = existantes[d["titre"]]["id"]
            if did not in etat["definitions"].values():
                raise SystemExit(f"définition « {d['titre']} » existante non créée par cet outil : arrêt")
            cl.api("PUT", f"/events/definitions/{did}?schedule=false", {"entity": dict(corps, id=did)})
        else:
            did = cl.api("POST", "/events/definitions?schedule=false", {"entity": corps})["id"]
            etat["definitions"][d["id"]] = did
            etat_ecrire(etat)
        cl.api("PUT", f"/events/definitions/{did}/{'schedule' if planif else 'unschedule'}")
        journal.append(libelle + f" [{did}]")
    return journal


# ----------------------------------------------------------------------------- vérification après déploiement
def verifier(cat, site, cl, jours=7):
    defauts = []
    streams, regles, pipelines, connexions, tables = inventaire(cl)
    par_id = {s["id"]: s for s in streams.values()}
    liste = cl.api("GET", "/events/definitions?per_page=1000")
    defs = {x["title"]: x for x in liste["event_definitions"]}
    sched = liste.get("context", {}).get("scheduler", {})
    p = parametres(site)
    pl = plan(cat, site, cl)
    rapport = []
    for d, e in zip(cat["detections"], pl["detections"]):
        x = defs.get(d["titre"])
        if not x:
            continue
        actif = (sched.get(x["id"]) or {}).get("is_scheduled", False)
        ligne = {"id": d["id"], "definition": x["id"], "planifiee": actif, "defauts": []}
        if actif:
            for sid in x["config"]["streams"]:
                s = par_id.get(sid)
                if not s or s.get("disabled"):
                    ligne["defauts"].append(f"stream {sid} absent ou désactivé")
                    continue
                idx = cat["sources"][d["source"]]["index"]
                if cl.compter("*", "*", 1, [sid]) == 0:
                    ligne["defauts"].append(f"stream « {s['title']} » sans message depuis 24 h")
                if "condition" in d:
                    titre = nom_regle(d)
                    if sid not in streams_connectes(titre, pipelines, connexions):
                        ligne["defauts"].append(f"règle {titre} non connectée au stream « {s['title']} »")
                    # Champs décisifs (condition) seulement : ceux du libellé ou de l'entité n'existent
                    # souvent que dans l'événement détecté lui-même (ex. MemberName d'un 4728 encore jamais vu).
                    a_lire = champs_lus(rendre(d["condition"], p))
                elif d.get("tag"):
                    a_lire = set()
                    if not any(sid in streams_connectes(r, pipelines, connexions) for r in e.get("regles_socle", [])):
                        ligne["defauts"].append(f"aucune règle du socle posant alert_tag:{d['tag']} connectée au stream")
                else:
                    a_lire = champs_requete(requete(d)) - set(cat["champs_produits"])
                for c in sorted(a_lire - {"event_source"}):
                    if cl.compter(idx, f"_exists_:{c}", jours, [sid]) == 0:
                        ligne["defauts"].append(f"champ {c} jamais produit par la source en {jours} j")
                if d.get("ti"):
                    lk = next(lk for lk in cat["lookups"] if lk["nom"] == d["ti"])
                    if d["ti"] not in tables or lignes_csv(lk["csv"]) == 0:
                        ligne["defauts"].append(f"table {d['ti']} absente ou vide")
        defauts += [f"{d['id']}: {m}" for m in ligne["defauts"]]
        rapport.append(ligne)
    # Chaîne interne : sans elle, les décisions du tri (dont le rodage) n'atteignent pas le récapitulatif
    ci = cat["chaine_interne"]
    etats_entrees = {s["id"]: s["state"] for s in cl.api("GET", "/system/inputstates")["states"]}
    gelf = [x for x in cl.api("GET", "/system/inputs")["inputs"]
            if x["type"].endswith("GELFHttpInput") and int(x.get("attributes", {}).get("port", 0)) == ci["entree"]["port"]]
    if not gelf or etats_entrees.get(gelf[0]["id"]) != "RUNNING":
        defauts.append(f"chaîne interne : aucune entrée GELF en service sur le port {ci['entree']['port']}")
    st = streams.get(ci["stream"]["titre"])
    if not st or st.get("disabled"):
        defauts.append(f"chaîne interne : stream « {ci['stream']['titre']} » absent ou arrêté")
    # Toute table lue par une règle connectée doit exister (sinon un avertissement par message dans server.log)
    connectees = {pid for c in connexions for pid in c.get("pipeline_ids", [])}
    actives = set()
    for pp in pipelines:
        if pp["id"] in connectees:
            actives |= set(re.findall(r'rule\s+"([^"]+)"', pp.get("source", "")))
    for r in regles:
        if r["title"] not in actives:
            continue
        for t in set(re.findall(r'lookup_value\(\s*"([^"]+)"', r["source"])) | set(re.findall(r'lookup\(\s*"([^"]+)"', r["source"])):
            if t not in tables:
                defauts.append(f"règle {r['title']} : table de correspondance {t} inexistante")
    return rapport, defauts


def mesure(cl, site, minutes):
    res = {}
    for nom, conf in (site.get("sources") or {}).items():
        if not conf:
            continue
        s = next((x for x in cl.api("GET", "/streams")["streams"] if x["title"] == conf["stream"]), None)
        if not s:
            continue
        r = cl.os("POST", "/*/_search", {"size": 0, "query": {"bool": {"filter": [{"term": {"streams": s["id"]}}, {"range": {"timestamp": {"gte": f"now-{minutes}m"}}}]}},
                                         "aggs": {"m": {"avg": {"field": "gl2_processing_duration_ms"}}, "p": {"percentiles": {"field": "gl2_processing_duration_ms", "percents": [50, 95, 99]}}}})
        res[nom] = {"messages": r["hits"]["total"]["value"], "moyenne_ms": round(r["aggregations"]["m"]["value"] or 0, 2),
                    "p50_p95_p99": [round(v or 0, 1) for v in r["aggregations"]["p"]["values"].values()]}
    return res


# ----------------------------------------------------------------------------- retour
def retour(cl, simuler):
    etat = etat_lire()
    journal = []
    for did in list(etat["definitions"].values()):
        journal.append(f"définition {did}")
        if not simuler:
            try:
                cl.api("PUT", f"/events/definitions/{did}/unschedule")
                cl.api("DELETE", f"/events/definitions/{did}")
            except urllib.error.HTTPError as ex:
                journal.append(f"  {ex.code}")
    for sid, pids in etat["connexions"].items():
        journal.append(f"déconnexion {pids} de {sid}")
        if not simuler:
            conn = next((c for c in cl.api("GET", "/system/pipelines/connections") if c["stream_id"] == sid), None)
            if conn:
                cl.api("POST", "/system/pipelines/connections/to_stream", {"stream_id": sid, "pipeline_ids": [x for x in conn["pipeline_ids"] if x not in pids]})
    for nom, pid in etat["pipelines"].items():
        journal.append(f"pipeline {nom} {pid}")
        if not simuler:
            cl.api("DELETE", f"/system/pipelines/pipeline/{pid}")
    for nom, rid in etat["regles"].items():
        journal.append(f"règle {nom} {rid}")
        if not simuler:
            cl.api("DELETE", f"/system/pipelines/rule/{rid}")
    for lk in etat["lookups"]:
        journal.append(f"table {lk}")
        if not simuler:
            for cle, chemin in (("table", "tables"), ("cache", "caches"), ("adaptateur", "adapters")):
                if lk.get(cle):
                    cl.api("DELETE", f"/system/lookup/{chemin}/{lk[cle]}")
    ch = etat.get("chaine", {})
    for cle, chemin in (("stream", "/streams/{}"), ("index_set", "/system/indices/index_sets/{}?delete_indices=true"), ("entree", "/system/inputs/{}")):
        if ch.get(cle):
            journal.append(f"chaîne interne : {cle} {ch[cle]}")
            if not simuler:
                cl.api("DELETE", chemin.format(ch[cle]))
    if not simuler:
        etat_ecrire({"lookups": [], "regles": {}, "pipelines": {}, "connexions": {}, "definitions": {}})
    return journal


# ----------------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("commande", choices=["valider", "plan", "appliquer-regles", "rejeu", "rejeu-ti", "appliquer-definitions", "verifier", "mesure", "retour"])
    ap.add_argument("--plafond-jour", type=int, help="déclenchements par jour tolérés au rejeu (défaut : catalogue)")
    ap.add_argument("--catalogue", default=str(CATALOGUE))
    ap.add_argument("--site", default=str(SITE))
    ap.add_argument("--simuler", action="store_true")
    ap.add_argument("--jours", type=int, default=30)
    ap.add_argument("--plafond-messages", type=int, default=3000)
    ap.add_argument("--rejeu-fichier", default="/var/lib/omni-siem/site-detections-rejeu.json")
    ap.add_argument("--seulement", nargs="*")
    ap.add_argument("--minutes", type=int, default=30)
    a = ap.parse_args(argv)
    cat = charger(a.catalogue)
    if a.commande == "valider":
        exemple = charger(Path(a.catalogue).parent / "site.exemple.json")
        err = valider(cat, exemple)
        for x in err:
            print("ERREUR", x)
        print(f"{len(cat['detections'])} détections, {len(cat['ti_regles'])} règles TI, {len(err)} erreur(s)")
        return 1 if err else 0
    site = site_charge(a)
    cl = Client()
    if a.commande == "plan":
        print(json.dumps(plan(cat, site, cl, a.jours), ensure_ascii=False, indent=1))
    elif a.commande == "appliquer-regles":
        print("\n".join(appliquer_regles(cat, site, cl, a.simuler)))
    elif a.commande in ("rejeu", "rejeu-ti"):
        if a.commande == "rejeu":
            r = rejeu(cat, site, cl, a.jours, a.plafond_messages, a.seulement)
        else:
            r = rejeu_ti(cat, site, cl, a.jours, a.plafond_messages)
        if (a.seulement or a.commande == "rejeu-ti") and Path(a.rejeu_fichier).exists():
            ancien = charger(a.rejeu_fichier)
            ancien["detections"].update(r["detections"])
            r = dict(ancien, date=r["date"])
        Path(a.rejeu_fichier).parent.mkdir(parents=True, exist_ok=True)
        Path(a.rejeu_fichier).write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"rejeu écrit dans {a.rejeu_fichier}")
    elif a.commande == "appliquer-definitions":
        rj = charger(a.rejeu_fichier) if Path(a.rejeu_fichier).exists() else None
        print("\n".join(appliquer_definitions(cat, site, cl, rj, a.simuler, a.seulement, a.plafond_jour)))
    elif a.commande == "verifier":
        rapport, defauts = verifier(cat, site, cl)
        print(json.dumps(rapport, ensure_ascii=False, indent=1))
        for x in defauts:
            print("DÉFAUT", x)
        print(f"{sum(1 for r in rapport if r['planifiee'])} définition(s) planifiée(s), {len(defauts)} défaut(s)")
        return 1 if defauts else 0
    elif a.commande == "mesure":
        print(json.dumps(mesure(cl, site, a.minutes), ensure_ascii=False, indent=1))
    elif a.commande == "retour":
        print("\n".join(retour(cl, a.simuler)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
