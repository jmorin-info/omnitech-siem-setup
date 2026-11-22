#!/usr/bin/env python3
"""Exercice de restauration complète et chronométrée du SIEM, sur VM isolée uniquement.

  plan              garde anti-production et plan des étapes ; lecture seule (GET)
  executer          exercice complet : socle, configuration, MongoDB, snapshots
                    OpenSearch, démarrage de Graylog, contrôles de réception
  analyser          synthèse et validation d'un ou plusieurs rapports JSON
  jeu-factice       banc VM uniquement : jeu de sauvegardes factices au format de production
  sinistre-factice  banc VM uniquement : efface la base graylog et les index du laboratoire

L'exercice refuse de tourner sur la production : nom d'hôte, adresse, nom du nœud
OpenSearch, volume d'index préexistant et variable de garde OMNI_RESTORE_DRILL_ISOLATED=1.
Procédure : docs/exploitation/RESTAURATION-COMPLETE.md.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 1
GARDE_ENV = "OMNI_RESTORE_DRILL_ISOLATED"
PRODUCTION_HOTES = frozenset({"bx-it-graylog-vm"})
PRODUCTION_ADRESSES = frozenset({"10.33.220.10"})
# Domaines dont la présence dans server.conf signale une archive de production :
# l'exercice exige alors la preuve que la VM ne joint pas le réseau de production.
PRODUCTION_DOMAINES = ("omnitech.security", "omnitech-security.fr")
SEUIL_DOCS = 1_000_000
SEUIL_OCTETS = 1 << 30
OPENSEARCH = "http://127.0.0.1:9200"
DEPOT_EXERCICE = "omni_drill_ro"
MONGO_ADMIN_URI = "mongodb://admin@127.0.0.1:27017/?replicaSet=rs0&authSource=admin"
MONGO_SHELL_URI = "mongodb://127.0.0.1:27017/?replicaSet=rs0"
# Mêmes composants critiques que le contrôle de restaurabilité de 30-backup-config.sh (§3b).
MEMBRES_REQUIS = (
    "mongodump/graylog/streams.bson",
    "mongodump/graylog/pipeline_processor_pipelines.bson",
    "mongodump/graylog/pipeline_processor_rules.bson",
    "mongodump/graylog/event_definitions.bson",
    "mongodump/graylog/event_notifications.bson",
    "mongodump/graylog/inputs.bson",
    "etc/graylog/server/server.conf",
)
MEMBRES_FACULTATIFS = ("etc/graylog/lookup/mitre-attack.csv",)
# Chemins de l'archive appliqués à la VM ; le reste est seulement inventorié.
APPLIQUES = ("etc/graylog",)
COLLECTIONS_CLES = {
    "entrees": "inputs",
    "flux": "streams",
    "definitions": "event_definitions",
    "regles": "pipeline_processor_rules",
    "pipelines": "pipeline_processor_pipelines",
    "index_sets": "index_sets",
}
ETAPES_SERVICE = ("socle", "configuration", "mongodb", "opensearch", "graylog")
INDEX_EVENEMENTS = re.compile(r"^gl-(system-)?events_\d+$")
# Index techniques jamais restaurés : masqués (.) et statistiques de requêtes du greffon query insights.
INDEX_IGNORES = re.compile(r"^(\.|top_queries-)")
MOTIFS_NOMS = (
    (re.compile(r"omni-siem-config_(\d{4})-(\d{2})-(\d{2})"), "jour"),
    (re.compile(r"omni-mongo-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-[0-9a-f]{12}"), "seconde"),
    (re.compile(r"graylog-mongo-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})?"), "minute"),
    (re.compile(r"oms-sel-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})"), "minute"),
    (re.compile(r"snap-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})?"), "minute"),
    (re.compile(r"drill-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})?"), "minute"),
)
COMPTAGES_JS = ('const d=db.getSiblingDB("graylog"); const o={}; '
                'd.getCollectionNames().filter(c=>!c.startsWith("system.")).sort()'
                '.forEach(c=>o[c]=d.getCollection(c).countDocuments()); print(JSON.stringify(o));')
AUTH_JS = ('const a=db.getSiblingDB("admin").auth("admin",process.env.OMNI_MONGO_ADMIN); '
           'if(a!==1 && a.ok!==1) throw new Error("authentification refusee"); ')
UTILISATEUR_JS = (
    'const b=db.getSiblingDB(process.env.OMNI_APP_AUTHDB); const n=process.env.OMNI_APP_USER; '
    'const r=[{role:"readWrite",db:process.env.OMNI_APP_DB},{role:"dbAdmin",db:process.env.OMNI_APP_DB}]; '
    'if(b.getUser(n)){b.updateUser(n,{pwd:process.env.OMNI_APP_PASS,roles:r});print("MIS_A_JOUR");}'
    'else{b.createUser({user:n,pwd:process.env.OMNI_APP_PASS,roles:r});print("CREE");}'
)


class ErreurExercice(Exception):
    """Erreur rédigée par l'exercice : son texte ne contient jamais de secret."""


# --------------------------------------------------------------------------
# Logique pure (testée hors ligne)
# --------------------------------------------------------------------------

def adresses_ipv4(sortie_ip):
    """Adresses de `ip -o -4 addr show`."""
    return sorted(set(re.findall(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/", sortie_ip)))


def index_depuis_cat(lignes):
    """Normalise `_cat/indices?format=json&h=index,docs.count,store.size&bytes=b`."""
    resultat = []
    for ligne in lignes or []:
        nom = ligne.get("index")
        if not isinstance(nom, str):
            continue
        def entier(cle):
            valeur = ligne.get(cle)
            return int(valeur) if isinstance(valeur, (int, str)) and str(valeur).isdigit() else 0
        resultat.append({"index": nom, "docs": entier("docs.count"), "octets": entier("store.size"),
                         "sante": ligne.get("health")})
    return resultat


def motifs_refus(*, env, hostname, fqdn, adresses, noeud, index, seuil_docs=SEUIL_DOCS, seuil_octets=SEUIL_OCTETS):
    """Raisons de refuser l'exercice ; liste vide = hôte acceptable."""
    raisons = []
    if env.get(GARDE_ENV) != "1":
        raisons.append(f"variable de garde {GARDE_ENV}=1 absente")
    noms = {str(n).lower().rstrip(".").split(".")[0] for n in (hostname, fqdn) if n}
    if noms & PRODUCTION_HOTES:
        raisons.append("nom d'hôte de production")
    if set(adresses or ()) & PRODUCTION_ADRESSES:
        raisons.append("adresse IP de production présente sur l'hôte")
    if noeud is None:
        raisons.append("OpenSearch local injoignable : contrôle des index impossible")
    else:
        if str(noeud.get("name", "")).lower() in PRODUCTION_HOTES:
            raisons.append("nœud OpenSearch de production")
        utiles = [i for i in index if not i["index"].startswith(".")]
        docs = sum(i["docs"] for i in utiles)
        octets = sum(i["octets"] for i in utiles)
        if docs > seuil_docs or octets > seuil_octets:
            raisons.append(f"index préexistants : {len(utiles)} index, {docs} documents, {octets} octets "
                           f"(seuils {seuil_docs} documents / {seuil_octets} octets) ; une VM vierge est requise")
    return raisons


def lire_proprietes(texte):
    """Fichier de propriétés Graylog : la dernière occurrence d'une clé l'emporte (sémantique Java)."""
    proprietes = {}
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne[0] in "#!":
            continue
        separateur = re.search(r"\s*[=:]\s*|\s+", ligne)
        if not separateur:
            continue
        proprietes[ligne[:separateur.start()]] = ligne[separateur.end():]
    return proprietes


def neutraliser_courriel(texte):
    """Désactive le transport de courriel de Graylog dans la copie restaurée de server.conf."""
    lignes = [ligne for ligne in texte.splitlines() if not re.match(r"\s*transport_email_enabled\s*[=:\s]", ligne)]
    lignes.append("# omni-restore-drill : courriel désactivé pendant l'exercice")
    lignes.append("transport_email_enabled = false")
    return "\n".join(lignes) + "\n"


def uri_application(proprietes):
    """Utilisateur MongoDB de Graylog d'après mongodb_uri (dernière occurrence)."""
    uri = proprietes.get("mongodb_uri", "")
    parties = urllib.parse.urlsplit(uri)
    if parties.scheme != "mongodb" or not parties.username or parties.password is None:
        raise ErreurExercice("mongodb_uri restauré inexploitable (utilisateur ou mot de passe absent)")
    base = parties.path.lstrip("/") or "admin"
    options = urllib.parse.parse_qs(parties.query)
    return {"utilisateur": urllib.parse.unquote(parties.username),
            "mot_de_passe": urllib.parse.unquote(parties.password),
            "base": base, "base_auth": options.get("authSource", [base])[0]}


def adresse_graylog(proprietes):
    """URL de l'API Graylog locale d'après http_bind_address et http_enable_tls."""
    lien = proprietes.get("http_bind_address", "127.0.0.1:9000")
    hote, _, port = lien.rpartition(":")
    hote = hote.strip("[]") or "127.0.0.1"
    if hote in ("0.0.0.0", "::"):
        hote = "127.0.0.1"
    schema = "https" if proprietes.get("http_enable_tls", "false").lower() == "true" else "http"
    return f"{schema}://{hote}:{port or 9000}/api"


def archive_de_production(proprietes):
    for cle in ("http_external_uri", "http_publish_uri"):
        hote = (urllib.parse.urlsplit(proprietes.get(cle, "")).hostname or "").lower()
        if hote.split(".")[0] in PRODUCTION_HOTES or hote.endswith(PRODUCTION_DOMAINES):
            return True
    return False


def filtre_extraction(ignores):
    """Filtre tarfile « tar » ; les liens absolus ou sortants (unités systemd, sites nginx) sont ignorés et comptés."""
    def filtre(membre, destination):
        membre = tarfile.tar_filter(membre, destination)
        if membre.issym() or membre.islnk():
            racine = os.path.realpath(destination)
            base = os.path.dirname(os.path.join(racine, membre.name)) if membre.issym() else racine
            cible = os.path.realpath(os.path.join(base, membre.linkname))
            if os.path.isabs(membre.linkname) or os.path.commonpath([cible, racine]) != racine:
                ignores.append(membre.name)
                return None
        return membre
    return filtre


def instant_iso(valeur):
    instant = dt.datetime.fromisoformat(valeur)
    return instant if instant.tzinfo else instant.astimezone()


def membres_manquants(noms):
    presents = {n.lstrip("./") for n in noms}
    return [m for m in MEMBRES_REQUIS if m not in presents]


def horodatage_nom(nom, fuseau=None):
    """Horodatage d'une sauvegarde d'après son nom ; (datetime avec fuseau, précision) ou (None, None)."""
    fuseau = fuseau or dt.datetime.now().astimezone().tzinfo
    for motif, precision in MOTIFS_NOMS:
        trouve = motif.search(nom)
        if trouve:
            valeurs = [int(v) for v in trouve.groups() if v is not None]
            return dt.datetime(*valeurs, tzinfo=fuseau), precision
    return None, None


def versions_compatibles(installees, reference):
    """Écarts entre les paquets installés et stack-versions.env de l'archive."""
    ecarts = []
    def majeure(version):
        trouve = re.match(r"(\d+)\.(\d+)", version or "")
        return (int(trouve[1]), int(trouve[2])) if trouve else None
    serie = reference.get("GRAYLOG_SERIES")
    if serie and not (installees.get("graylog-server") or "").startswith(serie + "."):
        ecarts.append(f"Graylog installé {installees.get('graylog-server')} hors série {serie}")
    for paquet, cle in (("mongodb-org-server", "MONGODB_PACKAGE_VERSION"), ("opensearch", "OPENSEARCH_PACKAGE_VERSION")):
        attendu, present = majeure(reference.get(cle)), majeure(installees.get(paquet))
        if attendu and (present is None or present[0] < attendu[0] or (paquet == "opensearch" and present[0] != attendu[0])):
            ecarts.append(f"{paquet} installé {installees.get(paquet)} incompatible avec {reference.get(cle)}")
    return ecarts


def debit_mo_s(octets, secondes):
    if not octets or not secondes or secondes <= 0:
        return None
    return round(octets / 1e6 / secondes, 1)


def calcul_rto(etapes):
    """RTO mesuré : service rendu à la fin du démarrage de Graylog ; total avec les contrôles."""
    par_nom = {e["nom"]: e for e in etapes}
    valide = all(par_nom.get(n, {}).get("statut") == "ok" for n in ETAPES_SERVICE)
    service = sum(par_nom.get(n, {}).get("secondes", 0) for n in ETAPES_SERVICE)
    total = service + par_nom.get("controles", {}).get("secondes", 0)
    restauration_index = par_nom.get("opensearch", {}).get("secondes", 0)
    return {"valide": valide, "service_secondes": round(service, 1), "total_secondes": round(total, 1),
            # Déduit, non mesuré : la collecte peut reprendre avant la restauration de l'historique.
            "collecte_deduit_secondes": round(service - restauration_index, 1),
            "socle_mode": par_nom.get("socle", {}).get("mode")}


def calcul_rpo(sources, instant):
    """Âge de chaque sauvegarde utilisée à l'instant du sinistre ; RPO = âge le plus grand par classe."""
    resultat, classes = [], {"configuration": [], "journaux": []}
    for source in sources:
        horodatage = dt.datetime.fromisoformat(source["horodatage"])
        age = round((instant - horodatage).total_seconds())
        resultat.append({**source, "age_secondes": age})
        classes["journaux" if source["type"] == "snapshot" else "configuration"].append(age)
    rpo = {f"{nom}_secondes": max(ages) if ages else None for nom, ages in classes.items()}
    connus = [v for v in rpo.values() if v is not None]
    rpo["global_secondes"] = max(connus) if connus else None
    return {"instant_reference": instant.isoformat(), "sources": resultat, **rpo}


def comparer_comptages(attendus, api):
    """Comptages Graylog (API) contre les collections MongoDB restaurées : l'API ne doit rien perdre."""
    resultat = {}
    for cle, collection in COLLECTIONS_CLES.items():
        attendu, obtenu = attendus.get(collection), api.get(cle)
        resultat[cle] = {"collection": collection, "mongodb": attendu, "api": obtenu,
                         "conforme": attendu is not None and obtenu is not None and obtenu >= attendu}
    return resultat


def comparer_inventaire(restaures, inventaire):
    """Documents restaurés contre l'inventaire source ; un index d'écriture a pu grossir après le snapshot."""
    ecarts, identiques, toleres = [], 0, 0
    for nom, docs in sorted(restaures.items()):
        source = inventaire.get(nom)
        if not isinstance(source, dict):
            continue
        if source.get("docs") == docs:
            identiques += 1
        elif source.get("ecriture") and docs <= source.get("docs", 0):
            toleres += 1
        else:
            ecarts.append({"index": nom, "restaure": docs, "source": source.get("docs")})
    return {"compares": identiques + toleres + len(ecarts), "identiques": identiques, "toleres": toleres, "ecarts": ecarts}


def duree(secondes):
    if secondes is None:
        return "n.d."
    secondes = int(round(secondes))
    heures, reste = divmod(secondes, 3600)
    return f"{heures} h {reste // 60:02d} min" if heures else f"{reste // 60} min {reste % 60:02d} s"


def valider_rapport(rapport):
    """Erreurs de structure d'un rapport d'exercice (liste vide = exploitable)."""
    erreurs = []
    if not isinstance(rapport, dict):
        return ["rapport non objet"]
    if rapport.get("schema_version") != SCHEMA:
        erreurs.append("schema_version inattendue")
    if not isinstance(rapport.get("reussi"), bool):
        erreurs.append("champ reussi absent")
    etapes = rapport.get("etapes")
    if not isinstance(etapes, list) or not all(isinstance(e, dict) and isinstance(e.get("nom"), str)
                                               and isinstance(e.get("secondes", 0), (int, float)) for e in etapes):
        erreurs.append("etapes invalides")
    for cle in ("rto", "rpo"):
        if not isinstance(rapport.get(cle), dict):
            erreurs.append(cle + " absent")
    if rapport.get("reussi") and isinstance(rapport.get("rto"), dict) and not rapport["rto"].get("valide"):
        erreurs.append("rapport réussi avec un RTO invalide")
    return erreurs


def synthese(rapports):
    """Lignes de synthèse pour plusieurs rapports, du plus ancien au plus récent."""
    lignes = []
    for chemin, rapport in rapports:
        rto, rpo = rapport.get("rto", {}), rapport.get("rpo", {})
        lignes.append({"rapport": str(chemin), "debut": rapport.get("debut"), "hote": rapport.get("hote"),
                       "reussi": rapport.get("reussi"), "rto_service_secondes": rto.get("service_secondes"),
                       "rto_total_secondes": rto.get("total_secondes"), "rpo_global_secondes": rpo.get("global_secondes"),
                       "debit_restauration_mo_s": rapport.get("mesures", {}).get("debit_restauration_mo_s")})
    return sorted(lignes, key=lambda ligne: ligne.get("debut") or "")


def rendre_markdown(rapport):
    etat = "RÉUSSI" if rapport.get("reussi") else "ÉCHEC OU INCOMPLET"
    rto, rpo, mesures = rapport.get("rto", {}), rapport.get("rpo", {}), rapport.get("mesures", {})
    l = [f"# Exercice de restauration complète du SIEM : {etat}", "",
         f"- Hôte d'exercice : `{rapport.get('hote')}`",
         f"- Début : {rapport.get('debut')} ; fin : {rapport.get('fin')}",
         f"- Révision de l'outil : `{rapport.get('revision', 'inconnue')}`", "",
         "## Étapes chronométrées", "", "| Étape | Statut | Durée | Détail |", "|---|---|---|---|"]
    for etape in rapport.get("etapes", []):
        detail = etape.get("erreur") or etape.get("resume") or ""
        l.append(f"| {etape['nom']} | {etape.get('statut')} | {duree(etape.get('secondes'))} | {detail} |")
    l += ["", "## RTO mesuré", "",
          f"- Reprise du service (socle jusqu'à Graylog opérationnel) : **{duree(rto.get('service_secondes'))}**"
          + ("" if rto.get("valide") else " (non valide : une étape n'a pas abouti)"),
          f"- Avec les contrôles de réception : {duree(rto.get('total_secondes'))}",
          f"- Reprise de la collecte si l'historique est restauré après coup (déduit, non mesuré) : "
          f"{duree(rto.get('collecte_deduit_secondes'))}",
          f"- Mode du socle : {rto.get('socle_mode') or 'n.d.'}", "",
          "## RPO déduit de l'âge des sauvegardes", "",
          f"Instant de référence : {rpo.get('instant_reference')}", "",
          "| Sauvegarde | Type | Horodatage | Précision | Âge |", "|---|---|---|---|---|"]
    for source in rpo.get("sources", []):
        l.append(f"| `{source.get('nom')}` | {source.get('type')} | {source.get('horodatage')} | "
                 f"{source.get('precision')} | {duree(source.get('age_secondes'))} |")
    l += ["", f"- RPO configuration (MongoDB et fichiers) : **{duree(rpo.get('configuration_secondes'))}**",
          f"- RPO journaux restaurés : **{duree(rpo.get('journaux_secondes'))}** "
          "(index absents du snapshot : non restaurables)", "",
          "## Mesures", ""]
    for cle, valeur in sorted(mesures.items()):
        l.append(f"- `{cle}` : {valeur}")
    l += ["", "## Contrôles de réception", "", "| Contrôle | Résultat | Détail |", "|---|---|---|"]
    for controle in rapport.get("controles", []):
        resultat = {True: "conforme", False: "non conforme"}.get(controle.get("conforme"), "non vérifié")
        l.append(f"| {controle.get('nom')} | {resultat} | {json.dumps(controle.get('preuve'), ensure_ascii=False)} |")
    if rapport.get("non_appliques"):
        l += ["", "## Contenu de l'archive inventorié mais non appliqué", "",
              "Ces éléments ne sont jamais réactivés par l'exercice (robots, SOAR, courriel) :", ""]
        for chemin, nombre in sorted(rapport["non_appliques"].items()):
            l.append(f"- `{chemin}` : {nombre} fichier(s)")
    if rapport.get("avertissements"):
        l += ["", "## Avertissements", ""] + [f"- {a}" for a in rapport["avertissements"]]
    return "\n".join(l) + "\n"


# --------------------------------------------------------------------------
# Accès système (VM d'exercice)
# --------------------------------------------------------------------------

def maintenant():
    return dt.datetime.now().astimezone()


def http_json(methode, url, corps=None, *, en_tetes=None, contexte=None, delai=60, lecture_seule=False, brut=False):
    if lecture_seule and methode != "GET":
        raise ErreurExercice("mode lecture seule : seule la méthode GET est permise")
    donnees = json.dumps(corps).encode() if corps is not None else None
    requete = urllib.request.Request(url, data=donnees, method=methode,
                                     headers={"Accept": "application/json", "Content-Type": "application/json",
                                              **(en_tetes or {})})
    gestionnaires = [urllib.request.ProxyHandler({})]
    if contexte is not None:
        gestionnaires.append(urllib.request.HTTPSHandler(context=contexte))
    with urllib.request.build_opener(*gestionnaires).open(requete, timeout=delai) as reponse:
        contenu = reponse.read()
    if brut:
        return contenu
    return json.loads(contenu) if contenu else {}


def etat_opensearch(lecture_seule=True):
    try:
        noeud = http_json("GET", OPENSEARCH + "/", delai=10, lecture_seule=lecture_seule)
        lignes = http_json("GET", OPENSEARCH + "/_cat/indices?format=json&h=index,docs.count,store.size,health&bytes=b",
                           delai=30, lecture_seule=lecture_seule)
        return noeud, index_depuis_cat(lignes)
    except (OSError, ValueError, urllib.error.URLError):
        return None, []


def evaluer_garde(env=None, lecture_seule=True):
    env = os.environ if env is None else env
    try:
        sortie_ip = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        sortie_ip = ""
    noeud, index = etat_opensearch(lecture_seule)
    raisons = motifs_refus(env=env, hostname=socket.gethostname(), fqdn=socket.getfqdn(),
                           adresses=adresses_ipv4(sortie_ip), noeud=noeud, index=index)
    return {"hote": socket.gethostname(), "raisons_refus": raisons, "accepte": not raisons,
            "index_preexistants": len([i for i in index if not i["index"].startswith(".")])}


def charger_module(nom, chemin):
    spec = importlib.util.spec_from_file_location(nom, chemin)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def charger_config_socle(chemin):
    if chemin.is_symlink() or not chemin.is_file():
        raise ErreurExercice("configuration du socle introuvable : " + str(chemin))
    return charger_module("omni_install", ROOT / "tools/install-platform.py").load_config(chemin)


def fichier_prive(chemin):
    """Refuse un fichier secret lisible par d'autres que son propriétaire."""
    if chemin.is_symlink() or not chemin.is_file():
        raise ErreurExercice(f"fichier ordinaire requis : {chemin}")
    if chemin.stat().st_mode & 0o077:
        raise ErreurExercice(f"{chemin} doit être en mode 600")
    return chemin


class Exercice:
    def __init__(self, args):
        self.args = args
        self.travail = Path(tempfile.mkdtemp(prefix="omni-restore-drill.", dir=args.travail))
        self.travail.chmod(0o700)
        self.journaux = self.travail / "journaux"
        self.journaux.mkdir(mode=0o700)
        self.extraction = self.travail / "archive"
        self.rapport = {"schema_version": SCHEMA, "reussi": False, "hote": socket.gethostname(),
                        "debut": maintenant().isoformat(), "revision": self.revision(), "etapes": [],
                        "controles": [], "mesures": {}, "sources": [], "avertissements": [], "non_appliques": {}}
        self.proprietes = {}
        self.comptages = {}
        self.restaures = {}
        self.secret_temporaire = None

    @staticmethod
    def revision():
        try:
            return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True,
                                           stderr=subprocess.DEVNULL, timeout=10).strip()
        except (OSError, subprocess.SubprocessError):
            return "inconnue"

    # -- outils ---------------------------------------------------------------
    def commande(self, argv, *, env=None, delai=600, nom=None):
        nom = nom or Path(argv[0]).name
        journal = self.journaux / f"{len(list(self.journaux.iterdir())):02d}-{nom}.log"
        with journal.open("wb") as sortie_erreur:
            journal.chmod(0o600)
            resultat = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=sortie_erreur, timeout=delai)
        if resultat.returncode:
            raise ErreurExercice(f"{nom} en échec (code {resultat.returncode}, journal {journal.name})")
        return resultat.stdout.decode(errors="replace")

    def env_mongo(self, **extra):
        base = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "HOME", "TMPDIR")}
        return {**base, "OMNI_MONGO_ADMIN": self.config_socle["MONGO_ADMIN_PASS"], **extra}

    def mongosh(self, script, **extra):
        return self.commande(["mongosh", "--quiet", "--norc", MONGO_SHELL_URI, "--eval", AUTH_JS + script],
                             env=self.env_mongo(**extra), delai=300, nom="mongosh")

    def etape(self, nom):
        return Chrono(self.rapport, nom)

    def controle(self, nom, conforme, preuve=None):
        self.rapport["controles"].append({"nom": nom, "conforme": conforme, "preuve": preuve})

    def systemctl(self, action, unite):
        self.commande(["systemctl", action, unite], delai=600, nom=f"systemctl-{action}")

    def reverifier_garde(self):
        garde = evaluer_garde(lecture_seule=True)
        hote = [r for r in garde["raisons_refus"] if "index" not in r and "OpenSearch" not in r]
        if hote:
            raise ErreurExercice("garde anti-production : " + " ; ".join(hote))

    # -- étapes ----------------------------------------------------------------
    def socle(self, entree):
        if self.args.socle_commande:
            entree["mode"] = "installation"
            self.commande(shlex.split(self.args.socle_commande), delai=self.args.delai_socle, nom="socle")
        else:
            entree["mode"] = "verification"
        versions = {}
        for paquet in ("graylog-server", "opensearch", "mongodb-org-server"):
            sortie = subprocess.run(["dpkg-query", "-W", "-f=${Version}", paquet], capture_output=True, text=True, timeout=15)
            if sortie.returncode or not sortie.stdout.strip():
                raise ErreurExercice(f"paquet {paquet} absent : installer le socle (install.sh --apply)")
            versions[paquet] = sortie.stdout.strip()
        for outil in ("mongorestore", "mongosh", "openssl"):
            if not shutil.which(outil):
                raise ErreurExercice("outil requis absent : " + outil)
        for service in ("mongod", "opensearch"):
            if subprocess.run(["systemctl", "is-active", "--quiet", service], timeout=15).returncode:
                raise ErreurExercice(f"service {service} inactif après installation du socle")
        self.versions = versions
        entree["resume"] = ", ".join(f"{k} {v}" for k, v in versions.items())

    def cle(self):
        if self.args.cle_stdin:
            valeur = sys.stdin.readline().rstrip("\n")
            if not valeur:
                raise ErreurExercice("clé de déchiffrement vide sur l'entrée standard")
            chemin = self.travail / "cle"
            descripteur = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descripteur, "w") as flux:
                flux.write(valeur + "\n")
            self.secret_temporaire = chemin
            return chemin
        if not self.args.cle_fichier:
            raise ErreurExercice("clé de déchiffrement requise : --cle-fichier ou --cle-stdin")
        return fichier_prive(Path(self.args.cle_fichier))

    def configuration(self, entree):
        archive = Path(self.args.archive_config)
        if archive.is_symlink() or not archive.is_file():
            raise ErreurExercice("archive de configuration introuvable")
        self.rapport["mesures"]["archive_config_octets"] = archive.stat().st_size
        self.systemctl("stop", "graylog-server")
        clair = self.travail / "config.tar.gz"
        self.commande(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                       "-in", str(archive), "-out", str(clair), "-pass", "file:" + str(self.cle())], nom="openssl")
        if self.secret_temporaire:
            self.secret_temporaire.unlink()
        self.extraction.mkdir(mode=0o700)
        with tarfile.open(clair) as tar:
            membres = tar.getmembers()
            noms = [m.name for m in membres]
            manquants = membres_manquants(noms)
            if manquants:
                raise ErreurExercice("archive incomplète : " + ", ".join(manquants))
            for facultatif in MEMBRES_FACULTATIFS:
                if facultatif not in {n.lstrip("./") for n in noms}:
                    self.rapport["avertissements"].append(f"{facultatif} absent de l'archive")
            # Filtre « tar » : refuse chemins absolus et sorties de l'arborescence, retire les bits
            # setuid, conserve les propriétaires (graylog, opensearch) ; liens externes ignorés.
            ignores = []
            tar.extractall(self.extraction, filter=filtre_extraction(ignores))
            if ignores:
                self.rapport["avertissements"].append(f"{len(ignores)} lien(s) absolu(s) non extrait(s), "
                                                      f"dont {sum(n.lstrip('./').startswith('etc/graylog/') for n in ignores)} sous etc/graylog")
            dumps = [m.mtime for m in membres if m.name.lstrip("./").startswith("mongodump/graylog/") and m.isfile()]
        clair.unlink()
        horodatage = (dt.datetime.fromtimestamp(max(dumps)).astimezone(), "seconde") if dumps \
            else horodatage_nom(archive.name)
        self.rapport["sources"].append({"type": "archive_config", "nom": archive.name,
                                        "horodatage": horodatage[0].isoformat(), "precision": horodatage[1],
                                        "octets": archive.stat().st_size})
        self.rapport["mesures"]["archive_config_membres"] = len(noms)
        self.verifier_versions()
        conf = self.extraction / "etc/graylog/server/server.conf"
        self.proprietes = lire_proprietes(conf.read_text(errors="replace"))
        if archive_de_production(self.proprietes):
            self.verifier_isolement()
        sauvegarde = self.travail / "avant-restauration"
        sauvegarde.mkdir(mode=0o700)
        if Path("/etc/graylog").is_dir():
            shutil.copytree("/etc/graylog", sauvegarde / "etc-graylog", symlinks=True)
        for chemin in APPLIQUES:
            shutil.copytree(self.extraction / chemin, Path("/") / chemin, symlinks=True, dirs_exist_ok=True)
        cible = Path("/etc/graylog/server/server.conf")
        mode = cible.stat()
        cible.write_text(neutraliser_courriel(cible.read_text(errors="replace")))
        os.chown(cible, mode.st_uid, mode.st_gid)
        for cle in ("data_dir", "message_journal_dir"):
            if self.proprietes.get(cle):
                repertoire = Path(self.proprietes[cle])
                repertoire.mkdir(parents=True, exist_ok=True)
                shutil.chown(repertoire, "graylog", "graylog")
        for haut in sorted({n.lstrip("./").split("/")[0] for n in noms} - {"mongodump"}):
            racine = self.extraction / haut
            elements = sorted(racine.iterdir()) if racine.is_dir() and not racine.is_symlink() else [racine]
            for element in elements:
                relatif = str(element.relative_to(self.extraction))
                if relatif in APPLIQUES:
                    continue
                nombre = sum(1 for f in element.rglob("*") if f.is_file()) if element.is_dir() else 1
                self.rapport["non_appliques"][relatif] = nombre
        entree["resume"] = f"{len(noms)} membres ; appliqué : {', '.join(APPLIQUES)} ; courriel Graylog désactivé"

    def verifier_versions(self):
        candidates = [p for p in self.extraction.glob("**/stack-versions.env")
                      if (p.parent / "30-backup-config.sh").is_file() and len(p.relative_to(self.extraction).parts) <= 5]
        if not candidates:
            self.rapport["avertissements"].append("stack-versions.env absent de l'archive : versions non comparées")
            return
        reference = dict(ligne.split("=", 1) for ligne in candidates[0].read_text().splitlines()
                         if "=" in ligne and not ligne.startswith("#"))
        ecarts = versions_compatibles(self.versions, reference)
        if ecarts:
            raise ErreurExercice("socle incompatible avec l'archive : " + " ; ".join(ecarts))

    def verifier_isolement(self):
        if not self.args.sonde_sortie:
            raise ErreurExercice("archive de production : déclarer au moins une --sonde-sortie hote:port "
                                 "(relais SMTP, FortiGate, partage SMB) pour prouver l'isolement réseau")
        joignables = []
        for sonde in self.args.sonde_sortie:
            hote, _, port = sonde.rpartition(":")
            try:
                with socket.create_connection((hote, int(port)), timeout=3):
                    joignables.append(sonde)
            except (OSError, ValueError):
                pass
        self.rapport["mesures"]["sondes_sortie"] = len(self.args.sonde_sortie)
        if joignables:
            raise ErreurExercice("VM non isolée, destination joignable : " + ", ".join(joignables))

    def mongodb(self, entree):
        conf = self.travail / "mongo-outils.yaml"
        descripteur = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descripteur, "w") as flux:
            valeur = self.config_socle["MONGO_ADMIN_PASS"]
            json.dump({"password": valeur}, flux)
        argv = ["mongorestore", "--quiet", "--config=" + str(conf), "--uri", MONGO_ADMIN_URI,
                "--drop", "--nsInclude=graylog.*"]
        if self.args.archive_mongo:
            archive = Path(self.args.archive_mongo)
            if archive.is_symlink() or not archive.is_file():
                raise ErreurExercice("archive MongoDB introuvable")
            argv += ["--gzip", "--archive=" + str(archive)]
            horodatage, precision = horodatage_nom(archive.name)
            if horodatage is None:
                horodatage, precision = dt.datetime.fromtimestamp(archive.stat().st_mtime).astimezone(), "mtime"
            self.rapport["sources"].append({"type": "mongo", "nom": archive.name, "horodatage": horodatage.isoformat(),
                                            "precision": precision, "octets": archive.stat().st_size})
            entree["source"] = "archive omni-mongo-backup"
        else:
            argv += ["--dir", str(self.extraction / "mongodump")]
            entree["source"] = "mongodump de l'archive de configuration"
        try:
            debut = time.monotonic()
            self.commande(argv, env=self.env_mongo(), delai=self.args.delai_mongo, nom="mongorestore")
            self.rapport["mesures"]["mongorestore_secondes"] = round(time.monotonic() - debut, 1)
        finally:
            conf.unlink(missing_ok=True)
        app = uri_application(self.proprietes)
        action = self.mongosh(UTILISATEUR_JS, OMNI_APP_USER=app["utilisateur"], OMNI_APP_PASS=app["mot_de_passe"],
                              OMNI_APP_DB=app["base"], OMNI_APP_AUTHDB=app["base_auth"]).strip().splitlines()[-1:]
        self.comptages = json.loads(self.mongosh(COMPTAGES_JS).strip().splitlines()[-1])
        self.rapport["mesures"]["mongo_collections"] = len(self.comptages)
        self.rapport["mesures"]["mongo_documents"] = sum(self.comptages.values())
        entree["resume"] = (f"{len(self.comptages)} collections, {sum(self.comptages.values())} documents ; "
                            f"utilisateur applicatif {''.join(action).lower() or 'inchangé'}")

    def opensearch(self, entree):
        depot = Path(self.args.depot_snapshots).resolve()
        if not (depot / "index.latest").is_file() and not list(depot.glob("index-*")):
            raise ErreurExercice("répertoire de dépôt de snapshots invalide (index-N absent)")
        reglages = http_json("GET", OPENSEARCH + "/_nodes/_local/settings")
        chemins = []
        for noeud in reglages.get("nodes", {}).values():
            valeur = noeud.get("settings", {}).get("path", {}).get("repo", [])
            chemins += [valeur] if isinstance(valeur, str) else list(valeur)
        if not any(depot == Path(c).resolve() or Path(c).resolve() in depot.parents for c in chemins):
            raise ErreurExercice(f"{depot} hors de path.repo d'OpenSearch : l'ajouter à opensearch.yml puis redémarrer")
        http_json("PUT", f"{OPENSEARCH}/_snapshot/{DEPOT_EXERCICE}",
                  {"type": "fs", "settings": {"location": str(depot), "readonly": True}})
        snapshots = http_json("GET", f"{OPENSEARCH}/_snapshot/{DEPOT_EXERCICE}/_all").get("snapshots", [])
        reussis = sorted((s for s in snapshots if s.get("state") == "SUCCESS"), key=lambda s: s.get("start_time_in_millis", 0))
        choisi = next((s for s in reussis if s["snapshot"] == self.args.snapshot), None) if self.args.snapshot \
            else (reussis[-1] if reussis else None)
        if not choisi:
            raise ErreurExercice("aucun snapshot réussi correspondant dans le dépôt")
        motif = re.compile(self.args.index_motif) if self.args.index_motif else None
        existants = {i["index"] for i in etat_opensearch(lecture_seule=False)[1]}
        voulus = [i for i in choisi.get("indices", []) if not INDEX_IGNORES.match(i) and (not motif or motif.search(i))]
        conflits = sorted(set(voulus) & existants)
        selection = sorted(set(voulus) - existants)
        if conflits:
            self.rapport["avertissements"].append(f"{len(conflits)} index déjà présents, non restaurés : {', '.join(conflits[:10])}")
        if not selection:
            raise ErreurExercice("aucun index à restaurer")
        statut = http_json("GET", f"{OPENSEARCH}/_snapshot/{DEPOT_EXERCICE}/{choisi['snapshot']}/_status", delai=600)
        par_index = (statut.get("snapshots") or [{}])[0].get("indices", {})
        octets = sum(par_index.get(i, {}).get("stats", {}).get("total", {}).get("size_in_bytes", 0) for i in selection)
        debut_snapshot = dt.datetime.fromtimestamp(choisi["start_time_in_millis"] / 1000).astimezone()
        self.rapport["sources"].append({"type": "snapshot", "nom": choisi["snapshot"], "horodatage": debut_snapshot.isoformat(),
                                        "precision": "seconde", "octets": octets, "index": len(selection)})
        debut = time.monotonic()
        reponse = http_json("POST", f"{OPENSEARCH}/_snapshot/{DEPOT_EXERCICE}/{choisi['snapshot']}/_restore",
                            {"indices": ",".join(selection), "include_aliases": False, "include_global_state": False,
                             "index_settings": {"index.number_of_replicas": 0}})
        if reponse.get("accepted") is not True and "snapshot" not in reponse:
            raise ErreurExercice("restauration refusée par OpenSearch")
        limite = time.monotonic() + self.args.delai_index
        while True:
            etat = {i["index"]: i for i in etat_opensearch(lecture_seule=False)[1] if i["index"] in set(selection)}
            if len(etat) == len(selection) and all(i["sante"] == "green" for i in etat.values()):
                break
            if time.monotonic() > limite:
                raise ErreurExercice(f"délai de restauration dépassé : {sum(i['sante'] == 'green' for i in etat.values())}"
                                     f"/{len(selection)} index verts")
            time.sleep(10)
        secondes = time.monotonic() - debut
        http_json("POST", OPENSEARCH + "/_refresh")
        self.restaures = {i["index"]: i["docs"] for i in etat_opensearch(lecture_seule=False)[1] if i["index"] in set(selection)}
        alias = http_json("GET", OPENSEARCH + "/_cat/aliases?format=json&h=alias,index")
        avec_alias = sorted({a["index"] for a in alias if a.get("index") in self.restaures})
        self.controle("opensearch:aucun-alias-restaure", not avec_alias, {"index_avec_alias": avec_alias[:10]})
        self.rapport["mesures"].update({"index_restaures": len(selection), "octets_restaures": octets,
                                        "documents_restaures": sum(self.restaures.values()),
                                        "restauration_index_secondes": round(secondes, 1),
                                        "debit_restauration_mo_s": debit_mo_s(octets, secondes)})
        if self.args.inventaire_source:
            inventaire = json.loads(Path(self.args.inventaire_source).read_text()).get("index", {})
            comparaison = comparer_inventaire(self.restaures, inventaire)
            self.controle("opensearch:documents-conformes-inventaire", not comparaison["ecarts"], comparaison)
        entree["resume"] = (f"{choisi['snapshot']} : {len(selection)} index, {octets} octets, "
                            f"{debit_mo_s(octets, secondes)} Mo/s")

    def graylog(self, entree):
        self.reverifier_garde()
        self.systemctl("start", "graylog-server")
        url = adresse_graylog(self.proprietes)
        limite = time.monotonic() + self.args.delai_graylog
        while time.monotonic() < limite:
            try:
                if http_json("GET", url + "/system/lbstatus", contexte=self.contexte_local(), delai=10, brut=True).strip() == b"ALIVE":
                    entree["resume"] = "lbstatus ALIVE"
                    return
            except (OSError, ValueError, urllib.error.URLError):
                pass
            time.sleep(5)
        raise ErreurExercice("Graylog n'a pas atteint l'état ALIVE dans le délai")

    @staticmethod
    def contexte_local():
        # Boucle locale de la VM d'exercice : le certificat restauré porte le nom de production.
        contexte = ssl.create_default_context()
        contexte.check_hostname = False
        contexte.verify_mode = ssl.CERT_NONE
        return contexte

    def api(self, methode, chemin, corps=None):
        return http_json(methode, adresse_graylog(self.proprietes) + chemin, corps, contexte=self.contexte_local(),
                         en_tetes={"Authorization": self.autorisation, "X-Requested-By": "omni-restore-drill"}, delai=120)

    def controles(self, entree):
        if not self.args.identifiants_api:
            self.controle("graylog:api", None, "identifiants non fournis (--identifiants-api) : contrôles API non réalisés")
            self.console()
            raise ErreurExercice("contrôles incomplets : identifiants API absents")
        utilisateur, _, mot = fichier_prive(Path(self.args.identifiants_api)).read_text().strip().partition(":")
        self.autorisation = "Basic " + base64.b64encode(f"{utilisateur}:{mot}".encode()).decode()
        api = {"entrees": self.api("GET", "/system/inputs").get("total"),
               "flux": self.api("GET", "/streams").get("total")}
        definitions = self.api("GET", "/events/definitions?per_page=1&page=1")
        api["definitions"] = definitions.get("pagination", {}).get("total", definitions.get("total"))
        api["regles"] = len(self.api("GET", "/system/pipelines/rule"))
        api["pipelines"] = len(self.api("GET", "/system/pipelines/pipeline"))
        api["index_sets"] = self.api("GET", "/system/indices/index_sets?skip=0&limit=0").get("total")
        for cle, resultat in comparer_comptages(self.comptages, api).items():
            self.controle("graylog:" + cle, resultat["conforme"], resultat)
        etats = self.api("GET", "/system/inputstates").get("states", [])
        self.rapport["mesures"]["entrees_demarrees"] = sum(e.get("state") == "RUNNING" for e in etats)
        self.plages()
        self.recherches()
        self.console()
        echecs = [c["nom"] for c in self.rapport["controles"] if c["conforme"] is not True]
        entree["resume"] = f"{len(self.rapport['controles'])} contrôles, {len(echecs)} non conforme(s)"
        if echecs:
            raise ErreurExercice("contrôles non conformes : " + ", ".join(echecs))

    def plages(self):
        self.api("POST", "/system/indices/ranges/rebuild")
        limite, presentes = time.monotonic() + self.args.delai_plages, set()
        while time.monotonic() < limite:
            presentes = {p.get("index_name") for p in self.api("GET", "/system/indices/ranges").get("ranges", [])}
            if set(self.restaures) <= presentes:
                break
            time.sleep(10)
        manquantes = sorted(set(self.restaures) - presentes)
        self.controle("graylog:plages-index", not manquantes, {"index_sans_plage": len(manquantes), "exemples": manquantes[:5]})

    def recherches(self):
        messages = [i for i, docs in self.restaures.items() if docs and not INDEX_EVENEMENTS.match(i)]
        if not messages:
            self.controle("recherche:index-restaures", None, "aucun index de messages non vide restauré")
            return
        corps = {"size": 0, "aggs": {"min": {"min": {"field": "timestamp"}}, "max": {"max": {"field": "timestamp"}}}}
        total = 0
        bornes = []
        for lot in range(0, len(messages), 50):
            noms = ",".join(messages[lot:lot + 50])
            resultat = http_json("POST", f"{OPENSEARCH}/{noms}/_search?track_total_hits=true", corps, delai=300)
            if resultat.get("_shards", {}).get("failed"):
                raise ErreurExercice("recherche OpenSearch partielle sur les index restaurés")
            total += resultat["hits"]["total"]["value"]
            bornes += [resultat["aggregations"]["min"].get("value"), resultat["aggregations"]["max"].get("value")]
        bornes = [b for b in bornes if b is not None]
        self.controle("recherche:opensearch", total > 0, {"documents": total, "index": len(messages)})
        if not bornes:
            return
        def iso(ms):
            return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        plage = {"type": "absolute", "from": iso(min(bornes)), "to": iso(max(bornes) + 1000)}
        requete, type_id = str(uuid.uuid4()), str(uuid.uuid4())
        chaine = {"type": "elasticsearch", "query_string": "*"}
        recherche = self.api("POST", "/views/search", {"queries": [{
            "id": requete, "query": chaine, "timerange": plage, "filters": [],
            "search_types": [{"id": type_id, "name": "messages", "type": "messages", "limit": 1, "offset": 0,
                              "sort": [{"field": "timestamp", "order": "DESC"}], "query": chaine,
                              "timerange": plage, "streams": [], "filters": []}]}], "parameters": []})
        travail = self.api("POST", f"/views/search/{recherche['id']}/execute", {})
        for _ in range(120):
            travail = self.api("GET", f"/views/search/status/{travail['id']}")
            if travail.get("execution", {}).get("done"):
                break
            time.sleep(2)
        resultat = travail.get("results", {}).get(requete, {})
        type_resultat = resultat.get("search_types", {}).get(type_id, {})
        trouves = type_resultat.get("total_results")
        erreurs = bool(travail.get("errors") or resultat.get("errors"))
        self.controle("recherche:graylog", isinstance(trouves, int) and trouves > 0 and not erreurs,
                      {"documents_graylog": trouves, "documents_opensearch": total, "egalite": trouves == total,
                       "erreurs": erreurs, "plage": plage})

    def console(self):
        url = self.args.url_console or ("https://" + self.config_socle.get("SIEM_FQDN", "localhost") + "/soc/")
        certificat = Path("/etc/nginx/ssl/graylog.crt")
        contexte = ssl.create_default_context(cafile=str(certificat)) if certificat.is_file() else ssl.create_default_context()
        try:
            corps = http_json("GET", url, contexte=contexte, delai=30, brut=True)[:8192].lower()
            self.controle("console:soc", b"<html" in corps or b"<!doctype html" in corps, {"url": url})
        except (OSError, ValueError, urllib.error.URLError) as erreur:
            self.controle("console:soc", False, {"url": url, "erreur": type(erreur).__name__})

    # -- orchestration -----------------------------------------------------------
    def lancer(self):
        try:
            garde = evaluer_garde(lecture_seule=True)
            self.rapport["garde"] = garde
            if not garde["accepte"]:
                raise ErreurExercice("exercice refusé : " + " ; ".join(garde["raisons_refus"]))
            if os.geteuid() != 0:
                raise ErreurExercice("l'exercice s'exécute en root dans la VM isolée")
            self.config_socle = charger_config_socle(Path(self.args.config_socle))
            if not self.config_socle.get("MONGO_ADMIN_PASS"):
                raise ErreurExercice("MONGO_ADMIN_PASS absent de la configuration du socle")
            for nom in ("socle", "configuration", "mongodb", "opensearch", "graylog", "controles"):
                with self.etape(nom) as entree:
                    getattr(self, nom)(entree)
        except ErreurExercice as erreur:
            self.rapport["erreur"] = str(erreur)
        except Exception as erreur:  # noqa: BLE001 - le rapport ne doit jamais citer de secret
            self.rapport["erreur"] = type(erreur).__name__
        finally:
            fin = maintenant()
            self.rapport["fin"] = fin.isoformat()
            instant = instant_iso(self.args.instant_sinistre or self.rapport["debut"])
            self.rapport["rto"] = calcul_rto(self.rapport["etapes"])
            self.rapport["rpo"] = calcul_rpo(self.rapport["sources"], instant)
            self.rapport["reussi"] = (not self.rapport.get("erreur") and self.rapport["rto"]["valide"]
                                      and all(e["statut"] == "ok" for e in self.rapport["etapes"])
                                      and len(self.rapport["etapes"]) == 6)
            if not self.args.conserver_extraction:
                shutil.rmtree(self.extraction, ignore_errors=True)
            ecrire_rapport(Path(self.args.rapport), self.rapport)
        return 0 if self.rapport["reussi"] else 1


class Chrono:
    def __init__(self, rapport, nom):
        self.rapport, self.nom = rapport, nom

    def __enter__(self):
        self.debut = time.monotonic()
        self.entree = {"nom": self.nom, "statut": "en_cours", "debut": maintenant().isoformat()}
        self.rapport["etapes"].append(self.entree)
        return self.entree

    def __exit__(self, type_exc, exc, trace):
        self.entree["secondes"] = round(time.monotonic() - self.debut, 1)
        if exc is None:
            self.entree["statut"] = "ok"
        else:
            self.entree["statut"] = "echec"
            self.entree["erreur"] = str(exc) if isinstance(exc, ErreurExercice) else type(exc).__name__
        return False


def ecrire_rapport(repertoire, rapport):
    if repertoire.is_symlink():
        raise ErreurExercice("répertoire de rapport en lien symbolique refusé")
    repertoire.mkdir(mode=0o700, parents=True, exist_ok=True)
    for nom, contenu in (("rapport-restauration.json", json.dumps(rapport, indent=2, ensure_ascii=False) + "\n"),
                         ("rapport-restauration.md", rendre_markdown(rapport))):
        cible = repertoire / nom
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=repertoire, delete=False) as flux:
            flux.write(contenu)
        os.chmod(flux.name, 0o600)
        os.replace(flux.name, cible)


# --------------------------------------------------------------------------
# Banc VM : jeu factice et sinistre simulé (laboratoire uniquement)
# --------------------------------------------------------------------------

def configuration_laboratoire():
    """Réutilise la garde du banc d'intégration : identité de laboratoire et marqueur root."""
    return charger_module("omni_integration_vm", ROOT / "tools/test-integration-vm.py").isolated_configuration()


def jeu_factice(args):
    config = configuration_laboratoire()
    sortie = Path(args.sortie)
    sortie.mkdir(mode=0o700)
    cle = sortie / "cle"
    descripteur = os.open(cle, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descripteur, "w") as flux:
        flux.write(base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
    travail = Path(tempfile.mkdtemp(prefix="omni-drill-jeu.", dir=sortie))
    conf = travail / "mongo.yaml"
    descripteur = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descripteur, "w") as flux:
        json.dump({"password": config["MONGO_ADMIN_PASS"]}, flux)
    # Base dans l'URI, comme 30-backup-config.sh : seul graylog est exporté.
    uri = "mongodb://admin@127.0.0.1:27017/graylog?replicaSet=rs0&authSource=admin"
    subprocess.run(["mongodump", "--quiet", "--config=" + str(conf), "--uri", uri,
                    "--out", str(travail / "mongodump")], check=True, timeout=600)
    conf.unlink()
    # Même disposition que 30-backup-config.sh : chemins relatifs à / puis mongodump/.
    chemins = [c for c in ("etc/graylog", "etc/default/graylog-server", "etc/opensearch", "etc/mongod.conf", "etc/nginx",
                           "etc/hosts", "etc/nftables.conf", "etc/systemd/system", "usr/local/sbin",
                           str(ROOT).lstrip("/")) if (Path("/") / c).exists()]
    archive = sortie / f"omni-siem-config_{dt.date.today():%Y-%m-%d}.tar.gz"
    subprocess.run(["tar", "czf", str(archive), "--ignore-failed-read", "-C", "/", *chemins,
                    "-C", str(travail), "mongodump"], check=True, timeout=900)
    subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt", "-in", str(archive),
                    "-out", str(archive) + ".enc", "-pass", "file:" + str(cle)], check=True, timeout=600)
    archive.unlink()
    shutil.rmtree(travail)
    depot = http_json("GET", OPENSEARCH + "/_snapshot/graylog_fs")["graylog_fs"]["settings"]["location"]
    nom = f"drill-{dt.datetime.now():%Y%m%d-%H%M%S}"
    index = [i["index"] for i in etat_opensearch(lecture_seule=False)[1] if not INDEX_IGNORES.match(i["index"])]
    http_json("PUT", f"{OPENSEARCH}/_snapshot/graylog_fs/{nom}?wait_for_completion=true",
              {"indices": ",".join(index), "include_global_state": False, "partial": False}, delai=1800)
    inventaire = sortie / "inventaire-source.json"
    alias = http_json("GET", OPENSEARCH + "/_cat/aliases?format=json&h=alias,index")
    ecriture = {a["index"] for a in alias if str(a.get("alias", "")).endswith("_deflector")}
    inventaire.write_text(json.dumps({"index": {i["index"]: {"docs": i["docs"], "ecriture": i["index"] in ecriture}
                                                for i in etat_opensearch(lecture_seule=False)[1]
                                                if not INDEX_IGNORES.match(i["index"])}}, indent=2) + "\n")
    identifiants = sortie / "api.cred"
    descripteur = os.open(identifiants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descripteur, "w") as flux:
        flux.write("admin:" + config["GRAYLOG_ADMIN_PASS"] + "\n")
    jeu = {"archive_config": str(archive) + ".enc", "cle_fichier": str(cle), "depot_snapshots": depot,
           "snapshot": nom, "inventaire_source": str(inventaire), "identifiants_api": str(identifiants),
           "config_socle": str(ROOT / "00-vars.env")}
    (sortie / "jeu.json").write_text(json.dumps(jeu, indent=2) + "\n")
    print(json.dumps({"jeu": str(sortie / "jeu.json"), "snapshot": nom, "index": len(index)}))
    return 0


def sinistre_factice(args):
    config = configuration_laboratoire()
    # Ne rien effacer tant que le jeu de sauvegardes n'est pas complet et lisible.
    jeu = json.loads(Path(args.jeu).read_text())
    if not all(Path(jeu[c]).is_file() for c in ("archive_config", "cle_fichier", "inventaire_source")):
        raise ErreurExercice("jeu factice incomplet : rien n'est effacé")
    etat = http_json("GET", f"{OPENSEARCH}/_snapshot/graylog_fs/{jeu['snapshot']}").get("snapshots", [{}])[0]
    if etat.get("state") != "SUCCESS":
        raise ErreurExercice("snapshot du jeu factice absent ou incomplet : rien n'est effacé")
    subprocess.run(["systemctl", "stop", "graylog-server"], check=True, timeout=600)
    supprimes = 0
    for index in etat_opensearch(lecture_seule=False)[1]:
        if not index["index"].startswith("."):
            http_json("DELETE", f"{OPENSEARCH}/{urllib.parse.quote(index['index'])}")
            supprimes += 1
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "HOME")}
    subprocess.run(["mongosh", "--quiet", "--norc", MONGO_SHELL_URI, "--eval",
                    AUTH_JS + 'db.getSiblingDB("graylog").dropDatabase(); print("OK");'],
                   env={**env, "OMNI_MONGO_ADMIN": config["MONGO_ADMIN_PASS"]}, check=True, capture_output=True, timeout=120)
    print(json.dumps({"index_supprimes": supprimes, "base_graylog": "supprimée"}))
    return 0


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------

def appliquer_jeu(args):
    if not args.jeu:
        return
    jeu = json.loads(Path(args.jeu).read_text())
    for cle, valeur in jeu.items():
        if getattr(args, cle, None) in (None, False, []):
            setattr(args, cle, valeur)


def analyser(args):
    rapports, erreurs = [], {}
    for chemin in args.rapports:
        try:
            rapport = json.loads(Path(chemin).read_text())
        except (OSError, ValueError):
            erreurs[chemin] = ["illisible"]
            continue
        problemes = valider_rapport(rapport)
        if problemes:
            erreurs[chemin] = problemes
        else:
            rapports.append((chemin, rapport))
    lignes = synthese(rapports)
    print(json.dumps({"rapports": lignes, "invalides": erreurs}, indent=2, ensure_ascii=False))
    if erreurs:
        return 2
    if args.exiger_reussite and (not lignes or lignes[-1]["reussi"] is not True):
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sous = parser.add_subparsers(dest="commande", required=True)
    for nom in ("plan", "executer"):
        p = sous.add_parser(nom)
        p.add_argument("--jeu", help="manifeste jeu.json (banc VM) fournissant les chemins ci-dessous")
        p.add_argument("--archive-config", help="omni-siem-config_AAAA-MM-JJ.tar.gz.enc")
        p.add_argument("--cle-fichier", help="fichier (mode 600) contenant la passphrase de l'archive")
        p.add_argument("--cle-stdin", action="store_true", help="lire la passphrase sur l'entrée standard")
        p.add_argument("--archive-mongo", help="archive omni-mongo-*.archive.gz (sinon mongodump de l'archive de configuration)")
        p.add_argument("--depot-snapshots", help="copie ou montage en lecture seule du dépôt graylog_fs")
        p.add_argument("--snapshot", help="nom du snapshot (défaut : le plus récent réussi)")
        p.add_argument("--index-motif", help="expression régulière restreignant les index restaurés")
        p.add_argument("--inventaire-source", help="inventaire des index (omni-backup-inventory.py --inventaire-index)")
        p.add_argument("--identifiants-api", help="fichier (mode 600) utilisateur:motdepasse Graylog restauré")
        p.add_argument("--config-socle", default=str(ROOT / "00-vars.env"), help="00-vars.env du socle de la VM")
        p.add_argument("--socle-commande", help="commande d'installation du socle à chronométrer (sinon vérification)")
        p.add_argument("--sonde-sortie", action="append", default=[], help="hote:port qui doit être injoignable")
        p.add_argument("--url-console", help="URL de la console (défaut https://SIEM_FQDN/soc/)")
        p.add_argument("--instant-sinistre", help="instant ISO 8601 du sinistre simulé (défaut : début de l'exercice)")
        p.add_argument("--rapport", help="répertoire du rapport JSON et Markdown")
        p.add_argument("--travail", default="/var/tmp", help="répertoire parent du dossier de travail temporaire")
        p.add_argument("--conserver-extraction", action="store_true")
        p.add_argument("--delai-socle", type=int, default=7200)
        p.add_argument("--delai-mongo", type=int, default=3600)
        p.add_argument("--delai-index", type=int, default=12 * 3600)
        p.add_argument("--delai-graylog", type=int, default=900)
        p.add_argument("--delai-plages", type=int, default=900)
    p = sous.add_parser("analyser")
    p.add_argument("rapports", nargs="+")
    p.add_argument("--exiger-reussite", action="store_true", help="code 1 si le rapport le plus récent n'est pas réussi")
    p = sous.add_parser("jeu-factice")
    p.add_argument("--sortie", required=True)
    p = sous.add_parser("sinistre-factice")
    p.add_argument("--jeu", required=True)
    args = parser.parse_args(argv)
    if args.commande == "analyser":
        return analyser(args)
    if args.commande == "jeu-factice":
        return jeu_factice(args)
    if args.commande == "sinistre-factice":
        return sinistre_factice(args)
    appliquer_jeu(args)
    if args.commande == "plan":
        garde = evaluer_garde(lecture_seule=True)
        print(json.dumps({"garde": garde, "etapes": ["socle", "configuration", "mongodb", "opensearch", "graylog", "controles"],
                          "archive_config": args.archive_config, "depot_snapshots": args.depot_snapshots},
                         indent=2, ensure_ascii=False))
        return 0 if garde["accepte"] else 3
    manquants = [o for o in ("archive_config", "depot_snapshots", "rapport") if not getattr(args, o)]
    if manquants:
        parser.error("options requises : " + ", ".join("--" + m.replace("_", "-") for m in manquants))
    # Garde évaluée avant toute écriture (dossier de travail, rapport) : un refus ne laisse aucune trace.
    garde = evaluer_garde(lecture_seule=True)
    if not garde["accepte"]:
        print(json.dumps({"refus": garde}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 3
    return Exercice(args).lancer()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ErreurExercice as erreur:
        print("Refus : " + str(erreur), file=sys.stderr)
        raise SystemExit(2)
