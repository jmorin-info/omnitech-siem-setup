#!/usr/bin/env python3
"""Mesure en lecture seule des intrants du RPO et du RTO du SIEM.

Lectures uniquement : liste des archives (nom, taille, date, jamais leur contenu),
journal d'oms-snap-siem, `systemctl show`, requêtes GET sur OpenSearch 127.0.0.1:9200.
Toute autre méthode HTTP est refusée par construction. Sorties : JSON et Markdown,
et en option l'inventaire des index attendu par omni-restore-drill.py --inventaire-source.

  python3 tools/omni-backup-inventory.py --json /tmp/x.json --markdown /tmp/x.md
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("omni_restore_drill", ROOT / "tools/omni-restore-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)

OPENSEARCH = "http://127.0.0.1:9200"
UNITES = ("omni-backup-config", "omni-mongo-backup", "oms-snap-siem", "oms-snap-siem-test")
MOTIF_CONFIG = re.compile(r"^omni-siem-config_\d{4}-\d{2}-\d{2}\.tar\.gz\.enc$")
MOTIF_MONGO = re.compile(r"^(omni-mongo-\d{8}-\d{6}-[0-9a-f]{12}|graylog-mongo-\d{8}-\d{4,6})\.archive\.gz$")
LIGNE_DEBUT = re.compile(r"^(\S+ \S+) === snapshot selectif : (\d+) index, ~(\d+) Go bruts ===")
LIGNE_FIN = re.compile(r"^(\S+ \S+) snapshot (\S+) : (\w+) (\d+)/(\d+) shards, (\d+) echec\(s\), (\d+) min")
LIGNE_TEST = re.compile(r"^(\S+ \S+) Test de restauration (OK|EN ECHEC)")
# Hypothèses non mesurées sur la production, à remplacer par les durées d'un exercice.
HYPOTHESES = {"socle_minutes": 60, "configuration_minutes": 15, "mongodb_minutes": 5,
              "graylog_minutes": 10, "controles_minutes": 15, "debit_transfert_mo_s": 50}


def get(chemin):
    requete = urllib.request.Request(OPENSEARCH + chemin, method="GET", headers={"Accept": "application/json"})
    if requete.get_method() != "GET":
        raise RuntimeError("lecture seule")
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(requete, timeout=120) as reponse:
        return json.load(reponse)


def fichiers(repertoire, motif):
    resultat = []
    try:
        for entree in os.scandir(repertoire):
            if entree.is_file(follow_symlinks=False) and motif.match(entree.name):
                info = entree.stat(follow_symlinks=False)
                resultat.append({"nom": entree.name, "octets": info.st_size,
                                 "mtime": dt.datetime.fromtimestamp(info.st_mtime).astimezone().isoformat()})
    except OSError:
        return None
    return resultat


def serie(entrees, instant):
    """Âge, fréquence et tailles d'une série de sauvegardes (horodatage du nom, sinon mtime)."""
    if not entrees:
        return {"nombre": 0}
    points = []
    for entree in entrees:
        horodatage, precision = drill.horodatage_nom(entree["nom"])
        mtime = dt.datetime.fromisoformat(entree["mtime"])
        # Un nom à la journée ne donne pas l'heure : la date de modification est plus précise.
        if horodatage is None or precision == "jour":
            horodatage, precision = mtime, "mtime"
        points.append((horodatage, entree["octets"], entree["nom"], precision))
    points.sort()
    ecarts = [(b[0] - a[0]).total_seconds() for a, b in zip(points, points[1:])]
    tailles = [p[1] for p in points]
    return {"nombre": len(points), "plus_recente": points[-1][2], "horodatage_recent": points[-1][0].isoformat(),
            "precision": points[-1][3], "age_secondes": round((instant - points[-1][0]).total_seconds()),
            "plus_ancienne": points[0][0].isoformat(),
            "intervalle_median_secondes": round(statistics.median(ecarts)) if ecarts else None,
            "intervalle_max_secondes": round(max(ecarts)) if ecarts else None,
            "octets_recent": tailles[-1], "octets_median": round(statistics.median(tailles)), "octets_total": sum(tailles)}


def analyser_journal_snap(lignes):
    """Exécutions d'oms-snap-siem (début, volume brut annoncé, durée, statut) et tests de restauration."""
    executions, tests, courant = [], [], None
    for ligne in lignes:
        debut = LIGNE_DEBUT.match(ligne)
        if debut:
            courant = {"debut": debut[1], "index": int(debut[2]), "gio_bruts": int(debut[3])}
            continue
        fin = LIGNE_FIN.match(ligne)
        if fin and courant:
            courant.update(snapshot=fin[2], statut=fin[3], shards=int(fin[5]), echecs=int(fin[6]), minutes=int(fin[7]))
            executions.append(courant)
            courant = None
            continue
        test = LIGNE_TEST.match(ligne)
        if test:
            tests.append({"date": test[1], "resultat": test[2]})
    return {"executions": executions, "tests_restauration": tests}


def debit_snapshot_complet(executions):
    """Débit de la plus longue exécution (snapshot initial complet) : seul transfert intégral mesuré."""
    candidates = [e for e in executions if e.get("statut") == "SUCCESS" and e.get("minutes")]
    if not candidates:
        return None
    longue = max(candidates, key=lambda e: e["minutes"])
    return {"snapshot": longue["snapshot"], "gio": longue["gio_bruts"], "minutes": longue["minutes"],
            "debit_mo_s": drill.debit_mo_s(longue["gio_bruts"] * (1 << 30), longue["minutes"] * 60)}


def couverture(index_cluster, index_snapshot):
    """Part du volume et des documents présents dans le snapshot, par préfixe d'index."""
    dans = set(index_snapshot)
    prefixes = {}
    for index in index_cluster:
        if drill.INDEX_IGNORES.match(index["index"]):
            continue
        prefixe = re.sub(r"_\d+$", "", index["index"])
        p = prefixes.setdefault(prefixe, {"index": 0, "index_couverts": 0, "octets": 0, "octets_couverts": 0, "docs": 0})
        p["index"] += 1
        p["octets"] += index["octets"]
        p["docs"] += index["docs"]
        if index["index"] in dans:
            p["index_couverts"] += 1
            p["octets_couverts"] += index["octets"]
    total = sum(p["octets"] for p in prefixes.values())
    couvert = sum(p["octets_couverts"] for p in prefixes.values())
    return {"prefixes": prefixes, "octets_total": total, "octets_couverts": couvert,
            "part_couverte": round(couvert / total, 4) if total else None,
            "non_couverts": sorted(k for k, p in prefixes.items() if p["index_couverts"] == 0)}


def estimer_rto(archive_octets, snapshot_octets, debit_restauration, hypotheses=None):
    """Estimation du RTO : composantes mesurées (volumes, débit) et hypothèses explicites."""
    h = {**HYPOTHESES, **(hypotheses or {})}
    composantes = {
        "socle": (h["socle_minutes"] * 60, "hypothèse"),
        "transfert_archive": ((archive_octets or 0) / 1e6 / h["debit_transfert_mo_s"], "volume mesuré, débit supposé"),
        "configuration": (h["configuration_minutes"] * 60, "hypothèse"),
        "mongodb": (h["mongodb_minutes"] * 60, "hypothèse (relevé du 22/11/2026 : 2,6 s de mongorestore)"),
        "restauration_index": ((snapshot_octets or 0) / 1e6 / debit_restauration if debit_restauration else None,
                               "volume mesuré, débit d'écriture du snapshot initial pris comme débit de lecture"),
        "graylog": (h["graylog_minutes"] * 60, "hypothèse"),
        "controles": (h["controles_minutes"] * 60, "hypothèse"),
    }
    def somme(noms):
        valeurs = [composantes[n][0] for n in noms]
        return None if any(v is None for v in valeurs) else round(sum(valeurs))
    collecte = ("socle", "transfert_archive", "configuration", "mongodb", "graylog")
    return {"composantes": {k: {"secondes": None if v is None else round(v), "origine": o} for k, (v, o) in composantes.items()},
            "rto_collecte_secondes": somme(collecte),
            "rto_complet_secondes": somme(collecte + ("restauration_index", "controles")),
            "hypotheses": h}


def duree_unite(unite):
    sortie = subprocess.run(["systemctl", "show", unite + ".service", "-p", "Result", "-p", "ExecMainStartTimestampMonotonic",
                             "-p", "ExecMainExitTimestampMonotonic", "-p", "ExecMainStartTimestamp"],
                            capture_output=True, text=True, timeout=15)
    valeurs = dict(ligne.split("=", 1) for ligne in sortie.stdout.splitlines() if "=" in ligne)
    debut, fin = int(valeurs.get("ExecMainStartTimestampMonotonic") or 0), int(valeurs.get("ExecMainExitTimestampMonotonic") or 0)
    return {"resultat": valeurs.get("Result"), "dernier_debut": valeurs.get("ExecMainStartTimestamp") or None,
            "derniere_duree_secondes": round((fin - debut) / 1e6) if fin > debut > 0 else None}


def collecter(args):
    instant = dt.datetime.now().astimezone()
    mesures = {"schema_version": 1, "instant": instant.isoformat(), "hote": os.uname().nodename, "lecture_seule": True}
    mesures["archives_config"] = serie(fichiers(args.repertoire_config, MOTIF_CONFIG) or [], instant)
    mesures["archives_config"]["portee"] = "copie locale (rétention courte) ; le partage SMB n'est pas listé par cet outil"
    mesures["archives_mongo"] = serie(fichiers(args.repertoire_mongo, MOTIF_MONGO) or [], instant)
    mesures["unites"] = {u: duree_unite(u) for u in UNITES}
    try:
        lignes = Path(args.journal_snap).read_text(errors="replace").splitlines()
    except OSError:
        lignes = []
    journal = analyser_journal_snap(lignes)
    mesures["journal_snap"] = {"executions": len(journal["executions"]), "dernieres": journal["executions"][-7:],
                               "tests_restauration": journal["tests_restauration"][-5:]}
    mesures["debit_snapshot_complet"] = debit_snapshot_complet(journal["executions"])
    depot = get(f"/_snapshot/{args.depot}")[args.depot]
    snapshots = get(f"/_snapshot/{args.depot}/_all").get("snapshots", [])
    reussis = sorted((s for s in snapshots if s.get("state") == "SUCCESS"), key=lambda s: s["start_time_in_millis"])
    mesures["snapshots"] = [{"nom": s["snapshot"], "index": len(s.get("indices", [])), "debut": s.get("start_time"),
                             "duree_secondes": round(s.get("duration_in_millis", 0) / 1000), "shards_echec": s.get("shards", {}).get("failed")}
                            for s in snapshots]
    index_cluster = drill.index_depuis_cat(get("/_cat/indices?format=json&h=index,docs.count,store.size,health&bytes=b"))
    dernier = reussis[-1] if reussis else None
    if dernier:
        statut = get(f"/_snapshot/{args.depot}/{dernier['snapshot']}/_status")["snapshots"][0]["stats"]
        debut = dt.datetime.fromtimestamp(dernier["start_time_in_millis"] / 1000).astimezone()
        mesures["dernier_snapshot"] = {
            "nom": dernier["snapshot"], "age_secondes": round((instant - debut).total_seconds()),
            "octets_total": statut["total"]["size_in_bytes"], "octets_incrementaux": statut["incremental"]["size_in_bytes"],
            "duree_secondes": round(statut["time_in_millis"] / 1000),
            "debit_incremental_mo_s": drill.debit_mo_s(statut["incremental"]["size_in_bytes"], statut["time_in_millis"] / 1000)}
        mesures["couverture"] = couverture(index_cluster, dernier.get("indices", []))
        ecarts = [(b["start_time_in_millis"] - a["start_time_in_millis"]) / 1000 for a, b in zip(reussis, reussis[1:])]
        mesures["snapshots_intervalle_median_secondes"] = round(statistics.median(ecarts)) if ecarts else None
    mesures["depot"] = {"nom": args.depot, "emplacement": depot.get("settings", {}).get("location")}
    if args.taille_depot and mesures["depot"]["emplacement"]:
        du = subprocess.run(["du", "-sb", mesures["depot"]["emplacement"]], capture_output=True, text=True, timeout=1800)
        mesures["depot"]["octets_disque"] = int(du.stdout.split()[0]) if du.returncode == 0 and du.stdout else None
    debit = args.debit_restauration_mo_s or (mesures["debit_snapshot_complet"] or {}).get("debit_mo_s")
    mesures["estimation_rto"] = estimer_rto(mesures["archives_config"].get("octets_recent"),
                                            mesures.get("dernier_snapshot", {}).get("octets_total"), debit,
                                            {"socle_minutes": args.socle_minutes})
    if args.inventaire_index:
        alias = get("/_cat/aliases?format=json&h=alias,index")
        ecriture = {a["index"] for a in alias if str(a.get("alias", "")).endswith("_deflector")}
        ecrire(Path(args.inventaire_index), json.dumps({"instant": instant.isoformat(), "index": {
            i["index"]: {"docs": i["docs"], "ecriture": i["index"] in ecriture}
            for i in index_cluster if not drill.INDEX_IGNORES.match(i["index"])}}, indent=2) + "\n")
    return mesures


def rendre_markdown(m):
    d = drill.duree
    def go(octets):
        if octets is None:
            return "n.d."
        texte = f"{octets / (1 << 30):.1f} Gio" if octets >= 1 << 30 else f"{octets / (1 << 20):.1f} Mio"
        return texte.replace(".", ",")
    l = [f"# Intrants RPO/RTO mesurés le {m['instant']} sur `{m['hote']}`", "", "## Sauvegardes", "",
         "| Source | Nombre | Plus récente | Âge | Intervalle médian | Taille récente |", "|---|---|---|---|---|---|"]
    for nom, cle in (("Archive de configuration (locale)", "archives_config"), ("Archives MongoDB", "archives_mongo")):
        s = m[cle]
        l.append(f"| {nom} | {s.get('nombre', 0)} | `{s.get('plus_recente', '-')}` | {d(s.get('age_secondes'))} | "
                 f"{d(s.get('intervalle_median_secondes'))} | {go(s.get('octets_recent'))} |")
    s = m.get("dernier_snapshot")
    if s:
        l.append(f"| Snapshot OpenSearch | {len(m['snapshots'])} | `{s['nom']}` | {d(s['age_secondes'])} | "
                 f"{d(m.get('snapshots_intervalle_median_secondes'))} | {go(s['octets_total'])} "
                 f"(incrément {go(s['octets_incrementaux'])}) |")
    c = m.get("couverture")
    if c:
        l += ["", "## Couverture des journaux par le snapshot", "",
              f"{go(c['octets_couverts'])} couverts sur {go(c['octets_total'])} "
              f"({100 * (c['part_couverte'] or 0):.1f} %)".replace(".", ",") + ". Préfixes sans aucun index couvert : "
              + (", ".join(f"`{p}`" for p in c["non_couverts"]) or "aucun") + "."]
    l += ["", "## Dernières exécutions", "", "| Unité | Résultat | Dernier début | Durée |", "|---|---|---|---|"]
    for unite, u in m["unites"].items():
        l.append(f"| {unite} | {u['resultat']} | {u['dernier_debut'] or '-'} | {d(u['derniere_duree_secondes'])} |")
    if m.get("debit_snapshot_complet"):
        p = m["debit_snapshot_complet"]
        l += ["", f"Snapshot complet le plus long : `{p['snapshot']}`, {p['gio']} Gio en {p['minutes']} min, "
              f"soit {p['debit_mo_s']} Mo/s (écriture /data vers /home sous charge de production)."]
    e = m["estimation_rto"]
    l += ["", "## Estimation du RTO (à confirmer par un exercice)", "", "| Composante | Durée | Origine |", "|---|---|---|"]
    for nom, comp in e["composantes"].items():
        l.append(f"| {nom} | {d(comp['secondes'])} | {comp['origine']} |")
    l += ["", f"- RTO reprise de la collecte : **{d(e['rto_collecte_secondes'])}**",
          f"- RTO complet avec l'historique couvert : **{d(e['rto_complet_secondes'])}**"]
    return "\n".join(l) + "\n"


def ecrire(chemin, contenu):
    if chemin.is_symlink():
        raise ValueError("destination en lien symbolique refusée")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=chemin.parent, delete=False) as flux:
        flux.write(contenu)
    os.chmod(flux.name, 0o600)
    os.replace(flux.name, chemin)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repertoire-config", default="/var/backups/siem")
    parser.add_argument("--repertoire-mongo", default="/home/siem-backup/mongo")
    parser.add_argument("--journal-snap", default="/var/log/oms-snap-siem.log")
    parser.add_argument("--depot", default="graylog_fs")
    parser.add_argument("--taille-depot", action="store_true", help="mesure l'occupation disque du dépôt (du, lent)")
    parser.add_argument("--debit-restauration-mo-s", type=float, help="débit de restauration (défaut : snapshot complet mesuré)")
    parser.add_argument("--socle-minutes", type=int, default=HYPOTHESES["socle_minutes"])
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--inventaire-index", type=Path, help="écrit l'inventaire des index pour l'exercice")
    args = parser.parse_args(argv)
    mesures = collecter(args)
    texte = json.dumps(mesures, indent=2, ensure_ascii=False) + "\n"
    if args.json:
        ecrire(args.json, texte)
    else:
        sys.stdout.write(texte)
    if args.markdown:
        ecrire(args.markdown, rendre_markdown(mesures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
