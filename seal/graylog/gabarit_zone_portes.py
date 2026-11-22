#!/usr/bin/env python3
"""Gabarit de la table de zones physiques SEAL (lookup omni-seal-zone), sans accès SQL.

La table /etc/graylog/lookup/omni-seal-zone.csv est normalement produite par
regen_zone_lookup.sh depuis la vue SEAL dbo.vw_SealZone_SIEM. Tant que cette vue
n'existe pas (étapes opérateur de seal/docs/ZONES-TOPOLOGIE.md), la table ne contient
que son en-tête, seal_zone n'est jamais posé et ZON-001 est inerte.

Ce script prépare le travail de l'opérateur sans rien écrire en production :

  gabarit : lit OpenSearch en lecture seule (POST _search, agrégation) et écrit un CSV
            listant chaque porte vue sur la fenêtre (clé seal_site:OBFI_ID, identique à
            celle de 16-seal-zone.rule), avec une colonne ZONE_PATH vide à renseigner ;
            --existant reprend les zones déjà saisies dans un gabarit précédent ;
  table   : à partir d'un gabarit renseigné, produit le CSV du lookup (SITE_OBFI,
            ZONE_PATH) en ne gardant que les lignes dont la zone est renseignée
            (une zone vide poserait seal_zone="" et fausserait le regroupement de ZON-001).

Le fichier produit est écrit là où --sortie l'indique ; l'installation dans
/etc/graylog/lookup reste une action d'exploitation (voir ZONES-TOPOLOGIE.md).
Dépendances : bibliothèque standard.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path

ENTETE_GABARIT = ["SITE_OBFI", "ZONE_PATH", "PORTE_LIBELLE", "EVENEMENTS"]
ENTETE_TABLE = ["SITE_OBFI", "ZONE_PATH"]


def obfi_normalise(brut) -> str | None:
    """Même normalisation que 16-seal-zone.rule : to_long(to_double(x)) ("0.279e3" -> "279")."""
    try:
        return str(int(Decimal(str(brut))))
    except (InvalidOperation, ValueError, TypeError):
        return None


def corps_recherche(jours: int, apres: dict | None = None) -> dict:
    comp = {"size": 500, "sources": [{"site": {"terms": {"field": "seal_site"}}},
                                     {"obfi": {"terms": {"field": "target_object_id"}}}]}
    if apres:
        comp["after"] = apres
    return {"size": 0,
            "query": {"bool": {"filter": [{"term": {"event_domain": "access"}},
                                          {"exists": {"field": "target_object_id"}},
                                          {"range": {"timestamp": {"gte": f"now-{jours}d"}}}]}},
            "aggs": {"portes": {"composite": comp,
                                "aggs": {"libelle": {"terms": {"field": "target_object_label", "size": 1}}}}}}


def lire_portes(appel, index: str, jours: int) -> dict:
    """appel(chemin, corps) -> réponse JSON. Retourne {clé: (libellé, nb)}."""
    portes, apres = {}, None
    for _ in range(1000):
        rep = appel(f"/{index}/_search", corps_recherche(jours, apres))
        agg = rep.get("aggregations", {}).get("portes", {})
        for b in agg.get("buckets", []):
            obfi = obfi_normalise(b["key"]["obfi"])
            if obfi is None:
                continue
            cle = f"{b['key']['site']}:{obfi}"
            lib = ((b.get("libelle") or {}).get("buckets") or [{}])[0].get("key", "")
            ancien = portes.get(cle, ("", 0))
            portes[cle] = (ancien[0] or lib, ancien[1] + b["doc_count"])
        apres = agg.get("after_key")
        if not apres or not agg.get("buckets"):
            break
    return portes


def lire_csv(chemin: Path) -> list[dict]:
    with chemin.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def ecrire_gabarit(portes: dict, sortie: Path, existant: Path | None = None) -> int:
    zones = {}
    if existant and existant.is_file():
        zones = {r["SITE_OBFI"]: r.get("ZONE_PATH", "") for r in lire_csv(existant)}
    with sortie.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(ENTETE_GABARIT)
        for cle in sorted(portes, key=lambda k: (k.split(":")[0], int(k.split(":")[1]))):
            lib, nb = portes[cle]
            w.writerow([cle, zones.get(cle, ""), lib, nb])
    return len(portes)


def ecrire_table(gabarit: Path, sortie: Path) -> tuple[int, int]:
    lignes = lire_csv(gabarit)
    gardees = [r for r in lignes if (r.get("ZONE_PATH") or "").strip()]
    with sortie.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(ENTETE_TABLE)
        for r in gardees:
            w.writerow([r["SITE_OBFI"].strip(), r["ZONE_PATH"].strip()])
    return len(gardees), len(lignes) - len(gardees)


def _appel_opensearch(url: str):
    def appel(chemin, corps):
        if not chemin.endswith("/_search"):
            raise PermissionError("lecture seule : _search uniquement")
        req = urllib.request.Request(url.rstrip("/") + chemin, data=json.dumps(corps).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)
    return appel


def main(argv=None, appel=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sp = ap.add_subparsers(dest="mode", required=True)
    g = sp.add_parser("gabarit", help="liste des portes à rattacher à une zone (lecture OpenSearch)")
    g.add_argument("--sortie", type=Path, required=True)
    g.add_argument("--existant", type=Path, default=None, help="gabarit déjà renseigné à reprendre")
    g.add_argument("--opensearch", default="http://127.0.0.1:9200")
    g.add_argument("--index", default="omni-seal-access_*")
    g.add_argument("--jours", type=int, default=30)
    t = sp.add_parser("table", help="CSV du lookup à partir d'un gabarit renseigné")
    t.add_argument("--gabarit", type=Path, required=True)
    t.add_argument("--sortie", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.mode == "gabarit":
        portes = lire_portes(appel or _appel_opensearch(a.opensearch), a.index, a.jours)
        n = ecrire_gabarit(portes, a.sortie, a.existant)
        print(f"{n} porte(s) écrite(s) dans {a.sortie} ; renseigner ZONE_PATH puis lancer le mode table.")
        return 0
    gardees, vides = ecrire_table(a.gabarit, a.sortie)
    print(f"{gardees} ligne(s) avec zone écrite(s) dans {a.sortie} ; {vides} porte(s) sans zone ignorée(s).")
    return 0 if gardees else 1


if __name__ == "__main__":
    sys.exit(main())
