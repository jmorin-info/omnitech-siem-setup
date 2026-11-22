#!/usr/bin/env python3
"""Mise à jour des définitions d'événements Graylog corrigées en novembre 2026.

Mode par défaut : PLAN, en lecture seule. Pour chaque cible de
tools/maj-detections-2026-11/cibles.json, l'outil lit la définition en production
(GET), construit la définition cible, affiche le diff production -> cible et
compte sur OpenSearch (POST _count, lecture seule) les messages trouvés par la
requête actuelle et par la requête cible sur la fenêtre demandée (30 jours).

--apply : applique les cibles une par une (PUT /events/definitions/<id>, état de
planification conservé), après sauvegarde JSON de la définition dans le répertoire
--sauvegardes. Idempotent : une définition déjà conforme n'est pas réécrite. Rien
n'est créé ni supprimé ; la seule désactivation possible est celle listée
explicitement dans le fichier de cibles (« state »: « DISABLED »), faite par
PUT /events/definitions/<id>/unschedule. Une dérive (valeur de production
différente de « attendu_avant ») bloque la cible, sauf --forcer.

--rollback DIR : remet en production les définitions sauvegardées dans DIR
(PUT du JSON sauvegardé, état de planification d'origine).

Dépendances : bibliothèque standard ; réutilise le client GET, la traduction
query_string et la résolution des index de tools/omni-detection-validate.py.
Code retour : 0 succès ; 1 au moins une cible en dérive, introuvable ou en échec ;
3 erreur d'usage ou API injoignable.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import difflib
import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ICI = Path(__file__).resolve().parent
DEPOT = ICI.parent
CIBLES_PAR_DEFAUT = ICI / "maj-detections-2026-11" / "cibles.json"
CHAMPS_SERVEUR = ("_scope", "matched_at", "updated_at", "scheduler", "state")


def _charger_validateur():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("omni_detection_validate_maj", ICI / "omni-detection-validate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["omni_detection_validate_maj"] = mod
    spec.loader.exec_module(mod)
    return mod


dv = _charger_validateur()


# =============================================================================
# Accès Graylog : lecture (validateur) et écriture (uniquement en --apply/--rollback)
# =============================================================================
class ClientGraylogEcriture(dv.ClientGraylog):
    """Ajoute PUT au client GET du validateur. N'est instancié qu'avec --apply ou --rollback."""

    def put(self, chemin: str, corps: dict | None = None):
        data = json.dumps(corps).encode() if corps is not None else None
        req = urllib.request.Request(self.base + chemin, data=data, method="PUT",
                                     headers={"Authorization": self._auth, "Accept": "application/json",
                                              "Content-Type": "application/json", "X-Requested-By": "maj-detections"})
        with urllib.request.urlopen(req, timeout=90, context=self._ssl) as r:
            brut = r.read()
        return json.loads(brut) if brut else {}


# =============================================================================
# Construction de la cible
# =============================================================================
def valeur_live(defn: dict, champ: str, titres_flux: dict):
    cfg = defn.get("config", {})
    if champ == "streams_titres":
        return [titres_flux.get(s, s) for s in cfg.get("streams") or []]
    if champ == "state":
        return defn.get("state", "ENABLED")
    if champ.startswith("field_spec."):
        _, cle, _ = champ.split(".", 2)
        provs = ((defn.get("field_spec") or {}).get(cle) or {}).get("providers") or [{}]
        return provs[0].get("template")
    return cfg.get(champ)


def _normal(v):
    """Comparaison tolérante aux nombres (10 et 10.0) et aux clés de série absentes."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, list):
        return [_normal(x) for x in v]
    if isinstance(v, dict):
        return {k: _normal(x) for k, x in sorted(v.items()) if not (k == "field" and x is None)}
    return v


def egal(a, b) -> bool:
    return _normal(a) == _normal(b)


def construire_cible(live: dict, cible: dict, ids_flux: dict) -> dict:
    """Définition cible = définition de production + champs de la cible. Lève KeyError si un flux manque."""
    out = copy.deepcopy(live)
    cfg = out.setdefault("config", {})
    for champ, val in cible.items():
        if champ == "state":
            out["state"] = val
        elif champ == "streams_titres":
            cfg["streams"] = [ids_flux[t] for t in val]
        elif champ.startswith("field_spec."):
            _, cle, _ = champ.split(".", 2)
            prov = out["field_spec"][cle]["providers"][0]
            prov["template"] = val
        else:
            cfg[champ] = copy.deepcopy(val)
    return out


def corps_put(defn: dict) -> dict:
    return {k: v for k, v in defn.items() if k not in CHAMPS_SERVEUR}


def vue_diff(defn: dict, titres_flux: dict) -> str:
    cfg = defn.get("config", {})
    vue = {
        "etat": defn.get("state", "ENABLED"),
        "query": cfg.get("query"),
        "flux": sorted(titres_flux.get(s, s) for s in cfg.get("streams") or []),
        "group_by": cfg.get("group_by"),
        "series": cfg.get("series"),
        "conditions": cfg.get("conditions"),
        "field_spec": {k: [p.get("template") for p in (v or {}).get("providers") or []]
                       for k, v in (defn.get("field_spec") or {}).items()},
        "key_spec": defn.get("key_spec"),
    }
    return json.dumps(vue, ensure_ascii=False, indent=1, sort_keys=True)


def diff_texte(avant: str, apres: str) -> list[str]:
    return [ligne for ligne in difflib.unified_diff(avant.splitlines(), apres.splitlines(),
                                                    "production", "cible", lineterm="", n=0)
            if not ligne.startswith("@@")]


# =============================================================================
# Comptage (lecture seule)
# =============================================================================
def compter(os_client, defn: dict, flux: dict, isets: dict, fenetre_j: int):
    cfg = defn.get("config", {})
    prefixes, ids = dv._index_cibles(cfg.get("streams") or [], flux, isets)
    if not prefixes:
        return None
    corps = dv.corps_requete(cfg.get("query", ""), ids, f"now-{fenetre_j}d")
    chemin = f"/{dv._motif_index(prefixes)}/_count?ignore_unavailable=true&allow_no_indices=true"
    try:
        return int(os_client.appel("POST", chemin, corps).get("count", 0))
    except dv.ErreurOpenSearch as exc:
        return f"erreur : {exc.raison()}"
    except OSError as exc:
        return f"erreur : {exc}"


# =============================================================================
# Plan, application, retour arrière
# =============================================================================
def analyser_cible(c: dict, live: dict | None, flux: dict) -> dict:
    titres_flux = {i: s.get("title", i) for i, s in flux.items()}
    ids_flux = {s.get("title"): i for i, s in flux.items()}
    res = {"id": c["id"], "titre": c["titre"], "chantier": c.get("chantier"), "motif": c.get("motif"),
           "statut": None, "derives": [], "diff": [], "live": live, "cible_def": None}
    if live is None:
        res["statut"] = "INTROUVABLE"
        return res
    if live.get("title") != c["titre"]:
        res["derives"].append(f"titre en production « {live.get('title')} »")
    for champ, attendu in (c.get("attendu_avant") or {}).items():
        actuel = valeur_live(live, champ, titres_flux)
        if not egal(actuel, attendu) and not egal(actuel, c["cible"].get(champ)):
            res["derives"].append(f"{champ} : production différente de la valeur relevée le 22/11/2026")
    try:
        cible_def = construire_cible(live, c["cible"], ids_flux)
    except KeyError as exc:
        res["statut"] = "INTROUVABLE"
        res["derives"].append(f"flux introuvable : {exc}")
        return res
    res["cible_def"] = cible_def
    res["diff"] = diff_texte(vue_diff(live, titres_flux), vue_diff(cible_def, titres_flux))
    if all(egal(valeur_live(live, k, titres_flux), v) for k, v in c["cible"].items()):
        res["statut"] = "CONFORME"
    elif res["derives"]:
        res["statut"] = "DERIVE"
    else:
        res["statut"] = "A_APPLIQUER"
    return res


def afficher(res: dict, avant, apres, journal=print):
    journal(f"\n== [{res['statut']}] {res['titre']} ({res['id']}) - chantier {res['chantier']}")
    journal(f"   motif : {res['motif']}")
    for d in res["derives"]:
        journal(f"   dérive : {d}")
    if avant is not None or apres is not None:
        ecart = ""
        if isinstance(avant, int) and isinstance(apres, int):
            ecart = f" (écart {apres - avant:+d})"
        journal(f"   _count : production {avant} -> cible {apres}{ecart}")
    for ligne in res["diff"]:
        journal(f"   {ligne}")


def sauvegarder(rep: Path, live: dict) -> Path:
    rep.mkdir(parents=True, exist_ok=True)
    chemin = rep / f"{live['id']}.json"
    if not chemin.exists():   # on garde l'état d'origine si l'outil est relancé
        chemin.write_text(json.dumps(live, ensure_ascii=False, indent=2), encoding="utf-8")
    return chemin


def appliquer(gl, res: dict, rep: Path, journal=print) -> bool:
    live, cible = res["live"], res["cible_def"]
    sauvegarder(rep, live)
    if live.get("state", "ENABLED") == "ENABLED" and cible.get("state") == "DISABLED" \
            and egal(corps_put(live), corps_put(cible)):
        gl.put(f"/events/definitions/{live['id']}/unschedule")
    else:
        planifier = "true" if cible.get("state", "ENABLED") == "ENABLED" else "false"
        rep_put = gl.put(f"/events/definitions/{live['id']}?schedule={planifier}", corps_put(cible))
        if rep_put.get("id") != live["id"]:
            journal(f"   ECHEC : réponse PUT sans identifiant pour {live['id']}")
            return False
    relu = gl.get(f"/events/definitions/{live['id']}")
    flux_titres = {}
    if not egal(vue_diff(relu, flux_titres), vue_diff(cible, flux_titres)):
        journal(f"   ECHEC : la définition relue ne correspond pas à la cible ({live['id']})")
        return False
    journal(f"   appliqué ; sauvegarde {rep / (live['id'] + '.json')}")
    return True


def rollback(gl, rep: Path, journal=print) -> int:
    fichiers = sorted(rep.glob("*.json"))
    if not fichiers:
        journal(f"aucune sauvegarde dans {rep}")
        return 3
    erreurs = 0
    for f in fichiers:
        orig = json.loads(f.read_text(encoding="utf-8"))
        planifier = "true" if orig.get("state", "ENABLED") == "ENABLED" else "false"
        try:
            gl.put(f"/events/definitions/{orig['id']}?schedule={planifier}", corps_put(orig))
            journal(f"restauré : {orig.get('title')} ({orig['id']}), planification {planifier}")
        except (urllib.error.URLError, OSError) as exc:
            erreurs += 1
            journal(f"ECHEC restauration {orig['id']} : {exc}")
    return 1 if erreurs else 0


# =============================================================================
def main(argv=None, gl=None, os_client=None, journal=print) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vars", type=Path, default=DEPOT / "00-vars.env")
    ap.add_argument("--graylog-url", default=None)
    ap.add_argument("--opensearch", default=dv.OPENSEARCH_PAR_DEFAUT)
    ap.add_argument("--cibles", type=Path, default=CIBLES_PAR_DEFAUT)
    ap.add_argument("--fenetre-jours", type=int, default=30)
    ap.add_argument("--sans-comptage", action="store_true", help="n'interroge pas OpenSearch")
    ap.add_argument("--seulement", action="append", default=[],
                    help="identifiant ou chantier (ex. 1-casse) à traiter ; répétable")
    ap.add_argument("--apply", action="store_true", help="applique les cibles (PUT), après sauvegarde")
    ap.add_argument("--forcer", action="store_true", help="applique aussi les cibles en dérive")
    ap.add_argument("--sauvegardes", type=Path, default=None,
                    help="répertoire des sauvegardes JSON (obligatoire avec --apply et --rollback)")
    ap.add_argument("--rollback", action="store_true", help="restaure les définitions sauvegardées")
    a = ap.parse_args(argv)

    if (a.apply or a.rollback) and a.sauvegardes is None:
        journal("--apply et --rollback exigent --sauvegardes REPERTOIRE")
        return 3
    if a.apply and a.rollback:
        journal("--apply et --rollback sont exclusifs")
        return 3
    if gl is None:
        gl = (ClientGraylogEcriture if (a.apply or a.rollback) else dv.ClientGraylog)(a.vars, a.graylog_url)
    if a.rollback:
        return rollback(gl, a.sauvegardes, journal)

    cibles = json.loads(a.cibles.read_text(encoding="utf-8"))["cibles"]
    if a.seulement:
        cibles = [c for c in cibles if c["id"] in a.seulement or c.get("chantier") in a.seulement]
    try:
        flux = {s["id"]: s for s in gl.get("/streams").get("streams", [])}
        isets = {i["id"]: i for i in gl.get("/system/indices/index_sets?skip=0&limit=500").get("index_sets", [])}
    except (urllib.error.URLError, OSError) as exc:
        journal(f"API Graylog injoignable : {exc}")
        return 3
    if os_client is None and not a.sans_comptage:
        os_client = dv.ClientOpenSearch(a.opensearch)

    mode = "APPLICATION" if a.apply else "PLAN (lecture seule)"
    journal(f"maj-detections-2026-11 - mode {mode} - {len(cibles)} cible(s) - "
            f"{dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %z')}")
    bilan = {}
    code = 0
    for c in cibles:
        try:
            live = gl.get(f"/events/definitions/{c['id']}")
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            live = None
        res = analyser_cible(c, live, flux)
        avant = apres = None
        if os_client is not None and res["cible_def"] is not None:
            avant = compter(os_client, live, flux, isets, a.fenetre_jours)
            apres = (avant if live.get("config", {}).get("query") == res["cible_def"]["config"].get("query")
                     and live["config"].get("streams") == res["cible_def"]["config"].get("streams")
                     else compter(os_client, res["cible_def"], flux, isets, a.fenetre_jours))
        afficher(res, avant, apres, journal)
        statut = res["statut"]
        if a.apply and (statut == "A_APPLIQUER" or (statut == "DERIVE" and a.forcer)):
            try:
                statut = "APPLIQUE" if appliquer(gl, res, a.sauvegardes, journal) else "ECHEC"
            except (urllib.error.URLError, OSError, KeyError) as exc:
                journal(f"   ECHEC : {exc}")
                statut = "ECHEC"
            if statut == "ECHEC":
                bilan[statut] = bilan.get(statut, 0) + 1
                journal("arrêt après échec : les cibles suivantes ne sont pas traitées")
                code = 1
                break
        if statut in ("DERIVE", "INTROUVABLE"):
            code = 1
        bilan[statut] = bilan.get(statut, 0) + 1
    journal("\nBilan : " + ", ".join(f"{k} {v}" for k, v in sorted(bilan.items())))
    if not a.apply:
        journal("Aucune écriture effectuée (mode plan). Appliquer : --apply --sauvegardes REPERTOIRE")
    return code


if __name__ == "__main__":
    sys.exit(main())
