#!/usr/bin/env python3
"""Validation continue des définitions d'événements Graylog, en LECTURE SEULE.

Trois familles de contrôles, combinables avec --controles :

  statique  : pour chaque définition active (type aggregation-v1), via l'API
              Graylog en GET : requête valide (analyse locale + GET _validate/query
              d'OpenSearch), flux existants et non désactivés, index set présent,
              notifications existantes, champs de la requête / du group_by / des
              séries présents dans le mapping des index visés (GET _mapping/field),
              planification cohérente (search_within_ms / execute_every_ms, état du
              planificateur renvoyé par l'API), producteur des étiquettes alert_tag /
              v3_tag (règle de pipeline connectée ou robot du dépôt) ;
  vivacite  : la requête de chaque définition est traduite en query_string
              OpenSearch, restreinte aux index et aux flux visés, et comptée avec
              _count sur une fenêtre longue (30 j) puis récente (7 j) ; les flux
              visés sont comptés de la même façon ; les événements émis par la
              définition sont comptés dans l'index set Events (_search agrégé) ;
  fixtures  : cas de test synthétiques (tools/detection-validation/fixtures/*.json)
              évalués EN MÉMOIRE contre la définition en production (ou, avec
              --hors-ligne, contre l'instantané embarqué dans la fixture). Aucun
              message n'est créé dans Graylog.

Mode --replay URL : rejoue les fixtures sur un OpenSearch JETABLE (jamais celui de
la production : refus si l'URL est la boucle locale 9200, si le cluster s'appelle
« graylog » ou s'il héberge des index Graylog) pour vérifier que la traduction
query_string de l'évaluateur hors ligne donne les mêmes documents qu'OpenSearch.

Appels réseau vers la production : GET uniquement sur l'API Graylog ; GET
(_mapping, _validate, _cat) et POST de recherche en lecture seule (_count,
_search) sur OpenSearch. Dépendances : bibliothèque standard seule.

Code retour : 0 aucune détection critique cassée ; 2 au moins une détection
critique cassée (défaut de gravité critique) ; 3 erreur d'usage ou API injoignable.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

ICI = Path(__file__).resolve().parent
DEPOT = ICI.parent
FIXTURES_PAR_DEFAUT = ICI / "detection-validation" / "fixtures"
EXCEPTIONS_PAR_DEFAUT = ICI / "detection-validation" / "exceptions.json"
OPENSEARCH_PAR_DEFAUT = "http://127.0.0.1:9200"

GRAVITES = ("critique", "elevee", "moyenne", "faible", "info")
RANG_GRAVITE = {g: i for i, g in enumerate(GRAVITES)}
CHAMPS_INTEGRES = {"message", "full_message", "source", "timestamp", "streams", "_id", "gl2_message_id",
                   "gl2_source_input", "gl2_source_node", "_exists_"}
CHAMPS_TEXTE = {"message", "full_message"}          # analysés (standard) dans les index Graylog
CHAMPS_PRODUCTEURS = ("alert_tag", "v3_tag")         # étiquettes posées par pipeline ou robot
VIVACITES_MORTES = ("muette", "source_absente", "battement_absent")


# =============================================================================
# 1. Analyse de la syntaxe de requête Graylog (Lucene classique, sous-ensemble)
# =============================================================================
class ErreurRequete(ValueError):
    pass


SPECIAUX = set(' \t\r\n()[]{}":^~!')


@dataclass
class Terme:
    champ: str | None
    nature: str            # exact | phrase | wildcard | range | cmp | exists | regex | tout
    valeur: object = None


@dataclass
class Booleen:
    clauses: list = field(default_factory=list)   # [(occur, noeud)] occur in must|should|must_not


class ToutDoc:
    """Correspond à tous les documents (requête vide ou « * »)."""


def _lexer(q: str):
    jetons, i, n = [], 0, len(q)
    while i < n:
        c = q[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c in "()":
            jetons.append((c, c))
            i += 1
            continue
        if c == ":":
            jetons.append((":", ":"))
            i += 1
            continue
        if q.startswith("&&", i) or q.startswith("||", i):
            jetons.append(("AND" if c == "&" else "OR", q[i:i + 2]))
            i += 2
            continue
        if c in "+-!" and (not jetons or jetons[-1][0] in ("(", "AND", "OR", "NOT", "+", "-")
                           or q[i - 1] in " \t\r\n("):
            jetons.append(("NOT" if c == "!" else c, c))
            i += 1
            continue
        if c == '"':
            j, buf = i + 1, []
            while j < n and q[j] != '"':
                if q[j] == "\\" and j + 1 < n:
                    buf.append(q[j + 1])
                    j += 2
                    continue
                buf.append(q[j])
                j += 1
            if j >= n:
                raise ErreurRequete("guillemet non fermé")
            jetons.append(("PHRASE", "".join(buf)))
            i = j + 1
            continue
        if c in "[{":
            fins = [x for x in (q.find("]", i), q.find("}", i)) if x != -1]
            fin = min(fins) if fins else -1   # [a TO b} est permis : borne fermante quelconque
            if fin == -1:
                raise ErreurRequete("intervalle non fermé")
            corps = q[i + 1:fin]
            m = re.match(r"^\s*(\S+)\s+TO\s+(\S+)\s*$", corps)
            if not m:
                raise ErreurRequete(f"intervalle invalide : {q[i:fin + 1]}")
            jetons.append(("RANGE", (c == "[", m.group(1), m.group(2), q[fin] == "]")))
            i = fin + 1
            continue
        if c == "/":
            j = i + 1
            while j < n and q[j] != "/":
                j += 2 if q[j] == "\\" else 1
            if j >= n:
                raise ErreurRequete("expression régulière non fermée")
            jetons.append(("REGEX", q[i + 1:j]))
            i = j + 1
            continue
        if c in "^~":
            j = i + 1
            while j < n and (q[j].isdigit() or q[j] == "."):
                j += 1
            jetons.append(("MODIF", q[i:j]))
            i = j
            continue
        # terme nu : on garde les échappements pour distinguer les jokers échappés
        j, brut = i, []
        if q.startswith((">=", "<="), i):
            brut.append(q[i:i + 2])
            j += 2
        elif c in "<>":
            brut.append(c)
            j += 1
        while j < n and q[j] not in SPECIAUX:
            if q[j] == "\\" and j + 1 < n:
                brut.append(q[j:j + 2])
                j += 2
                continue
            brut.append(q[j])
            j += 1
        if j == i:
            raise ErreurRequete(f"caractère inattendu {c!r} en position {i}")
        mot = "".join(brut)
        if mot in ("AND", "OR", "NOT"):
            jetons.append((mot, mot))
        else:
            jetons.append(("TERME", mot))
        i = j
    return jetons


def _desechapper(brut: str) -> str:
    return re.sub(r"\\(.)", r"\1", brut)


def _joker(brut: str) -> bool:
    i = 0
    while i < len(brut):
        if brut[i] == "\\":
            i += 2
            continue
        if brut[i] in "*?":
            return True
        i += 1
    return False


def _motif_joker(brut: str) -> str:
    """Terme brut (avec échappements) -> motif regex ancré."""
    out, i = [], 0
    while i < len(brut):
        c = brut[i]
        if c == "\\" and i + 1 < len(brut):
            out.append(re.escape(brut[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "^" + "".join(out) + "$"


class _Analyseur:
    def __init__(self, jetons):
        self.j, self.p = jetons, 0

    def voir(self):
        return self.j[self.p] if self.p < len(self.j) else (None, None)

    def prendre(self):
        t = self.voir()
        self.p += 1
        return t

    def requete(self, champ_defaut, fin=None):
        clauses = []
        while True:
            typ, _ = self.voir()
            if typ is None or typ == fin:
                break
            conj = None
            if typ in ("AND", "OR"):
                conj = typ
                self.prendre()
                typ, _ = self.voir()
                if typ is None or typ == fin:
                    raise ErreurRequete(f"opérateur {conj} sans opérande")
            mod = None
            while typ in ("NOT", "+", "-"):
                mod = "NOT" if typ in ("NOT", "-") else "+"
                self.prendre()
                typ, _ = self.voir()
            noeud = self.clause(champ_defaut)
            # Sémantique QueryParserBase.addClause (opérateur par défaut OR)
            if clauses and conj == "AND":
                occ, prec = clauses[-1]
                if occ != "must_not":
                    clauses[-1] = ("must", prec)
            requis = mod == "+" or (conj == "AND" and mod != "NOT")
            interdit = mod == "NOT"
            clauses.append(("must_not" if interdit else "must" if requis else "should", noeud))
        return Booleen(clauses)

    def clause(self, champ_defaut):
        typ, val = self.prendre()
        if typ == "(":
            sous = self.requete(champ_defaut, fin=")")
            if self.prendre()[0] != ")":
                raise ErreurRequete("parenthèse non fermée")
            self._modifs()
            return sous
        if typ == "TERME" and self.voir()[0] == ":":
            self.prendre()
            champ = _desechapper(val)
            typ2, val2 = self.voir()
            if typ2 == "(":
                self.prendre()
                sous = self.requete(champ, fin=")")
                if self.prendre()[0] != ")":
                    raise ErreurRequete("parenthèse non fermée")
                self._modifs()
                return sous
            if typ2 is None:
                raise ErreurRequete(f"valeur manquante après {champ}:")
            self.prendre()
            return self.terme(champ, typ2, val2)
        if typ in ("TERME", "PHRASE", "RANGE", "REGEX"):
            return self.terme(champ_defaut, typ, val)
        if typ == ")":
            raise ErreurRequete("parenthèse fermante sans ouvrante")
        raise ErreurRequete(f"jeton inattendu : {val!r}")

    def _modifs(self):
        while self.voir()[0] == "MODIF":
            self.prendre()

    def terme(self, champ, typ, val):
        self._modifs()
        if typ == "PHRASE":
            return Terme(champ, "phrase", val)
        if typ == "RANGE":
            inc_bas, bas, haut, inc_haut = val
            return Terme(champ, "range", (inc_bas, None if bas == "*" else _desechapper(bas),
                                          None if haut == "*" else _desechapper(haut), inc_haut))
        if typ == "REGEX":
            return Terme(champ, "regex", val)
        if typ != "TERME":
            raise ErreurRequete(f"valeur inattendue après {champ}:")
        if champ == "_exists_":
            return Terme(_desechapper(val), "exists")
        m = re.match(r"^(>=|<=|>|<)(.+)$", val)
        if m:
            return Terme(champ, "cmp", (m.group(1), _desechapper(m.group(2))))
        if val == "*":
            return Terme(champ, "exists") if champ else ToutDoc()
        if _joker(val):
            return Terme(champ, "wildcard", val)
        return Terme(champ, "exact", _desechapper(val))


def analyser(requete: str):
    """Requête Graylog -> arbre (Booleen / Terme / ToutDoc). Lève ErreurRequete."""
    q = (requete or "").strip()
    if q in ("", "*"):
        return ToutDoc()
    a = _Analyseur(_lexer(q))
    arbre = a.requete(None)
    if a.p != len(a.j):
        raise ErreurRequete("jetons en trop en fin de requête (parenthèse fermante orpheline ?)")
    if not arbre.clauses:
        return ToutDoc()
    return arbre


def termes(noeud, negatif=False):
    """Itère (terme, sous_negation)."""
    if isinstance(noeud, Terme):
        yield noeud, negatif
    elif isinstance(noeud, Booleen):
        for occ, n in noeud.clauses:
            yield from termes(n, negatif ^ (occ == "must_not"))


def champs_requete(noeud) -> dict:
    """{champ: {'positif': bool, 'negatif': bool}} ; None = terme sans champ."""
    res = {}
    for t, neg in termes(noeud):
        d = res.setdefault(t.champ, {"positif": False, "negatif": False})
        d["negatif" if neg else "positif"] = True
    return res


def satisfiable(noeud, absents: set) -> str:
    """Logique à trois valeurs : 'non' si la requête ne peut jamais correspondre
    sachant que les champs `absents` n'existent dans aucun index visé."""
    if isinstance(noeud, ToutDoc):
        return "oui"
    if isinstance(noeud, Terme):
        return "non" if noeud.champ in absents else "peut-etre"
    must = [satisfiable(n, absents) for o, n in noeud.clauses if o == "must"]
    should = [satisfiable(n, absents) for o, n in noeud.clauses if o == "should"]
    nots = [satisfiable(n, absents) for o, n in noeud.clauses if o == "must_not"]
    if "non" in must:
        return "non"
    if not must and should and all(s == "non" for s in should):
        return "non"
    if "oui" in nots:
        return "non"
    return "peut-etre"


# =============================================================================
# 2. Évaluateur hors ligne (faux index en mémoire)
# =============================================================================
_MOT = re.compile(r"[^\W_]+(?:['’][^\W_]+)*", re.UNICODE)


def _jetons_texte(v) -> list[str]:
    return [m.group(0).lower() for m in _MOT.finditer(str(v))]


def _valeurs(doc: dict, champ: str) -> list:
    if champ not in doc or doc[champ] is None:
        return []
    v = doc[champ]
    return [x for x in (v if isinstance(v, list) else [v]) if x is not None and x != ""]


def _nombre(x):
    if isinstance(x, bool):
        return None
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(str(x))
    except ValueError:
        return None


def _egal(v, attendu: str) -> bool:
    if isinstance(v, bool):
        return attendu.lower() == str(v).lower()
    if isinstance(v, (int, float)):
        n = _nombre(attendu)
        return n is not None and float(v) == n
    return str(v) == attendu


def _compare(v, op, borne) -> bool:
    a, b = _nombre(v), _nombre(borne)
    if a is None or b is None:
        a, b = str(v), str(borne)
    return {">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op]


def _correspond_terme(t: Terme, doc: dict) -> bool:
    if t.nature == "exists":
        return bool(_valeurs(doc, t.champ))
    if t.champ is None:
        # Terme sans champ : on cherche dans message (comportement le plus courant).
        return _correspond_terme(Terme("message", t.nature, t.valeur), doc)
    vals = _valeurs(doc, t.champ)
    texte = t.champ in CHAMPS_TEXTE
    for v in vals:
        if t.nature == "exact":
            if texte:
                attendus = _jetons_texte(t.valeur)
                if attendus and _sequence(attendus, _jetons_texte(v)):
                    return True
            elif _egal(v, t.valeur):
                return True
        elif t.nature == "phrase":
            if texte:
                attendus = _jetons_texte(t.valeur)
                if attendus and _sequence(attendus, _jetons_texte(v)):
                    return True
            elif _egal(v, t.valeur):
                return True
        elif t.nature == "wildcard":
            if texte:
                motif = re.compile(_motif_joker(t.valeur.lower()))
                if any(motif.match(tok) for tok in _jetons_texte(v)):
                    return True
            elif re.match(_motif_joker(t.valeur), str(v), re.DOTALL):
                return True
        elif t.nature == "cmp":
            op, borne = t.valeur
            if _compare(v, op, borne):
                return True
        elif t.nature == "range":
            inc_bas, bas, haut, inc_haut = t.valeur
            ok = True
            if bas is not None:
                ok = _compare(v, ">=" if inc_bas else ">", bas)
            if ok and haut is not None:
                ok = _compare(v, "<=" if inc_haut else "<", haut)
            if ok:
                return True
        elif t.nature == "regex":
            if re.fullmatch(t.valeur, str(v)):
                return True
    return False


def _sequence(aiguille, botte) -> bool:
    n = len(aiguille)
    return any(botte[i:i + n] == aiguille for i in range(len(botte) - n + 1))


def correspond(noeud, doc: dict) -> bool:
    if isinstance(noeud, ToutDoc):
        return True
    if isinstance(noeud, Terme):
        return _correspond_terme(noeud, doc)
    must = [n for o, n in noeud.clauses if o == "must"]
    should = [n for o, n in noeud.clauses if o == "should"]
    nots = [n for o, n in noeud.clauses if o == "must_not"]
    if must or should:
        base = all(correspond(n, doc) for n in must) and (bool(must) or any(correspond(n, doc) for n in should))
    else:
        base = True   # requête purement négative : OpenSearch ajoute match_all
    return base and not any(correspond(n, doc) for n in nots)


def _serie(serie: dict, docs: list[dict]):
    typ, champ = serie.get("type"), serie.get("field")
    if typ == "count":
        return float(len(docs) if not champ else sum(1 for d in docs if _valeurs(d, champ)))
    vals = [v for d in docs for v in _valeurs(d, champ)] if champ else []
    if typ == "card":
        return float(len({json.dumps(v, sort_keys=True) for v in vals}))
    nums = [n for n in (_nombre(v) for v in vals) if n is not None]
    if typ == "sum":
        return float(sum(nums))
    if not nums:
        return None
    return {"min": min(nums), "max": max(nums), "avg": sum(nums) / len(nums)}.get(typ)


def _expr(e, valeurs: dict):
    if e is None:
        return True
    t = e.get("expr")
    if t == "number":
        return float(e.get("value"))
    if t == "number-ref":
        return valeurs.get(e.get("ref"))
    if t == "group":
        return _expr(e.get("child"), valeurs)
    if t in ("&&", "||"):
        g, d = _expr(e.get("left"), valeurs), _expr(e.get("right"), valeurs)
        return (g and d) if t == "&&" else (g or d)
    if t == "!":
        return not _expr(e.get("left") or e.get("child"), valeurs)
    g, d = _expr(e.get("left"), valeurs), _expr(e.get("right"), valeurs)
    if g is None or d is None:
        return False
    return {">": g > d, ">=": g >= d, "<": g < d, "<=": g <= d, "==": g == d}.get(t, False)


def evaluer_definition(defn: dict, docs: list[dict], maintenant: float) -> dict:
    """Évalue une définition (format normalisé, flux par titre) sur un faux index.

    Chaque document porte `_flux` (titre du flux) et `_ts` (epoch s). Retourne
    {'correspondances': [indices], 'evenements': [{'cle': [...], 'series': {...}}]}."""
    arbre = analyser(defn.get("query", ""))
    debut = maintenant - defn.get("search_within_ms", 300000) / 1000.0
    flux = set(defn.get("streams") or [])
    idx = [i for i, d in enumerate(docs)
           if debut <= d.get("_ts", maintenant) <= maintenant
           and (not flux or d.get("_flux") in flux)
           and correspond(arbre, d)]
    retenus = [docs[i] for i in idx]
    series = defn.get("series") or []
    cond = (defn.get("conditions") or {}).get("expression")
    evenements = []
    if not series or cond is None:
        evenements = [{"cle": [], "series": {}, "document": i} for i in idx]
        return {"correspondances": idx, "evenements": evenements}
    groupes: dict = {}
    gb = defn.get("group_by") or []
    if gb:
        for d in retenus:
            vals = [_valeurs(d, g) for g in gb]
            if any(not v for v in vals):
                continue        # agrégation terms : pas de seau pour un champ manquant
            groupes.setdefault(tuple(str(v[0]) for v in vals), []).append(d)
    else:
        groupes[()] = retenus
    for cle, lot in sorted(groupes.items()):
        valeurs = {s.get("id"): _serie(s, lot) for s in series}
        if _expr(cond, valeurs):
            evenements.append({"cle": list(cle), "series": valeurs})
    return {"correspondances": idx, "evenements": evenements}


# =============================================================================
# 3. Fixtures
# =============================================================================
def charger_fixtures(rep: Path) -> list[dict]:
    res = []
    if not rep or not rep.is_dir():
        return res
    for f in sorted(rep.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        data["_fichier"] = f.name
        res.append(data)
    return res


def _formater(v, i):
    if isinstance(v, str):
        return v.replace("{i}", str(i))
    if isinstance(v, list):
        return [_formater(x, i) for x in v]
    return v


def documents_cas(cas: dict, maintenant: float) -> list[dict]:
    docs = []
    for modele in cas.get("documents", []):
        for i in range(int(modele.get("repeter", 1))):
            d = {k: _formater(v, i) for k, v in (modele.get("champs") or {}).items()}
            d["_flux"] = modele.get("flux")
            d["_ts"] = maintenant - float(modele.get("age_s", 60)) - i * float(modele.get("pas_s", 0))
            docs.append(d)
    return docs


def verifier_cas(defn: dict, cas: dict, maintenant: float) -> dict:
    docs = documents_cas(cas, maintenant)
    try:
        res = evaluer_definition(defn, docs, maintenant)
    except ErreurRequete as exc:
        return {"cas": cas.get("nom"), "ok": False, "constat": f"requête non analysable : {exc}"}
    attendu = cas.get("attendu", {})
    n = len(res["evenements"])
    ok, constats = True, []
    if "evenements" in attendu and n != attendu["evenements"]:
        ok = False
        constats.append(f"{n} événement(s) au lieu de {attendu['evenements']}")
    if "cles" in attendu:
        cles = [e["cle"] for e in res["evenements"]]
        if sorted(cles) != sorted(attendu["cles"]):
            ok = False
            constats.append(f"clés {cles} au lieu de {attendu['cles']}")
    return {"cas": cas.get("nom"), "ok": ok, "evenements": n, "constat": "; ".join(constats)}


def normaliser_definition(d: dict, titres_flux: dict) -> dict:
    """Définition API -> format de l'évaluateur (flux par titre)."""
    cfg = d.get("config", {})
    return {
        "query": cfg.get("query", ""),
        "streams": [titres_flux.get(s, s) for s in cfg.get("streams") or []],
        "group_by": cfg.get("group_by") or [],
        "series": [{"type": s.get("type"), "id": s.get("id"), "field": s.get("field")}
                   for s in cfg.get("series") or []],
        "conditions": cfg.get("conditions") or {"expression": None},
        "search_within_ms": cfg.get("search_within_ms"),
        "execute_every_ms": cfg.get("execute_every_ms"),
    }


def ecart_instantane(instantane: dict, courant: dict) -> list[str]:
    cles = ("query", "streams", "group_by", "series", "conditions", "search_within_ms")
    diff = []
    for k in cles:
        a, b = instantane.get(k), courant.get(k)
        if k == "streams":
            a, b = sorted(a or []), sorted(b or [])
        if json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
            diff.append(k)
    return diff


def executer_fixtures(fixtures: list[dict], definitions_live: dict | None, maintenant: float) -> list[dict]:
    """definitions_live : {titre: définition normalisée} ou None (hors ligne : instantané)."""
    resultats = []
    for fx in fixtures:
        titre = fx.get("titre")
        instantane = fx.get("definition", {})
        r = {"titre": titre, "fichier": fx.get("_fichier"), "critique": bool(fx.get("critique")),
             "source_definition": "instantane", "ecarts_instantane": [], "cas": []}
        defn = instantane
        if definitions_live is not None:
            if titre not in definitions_live:
                r["absente"] = True
                resultats.append(r)
                continue
            defn = definitions_live[titre]
            r["source_definition"] = "production"
            r["ecarts_instantane"] = ecart_instantane(instantane, defn)
        r["cas"] = [verifier_cas(defn, c, maintenant) for c in fx.get("cas", [])]
        resultats.append(r)
    return resultats


# =============================================================================
# 4. Traduction vers OpenSearch
# =============================================================================
def corps_requete(requete: str, flux_ids: list[str], depuis: str) -> dict:
    q = (requete or "").strip()
    must = ([{"match_all": {}}] if q in ("", "*") else
            [{"query_string": {"query": q, "allow_leading_wildcard": True, "analyze_wildcard": True}}])
    filtres = [{"range": {"timestamp": {"gte": depuis}}}]
    if flux_ids:
        filtres.append({"terms": {"streams": list(flux_ids)}})
    return {"query": {"bool": {"must": must, "filter": filtres}}}


# =============================================================================
# 5. Accès réseau (injectables pour les tests)
# =============================================================================
def _charger_coherence():
    sys.dont_write_bytecode = True   # ne rien écrire dans le dépôt de référence (exécution en production)
    spec = importlib.util.spec_from_file_location("omni_coherence_check_dv", ICI / "omni-coherence-check.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["omni_coherence_check_dv"] = mod
    spec.loader.exec_module(mod)
    return mod


class ClientGraylog:
    """GET uniquement."""

    def __init__(self, vars_env: Path, url: str | None = None):
        occ = _charger_coherence()
        env = occ.lire_env(vars_env, {"GRAYLOG_API_URL", "SIEM_FQDN", "GRAYLOG_ADMIN_PASS", "GRAYLOG_API_CA"})
        brut = url or env.get("GRAYLOG_API_URL", "")
        self.base = occ.url_api(brut or (f"https://{env['SIEM_FQDN']}:9000" if env.get("SIEM_FQDN")
                                         else "http://127.0.0.1:9000"))
        self._auth = "Basic " + base64.b64encode(("admin:" + env.get("GRAYLOG_ADMIN_PASS", "")).encode()).decode()
        ca = env.get("GRAYLOG_API_CA") or "/etc/graylog/certs/omnitech-rootca.crt"
        tls = self.base.startswith("https") and os.path.exists(ca)
        self._ssl = ssl.create_default_context(cafile=ca) if tls else None

    def get(self, chemin: str):
        req = urllib.request.Request(self.base + chemin, method="GET",
                                     headers={"Authorization": self._auth, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=90, context=self._ssl) as r:
            return json.load(r)


class ClientOpenSearch:
    """GET et recherches en lecture seule (_count, _search) ; toute autre écriture est refusée,
    sauf instance explicitement marquée jetable (mode --replay)."""

    LECTURE_POST = ("/_count", "/_search")

    def __init__(self, url: str, jetable: bool = False, pause_s: float = 0.0):
        self.url = url.rstrip("/")
        self.jetable = jetable
        self.pause_s = pause_s

    def appel(self, methode: str, chemin: str, corps=None, ndjson: str | None = None, timeout=120):
        nu = chemin.split("?", 1)[0]
        if methode != "GET" and not self.jetable and not nu.endswith(self.LECTURE_POST):
            raise PermissionError(f"appel {methode} {nu} refusé : lecture seule")
        data, typ = None, "application/json"
        if ndjson is not None:
            data, typ = ndjson.encode(), "application/x-ndjson"
        elif corps is not None:
            data = json.dumps(corps).encode()
        req = urllib.request.Request(self.url + chemin, data=data, method=methode, headers={"Content-Type": typ})
        if self.pause_s:
            time.sleep(self.pause_s)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.load(exc)
            except Exception:  # noqa: BLE001
                detail = {}
            raise ErreurOpenSearch(exc.code, detail) from None


class ErreurOpenSearch(Exception):
    def __init__(self, code, detail):
        super().__init__(f"HTTP {code}")
        self.code, self.detail = code, detail

    def raison(self) -> str:
        err = (self.detail or {}).get("error")
        if isinstance(err, dict):
            cause = (err.get("root_cause") or [{}])[0]
            return f"{cause.get('type', err.get('type', ''))} : {cause.get('reason', err.get('reason', ''))}"[:300]
        return str(err or self.code)


# =============================================================================
# 6. Modèle de rapport
# =============================================================================
@dataclass
class Defaut:
    controle: str
    gravite: str
    constat: str


@dataclass
class Resultat:
    id: str
    titre: str
    priorite: int
    critique: bool
    statut: str = "OK"
    vivacite: dict = field(default_factory=dict)
    defauts: list = field(default_factory=list)
    fixtures: list = field(default_factory=list)
    requete: str = ""
    flux: list = field(default_factory=list)

    def ajouter(self, controle, gravite, constat):
        self.defauts.append(Defaut(controle, gravite, constat))

    def gravite_max(self) -> str:
        return min((d.gravite for d in self.defauts), key=RANG_GRAVITE.get, default="info")


def statut(r: Resultat) -> str:
    g = r.gravite_max() if r.defauts else None
    if g == "critique":
        return "CASSEE"
    if g in ("elevee", "moyenne"):
        return "DEFAUT"
    return "OK"


def score(r: Resultat) -> tuple:
    rang_statut = {"CASSEE": 0, "DEFAUT": 1, "OK": 2}[r.statut]
    viv = r.vivacite.get("etat", "")
    rang_viv = 0 if viv in VIVACITES_MORTES else 1
    nb = sum(1 for d in r.defauts if RANG_GRAVITE[d.gravite] <= 2)
    return (rang_statut, not r.critique, -r.priorite, RANG_GRAVITE[r.gravite_max()] if r.defauts else 9,
            rang_viv, -nb, r.titre)


# =============================================================================
# 7. Collecte (API Graylog, GET)
# =============================================================================
def collecter(gl_get) -> dict:
    defs, contexte, page = [], {}, 1
    while True:
        rep = gl_get(f"/events/definitions?per_page=100&page={page}")
        lot = rep.get("event_definitions", [])
        defs += lot
        contexte.update(((rep.get("context") or {}).get("scheduler")) or {})
        if len(lot) < 100 or page * 100 >= int(rep.get("total", 0) or 0):
            break
        page += 1
        if page > 50:
            break
    notifs = gl_get("/events/notifications?per_page=500&page=1")
    return {
        "definitions": defs,
        "planificateur": contexte,
        "flux": gl_get("/streams").get("streams", []),
        "index_sets": gl_get("/system/indices/index_sets?skip=0&limit=500").get("index_sets", []),
        "notifications": notifs.get("notifications", notifs if isinstance(notifs, list) else []),
        "regles": gl_get("/system/pipelines/rule"),
        "pipelines": gl_get("/system/pipelines/pipeline"),
        "connexions": gl_get("/system/pipelines/connections"),
    }


def corpus_robots(depot: Path) -> str:
    """Texte des robots et services du dépôt (producteurs GELF d'alert_tag)."""
    morceaux = []
    exclus = {".git", "docs", "tests", "archives", "node_modules", ".venv", "captures", "python-locks"}
    for racine, reps, fichiers in os.walk(depot):
        reps[:] = [r for r in reps if r not in exclus and not r.startswith(".")]
        for f in fichiers:
            if f.endswith((".py", ".sh", ".ps1", ".conf", ".json", ".yml", ".yaml", ".rb")) or "." not in f:
                p = Path(racine) / f
                try:
                    if p.stat().st_size < 2_000_000:
                        morceaux.append(p.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
                    pass
    return "\n".join(morceaux)


# =============================================================================
# 8. Contrôles
# =============================================================================
def _index_cibles(cfg_flux: list[str], flux: dict, isets: dict) -> tuple[list[str], list[str]]:
    """(préfixes d'index, ids de flux pour le filtre)."""
    if not cfg_flux:   # aucun flux : Graylog cherche dans tous les flux de messages
        prefixes = sorted({i["index_prefix"] for i in isets.values() if i.get("index_template_type") != "events"})
        return prefixes, []
    prefixes = sorted({isets[flux[s]["index_set_id"]]["index_prefix"] for s in cfg_flux
                       if s in flux and flux[s].get("index_set_id") in isets})
    return prefixes, [s for s in cfg_flux if s in flux]


def _motif_index(prefixes) -> str:
    return ",".join(f"{p}_*" for p in prefixes)


def controles_statiques(r: Resultat, d: dict, inv: dict, ctx: dict):
    cfg = d.get("config", {})
    flux, isets, notifs = ctx["flux"], ctx["isets"], ctx["notifs"]
    # --- requête
    try:
        arbre = analyser(cfg.get("query", ""))
    except ErreurRequete as exc:
        r.ajouter("requete", "critique", f"requête non analysable : {exc}")
        arbre = None
    if cfg.get("query_parameters"):
        r.ajouter("requete", "info", "paramètres de requête (lookup) : traduction OpenSearch non prise en charge")
    if cfg.get("filters"):
        r.ajouter("requete", "info", "filtres de recherche additionnels non pris en compte")
    # --- flux
    cfg_flux = cfg.get("streams") or []
    for s in cfg_flux:
        if s not in flux:
            r.ajouter("flux", "critique", f"flux {s} inexistant")
        elif flux[s].get("disabled"):
            r.ajouter("flux", "critique", f"flux « {flux[s].get('title')} » désactivé")
        elif flux[s].get("index_set_id") not in isets:
            r.ajouter("flux", "critique", f"index set du flux « {flux[s].get('title')} » introuvable")
    if cfg_flux and not any(s in flux for s in cfg_flux):
        r.ajouter("flux", "critique", "aucun flux visé n'existe")
    if not cfg_flux:
        r.ajouter("flux", "info", "aucun flux : recherche sur tous les index de messages (coûteux, sémantique large)")
    # --- notifications
    ids = [n.get("notification_id") for n in d.get("notifications") or []]
    for nid in ids:
        if nid not in notifs:
            r.ajouter("notifications", "critique", f"notification {nid} inexistante")
    if not ids:
        r.ajouter("notifications", "elevee" if r.critique else "moyenne",
                  "aucune notification : l'événement est enregistré mais personne n'est prévenu")
    # --- planification
    within, every = cfg.get("search_within_ms") or 0, cfg.get("execute_every_ms") or 0
    if cfg.get("use_cron_scheduling"):
        r.ajouter("planification", "info",
                  f"planification cron « {cfg.get('cron_expression')} » : cohérence non vérifiée")
    elif within and every:
        if within < every:
            r.ajouter("planification", "elevee",
                      f"fenêtre {within // 1000}s < période {every // 1000}s : des messages ne sont jamais évalués")
        elif within > every * 12 and within > 86_400_000:
            r.ajouter("planification", "faible",
                      f"fenêtre {within // 1000}s très supérieure à la période {every // 1000}s : "
                      "événements répétés possibles")
        if every < 60_000:
            r.ajouter("planification", "moyenne", f"période {every // 1000}s < 60 s : charge élevée sur OpenSearch")
    else:
        r.ajouter("planification", "elevee", "search_within_ms ou execute_every_ms absent")
    pl = ctx["planificateur"].get(r.id)
    if pl is None:
        r.ajouter("planification", "elevee",
                  "aucune tâche planifiée renvoyée par l'API pour cette définition active")
    else:
        if pl.get("status") not in ("runnable", "running"):
            r.ajouter("planification", "critique", f"planificateur en état « {pl.get('status')} »")
        if pl.get("is_scheduled") is False:
            r.ajouter("planification", "critique", "définition active mais non planifiée")
        dernier = _date(pl.get("triggered_at"))
        if dernier and every and not cfg.get("use_cron_scheduling"):
            retard = ctx["maintenant"] - dernier
            if retard > max(2 * every / 1000.0, every / 1000.0 + 900):
                r.ajouter("planification", "elevee", f"dernière exécution il y a {int(retard // 60)} min "
                                                     f"(période {every // 60000} min)")
    if arbre is None:
        return None
    # --- requête : remarques de syntaxe
    for t, neg in termes(arbre):
        if t.champ is None:
            r.ajouter("requete", "moyenne", "terme sans champ : dépend du champ par défaut d'OpenSearch")
        if t.nature == "wildcard" and t.champ not in CHAMPS_TEXTE and not neg:
            lettres = re.sub(r"[^A-Za-z]", "", _desechapper(t.valeur))
            if lettres and lettres == lettres.lower() and re.search(r"(?i)image|path|file|command|object|name",
                                                                       t.champ or ""):
                r.ajouter("requete", "faible", f"joker en minuscules sur {t.champ} ({t.valeur}) : les champs "
                                               "keyword sont sensibles à la casse")
    return arbre


def _date(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def producteur_champ(champ: str, ctx: dict) -> str | None:
    """Règle de pipeline connectée qui pose `champ` (set_field), sinon None.

    Les robots GELF ne sont pas pris en compte : le nom d'un champ apparaît aussi
    dans le code qui le lit, la recherche littérale serait trompeuse."""
    motif = re.compile(r"""set_field\(\s*["']""" + re.escape(champ) + r"""["']""")
    for nom, src in ctx["regles"].items():
        if nom in ctx["regles_connectees"] and motif.search(src):
            return f"règle « {nom} »"
    return None


def controle_champs(r: Resultat, d: dict, arbre, existants: set, ctx: dict):
    """existants : champs présents dans au moins un index des index sets visés.

    Un champ absent de tous les mappings n'a jamais été indexé sur la rétention.
    S'il n'a aucun producteur connu, la condition qui le requiert ne peut pas être
    satisfaite (critique) ; s'il est posé conditionnellement par une règle (lookup,
    enrichissement), on ne peut pas conclure à la panne (élevée)."""
    cfg = d.get("config", {})
    champs = champs_requete(arbre) if arbre is not None else {}
    absents = {c for c in champs if c and c not in CHAMPS_INTEGRES and c not in existants and "*" not in c}

    def origine(c):
        prod = producteur_champ(c, ctx)
        return f"{c} (posé par {prod}, jamais observé)" if prod else f"{c} (aucun producteur connu)"

    if absents:
        orphelins = {c for c in absents if not producteur_champ(c, ctx)}
        liste = ", ".join(origine(c) for c in sorted(absents))
        if arbre is not None and satisfiable(arbre, absents) == "non":
            grav = "critique" if arbre is not None and satisfiable(arbre, orphelins) == "non" else "elevee"
            r.ajouter("champs", grav, "requête jamais satisfaite sur la rétention : " + liste)
        else:
            pos = sorted(c for c in absents if champs[c]["positif"])
            neg = sorted(c for c in absents if not champs[c]["positif"])
            if pos:
                r.ajouter("champs", "elevee", "branche de requête morte : " + ", ".join(origine(c) for c in pos))
            if neg:
                r.ajouter("champs", "faible", "exclusion inopérante : " + ", ".join(origine(c) for c in neg))
    cond = (cfg.get("conditions") or {}).get("expression") or {}
    absence = cond.get("expr") in ("<", "<=")
    for g in cfg.get("group_by") or []:
        if g not in CHAMPS_INTEGRES and g not in existants:
            r.ajouter("champs", "elevee" if producteur_champ(g, ctx) else "critique",
                      f"champ de regroupement {origine(g)} : aucun seau, jamais d'événement")
    for s in cfg.get("series") or []:
        f = s.get("field")
        if f and f not in CHAMPS_INTEGRES and f not in existants:
            grav = "elevee" if absence or producteur_champ(f, ctx) else "critique"
            r.ajouter("champs", grav, f"champ de série {origine(f)} ({s.get('id')})")


def controle_producteurs(r: Resultat, arbre, ctx: dict):
    if arbre is None:
        return
    for t, neg in termes(arbre):
        if neg or t.champ not in CHAMPS_PRODUCTEURS or t.nature not in ("exact", "phrase"):
            continue
        val = str(t.valeur)
        litteral = re.compile(r"""["']""" + re.escape(val) + r"""["']""")
        regles = [nom for nom, src in ctx["regles"].items() if t.champ in src and litteral.search(src)]
        connectees = [n for n in regles if n in ctx["regles_connectees"]]
        if connectees:
            continue
        if ctx["corpus"] and litteral.search(ctx["corpus"]):
            continue
        if regles:
            r.ajouter("producteur", "elevee", f"{t.champ}:{val} posé par la règle « {regles[0]} » qui n'est dans "
                                             "aucun pipeline connecté à un flux")
        else:
            r.ajouter("producteur", "moyenne", f"aucun producteur trouvé pour {t.champ}:{val} (ni règle de pipeline, "
                                              "ni robot du dépôt) ; valeur peut-être construite dynamiquement")


def regles_connectees(inv: dict) -> set:
    pipelines = {p.get("id"): p for p in inv.get("pipelines") or []}
    ids_connectes = {pid for c in inv.get("connexions") or [] for pid in c.get("pipeline_ids") or []}
    noms = set()
    for pid in ids_connectes:
        for st in (pipelines.get(pid) or {}).get("stages") or []:
            noms.update(st.get("rules") or [])
    return noms


# =============================================================================
# 9. Orchestration
# =============================================================================
def valider(inv: dict, os_client, *, controles: set, fixtures: list, exceptions: dict, depot: Path | None,
            fenetre_j: int = 30, recente_j: int = 7, priorite_critique: int = 3, plafond: int = 10000,
            maintenant: float | None = None, journal=print) -> dict:
    maintenant = maintenant or time.time()
    flux = {s["id"]: s for s in inv["flux"]}
    titres_flux = {s["id"]: s.get("title", s["id"]) for s in inv["flux"]}
    isets = {i["id"]: i for i in inv["index_sets"]}
    notifs = {n["id"]: n for n in inv["notifications"]}
    titres_critiques = {fx.get("titre") for fx in fixtures if fx.get("critique")}
    ctx = {"flux": flux, "isets": isets, "notifs": notifs, "planificateur": inv.get("planificateur") or {},
           "exceptions": exceptions, "maintenant": maintenant,
           "regles": {x.get("title"): x.get("source", "") for x in inv.get("regles") or []},
           "regles_connectees": regles_connectees(inv),
           "corpus": corpus_robots(depot) if depot and "statique" in controles else ""}
    resultats, hors_perimetre, erreurs = [], [], []
    for d in inv["definitions"]:
        if d.get("config", {}).get("type") != "aggregation-v1":
            hors_perimetre.append({"titre": d.get("title"), "type": d.get("config", {}).get("type"),
                                   "etat": d.get("state")})
    actives = [d for d in inv["definitions"] if d.get("state", "ENABLED") == "ENABLED"
               and d.get("config", {}).get("type") == "aggregation-v1"]
    arbres, cibles = {}, {}
    for d in actives:
        prio = int(d.get("priority") or 0)
        critique = prio >= priorite_critique or d.get("title") in titres_critiques
        r = Resultat(d["id"], d.get("title", d["id"]), prio, critique,
                     requete=d.get("config", {}).get("query", ""),
                     flux=[titres_flux.get(s, s) for s in d.get("config", {}).get("streams") or []])
        arbres[d["id"]] = controles_statiques(r, d, inv, ctx) if "statique" in controles else _arbre_sur(d)
        cibles[d["id"]] = _index_cibles(d.get("config", {}).get("streams") or [], flux, isets)
        resultats.append(r)
    par_id = {r.id: r for r in resultats}

    if os_client is not None and ("statique" in controles or "vivacite" in controles):
        # --- mapping : champs nécessaires par préfixe d'index
        besoins: dict = {}
        for d in actives:
            arbre = arbres[d["id"]]
            noms = {c for c in (champs_requete(arbre) if arbre is not None else {}) if c}
            noms |= set(d["config"].get("group_by") or [])
            noms |= {s.get("field") for s in d["config"].get("series") or [] if s.get("field")}
            noms = {n for n in noms if n not in CHAMPS_INTEGRES and "*" not in n}
            for p in cibles[d["id"]][0]:
                besoins.setdefault(p, set()).update(noms)
        mapping, vides = {}, set()
        if "statique" in controles:
            for p, noms in sorted(besoins.items()):
                if _compter(os_client, [p], {"query": {"match_all": {}}}, 1, erreurs) == 0:
                    vides.add(p)
                mapping[p] = set()
                liste = sorted(noms)
                for k in range(0, len(liste), 40):
                    lot = ",".join(urllib.parse.quote(x, safe="") for x in liste[k:k + 40])
                    try:
                        rep = os_client.appel("GET", f"/{p}_*/_mapping/field/{lot}"
                                              "?ignore_unavailable=true&allow_no_indices=true")
                    except (ErreurOpenSearch, OSError) as exc:
                        erreurs.append(f"mapping {p} : {exc}")
                        mapping[p] = None
                        break
                    for idx in (rep or {}).values():
                        mapping[p].update((idx.get("mappings") or {}).keys())
            for d in actives:
                r = par_id[d["id"]]
                prefixes = cibles[d["id"]][0]
                if any(mapping.get(p) is None for p in prefixes):
                    continue
                existants = set().union(*[mapping.get(p, set()) for p in prefixes]) if prefixes else set()
                if prefixes and all(p in vides for p in prefixes):
                    r.ajouter("flux", "elevee", "index set(s) visé(s) vide(s) (" + ", ".join(prefixes)
                              + ") : contrôle des champs impossible, source jamais reçue sur la rétention")
                elif prefixes:
                    controle_champs(r, d, arbres[d["id"]], existants, ctx)
                controle_producteurs(r, arbres[d["id"]], ctx)
                # validation par OpenSearch (GET _validate/query)
                if arbres[d["id"]] is not None and prefixes:
                    corps = corps_requete(d["config"].get("query", ""), [], "now-1d")
                    try:
                        rep = os_client.appel("GET", f"/{_motif_index(prefixes)}/_validate/query?explain=true"
                                              "&ignore_unavailable=true&allow_no_indices=true", corps)
                        if rep.get("valid") is False:
                            expl = next((e.get("error") for e in rep.get("explanations") or [] if e.get("error")), "")
                            r.ajouter("requete", "critique", f"requête refusée par OpenSearch : {str(expl)[:200]}")
                    except ErreurOpenSearch as exc:
                        r.ajouter("requete", "critique", f"requête refusée par OpenSearch : {exc.raison()}")
                    except OSError as exc:
                        erreurs.append(f"validate {r.titre} : {exc}")

        # --- vivacité
        if "vivacite" in controles:
            depuis_l, depuis_r = f"now-{fenetre_j}d", f"now-{recente_j}d"
            # flux : volume par flux
            vol_flux = {}
            for sid, s in flux.items():
                iset = isets.get(s.get("index_set_id"))
                if not iset or iset.get("index_template_type") == "events":
                    continue
                vol_flux[sid] = _compter(os_client, [iset["index_prefix"]], corps_requete("", [sid], depuis_r),
                                         plafond, erreurs)
            vol_tous = None
            # événements émis
            emis = _evenements_emis(os_client, isets, depuis_l, erreurs)
            for d in actives:
                r = par_id[d["id"]]
                prefixes, ids = cibles[d["id"]]
                cond = (d["config"].get("conditions") or {}).get("expression") or {}
                absence = cond.get("expr") in ("<", "<=")
                viv = {"fenetre_jours": fenetre_j, "recente_jours": recente_j,
                       "evenements_fenetre": emis.get(d["id"], 0) if emis is not None else None}
                if not prefixes or any(t.gravite == "critique" and t.controle in ("flux", "requete")
                                       for t in r.defauts):
                    viv["etat"] = "non_mesuree"
                    r.vivacite = viv
                    continue
                if ids:
                    sources = [vol_flux.get(s) for s in ids]
                    src = sum(x for x in sources if x) if any(x is not None for x in sources) else None
                else:
                    if vol_tous is None:
                        vol_tous = _compter(os_client, prefixes, corps_requete("", [], depuis_r), plafond, erreurs)
                    src = vol_tous
                viv["source_recente"] = src
                n_l = _compter(os_client, prefixes, corps_requete(d["config"].get("query", ""), ids, depuis_l),
                               plafond, erreurs, r)
                viv["correspondances_fenetre"] = n_l
                if n_l is None:
                    viv["etat"] = "non_mesuree"
                elif n_l > 0:
                    n_r = _compter(os_client, prefixes, corps_requete(d["config"].get("query", ""), ids, depuis_r),
                                   plafond, erreurs, r)
                    viv["correspondances_recentes"] = n_r
                    viv["etat"] = "vivante" if n_r else "rare"
                    if absence and not n_r:
                        viv["etat"] = "battement_absent"
                elif src == 0:
                    viv["etat"] = "source_absente"
                else:
                    viv["etat"] = "battement_absent" if absence else "muette"
                r.vivacite = viv
                if viv["etat"] == "source_absente":
                    r.ajouter("vivacite", "elevee", f"aucun message dans les flux visés depuis {recente_j} j : "
                                                    "détection aveugle")
                elif viv["etat"] == "battement_absent":
                    r.ajouter("vivacite", "elevee", f"détection d'absence : aucun battement depuis {recente_j} j, "
                                                    "la source surveillée est muette (l'alerte devrait être active)")
                elif viv["etat"] == "muette" and ctx["exceptions"].get(r.titre, {}).get("vivacite_attendue"):
                    r.ajouter("vivacite", "elevee",
                              f"jamais rien vu en {fenetre_j} j alors qu'une activité est attendue")

    # --- fixtures
    resume_fx = None
    if "fixtures" in controles and fixtures:
        live = {d.get("title"): normaliser_definition(d, titres_flux) for d in actives}
        res_fx = executer_fixtures(fixtures, live, maintenant)
        resume_fx = {"total": len(res_fx), "ok": 0, "echec": 0, "absentes": 0}
        for fx in res_fx:
            r = next((x for x in resultats if x.titre == fx["titre"]), None)
            if fx.get("absente"):
                resume_fx["absentes"] += 1
                desactivee = any(d.get("title") == fx["titre"] for d in inv["definitions"])
                hors_perimetre.append({"titre": fx["titre"], "type": "fixture",
                                       "etat": "definition desactivee" if desactivee else "definition absente"})
                continue
            echecs = [c for c in fx["cas"] if not c["ok"]]
            resume_fx["echec" if echecs else "ok"] += 1
            if r is None:
                continue
            r.fixtures = fx["cas"]
            r.critique = r.critique or fx["critique"]
            for c in echecs:
                r.ajouter("fixture", "critique", f"cas « {c['cas']} » : {c['constat']}")
            if fx["ecarts_instantane"]:
                r.ajouter("fixture", "info", "définition modifiée depuis la capture de la fixture : "
                          + ", ".join(fx["ecarts_instantane"]) + " (cas rejoués sur la version en production)")

    vus: dict = {}
    for r in resultats:
        vus.setdefault(r.titre, []).append(r)
    for titre, lot in vus.items():
        if len(lot) > 1:
            for r in lot:
                r.ajouter("inventaire", "moyenne", f"titre porté par {len(lot)} définitions actives (doublon)")
    for r in resultats:
        exc = exceptions.get(r.titre) or {}
        ignores = set(exc.get("ignorer") or [])
        if ignores:
            gardes = [x for x in r.defauts if x.controle not in ignores]
            if len(gardes) != len(r.defauts):
                gardes.append(Defaut("exception", "info", f"contrôle(s) {', '.join(sorted(ignores))} ignoré(s) : "
                                     + str(exc.get("motif", "motif non renseigné"))))
            r.defauts = gardes
        r.statut = statut(r)
    resultats.sort(key=score)
    resume = {
        "definitions_total": len(inv["definitions"]),
        "definitions_actives_controlees": len(resultats),
        "hors_perimetre": len(hors_perimetre),
        "ok": sum(1 for r in resultats if r.statut == "OK"),
        "en_defaut": sum(1 for r in resultats if r.statut == "DEFAUT"),
        "cassees": sum(1 for r in resultats if r.statut == "CASSEE"),
        "cassees_critiques": sum(1 for r in resultats if r.statut == "CASSEE" and r.critique),
        "vivacite": {},
        "mortes": sum(1 for r in resultats if r.vivacite.get("etat") in VIVACITES_MORTES),
        "fixtures": resume_fx,
    }
    for r in resultats:
        e = r.vivacite.get("etat")
        if e:
            resume["vivacite"][e] = resume["vivacite"].get(e, 0) + 1
    return {"resume": resume, "resultats": resultats, "hors_perimetre": hors_perimetre, "erreurs": erreurs}


def _arbre_sur(d):
    try:
        return analyser(d.get("config", {}).get("query", ""))
    except ErreurRequete:
        return None


def _compter(os_client, prefixes, corps, plafond, erreurs, r: Resultat | None = None):
    chemin = f"/{_motif_index(prefixes)}/_count?ignore_unavailable=true&allow_no_indices=true"
    if plafond:
        chemin += f"&terminate_after={int(plafond)}"
    try:
        return int(os_client.appel("POST", chemin, corps).get("count", 0))
    except ErreurOpenSearch as exc:
        if r is not None:
            r.ajouter("requete", "critique", f"_count refusé par OpenSearch : {exc.raison()}")
        else:
            erreurs.append(f"_count {prefixes} : {exc.raison()}")
    except OSError as exc:
        erreurs.append(f"_count {prefixes} : {exc}")
    return None


def _evenements_emis(os_client, isets, depuis, erreurs):
    prefixes = [i["index_prefix"] for i in isets.values()
                if i.get("index_template_type") == "events" and not i["index_prefix"].startswith("gl-system")]
    if not prefixes:
        return None
    corps = {"size": 0, "query": {"range": {"timestamp": {"gte": depuis}}},
             "aggs": {"d": {"terms": {"field": "event_definition_id", "size": 2000}}}}
    try:
        rep = os_client.appel("POST", f"/{_motif_index(prefixes)}/_search?ignore_unavailable=true", corps)
    except (ErreurOpenSearch, OSError) as exc:
        erreurs.append(f"événements émis : {exc}")
        return None
    return {b["key"]: b["doc_count"] for b in rep.get("aggregations", {}).get("d", {}).get("buckets", [])}


# =============================================================================
# 10. Replay sur OpenSearch jetable
# =============================================================================
PREFIXE_REPLAY = "omni-detval-replay-"


def verifier_jetable(os_client) -> str | None:
    """Retourne un motif de refus, ou None si l'instance paraît jetable."""
    u = urllib.parse.urlparse(os_client.url)
    if (u.hostname in ("127.0.0.1", "localhost", "::1") and (u.port or 9200) == 9200) or \
            os_client.url.rstrip("/") == OPENSEARCH_PAR_DEFAUT:
        return "URL de l'OpenSearch de production (boucle locale 9200)"
    info = os_client.appel("GET", "/")
    if info.get("cluster_name") == "graylog":
        return "cluster nommé « graylog » (production)"
    indices = os_client.appel("GET", "/_cat/indices?format=json&h=index")
    for i in indices:
        nom = i.get("index", "")
        if nom.startswith(("gl-", "graylog_", "omni-")) and not nom.startswith(PREFIXE_REPLAY):
            return f"index Graylog présent ({nom})"
    return None


def replay(fixtures: list[dict], os_client, maintenant: float | None = None, journal=print) -> list[dict]:
    refus = verifier_jetable(os_client)
    if refus:
        raise PermissionError(f"replay refusé : {refus}")
    maintenant = maintenant or time.time()
    res = []
    for fx in fixtures:
        defn = fx.get("definition", {})
        for cas in fx.get("cas", []):
            docs = documents_cas(cas, maintenant)
            attendu = set(evaluer_definition(defn, docs, maintenant)["correspondances"])
            index = PREFIXE_REPLAY + re.sub(r"[^a-z0-9]+", "-", (fx.get("_fichier") or "x").lower()).strip("-")
            os_client.appel("PUT", f"/{index}", {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {"dynamic_templates": [{"chaines": {"match_mapping_type": "string",
                                                                "mapping": {"type": "keyword"}}}],
                             "properties": {"message": {"type": "text", "analyzer": "standard"},
                                            "full_message": {"type": "text", "analyzer": "standard"},
                                            "timestamp": {"type": "date", "format": "uuuu-MM-dd HH:mm:ss.SSS"},
                                            "streams": {"type": "keyword"}}}})
            try:
                lignes = []
                for i, d in enumerate(docs):
                    doc = {k: v for k, v in d.items() if not k.startswith("_")}
                    horodatage = dt.datetime.fromtimestamp(d["_ts"], dt.timezone.utc)
                    doc["timestamp"] = horodatage.strftime("%Y-%m-%d %H:%M:%S.000")
                    doc["streams"] = [d.get("_flux") or "aucun"]
                    lignes.append(json.dumps({"index": {"_index": index, "_id": str(i)}}))
                    lignes.append(json.dumps(doc))
                if lignes:
                    os_client.appel("POST", "/_bulk?refresh=true", ndjson="\n".join(lignes) + "\n")
                depuis = dt.datetime.fromtimestamp(maintenant - (defn.get("search_within_ms") or 300000) / 1000,
                                                   dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000")
                corps = corps_requete(defn.get("query", ""), defn.get("streams") or [], depuis)
                corps["size"] = len(docs) + 1
                corps["_source"] = False
                rep = os_client.appel("POST", f"/{index}/_search", corps)
                obtenu = {int(h["_id"]) for h in rep.get("hits", {}).get("hits", [])}
            finally:
                os_client.appel("DELETE", f"/{index}")
            ok = obtenu == attendu
            res.append({"titre": fx.get("titre"), "cas": cas.get("nom"), "ok": ok,
                        "evaluateur": sorted(attendu), "opensearch": sorted(obtenu)})
            journal(f"[{'OK' if ok else 'ECART'}] {fx.get('titre')} / {cas.get('nom')}")
    return res


# =============================================================================
# 11. Sorties
# =============================================================================
def rapport_json(res: dict, parametres: dict, genere: str) -> dict:
    return {"outil": "omni-detection-validate", "format": 1, "genere_le": genere, "parametres": parametres,
            "resume": res["resume"], "erreurs": res["erreurs"], "hors_perimetre": res["hors_perimetre"],
            "definitions": [{**asdict(r), "defauts": [asdict(d) for d in r.defauts]} for r in res["resultats"]]}


def _cell(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def rapport_markdown(res: dict, genere: str, top: int = 15) -> str:
    s = res["resume"]
    o = [f"# Validation des détections - {genere}", "",
         "Contrôle en lecture seule des définitions d'événements Graylog actives "
         "(tools/omni-detection-validate.py).", "",
         "## Synthèse", "",
         "| Indicateur | Valeur |", "|---|---|",
         f"| Définitions (toutes) | {s['definitions_total']} |",
         f"| Définitions actives contrôlées | {s['definitions_actives_controlees']} |",
         f"| OK | {s['ok']} |",
         f"| En défaut | {s['en_defaut']} |",
         f"| Cassées | {s['cassees']} (dont critiques : {s['cassees_critiques']}) |",
         f"| Mortes (muettes, source absente, battement absent) | {s['mortes']} |"]
    for etat, n in sorted(s["vivacite"].items()):
        o.append(f"| Vivacité « {etat} » | {n} |")
    if s.get("fixtures"):
        f = s["fixtures"]
        o.append(f"| Fixtures | {f['ok']} OK / {f['echec']} en échec / {f['absentes']} sans définition active |")
    o += ["", f"## Les {top} plus graves", "",
          "| # | Statut | Prio | Critique | Vivacité | Définition | Défaut principal |",
          "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(res["resultats"][:top], 1):
        principal = min(r.defauts, key=lambda d: RANG_GRAVITE[d.gravite]) if r.defauts else None
        detail = _cell(f"[{principal.gravite}] {principal.controle} : {principal.constat}") if principal else "-"
        o.append(f"| {i} | {r.statut} | {r.priorite} | {'oui' if r.critique else 'non'} | "
                 f"{r.vivacite.get('etat', '-')} | {_cell(r.titre)} | {detail} |")
    for statut_, titre in (("CASSEE", "Définitions cassées"), ("DEFAUT", "Définitions en défaut")):
        lot = [r for r in res["resultats"] if r.statut == statut_]
        if not lot:
            continue
        o += ["", f"## {titre} ({len(lot)})", ""]
        for r in lot:
            o.append(f"- **{_cell(r.titre)}** (priorité {r.priorite}, vivacité {r.vivacite.get('etat', '-')})")
            for d in sorted(r.defauts, key=lambda x: RANG_GRAVITE[x.gravite]):
                if RANG_GRAVITE[d.gravite] <= 2:
                    o.append(f"  - [{d.gravite}] {d.controle} : {_cell(d.constat)}")
    mortes = [r for r in res["resultats"] if r.vivacite.get("etat") in VIVACITES_MORTES]
    if mortes:
        o += ["", f"## Définitions sans correspondance ({len(mortes)})", "",
              "Une détection d'attaque rare peut légitimement ne rien voir : « muette » signifie que la "
              "source est active mais que la requête n'a trouvé aucun message sur la fenêtre longue.", "",
              "| Vivacité | Prio | Définition | Messages source (récent) |", "|---|---|---|---|"]
        for r in sorted(mortes, key=lambda x: (x.vivacite.get("etat"), -x.priorite, x.titre)):
            o.append(f"| {r.vivacite.get('etat')} | {r.priorite} | {_cell(r.titre)} | "
                     f"{r.vivacite.get('source_recente', '-')} |")
    if res["hors_perimetre"]:
        o += ["", "## Hors périmètre", ""]
        o += [f"- {_cell(h['titre'])} ({h['type']}, {h['etat']})" for h in res["hors_perimetre"]]
    if res["erreurs"]:
        o += ["", "## Erreurs de collecte", ""] + [f"- {_cell(e)}" for e in res["erreurs"]]
    o += ["", "## Limites", "",
          "- La traduction query_string reprend la requête Graylog telle quelle (allow_leading_wildcard, "
          "analyze_wildcard) ; les paramètres de requête (lookup) et filtres additionnels ne sont pas traduits.",
          "- Les comptages utilisent terminate_after : une valeur égale au plafond signifie « au moins ».",
          "- Zéro correspondance n'est pas une preuve de panne pour une attaque rare ; les fixtures prouvent "
          "la logique de la définition, pas la normalisation amont par les pipelines.", ""]
    return "\n".join(o)


# =============================================================================
# 12. Point d'entrée
# =============================================================================
def main(argv=None, gl_get=None, os_client=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--controles", default="statique,vivacite,fixtures",
                    help="liste parmi statique, vivacite, fixtures (défaut : les trois)")
    ap.add_argument("--hors-ligne", action="store_true",
                    help="exécute uniquement les fixtures contre leur instantané, sans réseau")
    ap.add_argument("--vars", type=Path, default=DEPOT / "00-vars.env", help="fichier de variables Graylog")
    ap.add_argument("--graylog-url", default=None, help="URL de l'API Graylog (défaut : 00-vars.env)")
    ap.add_argument("--opensearch", default=OPENSEARCH_PAR_DEFAUT, help="URL OpenSearch (lecture seule)")
    ap.add_argument("--fixtures", type=Path, default=FIXTURES_PAR_DEFAUT)
    ap.add_argument("--exceptions", type=Path, default=EXCEPTIONS_PAR_DEFAUT)
    ap.add_argument("--depot", type=Path, default=DEPOT, help="dépôt où chercher les robots producteurs")
    ap.add_argument("--fenetre-jours", type=int, default=30)
    ap.add_argument("--recente-jours", type=int, default=7)
    ap.add_argument("--priorite-critique", type=int, default=3,
                    help="priorité Graylog à partir de laquelle une définition est critique")
    ap.add_argument("--plafond", type=int, default=10000, help="terminate_after des _count (0 : sans plafond)")
    ap.add_argument("--pause", type=float, default=0.0, help="pause en secondes entre deux requêtes OpenSearch")
    ap.add_argument("--sortie", type=Path, default=None,
                    help="répertoire où écrire les rapports datés JSON et Markdown (défaut : aucun fichier)")
    ap.add_argument("--json", action="store_true", help="affiche le rapport JSON au lieu du Markdown")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--replay", metavar="URL", default=None,
                    help="rejoue les fixtures sur un OpenSearch JETABLE (crée puis supprime un index temporaire)")
    ap.add_argument("--replay-jetable-confirme", action="store_true",
                    help="confirmation explicite que l'URL --replay désigne une instance jetable")
    a = ap.parse_args(argv)

    fixtures = charger_fixtures(a.fixtures)
    if a.replay:
        if not a.replay_jetable_confirme:
            print("--replay exige --replay-jetable-confirme", file=sys.stderr)
            return 3
        try:
            res = replay(fixtures, os_client or ClientOpenSearch(a.replay, jetable=True))
        except PermissionError as exc:
            print(str(exc), file=sys.stderr)
            return 3
        ecarts = [x for x in res if not x["ok"]]
        print(f"{len(res)} cas rejoués, {len(ecarts)} écart(s) entre l'évaluateur et OpenSearch.")
        return 2 if ecarts else 0

    if a.hors_ligne:
        res_fx = executer_fixtures(fixtures, None, time.time())
        echecs = 0
        for fx in res_fx:
            for c in fx["cas"]:
                print(f"[{'OK' if c['ok'] else 'ECHEC'}] {fx['titre']} / {c['cas']}"
                      + (f" : {c['constat']}" if c.get("constat") else ""))
                echecs += not c["ok"]
        print(f"{sum(len(f['cas']) for f in res_fx)} cas, {echecs} échec(s).")
        return 2 if echecs else 0

    controles = {c.strip() for c in a.controles.split(",") if c.strip()}
    if not controles or controles - {"statique", "vivacite", "fixtures"}:
        print(f"contrôles invalides : {a.controles}", file=sys.stderr)
        return 3
    exceptions = {}
    if a.exceptions and a.exceptions.is_file():
        exceptions = {e["titre"]: e for e in json.loads(a.exceptions.read_text(encoding="utf-8")).get("exceptions", [])}
    gl_get = gl_get or ClientGraylog(a.vars, a.graylog_url).get
    try:
        inv = collecter(gl_get)
    except Exception as exc:  # noqa: BLE001 - API injoignable : validation impossible
        raison = getattr(exc, "reason", None) or getattr(exc, "code", None) or ""
        print(f"API Graylog injoignable : {type(exc).__name__} {raison}".strip(), file=sys.stderr)
        return 3
    if os_client is None and controles & {"statique", "vivacite"}:
        os_client = ClientOpenSearch(a.opensearch, pause_s=a.pause)
    res = valider(inv, os_client, controles=controles, fixtures=fixtures, exceptions=exceptions, depot=a.depot,
                  fenetre_j=a.fenetre_jours, recente_j=a.recente_jours, priorite_critique=a.priorite_critique,
                  plafond=a.plafond)
    genere = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
    parametres = {"controles": sorted(controles), "fenetre_jours": a.fenetre_jours, "recente_jours": a.recente_jours,
                  "priorite_critique": a.priorite_critique, "plafond": a.plafond, "fixtures": len(fixtures)}
    doc = rapport_json(res, parametres, genere)
    md = rapport_markdown(res, genere, a.top)
    if a.sortie:
        a.sortie.mkdir(parents=True, exist_ok=True)
        base = a.sortie / f"validation-detections-{dt.datetime.now().strftime('%Y%m%d-%H%M')}"
        base.with_suffix(".json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        base.with_suffix(".md").write_text(md, encoding="utf-8")
        for nom, cible in (("dernier.json", base.with_suffix(".json")), ("dernier.md", base.with_suffix(".md"))):
            lien = a.sortie / nom
            try:
                if lien.is_symlink() or lien.exists():
                    lien.unlink()
                lien.symlink_to(cible.name)
            except OSError:
                pass
    print(json.dumps(doc, ensure_ascii=False, indent=2) if a.json else md)
    if res["erreurs"] and not res["resultats"]:
        return 3
    return 2 if res["resume"]["cassees_critiques"] else 0


if __name__ == "__main__":
    sys.exit(main())
