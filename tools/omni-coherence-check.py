#!/usr/bin/env python3
"""Contrôle de cohérence dépôt / production, en LECTURE SEULE.

Contrôles :
  manifeste  : chaque entrée de manifeste-deploye.txt comparée en SHA-256
               (identique / différent avec sens probable / absent d'un côté) ;
  non-suivis : fichiers déployés (omni-*/oms-* de /usr/local/sbin, unités et
               drop-ins systemd, console /var/www/siem-soc) absents du manifeste ;
  copies     : unités systemd, scripts déployés et crontabs qui référencent une
               copie de travail (/root/omnitech-siem-*) au lieu du dépôt de
               référence ; état Git des copies (sans écrire l'index) ;
  robots     : timers omni-*/oms-* (désactivés, jamais déclenchés), unités en
               échec, dernier résultat non « success » ;
  versions   : paquets installés comparés à stack-versions.env ;
  graylog    : (option --graylog) inventaire par requêtes GET uniquement, titres
               présents en production mais introuvables dans le dépôt (tout
               fichier suivi hors docs/ ; les objets manuels versionnés par
               26-graylog-objets-manuels.sh le sont sous objets-graylog/).

Aucune écriture : pas de systemctl start/stop, pas de POST/PUT/DELETE, Git
appelé avec --no-optional-locks. Dépendances : bibliothèque standard seule.

Code retour : 0 sans écart critique, 2 si au moins un écart critique,
1 si --strict et au moins un écart de gravité élevée, 3 erreur d'usage.
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import unicodedata
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

GRAVITES = ("critique", "elevee", "moyenne", "faible", "info")
LIBELLES = {"critique": "CRITIQUE", "elevee": "ELEVEE", "moyenne": "MOYENNE", "faible": "FAIBLE", "info": "INFO"}
COPIES_PAR_DEFAUT = ("/root/omnitech-siem-setup", "/root/omnitech-siem-merge", "/root/omnitech-siem-purge")
MOTIF_COPIE = re.compile(r"/root/omnitech-siem-[A-Za-z0-9_.-]+")
DIRECTIVES_EXEC = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "WorkingDirectory",
                   "EnvironmentFile", "ReadWritePaths", "ReadOnlyPaths")
INTEGRES_GRAYLOG = {"System notification events", "All events", "All system events", "Default Stream"}
PAQUETS = {"GRAYLOG_PACKAGE_VERSION": "graylog-server", "OPENSEARCH_PACKAGE_VERSION": "opensearch",
           "MONGODB_PACKAGE_VERSION": "mongodb-org-server"}


@dataclass
class Ecart:
    controle: str
    gravite: str
    objet: str
    constat: str
    preuve: str = ""
    correctif: str = ""


@dataclass
class Rapport:
    ecarts: list[Ecart] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def ajouter(self, *args, **kw):
        self.ecarts.append(Ecart(*args, **kw))

    def compte(self, gravite):
        return sum(1 for e in self.ecarts if e.gravite == gravite)


class Contexte:
    """Accès au système : racine de production et dépôt injectables pour les tests."""

    def __init__(self, depot: Path, racine: Path = Path("/"), executer=None):
        self.depot = depot
        self.racine = racine
        self._executer = executer

    def prod(self, chemin: str) -> Path:
        return self.racine / chemin.lstrip("/")

    def executer(self, cmd: list[str], timeout: int = 30) -> tuple[int, str]:
        if self._executer is not None:
            return self._executer(cmd)
        env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", LC_ALL="C", SYSTEMD_PAGER="", GIT_PAGER="cat")
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            return p.returncode, p.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, str(exc)


def sha256(chemin: Path) -> str:
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def lire_manifeste(chemin: Path) -> list[tuple[str, str]]:
    entrees = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        if not ligne.strip() or ligne.startswith("#"):
            continue
        prod, _, depot = ligne.partition("\t")
        if prod and depot:
            entrees.append((prod.strip(), depot.strip()))
    return entrees


def date_commit(ctx: Contexte, rel: str) -> float | None:
    code, sortie = ctx.executer(["git", "--no-optional-locks", "-C", str(ctx.depot), "log", "-1", "--format=%ct", "--", rel])
    try:
        return float(sortie.strip()) if code == 0 and sortie.strip() else None
    except ValueError:
        return None


# ----------------------------------------------------------------- manifeste
def controle_manifeste(ctx: Contexte, rapport: Rapport) -> set[str]:
    man = ctx.depot / "manifeste-deploye.txt"
    if not man.is_file():
        rapport.ajouter("manifeste", "elevee", str(man), "manifeste absent", correctif="./generer-manifeste.sh")
        return set()
    entrees = lire_manifeste(man)
    n = {"identiques": 0, "differents": 0, "absents_prod": 0, "absents_depot": 0}
    for prod, rel in entrees:
        p, d = ctx.prod(prod), ctx.depot / rel
        if not p.is_file():
            n["absents_prod"] += 1
            rapport.ajouter("manifeste", "moyenne", prod, f"absent en production (dépôt : {rel})",
                            preuve=f"test -f {prod}", correctif="retirer l'entrée du manifeste ou déployer le fichier")
            continue
        if not d.is_file():
            n["absents_depot"] += 1
            rapport.ajouter("manifeste", "elevee", prod, f"en service mais absent du dépôt ({rel})",
                            preuve=f"test -f {rel}", correctif="./synchro-manifeste.sh --copier puis revue et commit")
            continue
        if sha256(p) == sha256(d):
            n["identiques"] += 1
            continue
        n["differents"] += 1
        t_prod, t_depot = p.stat().st_mtime, date_commit(ctx, rel)
        if t_depot is None:
            sens = "sens indéterminé"
        elif t_prod > t_depot:
            sens = "production plus récente que le dépôt"
        else:
            sens = "dépôt plus récent que la production"
        rapport.ajouter("manifeste", "elevee", prod, f"contenu différent de {rel} ({sens})",
                        preuve=f"diff {prod} {rel}",
                        correctif="versionner la version en service" if "production" in sens.split()[0] else
                        "déployer la version du dépôt après revue")
    rapport.stats["manifeste"] = dict(n, entrees=len(entrees))
    return {prod for prod, _ in entrees}


def fichiers_deployes(ctx: Contexte) -> list[str]:
    trouves = []
    sbin = ctx.prod("/usr/local/sbin")
    if sbin.is_dir():
        trouves += [f"/usr/local/sbin/{f.name}" for f in sorted(sbin.iterdir())
                    if f.is_file() and (f.name.startswith("omni-") or f.name.startswith("oms-"))]
    unites = ctx.prod("/etc/systemd/system")
    if unites.is_dir():
        for f in sorted(unites.iterdir()):
            if not (f.name.startswith("omni-") or f.name.startswith("oms-")):
                continue
            if f.is_file() and not f.is_symlink():
                trouves.append(f"/etc/systemd/system/{f.name}")
            elif f.is_dir() and f.name.endswith(".d"):
                trouves += [f"/etc/systemd/system/{f.name}/{c.name}" for c in sorted(f.iterdir()) if c.is_file()]
        for svc in ("graylog-server", "opensearch", "mongod", "logstash", "nginx"):
            d = unites / f"{svc}.service.d"
            if d.is_dir():
                trouves += [f"/etc/systemd/system/{d.name}/{c.name}" for c in sorted(d.iterdir()) if c.is_file()]
    soc = ctx.prod("/var/www/siem-soc")
    if soc.is_dir():
        trouves += ["/" + str(f.relative_to(ctx.racine)) for f in sorted(soc.rglob("*")) if f.is_file()]
    for rep in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d", "/etc/nginx/snippets"):
        d = ctx.prod(rep)
        if d.is_dir():
            trouves += [f"{rep}/{f.name}" for f in sorted(d.iterdir())
                        if f.is_file() and f.name.startswith(("omni", "graylog"))]
    return trouves


def equivalent_console(ctx: Contexte, prod: str) -> Path | None:
    if prod.startswith("/var/www/siem-soc/"):
        return ctx.depot / "mobile/soc" / prod[len("/var/www/siem-soc/"):]
    return None


def controle_non_suivis(ctx: Contexte, rapport: Rapport, suivis: set[str]):
    n = 0
    for prod in fichiers_deployes(ctx):
        if prod in suivis:
            continue
        eq = equivalent_console(ctx, prod)
        if eq is not None and eq.is_file():
            if sha256(ctx.prod(prod)) == sha256(eq):
                continue
            rapport.ajouter("non-suivis", "elevee", prod, f"console : diffère de {eq.relative_to(ctx.depot)}",
                            preuve=f"sha256sum {prod}", correctif="redéployer la console (make console-deploy) après revue")
            n += 1
            continue
        n += 1
        rapport.ajouter("non-suivis", "moyenne", prod, "déployé mais absent du manifeste (non versionné ou non relié)",
                        preuve=f"grep -F '{prod}' manifeste-deploye.txt",
                        correctif="versionner sous deploye/ puis ./generer-manifeste.sh")
    rapport.stats["non_suivis"] = n


# -------------------------------------------------------------------- copies
def lignes_directives(texte: str):
    for i, ligne in enumerate(texte.splitlines(), 1):
        cle, sep, val = ligne.partition("=")
        if sep and cle.strip() in DIRECTIVES_EXEC:
            yield i, cle.strip(), val.strip()


def controle_copies(ctx: Contexte, rapport: Rapport, copies: tuple[str, ...]):
    unites = ctx.prod("/etc/systemd/system")
    services_copie, copies_utilisees = set(), set()
    if unites.is_dir():
        fichiers = [f for f in sorted(unites.rglob("*")) if f.is_file() and not f.is_symlink()
                    and re.match(r"(omni|oms)-", f.relative_to(unites).parts[0])]
        for f in fichiers:
            try:
                texte = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for num, cle, val in lignes_directives(texte):
                m = MOTIF_COPIE.search(val)
                if not m:
                    continue
                unite = f.relative_to(unites).parts[0].removesuffix(".d")
                services_copie.add(unite)
                copies_utilisees.add(m.group(0))
                grav = "critique" if cle in ("ExecStart", "WorkingDirectory", "ExecStartPre") else "elevee"
                rapport.ajouter("copies", grav, unite, f"{cle} pointe vers la copie {m.group(0)}",
                                preuve=f"/etc/systemd/system/{f.relative_to(unites)}:{num}",
                                correctif="repointer vers le dépôt de référence (voir plan de remise en cohérence)")
    sbin = ctx.prod("/usr/local/sbin")
    if sbin.is_dir():
        for f in sorted(sbin.iterdir()):
            if not f.is_file():
                continue
            try:
                texte = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            refs = sorted({m.group(0) for m in MOTIF_COPIE.finditer(texte)})
            if refs:
                rapport.ajouter("copies", "elevee", f"/usr/local/sbin/{f.name}",
                                f"chemin en dur vers {', '.join(refs)}",
                                preuve=f"grep -n omnitech-siem /usr/local/sbin/{f.name}",
                                correctif="lire la configuration depuis un chemin stable (variable ou /etc)")
    for rep in ("/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"):
        p = ctx.prod(rep)
        for f in ([p] if p.is_file() else sorted(p.glob("*")) if p.is_dir() else []):
            try:
                texte = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if MOTIF_COPIE.search(texte):
                rapport.ajouter("copies", "critique", str(f), "tâche cron lancée depuis une copie de travail",
                                preuve=f"grep -n omnitech-siem {f}", correctif="repointer vers le dépôt de référence")
    ref = etat_git(ctx, str(ctx.depot))
    rapport.stats["reference"] = ref
    etats = {}
    for c in copies:
        if not ctx.prod(c).is_dir():
            continue
        e = etat_git(ctx, str(ctx.prod(c)))
        if ref.get("head") and e.get("head"):
            code, sortie = ctx.executer(["git", "--no-optional-locks", "-C", str(ctx.depot), "rev-list", "--count",
                                         f"{e['head']}..{ref['head']}"])
            e["retard_sur_reference"] = int(sortie.strip()) if code == 0 and sortie.strip().isdigit() else None
        etats[c] = e
        utilisee = c in copies_utilisees
        if e.get("modifies", 0) and utilisee:
            rapport.ajouter("copies", "elevee", c,
                            f"copie utilisée par la production avec {e['modifies']} modification(s) non commitée(s)",
                            preuve=f"git -C {c} status --porcelain",
                            correctif="ne plus exécuter depuis cette copie ; archiver puis retirer")
        elif e.get("retard_sur_reference"):
            rapport.ajouter("copies", "faible", c, f"copie en retard de {e['retard_sur_reference']} commit(s)",
                            preuve=f"git rev-list --count {e.get('head', '')[:7]}..{ref.get('head', '')[:7]}",
                            correctif="archiver puis retirer si non utilisée")
    rapport.stats["copies"] = etats
    rapport.stats["unites_sur_copie"] = sorted(services_copie)
    rapport.stats["copies_utilisees"] = sorted(copies_utilisees)


def etat_git(ctx: Contexte, chemin: str) -> dict:
    code, head = ctx.executer(["git", "--no-optional-locks", "-C", chemin, "rev-parse", "HEAD"])
    if code != 0:
        return {}
    _, branche = ctx.executer(["git", "--no-optional-locks", "-C", chemin, "branch", "--show-current"])
    _, statut = ctx.executer(["git", "--no-optional-locks", "-C", chemin, "status", "--porcelain"])
    lignes = [l for l in statut.splitlines() if l.strip()]
    return {"head": head.strip(), "branche": branche.strip(),
            "modifies": sum(1 for l in lignes if not l.startswith("??")),
            "non_suivis": sum(1 for l in lignes if l.startswith("??"))}


# -------------------------------------------------------------------- robots
def controle_robots(ctx: Contexte, rapport: Rapport):
    code, sortie = ctx.executer(["systemctl", "list-unit-files", "--no-legend", "--plain", "omni-*", "oms-*"])
    if code not in (0, 1):
        rapport.ajouter("robots", "info", "systemctl", "inventaire systemd indisponible")
        return
    etats = {}
    for ligne in sortie.splitlines():
        champs = ligne.split()
        if len(champs) >= 2:
            etats[champs[0]] = champs[1]
    timers = sorted(u for u in etats if u.endswith(".timer"))
    for t in timers:
        if etats[t] in ("disabled", "masked"):
            rapport.ajouter("robots", "moyenne", t, f"timer {etats[t]} : le robot ne tourne plus",
                            preuve=f"systemctl is-enabled {t}",
                            correctif="réactiver ou retirer (et mettre la documentation à jour)")
    services = sorted(u for u in etats if u.endswith(".service") and "@" not in u)
    n_echec = 0
    for s in services:
        code, sortie = ctx.executer(["systemctl", "show", s, "-p", "ActiveState", "-p", "Result", "-p",
                                     "ExecMainStatus", "-p", "ExecMainExitTimestampMonotonic"])
        props = dict(l.split("=", 1) for l in sortie.splitlines() if "=" in l)
        if props.get("ActiveState") == "failed":
            n_echec += 1
            rapport.ajouter("robots", "critique", s, "unité en échec",
                            preuve=f"systemctl status {s}", correctif=f"journalctl -u {s} -n 50")
        elif props.get("Result") not in (None, "", "success"):
            n_echec += 1
            rapport.ajouter("robots", "elevee", s, f"dernier résultat : {props.get('Result')}",
                            preuve=f"systemctl show {s} -p Result", correctif=f"journalctl -u {s} -n 50")
    code, sortie = ctx.executer(["systemctl", "list-timers", "--all", "--output=json", "omni-*", "oms-*"])
    jamais = []
    if code == 0:
        try:
            for t in json.loads(sortie or "[]"):
                if not t.get("last"):
                    jamais.append(t.get("unit"))
        except ValueError:
            pass
    for t in jamais:
        if etats.get(t) not in ("disabled", "masked"):
            rapport.ajouter("robots", "faible", t, "timer jamais déclenché (ou historique purgé)",
                            preuve=f"systemctl list-timers {t}")
    rapport.stats["robots"] = {"timers": len(timers), "services": len(services), "en_echec": n_echec,
                               "timers_desactives": [t for t in timers if etats[t] in ("disabled", "masked")]}


# ------------------------------------------------------------------ versions
def lire_env(chemin: Path, cles=None) -> dict:
    """Lit un fichier KEY=valeur ; développe ${VAR}/$VAR déjà définis (guillemets simples : littéral)."""
    res = {}
    if not chemin.is_file():
        return res
    for ligne in chemin.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$', ligne)
        if not m:
            continue
        val = m.group(2).strip()
        if len(val) >= 2 and val[0] == val[-1] == "'":
            res[m.group(1)] = val[1:-1]
            continue
        if len(val) >= 2 and val[0] == val[-1] == '"':
            val = val[1:-1]
        res[m.group(1)] = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                                 lambda x: res.get(x.group(1) or x.group(2), ""), val)
    return {k: v for k, v in res.items() if cles is None or k in cles}


def controle_versions(ctx: Contexte, rapport: Rapport):
    attendu = lire_env(ctx.depot / "stack-versions.env")
    installe = {}
    for cle, paquet in PAQUETS.items():
        code, sortie = ctx.executer(["dpkg-query", "-W", "-f=${Version}", paquet])
        if code != 0:
            continue
        installe[paquet] = sortie.strip()
        voulu = attendu.get(cle)
        if voulu and sortie.strip() != voulu:
            rapport.ajouter("versions", "elevee", paquet, f"installé {sortie.strip()} ≠ stack-versions.env {voulu}",
                            preuve=f"dpkg-query -W {paquet}", correctif="aligner stack-versions.env ou planifier la montée")
    rapport.stats["versions"] = {"attendu": attendu, "installe": installe}


# ------------------------------------------------------------------- graylog
def plier(texte: str) -> str:
    return unicodedata.normalize("NFKD", texte).encode("ascii", "ignore").decode().lower()


def titres_introuvables(titres, corpus: str, corpus_plie: str) -> list[str]:
    manquants = []
    for t in titres:
        if t in corpus or json.dumps(t)[1:-1] in corpus or plier(t) in corpus_plie:
            continue
        manquants.append(t)
    return manquants


def corpus_depot(ctx: Contexte) -> str:
    code, sortie = ctx.executer(["git", "--no-optional-locks", "-C", str(ctx.depot), "ls-files"])
    morceaux = []
    for rel in sortie.splitlines() if code == 0 else []:
        if rel.startswith("docs/") or rel.endswith((".png", ".jpg", ".geojson", ".min.js", ".deb")):
            continue
        try:
            morceaux.append((ctx.depot / rel).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    # Titres assemblés par provision_detections.py : « OMNI - SEAL <id> - <title> »
    for m in re.finditer(r'id="([A-Z]{2,4}-\d{3})",\s*title="([^"]+)"', "\n".join(morceaux)):
        morceaux.append(f"OMNI - SEAL {m.group(1)} - {m.group(2)}")
    return "\n".join(morceaux)


def url_api(base: str) -> str:
    base = (base or "").rstrip("/")
    return base if base.endswith("/api") else base + "/api"


def controle_graylog(ctx: Contexte, rapport: Rapport, vars_env: Path, getter=None):
    env = lire_env(vars_env, {"GRAYLOG_API_URL", "SIEM_FQDN", "GRAYLOG_ADMIN_PASS", "GRAYLOG_API_CA"})
    brut = env.get("GRAYLOG_API_URL", "")
    if brut and not brut.rstrip("/").endswith("/api"):
        rapport.ajouter("graylog", "elevee", "GRAYLOG_API_URL",
                        "valeur sans suffixe /api : lib-platform.sh l'utilise telle quelle, les appels api_* "
                        "reçoivent la page HTML de l'interface",
                        preuve="grep -c '^GRAYLOG_API_URL=' 00-vars.env ; api_get /system | head -c 20",
                        correctif="ajouter /api (les scripts SEAL retirent le suffixe s'il est présent : à vérifier)")
    if getter is None:
        base = url_api(brut or (f"https://{env['SIEM_FQDN']}:9000" if env.get("SIEM_FQDN") else "http://127.0.0.1:9000"))
        auth = "Basic " + base64.b64encode(("admin:" + env.get("GRAYLOG_ADMIN_PASS", "")).encode()).decode()
        ca = env.get("GRAYLOG_API_CA") or "/etc/graylog/certs/omnitech-rootca.crt"
        sslctx = ssl.create_default_context(cafile=ca) if base.startswith("https") and os.path.exists(ca) else None

        def getter(chemin):
            req = urllib.request.Request(base + chemin, method="GET",
                                         headers={"Authorization": auth, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=60, context=sslctx) as r:
                return json.load(r)
    try:
        defs, page = [], 1
        while True:
            lot = getter(f"/events/definitions?per_page=100&page={page}").get("event_definitions", [])
            defs += lot
            if len(lot) < 100:
                break
            page += 1
        inv = {
            "event_definitions": defs,
            "streams": getter("/streams").get("streams", []),
            "pipelines": getter("/system/pipelines/pipeline"),
            "rules": getter("/system/pipelines/rule"),
            "inputs": getter("/system/inputs").get("inputs", []),
            "index_sets": getter("/system/indices/index_sets?limit=500").get("index_sets", []),
        }
        version = getter("/system").get("version", "")
    except Exception as exc:  # noqa: BLE001 - rapport, pas d'arrêt
        raison = getattr(exc, "reason", None) or getattr(exc, "code", None) or ""
        rapport.ajouter("graylog", "info", "API", f"inventaire impossible : {type(exc).__name__} {raison}".strip())
        return
    actives = sum(1 for d in defs if d.get("state") == "ENABLED")
    rapport.stats["graylog"] = {
        "version": version, "event_definitions": len(defs), "actives": actives,
        "desactivees": len(defs) - actives,
        **{k: len(v) for k, v in inv.items() if k != "event_definitions"}}
    corpus = corpus_depot(ctx)
    plie = plier(corpus)
    for cle, champ in (("event_definitions", "title"), ("streams", "title"), ("pipelines", "title"),
                       ("rules", "title"), ("inputs", "title")):
        titres = [o.get(champ, "") for o in inv[cle] if o.get(champ) not in INTEGRES_GRAYLOG]
        manquants = titres_introuvables(titres, corpus, plie)
        rapport.stats["graylog"][f"{cle}_introuvables"] = len(manquants)
        for t in manquants:
            rapport.ajouter("graylog", "faible", f"{cle}: {t}",
                            "présent en production, titre introuvable tel quel dans le dépôt",
                            preuve=f"git grep -F \"{t[:40]}\"",
                            correctif="versionner la définition (ou confirmer qu'elle est générée)")


# ------------------------------------------------------------------- sorties
def texte(rapport: Rapport) -> str:
    out = ["Contrôle de cohérence dépôt / production (lecture seule)", ""]
    for g in GRAVITES:
        lot = [e for e in rapport.ecarts if e.gravite == g]
        if not lot:
            continue
        out.append(f"== {LIBELLES[g]} ({len(lot)})")
        for e in lot:
            out.append(f"  [{e.controle}] {e.objet} : {e.constat}")
            if e.preuve:
                out.append(f"      preuve   : {e.preuve}")
            if e.correctif:
                out.append(f"      correctif: {e.correctif}")
        out.append("")
    out.append("Synthèse : " + ", ".join(f"{LIBELLES[g].lower()} {rapport.compte(g)}" for g in GRAVITES))
    return "\n".join(out)


def code_retour(rapport: Rapport, strict: bool) -> int:
    if rapport.compte("critique"):
        return 2
    if strict and rapport.compte("elevee"):
        return 1
    return 0


def main(argv=None, executer=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--depot", type=Path, default=Path(__file__).resolve().parents[1],
                    help="dépôt de référence (défaut : celui qui contient cet outil)")
    ap.add_argument("--racine", type=Path, default=Path("/"), help="racine du système contrôlé (tests)")
    ap.add_argument("--controles", default="manifeste,non-suivis,copies,robots,versions",
                    help="liste séparée par des virgules ; ajouter graylog ou utiliser --graylog")
    ap.add_argument("--graylog", action="store_true", help="ajoute l'inventaire Graylog (GET uniquement)")
    ap.add_argument("--vars", type=Path, default=None, help="fichier de variables (défaut : <dépôt>/00-vars.env)")
    ap.add_argument("--copie", action="append", default=None, help="copie de travail à inventorier (répétable)")
    ap.add_argument("--json", action="store_true", help="sortie JSON")
    ap.add_argument("--strict", action="store_true", help="code retour 1 si écart de gravité élevée")
    a = ap.parse_args(argv)
    if not a.depot.is_dir():
        print(f"dépôt introuvable : {a.depot}", file=sys.stderr)
        return 3
    controles = {c.strip() for c in a.controles.split(",") if c.strip()}
    if a.graylog:
        controles.add("graylog")
    inconnus = controles - {"manifeste", "non-suivis", "copies", "robots", "versions", "graylog"}
    if inconnus:
        print(f"contrôle inconnu : {', '.join(sorted(inconnus))}", file=sys.stderr)
        return 3
    ctx = Contexte(a.depot.resolve(), a.racine, executer)
    rapport = Rapport()
    suivis = controle_manifeste(ctx, rapport) if "manifeste" in controles or "non-suivis" in controles else set()
    if "non-suivis" in controles:
        controle_non_suivis(ctx, rapport, suivis)
    if "copies" in controles:
        controle_copies(ctx, rapport, tuple(a.copie) if a.copie else COPIES_PAR_DEFAUT)
    if "robots" in controles:
        controle_robots(ctx, rapport)
    if "versions" in controles:
        controle_versions(ctx, rapport)
    if "graylog" in controles:
        controle_graylog(ctx, rapport, a.vars or ctx.depot / "00-vars.env")
    if a.json:
        print(json.dumps({"ecarts": [asdict(e) for e in rapport.ecarts], "stats": rapport.stats,
                          "synthese": {g: rapport.compte(g) for g in GRAVITES}}, ensure_ascii=False, indent=2))
    else:
        print(texte(rapport))
    return code_retour(rapport, a.strict)


if __name__ == "__main__":
    sys.exit(main())
