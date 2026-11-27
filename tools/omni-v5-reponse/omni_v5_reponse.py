#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
omni-v5-reponse : réponse à incident AVEC VALIDATION HUMAINE, en SIMULATION.
Chantier 5 du SIEM v5 OMNITECH (27/11/2026).

Actions proposées (aucune n'est exécutée : ce service ne contient AUCUN client ESET,
AD ou Graph ; le mode réel n'existe pas dans ce code) :
  - isoler_poste_eset       : isoler un poste du réseau dans ESET PROTECT
  - desactiver_compte_ad    : désactiver un compte Active Directory
  - revoquer_sessions_entra : révoquer les sessions Entra ID (jetons d'actualisation)

Parcours : demande (compte SOC authentifié) -> jeton à usage unique, 15 min ->
page de confirmation réservée à SOC_ADMINS -> en simulation, journalisation de ce
qui AURAIT été fait (GELF event_source=reponse + audit local chaîné SHA-256).

Authentification : cookie de session de la console /soc/ (oms_session, Path=/m),
vérifié en le présentant à omni-mobile-api (GET /m/api/me, 127.0.0.1:8090) : ce
service ne connaît pas le secret de session. Validateurs : liste SOC_ADMINS extraite
au démarrage de /etc/default/omni-mobile (seule cette clé est lue) ET rôle
« administrateur » renvoyé par /m/api/me.

Écoute 127.0.0.1 uniquement ; exposé par nginx sous /m/reponse/.
Bibliothèque standard Python uniquement.

Cibles protégées propres au site (contrôleurs de domaine, serveurs d'infrastructure,
comptes de service, compte leurre, comptes d'accès d'urgence) : fichier
/etc/omni-v5-reponse/cibles-protegees (REPONSE_CIBLES), modèle cibles-protegees.exemple.
Sans ce fichier, ou s'il est vide ou mal formé, le service refuse de démarrer : les
garde-fous génériques (motifs AD/DC, adm-*, svc*, comptes machine, MAB, break-glass)
restent dans le code et ne sont jamais désactivables.
"""
import hashlib, hmac, html, ipaddress, json, os, re, secrets, socket, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0-20261127"

# --------------------------------------------------------------------- configuration
def _conf(path="/etc/omni-v5-reponse/reponse.env"):
    c = {}
    try:
        for l in open(path, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1)
                c[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return c

CONF = _conf(os.environ.get("REPONSE_CONF", "/etc/omni-v5-reponse/reponse.env"))
def C(k, d=""):
    return os.environ.get(k, CONF.get(k, d))

MODE = C("REPONSE_MODE", "simulation")
PORT = int(C("REPONSE_PORT", "8091"))
BIND = "127.0.0.1"                                   # en dur : jamais d'écoute externe
TTL = 15 * 60                                        # en dur : jeton valable 15 min
PREFIXE = "/m/reponse"
ME_URL = C("REPONSE_ME_URL", "http://127.0.0.1:8090/m/api/me")
GELF_URL = C("REPONSE_GELF_URL", "http://127.0.0.1:12201/gelf")
OS_URL = C("REPONSE_OS_URL", "http://127.0.0.1:9200")
ETAT = C("REPONSE_ETAT", os.environ.get("STATE_DIRECTORY", "/var/lib/omni-v5-reponse"))
SOC_ADMINS_FILE = C("REPONSE_SOC_ADMINS_FILE", "/run/omni-v5-reponse/soc_admins")
HOTES = {h.strip().lower() for h in C("REPONSE_HOTES", "bx-it-graylog-vm.omnitech.security,10.33.220.10").split(",") if h.strip()}
BASE_URL = C("REPONSE_BASE_URL", "https://bx-it-graylog-vm.omnitech.security")
RESEAUX = [ipaddress.ip_network(n.strip()) for n in C("REPONSE_RESEAUX", "10.0.0.0/8,127.0.0.1/32").split(",") if n.strip()]
DOMAINES_UPN = {d.strip().lower() for d in C("REPONSE_DOMAINES_UPN", "omnitech-security.fr,omnitech.security").split(",") if d.strip()}
SEPARATION = C("REPONSE_SEPARATION", "1") != "0"     # valideur différent du demandeur
DEMANDES_MAX_5MIN = int(C("REPONSE_DEMANDES_MAX_5MIN", "10"))

if MODE != "simulation":
    # Garde-fou structurel : le mode réel n'est pas implémenté (aucun client d'action).
    sys.stderr.write("omni-v5-reponse : seul REPONSE_MODE=simulation est accepté (mode réel non implémenté)\n")
    sys.exit(78)

DEM_DIR = os.path.join(ETAT, "demandes")
AUDIT = os.path.join(ETAT, "audit.jsonl")
CSRF_KEY_FILE = os.path.join(ETAT, "csrf.key")
os.makedirs(DEM_DIR, exist_ok=True)
_LOCK = threading.Lock()
_RATE = {}

def _csrf_key():
    try:
        with open(CSRF_KEY_FILE, "rb") as f:
            k = f.read()
            if len(k) >= 32:
                return k
    except OSError:
        pass
    k = secrets.token_bytes(32)
    fd = os.open(CSRF_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(k)
    return k
CSRF_KEY = _csrf_key()

def soc_admins():
    try:
        return {u.strip().lower() for u in open(SOC_ADMINS_FILE, encoding="utf-8").read().replace("\n", ",").split(",") if u.strip()}
    except OSError:
        return set()

# --------------------------------------------------------------------- actions (descriptions seulement)
ACTIONS = {
    "isoler_poste_eset": {
        "libelle": "Isoler le poste du réseau (ESET PROTECT)",
        "type_cible": "hote",
        "aurait_fait": ("ESET PROTECT : tâche client « Isoler l'ordinateur du réseau » "
                        "(Network Isolation, ESET Endpoint ≥ 10.1) sur la fiche ESET nommée {cible} ; seules les "
                        "communications avec ESET PROTECT restent ouvertes. Levée : tâche « Mettre fin à l'isolement du "
                        "réseau ». Compte prévu : compte natif ESET dédié, jeu d'autorisations limité aux tâches "
                        "d'isolement sur le groupe « Postes de travail »."),
        "reversible": "oui (tâche de fin d'isolement)",
    },
    "desactiver_compte_ad": {
        "libelle": "Désactiver le compte Active Directory",
        "type_cible": "compte",
        "aurait_fait": ("Active Directory : Disable-ADAccount -Identity {cible} (attribut userAccountControl, bit "
                        "ACCOUNTDISABLE) par un compte délégué dédié limité à l'écriture de userAccountControl sur les "
                        "OU d'utilisateurs ; propagation Entra Connect au cycle suivant (≤ 30 min). Les sessions déjà "
                        "ouvertes ne sont PAS coupées (à combiner avec la révocation Entra et le changement de mot de "
                        "passe). Levée : Enable-ADAccount -Identity {cible}."),
        "reversible": "oui (Enable-ADAccount)",
    },
    "revoquer_sessions_entra": {
        "libelle": "Révoquer les sessions Entra ID",
        "type_cible": "upn",
        "aurait_fait": ("Microsoft Graph : POST /v1.0/users/{cible}/revokeSignInSessions par l'application dédiée "
                        "« OMNI SOC Réponse » (permission d'application User.RevokeSessions.All, authentification par "
                        "certificat) ; les jetons d'actualisation et cookies de session sont invalidés, reconnexion "
                        "avec MFA exigée (délai de prise en compte : jusqu'à 1 h pour les jetons d'accès déjà émis)."),
        "reversible": "sans objet (l'utilisateur se reconnecte)",
    },
}

# --------------------------------------------------------------------- GARDE-FOUS
# Tout refus est définitif pour la demande ; l'évaluation est refaite à la validation.
# Génériques, en dur : motifs AD/DC, serveur SIEM, comptes intégrés, motifs de comptes techniques (ci-dessous).
# Propres au site : fichier CIBLES (format décrit dans cibles-protegees.exemple), obligatoire.
_DC_RX = re.compile(r"(^|[-_])(AD|DC)[-_]?\d{0,2}([-_]|$)|^DC\d|-DC\d", re.I)
_HOTES_INTERDITS_RX = [
    (re.compile(r"GRAYLOG|SIEM", re.I), "serveur SIEM (isoler le SIEM l'aveuglerait)"),
]
_COMPTES_INTEGRES = {"krbtgt", "administrateur", "administrator", "invité", "invite", "guest",
                     "defaultaccount", "wdagutilityaccount"}
CIBLES = C("REPONSE_CIBLES", "/etc/omni-v5-reponse/cibles-protegees")

def _charger_cibles(path):
    """Lit les cibles protégées du site : « type valeur [=> motif] » par ligne, # en début de ligne = commentaire.
    Types : dc (nom d'hôte de contrôleur de domaine), ip (adresse d'un DC), hote-rx (expression régulière
    sur le nom d'hôte), compte (sAMAccountName exact), leurre (compte leurre exact). Erreur = arrêt."""
    dc, ip, hrx, comptes, leurres = set(), set(), [], set(), set()
    with open(path, encoding="utf-8") as f:
        for n, ligne in enumerate(f, 1):
            ligne = ligne.strip()
            if not ligne or ligne.startswith("#"):
                continue
            corps, _, motif = ligne.partition("=>")
            parts = corps.split(None, 1)
            if len(parts) != 2:
                raise ValueError(f"{path}:{n} : « type valeur [=> motif] » attendu")
            t, v = parts[0].lower(), parts[1].strip()
            if t == "dc":
                dc.add(v.upper())
            elif t == "ip":
                ip.add(str(ipaddress.ip_address(v)))
            elif t == "hote-rx":
                hrx.append((re.compile(v, re.I), motif.strip() or "hôte protégé (liste du site)"))
            elif t == "compte":
                comptes.add(v.lower())
            elif t == "leurre":
                leurres.add(v.lower())
            else:
                raise ValueError(f"{path}:{n} : type inconnu {t!r}")
    if not (dc or ip or hrx or comptes or leurres):
        raise ValueError(f"{path} : aucune cible protégée")
    return dc, ip, hrx, comptes, leurres

try:
    _DC, _IP_DC, _HOTES_SITE_RX, _COMPTES_SITE, _LEURRES = _charger_cibles(CIBLES)
except (OSError, ValueError, re.error) as _ex:
    sys.stderr.write(f"omni-v5-reponse : cibles protégées illisibles ({_ex}) : démarrage refusé\n")
    sys.exit(78)
_HOTES_INTERDITS_RX += _HOTES_SITE_RX
_COMPTES_INTERDITS = _COMPTES_INTEGRES | _COMPTES_SITE | _LEURRES
_COMPTES_RX = [
    (re.compile(r"^adm[-_.]", re.I), "compte d'administration adm-*"),
    (re.compile(r"^(svc|srv[-_]|sa[-_]|gmsa|msol_|aad_|adsync|sync_|healthmailbox|sm_|on-premises|mab[-_])", re.I), "compte de service ou de synchronisation"),
    (re.compile(r"(svc|service|backup|sync|ldap|api|scan|robot|bot)$", re.I), "nom de compte technique"),
    (re.compile(r"\$$"), "compte machine ou gMSA"),
    (re.compile(r"^[0-9a-f]{12}$", re.I), "compte MAB du NAC Aruba (adresse MAC) : le désactiver coupe le réseau de l'équipement"),
    (re.compile(r"break.?glass|urgence|emergency", re.I), "compte d'accès d'urgence (break-glass)"),
]

def _norm_hote(c):
    c = c.strip().strip("\\").upper()
    if "\\" in c:
        c = c.split("\\")[-1]
    return c.split(".")[0].rstrip("$")

def _norm_compte(c):
    c = c.strip()
    if "\\" in c:
        c = c.split("\\")[-1]
    if "@" in c:
        c = c.split("@")[0]
    return c.lower()

def garde_fou(action, cible):
    """Retourne (True, cible_normalisée) ou (False, motif)."""
    a = ACTIONS.get(action)
    if not a:
        return False, "action inconnue"
    c = (cible or "").strip()
    if not c or len(c) > 120 or re.search(r"[\s\"'<>;|&`*?()\[\]{}]", c):
        return False, "cible vide, trop longue ou contenant des caractères interdits"
    t = a["type_cible"]
    if t == "hote":
        try:
            ipaddress.ip_address(c)
            return False, ("IP d'un contrôleur de domaine" if c in _IP_DC else
                           "cible attendue : nom d'ordinateur (pas d'adresse IP)")
        except ValueError:
            pass
        h = _norm_hote(c)
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]{0,62}", h):
            return False, "nom d'ordinateur invalide"
        if h in _DC or _DC_RX.search(h):
            return False, "contrôleur de domaine (ou nom de type AD/DC) : jamais d'action automatisée"
        for rx, motif in _HOTES_INTERDITS_RX:
            if rx.search(h):
                return False, motif
        return True, h
    # comptes (AD ou UPN Entra)
    if t == "upn":
        if not re.fullmatch(r"[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{3,190}", c):
            return False, "UPN attendu (prenom.nom@domaine)"
        dom = c.split("@", 1)[1].lower()
        if dom not in DOMAINES_UPN:
            return False, f"domaine {dom} non géré (invités, partenaires : action manuelle)"
        if "#ext#" in c.lower():
            return False, "compte invité"
        if re.match(r"^sync_", c, re.I) or "onmicrosoft.com" in dom:
            return False, "compte de synchronisation ou compte cloud technique"
    else:
        if "@" in c or not re.fullmatch(r"[A-Za-z0-9._\\$-]{1,64}", c):
            return False, "sAMAccountName attendu (sans domaine)"
    s = _norm_compte(c)
    if s in _COMPTES_INTERDITS:
        return False, ("compte leurre : NE JAMAIS TOUCHER" if s in _LEURRES
                       else "compte de service, intégré ou protégé (code ou liste du site)")
    for rx, motif in _COMPTES_RX:
        if rx.search(s):
            return False, motif
    return True, (c.lower() if t == "upn" else s)

# --------------------------------------------------------------------- journalisation
def gelf(etape, d, extra=None):
    msg = {"version": "1.1", "host": "omni-v5-reponse",
           "short_message": f"[REPONSE {MODE.upper()}] {etape} {d.get('action','?')} -> {d.get('cible','?')}"
                            f" (demandeur {d.get('demandeur','?')}, valideur {d.get('valideur','-')})",
           "_event_source": "reponse", "_mode": MODE, "_reponse_etape": etape,
           "_action": d.get("action", ""), "_cible": d.get("cible", ""),
           "_demandeur": d.get("demandeur", ""), "_valideur": d.get("valideur", ""),
           "_reponse_id": d.get("id", ""), "_alerte": d.get("alerte", "")[:200],
           "_motif": d.get("motif", "")[:300], "_reponse_version": VERSION}
    for k, v in (extra or {}).items():
        msg["_" + k] = v
    try:
        r = urllib.request.Request(GELF_URL, data=json.dumps(msg).encode(), headers={"Content-Type": "application/json"})
        urllib.request.urlopen(r, timeout=3).close()
        return True
    except Exception as ex:
        sys.stderr.write(f"gelf: echec {type(ex).__name__}\n")
        return False

def audit(etape, d, extra=None):
    e = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "etape": etape, "mode": MODE,
         **{k: d.get(k, "") for k in ("id", "action", "cible", "demandeur", "valideur", "alerte", "motif")}}
    if extra:
        e.update(extra)
    with _LOCK:
        prev, seq = "0" * 64, 0
        try:
            with open(AUDIT, "rb") as f:
                f.seek(0, 2); n = f.tell(); f.seek(max(0, n - 65536))
                for l in reversed(f.read().decode("utf-8", "replace").splitlines()):
                    if l.strip():
                        j = json.loads(l); prev, seq = j["hash"], j["seq"]; break
        except (OSError, ValueError, KeyError):
            pass
        e["seq"], e["prev"] = seq + 1, prev
        e["hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
            f.flush(); os.fsync(f.fileno())
    gelf(etape, d, extra)
    sys.stdout.write(f"[{etape}] {d.get('id','')} {d.get('action','')} {d.get('cible','')} "
                     f"dem={d.get('demandeur','')} val={d.get('valideur','')}\n"); sys.stdout.flush()

# --------------------------------------------------------------------- demandes
def _dem_path(rid):
    if not re.fullmatch(r"[0-9a-f]{16}", rid or ""):
        return None
    return os.path.join(DEM_DIR, rid + ".json")

def dem_lire(rid):
    p = _dem_path(rid)
    if not p:
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

def dem_ecrire(d):
    p = _dem_path(d["id"])
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, p)

def _ctx(rid, valideur):
    """Contexte d'une demande pour la journalisation d'un refus (sans l'empreinte du jeton)."""
    d = dem_lire(rid) or {}
    return {"id": rid, "valideur": valideur, **{k: d.get(k, "") for k in ("action", "cible", "demandeur", "alerte", "motif")}}

def _h(tok):
    return hashlib.sha256(("v5-reponse|" + tok).encode()).hexdigest()

def contexte_siem(action, cible):
    """Lecture informative : la cible apparaît-elle dans le SIEM sur 24 h ? (aucun effet)"""
    try:
        if ACTIONS[action]["type_cible"] == "hote":
            vals = [cible, cible.lower(), cible.lower() + ".omnitech.security", cible + ".omnitech.security"]
            q = {"bool": {"should": [{"terms": {"source": vals}}, {"terms": {"winlogbeat_computer_name": vals}}], "minimum_should_match": 1}}
        else:
            u = cible.split("@")[0]
            q = {"bool": {"should": [{"terms": {"user": [u, cible, u.upper()]}}, {"terms": {"winlogbeat_winlog_event_data_TargetUserName": [u, u.upper()]}}], "minimum_should_match": 1}}
        body = {"size": 0, "track_total_hits": 10000, "query": {"bool": {"filter": [q, {"range": {"timestamp": {"gte": "now-24h"}}}]}}}
        r = urllib.request.Request(OS_URL + "/omni-winsec_*,omni-m365_*,omni-eset_*/_search?request_cache=false&timeout=5s",
                                   data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        n = json.load(urllib.request.urlopen(r, timeout=8))["hits"]["total"]["value"]
        return f"{n}{'+' if n >= 10000 else ''} événement(s) sur 24 h dans le SIEM"
    except Exception as ex:
        return f"contexte SIEM indisponible ({type(ex).__name__})"

# --------------------------------------------------------------------- pages
CSS = ("body{margin:0;background:#eef1f4;font-family:Segoe UI,-apple-system,Roboto,Arial,sans-serif;color:#212529}"
       ".c{max-width:640px;margin:32px auto;background:#fff;border-radius:12px;padding:24px 22px;box-shadow:0 1px 6px rgba(0,0,0,.1)}"
       ".k{font-size:11px;letter-spacing:2px;color:#5f3dc4;text-transform:uppercase;font-weight:700}"
       ".sim{background:#fff3bf;border:1px solid #fab005;color:#5c3c00;padding:8px 12px;border-radius:8px;font-size:13px;margin:10px 0}"
       ".err{background:#ffe3e3;border:1px solid #fa5252;color:#7a1010;padding:8px 12px;border-radius:8px}"
       ".ok{background:#ebfbee;border:1px solid #40c057;color:#0b4d1c;padding:8px 12px;border-radius:8px}"
       "table{border-collapse:collapse;width:100%;font-size:14px}td{padding:6px 4px;border-bottom:1px solid #e9ecef;vertical-align:top}"
       "td.l{color:#868e96;width:34%}input,select,textarea{width:100%;box-sizing:border-box;padding:8px;font-size:14px;border:1px solid #ced4da;border-radius:6px}"
       "button{border:0;font-size:14px;font-weight:700;padding:10px 18px;border-radius:8px;cursor:pointer;margin:12px 8px 0 0}"
       ".b1{background:#c92a2a;color:#fff}.b2{background:#495057;color:#fff}.b3{background:#5f3dc4;color:#fff}"
       "code{background:#f1f3f5;padding:1px 4px;border-radius:4px;word-break:break-all}a{color:#5f3dc4}")

def page(titre, corps):
    return (f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="referrer" content="same-origin"><title>{html.escape(titre)}</title><style>{CSS}</style></head><body><div class="c">'
            f'<div class="k">SIEM OMNITECH · Réponse à incident</div><h2 style="margin:8px 0 6px">{html.escape(titre)}</h2>'
            f'<div class="sim"><b>MODE SIMULATION</b> : aucune action n\'est exécutée sur le SI ; ce qui aurait été fait est '
            f'seulement journalisé (Graylog <code>event_source:reponse</code>).</div>{corps}</div></body></html>')

def E(x):
    return html.escape(str(x if x is not None else ""), quote=True)

# --------------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "omni-v5-reponse"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(b)

    def _ip(self):
        peer = self.client_address[0] if self.client_address else ""
        if peer in ("127.0.0.1", "::1") and self.headers.get("X-Real-IP"):
            return self.headers.get("X-Real-IP").strip()
        return peer

    def _ip_ok(self):
        try:
            a = ipaddress.ip_address(self._ip())
        except ValueError:
            return False
        return any(a in n for n in RESEAUX)

    def _session(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["oms_session"].value if "oms_session" in c else ""

    def _ident(self):
        """(utilisateur, rôle) via omni-mobile-api ; None si non authentifié."""
        tok = self._session()
        if not tok or len(tok) > 1024:
            return None
        r = urllib.request.Request(ME_URL, headers={"Cookie": "oms_session=" + tok, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=5) as f:
                j = json.load(f)
            u = (j.get("user") or "").strip().lower()
            return (u, j.get("role") or "") if u else None
        except Exception:
            return None

    def _csrf(self, but):
        return hmac.new(CSRF_KEY, (self._session() + "|" + but).encode(), hashlib.sha256).hexdigest()[:40]

    def _origin_ok(self):
        o = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not o:
            return False
        return (urllib.parse.urlparse(o).hostname or "").lower() in HOTES

    def _form(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > 8192:
            return None
        raw = self.rfile.read(n).decode("utf-8", "replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

    def _q(self):
        return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).items()}

    def _non_connecte(self):
        return self._send(401, page("Connexion requise",
            '<p>Ouvrez d\'abord la <a href="/soc/">console SOC</a> et connectez-vous avec votre compte AD, '
            'puis rouvrez ce lien.</p>'))

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        p = urllib.parse.urlsplit(self.path).path
        if not self._ip_ok():
            return self._send(403, page("Accès refusé", '<p class="err">Réseau source non autorisé.</p>'))
        if p == PREFIXE + "/sante":
            return self._send(200, json.dumps({"ok": True, "mode": MODE, "version": VERSION, "ttl_s": TTL,
                                               "validateurs": len(soc_admins())}), "application/json")
        if p in (PREFIXE, PREFIXE + "/", PREFIXE + "/proposer"):
            return self._get_proposer()
        if p == PREFIXE + "/confirmer":
            return self._get_confirmer()
        return self._send(404, page("Page inconnue", '<p><a href="/m/reponse/">Retour</a></p>'))

    def _get_proposer(self):
        who = self._ident()
        if not who:
            return self._non_connecte()
        q = self._q()
        act = q.get("action", "")
        opts = "".join(f'<option value="{E(k)}"{" selected" if k == act else ""}>{E(v["libelle"])}</option>'
                       for k, v in ACTIONS.items())
        corps = (f'<p>Connecté : <b>{E(who[0])}</b> ({E(who[1])}). La demande devra être validée par un membre de '
                 f'<b>SOC_ADMINS</b>{" différent du demandeur" if SEPARATION else ""} dans les 15 minutes.</p>'
                 f'<form method="post" action="{PREFIXE}/demande">'
                 f'<input type="hidden" name="csrf" value="{E(self._csrf("demande"))}">'
                 f'<p><label>Action<br><select name="action">{opts}</select></label></p>'
                 f'<p><label>Cible (nom d\'ordinateur, sAMAccountName ou UPN selon l\'action)<br>'
                 f'<input name="cible" maxlength="120" required value="{E(q.get("cible", ""))}"></label></p>'
                 f'<p><label>Alerte d\'origine<br><input name="alerte" maxlength="200" value="{E(q.get("alerte", ""))}"></label></p>'
                 f'<p><label>Motif (obligatoire)<br><textarea name="motif" rows="3" maxlength="300" required>{E(q.get("motif", ""))}</textarea></label></p>'
                 f'<button class="b3" type="submit">Créer la demande</button></form>'
                 f'<p style="font-size:12px;color:#868e96">Garde-fous : jamais un contrôleur de domaine, un compte adm-*, '
                 f'un compte de service, le compte leurre ni les serveurs et comptes protégés du site.</p>')
        return self._send(200, page("Proposer une réponse", corps))

    def _verifier_jeton(self, rid, tok):
        d = dem_lire(rid)
        if not d or not tok or not hmac.compare_digest(d.get("jeton_sha256", ""), _h(tok)):
            return None, "jeton invalide"
        if d.get("utilise"):
            return None, "jeton déjà utilisé (usage unique)"
        if time.time() > d.get("expire", 0):
            return None, "jeton expiré (15 min)"
        return d, ""

    def _valideur_ok(self, who):
        if not who:
            return False, "non connecté"
        if who[0] not in soc_admins() or who[1] != "administrateur":
            return False, "validation réservée aux comptes SOC_ADMINS"
        return True, ""

    def _get_confirmer(self):
        who = self._ident()
        if not who:
            return self._non_connecte()
        ok, why = self._valideur_ok(who)
        q = self._q()
        if not ok:
            audit("refus_valideur", _ctx(q.get("id", "")[:16], who[0]), {"raison": why})
            return self._send(403, page("Validation refusée", f'<p class="err">{E(why)}.</p>'))
        d, why = self._verifier_jeton(q.get("id", ""), q.get("t", ""))
        if not d:
            audit("jeton_invalide", _ctx(q.get("id", "")[:16], who[0]), {"raison": why})
            return self._send(403, page("Lien invalide", f'<p class="err">{E(why)}.</p>'))
        a = ACTIONS[d["action"]]
        gf_ok, gf = garde_fou(d["action"], d["cible"])
        sep_ko = SEPARATION and who[0] == d["demandeur"]
        reste = int(d["expire"] - time.time())
        lignes = [("Action", a["libelle"]), ("Cible", d["cible"]), ("Demandeur", d["demandeur"]),
                  ("Demandé le", d["cree_le"]), ("Alerte d'origine", d.get("alerte") or "-"), ("Motif", d["motif"]),
                  ("Contexte SIEM", d.get("contexte", "-")), ("Réversible", a["reversible"]),
                  ("Jeton", f"usage unique, expire dans {reste // 60} min {reste % 60:02d} s")]
        tab = "".join(f'<tr><td class="l">{E(k)}</td><td>{E(v)}</td></tr>' for k, v in lignes)
        aurait = a["aurait_fait"].format(cible=d["cible"])
        if not gf_ok:
            bloc = f'<p class="err">Garde-fou : {E(gf)}. Validation impossible.</p>'
        elif sep_ko:
            bloc = '<p class="err">Le valideur doit être différent du demandeur (REPONSE_SEPARATION=1).</p>'
        else:
            bloc = (f'<form method="post" action="{PREFIXE}/confirmer">'
                    f'<input type="hidden" name="id" value="{E(d["id"])}"><input type="hidden" name="t" value="{E(q.get("t", ""))}">'
                    f'<input type="hidden" name="csrf" value="{E(self._csrf("confirmer|" + d["id"]))}">'
                    f'<button class="b1" name="decision" value="valider" type="submit">Valider (simulation)</button>'
                    f'<button class="b2" name="decision" value="refuser" type="submit">Refuser</button></form>')
        corps = (f'<p>Valideur : <b>{E(who[0])}</b></p><table>{tab}</table>'
                 f'<p style="margin-top:14px"><b>Ce qui serait fait en mode réel :</b><br>{E(aurait)}</p>{bloc}')
        return self._send(200, page("Confirmer une réponse", corps))

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        p = urllib.parse.urlsplit(self.path).path
        if not self._ip_ok():
            return self._send(403, page("Accès refusé", '<p class="err">Réseau source non autorisé.</p>'))
        if not self._origin_ok():
            return self._send(403, page("Origine refusée", '<p class="err">En-tête Origin/Referer absent ou étranger.</p>'))
        f = self._form()
        if f is None:
            return self._send(413, page("Requête trop grande", ""))
        if p == PREFIXE + "/demande":
            return self._post_demande(f)
        if p == PREFIXE + "/confirmer":
            return self._post_confirmer(f)
        return self._send(404, page("Page inconnue", ""))

    def _post_demande(self, f):
        who = self._ident()
        if not who:
            return self._non_connecte()
        if not hmac.compare_digest(f.get("csrf", ""), self._csrf("demande")):
            return self._send(403, page("Jeton de formulaire invalide", '<p class="err">Rechargez la page de demande.</p>'))
        now = time.time()
        with _LOCK:
            h = [t for t in _RATE.get(who[0], []) if now - t < 300]
            if len(h) >= DEMANDES_MAX_5MIN:
                return self._send(429, page("Trop de demandes", f'<p class="err">Maximum {DEMANDES_MAX_5MIN} demandes / 5 min.</p>'))
            h.append(now); _RATE[who[0]] = h
        action = f.get("action", "")
        motif = " ".join(f.get("motif", "").split())[:300]
        alerte = " ".join(f.get("alerte", "").split())[:200]
        base = {"id": "", "action": action, "cible": f.get("cible", "")[:120], "demandeur": who[0], "alerte": alerte, "motif": motif}
        if action not in ACTIONS:
            return self._send(400, page("Action inconnue", ""))
        if len(motif) < 4:
            return self._send(400, page("Motif obligatoire", '<p class="err">Motif de 4 caractères au moins.</p>'))
        ok, res = garde_fou(action, base["cible"])
        if not ok:
            audit("rejet_garde_fou", base, {"garde_fou": res})
            return self._send(403, page("Demande refusée par un garde-fou",
                f'<p class="err"><b>{E(base["cible"])}</b> : {E(res)}.</p><p>Rien n\'a été créé ; le refus est journalisé.</p>'))
        tok = secrets.token_urlsafe(32)
        d = dict(base, id=secrets.token_hex(8), cible=res, jeton_sha256=_h(tok), cree_le=time.strftime("%d/%m/%Y %H:%M:%S"),
                 cree_ts=now, expire=now + TTL, utilise=False, mode=MODE, contexte=contexte_siem(action, res))
        dem_ecrire(d)
        audit("demande", d, {"expire_le": time.strftime("%H:%M:%S", time.localtime(d["expire"]))})
        lien = f'{BASE_URL}{PREFIXE}/confirmer?id={d["id"]}&t={tok}'
        corps = (f'<p class="ok">Demande <b>{E(d["id"])}</b> créée : {E(ACTIONS[action]["libelle"])} sur <b>{E(res)}</b>.</p>'
                 f'<p>Lien de confirmation à transmettre à un valideur SOC_ADMINS (usage unique, expire à '
                 f'<b>{time.strftime("%H:%M", time.localtime(d["expire"]))}</b>) :</p><p><code>{E(lien)}</code></p>'
                 f'<p style="font-size:12px;color:#868e96">Le lien n\'est affiché qu\'une fois ; seule son empreinte est conservée.</p>')
        return self._send(201, page("Demande enregistrée", corps))

    def _post_confirmer(self, f):
        who = self._ident()
        if not who:
            return self._non_connecte()
        ok, why = self._valideur_ok(who)
        rid = f.get("id", "")[:16]
        if not ok:
            audit("refus_valideur", _ctx(rid, who[0]), {"raison": why})
            return self._send(403, page("Validation refusée", f'<p class="err">{E(why)}.</p>'))
        if not hmac.compare_digest(f.get("csrf", ""), self._csrf("confirmer|" + rid)):
            return self._send(403, page("Jeton de formulaire invalide", '<p class="err">Rouvrez le lien de confirmation.</p>'))
        with _LOCK:   # usage unique : vérification + consommation atomiques
            d, why = self._verifier_jeton(rid, f.get("t", ""))
            if d:
                d["utilise"] = True; d["utilise_le"] = time.strftime("%d/%m/%Y %H:%M:%S"); d["valideur"] = who[0]
                dem_ecrire(d)
        if not d:
            audit("jeton_invalide", _ctx(rid, who[0]), {"raison": why})
            return self._send(403, page("Lien invalide", f'<p class="err">{E(why)}.</p>'))
        if f.get("decision") == "refuser":
            audit("refus_valideur", d, {"raison": "refus explicite du valideur"})
            return self._send(200, page("Demande refusée", '<p class="ok">Refus enregistré. Aucune action.</p>'))
        if SEPARATION and who[0] == d["demandeur"]:
            audit("refus_valideur", d, {"raison": "valideur = demandeur"})
            return self._send(403, page("Validation refusée", '<p class="err">Valideur identique au demandeur.</p>'))
        gf_ok, gf = garde_fou(d["action"], d["cible"])
        if not gf_ok:
            audit("rejet_garde_fou", d, {"garde_fou": gf, "au_moment": "validation"})
            return self._send(403, page("Refus garde-fou", f'<p class="err">{E(gf)}.</p>'))
        aurait = ACTIONS[d["action"]]["aurait_fait"].format(cible=d["cible"])
        audit("validation_simulee", d, {"aurait_fait": aurait, "execute": "non"})
        corps = (f'<p class="ok"><b>Simulation enregistrée</b> : rien n\'a été exécuté.</p>'
                 f'<p><b>Ce qui aurait été fait :</b><br>{E(aurait)}</p>'
                 f'<p>Trace Graylog : <code>event_source:reponse AND reponse_id:{E(d["id"])}</code></p>')
        return self._send(200, page("Validation enregistrée (simulation)", corps))


def main():
    if not soc_admins():
        sys.stderr.write("avertissement : liste SOC_ADMINS vide, aucune validation possible\n")
    srv = ThreadingHTTPServer((BIND, PORT), H)
    srv.daemon_threads = True
    sys.stdout.write(f"omni-v5-reponse {VERSION} mode={MODE} écoute {BIND}:{PORT} validateurs={len(soc_admins())}\n")
    sys.stdout.flush()
    srv.serve_forever()

if __name__ == "__main__":
    main()
