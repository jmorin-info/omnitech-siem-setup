"""Jumeau d'attaque — graphe de propagation de compromission (DEFENSIF).

Modèle (orienté « ce qu'un attaquant gagne ») :
  - HasSession(compte A, hôte H)  ->  arête  H -> A   (contrôler H = moissonner les
    identifiants de A cachés sur H).
  - AdminTo(compte A, hôte H)     ->  arête  A -> H   (contrôler A = contrôler H).

Un CHEMIN D'EXPOSITION = pied-à-terre (poste) -> ... -> JOYAU. Sert à PRIORISER le
durcissement (chokepoints) et le PLACEMENT DES LEURRES, pas à attaquer.

Anti-bruit (sinon tout se relie à tout) : comptes machine ($) et système exclus en
amont ; comptes de GESTION ubiquitaires (RMM/sync admin de > N hôtes) sortis des
chemins latéraux et rapportés à part comme points uniques catastrophiques.
"""
from __future__ import annotations

from collections import deque
from typing import Any

H = "H:"   # préfixe nœud hôte
A = "A:"   # préfixe nœud compte


def _low(s: str) -> str:
    return (s or "").strip().lower()


def classify(name: str, cfg: dict) -> str:
    n = _low(name)
    cl = cfg["classes"]
    for c in ("privileged", "management"):
        spec = cl.get(c, {})
        if n in [_low(x) for x in spec.get("exact", [])]:
            return c
        if any(n.startswith(_low(p)) for p in spec.get("prefixes", [])):
            return c
    return "user"


def _match_jewel(host: str, cfg: dict) -> str | None:
    n = _low(host)
    for j in cfg["crown_jewels"]:
        if _low(j["match"]) in n:
            return j["label"]
    return None


def _is_foothold(host: str, cfg: dict) -> bool:
    n = _low(host)
    return any(_low(f) in n for f in cfg["footholds"])


class Graph:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.adj: dict[str, set[str]] = {}          # graphe de compromission (latéral)
        self.hosts: set[str] = set()
        self.accounts: set[str] = set()
        self.acct_class: dict[str, str] = {}
        self.admin_hosts: dict[str, set[str]] = {}  # compte -> hôtes administrés
        self.session_hosts: dict[str, set[str]] = {}  # compte -> hôtes avec session
        self.ubiquitous: dict[str, int] = {}        # comptes de gestion ubiquitaires
        self.jewels: dict[str, str] = {}            # nœud hôte -> label joyau
        self.footholds: set[str] = set()

    def _edge(self, u: str, v: str) -> None:
        self.adj.setdefault(u, set()).add(v)
        self.adj.setdefault(v, set())

    def _host(self, name: str) -> str:
        node = H + name
        if node not in self.hosts:
            self.hosts.add(node)
            self.adj.setdefault(node, set())
            lbl = _match_jewel(name, self.cfg)
            if lbl:
                self.jewels[node] = lbl
            if _is_foothold(name, self.cfg):
                self.footholds.add(node)
        return node

    def _acct(self, name: str) -> str:
        node = A + name
        if node not in self.accounts:
            self.accounts.add(node)
            self.adj.setdefault(node, set())
            self.acct_class[node] = classify(name, self.cfg)
        return node


def build(sessions: list[tuple[str, str, int]],
          admins: list[tuple[str, str, int]], cfg: dict) -> Graph:
    g = Graph(cfg)
    # Inventaire des relations brutes (avant filtre ubiquité).
    for acct, host, _w in sessions:
        an, hn = g._acct(acct), g._host(host)
        g.session_hosts.setdefault(an, set()).add(hn)
    for acct, host, _w in admins:
        an, hn = g._acct(acct), g._host(host)
        g.admin_hosts.setdefault(an, set()).add(hn)

    # Détection des comptes de GESTION ubiquitaires (admin de trop d'hôtes) : on les
    # sort des chemins latéraux (sinon hub reliant tout), on les rapporte à part.
    thr = int(cfg["graph"]["ubiquitous_admin_hosts"])
    for an, hs in g.admin_hosts.items():
        if g.acct_class.get(an) == "management" and len(hs) > thr:
            g.ubiquitous[an] = len(hs)

    # Construction du graphe de compromission (hors arêtes admin des ubiquitaires).
    for an, hs in g.session_hosts.items():
        for hn in hs:
            g._edge(hn, an)          # contrôler l'hôte -> moissonner le compte
    for an, hs in g.admin_hosts.items():
        if an in g.ubiquitous:
            continue
        for hn in hs:
            g._edge(an, hn)          # contrôler le compte -> contrôler l'hôte
    return g


def bfs(g: Graph, start: str, max_hops: int) -> dict[str, int]:
    """Distance (en sauts) de `start` vers chaque nœud atteignable."""
    dist = {start: 0}
    q = deque([start])
    while q:
        u = q.popleft()
        if dist[u] >= max_hops:
            continue
        for v in g.adj.get(u, ()):  # noqa: B007
            if v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def _bfs_path(g: Graph, start: str, goal: str, max_hops: int) -> list[str] | None:
    """Un plus court chemin start->goal (BFS), borné à max_hops sauts."""
    parent: dict[str, str | None] = {start: None}
    depth = {start: 0}
    q = deque([start])
    while q:
        u = q.popleft()
        if u == goal:
            path: list[str] = []
            cur: str | None = u
            while cur is not None:
                path.append(cur)
                cur = parent[cur]
            return list(reversed(path))
        if depth[u] >= max_hops:
            continue
        for v in g.adj.get(u, ()):
            if v not in parent:
                parent[v] = u
                depth[v] = depth[u] + 1
                q.append(v)
    return None


def analyze(g: Graph) -> dict[str, Any]:
    cfg = g.cfg
    max_hops = int(cfg["graph"]["max_path_hops"])
    topn = int(cfg["output"]["top"])

    # 1) Exposition des joyaux : pieds-à-terre pouvant l'atteindre + saut minimal.
    jewel_exposure: list[dict] = []
    choke: dict[str, int] = {}
    paths_found: list[dict] = []
    for jnode, label in g.jewels.items():
        reachers = []
        for f in g.footholds:
            d = bfs(g, f, max_hops)
            if jnode in d:
                reachers.append((f, d[jnode]))
        if reachers:
            reachers.sort(key=lambda x: x[1])
            jewel_exposure.append({
                "jewel": jnode[len(H):], "label": label,
                "reachable_from": len(reachers),
                "min_hops": reachers[0][1],
                "nearest_foothold": reachers[0][0][len(H):],
            })
            # Chokepoints : nœuds intermédiaires d'un plus court chemin par (foothold,joyau).
            for f, _hop in reachers[:topn]:
                p = _bfs_path(g, f, jnode, max_hops)
                if p and len(p) > 2:
                    for mid in p[1:-1]:
                        choke[mid] = choke.get(mid, 0) + 1
                    if len(paths_found) < topn:
                        paths_found.append({
                            "from": f[len(H):], "to": jnode[len(H):], "label": label,
                            "hops": len(p) - 1,
                            "path": [n[len(H):] if n.startswith(H) else n[len(A):] for n in p],
                            "path_kinds": ["host" if n.startswith(H) else "account" for n in p],
                        })
    jewel_exposure.sort(key=lambda d: (d["min_hops"], -d["reachable_from"]))

    # 2) Blast radius : si X compromis, combien d'hôtes deviennent atteignables.
    blast: list[dict] = []
    for node in list(g.accounts) + list(g.hosts):
        d = bfs(g, node, max_hops)
        reached_hosts = [n for n in d if n.startswith(H) and n != node]
        reached_jewels = [g.jewels[n] for n in d if n in g.jewels and n != node]
        if reached_hosts:
            blast.append({
                "entity": node[len(H):] if node.startswith(H) else node[len(A):],
                "kind": "host" if node.startswith(H) else "account",
                "klass": g.acct_class.get(node, "host"),
                "hosts_reached": len(reached_hosts),
                "jewels_reached": sorted(set(reached_jewels)),
            })
    blast.sort(key=lambda d: (len(d["jewels_reached"]), d["hosts_reached"]), reverse=True)

    # 3) Chokepoints classés.
    chokepoints = [{
        "entity": n[len(H):] if n.startswith(H) else n[len(A):],
        "kind": "host" if n.startswith(H) else "account",
        "klass": g.acct_class.get(n, "host"),
        "on_paths": c,
    } for n, c in sorted(choke.items(), key=lambda kv: kv[1], reverse=True)]

    # 4) Points uniques catastrophiques (comptes de gestion ubiquitaires).
    spof = [{"account": a[len(A):], "admin_on_hosts": n}
            for a, n in sorted(g.ubiquitous.items(), key=lambda kv: kv[1], reverse=True)]

    return {
        "jewel_exposure": jewel_exposure,
        "blast_radius": blast[:topn],
        "chokepoints": chokepoints[:topn],
        "single_points_of_failure": spof,
        "attack_paths": paths_found,
        "stats": {
            "hosts": len(g.hosts), "accounts": len(g.accounts),
            "jewels": len(g.jewels), "footholds": len(g.footholds),
            "ubiquitous_admin_accounts": len(g.ubiquitous),
        },
    }


def recommend_decoys(g: Graph, analysis: dict, existing_keys: set[str]) -> list[dict]:
    """Suggère où poser un leurre pour intercepter le plus de chemins : sur les
    chokepoints HÔTES et près des joyaux les plus exposés, s'ils ne sont pas déjà
    couverts par un leurre (registre omni-deception)."""
    recs: list[dict] = []
    seen: set[str] = set()
    # a) Chokepoints hôtes : poser un compte-leurre dont les creds seront moissonnés là.
    for cp in analysis["chokepoints"]:
        if cp["kind"] != "host" or cp["entity"] in seen:
            continue
        seen.add(cp["entity"])
        name = f"svc-{cp['entity'].split('-')[-1]}-bkp".lower()
        recs.append({
            "type": "decoy_identity",
            "place_on_host": cp["entity"],
            "suggested_key": name,
            "rationale": f"Chokepoint sur {cp['on_paths']} chemin(s) vers un joyau : "
                         f"un compte-leurre dont la session est exposée ici piège "
                         f"l'attaquant qui moissonne les identifiants.",
            "already_covered": name in existing_keys,
        })
    # b) Joyaux atteignables en <=2 sauts sans hôte-leurre adjacent : poser un hôte-leurre.
    for je in analysis["jewel_exposure"]:
        if je["min_hops"] > 2:
            continue
        decoy_host = f"{je['jewel']}-dr".lower()
        key = decoy_host + "$"
        if key in seen:
            continue
        seen.add(key)
        recs.append({
            "type": "decoy_host",
            "near_jewel": je["jewel"],
            "suggested_key": key,
            "rationale": f"Joyau « {je['label']} » atteignable en {je['min_hops']} saut(s) "
                         f"depuis {je['reachable_from']} pied(s)-à-terre : un hôte-leurre "
                         f"adjacent capte la reconnaissance latérale avant le joyau réel.",
            "already_covered": key in existing_keys,
        })
    return recs
