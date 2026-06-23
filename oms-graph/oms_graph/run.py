"""OMS-GRAPH — CLI (jumeau d'attaque / analyse d'exposition, DEFENSIF).

  python -m oms_graph.run analyze [--window 14d] [--push] [--top N]

Sans --push : calcule et AFFICHE seulement + écrit l'artefact JSON (lu par la console).
Avec --push : réinjecte en plus les chemins courts en GELF (event_source=attack_path).
Lecture passive d'OpenSearch ; n'exécute AUCUNE action sur le SI.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from pathlib import Path

import yaml

from . import graph, opensearch, response
from .gelf import Gelf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("oms-graph")


def load_cfg(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _existing_decoys(path: str) -> set[str]:
    keys: set[str] = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if row and row[0] and row[0] != "key" and not row[0].startswith("#"):
                    keys.add(row[0].strip().lower())
    except OSError:
        pass
    return keys


def _load_artifact(cfg: dict) -> dict:
    try:
        return json.loads(Path(cfg["output"]["artifact"]).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def cmd_analyze(cfg: dict, args) -> int:
    os_cfg = cfg["opensearch"]
    window = args.window or cfg.get("window", "14d")
    if args.top:
        cfg["output"]["top"] = args.top

    log.info("Extraction des arêtes (fenêtre %s)…", window)
    pats = cfg.get("system_account_patterns", [])
    sessions = opensearch.has_session_edges(
        os_cfg["url"], os_cfg["index"], window,
        cfg["graph"]["session_logon_types"], cfg["system_accounts"], pats)
    admins = opensearch.admin_to_edges(
        os_cfg["url"], os_cfg["index"], window, cfg["system_accounts"], pats)
    if not sessions and not admins:
        log.error("Aucune arête extraite (OpenSearch injoignable ?). Abandon.")
        return 2

    g = graph.build(sessions, admins, cfg)
    analysis = graph.analyze(g)
    existing = _existing_decoys(cfg["output"]["decoy_registry"])
    recos = graph.recommend_decoys(g, analysis, existing)
    analysis["decoy_recommendations"] = recos
    analysis["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    analysis["window"] = window

    _print(analysis)

    # Artefact JSON pour la console SOC (best-effort).
    art = cfg["output"]["artifact"]
    try:
        os.makedirs(os.path.dirname(art), exist_ok=True)
        Path(art).write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
        log.info("Artefact écrit : %s", art)
    except OSError as exc:
        log.warning("Artefact non écrit (%s) : %s", art, exc)

    if args.push:
        gelf = Gelf(cfg["gelf"])
        thr = int(cfg["output"]["push_threshold_hops"])
        n = sum(1 for p in analysis["attack_paths"] if gelf.push_path(p, thr))
        log.info("%d chemin(s) réinjecté(s) en GELF (event_source=attack_path).", n)
    return 0


def _print(a: dict) -> None:
    s = a["stats"]
    print(f"\n=== Jumeau d'attaque OMNITECH (fenêtre {a['window']}) ===")
    print(f"  {s['hosts']} hôtes · {s['accounts']} comptes · {s['jewels']} joyaux · "
          f"{s['footholds']} pieds-à-terre · {s['ubiquitous_admin_accounts']} comptes admin ubiquitaires")

    print("\n-- Exposition des joyaux (pied-à-terre -> joyau) --")
    for je in a["jewel_exposure"]:
        print(f"  ⚑ {je['label'][:42]:<42} ≤{je['min_hops']} saut(s), "
              f"depuis {je['reachable_from']} pied(s)-à-terre (ex {je['nearest_foothold']})")
    if not a["jewel_exposure"]:
        print("  (aucun joyau atteignable depuis un pied-à-terre — bonne nouvelle)")

    print("\n-- Chokepoints (où durcir / poser un leurre en priorité) --")
    for cp in a["chokepoints"]:
        print(f"  {cp['on_paths']:>3} chemins · {cp['kind']:<7} {cp['klass']:<11} {cp['entity'][:34]}")

    print("\n-- Rayon de souffle (si compromis, hôtes atteignables) --")
    for b in a["blast_radius"]:
        jw = f" -> joyaux: {', '.join(b['jewels_reached'])}" if b["jewels_reached"] else ""
        print(f"  {b['hosts_reached']:>3} hôtes · {b['kind']:<7} {b['klass']:<11} {b['entity'][:30]}{jw[:60]}")

    if a["single_points_of_failure"]:
        print("\n-- Points uniques catastrophiques (comptes de gestion admin partout) --")
        for sp in a["single_points_of_failure"]:
            print(f"  {sp['admin_on_hosts']:>3} hôtes admin · {sp['account']}  (RMM/sync : PAM + tiering)")

    if a.get("decoy_recommendations"):
        print("\n-- Placement de leurres recommandé (pré-positionnement) --")
        for r in a["decoy_recommendations"]:
            cov = "déjà couvert" if r["already_covered"] else "À POSER"
            loc = r.get("place_on_host") or r.get("near_jewel")
            print(f"  [{cov}] {r['type']} '{r['suggested_key']}' @ {loc}")


def _ctx_index(art: dict) -> dict:
    """Indexe le contexte du jumeau par entité : rayon de souffle + chokepoint."""
    idx: dict[str, dict] = {}
    for b in art.get("blast_radius", []):
        idx[b["entity"]] = {"hosts_reached": b.get("hosts_reached", 0),
                            "jewels_reached": b.get("jewels_reached", []),
                            "kind": b.get("kind", "host"), "is_chokepoint": False}
    chk = {c["entity"] for c in art.get("chokepoints", [])}
    for e in chk:
        idx.setdefault(e, {"hosts_reached": 0, "jewels_reached": [], "is_chokepoint": False})
        idx[e]["is_chokepoint"] = True
    return idx


def cmd_respond(cfg: dict, args) -> int:
    art = _load_artifact(cfg)
    if not art or art.get("error"):
        log.error("Artefact du jumeau absent — lancer 'analyze' d'abord.")
        return 2
    ctx = _ctx_index(art)
    resp = response.SentinelResponder(cfg)
    gelf = Gelf(cfg["gelf"]) if args.push else None

    # Déclencheurs : --simulate ENTITY (tabletop) ou les leurres réellement déclenchés.
    if args.simulate:
        # host vs compte : on lit le 'kind' du jumeau (sinon $ = compte machine).
        is_host = ctx.get(args.simulate, {}).get("kind", "host") == "host" \
            and not args.simulate.endswith("$")
        triggers = [{"tag": "simulation",
                     "source_host": args.simulate if is_host else None,
                     "source_ip": None,
                     "account": None if is_host else args.simulate,
                     "decoy": "(simulation)"}]
        log.info("SIMULATION : compromission hypothétique de %s (%s)",
                 args.simulate, "hôte" if is_host else "compte")
    else:
        rc = cfg["response"]
        triggers = opensearch.recent_triggers(cfg["opensearch"]["url"], cfg["opensearch"]["index"],
                                              rc["triggers"], rc.get("trigger_window", "24h"))
        if not triggers:
            print("\n=== Réponse Sentinel : aucun leurre déclenché sur la fenêtre. "
                  "Le piège est armé et silencieux (rien à contenir). ===")
            print("    Tabletop : oms-graph respond --simulate <hôte|compte> --config <cfg>")
            return 0

    armed = (not resp.dry) and resp.armed_env
    if not args.json:
        print(f"\n=== Réponse graduée Sentinel ({'SIMULATION' if args.simulate else 'leurres réels'}) ===")
        print(f"    Mode : {'ARMÉ (infra OMNITECH)' if armed else 'DRY-RUN (recommandation)'} · "
              f"approbation={'OUI' if args.execute else 'non'}")
    plans = []
    for t in triggers:
        host = t.get("source_host")
        entity = host or t.get("account") or t.get("decoy") or "?"
        context = ctx.get(entity) or ctx.get(host) or ctx.get(t.get("account")) or \
                  {"hosts_reached": 0, "jewels_reached": [], "is_chokepoint": False}
        g = response.grade(context, is_decoy=t["tag"] != "simulation")
        plan = response.build_plan(entity, host, t.get("source_ip"), t.get("account"), g, context)
        out = resp.execute(plan, approve=args.execute)
        out["mode"] = "armed" if armed else "dry_run"
        out["trigger"] = t.get("tag")
        plans.append(out)
        if not args.json:
            _print_plan(t, out)
        if gelf:
            gelf.push_response(out)
    if args.json:
        print(json.dumps(plans, ensure_ascii=False))
    return 0


def _print_plan(trig: dict, out: dict) -> None:
    gcol = {"critique": "⛔", "eleve": "⚠️", "modere": "•"}.get(out["grade"], "•")
    jr = out.get("jewels_at_risk") or []
    print(f"\n  {gcol} [{out['grade'].upper()}] déclencheur={trig.get('tag')} "
          f"entité={out['entity']} · atteint {out.get('hosts_reachable',0)} hôtes"
          + (f" · joyaux: {', '.join(jr)}" if jr else ""))
    for r in out.get("results", []):
        print(f"      - {r['status']:<22} {r['action']:<18} → {r.get('target','')}")
        print(f"        {r['text']}")


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="/etc/oms-graph/config.yaml")
    ap = argparse.ArgumentParser(prog="oms-graph", parents=[common])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", parents=[common], help="analyse d'exposition (jumeau d'attaque)")
    a.add_argument("--window", default=None)
    a.add_argument("--top", type=int, default=None)
    a.add_argument("--push", action="store_true", help="réinjecter les chemins courts en GELF")

    r = sub.add_parser("respond", parents=[common],
                       help="Pilier 3 : réponse graduée (leurres + contexte jumeau)")
    r.add_argument("--simulate", default=None, metavar="ENTITE",
                   help="tabletop : compromission hypothétique d'un hôte/compte")
    r.add_argument("--execute", action="store_true",
                   help="approuver l'exécution (n'agit que si ARMÉ : config + OMNI_SENTINEL_ARM=1)")
    r.add_argument("--push", action="store_true", help="auditer les plans en GELF (sentinel_response)")
    r.add_argument("--json", action="store_true", help="sortie JSON (consommée par la console)")

    args = ap.parse_args(argv)
    cfg_path = args.config if Path(args.config).exists() else str(
        Path(__file__).resolve().parent.parent / "config.yaml")
    cfg = load_cfg(cfg_path)
    if args.cmd == "analyze":
        return cmd_analyze(cfg, args)
    if args.cmd == "respond":
        return cmd_respond(cfg, args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
