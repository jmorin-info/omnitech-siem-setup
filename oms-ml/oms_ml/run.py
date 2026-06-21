"""OMS-ML — CLI.

  python -m oms_ml.run anomaly [--entity host|account|all] [--window 7d] [--push] [--top N]
  python -m oms_ml.run fp [--train] [--push]
  python -m oms_ml.run status            # état des labels FP

Sans --push : on calcule et on AFFICHE seulement (aucune écriture dans le SIEM).
Avec --push : réinjection GELF (event_source=ml_anomaly) — additif, non destructif.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import yaml

from . import anomaly, features, fpscore
from .gelf import Gelf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("oms-ml")


def load_cfg(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _segmented_score(names, matrix, ents, classes, min_entities, kw):
    """Anomalie par classe d'actif : un IsolationForest par classe (>= min_entities) ;
    classes trop petites regroupées en « autres ». Fusionne et retrie par score."""
    groups: dict = {}
    for i, c in enumerate(classes):
        c = c or "?"
        groups.setdefault(c, ([], []))
        groups[c][0].append(matrix[i])
        groups[c][1].append(ents[i])
    pool_m, pool_e, out = [], [], []
    for c, (m, e) in groups.items():
        if len(e) >= min_entities:
            for r in anomaly.train_score(names, m, e, **kw):
                r["cls"] = c
                out.append(r)
        else:
            pool_m += m
            pool_e += e
    if len(pool_e) >= min_entities:
        for r in anomaly.train_score(names, pool_m, pool_e, **kw):
            r["cls"] = "autres"
            out.append(r)
    elif pool_e:
        for ent in pool_e:
            out.append({"entity": ent, "ml_score": 0.0, "ml_reason": "classe trop petite",
                        "features": {}, "cls": "autres"})
    out.sort(key=lambda d: d["ml_score"], reverse=True)
    return out


def cmd_anomaly(cfg: dict, args) -> int:
    os_cfg, an = cfg["opensearch"], cfg["anomaly"]
    state = cfg.get("state_dir", "/var/lib/oms-ml")
    window = args.window or an.get("window", "7d")
    gelf = Gelf(cfg["gelf"]) if args.push else None

    wanted = list(an["entities"].keys()) if args.entity == "all" else [args.entity]
    me = an.get("min_entities", 12)
    rc = 0
    for etype in wanted:
        gb = an["entities"][etype]["group_by"]
        names, matrix, ents, classes = features.extract(os_cfg["url"], os_cfg["index"], gb, window)
        if len(ents) < me:
            log.warning("[%s] %d entités < min_entities=%s — modèle non fiable, on saute.",
                        etype, len(ents), me)
            continue
        kw = dict(contamination=an.get("contamination", "auto"), n_estimators=an.get("n_estimators", 200))
        # Segmentation par classe d'actif : compare un pare-feu à des pare-feux, un
        # serveur à des serveurs... évite qu'un gros émetteur (FortiGate) domine.
        if an["entities"][etype].get("segment") and len(set(classes)) > 1:
            res = _segmented_score(names, matrix, ents, classes, me, kw)
            log.info("[%s] anomalie segmentée par classe (%d classes)", etype, len(set(classes)))
        else:
            res = anomaly.train_score(names, matrix, ents, model_path=f"{state}/anomaly_{etype}.pkl", **kw)
        top = res[: args.top or an.get("top", 15)]
        thr = an.get("score_threshold", 70)
        print(f"\n=== Anomalies {etype} (window {window}, {len(ents)} entités) ===")
        for r in top:
            flag = "⚑" if r["ml_score"] >= thr else " "
            print(f" {flag} {r['ml_score']:5.1f}  {r['entity'][:34]:<34} {r['ml_reason']}")
            if gelf:
                gelf.push_anomaly(etype, r, thr)
        if gelf:
            pushed = sum(1 for r in top)
            log.info("[%s] %d scores réinjectés en GELF (event_source=ml_anomaly).", etype, pushed)
    return rc


def cmd_fp(cfg: dict, args) -> int:
    os_cfg, fp = cfg["opensearch"], cfg["fp_reduction"]
    state = cfg.get("state_dir", "/var/lib/oms-ml")
    if args.train:
        out = fpscore.train(os_cfg["url"], os_cfg["index"], fp["cases_file"],
                            fp.get("min_labels", 30), model_path=f"{state}/fp_model.pkl")
    else:
        out = {"trained": False, **fpscore.status(fp["cases_file"], fp.get("min_labels", 30))}
    if out.get("trained"):
        print(f"Modèle FP entraîné : n={out['n']} (VP={out['true_positive']} "
              f"FP={out['false_positive']}), AUC cv≈{out.get('auc_cv'):.2f}")
    else:
        print(f"FP supervisé EN ATTENTE de labels : {out['labeled']} cas qualifiés "
              f"(VP={out['true_positive']} FP={out['false_positive']}) ; "
              f"il en faut {out['min_labels']} des 2 classes (manque ~{out['missing']}).")
        print("→ Activer la disposition (vrai/faux positif) à la clôture des cas dans la console SOC.")
    return 0


def cmd_status(cfg: dict, args) -> int:
    return cmd_fp(cfg, argparse.Namespace(train=False))


def main(argv: list[str] | None = None) -> int:
    # --config accepte avant OU apres la sous-commande (parent parser partage).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="/etc/oms-ml/config.yaml")
    ap = argparse.ArgumentParser(prog="oms-ml", parents=[common])
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("anomaly", parents=[common], help="détection d'anomalie non-supervisée")
    a.add_argument("--entity", choices=["host", "account", "all"], default="all")
    a.add_argument("--window", default=None)
    a.add_argument("--top", type=int, default=None)
    a.add_argument("--push", action="store_true", help="réinjecter en GELF")

    f = sub.add_parser("fp", parents=[common], help="réduction de faux positifs supervisée")
    f.add_argument("--train", action="store_true")
    f.add_argument("--push", action="store_true")

    sub.add_parser("status", parents=[common], help="état des labels FP")

    args = ap.parse_args(argv)
    cfg_path = args.config if Path(args.config).exists() else str(
        Path(__file__).resolve().parent.parent / "config.yaml")
    cfg = load_cfg(cfg_path)

    if args.cmd == "anomaly":
        return cmd_anomaly(cfg, args)
    if args.cmd == "fp":
        return cmd_fp(cfg, args)
    if args.cmd == "status":
        return cmd_status(cfg, args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
