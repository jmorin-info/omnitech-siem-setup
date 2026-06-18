#!/usr/bin/env bash
# =============================================================================
# 57-mitre-coverage.sh - Carte de couverture MITRE ATT&CK du SIEM OMNITECH.
#   Lit lookups/mitre-attack.csv (tag -> technique/tactique/score) et genere :
#     - docs/mitre-navigator-layer.json : calque a charger dans MITRE ATT&CK
#       Navigator (https://mitre-attack.github.io/attack-navigator/) pour
#       VISUALISER la couverture (techniques colorees par score max).
#     - un resume console (tactiques couvertes, nb techniques, trous).
#   Idempotent, lecture seule cote SIEM (ne touche pas Graylog). A relancer
#   apres chaque ajout de detection (nouvelle ligne dans mitre-attack.csv).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
CSV="lookups/mitre-attack.csv"
OUT="docs/mitre-navigator-layer.json"
[[ -f "$CSV" ]] || { echo "CSV introuvable: $CSV" >&2; exit 1; }
mkdir -p docs

python3 - "$CSV" "$OUT" <<'PY'
import csv, json, sys, collections
csv_path, out_path = sys.argv[1], sys.argv[2]
# 14 tactiques ATT&CK Enterprise (ordre kill-chain) -> pour le rapport de trous
TACTICS = ["Reconnaissance","Resource Development","Initial Access","Execution",
           "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
           "Discovery","Lateral Movement","Collection","Command and Control",
           "Exfiltration","Impact"]
by_tech = collections.OrderedDict()   # techID -> {score, tags[], tactic, name}
by_tactic = collections.defaultdict(set)
with open(csv_path) as f:
    for row in csv.DictReader(f):
        tech = (row.get("technique") or "").strip()
        if not tech.startswith("T"):
            continue
        try: score = int(row.get("score") or 0)
        except ValueError: score = 0
        tag = (row.get("alert_tag") or "").strip()
        tactic = (row.get("tactic") or "").strip()
        name = (row.get("technique_name") or "").strip()
        by_tactic[tactic].add(tech)
        e = by_tech.setdefault(tech, {"score": 0, "tags": [], "tactic": tactic, "name": name})
        e["score"] = max(e["score"], score)
        if tag: e["tags"].append(tag)
# Calque Navigator v4.5
techniques = []
for tech, e in by_tech.items():
    techniques.append({
        "techniqueID": tech, "score": e["score"], "enabled": True,
        "comment": "%s : %s (score %d)" % (e["name"], ", ".join(e["tags"]), e["score"]),
        "metadata": [{"name": "detections", "value": ", ".join(e["tags"])}],
    })
layer = {
    "name": "OMNITECH SIEM - Couverture detection",
    "description": "Techniques couvertes par les detections OMNITECH (genere par 57-mitre-coverage.sh). Couleur = score de risque max.",
    "domain": "enterprise-attack",
    "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
    "techniques": techniques,
    "gradient": {"colors": ["#ffe8a1", "#ff8c42", "#c1121f"], "minValue": 0, "maxValue": 10},
    "legendItems": [{"label": "score 1-4 faible", "color": "#ffe8a1"},
                    {"label": "score 5-7 eleve", "color": "#ff8c42"},
                    {"label": "score 8-10 critique", "color": "#c1121f"}],
    "showTacticRowBackground": True, "tacticRowBackground": "#205081",
    "sorting": 3, "hideDisabled": False,
}
with open(out_path, "w") as f:
    json.dump(layer, f, indent=2, ensure_ascii=False)

print("=== Couverture MITRE ATT&CK OMNITECH ===")
print("Detections totales      :", sum(len(v["tags"]) for v in by_tech.values()))
print("Techniques distinctes   :", len(by_tech))
covered = [t for t in TACTICS if by_tactic.get(t)]
gaps = [t for t in TACTICS if not by_tactic.get(t)]
print("Tactiques couvertes %d/14 :" % len(covered))
for t in TACTICS:
    n = len(by_tactic.get(t, []))
    flag = "  <-- TROU" if n == 0 else ""
    print("   %-22s %2d technique(s)%s" % (t, n, flag))
print("Calque Navigator ecrit  :", out_path)
PY
echo
echo "=== 57 termine. Charger docs/mitre-navigator-layer.json dans"
echo "    https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer). ==="
