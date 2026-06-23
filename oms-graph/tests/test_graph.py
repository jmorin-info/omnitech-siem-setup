"""Tests de la logique du jumeau d'attaque (données synthétiques, pas d'OpenSearch)."""
from oms_graph import graph

CFG = {
    "graph": {"session_logon_types": ["2"], "ubiquitous_admin_hosts": 3, "max_path_hops": 6},
    "system_accounts": ["SYSTEM"],
    "classes": {
        "privileged": {"prefixes": ["adm-"], "exact": ["administrateur"]},
        "management": {"prefixes": ["svc_"], "exact": ["ninjaone"]},
    },
    "crown_jewels": [{"match": "bx-ad-01", "label": "DC1"}],
    "footholds": ["bx-dev-"],
    "output": {"top": 12, "decoy_registry": "/nonexistent.csv",
               "artifact": "/tmp/x.json", "push_threshold_hops": 3},
}


def test_classify():
    assert graph.classify("adm-jmorin", CFG) == "privileged"
    assert graph.classify("ninjaone", CFG) == "management"
    assert graph.classify("jmorin", CFG) == "user"


def test_path_foothold_to_jewel():
    # bob a une session sur le poste dev ; bob est admin de DC1 -> chemin en 2 sauts.
    sessions = [("bob", "bx-dev-pc1", 5)]
    admins = [("bob", "bx-ad-01-it-vm", 9)]
    g = graph.build(sessions, admins, CFG)
    a = graph.analyze(g)
    assert a["stats"]["jewels"] == 1
    assert a["stats"]["footholds"] == 1
    assert a["jewel_exposure"], "le joyau doit être atteignable depuis le foothold"
    je = a["jewel_exposure"][0]
    assert je["label"] == "DC1"
    assert je["min_hops"] == 2          # foothold -> bob -> DC1
    # bob est un chokepoint (sur le chemin).
    assert any(cp["entity"] == "bob" for cp in a["chokepoints"])


def test_ubiquitous_management_excluded_from_paths():
    # ninjaone (management) admin de 4 hôtes (> seuil 3) -> sorti des chemins latéraux.
    sessions = [("ninjaone", "bx-dev-pc1", 1)]
    admins = [("ninjaone", f"h{i}", 1) for i in range(4)] + [("ninjaone", "bx-ad-01-it-vm", 1)]
    g = graph.build(sessions, admins, CFG)
    a = graph.analyze(g)
    assert a["single_points_of_failure"], "ninjaone doit être un point unique catastrophique"
    assert a["single_points_of_failure"][0]["account"] == "ninjaone"
    # Comme ses arêtes admin sont exclues, le joyau n'est PAS atteignable via lui.
    assert a["jewel_exposure"] == []


def test_no_path_when_disconnected():
    sessions = [("alice", "bx-dev-pc1", 1)]
    admins = [("carol", "bx-ad-01-it-vm", 1)]   # carol ≠ alice : pas de pont
    g = graph.build(sessions, admins, CFG)
    a = graph.analyze(g)
    assert a["jewel_exposure"] == []


def test_decoy_reco_marks_existing():
    sessions = [("bob", "bx-dev-pc1", 5)]
    admins = [("bob", "bx-ad-01-it-vm", 9)]
    g = graph.build(sessions, admins, CFG)
    a = graph.analyze(g)
    recos = graph.recommend_decoys(g, a, existing_keys={"bx-ad-01-it-vm-dr$"})
    # le joyau atteignable en 2 sauts -> reco decoy_host près du joyau, marquée couverte
    host_recos = [r for r in recos if r["type"] == "decoy_host"]
    assert host_recos and host_recos[0]["already_covered"] is True
