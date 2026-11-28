"""Détections portables pilotées par le site, threat intel sans clé, collecteur FortiGate désactivable."""
from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAT_DIR = ROOT / "objets-graylog" / "detections-site"


def _module(nom, chemin):
    loader = importlib.machinery.SourceFileLoader(nom, str(chemin))
    spec = importlib.util.spec_from_loader(nom, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def outil():
    return _module("omni_site_detections", ROOT / "tools" / "omni-site-detections.py")


@pytest.fixture(scope="module")
def cat():
    return json.loads((CAT_DIR / "catalogue.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def site():
    return json.loads((CAT_DIR / "site.exemple.json").read_text(encoding="utf-8"))


def test_catalogue_valide(outil, cat, site):
    assert outil.valider(cat, site) == []


def test_valider_refuse_un_champ_que_personne_ne_produit(outil, cat, site):
    c = copy.deepcopy(cat)
    d = next(x for x in c["detections"] if x["id"] == "ti-wg-tor-entrant")
    d["requete"] += " AND champ_fantome:1"
    assert any("champ_fantome" in e for e in outil.valider(c, site))


def test_valider_refuse_une_regle_qui_lit_un_champ_absent_de_la_source(outil, cat, site):
    c = copy.deepcopy(cat)
    d = next(x for x in c["detections"] if x["id"] == "wg-hote-bloque")
    d["condition"] += ' && to_string($message.winlogbeat_winlog_event_id) == "1"'
    assert any("ne produit pas" in e for e in outil.valider(c, site))


def test_valider_exige_le_prefixe_du_rodage(outil, cat, site):
    c = copy.deepcopy(cat)
    c["detections"][0]["titre"] = "OMNI - sans rodage"
    assert any("rodage" in e for e in outil.valider(c, site))


def test_gabarits(outil):
    p = {"comptes": ["DC1$", "Dc2$"], "reseaux_internes": ["198.51.100.0/24"], "vide": []}
    assert outil.rendre("{{dans:X:comptes}}", p) == '(X == "dc1$" || X == "dc2$")'
    assert outil.rendre("{{dans:X:vide}}", p) == "false"
    assert outil.rendre("{{contient:X:comptes}}", p).startswith('(contains(X, "dc1$")')
    interne = outil.rendre("{{interne:$message.src_ip}}", p)
    assert 'cidr_match("10.0.0.0/8", to_ip($message.src_ip))' in interne and "198.51.100.0/24" in interne
    assert outil.rendre("$ed.Status", p) == "$message.winlogbeat_winlog_event_data_Status"
    assert outil.rendre("{{premier:comptes}}", p) == "dc1$"


def test_aucune_valeur_de_site_dans_le_catalogue(cat):
    texte = json.dumps(cat, ensure_ascii=False).lower()
    for interdit in ("groupesfpi", "omnitech-security", "90.115.", "192.1.75.", "srv-dc"):
        assert interdit not in texte


def test_planificateur_seuil_fenetre_grace(outil):
    d = {"fenetre_min": 10, "pas_min": 5, "grace_min": 60, "seuil": 3}
    t0 = 1_700_000_000
    evts = [(t0 + i * 60, "a", i) for i in range(5)] + [(t0 + 7200, "a", 9), (t0 + 30, "b", 1)]
    notifs = outil.planificateur(evts, d)
    assert [e for _, e in notifs] == ["a"]  # b sous le seuil, second passage de a isolé (sous le seuil)
    d["seuil"] = 1
    notifs = outil.planificateur([(t0, "a", 1), (t0 + 600, "a", 2), (t0 + 4000, "a", 3)], d)
    assert len(notifs) == 2  # la grâce de 60 min absorbe le second événement


def test_planificateur_cardinalite(outil):
    d = {"fenetre_min": 30, "pas_min": 5, "grace_min": 60, "seuil": 3, "serie": {"type": "card", "champ": "u"}}
    t0 = 1_700_000_000
    assert outil.planificateur([(t0 + i, "ip", "meme") for i in range(10)], d) == []
    assert len(outil.planificateur([(t0 + i, "ip", f"u{i}") for i in range(3)], d)) == 1


def test_decision_plafond_et_preuve(outil, cat):
    d = next(x for x in cat["detections"] if x["id"] == "wg-hote-bloque")
    e = {"etat": "active", "streams": ["s"]}
    rj = {"jours": 30, "detections": {d["id"]: {"exemples_ok": True, "candidats": 50, "etiquetes": 50, "notifications": 40, "max_par_jour": 9}}}
    planif, raison, _ = outil.decision(cat, d, e, rj)
    assert not planif and "5" in raison
    rj["detections"][d["id"]]["max_par_jour"] = 2
    assert outil.decision(cat, d, e, rj)[0]
    assert not outil.decision(cat, d, e, None)[0]
    assert not outil.decision(cat, d, {"etat": "desactivee", "raison": "x"}, rj)[0]


def test_definition_desactivee_porte_sa_raison(outil, cat):
    d = next(x for x in cat["detections"] if x["id"] == "win-pulverisation")
    corps = outil.entite_definition(cat, d, {"streams": ["s1"]}, "n1", raison="source muette")
    assert "DÉSACTIVÉE : source muette" in corps["description"]
    assert corps["config"]["series"][0] == {"id": "card(winlogbeat_winlog_event_data_TargetUserName)", "type": "card",
                                            "field": "winlogbeat_winlog_event_data_TargetUserName"}
    assert corps["config"]["group_by"] == ["v5_entite"] and corps["priority"] == 2


def test_champs_ti_declares_dans_le_module_watchguard(cat):
    m = json.loads((ROOT / "integrations" / "watchguard" / "manifest.json").read_text(encoding="utf-8"))
    assert set(cat["champs_produits"]) <= set(m.get("derived_fields", {}))


def test_fortidhcp_desactivable_par_le_site(tmp_path):
    env = tmp_path / "00-vars.env"
    env.write_text("FORTI_DHCP_ENABLED='0'\nFORTI_DHCP_HOST='10.0.0.254'\nFORTI_DHCP_TOKEN='x'\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(ROOT / "deploye" / "sbin" / "omni-fortidhcp-fetch")], env=dict(os.environ, OMNI_VARS=str(env)),
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "desactive par la configuration du site" in r.stdout
    env.write_text("FORTI_DHCP_HOST='10.0.0.254'\nFORTI_DHCP_TOKEN='CHANGEME'\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(ROOT / "deploye" / "sbin" / "omni-fortidhcp-fetch")], env=dict(os.environ, OMNI_VARS=str(env)),
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "non configures" in r.stdout
    assert "FORTI_DHCP_ENABLED" in (ROOT / "56-fortidhcp.sh").read_text(encoding="utf-8")


def test_canary_ne_remplace_pas_la_liste_du_site():
    t = (ROOT / "35-canary.sh").read_text(encoding="utf-8")
    assert 'if [[ -f "${LOOKUP_DIR}/canary-accounts.csv" ]]' in t


def test_ti_fetch_sans_cle(tmp_path, monkeypatch):
    env = {"OMNI_V5_TI_LOOKUP": str(tmp_path / "lk"), "OMNI_V5_TI_STATE": str(tmp_path / "st"),
           "OMNI_V5_TI_LOG": str(tmp_path / "log" / "f.log"), "OMNI_V5_TI_KEYFILE": str(tmp_path / "absente.key")}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    mod = _module("omni_v5_ti_fetch", ROOT / "deploye" / "sbin" / "omni-v5-ti-fetch")
    feodo_rec = "# Feodo Tracker\n198.51.100.20\n# END\n"
    feodo = "# Feodo Tracker\nfirst_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n2026-11-01,198.51.100.20,443,online,2026-11-21,QakBot\n# END\n"
    tor = "\n".join(f"203.0.113.{i % 250}" if i < 250 else f"192.0.2.{i % 250}" for i in range(400))
    urls = []

    def get(url, data=None, headers=None, timeout=180):
        urls.append(url)
        if "recommended" in url:
            return feodo_rec.encode()
        if "feodotracker" in url:
            return feodo.encode()
        if "torproject" in url:
            return tor.encode()
        raise AssertionError(f"flux à clé ou Tranco interrogé sans clé : {url}")

    monkeypatch.setattr(mod, "get", get)
    gelf = []
    monkeypatch.setattr(mod, "gelf", gelf.append)
    monkeypatch.setattr(mod, "ip_publique", lambda ip: True)
    monkeypatch.setattr(mod, "est_ip", lambda ip: bool(ip) and ip[0].isdigit())
    assert mod.main() == 0
    assert gelf[0]["_ti_fetch_statut"] == "ok" and gelf[0]["_ti_src_threatfox_ok"] == "desactivee"
    ip = (tmp_path / "lk" / "ip.csv").read_text(encoding="utf-8")
    assert "198.51.100.20,feodo|c2_botnet|QakBot|haute" in ip and "tor|tor_sortie" in ip
    assert (tmp_path / "lk" / "domaine.csv").read_text(encoding="utf-8") == "cle,valeur\n"
    assert not any("tranco" in u for u in urls)
