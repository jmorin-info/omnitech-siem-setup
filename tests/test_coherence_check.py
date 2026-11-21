"""Outil de contrôle de cohérence dépôt / production : fixtures synthétiques, aucune lecture du système réel."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("omni_coherence_check", ROOT / "tools/omni-coherence-check.py")
occ = importlib.util.module_from_spec(_spec)
sys.modules["omni_coherence_check"] = occ   # requis par dataclasses avec annotations différées
_spec.loader.exec_module(occ)


def ecrire(chemin: Path, contenu: str):
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(contenu, encoding="utf-8")


class FauxSysteme:
    """Remplace subprocess : réponses systemctl, git et dpkg-query programmées."""

    def __init__(self, unites=None, show=None, timers=None, paquets=None, git=None):
        self.unites = unites or {}
        self.show = show or {}
        self.timers = timers or []
        self.paquets = paquets or {}
        self.git = git or {}
        self.appels = []

    def __call__(self, cmd):
        self.appels.append(cmd)
        if cmd[0] == "systemctl" and cmd[1] == "list-unit-files":
            return 0, "".join(f"{u} {e} enabled\n" for u, e in self.unites.items())
        if cmd[0] == "systemctl" and cmd[1] == "show":
            return 0, self.show.get(cmd[2], "ActiveState=inactive\nResult=success\n")
        if cmd[0] == "systemctl" and cmd[1] == "list-timers":
            return 0, json.dumps(self.timers)
        if cmd[0] == "dpkg-query":
            v = self.paquets.get(cmd[-1])
            return (0, v) if v else (1, "")
        if cmd[0] == "git":
            chemin, action = cmd[3], cmd[4]
            rep = self.git.get((chemin, action))
            if rep is None:
                return 128, ""
            return 0, rep
        return 127, ""


@pytest.fixture
def plateforme(tmp_path):
    depot, racine = tmp_path / "depot", tmp_path / "racine"
    ecrire(depot / "deploye/sbin/omni-a", "#!/bin/sh\necho a\n")
    ecrire(depot / "deploye/sbin/omni-b", "#!/bin/sh\necho b-depot\n")
    ecrire(depot / "deploye/systemd/omni-a.service", "[Service]\nExecStart=/usr/local/sbin/omni-a\n")
    ecrire(depot / "manifeste-deploye.txt",
           "# Manifeste\n"
           "/usr/local/sbin/omni-a\tdeploye/sbin/omni-a\n"
           "/usr/local/sbin/omni-b\tdeploye/sbin/omni-b\n"
           "/usr/local/sbin/omni-c\tdeploye/sbin/omni-c\n"
           "/etc/systemd/system/omni-a.service\tdeploye/systemd/omni-a.service\n"
           "/usr/local/sbin/omni-absent\tdeploye/sbin/omni-absent\n")
    ecrire(depot / "stack-versions.env", "GRAYLOG_PACKAGE_VERSION=7.2.2-1\nOPENSEARCH_PACKAGE_VERSION=2.19.7\n")
    ecrire(depot / "mobile/soc/index.html", "<html>console</html>")
    ecrire(racine / "usr/local/sbin/omni-a", "#!/bin/sh\necho a\n")
    ecrire(racine / "usr/local/sbin/omni-b", "#!/bin/sh\necho b-prod\n")
    ecrire(racine / "usr/local/sbin/omni-c", "#!/bin/sh\necho c\n")
    ecrire(racine / "usr/local/sbin/omni-orphelin", "#!/bin/sh\n. /root/omnitech-siem-setup/00-vars.env\n")
    ecrire(racine / "etc/systemd/system/omni-a.service", "[Service]\nExecStart=/usr/local/sbin/omni-a\n")
    ecrire(racine / "etc/systemd/system/oms-x.service",
           "[Service]\nWorkingDirectory=/root/omnitech-siem-setup/oms-x\n"
           "ExecStart=/root/omnitech-siem-setup/oms-x/.venv/bin/python -m x\n")
    ecrire(racine / "etc/systemd/system/oms-x.service.d/hardening.conf",
           "[Service]\nReadWritePaths=/var/lib /root/omnitech-siem-setup/docs\n")
    ecrire(racine / "var/www/siem-soc/index.html", "<html>console</html>")
    ecrire(racine / "var/www/siem-soc/app.js", "inconnu()")
    return depot, racine


def lancer(depot, racine, faux, *args):
    rapport = occ.Rapport()
    ctx = occ.Contexte(depot, racine, faux)
    return ctx, rapport


def test_manifeste_classe_identique_different_absents(plateforme):
    depot, racine = plateforme
    faux = FauxSysteme(git={(str(depot), "log"): "1000\n"})
    ctx, rapport = lancer(depot, racine, faux)
    suivis = occ.controle_manifeste(ctx, rapport)
    stats = rapport.stats["manifeste"]
    assert stats == {"identiques": 2, "differents": 1, "absents_prod": 1, "absents_depot": 1, "entrees": 5}
    diff = [e for e in rapport.ecarts if e.objet == "/usr/local/sbin/omni-b"][0]
    assert "production plus récente" in diff.constat and diff.gravite == "elevee"
    assert any(e.objet == "/usr/local/sbin/omni-c" and "absent du dépôt" in e.constat for e in rapport.ecarts)
    assert any(e.objet == "/usr/local/sbin/omni-absent" and e.gravite == "moyenne" for e in rapport.ecarts)
    assert "/usr/local/sbin/omni-a" in suivis


def test_sens_depot_plus_recent(plateforme):
    depot, racine = plateforme
    faux = FauxSysteme(git={(str(depot), "log"): "9999999999\n"})
    ctx, rapport = lancer(depot, racine, faux)
    occ.controle_manifeste(ctx, rapport)
    diff = [e for e in rapport.ecarts if e.objet == "/usr/local/sbin/omni-b"][0]
    assert "dépôt plus récent" in diff.constat


def test_non_suivis_et_console(plateforme):
    depot, racine = plateforme
    ctx, rapport = lancer(depot, racine, FauxSysteme())
    suivis = occ.controle_manifeste(ctx, rapport)
    rapport.ecarts.clear()
    occ.controle_non_suivis(ctx, rapport, suivis)
    objets = {e.objet for e in rapport.ecarts}
    assert "/usr/local/sbin/omni-orphelin" in objets
    assert "/etc/systemd/system/oms-x.service" in objets
    assert "/etc/systemd/system/oms-x.service.d/hardening.conf" in objets
    assert "/var/www/siem-soc/app.js" in objets          # absent du dépôt
    assert "/var/www/siem-soc/index.html" not in objets  # identique à mobile/soc/index.html


def test_copies_detectees_dans_unites_dropins_et_scripts(plateforme):
    depot, racine = plateforme
    copie = racine / "root/omnitech-siem-setup"
    copie.mkdir(parents=True)
    faux = FauxSysteme(git={
        (str(depot), "rev-parse"): "b" * 40 + "\n", (str(depot), "branch"): "main\n", (str(depot), "status"): "",
        (str(copie), "rev-parse"): "a" * 40 + "\n", (str(copie), "branch"): "main\n",
        (str(copie), "status"): " M README.md\n D x\n?? y\n", (str(depot), "rev-list"): "12\n"})
    ctx, rapport = lancer(depot, racine, faux)
    occ.controle_copies(ctx, rapport, ("/root/omnitech-siem-setup",))
    critiques = [e for e in rapport.ecarts if e.gravite == "critique"]
    assert {e.constat.split()[0] for e in critiques} == {"WorkingDirectory", "ExecStart"}
    assert all(e.objet == "oms-x.service" for e in critiques)
    assert any("ReadWritePaths" in e.constat and e.gravite == "elevee" for e in rapport.ecarts)
    assert any(e.objet == "/usr/local/sbin/omni-orphelin" for e in rapport.ecarts)
    etat = rapport.stats["copies"]["/root/omnitech-siem-setup"]
    assert etat["modifies"] == 2 and etat["non_suivis"] == 1 and etat["retard_sur_reference"] == 12
    assert any("non commitée" in e.constat for e in rapport.ecarts)
    assert all("--no-optional-locks" in c for c in faux.appels if c[0] == "git")


def test_cron_sur_copie_est_critique(plateforme):
    depot, racine = plateforme
    ecrire(racine / "etc/cron.d/omni", "0 1 * * * root /root/omnitech-siem-purge/53-purge-clean.sh\n")
    ctx, rapport = lancer(depot, racine, FauxSysteme())
    occ.controle_copies(ctx, rapport, ())
    assert any(e.gravite == "critique" and "cron" in e.constat for e in rapport.ecarts)


def test_robots(plateforme):
    depot, racine = plateforme
    faux = FauxSysteme(
        unites={"omni-a.service": "static", "omni-a.timer": "enabled", "omni-b.timer": "disabled",
                "omni-b.service": "static", "omni-c.service": "static", "omni-d.timer": "enabled"},
        show={"omni-b.service": "ActiveState=failed\nResult=exit-code\n",
              "omni-c.service": "ActiveState=inactive\nResult=timeout\n"},
        timers=[{"unit": "omni-a.timer", "last": 1}, {"unit": "omni-d.timer", "last": None}])
    ctx, rapport = lancer(depot, racine, faux)
    occ.controle_robots(ctx, rapport)
    par_objet = {e.objet: e for e in rapport.ecarts}
    assert par_objet["omni-b.service"].gravite == "critique"
    assert par_objet["omni-c.service"].gravite == "elevee"
    assert par_objet["omni-b.timer"].gravite == "moyenne"
    assert par_objet["omni-d.timer"].gravite == "faible"
    assert "omni-a.service" not in par_objet
    assert rapport.stats["robots"]["timers_desactives"] == ["omni-b.timer"]


def test_versions(plateforme):
    depot, racine = plateforme
    faux = FauxSysteme(paquets={"graylog-server": "7.2.2-1", "opensearch": "2.19.6"})
    ctx, rapport = lancer(depot, racine, faux)
    occ.controle_versions(ctx, rapport)
    assert [e.objet for e in rapport.ecarts] == ["opensearch"]


def test_graylog_get_uniquement_et_titres(plateforme, tmp_path):
    depot, racine = plateforme
    ecrire(depot / "12-x.sh", 'ensure_rule "omni-regle-connue"\ntitle:"OMNI - Défini"\n')
    vars_env = tmp_path / "vars.env"
    ecrire(vars_env, 'GRAYLOG_API_URL="https://siem.example:9000"\nGRAYLOG_ADMIN_PASS="factice"\n')
    demandes = []

    def getter(chemin):
        demandes.append(chemin)
        reponses = {
            "/streams": {"streams": [{"title": "OMNI - Defini"}]},
            "/system/pipelines/pipeline": [],
            "/system/pipelines/rule": [{"title": "omni-regle-connue"}, {"title": "omni-regle-orpheline"}],
            "/system/inputs": {"inputs": []},
            "/system/indices/index_sets?limit=500": {"index_sets": [{}]},
            "/system": {"version": "7.2.2"},
        }
        if chemin.startswith("/events/definitions"):
            return {"event_definitions": [{"title": "OMNI - Défini", "state": "ENABLED"},
                                          {"title": "OMNI - Inconnu", "state": "DISABLED"}]}
        return reponses[chemin]

    faux = FauxSysteme(git={(str(depot), "ls-files"): "12-x.sh\n"})
    ctx, rapport = lancer(depot, racine, faux)
    occ.controle_graylog(ctx, rapport, vars_env, getter=getter)
    g = rapport.stats["graylog"]
    assert g["event_definitions"] == 2 and g["actives"] == 1 and g["desactivees"] == 1
    manquants = sorted(e.objet for e in rapport.ecarts if e.gravite == "faible")
    assert manquants == ["event_definitions: OMNI - Inconnu", "rules: omni-regle-orpheline"]
    assert any(e.objet == "GRAYLOG_API_URL" for e in rapport.ecarts)
    assert "factice" not in json.dumps([e.__dict__ for e in rapport.ecarts])


def test_url_api():
    assert occ.url_api("https://h:9000") == "https://h:9000/api"
    assert occ.url_api("https://h:9000/api/") == "https://h:9000/api"


def test_main_json_et_code_retour(plateforme, capsys):
    depot, racine = plateforme
    faux = FauxSysteme()
    code = occ.main(["--depot", str(depot), "--racine", str(racine), "--controles", "manifeste,copies",
                     "--copie", "/root/omnitech-siem-setup", "--json"], executer=faux)
    sortie = json.loads(capsys.readouterr().out)
    assert code == 2 and sortie["synthese"]["critique"] == 2
    code = occ.main(["--depot", str(depot), "--racine", str(racine), "--controles", "manifeste"], executer=faux)
    assert code == 0 and "Synthèse" in capsys.readouterr().out
    code = occ.main(["--depot", str(depot), "--racine", str(racine), "--controles", "manifeste", "--strict"],
                    executer=faux)
    assert code == 1
    assert occ.main(["--depot", str(depot), "--controles", "inconnu"], executer=faux) == 3


def test_aucune_commande_d_ecriture(plateforme):
    depot, racine = plateforme
    faux = FauxSysteme(unites={"omni-a.service": "static", "omni-a.timer": "enabled"})
    occ.main(["--depot", str(depot), "--racine", str(racine), "--json"], executer=faux)
    interdits = {"start", "stop", "restart", "enable", "disable", "daemon-reload", "commit", "checkout", "reset",
                 "add", "push", "fetch", "pull"}
    for cmd in faux.appels:
        assert not interdits.intersection(cmd[1:5]), cmd


def test_lire_env_developpe_les_variables(tmp_path):
    f = tmp_path / "v.env"
    ecrire(f, 'H=siem\nD=example.org\nFQDN="${H}.${D}"\nURL="https://$FQDN:9000"\nLIT=\'${H}\'\n')
    env = occ.lire_env(f)
    assert env["URL"] == "https://siem.example.org:9000" and env["LIT"] == "${H}"
    assert occ.lire_env(f, {"URL"}) == {"URL": "https://siem.example.org:9000"}
