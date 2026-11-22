"""Exercice de restauration complète : garde anti-production, calculs RTO/RPO, rapports."""
from importlib.util import module_from_spec, spec_from_file_location
import argparse
import datetime as dt
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("omni_restore_drill", ROOT / "tools/omni-restore-drill.py")
drill = module_from_spec(spec)
spec.loader.exec_module(drill)

LAB = {"env": {drill.GARDE_ENV: "1"}, "hostname": "siem-lab", "fqdn": "siem.lab.test", "adresses": ["10.0.2.15"],
       "noeud": {"name": "siem-lab"}, "index": [{"index": "omni-winsec_0", "docs": 10, "octets": 2048}]}
TZ = dt.timezone(dt.timedelta(hours=1))


# -- garde anti-production ----------------------------------------------------

def test_isolated_lab_is_accepted():
    assert drill.motifs_refus(**LAB) == []


@pytest.mark.parametrize("champ,valeur,attendu", [
    ("env", {}, "variable de garde"),
    ("env", {drill.GARDE_ENV: "yes"}, "variable de garde"),
    ("hostname", "bx-it-graylog-vm", "nom d'hôte"),
    ("hostname", "BX-IT-GRAYLOG-VM", "nom d'hôte"),
    ("fqdn", "bx-it-graylog-vm.omnitech.security", "nom d'hôte"),
    ("adresses", ["10.0.2.15", "10.33.220.10"], "adresse IP"),
    ("noeud", {"name": "bx-it-graylog-vm"}, "nœud OpenSearch"),
    ("noeud", None, "injoignable"),
    ("index", [{"index": "omni-fortigate_124", "docs": 2_000_000, "octets": 10}], "index préexistants"),
    ("index", [{"index": "omni-winsec_124", "docs": 5, "octets": 2 << 30}], "index préexistants"),
])
def test_each_production_signal_refuses(champ, valeur, attendu):
    raisons = drill.motifs_refus(**{**LAB, champ: valeur})
    assert len(raisons) == 1 and attendu in raisons[0]


def test_hidden_system_indices_do_not_count_as_production_data():
    index = [{"index": ".opensearch-observability", "docs": 5_000_000, "octets": 5 << 30}]
    assert drill.motifs_refus(**{**LAB, "index": index}) == []


def test_production_profile_lists_every_reason():
    raisons = drill.motifs_refus(env={}, hostname="bx-it-graylog-vm", fqdn="bx-it-graylog-vm.omnitech.security",
                                 adresses=["10.33.220.10"], noeud={"name": "bx-it-graylog-vm"},
                                 index=[{"index": "omni-winsec_120", "docs": 735_488_623, "octets": 1 << 40}])
    assert len(raisons) == 5


def test_ip_output_parsing():
    sortie = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
              "2: eno1    inet 10.33.220.10/24 brd 10.33.220.255 scope global eno1\n")
    assert drill.adresses_ipv4(sortie) == ["10.33.220.10", "127.0.0.1"]


def test_cat_indices_normalisation_tolerates_closed_indices():
    lignes = [{"index": "a_1", "docs.count": "12", "store.size": "300", "health": "green"},
              {"index": "b_1", "docs.count": None, "store.size": None, "health": "red"}, {"bad": 1}]
    assert drill.index_depuis_cat(lignes) == [{"index": "a_1", "docs": 12, "octets": 300, "sante": "green"},
                                              {"index": "b_1", "docs": 0, "octets": 0, "sante": "red"}]


def test_read_only_http_refuses_write_methods():
    for methode in ("PUT", "POST", "DELETE"):
        with pytest.raises(drill.ErreurExercice):
            drill.http_json(methode, "http://127.0.0.1:9/", lecture_seule=True)


def refus():
    return {"hote": "bx-it-graylog-vm", "raisons_refus": ["nom d'hôte de production"], "accepte": False}


def test_execution_is_refused_before_any_write(monkeypatch, tmp_path):
    monkeypatch.setattr(drill, "evaluer_garde", lambda **_: refus())
    monkeypatch.setattr(drill, "Exercice", lambda *_: pytest.fail("aucun dossier de travail ne doit être créé"))
    rapport = tmp_path / "rapport"
    code = drill.main(["executer", "--archive-config", "a.enc", "--depot-snapshots", str(tmp_path),
                       "--rapport", str(rapport), "--travail", str(tmp_path)])
    assert code == 3 and not rapport.exists() and list(tmp_path.iterdir()) == []


def test_plan_reports_refusal_with_dedicated_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(drill, "evaluer_garde", lambda **_: refus())
    assert drill.main(["plan"]) == 3
    assert json.loads(capsys.readouterr().out)["garde"]["accepte"] is False


def test_lab_fixture_commands_reuse_the_integration_guard(monkeypatch, tmp_path):
    def refuse():
        raise ValueError("OMNI_ISOLATED_VM_TEST=1 is required")
    monkeypatch.setattr(drill, "configuration_laboratoire", refuse)
    monkeypatch.setattr(drill.subprocess, "run", lambda *a, **k: pytest.fail("aucune commande ne doit partir"))
    monkeypatch.setattr(drill, "http_json", lambda *a, **k: pytest.fail("aucun appel OpenSearch"))
    with pytest.raises(ValueError):
        drill.sinistre_factice(argparse.Namespace(jeu=str(tmp_path / "jeu.json")))
    with pytest.raises(ValueError):
        drill.jeu_factice(argparse.Namespace(sortie=str(tmp_path / "jeu")))
    assert not (tmp_path / "jeu").exists()


# -- configuration restaurée ---------------------------------------------------

SERVER_CONF = """# commentaire
http_bind_address = 127.0.0.1:9000
http_enable_tls = true
http_external_uri = https://bx-it-graylog-vm.omnitech.security/
transport_email_enabled = true
mongodb_uri = mongodb://ancien:dummy-old@127.0.0.1:27017/graylog
mongodb_uri = mongodb://graylog:dummy%2Fvalue@127.0.0.1:27017/graylog?authSource=admin&replicaSet=rs0
"""


def test_properties_follow_java_last_occurrence_semantics():
    proprietes = drill.lire_proprietes(SERVER_CONF)
    assert proprietes["mongodb_uri"].startswith("mongodb://graylog:")
    app = drill.uri_application(proprietes)
    assert app == {"utilisateur": "graylog", "mot_de_passe": "dummy/value", "base": "graylog", "base_auth": "admin"}


def test_application_uri_without_credentials_is_refused_without_echoing_it():
    with pytest.raises(drill.ErreurExercice) as erreur:
        drill.uri_application({"mongodb_uri": "mongodb://127.0.0.1:27017/graylog"})
    assert "127.0.0.1" not in str(erreur.value)


def test_email_transport_is_always_disabled_once():
    texte = drill.neutraliser_courriel(SERVER_CONF)
    assert texte.count("transport_email_enabled") == 1
    assert drill.lire_proprietes(texte)["transport_email_enabled"] == "false"
    assert drill.lire_proprietes(drill.neutraliser_courriel("a = b\n"))["transport_email_enabled"] == "false"


@pytest.mark.parametrize("proprietes,url", [
    ({}, "http://127.0.0.1:9000/api"),
    ({"http_bind_address": "0.0.0.0:9001", "http_enable_tls": "true"}, "https://127.0.0.1:9001/api"),
    ({"http_bind_address": "10.0.2.15:9000"}, "http://10.0.2.15:9000/api"),
])
def test_local_graylog_address(proprietes, url):
    assert drill.adresse_graylog(proprietes) == url


def test_production_archive_detection_requires_network_isolation_proof():
    assert drill.archive_de_production(drill.lire_proprietes(SERVER_CONF))
    assert not drill.archive_de_production({"http_external_uri": "https://siem.lab.test/"})


def test_required_members_follow_the_backup_restorability_check():
    noms = ["./" + m for m in drill.MEMBRES_REQUIS]
    assert drill.membres_manquants(noms) == []
    assert drill.membres_manquants(noms[1:]) == [drill.MEMBRES_REQUIS[0]]
    source = (ROOT / "30-backup-config.sh").read_text()
    assert all(m in source for m in drill.MEMBRES_REQUIS)


def make_tar(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for name, kind, target in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = b"x"
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = target
                tar.addfile(info)


def test_extraction_skips_absolute_links_but_refuses_traversal(tmp_path):
    archive = tmp_path / "a.tar.gz"
    make_tar(archive, [("etc/graylog/server/server.conf", "file", None),
                       ("etc/systemd/system/multi-user.target.wants/x.service", "link", "/lib/systemd/system/x.service"),
                       ("etc/nginx/sites-enabled/graylog", "link", "../sites-available/graylog"),
                       ("etc/graylog/evade", "link", "../../../../../../etc/shadow")])
    ignores = []
    with tarfile.open(archive) as tar:
        tar.extractall(tmp_path / "out", filter=drill.filtre_extraction(ignores))
    assert (tmp_path / "out/etc/graylog/server/server.conf").is_file()
    assert ignores == ["etc/systemd/system/multi-user.target.wants/x.service", "etc/graylog/evade"]
    assert (tmp_path / "out/etc/nginx/sites-enabled/graylog").is_symlink()
    hostile = tmp_path / "b.tar.gz"
    make_tar(hostile, [("../evade", "file", None)])
    with tarfile.open(hostile) as tar, pytest.raises(tarfile.FilterError):
        tar.extractall(tmp_path / "out2", filter=drill.filtre_extraction([]))
    assert not (tmp_path / "evade").exists()


def test_version_compatibility_against_archive_reference():
    reference = {"GRAYLOG_SERIES": "7.2", "MONGODB_PACKAGE_VERSION": "8.0.38", "OPENSEARCH_PACKAGE_VERSION": "2.19.7"}
    assert drill.versions_compatibles({"graylog-server": "7.2.2-1", "mongodb-org-server": "8.0.40",
                                       "opensearch": "2.19.7"}, reference) == []
    ecarts = drill.versions_compatibles({"graylog-server": "7.1.5-1", "mongodb-org-server": "7.0.12",
                                         "opensearch": "3.0.0"}, reference)
    assert len(ecarts) == 3


# -- calculs RTO / RPO ---------------------------------------------------------

@pytest.mark.parametrize("nom,attendu,precision", [
    ("omni-siem-config_2026-11-22.tar.gz.enc", (2026, 11, 22, 0, 0, 0), "jour"),
    ("omni-mongo-20261122-175932-c25e75fe2ded.archive.gz", (2026, 11, 22, 17, 59, 32), "seconde"),
    ("graylog-mongo-20261122-0946.archive.gz", (2026, 11, 22, 9, 46, 0), "minute"),
    ("oms-sel-20261122-0130", (2026, 11, 22, 1, 30, 0), "minute"),
    ("snap-20261122-023012", (2026, 11, 22, 2, 30, 12), "minute"),
])
def test_backup_timestamps_from_names(nom, attendu, precision):
    horodatage, trouvee = drill.horodatage_nom(nom, TZ)
    assert horodatage == dt.datetime(*attendu, tzinfo=TZ) and trouvee == precision


def test_unknown_name_has_no_timestamp():
    assert drill.horodatage_nom("autre.tar.gz") == (None, None)


def etape(nom, secondes, statut="ok", **extra):
    return {"nom": nom, "secondes": secondes, "statut": statut, **extra}


def test_rto_sums_service_steps_and_deduces_collection_restart():
    etapes = [etape("socle", 1800, mode="installation"), etape("configuration", 60), etape("mongodb", 5),
              etape("opensearch", 12000), etape("graylog", 120), etape("controles", 300)]
    rto = drill.calcul_rto(etapes)
    assert rto == {"valide": True, "service_secondes": 13985, "total_secondes": 14285,
                   "collecte_deduit_secondes": 1985, "socle_mode": "installation"}


def test_rto_is_invalid_when_a_service_step_failed_or_is_missing():
    assert not drill.calcul_rto([etape("socle", 1), etape("configuration", 1, "echec")])["valide"]
    assert not drill.calcul_rto([etape(n, 1) for n in ("socle", "configuration", "mongodb", "graylog")])["valide"]


def test_rpo_is_the_oldest_backup_per_class():
    instant = dt.datetime(2026, 11, 22, 12, 0, tzinfo=TZ)
    sources = [{"type": "archive_config", "nom": "c", "horodatage": "2026-11-22T03:16:00+01:00"},
               {"type": "mongo", "nom": "m", "horodatage": "2026-11-22T02:40:00+01:00"},
               {"type": "snapshot", "nom": "s", "horodatage": "2026-11-22T01:30:00+01:00"}]
    rpo = drill.calcul_rpo(sources, instant)
    assert rpo["configuration_secondes"] == 9 * 3600 + 20 * 60
    assert rpo["journaux_secondes"] == 10 * 3600 + 30 * 60
    assert rpo["global_secondes"] == rpo["journaux_secondes"]
    assert [s["age_secondes"] for s in rpo["sources"]] == [31440, 33600, 37800]


def test_rpo_without_sources_is_unknown():
    rpo = drill.calcul_rpo([], dt.datetime(2026, 1, 1, tzinfo=TZ))
    assert rpo["global_secondes"] is None and rpo["journaux_secondes"] is None


def test_throughput():
    assert drill.debit_mo_s(477_562_464_109, 12_000) == 39.8
    assert drill.debit_mo_s(0, 10) is None and drill.debit_mo_s(10, 0) is None


def test_api_counts_must_not_lose_restored_objects():
    attendus = {"inputs": 15, "streams": 22, "event_definitions": 214, "pipeline_processor_rules": 282,
                "pipeline_processor_pipelines": 41, "index_sets": 22}
    api = {"entrees": 15, "flux": 23, "definitions": 214, "regles": 281, "pipelines": 41, "index_sets": None}
    resultat = drill.comparer_comptages(attendus, api)
    assert [k for k, v in resultat.items() if not v["conforme"]] == ["regles", "index_sets"]


def test_inventory_comparison_tolerates_growth_of_write_indices_only():
    inventaire = {"omni-winsec_120": {"docs": 100, "ecriture": False}, "omni-winsec_124": {"docs": 900, "ecriture": True},
                  "omni-m365_111": {"docs": 50, "ecriture": False}}
    resultat = drill.comparer_inventaire({"omni-winsec_120": 100, "omni-winsec_124": 640, "omni-m365_111": 49,
                                          "inconnu_1": 3}, inventaire)
    assert resultat == {"compares": 3, "identiques": 1, "toleres": 1, "ecarts": [{"index": "omni-m365_111", "restaure": 49, "source": 50}]}
    assert drill.comparer_inventaire({"omni-winsec_124": 901}, inventaire)["ecarts"]


# -- orchestration et rapports -------------------------------------------------

def test_step_timer_never_reports_unexpected_exception_text():
    rapport = {"etapes": []}
    with pytest.raises(RuntimeError):
        with drill.Chrono(rapport, "mongodb"):
            raise RuntimeError("mongodb://admin:dummy-private-value@127.0.0.1")
    assert rapport["etapes"][0]["statut"] == "echec" and rapport["etapes"][0]["erreur"] == "RuntimeError"
    with pytest.raises(drill.ErreurExercice):
        with drill.Chrono(rapport, "opensearch"):
            raise drill.ErreurExercice("aucun snapshot réussi")
    assert rapport["etapes"][1]["erreur"] == "aucun snapshot réussi"


def arguments(tmp_path, **extra):
    valeurs = {"travail": str(tmp_path), "rapport": str(tmp_path / "rapport"), "config_socle": str(tmp_path / "vars"),
               "instant_sinistre": None, "conserver_extraction": False}
    return argparse.Namespace(**{**valeurs, **extra})


@pytest.fixture
def exercice(monkeypatch, tmp_path):
    accepte = {"hote": "siem-lab", "raisons_refus": [], "accepte": True}
    monkeypatch.setattr(drill, "evaluer_garde", lambda **_: accepte)
    monkeypatch.setattr(drill.os, "geteuid", lambda: 0)
    monkeypatch.setattr(drill, "charger_config_socle", lambda _: {"MONGO_ADMIN_PASS": "dummy-lab-value"})
    instance = drill.Exercice(arguments(tmp_path))
    appels = []
    for nom in ("socle", "configuration", "mongodb", "opensearch", "graylog", "controles"):
        monkeypatch.setattr(instance, nom, lambda entree, nom=nom: appels.append(nom))
    return instance, appels, tmp_path


def test_orchestration_runs_every_step_in_order_and_writes_private_reports(exercice):
    instance, appels, tmp_path = exercice
    instance.rapport["sources"].append({"type": "snapshot", "nom": "oms-sel-20261122-0130",
                                        "horodatage": "2026-11-22T01:30:00+01:00", "precision": "minute"})
    assert instance.lancer() == 0
    assert appels == ["socle", "configuration", "mongodb", "opensearch", "graylog", "controles"]
    rapport = json.loads((tmp_path / "rapport/rapport-restauration.json").read_text())
    assert rapport["reussi"] is True and drill.valider_rapport(rapport) == []
    assert rapport["rpo"]["journaux_secondes"] > 0
    for nom in ("rapport-restauration.json", "rapport-restauration.md"):
        assert (tmp_path / "rapport" / nom).stat().st_mode & 0o777 == 0o600
    assert "dummy-lab-value" not in (tmp_path / "rapport/rapport-restauration.json").read_text()


def test_orchestration_stops_at_the_first_failed_step(exercice, monkeypatch):
    instance, appels, tmp_path = exercice
    def echec(entree):
        raise drill.ErreurExercice("aucun snapshot réussi correspondant dans le dépôt")
    monkeypatch.setattr(instance, "opensearch", echec)
    assert instance.lancer() == 1
    assert appels == ["socle", "configuration", "mongodb"]
    rapport = json.loads((tmp_path / "rapport/rapport-restauration.json").read_text())
    assert rapport["reussi"] is False and rapport["rto"]["valide"] is False
    assert rapport["etapes"][-1]["statut"] == "echec"


def rapport_type(**extra):
    return {"schema_version": 1, "reussi": True, "debut": "2026-11-22T10:00:00+01:00", "hote": "siem-lab",
            "etapes": [etape("socle", 10)], "rto": {"valide": True, "service_secondes": 10, "total_secondes": 12},
            "rpo": {"global_secondes": 3600}, "mesures": {"debit_restauration_mo_s": 40.0}, **extra}


@pytest.mark.parametrize("modification,erreur", [
    ({"schema_version": 2}, "schema_version"), ({"reussi": "oui"}, "reussi"),
    ({"etapes": [{"secondes": 1}]}, "etapes"), ({"rpo": None}, "rpo absent"),
    ({"rto": {"valide": False}}, "RTO invalide"),
])
def test_report_validation(modification, erreur):
    assert any(erreur in e for e in drill.valider_rapport(rapport_type(**modification)))


def test_report_analysis_orders_runs_and_enforces_latest_success(tmp_path, capsys):
    ancien, recent = tmp_path / "a.json", tmp_path / "b.json"
    recent.write_text(json.dumps(rapport_type(debut="2026-11-23T10:00:00+01:00", reussi=False,
                                              rto={"valide": False, "service_secondes": 5})))
    ancien.write_text(json.dumps(rapport_type()))
    assert drill.main(["analyser", str(recent), str(ancien)]) == 0
    lignes = json.loads(capsys.readouterr().out)["rapports"]
    assert [ligne["reussi"] for ligne in lignes] == [True, False]
    assert drill.main(["analyser", "--exiger-reussite", str(recent), str(ancien)]) == 1
    capsys.readouterr()
    (tmp_path / "c.json").write_text("{")
    assert drill.main(["analyser", str(tmp_path / "c.json")]) == 2


def test_markdown_report_is_french_and_emoji_free():
    rapport = rapport_type(etapes=[etape("socle", 3700, mode="verification"), etape("graylog", 65)],
                           rpo={"instant_reference": "x", "sources": [{"nom": "oms-sel-1", "type": "snapshot",
                                "age_secondes": 7200}], "configuration_secondes": 60, "journaux_secondes": 7200},
                           controles=[{"nom": "graylog:flux", "conforme": True, "preuve": {"api": 22}},
                                      {"nom": "graylog:api", "conforme": None, "preuve": "non fourni"}],
                           non_appliques={"usr/local/sbin": 120}, avertissements=["exemple"])
    texte = drill.rendre_markdown(rapport)
    for attendu in ("## RTO mesuré", "## RPO déduit", "1 h 01 min", "non vérifié", "`usr/local/sbin` : 120"):
        assert attendu in texte
    assert all(ord(c) < 0x2600 for c in texte)


def test_report_directory_symlink_is_refused(tmp_path):
    (tmp_path / "cible").mkdir()
    (tmp_path / "lien").symlink_to(tmp_path / "cible")
    with pytest.raises(drill.ErreurExercice):
        drill.ecrire_rapport(tmp_path / "lien", rapport_type())


def test_secret_files_must_be_private(tmp_path):
    cle = tmp_path / "cle"
    cle.write_text("dummy\n")
    cle.chmod(0o644)
    with pytest.raises(drill.ErreurExercice):
        drill.fichier_prive(cle)
    cle.chmod(0o600)
    assert drill.fichier_prive(cle) == cle


def test_vm_bench_keeps_the_drill_opt_in():
    script = (ROOT / "tools/test-ubuntu-vm.sh").read_text()
    assert 'OMNI_VM_RESTORE_DRILL:-0' in script
    assert "sinistre-factice" in script and "jeu-factice" in script
