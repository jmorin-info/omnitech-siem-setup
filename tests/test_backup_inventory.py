"""Mesure des intrants RPO/RTO : lecture seule, calculs de fréquence, couverture et estimation."""
from importlib.util import module_from_spec, spec_from_file_location
import datetime as dt
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("omni_backup_inventory", ROOT / "tools/omni-backup-inventory.py")
inv = module_from_spec(spec)
spec.loader.exec_module(inv)
TZ = dt.timezone(dt.timedelta(hours=1))

JOURNAL = """2026-11-11 06:17:17 === snapshot selectif : 945 index, ~453 Go bruts ===
2026-11-11 06:17:17 snapshot oms-sel-20261111-0617 lance
2026-11-11 09:49:17 snapshot oms-sel-20261111-0617 : SUCCESS 945/945 shards, 0 echec(s), 211 min ; /home libre 40 %
2026-11-11 09:51:47 Test de restauration OK : omni-aruba_70 depuis oms-sel-20261111-0617 -> x (1309 documents = source, sans alias)
2026-11-22 01:30:02 === snapshot selectif : 144 index, ~445 Go bruts ===
2026-11-22 01:43:13 snapshot oms-sel-20261122-0130 : SUCCESS 144/144 shards, 0 echec(s), 12 min ; /home libre 28 %
2026-11-23 01:30:02 === snapshot selectif : 144 index, ~446 Go bruts ===
2026-11-23 02:00:00 ALERTE : snapshot annule - /home n'a plus que 4 % libres
""".splitlines()


def test_snapshot_log_parsing_pairs_start_and_end_lines():
    journal = inv.analyser_journal_snap(JOURNAL)
    assert [e["snapshot"] for e in journal["executions"]] == ["oms-sel-20261111-0617", "oms-sel-20261122-0130"]
    assert journal["executions"][0] == {"debut": "2026-11-11 06:17:17", "index": 945, "gio_bruts": 453,
                                        "snapshot": "oms-sel-20261111-0617", "statut": "SUCCESS", "shards": 945,
                                        "echecs": 0, "minutes": 211}
    assert journal["tests_restauration"] == [{"date": "2026-11-11 09:51:47", "resultat": "OK"}]


def test_full_snapshot_throughput_uses_the_longest_successful_run():
    debit = inv.debit_snapshot_complet(inv.analyser_journal_snap(JOURNAL)["executions"])
    assert debit == {"snapshot": "oms-sel-20261111-0617", "gio": 453, "minutes": 211, "debit_mo_s": 38.4}
    assert inv.debit_snapshot_complet([]) is None


def entree(nom, octets, mtime):
    return {"nom": nom, "octets": octets, "mtime": mtime}


def test_backup_series_age_frequency_and_sizes():
    instant = dt.datetime(2026, 11, 22, 18, 0, tzinfo=TZ)
    serie = inv.serie([entree("omni-siem-config_2026-11-21.tar.gz.enc", 300, "2026-11-21T03:20:58+01:00"),
                       entree("omni-siem-config_2026-11-20.tar.gz.enc", 100, "2026-11-20T03:19:06+01:00"),
                       entree("omni-siem-config_2026-11-22.tar.gz.enc", 200, "2026-11-22T04:34:07+01:00")], instant)
    # Le nom ne porte que le jour : la date de modification sert d'horodatage.
    assert serie["precision"] == "mtime" and serie["plus_recente"] == "omni-siem-config_2026-11-22.tar.gz.enc"
    assert serie["age_secondes"] == 13 * 3600 + 25 * 60 + 53
    assert serie["intervalle_max_secondes"] == 25 * 3600 + 13 * 60 + 9
    assert serie["octets_median"] == 200 and serie["octets_total"] == 600
    assert inv.serie([], instant) == {"nombre": 0}


def test_precise_names_win_over_modification_time():
    instant = dt.datetime(2026, 11, 22, 18, 0, tzinfo=dt.datetime.now().astimezone().tzinfo)
    serie = inv.serie([entree("omni-mongo-20261122-175932-c25e75fe2ded.archive.gz", 10, "2026-11-22T18:00:00+01:00")], instant)
    assert serie["precision"] == "seconde"


def test_coverage_by_prefix_ignores_technical_indices():
    cluster = [{"index": "omni-winsec_1", "docs": 5, "octets": 100}, {"index": "omni-winsec_2", "docs": 5, "octets": 300},
               {"index": "omni-sysmon_1", "docs": 9, "octets": 600}, {"index": "top_queries-2026.11.22-1", "docs": 1, "octets": 5},
               {"index": ".tasks", "docs": 1, "octets": 5}]
    resultat = inv.couverture(cluster, ["omni-winsec_2", "absent_1"])
    assert resultat["octets_total"] == 1000 and resultat["octets_couverts"] == 300 and resultat["part_couverte"] == 0.3
    assert resultat["non_couverts"] == ["omni-sysmon"]
    assert resultat["prefixes"]["omni-winsec"]["index_couverts"] == 1


def test_rto_estimate_separates_collection_restart_from_history_restore():
    estimation = inv.estimer_rto(335_580_848, 477_562_464_109, 38.4)
    composantes = estimation["composantes"]
    assert composantes["restauration_index"]["secondes"] == round(477_562_464_109 / 1e6 / 38.4)
    assert composantes["socle"]["origine"] == "hypothèse"
    assert estimation["rto_collecte_secondes"] == 3600 + 7 + 900 + 300 + 600
    assert abs(estimation["rto_complet_secondes"] - (estimation["rto_collecte_secondes"] + 12437 + 900)) <= 1
    sans_debit = inv.estimer_rto(1, 1, None)
    assert sans_debit["rto_complet_secondes"] is None and sans_debit["rto_collecte_secondes"] is not None


def test_http_access_is_get_only(monkeypatch):
    methodes = []
    class Ouvreur:
        def open(self, requete, timeout):
            methodes.append(requete.get_method())
            raise OSError("pas de réseau en test")
    monkeypatch.setattr(inv.urllib.request, "build_opener", lambda *a: Ouvreur())
    with pytest.raises(OSError):
        inv.get("/_cat/indices")
    assert methodes == ["GET"]
    source = (ROOT / "tools/omni-backup-inventory.py").read_text()
    assert "method=\"GET\"" in source and "method=\"POST\"" not in source and "DELETE" not in source


def test_collection_with_fake_cluster_writes_private_outputs(monkeypatch, tmp_path):
    config, mongo = tmp_path / "config", tmp_path / "mongo"
    config.mkdir()
    mongo.mkdir()
    (config / "omni-siem-config_2026-11-22.tar.gz.enc").write_bytes(b"x" * 10)
    (config / "rapport-hebdo_2026-06-12.html").write_text("ignoré")
    (mongo / "omni-mongo-20261122-175932-c25e75fe2ded.archive.gz").write_bytes(b"y")
    journal = tmp_path / "snap.log"
    journal.write_text("\n".join(JOURNAL) + "\n")
    reponses = {
        "/_snapshot/graylog_fs": {"graylog_fs": {"type": "fs", "settings": {"location": "/home/siem-backup/opensearch-snapshots"}}},
        "/_snapshot/graylog_fs/_all": {"snapshots": [
            {"snapshot": "oms-sel-20261121-0130", "state": "SUCCESS", "indices": ["omni-winsec_2"],
             "start_time_in_millis": 1795221003122, "start_time": "x", "duration_in_millis": 1032000, "shards": {"failed": 0}},
            {"snapshot": "oms-sel-20261122-0130", "state": "SUCCESS", "indices": ["omni-winsec_2", "omni-winsec_3"],
             "start_time_in_millis": 1795307403108, "start_time": "y", "duration_in_millis": 755539, "shards": {"failed": 0}}]},
        "/_snapshot/graylog_fs/oms-sel-20261122-0130/_status": {"snapshots": [{"stats": {
            "incremental": {"size_in_bytes": 28661337206}, "total": {"size_in_bytes": 477562464109}, "time_in_millis": 755539}}]},
        "/_cat/indices?format=json&h=index,docs.count,store.size,health&bytes=b": [
            {"index": "omni-winsec_2", "docs.count": "10", "store.size": "100"},
            {"index": "omni-winsec_3", "docs.count": "20", "store.size": "100"},
            {"index": "omni-sysmon_3", "docs.count": "30", "store.size": "800"}],
        "/_cat/aliases?format=json&h=alias,index": [{"alias": "omni-winsec_deflector", "index": "omni-winsec_3"}],
    }
    monkeypatch.setattr(inv, "get", lambda chemin: reponses[chemin])
    monkeypatch.setattr(inv, "duree_unite", lambda unite: {"resultat": "success", "dernier_debut": None,
                                                           "derniere_duree_secondes": 58})
    sorties = {"json": tmp_path / "m.json", "markdown": tmp_path / "m.md", "inventaire": tmp_path / "inv.json"}
    assert inv.main(["--repertoire-config", str(config), "--repertoire-mongo", str(mongo), "--journal-snap", str(journal),
                     "--json", str(sorties["json"]), "--markdown", str(sorties["markdown"]),
                     "--inventaire-index", str(sorties["inventaire"])]) == 0
    mesures = json.loads(sorties["json"].read_text())
    assert mesures["lecture_seule"] is True and mesures["archives_config"]["nombre"] == 1
    assert mesures["dernier_snapshot"]["debit_incremental_mo_s"] == 37.9
    assert mesures["couverture"]["non_couverts"] == ["omni-sysmon"]
    assert mesures["snapshots_intervalle_median_secondes"] == 86400
    inventaire = json.loads(sorties["inventaire"].read_text())["index"]
    assert inventaire["omni-winsec_3"] == {"docs": 20, "ecriture": True}
    texte = sorties["markdown"].read_text()
    assert "Couverture des journaux" in texte and "20,0 %" in texte
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in sorties.values())


def test_markdown_handles_absent_snapshot():
    mesures = {"instant": "x", "hote": "h", "archives_config": {"nombre": 0}, "archives_mongo": {"nombre": 0},
               "unites": {}, "debit_snapshot_complet": None, "estimation_rto": inv.estimer_rto(None, None, None)}
    assert "n.d." in inv.rendre_markdown(mesures)


def test_namespace_defaults_point_to_documented_locations():
    parser_defaults = inv.main.__code__.co_consts
    assert "/var/backups/siem" in parser_defaults and "/home/siem-backup/mongo" in parser_defaults
