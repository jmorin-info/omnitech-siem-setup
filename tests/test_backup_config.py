"""30-backup-config.sh exécuté hors ligne : faux système de fichiers et fausses commandes.

Aucune commande réelle de stockage, de base ou de réseau n'est appelée : findmnt, lsblk,
blkid, cryptsetup, mongodump, mount, mountpoint, umount et curl sont remplacés par des
doublures qui journalisent leurs arguments. Seuls tar, openssl, od, shred et sha256sum
(locaux, sans effet hors du répertoire temporaire) sont réels.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "30-backup-config.sh"
UUID = "ff2e8939-0000-4000-8000-000000000001"
PASSPHRASE = "fixture-passphrase-sans-valeur"
pytestmark = pytest.mark.skipif(
    os.name == "nt" or not all(shutil.which(c) for c in ("openssl", "tar", "od", "shred", "sha256sum")),
    reason="Bash, tar et openssl requis",
)

FAKE = r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
nom = Path(sys.argv[0]).name
args = sys.argv[1:]
env = os.environ
with open(env["FIXTURE_CALLS"], "a") as log:
    log.write(nom + "\t" + "\t".join(" ".join(a.split()) for a in args) + "\n")
def entete(chemin, uuid):
    data = bytearray(b"LUKS\xba\xbe\x00\x02" + bytes(4096 - 8))
    u = uuid.encode()
    data[168:168 + len(u)] = u
    Path(chemin).write_bytes(bytes(data))
if nom == "findmnt":
    if env.get("FIXTURE_SOURCE"): print(env["FIXTURE_SOURCE"]); sys.exit(0)
    sys.exit(1)
elif nom == "cryptsetup":
    cmd = args[0]
    if cmd == "status":
        if env.get("FIXTURE_STATUS_KO"): sys.exit(4)
        print("/dev/mapper/%s is active and is in use.\n  type:    LUKS2\n  device:  /dev/sdb1" % args[1]); sys.exit(0)
    if cmd == "isLuks":
        sys.exit(0 if args[1] in env.get("FIXTURE_LUKS_DEVS", "").split() else 1)
    if cmd == "luksUUID":
        print(env.get("FIXTURE_UUID", "")); sys.exit(0)
    if cmd == "luksHeaderBackup":
        if env.get("FIXTURE_HEADER_KO"): sys.exit(1)
        cible = args[args.index("--header-backup-file") + 1]
        if os.path.exists(cible): sys.exit(1)
        entete(cible, env.get("FIXTURE_HEADER_UUID", env.get("FIXTURE_UUID", ""))); sys.exit(0)
    sys.exit(99)  # toute autre sous-commande est interdite
elif nom == "lsblk":
    print(env.get("FIXTURE_LSBLK", "")); sys.exit(0)
elif nom == "blkid":
    if args[:1] == ["-U"] and env.get("FIXTURE_BLKID"): print(env["FIXTURE_BLKID"]); sys.exit(0)
    sys.exit(2)
elif nom == "mongodump":
    out = Path(args[args.index("--out") + 1]) / "graylog"
    out.mkdir(parents=True)
    for c in ("streams", "pipeline_processor_pipelines", "pipeline_processor_rules", "event_definitions",
              "event_notifications", "inputs", "index_sets"):
        (out / (c + ".bson")).write_bytes(b"fixture")
elif nom == "mountpoint":
    sys.exit(0)
elif nom in ("mount", "umount", "curl"):
    sys.exit(0)
'''


def ecrire(chemin, texte="x\n"):
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(texte)


@pytest.fixture
def banc(tmp_path):
    racine = tmp_path / "racine"
    ecrire(racine / "etc/graylog/server/server.conf",
           "password_secret = fixture\n"
           "mongodb_uri = mongodb://premier:a@127.0.0.1:27017/graylog\n"
           "#mongodb_uri = mongodb://commente:b@127.0.0.1:27017/graylog\n"
           "mongodb_uri = mongodb://deuxieme:c@127.0.0.1:27017/graylog\n"
           "  mongodb_uri =  mongodb://effectif:d@127.0.0.1:27017/graylog?replicaSet=rs0  \n"
           "# mongodb_uri = mongodb://commente-fin:e@127.0.0.1:27017/graylog\n")
    ecrire(racine / "etc/graylog/lookup/mitre-attack.csv", "id,nom\n")
    ecrire(racine / "etc/mongod.conf", "security:\n  keyFile: /etc/mongod.keyfile\n")
    ecrire(racine / "etc/mongod.keyfile", "fixture-cle\n")
    for f in ("sites-available/siem", "sites-enabled/siem", "snippets/omni.conf", "conf.d/omni-ratelimit.conf",
              "nginx.conf"):
        ecrire(racine / "etc/nginx" / f)
    ecrire(racine / "var/www/siem-soc/index.html")
    ecrire(racine / "etc/default/omni-mobile", "FIXTURE=1\n")
    ecrire(racine / "etc/default/graylog-server")
    ecrire(racine / "etc/omni-alert-triage.env", "FIXTURE=1\n")
    ecrire(racine / "etc/omni-soar/soar.env", "FIXTURE=1\n")
    ecrire(racine / "etc/oms-ml/config.yaml")
    ecrire(racine / "opt/oms-seal-sla/seal_sla_poller.py")
    ecrire(racine / "opt/oms-seal-sla/.venv/bin/python")
    ecrire(racine / "opt/oms-seal-sla/__pycache__/seal.cpython-313.pyc")
    ecrire(racine / "etc/fstab", "# commentaire\n/dev/mapper/cryptdata /data xfs defaults,nofail 0 2\n")
    ecrire(racine / "etc/crypttab", "# <target>\ncryptdata UUID=%s none luks,nofail\n" % UUID)
    for i in range(120):
        ecrire(racine / "usr/local/sbin" / ("outil-%03d" % i))
    depot = racine / "opt/omni-siem/repository"
    depot.mkdir(parents=True)
    shutil.copy2(SCRIPT, depot / "30-backup-config.sh")
    ecrire(depot / "00-vars.env", "BACKUP_PASSPHRASE=%s\n" % PASSPHRASE)
    ecrire(depot / "oms-ml/.venv/lib/lourd.so")
    ecrire(depot / "README.md")

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nom in ("findmnt", "cryptsetup", "lsblk", "blkid", "mongodump", "mountpoint", "mount", "umount", "curl"):
        (bin_ / nom).write_text(FAKE)
        (bin_ / nom).chmod(0o755)
    env = {
        "PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % bin_,
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "TMPDIR": str(tmp_path),
        "OMNI_BACKUP_RACINE": str(racine),
        "OMNI_BACKUP_WORK": str(tmp_path / "work"),
        "OMNI_BACKUP_MNT": str(tmp_path / "mnt"),
        "OMNI_BACKUP_GELF_URL": "http://127.0.0.1:9/gelf",
        "SMB_CRED_FILE": str(tmp_path / "absent.cred"),
        "FIXTURE_CALLS": str(tmp_path / "calls.log"),
        "FIXTURE_SOURCE": "/dev/mapper/cryptdata",
        "FIXTURE_LSBLK": "/dev/mapper/cryptdata xfs\n/dev/sdb1 crypto_LUKS\n/dev/sdb ",
        "FIXTURE_LUKS_DEVS": "/dev/sdb1",
        "FIXTURE_UUID": UUID,
    }

    class Banc:
        pass
    b = Banc()
    b.tmp, b.racine, b.depot, b.env = tmp_path, racine, depot, env

    def lancer(**surcharges):
        e = dict(env)
        for k, v in surcharges.items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
        return subprocess.run(["bash", str(depot / "30-backup-config.sh")], env=e,
                              capture_output=True, text=True, timeout=120)
    b.lancer = lancer

    def appels(outil=None):
        log = tmp_path / "calls.log"
        lignes = [l.split("\t") for l in log.read_text().splitlines()] if log.exists() else []
        return [l[1:] for l in lignes if outil is None or l[0] == outil]
    b.appels = appels

    def archive():
        encs = sorted((tmp_path / "work").glob("omni-siem-config_*.tar.gz.enc"))
        assert len(encs) == 1
        clair = tmp_path / "verif.tar.gz"
        subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-in", str(encs[0]),
                        "-out", str(clair), "-pass", "pass:" + PASSPHRASE], check=True)
        return tarfile.open(clair, "r:gz")
    b.archive = archive

    def gelf():
        return [" ".join(a) for a in appels("curl")]
    b.gelf = gelf
    return b


def test_nominal_archive_tous_les_elements_de_reprise(banc):
    r = banc.lancer()
    assert r.returncode == 0, r.stderr + r.stdout
    assert "en-tete LUKS /data inclus (/dev/sdb1" in r.stdout
    with banc.archive() as tar:
        noms = set(tar.getnames())
        entete = tar.extractfile("luks/data-header.img").read()
        meta = tar.extractfile("luks/data-header.txt").read().decode()
    for attendu in ("luks/data-header.img", "etc/mongod.keyfile", "etc/nginx/sites-enabled/siem",
                    "etc/nginx/sites-available/siem", "etc/nginx/snippets/omni.conf",
                    "etc/nginx/conf.d/omni-ratelimit.conf", "var/www/siem-soc/index.html",
                    "etc/default/omni-mobile", "etc/omni-alert-triage.env", "etc/omni-soar/soar.env",
                    "etc/oms-ml/config.yaml", "opt/oms-seal-sla/seal_sla_poller.py",
                    "etc/graylog/lookup/mitre-attack.csv", "mongodump/graylog/streams.bson",
                    "opt/omni-siem/repository/README.md"):
        assert attendu in noms, attendu
    assert not [n for n in noms if "/.venv" in n or "__pycache__" in n or n.endswith(".pyc")]
    assert entete[:6] == b"LUKS\xba\xbe" and UUID.encode() in entete[168:208]
    assert "peripherique=/dev/sdb1" in meta and "uuid=" + UUID in meta and "sha256=" in meta
    # copie sur le partage, aucune archive en clair déposée
    assert len(list((banc.tmp / "mnt/SIEM-Sauvegardes").glob("*.tar.gz.enc"))) == 1
    assert not list((banc.tmp / "work").glob("*.tar.gz"))
    gelf = banc.gelf()
    assert any("backup_config_ok" in g and "en-tete LUKS : inclus" in g for g in gelf)
    assert not any("backup_config_echec" in g for g in gelf)
    assert all("127.0.0.1:9/gelf" in g for g in gelf)


def test_mongodb_uri_derniere_ligne_effective(banc):
    assert banc.lancer().returncode == 0
    (args,) = banc.appels("mongodump")
    assert "--uri=mongodb://effectif:d@127.0.0.1:27017/graylog?replicaSet=rs0" in args


def test_cryptsetup_lecture_seule_et_destination_temporaire(banc):
    assert banc.lancer().returncode == 0
    appels = banc.appels("cryptsetup")
    assert {a[0] for a in appels} <= {"status", "isLuks", "luksUUID", "luksHeaderBackup"}
    (sauvegarde,) = [a for a in appels if a[0] == "luksHeaderBackup"]
    assert sauvegarde[1] == "/dev/sdb1"
    assert sauvegarde[3].startswith(str(banc.tmp)) and sauvegarde[3].endswith("/luks/data-header.img")
    assert ["status", "cryptdata"] in appels
    assert not (banc.racine / "dev").exists()


def test_detection_par_lsblk_si_status_indisponible(banc):
    r = banc.lancer(FIXTURE_STATUS_KO="1")
    assert r.returncode == 0, r.stderr
    assert "/dev/sdb1" in [a[1] for a in banc.appels("cryptsetup") if a[0] == "luksHeaderBackup"]


def test_detection_par_fstab_et_crypttab_si_data_non_monte(banc):
    r = banc.lancer(FIXTURE_SOURCE=None, FIXTURE_STATUS_KO="1", FIXTURE_LSBLK="", FIXTURE_BLKID="/dev/sdb1")
    assert r.returncode == 0, r.stderr
    assert ["-U", UUID] in banc.appels("blkid")
    with banc.archive() as tar:
        assert "luks/data-header.img" in tar.getnames()


def test_peripherique_force(banc):
    r = banc.lancer(LUKS_DEVICE="/dev/vdz9", FIXTURE_LUKS_DEVS="/dev/vdz9")
    assert r.returncode == 0, r.stderr
    assert [a[1] for a in banc.appels("cryptsetup") if a[0] == "luksHeaderBackup"] == ["/dev/vdz9"]


def test_elements_facultatifs_absents_ne_font_pas_echouer(banc):
    for chemin in ("etc/mongod.keyfile", "var/www/siem-soc", "opt/oms-seal-sla", "etc/nginx/snippets",
                   "etc/nginx/conf.d", "etc/omni-soar", "etc/default/omni-mobile", "etc/crypttab"):
        p = banc.racine / chemin
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    r = banc.lancer(FIXTURE_SOURCE="/dev/sdc1", FIXTURE_LSBLK="/dev/sdc1 xfs\n/dev/sdc ", FIXTURE_LUKS_DEVS="")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "en-tete LUKS : non concerne" in r.stdout
    with banc.archive() as tar:
        noms = tar.getnames()
    assert not [n for n in noms if n.startswith("luks")] and "etc/mongod.keyfile" not in noms
    assert not any("backup_config_echec" in g for g in banc.gelf())
    assert not [a for a in banc.appels("cryptsetup") if a[0] == "luksHeaderBackup"]


@pytest.mark.parametrize("panne", [{"FIXTURE_HEADER_KO": "1"}, {"FIXTURE_HEADER_UUID": "autre-uuid"},
                                   {"FIXTURE_LUKS_DEVS": ""}, {"FIXTURE_STATUS_KO": "1", "FIXTURE_LSBLK": ""}])
def test_entete_attendu_absent_archive_expediee_et_alerte(banc, panne):
    if "FIXTURE_LSBLK" in panne:  # crypttab illisible : plus aucun moyen de détection
        (banc.racine / "etc/crypttab").unlink()
    r = banc.lancer(**panne)
    assert r.returncode == 0, r.stderr
    assert "en-tete LUKS NON sauvegarde" in r.stdout
    with banc.archive() as tar:
        assert not [n for n in tar.getnames() if n.startswith("luks")]
    assert len(list((banc.tmp / "mnt/SIEM-Sauvegardes").glob("*.tar.gz.enc"))) == 1
    gelf = banc.gelf()
    assert any("backup_config_ok" in g for g in gelf)
    assert any("backup_config_echec" in g and "SANS en-tete LUKS" in g for g in gelf)


def test_element_present_mais_absent_de_l_archive_bloque_l_envoi(banc):
    # Fichier présent sur la source mais écarté par les exclusions : la vérification doit refuser.
    ecrire(banc.racine / "etc/default/omni-piege.pyc")
    r = banc.lancer()
    assert r.returncode == 1
    assert "etc/default/omni-piege.pyc absent de l'archive" in r.stderr
    assert not (banc.tmp / "mnt/SIEM-Sauvegardes").exists() or not list((banc.tmp / "mnt/SIEM-Sauvegardes").iterdir())
    assert any("backup_config_echec" in g for g in banc.gelf())
    assert not any("backup_config_ok" in g for g in banc.gelf())


def test_uri_mongodb_absente_echoue_proprement(banc):
    ecrire(banc.racine / "etc/graylog/server/server.conf", "# mongodb_uri = mongodb://x@h/graylog\n")
    r = banc.lancer()
    assert r.returncode == 1 and "mongodb_uri introuvable" in r.stderr
    assert not banc.appels("mongodump")


def test_valeurs_par_defaut_de_production():
    source = SCRIPT.read_text()
    for defaut in ('OMNI_BACKUP_RACINE:-/}', 'OMNI_BACKUP_WORK:-/var/backups/siem}', 'OMNI_BACKUP_MNT:-/mnt/siem-backup}',
                   'OMNI_BACKUP_GELF_URL:-http://127.0.0.1:12201/gelf}', 'LUKS_MOUNTPOINT:-/data}'):
        assert defaut in source
    assert "isLuks /dev/sda1" not in source and "luksHeaderBackup /dev/sda1" not in source


def test_timers_de_sauvegarde_rattrapent_une_execution_manquee():
    systemd = ROOT / "deploye/systemd"
    for timer in ("oms-snap-siem.timer", "omni-backup-config.timer"):
        assert "Persistent=true" in (systemd / timer).read_text(), timer
    # La mise à jour avec redémarrage reste volontairement sans rattrapage.
    assert "Persistent=false" in (systemd / "oms-maj-siem.timer").read_text()
