"""tools/retirer-ancienne-copie.sh : contrôles, mv + lien et retour arrière, hors ligne.

systemctl est simulé et /proc, les répertoires systemd et cron sont des répertoires
temporaires : aucune lecture de l'état réel de la machine.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "retirer-ancienne-copie.sh"
pytestmark = pytest.mark.skipif(os.name == "nt", reason="Bash requis")
APRES = int(dt.datetime(2026, 11, 23, 10, 5).timestamp())
AVANT = int(dt.datetime(2026, 11, 23, 9, 55).timestamp())

FAKE_SYSTEMCTL = r'''#!/bin/bash
# systemctl show <unité> -p ... : propriétés effectives lues dans $FAKE_UNITS/<unité>
[[ "$1" == show ]] || exit 0
cat "$FAKE_UNITS/$2" 2>/dev/null
'''


@pytest.fixture
def site(tmp_path):
    canon, ancien = tmp_path / "canon", tmp_path / "root" / "omnitech-siem-setup"
    for repo in (canon, ancien):
        repo.mkdir(parents=True)
        (repo / "README").write_text("x\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "00-vars.env").write_text("SECRET_DE_TEST=valeur\n")
        (repo / "00-vars.env").chmod(0o600)
    (ancien / "SECRETS.md").write_text("valeur\n")
    (ancien / "00-vars.env.example").write_text("x\n")
    (ancien / "kit").mkdir()
    (ancien / "kit" / "client.key").write_text("valeur\n")
    systemd = tmp_path / "systemd"
    (systemd / "omni-disk-guard.service.d").mkdir(parents=True)
    (systemd / "omni-disk-guard.service").write_text(f"[Service]\nExecStart=/usr/bin/bash {ancien}/32-disk-guard.sh\n")
    (systemd / "omni-disk-guard.service.d" / "50-depot-reference.conf").write_text(
        f"[Service]\nExecStart=\nExecStart=/usr/bin/bash {canon}/32-disk-guard.sh\n")
    units = tmp_path / "units"
    units.mkdir()
    (units / "omni-disk-guard.service").write_text(f"ExecStart={{ path=/usr/bin/bash ; argv[]=/usr/bin/bash {canon}/32-disk-guard.sh }}\n")
    proc = tmp_path / "proc"
    (proc / "4242" / "fd").mkdir(parents=True)
    (proc / "4242" / "cmdline").write_bytes(b"/usr/bin/python3\0/opt/x.py\0")
    os.symlink("/", proc / "4242" / "cwd")
    cron = tmp_path / "cron"
    cron.mkdir()
    (cron / "omni").write_text("0 1 * * * root /usr/local/sbin/x\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "systemctl").write_text(FAKE_SYSTEMCTL)
    (bindir / "systemctl").chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "OMNI_SIEM_HOME": str(canon),
           "MIGRATION_ANCIEN": str(ancien), "MIGRATION_ARCHIVES": str(tmp_path / "archives"),
           "RETRAIT_ETAT": str(tmp_path / "etat"), "RETRAIT_MAINTENANT": str(APRES),
           "RETRAIT_SYSTEMD_DIRS": str(systemd), "RETRAIT_CRON": str(cron), "RETRAIT_PROC": str(proc),
           "RETRAIT_TEST_MODE": "1", "FAKE_UNITS": str(units)}

    def run(*args, **extra):
        return subprocess.run(["bash", str(SCRIPT), *args], env={**env, **extra},
                              capture_output=True, text=True, timeout=60)

    return {"run": run, "canon": canon, "ancien": ancien, "units": units, "proc": proc, "cron": cron,
            "tmp": tmp_path}


def test_plan_is_read_only_and_lists_plaintext_secrets_without_content(site):
    result = site["run"]()
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "configuration effective repointée" in out          # unité de base + drop-in
    assert "secret en clair : 00-vars.env" in out and "secret en clair : SECRETS.md" in out
    assert "secret en clair : kit/client.key" in out and "00-vars.env.example" not in out
    assert "valeur" not in out + result.stderr
    assert site["ancien"].is_dir() and not site["ancien"].is_symlink()
    assert not (site["tmp"] / "etat").exists()


def test_apply_renames_links_and_rollback_restores(site):
    result = site["run"]("--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    ancien = site["ancien"]
    retire = ancien.with_name("omnitech-siem-setup.retire-20261123")
    assert ancien.is_symlink() and os.readlink(ancien) == str(site["canon"])
    assert (retire / "SECRETS.md").exists()
    listed = (site["tmp"] / "etat" / "secrets-a-supprimer.txt").read_text().splitlines()
    assert str(retire / "SECRETS.md") in listed and all(line.startswith(str(retire)) for line in listed)
    again = site["run"]("--apply")
    assert again.returncode != 0 and "déjà un lien symbolique" in again.stdout
    back = site["run"]("--rollback")
    assert back.returncode == 0, back.stdout + back.stderr
    assert ancien.is_dir() and not ancien.is_symlink() and not retire.exists()


@pytest.mark.parametrize("cas", ["date", "unite", "processus", "cron", "env"])
def test_each_control_blocks_apply(site, cas):
    extra = {}
    if cas == "date":
        extra["RETRAIT_MAINTENANT"] = str(AVANT)
        attendu = "pas avant le 2026-11-23 10:00"
    elif cas == "unite":
        (site["units"] / "omni-disk-guard.service").write_text(
            f"WorkingDirectory={site['ancien']}\nExecStart={{ path=/usr/bin/bash }}\n")
        attendu = "unité omni-disk-guard.service : configuration effective utilisant"
    elif cas == "processus":
        os.unlink(site["proc"] / "4242" / "cwd")
        os.symlink(site["ancien"] / "mobile", site["proc"] / "4242" / "cwd")
        attendu = "processus 4242"
    elif cas == "cron":
        (site["cron"] / "ancien").write_text(f"0 2 * * * root {site['ancien']}/x.sh\n")
        attendu = "tâche cron citant"
    else:
        (site["ancien"] / "00-vars.env").write_text("SECRET_DE_TEST=autre\n")
        attendu = "00-vars.env diffère"
    result = site["run"]("--apply", **extra)
    assert result.returncode != 0
    assert attendu in result.stdout
    assert site["ancien"].is_dir() and not site["ancien"].is_symlink()
    assert "valeur" not in result.stdout and "autre" not in result.stdout


def test_rollback_refuses_a_foreign_link(site, tmp_path):
    ancien = site["ancien"]
    ancien.rename(ancien.with_name("omnitech-siem-setup.retire-20261123"))
    os.symlink(tmp_path / "ailleurs", ancien)
    result = site["run"]("--rollback")
    assert result.returncode != 0 and "intervention manuelle" in result.stderr
    assert ancien.is_symlink()
