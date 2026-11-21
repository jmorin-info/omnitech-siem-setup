"""Script de migration vers le dépôt canonique : plan en lecture seule et blocages."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/migrer-chemin-canonique.sh"


def git_repo(path: Path, files: dict[str, str]):
    path.mkdir(parents=True)
    for name, content in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(content)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}
    for argv in (["init", "-q"], ["add", "."], ["commit", "-qm", "init"]):
        subprocess.run(["git", "-C", str(path), *argv], check=True, env=env, capture_output=True)


def run(tmp_path, *args):
    env = {**os.environ, "OMNI_SIEM_HOME": str(tmp_path / "canon"), "MIGRATION_ANCIEN": str(tmp_path / "ancien"),
           "MIGRATION_ARCHIVES": str(tmp_path / "archives")}
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env)


def snapshot(path: Path):
    return sorted((str(p.relative_to(path)), p.read_bytes() if p.is_file() else b"") for p in path.rglob("*")
                  if ".git" not in p.parts)


def test_plan_reports_env_copy_and_changes_nothing(tmp_path):
    git_repo(tmp_path / "canon", {"omni_deploy/engine.py": "", "mobile/requirements.txt": "pywebpush\n",
                                  "lib-platform.sh": (ROOT / "lib-platform.sh").read_text()})
    git_repo(tmp_path / "ancien", {"README": "x"})
    (tmp_path / "ancien/00-vars.env").write_text("SECRET_DE_TEST=valeur\n")
    before = snapshot(tmp_path)
    result = run(tmp_path)
    assert result.returncode == 0, result.stdout
    assert "sera copié" in result.stdout and "Plan seul (0 blocage(s))" in result.stdout
    assert "valeur" not in result.stdout + result.stderr
    assert snapshot(tmp_path) == before and not (tmp_path / "archives").exists()


def test_diverging_site_configuration_blocks_apply(tmp_path):
    git_repo(tmp_path / "canon", {"omni_deploy/engine.py": ""})
    git_repo(tmp_path / "ancien", {"README": "x"})
    (tmp_path / "canon/00-vars.env").write_text("A=1\n")
    (tmp_path / "canon/00-vars.env").chmod(0o600)
    (tmp_path / "ancien/00-vars.env").write_text("A=2\n")
    plan = run(tmp_path)
    assert plan.returncode == 2 and "diffère" in plan.stdout
    applied = run(tmp_path, "--apply")
    assert applied.returncode == 2 and "refusée" in applied.stderr
    assert not (tmp_path / "archives").exists()


def test_canonical_clone_without_deploy_tool_is_blocked(tmp_path):
    git_repo(tmp_path / "canon", {"README": "x"})
    result = run(tmp_path)
    assert result.returncode == 2 and "omni_deploy absent" in result.stdout


def test_unknown_option_is_refused(tmp_path):
    assert run(tmp_path, "--force").returncode == 2


def test_missing_api_normalisation_blocks_disk_guard_repointing(tmp_path):
    git_repo(tmp_path / "canon", {"omni_deploy/engine.py": "", "mobile/requirements.txt": "pywebpush\n",
                                  "lib-platform.sh": 'API="${API%/}"\n'})
    result = run(tmp_path)
    assert result.returncode == 2 and "ne normalise pas /api" in result.stdout
