"""Contrôles de la CI rejouables hors ligne : scan de secrets et lint (si les outils sont présents)."""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_tree_secret_scan_is_clean():
    result = subprocess.run(["bash", str(ROOT / "scan-depot.sh"), "--arbre"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout


def test_tree_secret_scan_detects_and_masks(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    # Valeur factice assemblée à l'exécution pour ne pas déclencher le scan sur ce fichier.
    (tmp_path / "conf").write_text("pass" + 'word="' + "Zx9kQ2mLp4Rt8vWn3" + '"\n')
    subprocess.run(["git", "add", "conf"], cwd=tmp_path, check=True)
    result = subprocess.run(["bash", str(ROOT / "scan-depot.sh"), "--arbre"], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1 and "Zx9kQ2mLp4Rt8vWn3" not in result.stdout


def test_lint_has_no_new_findings():
    bindir = Path(sys.executable).parent
    shellcheck = shutil.which("shellcheck", path=str(bindir)) or shutil.which("shellcheck")
    ruff = shutil.which("ruff", path=str(bindir)) or shutil.which("ruff")
    if not shellcheck or not ruff:
        pytest.skip("shellcheck/ruff absents : pip install -r requirements-lint.txt")
    result = subprocess.run(["bash", str(ROOT / "tools/ci-lint.sh")], cwd=ROOT, capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin", "SHELLCHECK": shellcheck, "RUFF": ruff})
    assert result.returncode == 0, result.stdout[-3000:]


@pytest.mark.parametrize("missing", ["SHELLCHECK", "RUFF"])
def test_lint_fails_when_a_required_tool_is_missing(missing):
    env = {"PATH": "/usr/bin:/bin", "SHELLCHECK": "/bin/true", "RUFF": "/bin/true"}
    env[missing] = "/missing/omni-lint-tool"
    result = subprocess.run(["bash", str(ROOT / "tools/ci-lint.sh")], cwd=ROOT, capture_output=True, text=True, env=env)
    assert result.returncode == 2 and "indisponible" in result.stderr
    assert "aucun nouveau constat" not in result.stdout
