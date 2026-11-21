"""Contrôle des liens internes de la documentation (tools/check-doc-links.py)."""
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "check-doc-links.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("check_doc_links", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_has_no_broken_internal_link():
    tool = load_tool()
    broken = tool.check(ROOT)
    assert broken == [], "\n".join(f"{f}:{line} -> {t}" for f, line, t in broken)


def test_repository_text_references_to_docs_exist():
    tool = load_tool()
    refs = tool.check_text_refs(ROOT)
    assert refs == [], "\n".join(f"{f}:{line} -> {t}" for f, line, t in refs)


def test_checker_detects_broken_links_and_ignores_code(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "ok.md").write_text("# ok\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "[bon](docs/ok.md#section) [externe](https://example.org) [ancre](#x)\n"
        "[cassé](docs/absent.md)\n"
        "`[ignoré](docs/dans-du-code.md)`\n"
        "```\n[ignoré](docs/bloc.md)\n```\n"
        '<a href="docs/absent2.md">html</a>\n',
        encoding="utf-8",
    )
    (tmp_path / "script.sh").write_text("# voir docs/ok.md et docs/manquant.md\n", encoding="utf-8")
    tool = load_tool()
    broken = sorted(t for _, _, t in tool.check(tmp_path))
    assert broken == ["docs/absent.md", "docs/absent2.md"]
    refs = [t for _, _, t in tool.check_text_refs(tmp_path)]
    assert "docs/manquant.md" in refs and "docs/ok.md" not in refs


def test_cli_exit_code_reflects_result(tmp_path):
    (tmp_path / "README.md").write_text("[x](absent.md)\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(TOOL), "--root", str(tmp_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "absent.md" in proc.stdout
    (tmp_path / "absent.md").write_text("ok\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(TOOL), "--root", str(tmp_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 0


def test_strip_code_preserves_offsets():
    tool = load_tool()
    text = "a `code` [l](x.md)\n```\n[b](y.md)\n```\nfin"
    masked = tool.strip_code(text)
    assert len(masked) == len(text)
    assert masked.index("[l](x.md)") == text.index("[l](x.md)")
    assert "y.md" not in masked
