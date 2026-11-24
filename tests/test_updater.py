"""Updates must preserve tenant data and stop before overwriting local work."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

SPEC = importlib.util.spec_from_file_location("omni_update", Path(__file__).resolve().parents[1] / "tools/omni-update.py")
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()


def put(repo, name, text):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit(repo, message):
    git(repo, "add", ".")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def installation(tmp_path):
    source, state = tmp_path / "source", tmp_path / "updater"
    source.mkdir()
    git(source, "init")
    git(source, "config", "user.name", "Update tests")
    git(source, "config", "user.email", "tests@example.invalid")
    git(source, "config", "core.autocrlf", "false")
    put(source, ".gitignore", "00-vars.env\n")
    put(source, "mobile/soc/app.js", "const version = 1;\n")
    put(source, "mobile/omni-mobile-api.py", "version = 1\n")
    put(source, "tools/omni-soc-kpi.py", "version = 1\n")
    put(source, "oms-xdr/config.yaml", "site: example\n")
    base = commit(source, "base")
    put(source, "mobile/soc/app.js", "const version = 2;\n")
    put(source, "mobile/omni-mobile-api.py", "version = 2\n")
    put(source, "tools/omni-soc-kpi.py", "version = 2\n")
    put(source, "oms-xdr/config.yaml", "site: upstream-new-example\n")
    target = commit(source, "code update and configuration example")
    git(source, "checkout", base)
    put(source, "00-vars.env", "SITE_PRIVATE_VALUE=local-only\n")
    put(source, "oms-xdr/config.yaml", "site: tenant-customization\n")
    return source, state, base, target


def test_plan_is_read_only_and_reports_withheld_config(installation):
    source, state, base, target = installation
    result = updater.plan(source, state, target)
    assert result["can_apply_code"]
    assert result["source_head"] == base
    assert result["preserved_or_manual_files"] == ["oms-xdr/config.yaml"]
    assert not state.exists()


def test_update_and_rollback_keep_tenant_configuration_and_git_head(installation):
    source, state, base, target = installation
    widgets = source.parent / "local-state/modules/modules.json"
    widgets.parent.mkdir(parents=True)
    widgets.write_text('{"schema_version":1,"pages":[{"id":"site-watchguard"}]}\n')
    before_widgets = widgets.read_bytes()
    updater.stage(source, state, target)
    applied = updater.apply_code(source, state, target)
    assert (source / "mobile/soc/app.js").read_text() == "const version = 2;\n"
    assert (source / "tools/omni-soc-kpi.py").read_text() == "version = 2\n"
    assert widgets.read_bytes() == before_widgets
    assert (source / "00-vars.env").read_text() == "SITE_PRIVATE_VALUE=local-only\n"
    assert (source / "oms-xdr/config.yaml").read_text() == "site: tenant-customization\n"
    assert git(source, "rev-parse", "HEAD") == base
    assert updater.plan(source, state, target)["code_files"] == []
    updater.restore(source, state, applied["transaction"])
    assert (source / "mobile/soc/app.js").read_text() == "const version = 1;\n"
    assert (source / "tools/omni-soc-kpi.py").read_text() == "version = 1\n"
    assert widgets.read_bytes() == before_widgets
    assert (source / "oms-xdr/config.yaml").read_text() == "site: tenant-customization\n"
    assert not (state / "current.json").exists()


def test_local_code_changes_block_before_any_file_is_copied(installation):
    source, state, _, target = installation
    put(source, "mobile/soc/app.js", "tenant edit\n")
    result = updater.plan(source, state, target)
    assert result["conflicts"] == ["mobile/soc/app.js"]
    updater.stage(source, state, target)
    with pytest.raises(updater.UpdateError, match="manual review"):
        updater.apply_code(source, state, target)
    assert (source / "mobile/soc/app.js").read_text() == "tenant edit\n"
    assert not (state / "backups").exists()


def test_changed_database_installation_script_blocks_automatic_code_update(installation):
    source, state, base, target = installation
    git(source, "checkout", "--", "oms-xdr/config.yaml")
    git(source, "checkout", target)
    put(source, "04-graylog.sh", "new-version-installation\n")
    migration = commit(source, "dependency change")
    git(source, "checkout", base)
    result = updater.plan(source, state, migration)
    assert result["migration_review_required"] == ["04-graylog.sh"]
    assert not result["can_apply_code"]


def test_modified_stage_is_rejected(installation):
    source, state, _, target = installation
    staged = updater.stage(source, state, target)
    path = staged / "mobile/soc/app.js"
    path.chmod(0o644)
    path.write_text("tampered\n")
    with pytest.raises(updater.UpdateError, match="integrity"):
        updater.apply_code(source, state, target)
    assert (source / "mobile/soc/app.js").read_text() == "const version = 1;\n"


def test_rollback_refuses_to_destroy_edits_made_after_update(installation):
    source, state, _, target = installation
    updater.stage(source, state, target)
    applied = updater.apply_code(source, state, target)
    put(source, "mobile/soc/app.js", "new tenant edit\n")
    with pytest.raises(updater.UpdateError, match="Local file changed"):
        updater.restore(source, state, applied["transaction"])
    assert (source / "mobile/soc/app.js").read_text() == "new tenant edit\n"


def test_copy_failure_rolls_back_already_copied_files(installation, monkeypatch):
    source, state, _, target = installation
    updater.stage(source, state, target)
    original = updater.atomic
    failed = False

    def atomic(path, data, mode):
        nonlocal failed
        if path == source / "mobile/soc/app.js" and not failed:
            failed = True
            raise OSError("simulated disk error")
        return original(path, data, mode)

    monkeypatch.setattr(updater, "atomic", atomic)
    with pytest.raises(OSError, match="simulated disk error"):
        updater.apply_code(source, state, target)
    assert (source / "mobile/omni-mobile-api.py").read_text() == "version = 1\n"
    assert (source / "mobile/soc/app.js").read_text() == "const version = 1;\n"
    assert not (state / "current.json").exists()


@pytest.mark.parametrize("path", ["../outside", "/absolute", "safe/../../outside", "C:/absolute", "safe\\outside"])
def test_path_escape_is_rejected(tmp_path, path):
    with pytest.raises(updater.UpdateError):
        updater.safe_path(tmp_path, path)


@pytest.mark.parametrize("url", ["http://example.invalid/repo.git", "https://user:pass@example.invalid/repo.git", "https://example.invalid/repo.git?secret=value"])
def test_unsafe_remote_is_rejected_before_creating_state(tmp_path, url):
    state = tmp_path / "state"
    with pytest.raises(updater.UpdateError, match="HTTPS"):
        updater.fetch(tmp_path / "source", state, url, "main")
    assert not state.exists()


def test_untracked_file_colliding_with_new_upstream_code_is_preserved(installation):
    source, state, base, target = installation
    git(source, "checkout", "--", "oms-xdr/config.yaml")
    git(source, "checkout", target)
    put(source, "mobile/soc/new.js", "upstream\n")
    newer = commit(source, "new asset")
    git(source, "checkout", base)
    put(source, "mobile/soc/new.js", "local custom asset\n")
    result = updater.plan(source, state, newer)
    assert "mobile/soc/new.js" in result["conflicts"]
    assert (source / "mobile/soc/new.js").read_text() == "local custom asset\n"


@pytest.mark.parametrize("name", ["stack-versions.env", "oms-xdr/requirements.txt", "docker/Dockerfile.console"])
def test_dependency_changes_require_review(installation, name):
    source, state, base, target = installation
    git(source, "checkout", "--", "oms-xdr/config.yaml")
    git(source, "checkout", target)
    put(source, name, "dependency or version changed\n")
    newer = commit(source, "dependency changed")
    git(source, "checkout", base)
    information = updater.plan(source, state, newer)
    assert name in information["migration_review_required"]
    assert not information["can_apply_code"]


def test_recover_restores_a_partial_transaction(installation):
    source, state, _, target = installation
    updater.stage(source, state, target)
    applied = updater.apply_code(source, state, target)
    journal_path = state / "backups" / applied["transaction"] / "transaction.json"
    journal = updater.read_json(journal_path)
    journal["status"] = "applying"
    updater.write_json(journal_path, journal)
    (state / "current.json").unlink()
    # Simulate interruption after only the first file was copied.
    put(source, "mobile/soc/app.js", "const version = 1;\n")
    updater.restore(source, state, applied["transaction"], interrupted=True)
    assert (source / "mobile/omni-mobile-api.py").read_text() == "version = 1\n"
    assert (source / "mobile/soc/app.js").read_text() == "const version = 1;\n"


def test_corrupt_backup_is_detected_before_any_rollback_copy(installation):
    source, state, _, target = installation
    updater.stage(source, state, target)
    applied = updater.apply_code(source, state, target)
    backup = state / "backups" / applied["transaction"] / "files/mobile/soc/app.js"
    backup.write_text("corrupt\n")
    with pytest.raises(updater.UpdateError, match="Backup integrity"):
        updater.restore(source, state, applied["transaction"])
    assert (source / "mobile/omni-mobile-api.py").read_text() == "version = 2\n"
    assert (source / "mobile/soc/app.js").read_text() == "const version = 2;\n"


def test_invalid_python_candidate_cannot_be_applied(installation):
    source, state, base, target = installation
    git(source, "checkout", "--", "oms-xdr/config.yaml")
    git(source, "checkout", target)
    put(source, "mobile/omni-mobile-api.py", "def broken syntax\n")
    newer = commit(source, "invalid source")
    git(source, "checkout", base)
    updater.stage(source, state, newer)
    with pytest.raises(updater.UpdateError, match="syntax validation"):
        updater.apply_code(source, state, newer)
    assert not (state / "backups").exists()
    assert (source / "mobile/omni-mobile-api.py").read_text() == "version = 1\n"
