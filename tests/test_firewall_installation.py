"""Exercise firewall persistence and failure recovery without touching the host."""
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("firewall_install", ROOT / "tools/install-firewall.py")
firewall = module_from_spec(spec)
spec.loader.exec_module(firewall)


class Commands:
    def __init__(self, *, fail=None, enabled="disabled"):
        self.calls = []
        self.fail = fail
        self.enabled = enabled
        self.tables = {"foreign": "keep", "omni_siem": "old"}

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        assert not any(word in argv for word in ("restart", "stop", "reload", "flush", "--now"))
        if argv[:2] == ["systemctl", "is-enabled"]:
            return subprocess.CompletedProcess(argv, 0 if self.enabled == "enabled" else 1, self.enabled + "\n", "")
        if argv[:2] == ["nft", "-c"]:
            if self.fail == "validate" or self.fail == "boot" and Path(argv[-1]).name == "nftables.conf":
                raise subprocess.CalledProcessError(1, argv)
        elif argv[:2] == ["nft", "-f"]:
            assert b"flush ruleset" not in Path(argv[-1]).read_bytes()
            if self.fail == "apply":
                raise subprocess.CalledProcessError(1, argv)
            self.tables["omni_siem"] = "new"
        elif argv[:2] == ["systemctl", "enable"]:
            if self.fail == "enable":
                raise subprocess.CalledProcessError(1, argv)
            self.enabled = "enabled-runtime" if "--runtime" in argv else "enabled"
        elif argv[:2] == ["systemctl", "disable"]:
            self.enabled = "disabled"
        else:
            pytest.fail("unexpected command: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0)


@pytest.fixture
def files(tmp_path):
    config = tmp_path / "etc/nftables.conf"
    fragment = tmp_path / "etc/nftables.d/omni-siem.nft"
    config.parent.mkdir()
    fragment.parent.mkdir()
    config.write_text('# Existing policy must survive byte for byte.\nflush ruleset\ntable inet foreign { }\n')
    config.chmod(0o640)
    fragment.write_text("# old dedicated policy\n")
    fragment.chmod(0o600)
    candidate = tmp_path / "candidate.nft"
    candidate.write_text("add table inet omni_siem\nflush table inet omni_siem\ntable inet omni_siem { }\n")
    return candidate, config, fragment, tmp_path / "backups"


def test_namespaced_application_preserves_runtime_and_boot_policy(files, monkeypatch):
    candidate, config, fragment, backups = files
    before = config.read_bytes()
    commands = Commands()
    monkeypatch.setattr(subprocess, "run", commands)
    directory = firewall.install(*files)
    assert config.read_bytes().startswith(before)
    assert config.read_text().count('include "' + fragment.as_posix() + '"') == 1
    assert fragment.read_bytes() == candidate.read_bytes()
    assert commands.tables == {"foreign": "keep", "omni_siem": "new"}
    assert (directory / "nftables.conf").read_bytes() == before
    assert (directory / "omni-siem.nft").read_text() == "# old dedicated policy\n"
    assert json.loads((directory / "manifest.json").read_text())["nftables.conf"]["exists"] is True
    assert ["nft", "-f", str(config)] not in commands.calls
    assert ["systemctl", "enable", "nftables"] in commands.calls
    if os.name == "posix":
        assert directory.stat().st_mode & 0o077 == 0
        assert all(path.stat().st_mode & 0o077 == 0 for path in directory.iterdir())
        assert config.stat().st_mode & 0o777 == 0o640
    firewall.install(*files)
    assert config.read_text().count('include "' + fragment.as_posix() + '"') == 1


@pytest.mark.parametrize("failure", ["validate", "boot", "enable", "apply"])
@pytest.mark.parametrize("enabled", ["disabled", "enabled", "enabled-runtime"])
def test_failure_preserves_original_configs_tables_and_service_enablement(files, monkeypatch, failure, enabled):
    candidate, config, fragment, backups = files
    before = {path: path.read_bytes() for path in (config, fragment)}
    commands = Commands(fail=failure, enabled=enabled)
    monkeypatch.setattr(subprocess, "run", commands)
    with pytest.raises(subprocess.CalledProcessError):
        firewall.install(*files)
    assert all(path.read_bytes() == data for path, data in before.items())
    assert commands.tables == {"foreign": "keep", "omni_siem": "old"}
    assert commands.enabled == enabled
    if failure == "validate":
        assert not backups.exists()
    if os.name == "posix":
        assert config.stat().st_mode & 0o777 == 0o640


def test_failure_removes_new_configs_when_previously_absent(files, monkeypatch):
    candidate, config, fragment, backups = files
    config.unlink()
    fragment.unlink()
    commands = Commands(fail="apply")
    monkeypatch.setattr(subprocess, "run", commands)
    with pytest.raises(subprocess.CalledProcessError):
        firewall.install(*files)
    assert not config.exists() and not fragment.exists()


@pytest.mark.parametrize("pattern", ["explicit", "wildcard", "relative"])
def test_existing_include_is_preserved_without_duplicate(files, monkeypatch, pattern):
    _, config, fragment, _ = files
    path = {"explicit": fragment.as_posix(), "wildcard": fragment.parent.as_posix() + "/*.nft", "relative": "nftables.d/*.nft"}[pattern]
    before = ('# Keep custom formatting\ninclude "' + path + '"\n').encode()
    config.write_bytes(before)
    monkeypatch.setattr(subprocess, "run", Commands())
    firewall.install(*files)
    assert config.read_bytes() == before


def test_legacy_inline_table_requires_review_instead_of_duplicate_rules(files, monkeypatch):
    _, config, fragment, _ = files
    config.write_text("table inet omni_siem { }\n")
    before = config.read_bytes()
    commands = Commands()
    monkeypatch.setattr(subprocess, "run", commands)
    with pytest.raises(ValueError, match="inline"):
        firewall.install(*files)
    assert config.read_bytes() == before and commands.calls == []


def test_candidate_cannot_flush_global_ruleset(files, monkeypatch):
    candidate, config, _, _ = files
    before = config.read_bytes()
    candidate.write_text("flush ruleset\nflush table inet omni_siem\n")
    commands = Commands()
    monkeypatch.setattr(subprocess, "run", commands)
    with pytest.raises(ValueError, match="dedicated"):
        firewall.install(*files)
    assert config.read_bytes() == before and commands.calls == []


def test_shell_entrypoint_uses_persistence_helper_without_service_restart():
    script = (ROOT / "06-firewall.sh").read_text()
    assert 'tools/install-firewall.py --candidate "$TMP"' in script
    assert "systemctl restart" not in script and "systemctl stop" not in script
