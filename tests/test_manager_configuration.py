"""Administration settings: private secrets, safe round trips and local preservation."""
from pathlib import Path
import os
import shlex

import pytest

from manager.configuration import Configuration


@pytest.fixture
def settings(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    reference = Path(__file__).resolve().parents[1] / "00-vars.env.example"
    (source / "00-vars.env.example").write_bytes(reference.read_bytes())
    state = tmp_path / "state"
    instance = Configuration(source=source, state=state)
    return instance, source, state


def test_defaults_resolve_supported_identity_references_without_secret_values(settings):
    instance, _, _ = settings
    defaults = instance.defaults()
    assert defaults["SIEM_FQDN"] == defaults["SIEM_HOSTNAME"] + "." + defaults["SIEM_DOMAIN"]
    assert "GRAYLOG_ADMIN_PASS" not in defaults
    assert "MONGO_GRAYLOG_PASS" not in defaults


def test_read_hides_secret_but_reports_its_presence(settings):
    instance, source, _ = settings
    secret = "dummy-test-value-only"
    (source / "00-vars.env").write_text("GRAYLOG_ADMIN_PASS=" + shlex.quote(secret) + "\nSIEM_HOSTNAME='before'\n")
    data = instance.read()
    assert data["secret_status"]["GRAYLOG_ADMIN_PASS"] is True
    assert "GRAYLOG_ADMIN_PASS" not in data["values"]
    assert secret not in repr(data)


def test_partial_update_preserves_secret_custom_lines_and_resolves_identity(settings):
    instance, source, _ = settings
    path = source / "00-vars.env"
    path.write_text("# local operator comment\nSIEM_HOSTNAME='before'\nSIEM_DOMAIN='example.test'\n"
                    'SIEM_FQDN="${SIEM_HOSTNAME}.${SIEM_DOMAIN}"\n'
                    "GRAYLOG_ADMIN_PASS='private-test-value-only'\nCUSTOM_SITE_SETTING='keep me'\n")
    result = instance.save({"SIEM_HOSTNAME": "after"}, {"GRAYLOG_ADMIN_PASS": ""})
    text = path.read_text()
    assert "# local operator comment" in text
    assert "CUSTOM_SITE_SETTING='keep me'" in text
    assert "GRAYLOG_ADMIN_PASS='private-test-value-only'" in text
    assert result["values"]["SIEM_HOSTNAME"] == "after"
    assert result["values"]["SIEM_FQDN"] == "after.example.test"
    assert "private-test-value-only" not in repr(result)


def test_legacy_shell_expressions_are_not_executed_on_read_or_partial_save(settings, tmp_path):
    instance, source, _ = settings
    marker = tmp_path / "must-not-be-created"
    line = 'CUSTOM_COMMAND="$(touch ' + marker.as_posix() + ')"\n'
    path = source / "00-vars.env"
    path.write_text("SIEM_HOSTNAME='safe-host'\n" + line)
    assert instance.read()["values"]["SIEM_HOSTNAME"] == "safe-host"
    instance.save({"SIEM_HOSTNAME": "other-host"}, {})
    assert not marker.exists()
    assert line in path.read_text()


def test_new_secret_quotes_shell_metacharacters_and_stays_private(settings):
    instance, source, _ = settings
    secret = "test-only $HOME $(touch no-file) 'double\" quotes # &\\"
    result = instance.save({}, {"GRAYLOG_ADMIN_PASS": secret})
    line = next(line for line in (source / "00-vars.env").read_text().splitlines() if line.startswith("GRAYLOG_ADMIN_PASS="))
    assert shlex.split(line)[0].split("=", 1)[1] == secret
    assert secret not in repr(result)
    assert instance.read()["secret_status"]["GRAYLOG_ADMIN_PASS"] is True


@pytest.mark.parametrize("values", [{"UNKNOWN_SETTING": "x"}, {"SMTP_PORT": "70000"}, {"SMTP_PORT": "abc"},
                                    {"SIEM_HOSTNAME": "bad\nHOST=oops"}, {"SIEM_HOSTNAME": "bad\x00host"},
                                    {"SIEM_HOSTNAME": "bad\rhost"}, {"MONGO_CACHE_GB": "nan"},
                                    {"MONGO_CACHE_GB": "inf"}, {"RETENTION_DAYS": "1.5"},
                                    {"GRAYLOG_API_URL": "http://127.0.0.1:8080/api"},
                                    {"GRAYLOG_API_URL": "http://127.0.0.1:9000/wrong"}])
def test_invalid_form_updates_are_rejected_without_touching_existing_file(settings, values):
    instance, source, _ = settings
    path = source / "00-vars.env"
    path.write_text("SIEM_HOSTNAME='unchanged'\n")
    before = path.read_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        instance.save(values, {})
    assert path.read_bytes() == before


def test_secret_newline_is_rejected_without_a_partial_save(settings):
    instance, source, _ = settings
    with pytest.raises((ValueError, RuntimeError)):
        instance.save({"SIEM_HOSTNAME": "valid"}, {"GRAYLOG_ADMIN_PASS": "bad\nMALICIOUS=value"})
    assert not (source / "00-vars.env").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_configuration_and_prior_backups_are_private(settings):
    instance, source, state = settings
    path = source / "00-vars.env"
    instance.save({"SIEM_HOSTNAME": "first"}, {"GRAYLOG_ADMIN_PASS": "test-private-secret"})
    instance.save({"SIEM_HOSTNAME": "second"}, {})
    backups = list((state / "config-backups").rglob("*"))
    backups = [path for path in backups if path.is_file()]
    assert backups
    assert path.stat().st_mode & 0o077 == 0
    assert all(backup.stat().st_mode & 0o077 == 0 for backup in backups)
    assert any("SIEM_HOSTNAME=first" in backup.read_text() or "SIEM_HOSTNAME='first'" in backup.read_text() for backup in backups)


@pytest.mark.skipif(os.name == "nt", reason="requires symlink creation")
def test_symlinked_site_config_is_refused(settings, tmp_path):
    instance, source, _ = settings
    target = tmp_path / "outside.env"
    target.write_text("SIEM_HOSTNAME='untouched'\n")
    (source / "00-vars.env").symlink_to(target)
    with pytest.raises((ValueError, RuntimeError)):
        instance.save({"SIEM_HOSTNAME": "changed"}, {})
    assert target.read_text() == "SIEM_HOSTNAME='untouched'\n"
