"""The package updater talks to the local Graylog API over loopback."""
from omni_update.stack import GRAYLOG_API


def test_graylog_api_default_uses_loopback_without_tls_name_mismatch():
    assert GRAYLOG_API == "http://127.0.0.1:9000/api"
