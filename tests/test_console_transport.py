"""Changing deployment/config paths must not disable transport validation."""
import pytest


def test_remote_cleartext_remains_rejected(api):
    api.GL_URL = "http://siem.example.test:9000/api"
    with pytest.raises(SystemExit, match="HTTP clair"):
        api._make_ssl_ctx()


def test_docker_cleartext_requires_opt_in_and_exact_service_hostname(api):
    api.GL_URL = "http://graylog:9000/api"
    with pytest.raises(SystemExit):
        api._make_ssl_ctx()
    api.CONF["MOBILE_ALLOW_HTTP_DOCKER"] = "1"
    assert api._make_ssl_ctx() is None
    api.GL_URL = "http://other-host:9000/api"
    with pytest.raises(SystemExit):
        api._make_ssl_ctx()
