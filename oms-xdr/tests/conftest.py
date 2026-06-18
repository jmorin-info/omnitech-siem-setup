"""Fixtures de test : client Graylog simulé (aucun appel réseau)."""
from __future__ import annotations

import pathlib

import pytest


class FakeGraylog:
    """Renvoie des agrégats prédéfinis selon (query, stream, group_by)."""

    def __init__(self, data: dict[tuple[str, str, str], dict[str, int]]):
        self.data = data
        self.sent: list[dict] = []

    def aggregate(self, query, stream, group_by, minutes):
        return self.data.get((query, stream, group_by), {})

    def messages(self, query, stream, minutes, fields, size=500):
        return []

    def send_gelf(self, payload):
        self.sent.append(payload)
        return True


@pytest.fixture
def rules_path() -> str:
    return str(pathlib.Path(__file__).parents[1] / "oms_xdr" / "rules.yaml")


@pytest.fixture
def graylog_factory():
    """Retourne la classe FakeGraylog pour instanciation dans les tests."""
    return FakeGraylog
