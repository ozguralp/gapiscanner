"""Keep regression tests offline and isolate persistent scanner data."""
import socket

import pytest


@pytest.fixture(autouse=True)
def isolated_scanner_data(monkeypatch, tmp_path):
    monkeypatch.setenv("GAPISCANNER_DATA_DIR", str(tmp_path / "scanner-data"))


@pytest.fixture(autouse=True)
def forbid_accidental_network(monkeypatch):
    attempted = []

    def blocked(*args, **kwargs):
        attempted.append(True)
        raise RuntimeError("Network access is forbidden in the offline test suite")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    yield
    assert not attempted, "A test attempted real network access; mock the transport"
