"""One end-to-end pass, to prove the harness and the server agree at all."""
import pytest
from roundelay import fixtures


def test_health(server):
    h = server.health
    assert h["status"] == "ok"
    assert h["protocol_namespace"] == "acme"
    assert h["contract_versions"] == ["v1"]


def test_founding_ceremony(founded):
    session, ws = founded
    got = session.post_ops(ws, session.content(ws))
    assert got.status == 200, got.body
    page = server_ops(session, ws)
    assert len(page) == 3


def server_ops(session, ws):
    got = session.s.get(f"/v1/w/{fixtures.uuid(ws)}/ops", token=session.d.access)
    assert got.status == 200, got.body
    return got.body["ops"]
