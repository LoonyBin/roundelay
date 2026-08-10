"""Contract versioning, and the rules that close every request body."""

from __future__ import annotations

import pytest

from roundelay import fixtures

pytestmark = pytest.mark.usefixtures("server")


@pytest.mark.item("CONF-VER-001")
def test_prefix_placement(server, founded):
    """Every functional route under /v1; only /health and /health/db outside."""
    session, ws = founded
    assert server.get("/health").status == 200
    assert server.get("/health/db").status == 200
    # The same route without the prefix is not a route.
    assert server.get(f"/w/{fixtures.uuid(ws)}/ops", token=session.d.access).status == 404
    assert server.get(f"/v1/w/{fixtures.uuid(ws)}/ops", token=session.d.access).status == 200
    # And discovery is not behind the thing being discovered.
    assert server.get("/v1/health").code == "not_found"


@pytest.mark.item("CONF-VER-002")
def test_unserved_version(server):
    got = server.get("/v2/w/00000000-0000-0000-0000-000000000000/ops")
    assert got.status == 404
    assert got.code == "unsupported_contract_version"
    assert got.detail["requested"] == "v2"
    assert got.detail["served"] == ["v1"]


@pytest.mark.item("CONF-VER-003")
@pytest.mark.parametrize("path", ["/api/w/x/ops", "/V2/w/x/ops", "/v01/w/x/ops", "/v1x/w/x/ops", "/v1/nope"])
def test_not_version_shaped(server, path):
    """"I built the wrong URL" is a different 404 from "you are older than me".

    v01 is on this branch and not the other, which the layer document's own
    ^v[0-9]+$ would have got backwards.
    """
    got = server.get(path)
    assert got.status == 404
    assert got.code == "not_found"


@pytest.mark.item("CONF-VER-004")
def test_unknown_body_field(server, founded):
    session, ws = founded
    got = server.post(
        f"/v1/w/{fixtures.uuid(ws)}/ops",
        token=session.d.access,
        raw_body='{"ops":[],"epoch_note":1,"another":2}',
    )
    assert got.status == 422
    assert got.code == "unknown_request_field"
    # Every offending path in one response, sorted lexicographically.
    assert got.detail["fields"] == ["another", "epoch_note"]


@pytest.mark.item("CONF-VER-005")
def test_unknown_query_parameter(server, founded):
    session, ws = founded
    got = server.get(f"/v1/w/{fixtures.uuid(ws)}/ops?cursor=3", token=session.d.access)
    assert got.status == 422
    assert got.code == "unknown_request_field"
    assert got.detail["fields"] == ["cursor"]


@pytest.mark.item("CONF-VER-006")
def test_check_order(server, founded):
    """After credential resolution, before authorisation.

    Earlier and the field set is a free oracle; later and a caller with both
    problems is told only that they lack access, and fixes the wrong thing.
    """
    _, ws = founded
    path = f"/v1/w/{fixtures.uuid(ws)}/ops"
    unauthenticated = server.post(path, raw_body='{"ops":[],"surprise":1}')
    assert unauthenticated.status == 401
    assert unauthenticated.code == "invalid_credential"


@pytest.mark.item("CONF-VER-007")
def test_duplicate_key(server, founded):
    session, ws = founded
    got = server.post(
        f"/v1/w/{fixtures.uuid(ws)}/ops",
        token=session.d.access,
        raw_body='{"ops":[],"ops":[]}',
    )
    assert got.status == 422
    assert got.code == "malformed_request"


@pytest.mark.item("CONF-VER-008")
@pytest.mark.parametrize("value", ["true", "1.0", '"1"', "null"])
def test_wrong_scalar_types(server, founded, value):
    """An integer field is a JSON integer: never a float, boolean or string."""
    session, ws = founded
    got = server.get(f"/v1/w/{fixtures.uuid(ws)}/ops?since=1.5", token=session.d.access)
    assert got.status == 422 and got.code == "malformed_request"
    # And in a body, on a field the conventions type as an integer.
    got = server.put(
        f"/v1/w/{fixtures.uuid(ws)}/keywraps",
        token=session.d.access,
        raw_body='{"epoch":%s,"wraps":[],"escrow_wrap_b64":"","keywrap_digest_b64":""}' % value,
    )
    assert got.status == 422, got.body
    assert got.code in {"malformed_key_epoch", "malformed_request"}
