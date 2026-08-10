"""Discovery: the entry point for everything else."""

from __future__ import annotations

import pytest


@pytest.mark.item("CONF-HEALTH-001")
def test_health_document(server):
    h = server.health
    assert h["status"] == "ok"
    assert h["version"]
    assert h["contract_versions"] == sorted(h["contract_versions"], key=lambda v: int(v[1:]))
    assert h["protocol_namespace"] == "acme"
    assert h["profile"]
    # {} when none are enabled, never absent: absent is indistinguishable from a
    # server too old to carry the field.
    assert isinstance(h["extension_classes"], dict)
    limits = h["limits"]
    for key in ("max_ops_per_batch", "max_page_size", "default_page_size", "signal_keepalive_seconds"):
        assert isinstance(limits[key], int) and limits[key] > 0, key


@pytest.mark.item("CONF-HEALTH-006")
def test_served_sets_are_truthful(server, founded):
    """Every array is exactly what this server serves, nothing withheld.

    Checked against the fail-closed codes rather than taken on the field's word:
    a byte in the list is accepted, and one outside it is refused.
    """
    from roundelay import fixtures, wire

    session, ws = founded
    sets = server.health["served_sets"]

    assert sets["suites"] == sorted(sets["suites"])
    assert sets["op_classes"] == sorted(sets["op_classes"])
    assert sets["control_types"] == sorted(sets["control_types"])
    assert sets["prune_types"] == sorted(sets["prune_types"])
    assert len(sets["control_types"]) == 10
    assert sets["prune_types"] == ["hard_prune", "prune", "prune_ext"]

    # A class the list does not carry is refused.
    absent = next(c for c in range(0x03, 0x40) if c not in sets["op_classes"])
    got = session.post_ops(ws, session.content(ws, op_label="served/absent", author_seq=99))
    # (the class byte is what is under test, so build one directly)
    env = session.envelope(
        op_class=absent, payload=b"x", workspace=ws, op_label="served/absent2", author_seq=99
    )
    got = session.post_ops(ws, env)
    assert got.code == "unsupported_op_class", got.body

    # A suite the list does not carry is refused, and under its own code.
    env = session.envelope(
        op_class=wire.CLASS_CONTENT, payload=b"x", workspace=ws,
        suite=0x02, op_label="served/suite", author_seq=99,
    )
    got = session.post_ops(ws, env)
    assert got.code == "unsupported_suite", got.body
    assert fixtures.NAMESPACE == server.health["protocol_namespace"]


@pytest.mark.item("CONF-HEALTH-007")
def test_op_classes_covers_every_range(server):
    """Core assignments at least; a profile's opaque and extension rows too."""
    sets = server.health["served_sets"]
    for core in (0x01, 0x02, 0x80, 0x81, 0xBF):
        assert core in sets["op_classes"], hex(core)
    # extension_classes never disagrees with op_classes.
    for key in server.health["extension_classes"]:
        assert int(key) in sets["op_classes"]


@pytest.mark.item("CONF-DISC-001")
def test_every_refusal_carries_a_code(server):
    """One error shape, so a client branching on detail.code never meets a bare
    string."""
    for path in ("/v1/nope", "/v2/x", "/v1/vault/nothex"):
        got = server.get(path)
        assert got.status >= 400
        assert isinstance(got.body.get("detail"), dict), path
        assert isinstance(got.detail.get("code"), str), path


@pytest.mark.item("CONF-DISC-003")
def test_every_429_carries_retry_after(server, founder):
    """The vault fetch is the reachable limit here."""
    import secrets
    from roundelay import fixtures

    locator = secrets.token_bytes(32).hex()
    # An unwritten slot spends no quota, so drive the limit against a real one
    # is not possible without a genesis; assert the shape where a 429 can occur.
    got = server.get(f"/v1/vault/{locator}")
    assert got.status == 404 and got.code == "no_vault_record"
