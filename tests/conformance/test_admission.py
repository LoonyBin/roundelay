"""Admission: the one gate, and everywhere it is not.

A deployment decides who may bring a Workspace into being, and that decision is
made once — at a founding registration — and never consulted again. Everything
below the founding is authorised by the log: a certificate signed under a
Workspace's root authority, a grant, a token. So most of this file is about the
gate being *absent*, which is harder to test and more valuable, because a gate
that crept into a second route would break every joining device.

The deployment under test runs with a token gate, so "the gate is closed" means
sending no Roundelay-Admission header, and "open" means sending the right one.
"""

from __future__ import annotations

import secrets

import pytest

from conftest import ADMISSION_TOKEN
from roundelay import crypto, fixtures
from roundelay.client import Device, Session

pytestmark = pytest.mark.usefixtures("server")


def shell(server, root: bytes) -> Session:
    return Session(server, Device(secrets.token_hex(8)), root)


def gid() -> str:
    return fixtures.uuid(secrets.token_bytes(16))


# ── the gate itself ─────────────────────────────────────────────────────────


@pytest.mark.item("CONF-ADM-001")
def test_a_founding_registration_the_server_declines(server, root):
    """403, and no member record — so a device that was refused can be
    admitted later without colliding with a half-made record of itself."""
    device = shell(server, root)
    ws = secrets.token_bytes(16)
    cert, sig = device.genesis_cert(ws)

    got = device.register(cert, sig)
    assert got.status == 403, got.body
    assert got.code == "admission_refused"

    # Nothing was created: the challenge route cannot find the member.
    got = server.post(f"/v1/members/{fixtures.uuid(device.d.member_id)}/challenge")
    assert got.status == 404, got.body
    assert got.code == "unknown_member"

    # And admitted, the same registration is a create rather than a repeat.
    assert device.register(cert, sig, admission=ADMISSION_TOKEN).status == 201


@pytest.mark.item("CONF-ADM-008")
def test_the_certificate_type_selects_the_branch(server, founded, root):
    """A workspace_genesis certificate takes the admitted path even when the
    Workspace it names already exists. Otherwise the branch would depend on
    server state, and a client could not predict which verdict it would get."""
    _, ws = founded
    device = shell(server, root)

    # A genesis certificate for a Workspace that is already there, with the
    # gate closed: the admitted path answers, not the joining one.
    cert, sig = device.genesis_cert(ws)
    got = device.register(cert, sig)
    assert got.status == 403, got.body
    assert got.code == "admission_refused"


@pytest.mark.item("CONF-ADM-003")
def test_a_joining_device_needs_no_admission(server, founded, root):
    """The Workspace's root authority already said yes. Asking the deployment
    again would put the operator between a Root and its own devices."""
    founder, ws = founded
    joiner = shell(server, root)

    cert, sig = joiner.register_cert(ws)
    got = joiner.register(cert, sig)
    assert got.status == 201, got.body
    assert got.body["chained"] is False
    assert joiner.log_in().status == 200


@pytest.mark.item("CONF-ADM-003")
def test_a_delegate_signed_registration_needs_no_admission(server, founded, root):
    """"Root authority" is the current Root or a delegation live as the route
    evaluates the request — the same reading the append path uses."""
    founder, ws = founded
    seed = secrets.token_bytes(32)
    founder.resync()
    assert founder.post_ops(
        ws, founder.delegate(ws, crypto.ed25519_public(seed), gid())).status == 200
    founder.resync()

    joiner = shell(server, root)
    cert = joiner.d.registration_block(ws)
    import json
    raw = json.dumps(cert, separators=(",", ":")).encode()
    from roundelay import wire
    sig = crypto.sign(seed, wire.cert_input(server.namespace, "member-register", raw))

    got = joiner.register(raw, sig)
    assert got.status == 201, got.body


@pytest.mark.item("CONF-ADM-007")
def test_the_joining_branch_is_checked_not_assumed(server, founded, root):
    """A registration certificate is judged against the Workspace it names, so
    a Workspace that does not exist and a Root that is not its current one are
    two different answers."""
    founder, ws = founded

    absent = shell(server, root)
    cert, sig = absent.register_cert(secrets.token_bytes(16))
    got = absent.register(cert, sig)
    assert got.status == 409, got.body
    assert got.code == "workspace_not_created"

    # A different Root, signing a certificate for a Workspace that is not its.
    impostor_root = secrets.token_bytes(32)
    other = Session(server, Device(secrets.token_hex(8)), impostor_root)
    cert, sig = other.register_cert(ws)
    got = other.register(cert, sig)
    assert got.status == 422, got.body
    assert got.code == "cert_root_pk_mismatch"


@pytest.mark.item("CONF-ADM-007")
def test_a_delegate_signature_under_the_wrong_root_names_the_root(server, founded, root):
    """The signature verified under a live delegation, so the fault is the
    root_pk the request claims — never bad_root_signature."""
    founder, ws = founded
    seed = secrets.token_bytes(32)
    founder.resync()
    assert founder.post_ops(
        ws, founder.delegate(ws, crypto.ed25519_public(seed), gid())).status == 200
    founder.resync()

    joiner = shell(server, root)
    import json

    from roundelay import wire
    raw = json.dumps(joiner.d.registration_block(ws), separators=(",", ":")).encode()
    sig = crypto.sign(seed, wire.cert_input(server.namespace, "member-register", raw))

    got = server.post("/v1/members", json_body={
        "member_id": fixtures.uuid(joiner.d.member_id),
        "control_pk": fixtures.b64(joiner.d.control_pk),
        "content_pk": fixtures.b64(joiner.d.content_pk),
        "kex_pk": fixtures.b64(joiner.d.kex_pk),
        "cert_b64": fixtures.b64(raw),
        "cert_sig_b64": fixtures.b64(sig),
        # Not this Workspace's Root.
        "root_pk_b64": fixtures.b64(crypto.ed25519_public(secrets.token_bytes(32))),
    })
    assert got.status == 422, got.body
    assert got.code == "cert_root_pk_mismatch"


# ── everywhere the gate is not ──────────────────────────────────────────────


@pytest.mark.item("CONF-ADM-002")
def test_the_gate_is_consulted_at_founding_and_nowhere_else(server, founded, enrol, gid):
    """With the gate closed for the rest of this test: grants, ops, keywraps,
    a second genesis by an already-admitted device, and a vault write all
    proceed. None of them sends an admission credential and none is asked for
    one."""
    founder, ws = founded

    # A grant and an op.
    member = enrol(ws, founder)
    member.resync()
    assert member.post_ops(ws, member.content(ws)).status == 200

    # Keywraps.
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d, member.d])
    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200

    # A vault write, whose only gate is its Root having founded something.
    slot = secrets.token_bytes(32).hex()
    assert founder.vault_write(slot, 1, b"escrow").status == 200

    # A second Workspace, founded by a device already holding a token: the
    # genesis op carries no admission check at all, because the admitted act
    # was the registration that minted that token.
    second = secrets.token_bytes(16)
    founder.resync()
    got = founder.post_ops(second, founder.genesis(second))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-ADM-004")
def test_a_vault_write_by_a_root_that_founded_nothing(server, root):
    """A precondition rather than a second gate: it removes a state that never
    meant anything, a vault holding an identity that owns nothing."""
    device = shell(server, root)
    ws = secrets.token_bytes(16)
    cert, sig = device.genesis_cert(ws)
    assert device.register(cert, sig, admission=ADMISSION_TOKEN).status == 201
    assert device.log_in().status == 200

    slot = secrets.token_bytes(32).hex()
    got = device.vault_write(slot, 1, b"too early")
    assert got.status == 403, got.body
    assert got.code == "vault_requires_genesis"

    # Once the genesis lands, the same write succeeds.
    device.resync()
    assert device.post_ops(ws, device.genesis(ws)).status == 200
    assert device.vault_write(slot, 1, b"now").status == 200


@pytest.mark.item("CONF-ADM-005")
def test_a_later_vault_write_is_never_admission_checked(founded):
    """The pinned signature is the gate from the second write on."""
    founder, _ = founded
    slot = secrets.token_bytes(32).hex()
    assert founder.vault_write(slot, 1, b"one").status == 200
    assert founder.vault_write(slot, 2, b"two").status == 200
    assert founder.vault_read(slot).body["version"] == 2


@pytest.mark.item("CONF-ADM-006")
def test_the_admission_header_is_honoured_on_one_route(server, founded):
    """It is not a credential. A deployment that accepted it elsewhere would
    have a second, weaker way in to every route it touched."""
    founder, ws = founded
    header = {"Roundelay-Admission": ADMISSION_TOKEN}

    # Ignored where a device token is what is wanted, and never a substitute
    # for one.
    got = server.get(f"/v1/w/{fixtures.uuid(ws)}/ops", headers=header)
    assert got.status == 401, got.body
    assert got.code == "invalid_credential"

    got = server.post(f"/v1/w/{fixtures.uuid(ws)}/ops", headers=header,
                      json_body={"ops": []})
    assert got.status == 401, got.body
    assert got.code == "invalid_credential"

    # And ignored, rather than refused, alongside a real one.
    got = server.get(f"/v1/w/{fixtures.uuid(ws)}/ops",
                     token=founder.d.access, headers=header)
    assert got.status == 200, got.body
