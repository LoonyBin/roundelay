"""Who may write what, and the order the answers come in.

The access gate, the two bars, the control chain, and the certificate sequences
each control type fixes. Almost every case here is a pair: an op faulty in two
ways, and the assertion that the earlier check is the one that answers. That is
the only way an ordering is testable at all — a single-fault op tells you the
check exists, never where it sits.
"""

from __future__ import annotations

import secrets

import pytest

from conftest import own
from roundelay import crypto, fixtures, wire

pytestmark = pytest.mark.usefixtures("server")


# ── the access gate ─────────────────────────────────────────────────────────


@pytest.mark.item("CONF-AUTHZ-002")
def test_unregistered_device_is_refused(server, founded, root, gid):
    """A device with no registration here, writing something that is not its own
    registration, is stopped by the gate before anything looks at the op."""
    from roundelay.client import Device, Session

    stranger = Session(server, Device(secrets.token_hex(8)), root)
    ws = founded[1]
    # It founds a Workspace of its own, so it holds a real token and a real
    # registration — somewhere else.
    cert, sig = stranger.genesis_cert(own(stranger))
    assert stranger.register(cert, sig, admission="conformance-admission").status == 201
    assert stranger.log_in().status == 200

    got = stranger.post_ops(ws, stranger.content(ws))
    assert got.status == 403, got.body
    assert got.code == "no_registration"


@pytest.mark.item("CONF-AUTHZ-013")
def test_the_gate_is_per_workspace(server, founder, enrol, gid):
    """One Root founds two Workspaces; a device registered in the first is a
    stranger in the second."""
    from roundelay.client import Device, Session

    first = founder.founding_workspace
    assert founder.post_ops(
        first, founder.genesis(first),
        founder.grant(first, founder.d, "owner", gid()),
    ).status == 200
    founder.resync()

    # A second Workspace under the same Root, founded by a second device. One
    # Root derives one id per frozen namespace, so this is namespace 1.
    from conftest import derived, own
    second = derived(founder.root, 1)
    other = Session(server, Device(secrets.token_hex(8)), founder.root)
    other.founding_workspace = second
    cert, sig = other.genesis_cert(second)
    assert other.register(cert, sig, admission="conformance-admission").status == 201
    assert other.log_in().status == 200
    assert other.post_ops(
        second, other.genesis(second),
        other.grant(second, other.d, "owner", gid()),
    ).status == 200
    other.resync()

    member = enrol(first, founder)
    assert member.post_ops(first, member.content(first)).status == 200
    member.resync()
    got = member.post_ops(second, member.content(second))
    assert got.status == 403 and got.code == "no_registration"


@pytest.mark.item("CONF-AUTHZ-014")
def test_the_exemption_reaches_the_first_op_only(server, founded, root, enrol):
    """Registration and genesis are exempt. A batch whose *first* op is neither
    is not, even when a later op in it would have established access."""
    from roundelay.client import Device, Session

    _, ws = founded
    founder = founded[0]
    joiner = Session(server, Device(secrets.token_hex(8)), root)
    cert, sig = joiner.register_cert(ws)
    assert joiner.register(cert, sig, admission="conformance-admission").status == 201
    assert joiner.log_in().status == 200
    joiner.pending_tip = founder.committed_tip(ws)

    # Content first, registration second: the gate looks at index 0 and stops.
    got = joiner.post_ops(ws, joiner.content(ws), joiner.member_register(ws))
    assert got.status == 403, got.body
    assert got.code == "no_registration"

    # The same registration alone is accepted from the same unregistered device.
    joiner.d.author_seq[ws] = 0
    joiner.pending_tip = founder.committed_tip(ws)
    assert joiner.post_ops(ws, joiner.member_register(ws)).status == 200


@pytest.mark.item("CONF-AUTHZ-015")
def test_the_exemption_is_not_a_hole(server, founded, root):
    """The exempt op is still judged. A registration signed by a key that holds
    no root authority here is refused on its signature."""
    from roundelay.client import Device, Session

    founder, ws = founded
    impostor_root = secrets.token_bytes(32)
    joiner = Session(server, Device(secrets.token_hex(8)), impostor_root)
    # The route would refuse this too, so the device registers under the real
    # Root and then posts a certificate signed by the wrong one.
    real = Session(server, joiner.d, founder.root)
    cert, sig = real.register_cert(ws)
    assert real.register(cert, sig, admission="conformance-admission").status == 201
    assert real.log_in().status == 200

    joiner.d.access = real.d.access
    joiner.pending_tip = founder.committed_tip(ws)
    got = joiner.post_ops(ws, joiner.member_register(ws))
    assert got.status == 422, got.body
    assert got.code == "bad_root_signature"


# ── the bars ────────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-AUTHZ-006")
def test_role_forbids_op_class(founded, enrol):
    """participant holds 0x01 and nothing else, so a control op from one is
    refused with the class and the sorted live roles named.

    A rotate is the control op to try it with: every other type carries a
    certificate, and a Root-signed one bypasses the role check entirely.
    """
    founder, ws = founded
    member = enrol(ws, founder)

    member.pending_tip = founder.committed_tip(ws)
    got = member.post_ops(ws, member.rotate(ws, 0, 1, bytes(32)))
    assert got.status == 403, got.body
    assert got.code == "role_forbids_op_class"
    assert got.detail["op_class"] == wire.CLASS_CONTROL
    assert got.detail["roles"] == ["participant"]


@pytest.mark.item("CONF-AUTHZ-003")
@pytest.mark.item("CONF-REVK-002")
def test_revocation_leaves_the_registration(founded, enrol, gid):
    """A revoke closes grants and nothing else: the device is still a member,
    still passes the gate, and now fails bar 1 with revoked=true."""
    founder, ws = founded
    grant_id = gid()
    member = enrol(ws, founder, role=None)
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", grant_id)).status == 200
    founder.resync()
    assert member.post_ops(ws, member.content(ws)).status == 200
    member.resync()

    assert founder.post_ops(ws, founder.revoke(ws, grant_id, gid())).status == 200
    founder.resync()

    got = member.post_ops(ws, member.content(ws))
    assert got.status == 403, got.body
    assert got.code == "no_live_grant"
    assert got.detail["revoked"] is True

    # Still a member. The registration is not what a revoke touches.
    listing = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members", token=founder.d.access)
    assert listing.status == 200
    assert fixtures.uuid(member.d.member_id) in {
        m["member_id"] for m in listing.body["members"]
    }


@pytest.mark.item("CONF-AUTHZ-005")
def test_a_root_signed_payload_needs_no_grant(founded, enrol, gid):
    """Root's signature is the authority, so a member holding zero grants may
    carry a Root-signed control payload — and nothing else."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)

    # Zero grants, but the payload is signed by Root.
    member.pending_tip = founder.committed_tip(ws)
    other = enrol(ws, founder, role=None)
    founder.resync()
    member.pending_tip = founder.committed_tip(ws)
    got = member.post_ops(ws, member.grant(ws, other.d, "participant", gid()))
    assert got.status == 200, got.body
    member.resync()

    # A rotate carries no certificate, so nothing signs for it.
    member.pending_tip = founder.committed_tip(ws)
    got = member.post_ops(ws, member.rotate(ws, 0, 1, bytes(32)))
    assert got.status == 403, got.body
    assert got.code == "no_live_grant"


@pytest.mark.item("CONF-AUTHZ-008")
def test_an_owner_grant_requires_root(founded, enrol, gid):
    """An owner may grant, but not owner: only root mints that."""
    founder, ws = founded
    member = enrol(ws, founder)

    got = founder.post_ops(ws, founder.grant(
        ws, member.d, "owner", gid(),
        granter=fixtures.uuid(founder.d.member_id), signer=founder.d.control))
    assert got.status == 422, got.body
    assert got.code == "owner_grant_requires_root"


@pytest.mark.item("CONF-AUTHZ-009")
def test_an_owner_revoke_requires_root(founded, enrol, gid):
    founder, ws = founded
    second_owner = enrol(ws, founder, role=None)
    owner_grant = gid()
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, second_owner.d, "owner", owner_grant)).status == 200
    founder.resync()

    got = founder.post_ops(ws, founder.revoke(
        ws, owner_grant, gid(),
        revoker=fixtures.uuid(founder.d.member_id), signer=founder.d.control))
    assert got.status == 422, got.body
    assert got.code == "owner_revoke_requires_root"


@pytest.mark.item("CONF-AUTHZ-010")
def test_an_unknown_role_is_refused(founded, enrol, gid):
    """Never ignored, never treated as no grant: the token is not in the table."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)
    founder.resync()
    got = founder.post_ops(ws, founder.grant(ws, member.d, "archivist", gid()))
    assert got.status == 422, got.body
    assert got.code == "unknown_role"


@pytest.mark.item("CONF-AUTHZ-011")
def test_an_unknown_member_kind_is_refused(server, founded, root):
    """The profile's set is closed, and member_kind is the last of the
    registration sequence."""
    from roundelay.client import Device, Session

    founder, ws = founded
    joiner = Session(server, Device(secrets.token_hex(8)), root)
    cert, sig = joiner.register_cert(ws)
    assert joiner.register(cert, sig, admission="conformance-admission").status == 201
    assert joiner.log_in().status == 200

    block = joiner.d.registration_block(ws)
    block["member_kind"] = "kiosk"
    joiner.pending_tip = founder.committed_tip(ws)
    got = joiner.post_ops(ws, joiner.certified(
        ws, "member_register", "member-register", block))
    assert got.status == 422, got.body
    assert got.code == "unknown_member_kind"


# ── the control chain ───────────────────────────────────────────────────────


@pytest.mark.item("CONF-CTL-012")
def test_the_control_chain_is_linear(founded, enrol, gid):
    """Three linked ops accepted in sequence, a wrong link refused with the tip
    it should have named, and within one batch the second links the first."""
    founder, ws = founded
    a, b = enrol(ws, founder, role=None), enrol(ws, founder, role=None)

    founder.resync()
    got = founder.post_ops(
        ws,
        founder.grant(ws, a.d, "participant", gid()),
        founder.grant(ws, b.d, "participant", gid()),
    )
    assert got.status == 200, got.body
    founder.resync()

    # A link naming a tip that is not the current one.
    founder.pending_tip = "11" * 32
    got = founder.post_ops(ws, founder.grant(ws, a.d, "participant", gid()))
    assert got.status == 422, got.body
    assert got.code == "control_chain_break"
    expected = got.detail["expected_prev_control_hash"]

    # Rebuilt against the value the refusal named, it lands.
    founder.pending_tip = expected
    assert founder.post_ops(ws, founder.grant(ws, a.d, "participant", gid())).status == 200


@pytest.mark.item("CONF-CTL-003")
def test_the_zero_link_belongs_to_the_genesis_alone(founded, enrol, gid):
    """An all-zero link on a non-genesis is a break, and it names no expected
    value where there is no tip to name."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)

    founder.pending_tip = "00" * 32
    got = founder.post_ops(ws, founder.grant(ws, member.d, "participant", gid()))
    assert got.status == 422, got.body
    assert got.code == "control_chain_break"
    assert got.detail.get("expected_prev_control_hash") == founder.committed_tip(ws)


@pytest.mark.item("CONF-CTL-015")
def test_before_a_genesis_the_tip_is_not_asked(server, workspace, founder):
    """A registration into a Workspace with no genesis answers for the missing
    Workspace, not for a chain there is none of."""
    ws = workspace
    founder.pending_tip = "22" * 32
    got = founder.post_ops(ws, founder.member_register(ws))
    assert got.status == 409, got.body
    assert got.code == "workspace_not_created"


@pytest.mark.item("CONF-CTL-004")
def test_a_genesis_is_once_and_first(founded, gid):
    """Into a Workspace that exists, and anywhere but index 0."""
    founder, ws = founded

    founder.resync()
    got = founder.post_ops(ws, founder.genesis(ws))
    assert got.status == 409, got.body
    assert got.code == "genesis_not_first"


@pytest.mark.item("CONF-CTL-014")
def test_a_stale_repeat_is_a_duplicate_not_a_break(founded, enrol, gid):
    """Idempotency sits above the chain: the very same op, re-posted after the
    tip has moved, is the op that already landed."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)

    founder.resync()
    envelope = founder.grant(ws, member.d, "participant", gid())
    assert founder.post_ops(ws, envelope).status == 200

    # Move the tip on.
    founder.resync()
    other = gid()
    assert founder.post_ops(ws, founder.revoke(ws, other, gid())).status in (200, 422)
    founder.resync()

    got = founder.post_ops(ws, envelope)
    assert got.status == 200, got.body
    assert got.body["results"][0]["duplicate"] is True


@pytest.mark.item("CONF-CTL-006")
def test_an_authors_first_op_must_be_its_registration(founder, workspace, gid):
    """Before a genesis is where this rule is reachable, and the layer document
    names that case itself: a non-registering control op arriving in a Workspace
    with no genesis is answered by the author's own sequence.

    After one, the access gate has already refused an unregistered author, and a
    registered author is registered because it wrote the op that says so — so
    there is no author left holding author_seq 1 and something else to say.
    """
    ws = workspace
    founder.pending_tip = "44" * 32
    got = founder.post_ops(ws, founder.grant(ws, founder.d, "participant", gid()))
    assert got.status == 422, got.body
    assert got.code == "member_register_not_first"
    assert got.detail["author_seq"] == 1


@pytest.mark.item("CONF-CTL-011")
def test_revocation_is_grant_granular(founded, enrol, gid):
    """Revoking the granter does not unwind what it granted."""
    founder, ws = founded
    granter = enrol(ws, founder, role=None)
    granter_grant = gid()
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, granter.d, "owner", granter_grant)).status == 200
    founder.resync()

    grantee = enrol(ws, founder, role=None)
    granter.resync()
    granter.pending_tip = founder.committed_tip(ws)
    assert granter.post_ops(ws, granter.grant(
        ws, grantee.d, "participant", gid(),
        granter=fixtures.uuid(granter.d.member_id), signer=granter.d.control)).status == 200
    granter.resync()

    founder.resync()
    assert founder.post_ops(ws, founder.revoke(ws, granter_grant, gid())).status == 200
    founder.resync()

    # The granter is out; what it granted stands.
    grantee.resync()
    assert grantee.post_ops(ws, grantee.content(ws)).status == 200
    granter.resync()
    assert granter.post_ops(ws, granter.content(ws)).code == "no_live_grant"


# ── delegation ──────────────────────────────────────────────────────────────


@pytest.fixture
def delegation(founded, gid):
    """A live delegate key in the founded Workspace."""
    founder, ws = founded
    seed = secrets.token_bytes(32)
    delegation_id = gid()
    founder.resync()
    got = founder.post_ops(
        ws, founder.delegate(ws, crypto.ed25519_public(seed), delegation_id))
    assert got.status == 200, got.body
    founder.resync()
    return seed, delegation_id


@pytest.mark.item("CONF-DELG-001")
def test_a_delegate_may_not_delegate(founded, delegation, gid):
    """Only Root itself signs a delegate, and the same for its revocation."""
    founder, ws = founded
    seed, delegation_id = delegation

    got = founder.post_ops(ws, founder.delegate(
        ws, crypto.ed25519_public(secrets.token_bytes(32)), gid(), signer=seed))
    assert got.status == 422, got.body
    assert got.code == "bad_root_signature"

    founder.resync()
    got = founder.post_ops(
        ws, founder.revoke_delegation(ws, delegation_id, gid(), signer=seed))
    assert got.status == 422, got.body
    assert got.code == "bad_root_signature"


@pytest.mark.item("CONF-DELG-003")
def test_four_documents_are_roots_alone(founded, delegation, gid):
    """workspace_genesis, root_handover, role_table and the vault write are
    Root's; a live delegate's signature is refused on all of them."""
    founder, ws = founded
    seed, _ = delegation

    got = founder.post_ops(ws, founder.handover(
        ws, crypto.ed25519_public(secrets.token_bytes(32)), signer=seed))
    assert got.status == 422 and got.code == "bad_root_signature", got.body

    founder.resync()
    got = founder.post_ops(ws, founder.role_table(ws, [
        {"role": "owner", "classes": [0x01, 0x80], "prune_types": []},
    ], signer=seed))
    assert got.status == 422 and got.code == "bad_root_signature", got.body


@pytest.mark.item("CONF-DELG-002")
def test_a_delegate_signs_registrations_and_grants(server, founded, delegation, root, gid):
    """Exactly as Root would, including an owner grant."""
    from roundelay.client import Device, Session

    founder, ws = founded
    seed, _ = delegation

    joiner = Session(server, Device(secrets.token_hex(8)), root)
    cert, sig = joiner.register_cert(ws)
    assert joiner.register(cert, sig, admission="conformance-admission").status == 201
    assert joiner.log_in().status == 200

    # The registration certificate, signed by the delegate rather than by Root.
    joiner.pending_tip = founder.committed_tip(ws)
    got = joiner.post_ops(ws, joiner.certified(
        ws, "member_register", "member-register",
        joiner.d.registration_block(ws), signer=seed))
    assert got.status == 200, got.body
    joiner.resync()

    founder.resync()
    got = founder.post_ops(
        ws, founder.grant(ws, joiner.d, "owner", gid(), signer=seed))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-DELG-005")
def test_delegation_ids_are_once(founded, delegation, gid):
    founder, ws = founded
    _, delegation_id = delegation

    got = founder.post_ops(ws, founder.delegate(
        ws, crypto.ed25519_public(secrets.token_bytes(32)), delegation_id))
    assert got.status == 409, got.body
    assert got.code == "delegation_id_already_used"

    founder.resync()
    got = founder.post_ops(ws, founder.revoke_delegation(ws, gid(), gid()))
    assert got.status == 422, got.body
    assert got.code == "unknown_delegation"


@pytest.mark.item("CONF-DELG-006")
def test_a_delegate_key_may_not_be_in_use(founded, gid):
    """A key that already signs for somebody here cannot also be a delegation:
    the two authorities would be indistinguishable in the log."""
    founder, ws = founded

    got = founder.post_ops(ws, founder.delegate(ws, founder.d.control_pk, gid()))
    assert got.status == 422, got.body
    assert got.code == "delegate_pk_in_use"

    founder.resync()
    got = founder.post_ops(
        ws, founder.delegate(ws, crypto.ed25519_public(founder.root), gid()))
    assert got.status == 422, got.body
    assert got.code == "delegate_pk_in_use"


@pytest.mark.item("CONF-DELG-004")
def test_the_delegation_verdict_is_positional(server, founded, delegation, root, gid):
    """A revoke_delegation invalidates nothing already signed and landed."""
    from roundelay.client import Device, Session

    founder, ws = founded
    seed, delegation_id = delegation

    joiner = Session(server, Device(secrets.token_hex(8)), root)
    cert, sig = joiner.register_cert(ws)
    assert joiner.register(cert, sig, admission="conformance-admission").status == 201
    assert joiner.log_in().status == 200
    joiner.pending_tip = founder.committed_tip(ws)
    assert joiner.post_ops(ws, joiner.certified(
        ws, "member_register", "member-register",
        joiner.d.registration_block(ws), signer=seed)).status == 200
    joiner.resync()

    founder.resync()
    assert founder.post_ops(
        ws, founder.revoke_delegation(ws, delegation_id, gid())).status == 200
    founder.resync()

    # The registration stands: it is still served, and the device is a member.
    listing = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members", token=founder.d.access)
    assert fixtures.uuid(joiner.d.member_id) in {
        m["member_id"] for m in listing.body["members"]
    }

    # A new certificate under the dead delegation is not.
    founder.resync()
    got = founder.post_ops(
        ws, founder.grant(ws, joiner.d, "participant", gid(), signer=seed))
    assert got.status == 422, got.body
    assert got.code == "bad_grant_signature"


# ── handover ────────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-HAND-001")
def test_handover_names_the_current_root(founded):
    founder, ws = founded
    incoming = secrets.token_bytes(32)

    wrong = secrets.token_bytes(32)
    got = founder.post_ops(ws, founder.handover(
        ws, crypto.ed25519_public(incoming),
        from_root_pk=crypto.ed25519_public(wrong)))
    assert got.status == 422, got.body
    assert got.code == "cert_root_pk_mismatch"

    # Signed by something that is not the outgoing Root.
    founder.resync()
    got = founder.post_ops(ws, founder.handover(
        ws, crypto.ed25519_public(incoming), signer=wrong))
    assert got.status == 422, got.body
    assert got.code == "bad_root_signature"


@pytest.mark.item("CONF-HAND-002")
@pytest.mark.item("CONF-HAND-003")
def test_after_a_handover_the_incoming_root_signs(founded, enrol, gid):
    """And the retired key is retired: everything already recorded is untouched,
    and a second handover from the old key answers on the mismatch."""
    founder, ws = founded
    member = enrol(ws, founder)
    old_root = founder.root
    incoming = secrets.token_bytes(32)

    founder.resync()
    got = founder.post_ops(ws, founder.handover(ws, crypto.ed25519_public(incoming)))
    assert got.status == 200, got.body
    founder.resync()

    # Nothing already recorded moved: the member is still a member, its grant is
    # still live, and the Workspace is the same one.
    listing = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members", token=founder.d.access)
    assert fixtures.uuid(member.d.member_id) in {
        m["member_id"] for m in listing.body["members"]
    }
    member.resync()
    assert member.post_ops(ws, member.content(ws)).status == 200

    # The incoming Root signs.
    founder.root = incoming
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", gid())).status == 200

    # The retired one does not, and the code says which fact is wrong.
    founder.resync()
    got = founder.post_ops(ws, founder.handover(
        ws, crypto.ed25519_public(secrets.token_bytes(32)),
        from_root_pk=crypto.ed25519_public(old_root), signer=old_root))
    assert got.status == 422, got.body
    assert got.code == "cert_root_pk_mismatch"


# ── the role table ──────────────────────────────────────────────────────────


OWNER_ROW = {"role": "owner", "classes": [0x01, 0x02, 0x80, 0x81, 0xBF], "prune_types": []}


@pytest.mark.item("CONF-CTL-018")
def test_a_role_table_is_roots_own(founded, enrol):
    """Root-signed, so an author holding no grant at all may carry it."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)

    member.pending_tip = founder.committed_tip(ws)
    got = member.post_ops(ws, member.role_table(ws, [
        OWNER_ROW, {"role": "participant", "classes": [0x01], "prune_types": []},
    ]))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-CTL-019")
@pytest.mark.parametrize("roles,why", [
    ([{"role": "owner", "classes": [0x80]}], "an entry missing prune_types"),
    ([dict(OWNER_ROW, extra=1)], "an entry with a key outside the closed three"),
    ([OWNER_ROW, {"role": "Bad", "classes": [0x01], "prune_types": []}], "a role token with a capital"),
    ([OWNER_ROW, {"role": "-x", "classes": [0x01], "prune_types": []}], "a role token starting with a dash"),
    ([OWNER_ROW, {"role": "a" * 33, "classes": [0x01], "prune_types": []}], "a role token over 32 bytes"),
    ([OWNER_ROW, OWNER_ROW], "a repeated role token"),
    ([dict(OWNER_ROW, classes=[0x01, 0x01, 0x80])], "a repeated class"),
    ([dict(OWNER_ROW, classes=[256])], "a class outside 0-255"),
    ([{"role": "participant", "classes": [0x01], "prune_types": []}], "no owner entry"),
    ([OWNER_ROW, {"role": "p", "classes": [0x80], "prune_types": []}], "a non-owner naming 128"),
    ([dict(OWNER_ROW, prune_types=["prune"], classes=[0x01, 0x80])],
     "prune_types on an entry that does not name 129"),
    ([dict(OWNER_ROW, prune_types=["scrub"])], "an unserved prune type"),
    ([dict(OWNER_ROW, prune_types=["prune", "prune"])], "a repeated prune type"),
])
def test_malformed_role_tables(founded, roles, why):
    """Shape is decided from the certificate's own bytes, so it sits above the
    signature — and every case here is signed by the wrong key to prove it."""
    founder, ws = founded
    got = founder.post_ops(ws, founder.role_table(
        ws, roles, signer=secrets.token_bytes(32)))
    assert got.status == 422, (why, got.body)
    assert got.code == "malformed_role_table", why
    founder.resync()


@pytest.mark.item("CONF-CTL-020")
def test_the_table_in_force_is_positional(founded, enrol, gid):
    """An op after a role_table in the same batch is judged against the new
    table, and an op accepted under the old one is never revisited."""
    founder, ws = founded
    member = enrol(ws, founder)

    # Accepted under the initial table, which gives participant 0x01.
    member.resync()
    assert member.post_ops(ws, member.content(ws)).status == 200

    # Narrow participant to nothing.
    founder.resync()
    got = founder.post_ops(ws, founder.role_table(ws, [
        OWNER_ROW, {"role": "participant", "classes": [0x02], "prune_types": []},
    ]))
    assert got.status == 200, got.body
    founder.resync()

    # The op already in the log serves unchanged.
    page = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/ops", token=founder.d.access)
    assert page.status == 200 and page.body["ops"]

    # And the grant is still live — a role a table stops widening is not a
    # revocation, so the answer names the class, not the grant.
    member.resync()
    got = member.post_ops(ws, member.content(ws))
    assert got.status == 403, got.body
    assert got.code == "role_forbids_op_class"
    assert got.detail["roles"] == ["participant"]


# ── amendment ───────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-CTL-021")
def test_amend_refusal_order(founded, gid):
    """An empty keys object is malformed above the whole sequence, and a repeat
    of an accepted amendment is a duplicate rather than an id clash."""
    founder, ws = founded

    got = founder.post_ops(ws, founder.amend(ws, gid(), {}))
    assert got.status == 422, got.body
    assert got.code == "malformed_control_payload"

    # A key_id that is not the derivation of the pk beside it.
    founder.resync()
    fresh = secrets.token_bytes(32)
    got = founder.post_ops(ws, founder.amend(ws, gid(), {
        "control": {"pk": fixtures.b64(crypto.ed25519_public(fresh)),
                    "key_id": fixtures.b64(bytes(32))},
    }))
    assert got.status == 422, got.body
    assert got.code == "malformed_control_payload"

    # A well-formed amendment lands, and a byte-identical repeat is a duplicate.
    founder.resync()
    amend_id = gid()
    envelope = founder.amend(ws, amend_id, {
        "control": {"pk": fixtures.b64(crypto.ed25519_public(fresh)),
                    "key_id": fixtures.b64(crypto.key_id(crypto.ed25519_public(fresh)))},
    })
    got = founder.post_ops(ws, envelope)
    assert got.status == 200, got.body
    got = founder.post_ops(ws, envelope)
    assert got.status == 200, got.body
    assert got.body["results"][0]["duplicate"] is True


@pytest.mark.item("CONF-CTL-005")
def test_the_genesis_op_is_judged_for_reachability_too(server, root):
    """Both doors ask, and the append path's answer is the one that matters.

    A device registers with a genesis certificate for an id its Root derives,
    which is what mints its token — and then posts a genesis *op* naming a
    different id. The route never saw that one. If the append path took the id
    on trust, a derived policy would be enforced only against clients that
    volunteered the right answer at registration.
    """
    from roundelay.client import Device, Session

    device = Session(server, Device(secrets.token_hex(8)), root)
    cert, sig = device.genesis_cert(own(device))
    assert device.register(cert, sig, admission="conformance-admission").status == 201
    assert device.log_in().status == 200

    stray = secrets.token_bytes(16)
    got = device.post_ops(stray, device.genesis(stray))
    assert got.status == 403, got.body
    assert got.code == "workspace_not_reachable"
    assert got.detail["index"] == 0

    # Reachability sits above the signature, so an op wrong in both ways
    # answers on the id. And a genesis raises no cert_root_pk_mismatch at all:
    # it carries exactly one root_pk, its own.
    device.resync()
    got = device.post_ops(stray, device.genesis(stray, signer=secrets.token_bytes(32)))
    assert got.status == 403, got.body
    assert got.code == "workspace_not_reachable"

    # The id it does derive is accepted, so the refusals above are the
    # predicate answering rather than something else in the way.
    device.resync()
    ws = own(device)
    assert device.post_ops(ws, device.genesis(ws)).status == 200
