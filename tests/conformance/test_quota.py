"""Bounding what a Workspace consumes, and the four things that never are.

A deployment may stop accepting writes. It may not hold a history hostage, and
it may not stand between an identity and the key that would let it leave — so
reading the log, the vault, authentication and the wrap-set upload are refused
for consumption on no deployment, however its arrangement is written.

The two exempt classes are the same argument turned inwards. 0x80 because
revoking a compromised device is a security remedy and gating it on payment
makes non-payment a way to keep an attacker's grant alive; 0x81 because it is
the remedy *for this refusal* — the way back under an allowance is to write a
hard_prune, and a hard_prune is a write.

The deployments here bound the count of ops, which is a measure and not the
measure. What "consumed" means is deliberately unspecified, and none of these
tests can tell which rule refused them — which is the property, not a gap.
"""

from __future__ import annotations

import secrets

import pytest

from conftest import ADMISSION_TOKEN, found
from roundelay import fixtures
from roundelay.client import Device, Session

pytestmark = pytest.mark.usefixtures("quota_server")


@pytest.fixture
def exhausted(quota_server, root):
    """A founded Workspace on a deployment that refuses every non-exempt write.

    Founding still works, which is the first thing the exemption buys: a
    genesis and its self-grant are both 0x80.
    """
    return found(quota_server, root)


# ── the refusal ─────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-QUOTA-001")
def test_the_refusal_says_nothing_but_the_code(exhausted):
    """402, no retry_after_seconds because waiting is not the remedy, and no
    commercial surface at all — a code that carried an allowance or a price
    would be a code every client had to parse differently per server."""
    founder, ws = exhausted

    got = founder.post_ops(ws, founder.content(ws))
    assert got.status == 402, got.body
    assert got.code == "workspace_quota_exhausted"

    detail = got.detail
    assert "retry_after_seconds" not in detail
    # Nothing else is in there either. The code is the whole message.
    assert set(detail) == {"code"}, detail
    for word in ("allowance", "plan", "price", "url", "amount", "quota", "bytes"):
        assert not any(word in k.lower() for k in detail), detail
        assert not any(word in str(v).lower() for v in detail.values() if v != "workspace_quota_exhausted"), detail


@pytest.mark.item("CONF-QUOTA-002")
def test_the_four_routes_it_may_never_gate(exhausted, quota_server):
    """The exit path, and the rotation the 0x80 exemption already protects."""
    founder, ws = exhausted
    assert founder.post_ops(ws, founder.content(ws)).status == 402

    # Reading your own log. Otherwise non-payment destroys availability, and
    # the data was never really yours.
    got = founder.ops(ws)
    assert got.status == 200, got.body

    # Every vault route: it holds the identity's own recovery.
    slot = secrets.token_bytes(32).hex()
    assert founder.vault_write(slot, 1, b"recovery").status == 200
    assert founder.vault_read(slot).status == 200
    assert founder.vault_write(slot, 2, b"again").status == 200

    # Authentication — a member who cannot log in cannot read either.
    path = f"/v1/members/{fixtures.uuid(founder.d.member_id)}"
    assert quota_server.post(path + "/challenge").status == 200
    assert founder.log_in().status == 200
    assert quota_server.post(path + "/token/refresh", json_body={
        "refresh_token": founder.d.refresh}).status == 200

    # The wrap-set upload, which completes the rotation the 0x80 exemption
    # protects. Gate it and the new epoch exists with nobody able to be given
    # its key.
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d])
    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200


@pytest.mark.item("CONF-QUOTA-003")
@pytest.mark.item("CONF-QUOTA-006")
def test_the_two_exempt_classes(exhausted, enrol, gid):
    """0x80, and 0x81 whatever its payload type — the exemption is stated on
    the class, so prune and hard_prune are covered by the same sentence."""
    founder, ws = exhausted
    assert founder.post_ops(ws, founder.content(ws)).status == 402

    # A batch of control ops alone. Revocation is the case the exemption is
    # for, so this is the case it is tested with.
    member = enrol(ws, founder, role=None)
    grant_id = gid()
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", grant_id)).status == 200
    founder.resync()
    assert founder.post_ops(ws, founder.revoke(ws, grant_id, gid())).status == 200
    founder.resync()

    # A batch of 0x81 alone. There is nothing to prune, so the refusal proves
    # the class got past the ceiling: it is the shape rule answering, not 402.
    got = founder.post_ops(ws, founder.hard_prune(ws, []))
    assert got.status != 402, got.body
    assert got.code == "prune_targets_empty"

    got = founder.post_ops(ws, founder.prune(ws, [], gid()))
    assert got.status != 402, got.body
    assert got.code == "prune_targets_empty"


@pytest.mark.item("CONF-QUOTA-003")
def test_a_prune_batch_lands_under_a_closed_ceiling(quota_server, root, enrol, gid):
    """Not merely past the ceiling — all the way to a commit. The exemption is
    what makes the ceiling recoverable rather than terminal, and a hard_prune
    that is admitted but cannot land would not recover anything.

    The ops to fold have to exist before the ceiling closes, so this founds on
    the unbounded deployment's twin and writes them as control ops, which are
    exempt either way. A content op cannot be written here at all.
    """
    founder, ws = found(quota_server, root)

    # Under a closed ceiling there is nothing but 0x80 to fold, and a control
    # op is not a legal prune target. So what is provable here is that a prune
    # batch is judged on its own rules rather than on the ceiling — which the
    # target refusal, rather than 402, is exactly the evidence for.
    landed = founder.ops(ws).body["ops"]
    control_row = next(r for r in landed if founder.header_of(r).op_class == 0x80)
    got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(control_row)]))
    assert got.status != 402, got.body
    assert got.code in {"hard_prune_target_is_prune", "prune_target_is_control",
                        "hard_prune_target_not_reprised", "role_forbids_prune_type"}


@pytest.mark.item("CONF-QUOTA-004")
def test_the_exemption_does_not_survive_batching(exhausted, gid):
    """The batch is all-or-nothing, so a hard_prune sent alongside a content op
    is refused with it. Nothing breaks — the refusal is correct and says so —
    but the batch that would have freed space did not land."""
    founder, ws = exhausted

    got = founder.post_ops(ws,
                           founder.hard_prune(ws, []),
                           founder.content(ws))
    assert got.status == 402, got.body
    assert got.code == "workspace_quota_exhausted"

    # And nothing in it committed: the log is where it was.
    before = len(founder.ops(ws).body["ops"])
    founder.post_ops(ws, founder.hard_prune(ws, []), founder.content(ws))
    assert len(founder.ops(ws).body["ops"]) == before


# ── whose bytes were they ───────────────────────────────────────────────────


@pytest.mark.item("CONF-QUOTA-005")
def test_a_member_bound_is_a_different_code(member_quota_server, root, enrol):
    """Collapsing the two would tell two hundred people the Workspace is out of
    space when one runaway sync loop is the whole problem."""
    founder, ws = found(member_quota_server, root)
    member = enrol(ws, founder)

    # One non-exempt op each, and then this member is done.
    member.resync()
    assert member.post_ops(ws, member.content(ws)).status == 200
    got = member.post_ops(ws, member.content(ws))
    assert got.status == 402, got.body
    assert got.code == "member_quota_exhausted"
    assert got.detail["index"] == 0

    # The Workspace is not out of space, and another member writes.
    other = enrol(ws, founder)
    other.resync()
    assert other.post_ops(ws, other.content(ws)).status == 200


@pytest.mark.item("CONF-QUOTA-005")
def test_the_index_names_the_first_crossing(member_quota_server, root, enrol):
    """Every op in a batch shares one author, so the code is about the author
    rather than any one op — which is why *which* index it carries has to be
    stated, and why it is the op where counting stopped."""
    founder, ws = found(member_quota_server, root)
    member = enrol(ws, founder)

    # A batch of three from a member allowed one: the bound is crossed at the
    # second, and nothing commits.
    member.resync()
    got = member.post_ops(ws, *[member.content(ws, f"m{i}".encode()) for i in range(3)])
    assert got.status == 402, got.body
    assert got.code == "member_quota_exhausted"
    assert got.detail["index"] == 1

    assert member.ops(ws).status == 200
    assert not [r for r in member.ops(ws).body["ops"]
                if member.header_of(r).author_member_id == member.d.member_id
                and member.header_of(r).op_class == 0x01]
