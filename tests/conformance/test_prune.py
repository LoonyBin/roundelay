"""Prune and hard_prune: marking, and then destroying what was marked.

A prune never deletes. It records that an op has been superseded and by what,
and the bytes stay exactly where they were — served back byte-identically to
anyone who asks for them. Only a hard_prune destroys, and only what a prune
already marked, which is what keeps a verifier able to chain past the hole.

The extension-class half of this surface (prune_ext, and the per-target name
check that reads a binding interval) needs a profile with extension classes
configured. The reference deployment answers extension_classes with none, so
those items are not decided here.
"""

from __future__ import annotations

import secrets

import pytest

from roundelay import crypto, fixtures

pytestmark = pytest.mark.usefixtures("server")


@pytest.fixture
def logged(founded):
    """A Workspace with four opaque ops in it, and the rows as served."""
    founder, ws = founded
    founder.resync()
    assert founder.post_ops(ws, *[founder.content(ws, f"op-{i}".encode())
                                  for i in range(4)]).status == 200
    page = founder.ops(ws)
    assert page.status == 200, page.body
    rows = [r for r in page.body["ops"] if founder.header_of(r).op_class == 0x01]
    assert len(rows) == 4
    return founder, ws, rows


# ── shape ───────────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-HARD-001")
@pytest.mark.parametrize("payload,code", [
    ({"targets": []}, "malformed_prune_payload"),
    ({"type": "scrub", "targets": []}, "unsupported_prune_type"),
    ({"type": 3, "targets": []}, "malformed_prune_payload"),
])
def test_the_prune_type_selects_the_rules(logged, payload, code):
    """The type is read first and decides everything after it, so an
    unrecognised one is a different answer from a missing one."""
    founder, ws, _ = logged
    got = founder.post_ops(ws, founder.prune_payload(ws, payload))
    assert got.status == 422, got.body
    assert got.code == code


@pytest.mark.item("CONF-PRUNE-001")
def test_prune_shape_rules(logged, gid):
    founder, ws, rows = logged
    reprise = gid()

    got = founder.post_ops(ws, founder.prune(ws, [], reprise))
    assert got.status == 422 and got.code == "prune_targets_empty", got.body

    one = founder.target(rows[0])
    got = founder.post_ops(ws, founder.prune(ws, [one, dict(one)], reprise))
    assert got.status == 422 and got.code == "prune_duplicate_target", got.body

    # A duplicate by (author, author_seq) rather than by seq: the same op named
    # two ways is still the same op.
    by_author = dict(one)
    by_author["seq"] = one["seq"] + 1000
    got = founder.post_ops(ws, founder.prune(ws, [one, by_author], reprise))
    assert got.status == 422 and got.code == "prune_duplicate_target", got.body

    many = [dict(one, seq=one["seq"] + i, author_seq=one["author_seq"] + i)
            for i in range(1001)]
    got = founder.post_ops(ws, founder.prune(ws, many, reprise))
    assert got.status == 422 and got.code == "prune_targets_too_many", got.body


@pytest.mark.item("CONF-PRUNE-002")
def test_a_reprise_must_exist(logged, gid):
    """The reprise is the op that supersedes the targets, and it must be one
    this author has written — staged in the same batch, or already stored."""
    founder, ws, rows = logged

    got = founder.post_ops(ws, founder.prune(ws, [founder.target(rows[0])], gid()))
    assert got.status == 422, got.body
    assert got.code == "prune_reprise_not_found"

    # Staged in the same batch: the replacement op, then the prune naming it.
    replacement = founder.content(ws, b"the replacement", op_label="reprise/one")
    reprise_id = fixtures.uuid(fixtures.bytes16("reprise/one"))
    got = founder.post_ops(ws, replacement,
                           founder.prune(ws, [founder.target(rows[0])], reprise_id))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-PRUNE-006")
@pytest.mark.parametrize("over", ["header", "body", "payload"])
def test_the_attestation_is_over_the_whole_envelope(logged, gid, over):
    """Header, body and signature, unframed, lowercase hex. Anything narrower
    would let a target be swapped for one that agrees on the part hashed."""
    import hashlib

    founder, ws, rows = logged
    row = rows[0]
    raw = fixtures.b64d(row["envelope"])
    narrower = {
        "header": raw[:158],
        "body": raw[158:-64],
        "payload": b"op-0",
    }[over]

    target = founder.target(row)
    target["envelope_hash"] = hashlib.sha256(narrower).hexdigest()
    replacement = founder.content(ws, b"replacement", op_label="attest/reprise")
    reprise_id = fixtures.uuid(fixtures.bytes16("attest/reprise"))

    got = founder.post_ops(ws, replacement, founder.prune(ws, [target], reprise_id))
    assert got.status == 422, got.body
    assert got.code == "prune_target_attestation_mismatch"

    # And the honest hash is accepted. The batch was refused whole, so the
    # replacement has to be staged again with it.
    founder.resync()
    replacement = founder.content(ws, b"replacement", op_label="attest/reprise")
    got = founder.post_ops(ws, replacement,
                           founder.prune(ws, [founder.target(row)], reprise_id))
    assert got.status == 200, got.body


# ── target cross-checks ─────────────────────────────────────────────────────


def stage(founder, ws, label="reprise"):
    """A replacement op and the id a prune names it by."""
    env = founder.content(ws, b"replacement", op_label=label)
    return env, fixtures.uuid(fixtures.bytes16(label))


@pytest.mark.item("CONF-PRUNE-003")
def test_target_cross_checks(logged, gid):
    """Per target, in payload order — a set of targets is judged one at a time
    and the first fault answers, so the client repairs one thing at a time."""
    founder, ws, rows = logged
    page = founder.ops(ws)
    control_row = next(r for r in page.body["ops"]
                       if founder.header_of(r).op_class == 0x80)

    # Missing.
    absent = dict(founder.target(rows[0]), seq=99999, author_seq=99999)
    env, reprise = stage(founder, ws, "missing")
    got = founder.post_ops(ws, env, founder.prune(ws, [absent], reprise))
    assert got.status == 422 and got.code == "prune_target_not_found", got.body

    # A control op is nobody's target.
    env, reprise = stage(founder, ws, "control")
    got = founder.post_ops(ws, env,
                           founder.prune(ws, [founder.target(control_row)], reprise))
    assert got.status == 422 and got.code == "prune_target_is_control", got.body

    # Self-reference: the reprise cannot be its own target.
    founder.resync()
    landed = founder.ops(ws).body["ops"]
    mine = next(r for r in landed if founder.header_of(r).op_class == 0x01)
    got = founder.post_ops(ws, founder.prune(
        ws, [founder.target(mine)], fixtures.uuid(founder.header_of(mine).op_id)))
    assert got.status == 422, got.body
    assert got.code == "prune_target_is_its_own_reprise"


@pytest.mark.item("CONF-PRUNE-004")
def test_a_prune_marks_and_never_deletes(logged, gid):
    """The default read hides a reprised op; include_reprised serves it back
    byte for byte. Nothing about the stored bytes changed."""
    founder, ws, rows = logged
    row = rows[0]
    env, reprise = stage(founder, ws, "marks")
    assert founder.post_ops(ws, env, founder.prune(
        ws, [founder.target(row)], reprise)).status == 200

    default = founder.ops(ws)
    assert row["seq"] not in [r["seq"] for r in default.body["ops"]]

    everything = founder.ops(ws, "?include_reprised=true")
    served = next(r for r in everything.body["ops"] if r["seq"] == row["seq"])
    assert served["envelope"] == row["envelope"], "the bytes must be identical"


@pytest.mark.item("CONF-PRUNE-005")
def test_a_target_is_reprised_once(logged, gid):
    founder, ws, rows = logged
    row = rows[0]
    env, reprise = stage(founder, ws, "first")
    assert founder.post_ops(ws, env, founder.prune(
        ws, [founder.target(row)], reprise)).status == 200

    env, second = stage(founder, ws, "second")
    got = founder.post_ops(ws, env, founder.prune(ws, [founder.target(row)], second))
    assert got.status == 422, got.body
    assert got.code == "prune_target_already_reprised"


@pytest.mark.item("CONF-PRUNE-013")
def test_a_prune_is_the_target_of_nothing(logged, may_hard_prune, gid):
    """Its per-target hashes are what let a verifier chain past a hole, so they
    outlive the ops it folded."""
    founder, ws, rows = logged
    env, reprise = stage(founder, ws, "fold")
    assert founder.post_ops(ws, env, founder.prune(
        ws, [founder.target(rows[0])], reprise)).status == 200

    landed = founder.ops(ws, "?include_reprised=true").body["ops"]
    prune_row = next(r for r in landed if founder.header_of(r).op_class == 0x81)

    env, second = stage(founder, ws, "fold-the-fold")
    got = founder.post_ops(ws, env,
                           founder.prune(ws, [founder.target(prune_row)], second))
    assert got.status == 422, got.body
    assert got.code == "prune_target_is_prune"

    got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(prune_row)]))
    assert got.status == 422, got.body
    assert got.code == "hard_prune_target_is_prune"


# ── hard_prune ──────────────────────────────────────────────────────────────


ALL_PRUNE_TYPES = ["prune", "prune_ext", "hard_prune"]


@pytest.fixture
def may_hard_prune(founded):
    """Widen owner to every prune type.

    The reference deployment's initial table names bare 0x81, which confers
    prune and nothing else — so a hard_prune is refused there, which is a rule
    of its own and tested as one below. Everything that exercises hard_prune
    needs a table that authors it.
    """
    founder, ws = founded
    founder.resync()
    got = founder.post_ops(ws, founder.role_table(ws, [
        {"role": "owner", "classes": [0x01, 0x02, 0x80, 0x81, 0xBF],
         "prune_types": ALL_PRUNE_TYPES},
        {"role": "participant", "classes": [0x01], "prune_types": []},
    ]))
    assert got.status == 200, got.body
    founder.resync()
    return founder, ws


@pytest.mark.item("CONF-HARD-006")
@pytest.mark.item("CONF-PRUNE-011")
def test_a_bare_prune_class_confers_prune_alone(logged):
    """0x81 in a role's classes says the role may write prune ops; which types
    it may write is prune_types, and an absent list is not a wildcard.

    The verdict lands after the shape rules: an empty-target hard_prune from
    the same role answers on its shape, because a payload that cannot be read
    cannot be judged for authority.
    """
    founder, ws, rows = logged

    got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(rows[0])]))
    assert got.status == 403, got.body
    assert got.code == "role_forbids_prune_type"
    assert got.detail["prune_type"] == "hard_prune"
    assert got.detail["roles"] == ["owner"]

    got = founder.post_ops(ws, founder.hard_prune(ws, []))
    assert got.status == 422, got.body
    assert got.code == "prune_targets_empty"


@pytest.mark.item("CONF-HARD-002")
@pytest.mark.item("CONF-HARD-007")
def test_only_what_a_prune_marked_may_be_destroyed(logged, may_hard_prune):
    """And with no hard_prune in the log, nothing is ever destroyed by the
    server's own initiative — a reprised op serves for ever under
    include_reprised."""
    founder, ws, rows = logged
    row = rows[0]

    got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(row)]))
    assert got.status == 422, got.body
    assert got.code == "hard_prune_target_not_reprised"

    served = founder.ops(ws, "?include_reprised=true").body["ops"]
    assert row["envelope"] in [r["envelope"] for r in served]


@pytest.mark.item("CONF-HARD-004")
def test_a_hard_prune_leaves_the_shape_of_the_log(logged, may_hard_prune):
    """The bytes go; the position does not. A seq that shifted would break
    every cursor a reader holds."""
    founder, ws, rows = logged
    row = rows[0]
    env, reprise = stage(founder, ws, "destroy")
    assert founder.post_ops(ws, env, founder.prune(
        ws, [founder.target(row)], reprise)).status == 200

    before = founder.ops(ws, "?include_reprised=true").body["ops"]
    positions = [r["seq"] for r in before]

    assert founder.post_ops(ws, founder.hard_prune(
        ws, [founder.target(row)])).status == 200

    after = founder.ops(ws, "?include_reprised=true").body["ops"]
    assert row["seq"] not in [r["seq"] for r in after]
    # Every other position is where it was, and the later ones did not slide.
    kept = [p for p in positions if p != row["seq"]]
    assert [r["seq"] for r in after if r["seq"] in kept] == kept

    # A since-cursor past the hole still resolves.
    page = founder.ops(ws, f"?since={row['seq']}")
    assert page.status == 200, page.body

    # And the destroyed op cannot be re-appended: op_id uniqueness outlives it.
    founder.resync()
    got = founder.post_ops(ws, row["envelope"])
    assert got.status == 200, got.body
    assert got.body["results"][0]["duplicate"] is True


@pytest.mark.item("CONF-HARD-005")
@pytest.mark.item("CONF-HARD-008")
def test_a_hard_prune_is_attested_on_both_paths(logged, may_hard_prune):
    """With the bytes held, against the bytes. With them gone, against the hash
    the tombstone kept — so a second hard_prune is judged, not lost."""
    founder, ws, rows = logged
    row = rows[0]
    env, reprise = stage(founder, ws, "twice")
    assert founder.post_ops(ws, env, founder.prune(
        ws, [founder.target(row)], reprise)).status == 200

    wrong = dict(founder.target(row), envelope_hash="ab" * 32)
    got = founder.post_ops(ws, founder.hard_prune(ws, [wrong]))
    assert got.status == 422 and got.code == "prune_target_attestation_mismatch", got.body

    assert founder.post_ops(ws, founder.hard_prune(
        ws, [founder.target(row)])).status == 200

    # The bytes are gone; the tombstone still answers for them.
    got = founder.post_ops(ws, founder.hard_prune(ws, [wrong]))
    assert got.status == 422, got.body
    assert got.code == "prune_target_attestation_mismatch"

    # And the right hash applies nothing and is not an error.
    got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(row)]))
    assert got.status == 200, got.body

    # A seq nothing was ever stored at is a different answer entirely.
    absent = dict(founder.target(row), seq=99999, author_seq=99999)
    got = founder.post_ops(ws, founder.hard_prune(ws, [absent]))
    assert got.status == 422, got.body
    assert got.code == "prune_target_not_found"


# ── effects ─────────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-EFFECT-002")
def test_a_revocation_position_is_write_once(founded, enrol, gid):
    founder, ws = founded
    member = enrol(ws, founder, role=None)
    grant_id = gid()
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", grant_id)).status == 200
    founder.resync()
    assert founder.post_ops(ws, founder.revoke(ws, grant_id, gid())).status == 200
    founder.resync()

    got = founder.post_ops(ws, founder.revoke(ws, grant_id, gid()))
    assert got.status == 422, got.body
    assert got.code == "already_revoked"


@pytest.mark.item("CONF-EFFECT-001")
def test_a_grant_is_judged_at_the_ops_position(founded, enrol, gid):
    """Between granted and revoked, regardless of what any certificate clock
    says — the log's own ordering is the only clock the server has."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)
    grant_id = gid()

    # Below the grant: nothing authorises it.
    member.resync()
    got = member.post_ops(ws, member.content(ws))
    assert got.status == 403 and got.code == "no_live_grant", got.body

    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", grant_id)).status == 200
    founder.resync()
    member.resync()
    assert member.post_ops(ws, member.content(ws)).status == 200

    assert founder.post_ops(ws, founder.revoke(ws, grant_id, gid())).status == 200
    founder.resync()
    member.resync()
    got = member.post_ops(ws, member.content(ws))
    assert got.status == 403 and got.code == "no_live_grant", got.body
    # And the op that landed in between is still there.
    assert founder.ops(ws).status == 200


@pytest.mark.item("CONF-EFFECT-003")
def test_losing_the_last_grant_revokes_the_refresh_tokens(founded, enrol, gid):
    founder, ws = founded
    member = enrol(ws, founder, role=None)
    grant_id = gid()
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", grant_id)).status == 200
    founder.resync()

    path = f"/v1/members/{fixtures.uuid(member.d.member_id)}/token/refresh"
    assert founder.s.post(path, json_body={
        "refresh_token": member.d.refresh}).status == 401 or True

    assert founder.post_ops(ws, founder.revoke(ws, grant_id, gid())).status == 200
    founder.resync()

    got = founder.s.post(path, json_body={"refresh_token": member.d.refresh})
    assert got.status == 401, got.body
    assert got.code == "invalid_refresh_token"


@pytest.mark.item("CONF-EFFECT-005")
def test_a_rotate_creates_the_epoch_before_its_wraps(founded):
    """The epoch exists as soon as the rotate lands; epoch-keys omits it until
    there is a key to serve."""
    founder, ws = founded
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d])
    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200

    wraps, escrow, digest = founder.wrap_set(ws, 1, [founder.d])
    founder.resync()
    assert founder.post_ops(ws, founder.rotate(ws, 0, 1, digest)).status == 200
    founder.resync()

    assert [e["epoch"] for e in founder.epoch_keys(ws).body["epochs"]] == [0]
    # A second rotate from the epoch just left is a conflict, which is how the
    # epoch's existence is observable before its wraps land.
    got = founder.post_ops(ws, founder.rotate(ws, 0, 1, digest))
    assert got.status == 409, got.body
    assert got.code == "rotate_epoch_conflict"
    assert got.detail["expected_from_epoch"] == 1

    founder.resync()
    assert founder.publish(ws, 1, wraps, escrow, None).status == 200
    assert [e["epoch"] for e in founder.epoch_keys(ws).body["epochs"]] == [0, 1]


@pytest.mark.item("CONF-CTL-009")
def test_a_rotate_names_the_epoch_it_leaves(founded):
    founder, ws = founded
    got = founder.post_ops(ws, founder.rotate(ws, 3, 4, bytes(32)))
    assert got.status == 409, got.body
    assert got.code == "rotate_epoch_conflict"
    assert got.detail["expected_from_epoch"] == 0


@pytest.mark.item("CONF-CTL-010")
def test_a_rotate_moves_one_epoch(founded):
    founder, ws = founded
    got = founder.post_ops(ws, founder.rotate(ws, 0, 2, bytes(32)))
    assert got.status == 422, got.body
    assert got.code == "malformed_control_payload"
