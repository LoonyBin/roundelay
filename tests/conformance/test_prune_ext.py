"""prune_ext: folding ops of a class the server does not understand.

A soft prune replaces an op with another and names the replacement. A prune_ext
does not — there is nothing to replace, because the server cannot read either
one — so it carries no reprise and names instead the class and the NAME it
believes those ops were written under. That NAME is the whole of the safety
argument: the server refuses to fold ops whose author agreed to a different
meaning of the class byte, rather than folding them under the meaning it holds
today.

Everything here runs against the deployment that serves two extension classes,
0xCC as "purge" and 0xCD as "copy", and one opaque class at 0x40.
"""

from __future__ import annotations

import secrets

import pytest

from conftest import (EXT_CLASS, EXT_NAME, OPAQUE_CLASS, SECOND_EXT_CLASS,
                      SECOND_EXT_NAME, requires_durable_store)
from roundelay import fixtures

pytestmark = pytest.mark.usefixtures("ext_server")


def gid() -> str:
    return fixtures.uuid(secrets.token_bytes(16))


@pytest.fixture
def folded(ext_founded):
    """A Workspace holding one op of each extension class, both bound."""
    founder, ws = ext_founded
    got = founder.post_ops(
        ws,
        founder.bind(ws, EXT_CLASS, EXT_NAME),
        founder.ext_op(ws, EXT_CLASS, EXT_NAME, b"purge-me"),
        founder.bind(ws, SECOND_EXT_CLASS, SECOND_EXT_NAME),
        founder.ext_op(ws, SECOND_EXT_CLASS, SECOND_EXT_NAME, b"copy-me"),
        founder.content(ws, b"opaque", op_class=OPAQUE_CLASS),
    )
    assert got.status == 200, got.body

    rows = founder.ops(ws, "?include_reprised=true").body["ops"]
    by_class = {}
    for row in rows:
        by_class.setdefault(founder.header_of(row).op_class, []).append(row)
    return founder, ws, by_class


# ── shape ───────────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-PRUNE-007")
@pytest.mark.parametrize("payload,why", [
    ({"type": "prune_ext", "name": EXT_NAME, "targets": []}, "no op_class"),
    ({"type": "prune_ext", "op_class": EXT_CLASS, "targets": []}, "no name"),
    ({"type": "prune_ext", "op_class": 0x80, "name": EXT_NAME, "targets": []},
     "an op_class below 192"),
    ({"type": "prune_ext", "op_class": 256, "name": EXT_NAME, "targets": []},
     "an op_class above 255"),
    ({"type": "prune_ext", "op_class": "cc", "name": EXT_NAME, "targets": []},
     "an op_class spelled as hex"),
    ({"type": "prune_ext", "op_class": EXT_CLASS, "name": "Purge", "targets": []},
     "a name with a capital"),
    ({"type": "prune_ext", "op_class": EXT_CLASS, "name": "purge-", "targets": []},
     "a name ending in a dash"),
    ({"type": "prune_ext", "op_class": EXT_CLASS, "name": "", "targets": []},
     "an empty name"),
    ({"type": "prune_ext", "op_class": EXT_CLASS, "name": "p" * 33, "targets": []},
     "a name over 32 bytes"),
    ({"type": "prune_ext", "op_class": EXT_CLASS, "name": EXT_NAME, "targets": [],
      "surprise": 1}, "an unrecognised key"),
])
def test_prune_ext_shape_rules(ext_founded, payload, why):
    """All malformed_prune_payload — the payload cannot be read, so there is
    nothing more specific to say about it."""
    founder, ws = ext_founded
    got = founder.post_ops(ws, founder.prune_payload(ws, payload))
    assert got.status == 422, (why, got.body)
    assert got.code == "malformed_prune_payload", why


@pytest.mark.item("CONF-PRUNE-007")
def test_a_prune_ext_never_carries_a_reprise(ext_founded):
    """It replaces nothing, so a reprise is an unrecognised key rather than a
    reference the server goes looking for — prune_reprise_not_found cannot
    arise on one."""
    founder, ws = ext_founded
    got = founder.post_ops(ws, founder.prune_payload(ws, {
        "type": "prune_ext", "op_class": EXT_CLASS, "name": EXT_NAME,
        "reprise": {"op_id": gid()}, "targets": [],
    }))
    assert got.status == 422, got.body
    assert got.code == "malformed_prune_payload"
    assert got.code != "prune_reprise_not_found"


@pytest.mark.item("CONF-PRUNE-007")
def test_the_target_shape_rules_bind_identically(folded):
    """The same three as a soft prune: a prune_ext is a different payload, not
    a different set of rules about targets."""
    founder, ws, by_class = folded
    one = founder.target(by_class[EXT_CLASS][0])

    got = founder.post_ops(ws, founder.prune_ext(ws, EXT_CLASS, EXT_NAME, []))
    assert got.status == 422 and got.code == "prune_targets_empty", got.body

    got = founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, EXT_NAME, [one, dict(one)]))
    assert got.status == 422 and got.code == "prune_duplicate_target", got.body

    by_author = dict(one, seq=one["seq"] + 1000)
    got = founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, EXT_NAME, [one, by_author]))
    assert got.status == 422 and got.code == "prune_duplicate_target", got.body

    many = [dict(one, seq=one["seq"] + i, author_seq=one["author_seq"] + i)
            for i in range(1001)]
    got = founder.post_ops(ws, founder.prune_ext(ws, EXT_CLASS, EXT_NAME, many))
    assert got.status == 422 and got.code == "prune_targets_too_many", got.body


# ── the per-target sequence ─────────────────────────────────────────────────


@pytest.mark.item("CONF-PRUNE-008")
def test_the_per_target_order(folded):
    """Each check shown to precede the next by a target faulty in both ways."""
    founder, ws, by_class = folded
    mine = by_class[EXT_CLASS][0]
    good = founder.target(mine)

    def fold(targets, name=EXT_NAME, op_class=EXT_CLASS):
        return founder.post_ops(ws, founder.prune_ext(ws, op_class, name, targets))

    # 1. not found — and also of the wrong class and wrongly attested, which
    # are checks that need a stored op to make.
    absent = dict(good, seq=99999, author_seq=99999, envelope_hash="ab" * 32)
    got = fold([absent])
    assert got.status == 422 and got.code == "prune_target_not_found", got.body

    # 2. control, which is also not of the class named.
    control = founder.target(by_class[0x80][0])
    got = fold([dict(control, envelope_hash="ab" * 32)])
    assert got.status == 422 and got.code == "prune_target_is_control", got.body

    # 4. any other bit-7 class — 0xBF here — answers on the class and never
    # prune_ext_wrong_class, which is the first of the two seams.
    ext_binding = founder.target(by_class[0xBF][0])
    got = fold([dict(ext_binding, envelope_hash="ab" * 32)])
    assert got.status == 422, got.body
    assert got.code == "prune_target_is_server_read"

    # 5. wrong class, in both directions: another extension class, and an
    # opaque one. Both also wrongly attested, so the class is shown to lead.
    for row in (by_class[SECOND_EXT_CLASS][0], by_class[OPAQUE_CLASS][0]):
        target = dict(founder.target(row), envelope_hash="ab" * 32)
        got = fold([target])
        assert got.status == 422, got.body
        assert got.code == "prune_ext_wrong_class"
        assert got.detail["seq"] == target["seq"]

    # 6. attestation, which is the second seam: a target whose envelope_hash and
    # whose name in force are both wrong answers on the hash.
    got = fold([dict(good, envelope_hash="ab" * 32)], name=SECOND_EXT_NAME)
    assert got.status == 422, got.body
    assert got.code == "prune_target_attestation_mismatch"

    # 7. name, carrying seq and the name in force there.
    got = fold([good], name=SECOND_EXT_NAME)
    assert got.status == 422, got.body
    assert got.code == "prune_ext_name_mismatch"
    assert got.detail["seq"] == good["seq"]
    assert got.detail["expected"] == EXT_NAME

    # 8. already reprised, once the honest fold has landed.
    assert fold([good]).status == 200
    got = fold([good])
    assert got.status == 422, got.body
    assert got.code == "prune_target_already_reprised"


@pytest.mark.item("CONF-PRUNE-008")
def test_the_targets_are_judged_in_payload_order(folded):
    """A set of targets is judged one at a time and the first fault answers, so
    a client repairs one thing at a time."""
    founder, ws, by_class = folded
    good = founder.target(by_class[EXT_CLASS][0])
    wrong_class = founder.target(by_class[SECOND_EXT_CLASS][0])
    absent = dict(good, seq=99999, author_seq=99999)

    got = founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, EXT_NAME, [wrong_class, absent]))
    assert got.code == "prune_ext_wrong_class", got.body

    got = founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, EXT_NAME, [absent, wrong_class]))
    assert got.code == "prune_target_not_found", got.body


# ── who may author one ──────────────────────────────────────────────────────


@pytest.mark.item("CONF-PRUNE-010")
def test_the_author_needs_no_binding_of_its_own(ext_founded, enrol, gid):
    """A binding says "I write ops of this class under this meaning". Folding
    somebody else's ops is not writing one, so the folder needs none — and the
    absence of one is never checked."""
    founder, ws = ext_founded
    writer = enrol(ws, founder, role=None)
    founder.resync()
    assert founder.post_ops(ws, founder.grant(ws, writer.d, "owner", gid())).status == 200
    founder.resync()

    # The writer binds and writes; the founder holds no binding for the class
    # and never has.
    writer.resync()
    got = writer.post_ops(ws,
                          writer.bind(ws, EXT_CLASS, EXT_NAME),
                          writer.ext_op(ws, EXT_CLASS, EXT_NAME, b"theirs"))
    assert got.status == 200, got.body

    rows = founder.ops(ws, "?include_reprised=true").body["ops"]
    theirs = next(r for r in rows
                  if founder.header_of(r).op_class == EXT_CLASS
                  and founder.header_of(r).author_member_id == writer.d.member_id)

    founder.resync()
    got = founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, EXT_NAME, [founder.target(theirs)]))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-PRUNE-010")
def test_the_named_class_is_judged_for_range_alone(ext_founded):
    """Never against the configuration. A deployment that stopped implementing
    a class would otherwise strand every op of it: unfoldable for ever, because
    the one op that could fold them names the class it is folding.

    A bind of the same class answers ext_class_not_enabled, which is the
    contrast — the two rules read the same byte and ask different questions.
    """
    founder, ws = ext_founded
    unserved = 0xC1

    got = founder.post_ops(ws, founder.bind(ws, unserved, "whatever"))
    assert got.status == 422 and got.code == "ext_class_not_enabled", got.body

    # The same class named by a prune_ext gets as far as its targets.
    founder.resync()
    got = founder.post_ops(ws, founder.prune_ext(ws, unserved, "whatever", [{
        "seq": 99999, "author_member_id": fixtures.uuid(founder.d.member_id),
        "author_seq": 99999, "envelope_hash": "ab" * 32,
    }]))
    assert got.status == 422, got.body
    assert got.code == "prune_target_not_found"


# ── what an accepted fold does ──────────────────────────────────────────────


@pytest.mark.item("CONF-PRUNE-012")
def test_a_fold_marks_and_a_hard_prune_destroys(folded):
    """Reprised in the one sense that state has: hidden from the default read,
    served byte-identically under include_reprised, and then destroyable."""
    founder, ws, by_class = folded
    row = by_class[EXT_CLASS][0]

    assert founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, EXT_NAME, [founder.target(row)])).status == 200

    assert row["seq"] not in [r["seq"] for r in founder.ops(ws).body["ops"]]
    served = founder.ops(ws, "?include_reprised=true").body["ops"]
    assert next(r for r in served if r["seq"] == row["seq"])["envelope"] == row["envelope"]

    # A hard_prune then destroys it, and carries no op_class and no name of its
    # own — it names positions, and what they held is no longer its business.
    got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(row)]))
    assert got.status == 200, got.body
    after = founder.ops(ws, "?include_reprised=true").body["ops"]
    assert row["seq"] not in [r["seq"] for r in after]


@pytest.mark.item("CONF-PRUNE-012")
def test_what_no_prune_ext_has_marked(folded):
    """An extension-class op nothing folded, and a 0xBF op — which no type ever
    marks, so it answers the same code for ever."""
    founder, ws, by_class = folded

    for row in (by_class[SECOND_EXT_CLASS][0], by_class[0xBF][0]):
        got = founder.post_ops(ws, founder.hard_prune(ws, [founder.target(row)]))
        assert got.status == 422, got.body
        assert got.code == "hard_prune_target_not_reprised"

    # The extension-class one becomes destroyable; the 0xBF one never does,
    # because no type will mark it.
    assert founder.post_ops(ws, founder.prune_ext(
        ws, SECOND_EXT_CLASS, SECOND_EXT_NAME,
        [founder.target(by_class[SECOND_EXT_CLASS][0])])).status == 200
    assert founder.post_ops(ws, founder.hard_prune(
        ws, [founder.target(by_class[SECOND_EXT_CLASS][0])])).status == 200

    got = founder.post_ops(ws, founder.prune_ext(
        ws, 0xBF, EXT_NAME, [founder.target(by_class[0xBF][0])]))
    assert got.status == 422, got.body
    assert got.code in {"malformed_prune_payload", "prune_target_is_server_read"}


# ── the name is read from the log ───────────────────────────────────────────


@pytest.mark.item("CONF-PRUNE-014")
def test_a_client_takes_the_name_from_the_log(folded):
    """Not from its own binding, and not from GET /health.

    Here all three agree, so what is shown is the discipline rather than a
    divergence: the value posted is the one read out of the target's author's
    binding, and a payload built from either of the other two sources is
    refused when they differ — which the reconfiguration case below shows.
    """
    founder, ws, by_class = folded
    row = by_class[EXT_CLASS][0]

    # The name in force at the target's position, read from the log: the
    # author's most recent bind of that class at or below it.
    rows = founder.ops(ws, "?include_reprised=true").body["ops"]
    author = founder.header_of(row).author_member_id
    name_in_force = None
    for candidate in rows:
        header = founder.header_of(candidate)
        if candidate["seq"] > row["seq"] or header.op_class != 0xBF:
            continue
        if header.author_member_id != author:
            continue
        import json
        payload = json.loads(founder.s.ladder.unpack_body(
            fixtures.b64d(candidate["envelope"])[158:-64]))
        if payload["op_class"] != EXT_CLASS:
            continue
        name_in_force = payload.get("name") if payload["type"] == "bind" else None

    assert name_in_force == EXT_NAME
    assert founder.post_ops(ws, founder.prune_ext(
        ws, EXT_CLASS, name_in_force, [founder.target(row)])).status == 200


@pytest.mark.item("CONF-PRUNE-009")
@requires_durable_store()
def test_the_name_is_the_one_in_force_at_the_targets_position(deployment, root):
    """Positional, and per target.

    Two intervals for one class under two different names cannot exist within a
    single deployment configuration — a bind is checked against what the server
    implements now, so every accepted binding for a class names the same NAME.
    The case the rule exists for is therefore a *reconfiguration*: the operator
    changes what 0xCC means, and the ops written under the old meaning must
    still be foldable under the old name and must not be foldable under the new
    one.

    So this is two processes over one log: a server implementing 0xCC as
    "purge", and then one implementing it as "copy", with the log intact.
    """
    from roundelay.client import Server

    from conftest import ADMISSION_TOKEN, derived, found

    schema = f"reconf_{secrets.token_hex(4)}"
    before = Server(deployment(
        "-admission", f"token:{ADMISSION_TOKEN}",
        "-extension-classes", f"{EXT_CLASS:02x}={EXT_NAME}", schema=schema))
    after = Server(deployment(
        "-admission", f"token:{ADMISSION_TOKEN}",
        "-extension-classes", f"{EXT_CLASS:02x}={SECOND_EXT_NAME}", schema=schema))

    try:
        founder, ws = found(before, root)
        founder.resync()
        assert founder.post_ops(ws, founder.role_table(ws, [
            {"role": "owner", "classes": [0x01, 0x02, 0x80, 0x81, 0xBF, EXT_CLASS],
             "prune_types": ["prune", "prune_ext", "hard_prune"]},
            {"role": "participant", "classes": [0x01], "prune_types": []},
        ])).status == 200
        founder.resync()

        got = founder.post_ops(ws,
                               founder.bind(ws, EXT_CLASS, EXT_NAME),
                               founder.ext_op(ws, EXT_CLASS, EXT_NAME, b"old meaning"))
        assert got.status == 200, got.body
        founder.resync()

        rows = founder.ops(ws, "?include_reprised=true").body["ops"]
        old = next(r for r in rows if founder.header_of(r).op_class == EXT_CLASS)

        # The operator reconfigures. The same device, the same log, a server
        # that now implements 0xCC as "copy".
        #
        # The device logs in again, because an access token is derived from a
        # secret this deployment mints per process — so a restart ends every
        # session, which is what a refresh token is for. The member record and
        # its keys are in the store and outlive the process.
        founder.s = after
        assert founder.log_in().status == 200
        founder.resync()

        # The name it implements *now* is not the name in force where that op
        # landed, and the refusal says which.
        got = founder.post_ops(ws, founder.prune_ext(
            ws, EXT_CLASS, SECOND_EXT_NAME, [founder.target(old)]))
        assert got.status == 422, got.body
        assert got.code == "prune_ext_name_mismatch"
        assert got.detail["seq"] == old["seq"]
        assert got.detail["expected"] == EXT_NAME

        # And the name that *was* in force folds it, though no deployment
        # implements 0xCC that way any more.
        founder.resync()
        got = founder.post_ops(ws, founder.prune_ext(
            ws, EXT_CLASS, EXT_NAME, [founder.target(old)]))
        assert got.status == 200, got.body
    finally:
        before.close()
        after.close()
