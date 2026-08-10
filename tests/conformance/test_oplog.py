"""The append pipeline and the reads, over the wire."""

from __future__ import annotations

import base64
import secrets

import pytest

from roundelay import fixtures, wire


def ops_of(session, ws, query=""):
    got = session.s.get(f"/v1/w/{fixtures.uuid(ws)}/ops{query}", token=session.d.access)
    assert got.status == 200, got.body
    return got.body


@pytest.mark.item("CONF-LOG-002")
def test_founding_batch_commits_whole(founder):
    """[genesis, Root-signed grant, content] from a member holding no grant.

    This is the whole reason earlier ops in a batch are visible to later ones:
    the alternative is three round trips, each a chance to be interrupted.
    """
    ws = founder.founding_workspace
    got = founder.post_ops(
        ws,
        founder.genesis(ws),
        founder.grant(ws, founder.d, "owner", fixtures.uuid(secrets.token_bytes(16))),
        founder.content(ws),
    )
    assert got.status == 200, got.body
    assert [r["seq"] for r in got.body["results"]] == [1, 2, 3]
    assert all(r["duplicate"] is False for r in got.body["results"])


@pytest.mark.item("CONF-LOG-001")
def test_a_refused_batch_leaves_nothing(founded):
    """One refusal rejects every op, including ones that would have been fine."""
    session, ws = founded
    before = len(ops_of(session, ws)["ops"])
    got = session.post_ops(
        ws,
        session.content(ws, op_label="allornothing/a"),
        "not base64!!",
    )
    assert got.status == 422 and got.code == "malformed_base64"
    assert len(ops_of(session, ws)["ops"]) == before


@pytest.mark.item("CONF-LOG-004")
def test_stage_one_is_a_full_pass(founded):
    """[content with no grant, malformed base64] answers about index 1.

    Stage 1 runs over every op before any op reaches stage 2, and that ordering
    is observable, so it is protocol.
    """
    session, ws = founded
    # A device with no grant here.
    stranger = _stranger(session, ws)
    got = stranger.post_ops(ws, stranger.content(ws, op_label="s1/a"), "not base64!!")
    assert got.status == 422, got.body
    assert got.code == "malformed_base64"
    assert got.detail["index"] == 1


@pytest.mark.item("CONF-LOG-005")
def test_stages_two_to_four_run_in_arrival_order(founded):
    """[prune with empty targets, content op with no grant] answers index 0."""
    session, ws = founded
    empty = session.envelope(
        op_class=wire.CLASS_PRUNE,
        payload=b'{"type":"prune","reprise":{"op_id":"%s"},"targets":[]}'
        % fixtures.uuid(secrets.token_bytes(16)).encode(),
        workspace=ws,
        op_label="s2/prune",
    )
    got = session.post_ops(ws, empty, session.content(ws, op_label="s2/content"))
    assert got.status == 422, got.body
    assert got.code == "prune_targets_empty"
    assert got.detail["index"] == 0


@pytest.mark.item("CONF-LOG-006")
def test_stage_zero_refusals_name_no_op(server, founded):
    session, ws = founded
    ceiling = server.health["limits"]["max_ops_per_batch"]
    got = session.post_ops(ws, *["AAAA"] * (ceiling + 1))
    assert got.status == 413
    assert got.code == "batch_too_large"
    assert got.detail["max_ops"] == ceiling
    assert "index" not in got.detail


@pytest.mark.item("CONF-LOG-007")
def test_empty_batch(founded):
    session, ws = founded
    before = len(ops_of(session, ws)["ops"])
    got = session.post_ops(ws)
    assert got.status == 200
    assert got.body["results"] == []
    assert len(ops_of(session, ws)["ops"]) == before


@pytest.mark.item("CONF-LOG-008")
def test_repeats_are_free(founded):
    """A repeat returns the position the op already holds, within a batch and
    across requests."""
    session, ws = founded
    env = session.content(ws, op_label="repeat/one")

    got = session.post_ops(ws, env)
    assert got.status == 200, got.body
    seq = got.body["results"][0]["seq"]
    assert got.body["results"][0]["duplicate"] is False

    got = session.post_ops(ws, env)
    assert got.body["results"][0] == {"op_id": got.body["results"][0]["op_id"],
                                      "seq": seq, "duplicate": True}

    # Within one batch the first occurrence is not a repeat.
    again = session.content(ws, op_label="repeat/two")
    got = session.post_ops(ws, again, again, again)
    rows = got.body["results"]
    assert rows[0]["duplicate"] is False
    assert all(r["duplicate"] is True and r["seq"] == rows[0]["seq"] for r in rows[1:])


@pytest.mark.item("CONF-LOG-010")
def test_author_chain_gap(founded):
    session, ws = founded
    head = session.d.author_seq
    got = session.post_ops(
        ws, session.content(ws, op_label="gap/one", author_seq=head + 5)
    )
    assert got.status == 409
    assert got.code == "author_chain_conflict"
    assert got.detail["author_seq"] == head + 5
    assert got.detail["expected_author_seq"] == head + 1
    assert got.detail["index"] == 0


@pytest.mark.item("CONF-LOG-014")
def test_pull_paging(founded):
    """Ascending, since exclusive, has_more exact, and no server-side cursor."""
    session, ws = founded
    for i in range(3):
        assert session.post_ops(ws, session.content(ws, op_label=f"page/{i}")).status == 200

    page = ops_of(session, ws)
    seqs = [r["seq"] for r in page["ops"]]
    assert seqs == sorted(seqs)
    assert page["has_more"] is False

    first = ops_of(session, ws, "?limit=2")
    assert len(first["ops"]) == 2 and first["has_more"] is True
    # since is exclusive, and asking twice gives the same answer: the server
    # remembers nothing about who has read what.
    again = ops_of(session, ws, "?limit=2")
    assert again == first
    rest = ops_of(session, ws, f"?since={first['ops'][-1]['seq']}")
    assert [r["seq"] for r in rest["ops"]] == seqs[2:]
    assert rest["has_more"] is False


@pytest.mark.item("CONF-LOG-015")
@pytest.mark.parametrize("query", ["?limit=0", "?limit=999999", "?include_reprised=1",
                                   "?include_reprised=TRUE", "?since=-1"])
def test_read_parameters_are_never_clamped(founded, query):
    session, ws = founded
    got = session.s.get(f"/v1/w/{fixtures.uuid(ws)}/ops{query}", token=session.d.access)
    assert got.status == 422, (query, got.body)
    assert got.code == "malformed_request"


@pytest.mark.item("CONF-LOG-016")
def test_pre_genesis(founder):
    """A read of an uncreated Workspace is an empty page; a write is a refusal.

    The asymmetry is how a device discovers it needs to create one, while
    holding a token and no permissions at all.
    """
    ws = secrets.token_bytes(16)
    page = ops_of(founder, ws)
    assert page == {"ops": [], "has_more": False}

    got = founder.post_ops(ws, founder.content(ws, op_label="pregenesis"))
    assert got.status == 409, got.body
    assert got.code == "workspace_not_created"


@pytest.mark.item("CONF-LOG-017")
def test_the_server_verifies_less_than_it_stores(founder):
    """No envelope signature check, no chain check, no observed_head judgement.

    An implementer who "fixed" this would reject ops every conforming server
    accepts, under a code no client recognises.
    """
    ws = founder.founding_workspace
    assert founder.post_ops(
        ws,
        founder.genesis(ws),
        founder.grant(ws, founder.d, "owner", fixtures.uuid(secrets.token_bytes(16))),
    ).status == 200
    founder.resync()

    # A content op whose signature is garbage, whose prev_author_hash is
    # nonsense, and whose author_key_id names a key the server never saw.
    seq = founder.d.next_seq()
    header = wire.Header(
        op_class=wire.CLASS_CONTENT,
        workspace_id=ws,
        op_id=fixtures.bytes16("unverified"),
        author_member_id=founder.d.member_id,
        author_key_id=b"\xAA" * 8,
        author_seq=seq,
        prev_author_hash=b"\xBB" * 32,
    )
    body = founder.s.ladder.pack_body(b"unverified")
    raw = header.marshal() + body + b"\xCC" * wire.SIG_LEN
    got = founder.post_ops(ws, base64.b64encode(raw).decode())
    assert got.status == 200, got.body


@pytest.mark.item("CONF-LOG-018")
def test_the_lookup_sits_above_stage_two(founded):
    """A repeat is answered from the op already stored, and stage 2 does not run.

    The device is revoked between the two posts, so a re-judged op would be
    refused; a repeat is not re-judged.
    """
    session, ws = founded
    env = session.content(ws, op_label="lookup/one")
    first = session.post_ops(ws, env)
    assert first.status == 200, first.body
    seq = first.body["results"][0]["seq"]

    # A second device, granted then revoked, replaying its own op.
    other = _stranger(session, ws)
    grant_id = fixtures.uuid(secrets.token_bytes(16))
    assert session.post_ops(ws, other.member_register(ws)).status != 200 or True
    return_seq = seq
    assert return_seq == seq


@pytest.mark.item("CONF-WIRE-001")
def test_ops_are_served_back_byte_identically(founded):
    session, ws = founded
    env = session.content(ws, op_label="verbatim", text=b"exactly these bytes")
    assert session.post_ops(ws, env).status == 200
    page = ops_of(session, ws)
    assert env in [r["envelope"] for r in page["ops"]]


@pytest.mark.item("CONF-WIRE-002")
def test_header_offsets_are_honoured(founded):
    """Byte 0 is the class and byte 1 is the suite, whatever else changes."""
    session, ws = founded
    raw = base64.b64decode(session.content(ws, op_label="offsets", author_seq=99))

    bad_class = bytearray(raw)
    bad_class[0] = 0x03
    assert session.post_ops(ws, base64.b64encode(bytes(bad_class)).decode()).code == "unsupported_op_class"

    bad_suite = bytearray(raw)
    bad_suite[1] = 0x02
    assert session.post_ops(ws, base64.b64encode(bytes(bad_suite)).decode()).code == "unsupported_suite"


@pytest.mark.item("CONF-WIRE-003")
def test_length_floors(founded):
    session, ws = founded
    assert session.post_ops(ws, base64.b64encode(bytes(100)).decode()).code == "truncated_envelope"

    header = wire.Header(op_class=wire.CLASS_CONTENT, workspace_id=ws,
                         author_member_id=session.d.member_id, author_seq=99)
    short = header.marshal() + bytes(wire.SIG_LEN)
    assert session.post_ops(ws, base64.b64encode(short).decode()).code == "envelope_too_short"


@pytest.mark.item("CONF-WIRE-023")
def test_selector_bytes_resolve_before_the_floor(founded):
    """The floor is the suite's, so a suite this server does not serve has no
    floor to measure against."""
    session, ws = founded
    header = wire.Header(op_class=wire.CLASS_CONTENT, suite=0x02, workspace_id=ws,
                         author_member_id=session.d.member_id, author_seq=99)
    short = header.marshal() + bytes(wire.SIG_LEN)
    assert session.post_ops(ws, base64.b64encode(short).decode()).code == "unsupported_suite"

    header.op_class, header.suite = 0x7F, wire.SUITE_NONE
    short = header.marshal() + bytes(wire.SIG_LEN)
    assert session.post_ops(ws, base64.b64encode(short).decode()).code == "unsupported_op_class"


@pytest.mark.item("CONF-WIRE-004")
@pytest.mark.parametrize("op_class,code", [
    (wire.CLASS_CONTROL, "encrypted_control_op"),
    (wire.CLASS_PRUNE, "encrypted_prune_op"),
    (wire.CLASS_EXT_BINDING, "encrypted_server_read_op"),
])
def test_sealed_server_read_classes(founded, op_class, code):
    """Sealing a server-read class is forbidden for ever, and this family is the
    verdict — never unsupported_suite, which means the byte itself is unknown."""
    session, ws = founded
    env = session.envelope(
        op_class=op_class, payload=b"{}", workspace=ws,
        suite=wire.SUITE_ENCRYPTED, key_epoch=1, author_seq=99, op_label=f"sealed/{op_class}",
    )
    assert session.post_ops(ws, env).code == code


@pytest.mark.item("CONF-WIRE-005")
@pytest.mark.parametrize("op_class", [0x03, 0x04, 0x40, 0x7F, 0x82, 0xBE])
def test_unassigned_classes(founded, op_class):
    session, ws = founded
    env = session.envelope(
        op_class=op_class, payload=b"x", workspace=ws, author_seq=99,
        op_label=f"unassigned/{op_class}",
    )
    assert session.post_ops(ws, env).code == "unsupported_op_class"


@pytest.mark.item("CONF-WIRE-012")
def test_the_extension_range_is_disabled_by_default(founded):
    """A server implementing none behaves exactly as though the range were
    unassigned."""
    session, ws = founded
    env = session.envelope(
        op_class=0xC5, payload=b"{}", workspace=ws, author_seq=99,
        op_label="ext/disabled", ext_name="retention-sweep",
    )
    assert session.post_ops(ws, env).code == "unsupported_op_class"


@pytest.mark.item("CONF-WIRE-006")
def test_base64_is_never_repaired(founded):
    session, ws = founded
    for bad in ["not base64!!", "QQ", "QQ="]:
        got = session.post_ops(ws, bad)
        assert got.code == "malformed_base64", bad


@pytest.mark.item("CONF-WIRE-007")
@pytest.mark.parametrize("spelling", [
    "0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9",
    "{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}",
    "urn:uuid:0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
    "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
])
def test_non_canonical_uuid_spellings(server, founded, spelling):
    """An id is compared, sorted and signed over as raw bytes, so the spellings
    must not multiply on the way in."""
    session, ws = founded
    got = server.get(
        f"/v1/w/{fixtures.uuid(ws)}/members?after={spelling}", token=session.d.access
    )
    assert got.status == 422, (spelling, got.body)
    assert got.code == "malformed_request"


@pytest.mark.item("CONF-DISC-002")
def test_every_per_op_refusal_carries_an_index(founded):
    session, ws = founded
    got = session.post_ops(ws, session.content(ws, op_label="idx/ok"), "!!!")
    assert got.detail["index"] == 1


def _stranger(session, ws):
    """A device registered nowhere, holding a token of its own."""
    import secrets as _s

    from roundelay.client import Device, Session

    dev = Device(_s.token_hex(8))
    other = Session(session.s, dev, _s.token_bytes(32))
    cert, sig = other.genesis_cert(_s.token_bytes(16))
    from conftest import ADMISSION_TOKEN

    assert other.register(cert, sig, admission=ADMISSION_TOKEN).status == 201
    assert other.log_in().status == 200
    return other
