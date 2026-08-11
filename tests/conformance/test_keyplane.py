"""The key plane: wrap sets, the digest that binds them, and the vault.

The server is content-blind here too. It never opens a wrap and never holds a
content key; what it enforces is that a set matches the digest a rotate
committed, that the set is complete and well-formed, and that only an authority
may publish one. Everything below is decided from those bytes and the log.
"""

from __future__ import annotations

import secrets

import pytest

from roundelay import crypto, fixtures

pytestmark = pytest.mark.usefixtures("server")


def locator() -> str:
    return secrets.token_bytes(32).hex()


# ── publishing a wrap set ───────────────────────────────────────────────────


@pytest.mark.item("CONF-KEY-003")
def test_epoch_zero_needs_a_digest_until_it_has_one(founded):
    """There is no rotate below epoch 0 to commit one, so the first upload
    carries its own — and once a record exists the field is ignored, which is
    what makes a byte-identical replay a 200 rather than an argument."""
    founder, ws = founded
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d])

    got = founder.publish(ws, 0, wraps, escrow, None)
    assert got.status == 422, got.body
    assert got.code == "missing_keywrap_digest"

    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200
    # The same set again, this time without the digest at all.
    assert founder.publish(ws, 0, wraps, escrow, None).status == 200


@pytest.mark.item("CONF-KEY-004")
def test_a_written_epoch_takes_the_same_set_only(founded, enrol):
    founder, ws = founded
    member = enrol(ws, founder)
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d])
    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200

    # Byte-identical: idempotent.
    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200

    # A different set for the same epoch is not an amendment.
    other, other_escrow, other_digest = founder.wrap_set(ws, 0, [founder.d, member.d])
    got = founder.publish(ws, 0, other, other_escrow, other_digest)
    assert got.status == 409, got.body
    assert got.code == "keywrap_already_written"


@pytest.mark.item("CONF-KEY-001")
def test_an_unmaterialised_epoch_has_no_wraps(founded):
    """Above epoch 0 the digest comes from a rotate, so there is nothing to
    check a set against until one has landed."""
    founder, ws = founded
    wraps, escrow, digest = founder.wrap_set(ws, 1, [founder.d])
    got = founder.publish(ws, 1, wraps, escrow, digest)
    assert got.status == 409, got.body
    assert got.code == "rotate_not_materialised"


@pytest.mark.item("CONF-KEY-002")
def test_a_set_must_hash_to_the_committed_digest(founded, enrol):
    """The rotate commits the digest in the log; the upload must match it, and
    the refusal names the value the server expects."""
    founder, ws = founded
    member = enrol(ws, founder)

    zero_wraps, zero_escrow, zero_digest = founder.wrap_set(ws, 0, [founder.d, member.d])
    assert founder.publish(ws, 0, zero_wraps, zero_escrow, zero_digest).status == 200

    wraps, escrow, digest = founder.wrap_set(ws, 1, [founder.d, member.d])
    founder.resync()
    assert founder.post_ops(ws, founder.rotate(ws, 0, 1, digest)).status == 200
    founder.resync()

    # A set missing a member hashes to something else.
    short, short_escrow, _ = founder.wrap_set(ws, 1, [founder.d])
    got = founder.publish(ws, 1, short, short_escrow, None)
    assert got.status == 422, got.body
    assert got.code == "keywrap_digest_mismatch"
    assert got.detail["expected_digest"] == fixtures.b64(digest)

    assert founder.publish(ws, 1, wraps, escrow, None).status == 200


@pytest.mark.item("CONF-KEY-007")
def test_publishing_is_an_authoritys_act(founded, enrol):
    founder, ws = founded
    member = enrol(ws, founder)
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d, member.d])

    got = member.publish(ws, 0, wraps, escrow, digest)
    assert got.status == 403, got.body
    assert got.code == "keywrap_requires_owner"
    assert got.detail["revoked"] is False


@pytest.mark.item("CONF-KEY-005")
@pytest.mark.parametrize("mangle,code", [
    ("wrap", "malformed_keywrap"),
    ("kex_key_id", "malformed_kex_key_id"),
    ("member", "unknown_keywrap_member"),
    ("kex_unregistered", "kex_key_id_not_registered"),
    ("duplicate", "duplicate_keywrap_member"),
])
def test_per_entry_validation_names_the_entry(founded, enrol, mangle, code):
    """Each entry is judged on its own, and the refusal carries the index — a
    set of two hundred wraps is otherwise a bisection exercise."""
    founder, ws = founded
    member = enrol(ws, founder)
    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d, member.d])

    if mangle == "wrap":
        wraps[1]["wrap_b64"] = fixtures.b64(b"short")
    elif mangle == "kex_key_id":
        wraps[1]["kex_key_id_b64"] = fixtures.b64(b"\x00" * 7)
    elif mangle == "member":
        wraps[1]["member_id"] = fixtures.uuid(secrets.token_bytes(16))
    elif mangle == "kex_unregistered":
        wraps[1]["kex_key_id_b64"] = fixtures.b64(secrets.token_bytes(8))
    elif mangle == "duplicate":
        wraps[1] = dict(wraps[0])

    got = founder.publish(ws, 0, wraps, escrow, digest)
    assert got.status in (409, 422), got.body
    assert got.code == code
    assert got.detail["index"] == 1


@pytest.mark.item("CONF-KEY-006")
def test_the_two_top_level_fields_sit_at_documented_positions(founded, enrol):
    """malformed_key_epoch above the grant check, malformed_escrow_wrap below
    the authority check — each shown by a caller faulty in both ways."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)

    # No live grant *and* an epoch out of range: the epoch answers.
    got = member.publish(ws, 0, [], b"", None, raw_body=(
        '{"epoch":4294967296,"wraps":[],"escrow_wrap_b64":"","keywrap_digest_b64":""}'))
    assert got.status == 422, got.body
    assert got.code == "malformed_key_epoch"

    # Not an authority *and* a malformed escrow wrap: the authority answers.
    participant = enrol(ws, founder)
    wraps, _, digest = founder.wrap_set(ws, 0, [founder.d])
    got = participant.publish(ws, 0, wraps, b"tooshort", digest)
    assert got.status == 403, got.body
    assert got.code == "keywrap_requires_owner"

    # And with an authority behind it, the escrow wrap is what is wrong.
    got = founder.publish(ws, 0, wraps, b"tooshort", digest)
    assert got.status == 422, got.body
    assert got.code == "malformed_escrow_wrap"


@pytest.mark.item("CONF-KEY-006")
@pytest.mark.item("CONF-KEY-003")
@pytest.mark.parametrize("field,value,code", [
    ("escrow_wrap_b64", "!!", "malformed_escrow_wrap"),
    ("keywrap_digest_b64", "!!", "malformed_keywrap_digest"),
    ("keywrap_digest_b64", "AA==", "malformed_keywrap_digest"),
])
def test_the_byte_fields_keep_their_own_codes_at_the_decoder(founded, field, value, code):
    """A field that fails to decode answers with the same code as one that
    decodes to the wrong length. Otherwise where the failure happens to be
    caught decides what the caller is told, which is an implementation detail
    leaking into the vocabulary."""
    founder, ws = founded
    body = {
        "epoch": 0, "wraps": [], "escrow_wrap_b64": "AA==", "keywrap_digest_b64": "AA==",
    }
    body[field] = value
    import json as _json
    got = founder.publish(ws, 0, [], b"", None, raw_body=_json.dumps(body))
    assert got.status == 422, got.body
    assert got.code == code


@pytest.mark.item("CONF-WIRE-009")
def test_the_digest_the_server_computes_sorts_by_raw_bytes(founded, enrol):
    """Black-box, against a set whose two orderings disagree.

    The corpus pins the sort key against a hand-built preimage; this asks the
    server. A pair of members whose ids order one way as raw bytes and the
    other as base64 is found by searching, because the derived fixtures happen
    to agree and a fixture that cannot fail is not a test.
    """
    from roundelay.client import Device

    founder, ws = founded

    # The label is chosen offline: a member id is derived from it, so the pair
    # that separates the two orderings is found without touching the server and
    # the test enrols exactly one device every run.
    mine = founder.d.member_id
    run = secrets.token_hex(4)
    label = next(
        candidate for candidate in (f"digest-order/{run}/{i}" for i in range(10_000))
        if (mine < Device(candidate).member_id)
        != (fixtures.b64(mine) < fixtures.b64(Device(candidate).member_id))
    )
    partner = enrol(ws, founder, role=None, label=label)

    wraps, escrow, digest = founder.wrap_set(ws, 0, [founder.d, partner.d])

    # Uploaded in base64 order, which for this pair is not raw-byte order — the
    # label search guarantees the two disagree. The digest is over the raw-byte
    # order, so a server that hashed arrival order, or sorted the base64
    # spelling, computes something else.
    by_raw = sorted(wraps, key=lambda w: fixtures.parse_uuid(w["member_id"]))
    by_b64 = sorted(wraps, key=lambda w: fixtures.b64(fixtures.parse_uuid(w["member_id"])))
    assert [w["member_id"] for w in by_b64] != [w["member_id"] for w in by_raw]
    got = founder.publish(ws, 0, by_b64, escrow, digest)
    assert got.status == 200, got.body

    # And the digest a base64 sort would have produced is refused, which is the
    # same claim from the other side.
    import hashlib
    import struct

    from roundelay import crypto as _crypto

    rest = struct.pack(">II", 0, len(by_b64))
    for w in by_b64:
        rest += fixtures.parse_uuid(w["member_id"]) + fixtures.b64d(w["kex_key_id_b64"])
        rest += hashlib.sha256(fixtures.b64d(w["wrap_b64"])).digest()
    rest += hashlib.sha256(escrow).digest()
    wrong = hashlib.sha256(_crypto.framed(
        f"{founder.s.namespace}/keywrap-digest/v1", rest)).digest()
    assert wrong != digest, "the pair is not diagnostic"

    other, other_escrow, _ = founder.wrap_set(ws, 1, [founder.d, partner.d])
    founder.resync()
    assert founder.post_ops(ws, founder.rotate(ws, 0, 1, wrong)).status == 200
    founder.resync()
    got = founder.publish(ws, 1, other, other_escrow, None)
    assert got.status == 422, got.body
    assert got.code == "keywrap_digest_mismatch"


# ── reading wraps back ──────────────────────────────────────────────────────


@pytest.fixture
def keyed(founded, enrol):
    """A Workspace with three epochs published and two members."""
    founder, ws = founded
    member = enrol(ws, founder)
    everyone = [founder.d, member.d]

    wraps, escrow, digest = founder.wrap_set(ws, 0, everyone)
    assert founder.publish(ws, 0, wraps, escrow, digest).status == 200
    for epoch in (1, 2):
        wraps, escrow, digest = founder.wrap_set(ws, epoch, everyone)
        founder.resync()
        assert founder.post_ops(ws, founder.rotate(ws, epoch - 1, epoch, digest)).status == 200
        founder.resync()
        assert founder.publish(ws, epoch, wraps, escrow, None).status == 200
    return founder, member, ws


@pytest.mark.item("CONF-KEY-008")
def test_my_wraps_are_mine_alone(keyed):
    founder, member, ws = keyed
    got = member.my_wraps(ws)
    assert got.status == 200, got.body
    assert [w["epoch"] for w in got.body["wraps"]] == [0, 1, 2]
    assert {w["member_id"] for w in got.body["wraps"]} == {
        fixtures.uuid(member.d.member_id)
    }


@pytest.mark.item("CONF-KEY-012")
def test_my_wraps_pages_by_epoch(keyed):
    _, member, ws = keyed

    page = member.my_wraps(ws, "?limit=2")
    assert [w["epoch"] for w in page.body["wraps"]] == [0, 1]
    assert page.body["has_more"] is True

    page = member.my_wraps(ws, "?after_epoch=1")
    assert [w["epoch"] for w in page.body["wraps"]] == [2]
    assert page.body["has_more"] is False

    # after_epoch is exclusive, so 0 starts above epoch 0 — distinct from
    # absent, which starts at the first epoch held.
    assert [w["epoch"] for w in member.my_wraps(ws, "?after_epoch=0").body["wraps"]] == [1, 2]

    # And the last page is exact rather than optimistic.
    page = member.my_wraps(ws, "?after_epoch=1&limit=1")
    assert [w["epoch"] for w in page.body["wraps"]] == [2]
    assert page.body["has_more"] is False


@pytest.mark.item("CONF-KEY-009")
def test_epoch_keys_needs_a_live_grant(keyed, enrol):
    founder, member, ws = keyed
    got = member.epoch_keys(ws)
    assert got.status == 200, got.body
    assert [e["epoch"] for e in got.body["epochs"]] == [0, 1, 2]
    assert all(e["escrow_wrap_b64"] for e in got.body["epochs"])

    grantless = enrol(ws, founder, role=None)
    got = grantless.epoch_keys(ws)
    assert got.status == 403, got.body
    assert got.code == "no_live_grant"


@pytest.mark.item("CONF-KEY-014")
def test_epoch_keys_omits_an_epoch_with_no_escrow_wrap(keyed):
    """A rotate that nobody has published for is an epoch with no key to serve,
    and it is absent from every page rather than present and empty."""
    founder, member, ws = keyed
    _, _, digest = founder.wrap_set(ws, 3, [founder.d, member.d])
    founder.resync()
    assert founder.post_ops(ws, founder.rotate(ws, 2, 3, digest)).status == 200
    founder.resync()

    page = founder.epoch_keys(ws)
    assert [e["epoch"] for e in page.body["epochs"]] == [0, 1, 2]
    assert page.body["has_more"] is False

    page = founder.epoch_keys(ws, "?limit=2")
    assert [e["epoch"] for e in page.body["epochs"]] == [0, 1]
    assert page.body["has_more"] is True


@pytest.mark.item("CONF-KEY-013")
@pytest.mark.item("CONF-KEY-015")
@pytest.mark.parametrize("route", ["my_wraps", "epoch_keys"])
@pytest.mark.parametrize("query,code", [
    ("?limit=0", "malformed_request"),
    ("?limit=100000", "malformed_request"),
    ("?after_epoch=4294967296", "malformed_request"),
    ("?after_epoch=-1", "malformed_request"),
    ("?cursor=abc", "unknown_request_field"),
])
def test_paging_parameters_are_never_clamped(keyed, route, query, code):
    _, member, ws = keyed
    got = getattr(member, route)(ws, query)
    assert got.status == 422, got.body
    assert got.code == code


@pytest.mark.item("CONF-KEY-011")
def test_a_device_admitted_after_an_epoch_holds_none_of_it(keyed, enrol):
    """Registration alone gives a device nothing to read with. Its first wrap
    arrives in the next rotation, and until that lands it holds none."""
    founder, member, ws = keyed
    latecomer = enrol(ws, founder)

    got = latecomer.my_wraps(ws)
    assert got.status == 200, got.body
    assert got.body["wraps"] == []

    wraps, escrow, digest = founder.wrap_set(ws, 3, [founder.d, member.d, latecomer.d])
    founder.resync()
    assert founder.post_ops(ws, founder.rotate(ws, 2, 3, digest)).status == 200
    founder.resync()
    assert founder.publish(ws, 3, wraps, escrow, None).status == 200

    got = latecomer.my_wraps(ws)
    assert [w["epoch"] for w in got.body["wraps"]] == [3]


# ── the vault ───────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-ESC-001")
def test_the_first_write_is_version_one(founded):
    founder = founded[0]
    slot = locator()
    got = founder.vault_write(slot, 2, b"blob")
    assert got.status == 409, got.body
    assert got.code == "vault_version_regression"
    assert got.detail["stored_version"] == 0

    assert founder.vault_write(slot, 1, b"blob").status == 200


@pytest.mark.item("CONF-ESC-003")
def test_versions_only_go_up(founded):
    founder = founded[0]
    slot = locator()
    assert founder.vault_write(slot, 1, b"one").status == 200
    assert founder.vault_write(slot, 3, b"three").status == 200

    for version in (1, 3):
        got = founder.vault_write(slot, version, b"again")
        assert got.status == 409, got.body
        assert got.code == "vault_version_regression"
        assert got.detail["stored_version"] == 3


@pytest.mark.item("CONF-ESC-002")
def test_the_root_is_pinned_by_the_first_write(founded):
    founder = founded[0]
    """Trust on first use, and pinned thereafter: an unrelated key cannot take
    the slot over, and the failed attempt leaves it exactly as it was."""
    slot = locator()
    assert founder.vault_write(slot, 1, b"mine").status == 200

    stranger = secrets.token_bytes(32)
    got = founder.vault_write(slot, 2, b"theirs", signer=stranger)
    assert got.status == 403, got.body
    assert got.code == "bad_vault_signature"

    read = founder.vault_read(slot)
    assert read.status == 200
    assert read.body["version"] == 1
    assert read.body["blob_b64"] == fixtures.b64(b"mine")


@pytest.mark.item("CONF-ESC-009")
def test_the_pin_moves_only_when_the_pinned_root_says_so(founded):
    founder = founded[0]
    slot = locator()
    assert founder.vault_write(slot, 1, b"one").status == 200
    incoming = secrets.token_bytes(32)

    # Signed by the incoming key, declaring itself: that is the key asking to be
    # trusted on its own say-so.
    got = founder.vault_write(slot, 2, b"two", signer=incoming)
    assert got.status == 403, got.body
    assert got.code == "bad_vault_signature"

    # Signed by the pinned Root, declaring the incoming one: a handover.
    got = founder.vault_write(slot, 2, b"two", root_pk=crypto.ed25519_public(incoming))
    assert got.status == 200, got.body
    assert founder.vault_write(slot, 3, b"three", signer=incoming).status == 200


@pytest.mark.item("CONF-ESC-004")
@pytest.mark.parametrize("blob,sig,pk,version,code", [
    ("!!", "SIG", "PK", 1, "malformed_vault_blob"),
    ("AA==", "AA==", "PK", 1, "malformed_vault_signature"),
    ("AA==", "SIG", "AA==", 1, "malformed_root_pk"),
    ("AA==", "SIG", "PK", 0, "malformed_vault_version"),
])
def test_vault_fields_are_refused_individually(founded, blob, sig, pk, version, code):
    """Four codes rather than one, because each names a different repair."""
    founder = founded[0]
    sig = fixtures.b64(bytes(64)) if sig == "SIG" else sig
    pk = fixtures.b64(bytes(32)) if pk == "PK" else pk
    got = founder.vault_write(locator(), 1, b"", raw_body=(
        '{"version":%d,"blob_b64":"%s","root_sig_b64":"%s","root_pk_b64":"%s"}'
        % (version, blob, sig, pk)))
    assert got.status == 422, got.body
    assert got.code == code


@pytest.mark.item("CONF-ESC-004")
def test_the_blob_is_never_length_checked(founded):
    founder = founded[0]
    """It is written and read by the same client; the server holds bytes."""
    slot = locator()
    assert founder.vault_write(slot, 1, b"").status == 200
    assert founder.vault_write(slot, 2, secrets.token_bytes(40_000)).status == 200


@pytest.mark.item("CONF-ESC-005")
def test_an_unwritten_slot_is_not_found(founded):
    founder = founded[0]
    got = founder.vault_read(locator())
    assert got.status == 404, got.body
    assert got.code == "no_vault_record"


@pytest.mark.item("CONF-ESC-010")
@pytest.mark.parametrize("bad", [
    "short", "ZZ" * 32, "AA" * 32, "a" * 63, "a" * 65, "",
])
def test_a_locator_that_is_not_64_lowercase_hex(founded, bad):
    founder = founded[0]
    """Not a refusal with a code of its own: it is not a route."""
    got = founder.vault_read(bad) if bad else founder.s.get("/v1/vault/")
    assert got.status == 404, got.body
    assert got.code == "not_found"
