"""The harness checks itself against the frozen vectors, before anything else.

Every other file in this suite trusts that this client builds the same bytes the
server does. That trust has to be bought: a harness with a framing bug produces
envelopes the server rightly refuses, and every test then fails for a reason
that has nothing to do with the server.

These are also the only tests here that touch no server. They are the
cross-implementation check the corpus exists for — two implementations, written
from the specification, agreeing byte for byte.
"""

from __future__ import annotations

import base64
import json
import pathlib
import struct

import pytest

from roundelay import crypto, fixtures, wire

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


@pytest.mark.item("CONF-WIRE-008")
def test_framing_matches_the_corpus():
    doc = load("framing.json")
    for case in doc["cases"]:
        got = crypto.framed(case["domain"], bytes.fromhex(case["rest_hex"]))
        assert got.hex() == case["framed_hex"], case["name"]


def test_the_collision_pair_is_separated():
    """The property the length prefix exists for.

    Without the prefix these two concatenate to identical bytes; the corpus
    records both, and an implementation whose values match for them has dropped
    it.
    """
    doc = load("framing.json")
    cases = {c["name"]: c["framed_hex"] for c in doc["cases"]}
    assert cases["collision_a"] != cases["collision_b"]


@pytest.mark.item("CONF-WIRE-008")
def test_domains_match_the_corpus():
    doc = load("domains.json")
    ns = doc["namespace"]
    assert len(doc["core"]) == 15
    for row in doc["core"]:
        assert f"{ns}/{row['document']}/v1" == row["domain"]
    for row in doc["op_class_to_domain"]:
        got = wire.op_domain(ns, int(row["op_class"]), fixtures.EXT_NAME)
        assert got == row["domain"], row["op_class"]


def test_key_ids_match_the_corpus():
    for case in load("keyid.json")["cases"]:
        assert crypto.key_id(b64d(case["public_key_b64"])).hex() == case["key_id_hex"], case["label"]


def test_body_padding_matches_the_corpus():
    doc = load("body.json")
    ladder = wire.Ladder(classes=doc["ladder"]["classes"], step=doc["ladder"]["oversize_step"])
    import hashlib

    for row in doc["padding"]:
        body = ladder.pack_body(fixtures.filler(row["payload_len"]))
        assert len(body) == row["body_len"], row["payload_len"]
        assert hashlib.sha256(body).hexdigest() == row["body_sha256_hex"], row["payload_len"]
    for row in doc["legal_body_len"]:
        assert ladder.legal_body_len(row["body_len"]) is row["legal"], row["body_len"]
    assert ladder.min_envelope_len(0x00) == doc["min_envelope_len"]["suite_0x00"]
    assert ladder.min_envelope_len(0x01) == doc["min_envelope_len"]["suite_0x01"]


def test_envelopes_match_the_corpus():
    doc = load("envelope.json")
    assert doc["geometry"] == {
        "header_len": wire.HEADER_LEN,
        "sig_len": wire.SIG_LEN,
        "overhead": wire.OVERHEAD,
        "tag_len": wire.TAG_LEN,
    }
    for row in doc["envelopes"]:
        raw = b64d(row["envelope_b64"])
        header, body, sig = wire.parse_envelope(raw)

        assert header.marshal().hex() == row["header_hex"], row["name"]
        assert crypto.envelope_hash(raw).hex() == row["envelope_hash_hex"], row["name"]

        # The header offsets, read back out of the bytes.
        assert header.op_class == row["header"]["op_class"]
        assert header.suite == row["header"]["suite"]
        assert header.key_epoch == row["header"]["key_epoch"]
        assert header.author_seq == row["header"]["author_seq"]
        assert fixtures.uuid(header.workspace_id) == row["header"]["workspace_id"]

        # The signature verifies under the key its author_key_id names, over
        # framed(domain, header || sealed body).
        label = (
            fixtures.LABEL_DEVICE_A_CONTROL
            if wire.server_reads(header.op_class)
            else fixtures.LABEL_DEVICE_A_CONTENT
        )
        pub = crypto.ed25519_public(fixtures.seed(label))
        message = crypto.framed(row["signing_domain"], header.marshal(), body)
        assert crypto.verify(pub, message, sig), row["name"]


def test_a_sealed_body_opens():
    """The corpus pins the ciphertext; this proves the construction behind it."""
    doc = load("envelope.json")
    row = next(r for r in doc["envelopes"] if r["name"] == "content_sealed")
    raw = b64d(row["envelope_b64"])
    header, body, _ = wire.parse_envelope(raw)
    key = b64d(row["content_key_b64"])

    plaintext = crypto.xchacha_open(key, header.nonce, body, header.marshal())
    ladder = wire.Ladder()
    assert ladder.unpack_body(plaintext) == b"hello roundelay"

    # The literal header is the associated data, so changing any byte of it
    # stops the body opening.
    tampered = wire.Header.parse(header.marshal())
    tampered.key_epoch += 1
    with pytest.raises(Exception):
        crypto.xchacha_open(key, header.nonce, body, tampered.marshal())


def test_the_control_chain_link_matches_the_corpus():
    doc = load("envelope.json")["control_chain"]
    payload = doc["payload_utf8"].encode()
    assert crypto.payload_hash(payload).hex() == doc["prev_control_hash_hex"]
    assert doc["genesis_link_hex"] == "00" * 32


@pytest.mark.item("CONF-WIRE-010")
def test_member_wraps_match_the_corpus():
    doc = load("keyplane.json")
    ws = fixtures.parse_uuid(doc["workspace_id"])
    epoch = doc["epoch"]
    key = b64d(doc["content_key_b64"])

    for row in doc["member_wraps"]:
        got = crypto.member_wrap(
            fixtures.NAMESPACE,
            ws,
            epoch,
            fixtures.parse_uuid(row["member_id"]),
            b64d(row["kex_key_id_b64"]),
            b64d(row["kex_public_key_b64"]),
            b64d(row["ephemeral_private_key_b64"]),
            b64d(row["nonce_b64"]),
            key,
        )
        assert len(got) == 104, row["label"]
        assert base64.b64encode(got).decode() == row["wrap_b64"], row["label"]
        # And the info string, which is not on the wire and is what two
        # implementations most often disagree about.
        assert got[:32].hex() in row["info_hex"], row["label"]


@pytest.mark.item("CONF-WIRE-010")
def test_escrow_wrap_matches_the_corpus():
    doc = load("keyplane.json")
    ws = fixtures.parse_uuid(doc["workspace_id"])
    row = doc["escrow_wrap"]
    got = crypto.escrow_wrap(
        fixtures.NAMESPACE,
        ws,
        doc["epoch"],
        b64d(doc["master_wrap_key_b64"]),
        b64d(row["nonce_b64"]),
        b64d(doc["content_key_b64"]),
    )
    assert len(got) == 72
    assert base64.b64encode(got).decode() == row["escrow_wrap_b64"]
    assert crypto.escrow_info(fixtures.NAMESPACE, ws, doc["epoch"]).hex() == row["info_hex"]


def test_keywrap_digest_matches_the_corpus():
    doc = load("keyplane.json")
    entries = [
        (
            fixtures.parse_uuid(r["member_id"]),
            b64d(r["kex_key_id_b64"]),
            b64d(r["wrap_b64"]),
        )
        for r in doc["member_wraps"]
    ]
    got = crypto.keywrap_digest(
        fixtures.NAMESPACE, doc["epoch"], entries, b64d(doc["escrow_wrap"]["escrow_wrap_b64"])
    )
    assert got.hex() == doc["keywrap_digest"]["digest_hex"]
    # Order-independent: the digest describes the set, not the upload order.
    assert (
        crypto.keywrap_digest(
            fixtures.NAMESPACE,
            doc["epoch"],
            list(reversed(entries)),
            b64d(doc["escrow_wrap"]["escrow_wrap_b64"]),
        )
        == got
    )


def test_the_digest_sort_key_is_raw_bytes():
    """The diagnostic set: raw bytes, base64 and signed 64-bit halves disagree.

    The device fixtures cannot catch a wrong sort key — their derived ids happen
    to order the same way under all three — so the corpus carries a set built to
    separate them.
    """
    doc = load("keyplane.json")["keywrap_digest_ordering"]
    entries = [
        (
            fixtures.parse_uuid(r["member_id"]),
            b64d(r["kex_key_id_b64"]),
            b64d(r["wrap_b64"]),
        )
        for r in doc["entries_in_correct_sort_order"]
    ]
    escrow = b64d(doc["escrow_wrap_b64"])
    got = crypto.keywrap_digest(fixtures.NAMESPACE, doc["epoch"], entries, escrow)
    assert got.hex() == doc["digest_hex"]

    # Sorting the base64 spelling instead must produce something else.
    def digest_under(order):
        rest = struct.pack(">II", doc["epoch"], len(order))
        import hashlib

        for member_id, kid, wrap in order:
            rest += member_id + kid + hashlib.sha256(wrap).digest()
        rest += hashlib.sha256(escrow).digest()
        return hashlib.sha256(
            crypto.framed(f"{fixtures.NAMESPACE}/keywrap-digest/v1", rest)
        ).digest()

    by_b64 = sorted(
        entries, key=lambda e: (base64.b64encode(e[0]), base64.b64encode(e[1]))
    )
    assert [e[0] for e in by_b64] != [e[0] for e in entries], "the fixture is not diagnostic"
    assert digest_under(by_b64) != got


def test_auth_and_vault_preimages_match_the_corpus():
    doc = load("auth.json")

    ac = doc["auth_challenge"]
    member = fixtures.parse_uuid(ac["member_id"])
    got = wire.auth_challenge_input(fixtures.NAMESPACE, member, b64d(ac["nonce_b64"]))
    assert got.hex() == ac["signing_input_hex"]
    assert crypto.verify(b64d(ac["control_public_key_b64"]), got, b64d(ac["signature_b64"]))
    # The member id is bound, so a captured signature cannot be replayed into
    # another device's pending challenge.
    other = wire.auth_challenge_input(fixtures.NAMESPACE, fixtures.MEMBER_B, b64d(ac["nonce_b64"]))
    assert not crypto.verify(
        b64d(ac["control_public_key_b64"]), other, b64d(ac["signature_b64"])
    )

    vt = doc["vault"]
    locator = bytes.fromhex(vt["locator_hex"])
    preimage = wire.vault_input(fixtures.NAMESPACE, locator, vt["version"], b64d(vt["blob_b64"]))
    assert crypto.verify(b64d(vt["root_public_key_b64"]), preimage, b64d(vt["root_sig_b64"]))

    cert = doc["certificate"]
    ci = wire.cert_input(fixtures.NAMESPACE, cert["document"], b64d(cert["cert_bytes_b64"]))
    assert crypto.verify(b64d(cert["root_public_key_b64"]), ci, b64d(cert["cert_sig_b64"]))
    # A grant signature must not verify as another document.
    for other_doc in ("revoke", "role-table"):
        assert not crypto.verify(
            b64d(cert["root_public_key_b64"]),
            wire.cert_input(fixtures.NAMESPACE, other_doc, b64d(cert["cert_bytes_b64"])),
            b64d(cert["cert_sig_b64"]),
        )
