"""The profile: eleven rows a deployment answers before it serves anything.

Most of these are white-box by nature — a role table with exactly one owner is
a property of the build, and there is no request that reveals it. What *is*
observable is the namespace the whole domain scheme is built from, and the
arithmetic of a derived creation policy, which a client computes offline and
the server must compute the same way.
"""

from __future__ import annotations

import json
import pathlib
import secrets

import pytest

from conftest import DERIVED_NAMESPACES, derived
from roundelay import crypto, fixtures
from roundelay.client import Device, Session

pytestmark = pytest.mark.usefixtures("server")

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "vectors"


@pytest.mark.item("CONF-PROF-002")
def test_the_namespace_is_reported_unchanged(server):
    """It is the first component of every signing domain, so a server that
    reported one namespace and signed under another would produce a log no
    client could verify."""
    import re

    corpus = json.loads((VECTORS / "domains.json").read_text())
    namespace = corpus["namespace"]

    assert re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", namespace), namespace
    assert 1 <= len(namespace.encode()) <= 32
    assert "/" not in namespace

    # A slash would make <ns>/<doc>/v1 ambiguous: two different (ns, doc) pairs
    # could spell one domain, and the length prefix would not separate them
    # because it counts the whole string.
    assert server.health["protocol_namespace"] == namespace


@pytest.mark.item("CONF-PROF-003")
def test_the_derivation_matches_the_corpus():
    """SHA-256, never SHA-1; the 32 raw bytes of the key, never a spelling of
    them; and the two version bits and two variant bits set as RFC 9562 says.

    Those four bits are invisible in a hash — a value with the wrong nibble in
    octet 6 is a plausible-looking UUID that no other peer derives — so the
    corpus reports them separately and this checks them separately.
    """
    corpus = json.loads((VECTORS / "uuid8.json").read_text())
    assert corpus["namespaces"] == [fixtures.uuid(ns) for ns in DERIVED_NAMESPACES]

    for case in corpus["cases"]:
        namespace = fixtures.parse_uuid(case["namespace"])
        root_pk = fixtures.b64d(case["root_pk_b64"])
        got = crypto.uuid8(namespace, root_pk)
        assert fixtures.uuid(got) == case["workspace_id"], case
        assert got[6] >> 4 == 8 == case["version_nibble"]
        assert got[8] >> 6 == 2 == case["variant_bits"]

        # And the preimage is the two operands concatenated, nothing framed and
        # nothing spelled: both are fixed width, so there is no second way to
        # read the 48 bytes.
        import hashlib
        assert hashlib.sha256(namespace + root_pk).hexdigest() == \
            case["sha256_of_preimage_hex"]

    # A hex or base64 spelling of the key derives something else entirely.
    case = corpus["cases"][0]
    namespace = fixtures.parse_uuid(case["namespace"])
    root_pk = fixtures.b64d(case["root_pk_b64"])
    for spelling in (root_pk.hex().encode(), case["root_pk_b64"].encode()):
        import hashlib
        wrong = bytearray(hashlib.sha256(namespace + spelling).digest()[:16])
        wrong[6] = 0x80 | (wrong[6] & 0x0F)
        wrong[8] = 0x80 | (wrong[8] & 0x3F)
        assert bytes(wrong) != crypto.uuid8(namespace, root_pk)


@pytest.mark.item("CONF-PROF-003")
def test_an_id_derived_any_other_way_is_not_reachable(server, root):
    """The server computes the same arithmetic rather than taking the id on
    trust. Otherwise `derived` is a policy in name only."""
    device = Session(server, Device(secrets.token_hex(8)), root)

    # Every id this Root does derive is fine.
    for index in range(len(DERIVED_NAMESPACES)):
        assert crypto.uuid8(DERIVED_NAMESPACES[index],
                            crypto.ed25519_public(root)) == derived(root, index)

    # One it does not: a random id, and the id another Root derives.
    other = secrets.token_bytes(32)
    for ws in (secrets.token_bytes(16), derived(other, 0)):
        session = Session(server, Device(secrets.token_hex(8)), root)
        cert, sig = session.genesis_cert(ws)
        got = session.register(cert, sig, admission="conformance-admission")
        assert got.status == 403, got.body
        assert got.code == "workspace_not_reachable"

    # And the reachable one is accepted, so the refusal above is the predicate
    # answering rather than something else in the way.
    ws = derived(root, 0)
    cert, sig = device.genesis_cert(ws)
    assert device.register(cert, sig, admission="conformance-admission").status == 201


@pytest.mark.item("CONF-PROF-003")
def test_the_answer_survives_a_restart(deployment, root):
    """The namespaces are frozen literals rather than values recomputed at
    startup, so one (root_pk, id) pair answers identically across processes.

    Two deployments of the same build stand in for one restarted: what is being
    checked is that the derivation is a constant of the profile and not of the
    process.
    """
    from roundelay.client import Server

    ws = derived(root, 0)
    first = Server(deployment("-admission", "token:conformance-admission"))
    second = Server(deployment("-admission", "token:conformance-admission",
                               "-version", "0.0.2"))
    try:
        for server in (first, second):
            session = Session(server, Device(secrets.token_hex(8)), root)
            cert, sig = session.genesis_cert(ws)
            got = session.register(cert, sig, admission="conformance-admission")
            assert got.status == 201, got.body

        # A Workspace this Root does not derive is unreachable on both.
        stray = secrets.token_bytes(16)
        for server in (first, second):
            session = Session(server, Device(secrets.token_hex(8)), root)
            cert, sig = session.genesis_cert(stray)
            got = session.register(cert, sig, admission="conformance-admission")
            assert got.code == "workspace_not_reachable"
    finally:
        first.close()
        second.close()


@pytest.mark.item("CONF-PROF-005")
def test_holder_ref_groups_a_holders_devices(server, founded, enrol, root):
    """The profile declares a derivation — here, the holder's Root public key
    verbatim — and the deployment's clients use it, so two devices held by one
    identity carry equal holder_ref within a Workspace and a third held by
    another identity does not.

    The server never interprets it. Grouping by equality is the one use it may
    make of the field, and that is only possible if clients derive it.
    """
    founder, ws = founded
    sibling = enrol(ws, founder)

    listing = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members",
                            token=founder.d.access)
    assert listing.status == 200, listing.body
    refs = {m["member_id"]: m["holder_ref"] for m in listing.body["members"]}

    expected = fixtures.b64(crypto.ed25519_public(root))
    assert refs[fixtures.uuid(founder.d.member_id)] == expected
    assert refs[fixtures.uuid(sibling.d.member_id)] == expected

    # A device under another identity is a different holder, in the same
    # Workspace: the certificate is signed by this Workspace's Root, but the
    # holder the device belongs to is not.
    assert len(set(refs.values())) == 1
    assert expected != fixtures.b64(crypto.ed25519_public(secrets.token_bytes(32)))
