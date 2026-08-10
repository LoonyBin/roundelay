"""Opaque classes, extension classes, and the bindings that give them meaning.

Two profile rows the reference deployment answers "none". A second deployment
takes them up — one opaque class at 0x40, one extension class at 0xCC under the
NAME "purge" — and everything here is about what changes when it does.

The distinction the whole surface turns on: an opaque class is a class the
server stores and never reads, so declaring one adds a byte and nothing else.
An extension class carries a *meaning*, and a meaning two deployments could
disagree about — so the class byte alone is never enough, and every op of one
is judged against a binding its own author wrote.
"""

from __future__ import annotations

import secrets

import pytest

from conftest import EXT_CLASS, EXT_NAME, OPAQUE_CLASS
from roundelay import fixtures

pytestmark = pytest.mark.usefixtures("ext_server")


def gid() -> str:
    return fixtures.uuid(secrets.token_bytes(16))


# ── opaque classes ──────────────────────────────────────────────────────────


@pytest.mark.item("CONF-WIRE-011")
def test_an_undeclared_opaque_class_is_not_served(founded):
    """On the reference deployment, which declares none: the byte is unknown,
    not merely unauthorised."""
    founder, ws = founded
    got = founder.post_ops(ws, founder.content(ws, b"x", op_class=OPAQUE_CLASS))
    assert got.status == 422, got.body
    assert got.code == "unsupported_op_class"


@pytest.mark.item("CONF-WIRE-011")
def test_a_declared_opaque_class_behaves_exactly_like_content(ext_founded):
    """Stored and served byte-identically, never parsed, admitted only by a
    role that names it, and eligible as a prune target — 0x01 in every respect
    but the byte."""
    founder, ws = ext_founded

    # The body is not JSON and never will be: nothing reads it.
    envelope = founder.content(ws, b"\xff\x00 not json at all", op_class=OPAQUE_CLASS)
    assert founder.post_ops(ws, envelope).status == 200

    served = founder.ops(ws).body["ops"]
    row = next(r for r in served
               if founder.header_of(r).op_class == OPAQUE_CLASS)
    assert row["envelope"] == envelope, "served back byte-identically"

    # Eligible as a prune target, exactly as an 0x01 op is.
    replacement = founder.content(ws, b"replaces it", op_label="opaque/reprise")
    reprise = fixtures.uuid(fixtures.bytes16("opaque/reprise"))
    got = founder.post_ops(ws, replacement,
                           founder.prune(ws, [founder.target(row)], reprise))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-WIRE-011")
def test_a_declared_opaque_class_still_needs_a_role_that_names_it(ext_founded, enrol):
    """Declaring a class says the server will carry it, not that anyone may
    write it. participant names 0x01 and nothing else."""
    founder, ws = ext_founded
    member = enrol(ws, founder)

    member.resync()
    got = member.post_ops(ws, member.content(ws, b"x", op_class=OPAQUE_CLASS))
    assert got.status == 403, got.body
    assert got.code == "role_forbids_op_class"
    assert got.detail["op_class"] == OPAQUE_CLASS


# ── ext_binding shape ───────────────────────────────────────────────────────


@pytest.mark.item("CONF-WIRE-017")
@pytest.mark.parametrize("payload,code", [
    ({"type": "bind", "op_class": EXT_CLASS, "name": EXT_NAME, "extra": 1},
     "malformed_ext_binding_payload"),
    ({"op_class": EXT_CLASS, "name": EXT_NAME}, "malformed_ext_binding_payload"),
    ({"type": "bind", "name": EXT_NAME}, "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": EXT_CLASS}, "malformed_ext_binding_payload"),
    ({"type": "unbind", "op_class": EXT_CLASS, "name": EXT_NAME},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": 0x80, "name": EXT_NAME},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": 256, "name": EXT_NAME},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": "cc", "name": EXT_NAME},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": EXT_CLASS, "name": "Purge"},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": EXT_CLASS, "name": "-purge"},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": EXT_CLASS, "name": ""},
     "malformed_ext_binding_payload"),
    ({"type": "bind", "op_class": EXT_CLASS, "name": "p" * 33},
     "malformed_ext_binding_payload"),
    ({"type": "rebind", "op_class": EXT_CLASS, "name": EXT_NAME},
     "unsupported_ext_binding_type"),
])
def test_ext_binding_shape_rules(ext_founded, payload, code):
    founder, ws = ext_founded
    got = founder.post_ops(ws, founder.ext_binding(ws, payload))
    assert got.status == 422, (payload, got.body)
    assert got.code == code


@pytest.mark.item("CONF-WIRE-018")
def test_bind_refusals_in_order(ext_founded):
    """A class the deployment does not permit, one it implements under another
    name, and one this member already holds."""
    founder, ws = ext_founded

    got = founder.post_ops(ws, founder.bind(ws, 0xC1, "something"))
    assert got.status == 422, got.body
    assert got.code == "ext_class_not_enabled"
    assert got.detail["op_class"] == 0xC1

    got = founder.post_ops(ws, founder.bind(ws, EXT_CLASS, "shred"))
    assert got.status == 422, got.body
    assert got.code == "ext_name_mismatch"
    assert got.detail["expected"] == EXT_NAME

    assert founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME)).status == 200
    got = founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME))
    assert got.status == 409, got.body
    assert got.code == "ext_class_already_bound"


@pytest.mark.item("CONF-WIRE-014")
def test_a_wrong_name_records_no_binding(ext_founded):
    """Replaying a log written against another implementation's 0xCC fails at
    its first ext_binding, rather than processing every op after it under a
    meaning nobody agreed to."""
    founder, ws = ext_founded

    got = founder.post_ops(ws, founder.bind(ws, EXT_CLASS, "shred"))
    assert got.status == 422 and got.code == "ext_name_mismatch", got.body

    # Nothing was recorded, so an op of the class is still unbound.
    got = founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, "shred"))
    assert got.status == 422, got.body
    assert got.code == "ext_class_not_active"


# ── when a binding is in force ──────────────────────────────────────────────


@pytest.mark.item("CONF-WIRE-013")
def test_a_binding_binds_from_its_own_position(ext_founded):
    """Not from the batch, and not retroactively: [ext op, ext_binding] is
    refused at index 0 while [ext_binding, ext op] is accepted."""
    founder, ws = ext_founded

    # Before any binding at all.
    got = founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, EXT_NAME))
    assert got.status == 422 and got.code == "ext_class_not_active", got.body

    # The wrong way round, in one batch.
    got = founder.post_ops(ws,
                           founder.ext_op(ws, EXT_CLASS, EXT_NAME),
                           founder.bind(ws, EXT_CLASS, EXT_NAME))
    assert got.status == 422, got.body
    assert got.code == "ext_class_not_active"
    assert got.detail["index"] == 0

    # And the right way round.
    got = founder.post_ops(ws,
                           founder.bind(ws, EXT_CLASS, EXT_NAME),
                           founder.ext_op(ws, EXT_CLASS, EXT_NAME))
    assert got.status == 200, got.body


@pytest.mark.item("CONF-WIRE-019")
def test_unbind_closes_the_interval_and_another_may_open(ext_founded):
    """Bindings are intervals, and an op is judged against the one its position
    falls in — so a class may be bound, released, and bound again."""
    founder, ws = ext_founded

    got = founder.post_ops(ws, founder.unbind(ws, EXT_CLASS))
    assert got.status == 422, got.body
    assert got.code == "ext_class_not_bound"

    assert founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME)).status == 200
    assert founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, EXT_NAME)).status == 200
    assert founder.post_ops(ws, founder.unbind(ws, EXT_CLASS)).status == 200

    # Past the end of the interval.
    got = founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, EXT_NAME))
    assert got.status == 422, got.body
    assert got.code == "ext_class_not_active"

    # And it may be taken up again.
    assert founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME)).status == 200
    assert founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, EXT_NAME)).status == 200


@pytest.mark.item("CONF-WIRE-015")
def test_bindings_are_member_scoped(ext_founded, enrol, ext_server):
    """One member's binding does not bind another. A Workspace-wide binding
    would be a value that moves under an author who has not caught up, and no
    client-side check can prevent that."""
    founder, ws = ext_founded
    member = enrol(ws, founder, role=None)
    founder.resync()
    assert founder.post_ops(ws, founder.grant(ws, member.d, "owner", gid())).status == 200
    founder.resync()

    assert founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME)).status == 200
    assert founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, EXT_NAME)).status == 200

    # The other member holds no binding of its own, and is not judged against
    # the one that exists.
    member.resync()
    got = member.post_ops(ws, member.ext_op(ws, EXT_CLASS, EXT_NAME))
    assert got.status == 422, got.body
    assert got.code == "ext_class_not_active"

    member.resync()
    assert member.post_ops(ws, member.bind(ws, EXT_CLASS, EXT_NAME)).status == 200
    assert member.post_ops(ws, member.ext_op(ws, EXT_CLASS, EXT_NAME)).status == 200


@pytest.mark.item("CONF-WIRE-015")
def test_the_recorded_name_is_what_the_op_is_judged_against(ext_founded):
    """A binding records the meaning its author agreed to, and every later op
    of that class is checked against it — not against the class byte alone.

    The other half of the rule, where the *server* is reconfigured to implement
    the class under a different NAME and the author's further ops are refused
    ext_name_mismatch rather than reinterpreted, needs a restart under a new
    configuration with the log intact. That is a durable store and a second
    process, and it is not decided here.
    """
    founder, ws = ext_founded
    assert founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME)).status == 200
    assert founder.post_ops(ws, founder.ext_op(ws, EXT_CLASS, EXT_NAME)).status == 200

    # The recorded name cannot drift under the author. A rebind under another
    # name answers on the name — which sits above already_bound in the
    # sequence, so it is the verdict whether or not one is live.
    for _ in range(2):
        got = founder.post_ops(ws, founder.bind(ws, EXT_CLASS, "shred"))
        assert got.status == 422, got.body
        assert got.code == "ext_name_mismatch"
        assert got.detail["expected"] == EXT_NAME
        assert founder.post_ops(ws, founder.unbind(ws, EXT_CLASS)).status == 200
        assert founder.post_ops(ws, founder.bind(ws, EXT_CLASS, EXT_NAME)).status == 200


# ── the seams ───────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-WIRE-020")
def test_sealing_a_served_server_read_class_that_is_not_control_or_prune(
        founded, ext_founded):
    """0x80 and 0x81 have codes of their own; every other server-read class the
    deployment serves answers with the family code.

    Which is only reachable for a class that *is* served: stage 1 resolves the
    class byte before the suite byte, so an unassigned server-read byte answers
    unsupported_op_class and never reaches the family at all.
    """
    from roundelay import wire

    founder, ws = founded
    got = founder.post_ops(ws, founder.control_class(
        ws, 0xBF, {"type": "bind"}, suite=wire.SUITE_ENCRYPTED))
    assert got.status == 422, got.body
    assert got.code == "encrypted_server_read_op"

    # An extension class is a server-read class too, on a deployment that
    # serves one.
    ext_founder, ext_ws = ext_founded
    got = ext_founder.post_ops(ext_ws, ext_founder.control_class(
        ext_ws, EXT_CLASS, {"anything": 1}, suite=wire.SUITE_ENCRYPTED,
        ext_name=EXT_NAME))
    assert got.status == 422, got.body
    assert got.code == "encrypted_server_read_op"

    # And a byte no deployment serves answers on the byte.
    got = founder.post_ops(ws, founder.control_class(
        ws, 0xAA, {"anything": 1}, suite=wire.SUITE_ENCRYPTED))
    assert got.status == 422, got.body
    assert got.code == "unsupported_op_class"


@pytest.mark.item("CONF-WIRE-021")
def test_a_body_beyond_the_bound(server, founded):
    """On any route. The bound is the deployment's and is advertised, so a
    client can size its batches rather than discovering the limit by hitting
    it."""
    founder, ws = founded
    bound = server.health["limits"]["max_request_bytes"]

    oversized = '{"ops":["' + "A" * (bound + 1024) + '"]}'
    got = server.post(f"/v1/w/{fixtures.uuid(ws)}/ops",
                      token=founder.d.access, raw_body=oversized)
    assert got.status == 413, got.body
    assert got.code == "request_too_large"

    # And on a route that is not the append path.
    got = server.post("/v1/members", raw_body=oversized)
    assert got.status == 413, got.body
    assert got.code == "request_too_large"

    # Chunked, so there is no Content-Length to believe. A server that trusted
    # the header alone would buffer the whole body and then answer on its
    # contents — which is the case the bound exists to prevent.
    def chunks():
        block = b"A" * 65536
        yield b'{"ops":["'
        for _ in range(bound // len(block) + 2):
            yield block
        yield b'"]}'

    raw = server.http.request(
        "POST", f"/v1/w/{fixtures.uuid(ws)}/ops",
        headers={"Authorization": f"Bearer {founder.d.access}",
                 "Content-Type": "application/json"},
        content=chunks())
    assert raw.status_code == 413, raw.text
    assert raw.json()["detail"]["code"] == "request_too_large"


@pytest.mark.item("CONF-WIRE-022")
def test_enabling_extensions_leaves_the_core_domains_alone(server, ext_server):
    """Extensions add a domain each; they never move one.

    The fifteen fixed core domains are <ns>/<doc>/v1 and depend on the
    namespace alone, so two deployments with different extension lists frame
    every core preimage identically — which is what makes an extension a local
    agreement rather than a fork of the wire format. And two names never share
    a domain, because the name is what the domain is built from.
    """
    import json
    import pathlib

    from roundelay import crypto

    corpus = json.loads(
        (pathlib.Path(__file__).resolve().parents[2] / "vectors" / "domains.json").read_text())
    namespace = corpus["namespace"]

    # The two deployments differ in exactly the extension list.
    assert server.health["extension_classes"] == {}
    assert ext_server.health["extension_classes"] == {str(EXT_CLASS): EXT_NAME}
    assert server.health["profile"] == ext_server.health["profile"]

    # And the fifteen core domains are the same on both, because they are a
    # function of the namespace and nothing else.
    core = {row["domain"] for row in corpus["core"]}
    assert len(core) == 15
    for row in corpus["core"]:
        assert row["domain"] == f"{namespace}/{row['document']}/v1"

    # An extension domain is built from the NAME, so it is outside that set and
    # distinct per name.
    domains = {name: f"{namespace}/ext/{name}/v1" for name in (EXT_NAME, "shred", "copy")}
    assert len(set(domains.values())) == 3
    assert not (set(domains.values()) & core)

    # And the framing of each is the length-prefixed construction, not string
    # concatenation — the property the whole scheme rests on.
    for name, domain in domains.items():
        framed = crypto.framed(domain, b"body")
        assert framed[0] == len(domain)
        assert framed[1:1 + len(domain)].decode() == domain
