"""Registration, credentials, and the member list.

Two doors lead to a member record — the founding branch and the joining one —
and one certificate gets one verdict whichever it comes through. Below that,
the two token flavours are not interchangeable in either direction, and the
member list is a page over raw member ids.
"""

from __future__ import annotations

import secrets

import pytest

from roundelay import crypto, fixtures, wire
from roundelay.client import Device, Session

pytestmark = pytest.mark.usefixtures("server")

ADMISSION = "conformance-admission"


def shell(server, root: bytes) -> Session:
    """A device with keys and no registration anywhere."""
    return Session(server, Device(secrets.token_hex(8)), root)


# ── registration ────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-MEM-001")
def test_registration_is_idempotent(server, root):
    """201 the first time, 200 with the same body the second — because a client
    that retries a timed-out request must not be told it lost a race with
    itself."""
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))

    first = device.register(cert, sig, admission=ADMISSION)
    assert first.status == 201, first.body
    second = device.register(cert, sig, admission=ADMISSION)
    assert second.status == 200, second.body
    assert second.body == first.body


@pytest.mark.item("CONF-MEM-002")
@pytest.mark.item("CONF-DKEY-003")
@pytest.mark.parametrize("field,value,code", [
    ("control_pk", fixtures.b64(b"\x00" * 31), "malformed_sign_pk"),
    ("content_pk", fixtures.b64(b"\x00" * 33), "malformed_sign_pk"),
    ("kex_pk", fixtures.b64(b"\x00" * 31), "malformed_kex_pk"),
    ("control_pk", "!!not base64!!", "malformed_sign_pk"),
])
def test_malformed_keys_are_refused(server, root, field, value, code):
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))
    body = {
        "member_id": fixtures.uuid(device.d.member_id),
        "control_pk": fixtures.b64(device.d.control_pk),
        "content_pk": fixtures.b64(device.d.content_pk),
        "kex_pk": fixtures.b64(device.d.kex_pk),
        "cert_b64": fixtures.b64(cert),
        "cert_sig_b64": fixtures.b64(sig),
        "root_pk_b64": fixtures.b64(crypto.ed25519_public(root)),
    }
    body[field] = value
    got = server.post("/v1/members", json_body=body,
                      headers={"Roundelay-Admission": ADMISSION})
    assert got.status == 422, got.body
    assert got.code == code


@pytest.mark.item("CONF-DKEY-003")
@pytest.mark.parametrize("which", ["control_key_id", "content_key_id", "kex_key_id"])
def test_a_claimed_key_id_must_be_the_derivation(server, root, which):
    """The ids are the server's own derivation, so a claim is checked rather
    than believed — otherwise a device could name an id it does not hold and
    every wrap addressed to it would go somewhere else."""
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))
    body = {
        "member_id": fixtures.uuid(device.d.member_id),
        "control_pk": fixtures.b64(device.d.control_pk),
        "content_pk": fixtures.b64(device.d.content_pk),
        "kex_pk": fixtures.b64(device.d.kex_pk),
        "cert_b64": fixtures.b64(cert),
        "cert_sig_b64": fixtures.b64(sig),
        "root_pk_b64": fixtures.b64(crypto.ed25519_public(root)),
        "key_ids": {
            "control_key_id": fixtures.b64(crypto.key_id(device.d.control_pk)),
            "content_key_id": fixtures.b64(crypto.key_id(device.d.content_pk)),
            "kex_key_id": fixtures.b64(crypto.key_id(device.d.kex_pk)),
        },
    }
    body["key_ids"][which] = fixtures.b64(secrets.token_bytes(8))
    got = server.post("/v1/members", json_body=body,
                      headers={"Roundelay-Admission": ADMISSION})
    assert got.status == 422, got.body
    assert got.code == "key_id_not_derived_from_sign_pk"


@pytest.mark.item("CONF-MEM-010")
def test_key_ids_is_all_or_nothing(server, root):
    """Optional as a whole, never member by member: a partial object is a
    client that thinks the server will fill the rest in."""
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))

    def send(key_ids):
        body = {
            "member_id": fixtures.uuid(device.d.member_id),
            "control_pk": fixtures.b64(device.d.control_pk),
            "content_pk": fixtures.b64(device.d.content_pk),
            "kex_pk": fixtures.b64(device.d.kex_pk),
            "cert_b64": fixtures.b64(cert),
            "cert_sig_b64": fixtures.b64(sig),
            "root_pk_b64": fixtures.b64(crypto.ed25519_public(root)),
        }
        if key_ids is not None:
            body["key_ids"] = key_ids
        return server.post("/v1/members", json_body=body,
                           headers={"Roundelay-Admission": ADMISSION})

    whole = {
        "control_key_id": fixtures.b64(crypto.key_id(device.d.control_pk)),
        "content_key_id": fixtures.b64(crypto.key_id(device.d.content_pk)),
        "kex_key_id": fixtures.b64(crypto.key_id(device.d.kex_pk)),
    }

    got = send({**whole, "surprise_key_id": fixtures.b64(bytes(8))})
    assert got.status == 422 and got.code == "unknown_request_field", got.body
    assert got.detail["fields"] == ["key_ids.surprise_key_id"]

    partial = dict(whole)
    del partial["kex_key_id"]
    got = send(partial)
    assert got.status == 422, got.body
    assert got.code == "malformed_request"
    assert "key_ids.kex_key_id" in got.detail["fields"]

    # Omitted entirely is fine, and sent in full it round-trips.
    assert send(None).status == 201
    got = send(whole)
    assert got.status == 200, got.body
    assert got.body["key_ids"] == whole


@pytest.mark.item("CONF-MEM-003")
@pytest.mark.parametrize("differs", ["control", "content", "kex"])
def test_a_member_id_belongs_to_one_key_set(server, root, differs):
    """The certificate checks sit above the conflict, so this is a device with
    a certificate of its own that happens to claim an id already taken."""
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))
    assert device.register(cert, sig, admission=ADMISSION).status == 201

    impostor = Device(secrets.token_hex(8))
    impostor.member_id = device.d.member_id
    for name in ("control", "content", "kex"):
        if name != differs:
            setattr(impostor, name, getattr(device.d, name))
    other = Session(server, impostor, root)
    got = other.register(*other.genesis_cert(secrets.token_bytes(16)),
                         admission=ADMISSION)
    assert got.status == 409, got.body
    assert got.code == "member_id_already_registered"


@pytest.mark.item("CONF-MEM-003")
@pytest.mark.parametrize("missing,code", [
    ("control_pk", "malformed_sign_pk"),
    ("content_pk", "malformed_sign_pk"),
    ("kex_pk", "malformed_kex_pk"),
])
def test_an_omitted_key_is_a_shape_refusal(server, root, missing, code):
    """All three are required on every registration, so leaving one out is
    never a conflict with what is stored — there is nothing to compare."""
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))
    assert device.register(cert, sig, admission=ADMISSION).status == 201

    body = {
        "member_id": fixtures.uuid(device.d.member_id),
        "control_pk": fixtures.b64(device.d.control_pk),
        "content_pk": fixtures.b64(device.d.content_pk),
        "kex_pk": fixtures.b64(device.d.kex_pk),
        "cert_b64": fixtures.b64(cert),
        "cert_sig_b64": fixtures.b64(sig),
        "root_pk_b64": fixtures.b64(crypto.ed25519_public(root)),
    }
    del body[missing]
    got = server.post("/v1/members", json_body=body,
                      headers={"Roundelay-Admission": ADMISSION})
    assert got.status == 422, got.body
    assert got.code == code


@pytest.mark.item("CONF-CRED-006")
def test_the_founding_branch_is_gated_by_its_certificate(server, root):
    """No Workspace of that id exists yet, so the certificate in the body is
    the whole of the authorisation."""
    device = shell(server, root)
    ws = secrets.token_bytes(16)

    cert, sig = device.genesis_cert(ws)
    got = device.register(cert, crypto.sign(secrets.token_bytes(32), b"nonsense"),
                          admission=ADMISSION)
    assert got.status == 422, got.body
    assert got.code == "bad_root_signature"


# ── credentials ─────────────────────────────────────────────────────────────


@pytest.mark.item("CONF-CRED-001")
def test_a_refresh_token_is_not_a_bearer_token(founded):
    founder, ws = founded
    got = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/ops", token=founder.d.refresh)
    assert got.status == 401, got.body
    assert got.code == "invalid_credential"


@pytest.mark.item("CONF-CRED-002")
def test_an_access_token_is_not_a_refresh_token(server, founded, root):
    founder, _ = founded
    path = f"/v1/members/{fixtures.uuid(founder.d.member_id)}/token/refresh"

    got = server.post(path, json_body={"refresh_token": founder.d.access})
    assert got.status == 401, got.body
    assert got.code == "invalid_refresh_token"

    # And one scoped to another device is not this device's.
    other = shell(server, root)
    cert, sig = other.genesis_cert(secrets.token_bytes(16))
    assert other.register(cert, sig, admission=ADMISSION).status == 201
    assert other.log_in().status == 200
    got = server.post(path, json_body={"refresh_token": other.d.refresh})
    assert got.status == 401, got.body
    assert got.code == "invalid_refresh_token"


@pytest.mark.item("CONF-CRED-003")
def test_a_refresh_rotates_the_pair(server, founded):
    founder, _ = founded
    path = f"/v1/members/{fixtures.uuid(founder.d.member_id)}/token/refresh"
    spent = founder.d.refresh

    got = server.post(path, json_body={"refresh_token": spent})
    assert got.status == 200, got.body
    assert got.body["refresh_token"] != spent
    assert got.body["access_token"]
    # Only the refresh token is required to be high-entropy and returned once.
    # An access token is an opaque bearer string, and a server that derives one
    # from (member, expiry) legitimately returns the same bytes twice inside one
    # second — so there is nothing to assert about it but that it is there.

    # The presented one is revoked by the success, and only by it.
    again = server.post(path, json_body={"refresh_token": spent})
    assert again.status == 401, again.body
    assert again.code == "invalid_refresh_token"
    # The fresh one still works.
    assert server.post(path, json_body={
        "refresh_token": got.body["refresh_token"]}).status == 200


@pytest.mark.item("CONF-CRED-005")
def test_every_401_offers_the_scheme(server, founded, root):
    """WWW-Authenticate: Bearer, on all three flavours of 401 — a client that
    got the credential wrong is told what kind was wanted."""
    founder, ws = founded

    cases = [
        ("GET", f"/v1/w/{fixtures.uuid(ws)}/ops", {"token": "nonsense.token.here"}),
        ("POST", f"/v1/members/{fixtures.uuid(founder.d.member_id)}/token/refresh",
         {"json_body": {"refresh_token": "nonsense"}}),
        ("POST", f"/v1/members/{fixtures.uuid(founder.d.member_id)}/token",
         {"json_body": {"nonce": fixtures.b64(bytes(32)),
                        "signature": fixtures.b64(bytes(64))}}),
    ]
    for method, path, kw in cases:
        raw = server.http.request(
            method, path,
            headers=({"Authorization": f"Bearer {kw['token']}"} if "token" in kw else {}),
            json=kw.get("json_body"))
        assert raw.status_code == 401, (path, raw.text)
        assert raw.headers.get("WWW-Authenticate") == "Bearer", path


@pytest.mark.item("CONF-CRED-007")
@pytest.mark.item("CONF-DKEY-002")
def test_a_challenge_is_spent_by_the_attempt(server, root):
    """Win or lose. A nonce that survived a failure would let an attacker
    grind signatures against one challenge."""
    device = shell(server, root)
    cert, sig = device.genesis_cert(secrets.token_bytes(16))
    assert device.register(cert, sig, admission=ADMISSION).status == 201
    path = f"/v1/members/{fixtures.uuid(device.d.member_id)}"

    got = server.post(path + "/challenge")
    nonce = got.body["nonce"]

    # Answered by the content key, which is the wrong key for this door.
    wrong = crypto.sign(device.d.content, wire.auth_challenge_input(
        server.namespace, device.d.member_id, fixtures.b64d(nonce)))
    got = server.post(path + "/token", json_body={
        "nonce": nonce, "signature": fixtures.b64(wrong)})
    assert got.status == 401, got.body
    assert got.code == "bad_member_challenge"

    # The same nonce, now answered correctly: the challenge is gone.
    right = crypto.sign(device.d.control, wire.auth_challenge_input(
        server.namespace, device.d.member_id, fixtures.b64d(nonce)))
    got = server.post(path + "/token", json_body={
        "nonce": nonce, "signature": fixtures.b64(right)})
    assert got.status == 401, got.body
    assert got.code == "bad_member_challenge"


@pytest.mark.item("CONF-CRED-008")
def test_a_challenge_for_an_unknown_member(server, root):
    """404 and no counter, so registering afterwards does not start rate
    limited by the requests that preceded the record."""
    device = shell(server, root)
    path = f"/v1/members/{fixtures.uuid(device.d.member_id)}/challenge"

    for _ in range(8):
        got = server.post(path)
        assert got.status == 404, got.body
        assert got.code == "unknown_member"

    cert, sig = device.genesis_cert(secrets.token_bytes(16))
    assert device.register(cert, sig, admission=ADMISSION).status == 201
    assert server.post(path).status == 200


# ── the member list ─────────────────────────────────────────────────────────


@pytest.mark.item("CONF-MEM-006")
def test_a_pre_genesis_member_list_is_empty(founder, workspace):
    """Not an error: reading a Workspace that does not exist is how a device
    discovers it needs to found one."""
    got = founder.s.get(f"/v1/w/{fixtures.uuid(workspace)}/members",
                        token=founder.d.access)
    assert got.status == 200, got.body
    assert got.body["members"] == []
    assert got.body["has_more"] is False


@pytest.mark.item("CONF-MEM-004")
@pytest.mark.item("CONF-MEM-005")
def test_the_list_is_exactly_this_workspaces_members(server, founded, enrol, root):
    founder, ws = founded
    member = enrol(ws, founder)
    outsider = shell(server, root)
    cert, sig = outsider.genesis_cert(secrets.token_bytes(16))
    assert outsider.register(cert, sig, admission=ADMISSION).status == 201

    got = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members", token=founder.d.access)
    assert got.status == 200, got.body
    ids = [m["member_id"] for m in got.body["members"]]
    assert ids == sorted(ids, key=lambda u: fixtures.parse_uuid(u))
    assert set(ids) == {fixtures.uuid(founder.d.member_id),
                        fixtures.uuid(member.d.member_id)}
    # A shell registered nowhere, and a member of another Workspace, are absent.
    assert fixtures.uuid(outsider.d.member_id) not in ids
    for entry in got.body["members"]:
        assert entry["member_kind"] == "device"
        assert "chained" not in entry


@pytest.mark.item("CONF-MEM-007")
@pytest.mark.item("CONF-MEM-008")
def test_the_member_list_pages_on_raw_bytes(founded, enrol):
    """The ordering is over the raw 16 bytes, which is not the ordering of the
    UUID text — and `after` is a position, so a uuid naming nobody is a legal
    place to resume from."""
    founder, ws = founded
    for _ in range(3):
        enrol(ws, founder, role=None)

    everyone = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members",
                             token=founder.d.access).body["members"]
    ids = [m["member_id"] for m in everyone]
    assert len(ids) == 4

    walked, cursor = [], None
    while True:
        query = "?limit=2" + (f"&after={cursor}" if cursor else "")
        page = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members{query}",
                             token=founder.d.access)
        assert page.status == 200, page.body
        walked += [m["member_id"] for m in page.body["members"]]
        if not page.body["has_more"]:
            break
        cursor = walked[-1]
    assert walked == ids

    # A canonical uuid naming no member is a position, not a lookup.
    absent = "00000000-0000-0000-0000-000000000000"
    page = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members?after={absent}",
                         token=founder.d.access)
    assert page.status == 200, page.body
    assert [m["member_id"] for m in page.body["members"]] == [
        i for i in ids if fixtures.parse_uuid(i) > bytes(16)]


@pytest.mark.item("CONF-MEM-009")
@pytest.mark.parametrize("query,code", [
    ("?limit=0", "malformed_request"),
    ("?limit=99999", "malformed_request"),
    ("?after=not-a-uuid", "malformed_request"),
    ("?after=0000000000000000000000000000ffff", "malformed_request"),
    ("?page=2", "unknown_request_field"),
])
def test_member_list_parameters_are_never_clamped(founded, query, code):
    founder, ws = founded
    got = founder.s.get(f"/v1/w/{fixtures.uuid(ws)}/members{query}",
                        token=founder.d.access)
    assert got.status == 422, got.body
    assert got.code == code


# ── the two signing keys ────────────────────────────────────────────────────


@pytest.mark.item("CONF-DKEY-001")
def test_the_key_class_must_match_the_op_class(founded, enrol):
    """Header-only, and so above stage 2: an op that is both class-mismatched
    and unauthorised answers on the header, because stage 1 is a complete pass
    and never reads the log."""
    founder, ws = founded

    # A control op signed by the content key.
    founder.resync()
    got = founder.post_ops(ws, founder.control(ws, {
        "type": "rotate", "prev_control_hash": founder.tip(ws),
        "workspace_id": fixtures.uuid(ws), "from_epoch": 0, "to_epoch": 1,
        "keywrap_digest_b64": fixtures.b64(bytes(32)),
    }, signer=founder.d.content))
    assert got.status == 422, got.body
    assert got.code == "author_key_class_mismatch"

    # And an opaque op signed by the control key, from a device that also holds
    # no grant — the header answers first.
    grantless = enrol(ws, founder, role=None)
    grantless.resync()
    got = grantless.post_ops(ws, grantless.content(ws, signer=grantless.d.control))
    assert got.status == 422, got.body
    assert got.code == "author_key_class_mismatch"
