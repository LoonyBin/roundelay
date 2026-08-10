"""The signal socket, which carries no information but "look again".

Every assertion here is about what the server does *not* send. A socket that
leaked a position, an author or a count would be a metadata channel beside a
log the server cannot read, and the whole point of the design is that watching
the socket tells an observer nothing that reading the log would not.
"""

from __future__ import annotations

import asyncio
import secrets

import pytest
import websockets

from roundelay import fixtures

pytestmark = pytest.mark.usefixtures("server")

HANDSHAKE = 5.0

# How long a server waits for the first frame before closing 4400 is a limit
# nothing advertises. signal_keepalive_seconds is in the health document's
# limits block; this deadline is not, though a close code depends on it just as
# directly — so a client cannot know how long it has, and this suite cannot ask.
# Fifteen seconds is a guess generous enough for any plausible answer.
AUTH_DEADLINE_CEILING = 15.0


def signal_url(server, ws: bytes) -> str:
    return server.ws_url(f"/v1/w/{fixtures.uuid(ws)}/signal")


async def open_socket(server, ws: bytes, token: str | None):
    """Connect and, if a token is given, send it as the first frame."""
    sock = await websockets.connect(signal_url(server, ws), open_timeout=HANDSHAKE)
    if token is not None:
        await sock.send(token)
    return sock


async def nothing_within(sock, seconds: float) -> None:
    """Assert the socket stays silent. The absence is the assertion."""
    try:
        frame = await asyncio.wait_for(sock.recv(), timeout=seconds)
    except asyncio.TimeoutError:
        return
    raise AssertionError(f"expected silence, got {frame!r}")


async def expect_close(sock, code: int, timeout: float = HANDSHAKE) -> None:
    try:
        await asyncio.wait_for(sock.recv(), timeout=timeout)
    except websockets.exceptions.ConnectionClosed:
        pass
    except asyncio.TimeoutError:
        raise AssertionError(f"expected close {code}, got silence")
    await sock.wait_closed()
    assert sock.close_code == code, f"expected {code}, got {sock.close_code}"


def run(coro):
    return asyncio.run(coro)


# ── the handshake ───────────────────────────────────────────────────────────


@pytest.mark.item("CONF-SIG-001")
def test_the_socket_is_accepted_before_authentication(server, founded):
    """Accept, then authenticate over the socket. A 401 on the upgrade would
    put the credential in the handshake, where proxies log it."""
    founder, ws = founded

    async def go():
        sock = await open_socket(server, ws, None)
        # Accepted with no credential offered at all.
        assert sock.close_code is None
        await sock.send(founder.d.access)
        frame = await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE)
        assert frame == "", f"the acknowledgement is an empty text frame, got {frame!r}"
        await sock.close()

    run(go())


@pytest.mark.item("CONF-SIG-002")
@pytest.mark.parametrize("how", ["silence", "close", "binary"])
def test_a_handshake_that_is_not_a_token(server, founded, how):
    founder, ws = founded

    async def go():
        sock = await open_socket(server, ws, None)
        if how == "close":
            await sock.close()
            await sock.wait_closed()
            return
        if how == "binary":
            await sock.send(b"\x00\x01\x02")
            await expect_close(sock, 4400)
            return
        # Silence: the deadline is the server's, and it advertises none.
        await expect_close(sock, 4400, timeout=AUTH_DEADLINE_CEILING)

    run(go())


@pytest.mark.item("CONF-SIG-003")
@pytest.mark.parametrize("flavour", ["nonsense", "refresh"])
def test_a_credential_that_is_not_a_device_access_token(server, founded, flavour):
    """4401 is "your credential is wrong", distinct from 4400's "that was not a
    credential at all" and 4403's "it is fine and you may not be here"."""
    founder, ws = founded
    token = "not-a-token" if flavour == "nonsense" else founder.d.refresh

    async def go():
        sock = await open_socket(server, ws, token)
        await expect_close(sock, 4401)

    run(go())


@pytest.mark.item("CONF-SIG-004")
def test_a_device_that_may_not_watch_this_workspace(server, founded, enrol, gid):
    """A revocation closes a socket that is already open — one that only took
    effect at the next connection would leave a revoked device watching for as
    long as it cared to hold the connection."""
    founder, ws = founded
    member = enrol(ws, founder, role=None)
    grant_id = gid()
    founder.resync()
    assert founder.post_ops(
        ws, founder.grant(ws, member.d, "participant", grant_id)).status == 200
    founder.resync()

    async def go():
        sock = await open_socket(server, ws, member.d.access)
        assert await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE) == ""

        founder.resync()
        assert founder.post_ops(ws, founder.revoke(ws, grant_id, gid())).status == 200
        founder.resync()
        await expect_close(sock, 4403)

    run(go())


@pytest.mark.item("CONF-SIG-004")
def test_a_device_registered_nowhere_here(server, founded, root):
    """The gate at the handshake, for a Workspace that does exist."""
    from roundelay.client import Device, Session

    _, ws = founded
    stranger = Session(server, Device(secrets.token_hex(8)), secrets.token_bytes(32))
    from conftest import own

    cert, sig = stranger.genesis_cert(own(stranger))
    assert stranger.register(cert, sig, admission="conformance-admission").status == 201
    assert stranger.log_in().status == 200

    async def go():
        sock = await open_socket(server, ws, stranger.d.access)
        await expect_close(sock, 4403)

    run(go())


@pytest.mark.item("CONF-SIG-008")
def test_a_shell_may_watch_a_workspace_that_does_not_exist(server, founder, workspace):
    """Before a genesis there is nothing to be registered in, so the socket that
    tells a device its Workspace has appeared cannot demand a registration in
    it. Otherwise a founder could not learn that its own genesis landed."""
    ws = workspace

    async def go():
        sock = await open_socket(server, ws, founder.d.access)
        assert await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE) == ""
        await nothing_within(sock, 0.3)

        founder.resync()
        assert founder.post_ops(ws, founder.genesis(ws)).status == 200

        frame = await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE)
        assert frame == "", f"a poke is an empty text frame, got {frame!r}"
        await sock.close()

    run(go())


# ── what crosses the wire ───────────────────────────────────────────────────


@pytest.mark.item("CONF-SIG-005")
@pytest.mark.item("CONF-SIG-006")
def test_the_socket_says_only_look_again(server, founded):
    """Across a whole session every frame is empty or the literal "ping", and a
    batch of four ops is one poke rather than four.

    Coalescing under a slow reader is the other half of the rule and is not
    decidable from out here: the client's own receive buffer drains the socket
    whether or not this code calls recv, so the server's writer never blocks and
    has nothing to coalesce. What is decidable is that a poke describes an
    event and not an op — four ops landing together are one thing to look at.
    """
    founder, ws = founded

    async def go():
        sock = await open_socket(server, ws, founder.d.access)
        assert await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE) == ""

        founder.resync()
        assert founder.post_ops(ws, *[founder.content(ws) for _ in range(4)]).status == 200

        frames = []
        while True:
            try:
                frames.append(await asyncio.wait_for(sock.recv(), timeout=0.5))
            except asyncio.TimeoutError:
                break

        assert frames, "a batch landed and no poke at all"
        for frame in frames:
            assert isinstance(frame, str), f"a binary frame carries something: {frame!r}"
            assert frame in ("", "ping"), f"the socket said {frame!r}"
        assert len([f for f in frames if f == ""]) == 1, frames
        await sock.close()

    run(go())


@pytest.mark.item("CONF-SIG-007")
def test_an_expiring_access_token_does_not_close_a_live_socket(server, founded):
    """The token authorises the handshake; the socket's continued life is a
    grant question, not a token question. Otherwise every watcher drops on a
    fixed schedule and reconnects in a thundering herd."""
    founder, ws = founded

    async def go():
        sock = await open_socket(server, ws, founder.d.access)
        assert await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE) == ""

        # Rotate the credential out from under it: the old access token is no
        # longer the one a fresh handshake would use.
        path = f"/v1/members/{fixtures.uuid(founder.d.member_id)}/token/refresh"
        assert server.post(path, json_body={
            "refresh_token": founder.d.refresh}).status == 200

        await nothing_within(sock, 1.0)
        founder.resync()
        assert founder.post_ops(ws, founder.content(ws)).status == 200
        assert await asyncio.wait_for(sock.recv(), timeout=HANDSHAKE) == ""
        await sock.close()

    run(go())
