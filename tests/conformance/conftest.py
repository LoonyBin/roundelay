"""Fixtures for the conformance suite.

There is one, and it is the transport. No store handle, no process internals,
no test hook — which is what makes every item bound to a test in this suite
black-box by construction rather than by discipline.

The server under test is either one this file starts (``roundelay-server`` built
from this repository) or one already running at ``ROUNDELAY_BASE_URL``. The
second is the point: nothing here is specific to the Go implementation, and a
different server should be able to take the same suite.
"""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from roundelay import fixtures  # noqa: E402
from roundelay.client import Device, Server, Session  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
ADMISSION_TOKEN = "conformance-admission"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "item(id): the conformance checklist item this test decides, e.g. CONF-LOG-014",
    )


def pytest_collection_modifyitems(session, config, items) -> None:
    """Write the item → test binding the conformance lint reads.

    Without this the checklist's `test:` column is an aspiration. With it the
    lint can say which of the 250 items are actually decided by something that
    runs, and which are still only described.
    """
    bindings: dict[str, list[str]] = {}
    for item in items:
        for marker in item.iter_markers(name="item"):
            for cid in marker.args:
                bindings.setdefault(cid, []).append(item.nodeid)
    out = REPO / "conformance" / "bindings.json"
    out.write_text(json.dumps({"items": bindings}, indent=2, sort_keys=True) + "\n")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def base_url() -> str:
    """The server under test.

    ROUNDELAY_BASE_URL points the suite at something already running — another
    implementation, or a deployment. Otherwise this builds and starts the one in
    this repository.
    """
    if url := os.environ.get("ROUNDELAY_BASE_URL"):
        return url.rstrip("/")

    binary = REPO / "build" / "roundelay-server"
    binary.parent.mkdir(exist_ok=True)
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/roundelay-server"],
        cwd=REPO, check=True,
    )

    port = _free_port()
    proc = subprocess.Popen(
        [str(binary), "-addr", f"127.0.0.1:{port}", "-admission", f"token:{ADMISSION_TOKEN}"],
        cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    url = f"http://127.0.0.1:{port}"

    import httpx

    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"server exited: {proc.stderr.read().decode()}")
        try:
            httpx.get(url + "/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)
    else:
        proc.kill()
        raise RuntimeError("server did not become ready")

    yield url
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def server(base_url: str) -> Server:
    s = Server(base_url)
    yield s
    s.close()


@pytest.fixture
def workspace() -> bytes:
    """A Workspace nothing has touched.

    Ids are the caller's to choose under `derived`, and a suite that reused one
    would be testing whatever the previous case left behind.
    """
    return secrets.token_bytes(16)


@pytest.fixture
def root() -> bytes:
    """A fresh Root keypair seed. 32 random bytes and no server is involved."""
    return secrets.token_bytes(32)


@pytest.fixture
def founder(server: Server, root: bytes) -> Session:
    """A device that has registered and holds a token, but has founded nothing.

    Register, then genesis, then vault — this is the first step, and the state a
    founder is in before its own Workspace exists.
    """
    device = Device(secrets.token_hex(8))
    session = Session(server, device, root)
    # The certificate a founding registration carries is its own genesis's.
    ws = secrets.token_bytes(16)
    session.founding_workspace = ws  # type: ignore[attr-defined]
    cert, sig = session.genesis_cert(ws)
    got = session.register(cert, sig, admission=ADMISSION_TOKEN)
    assert got.status == 201, got.body
    assert session.log_in().status == 200
    return session


@pytest.fixture
def founded(founder: Session) -> tuple[Session, bytes]:
    """A Workspace that exists, with its founder holding owner.

    The whole enrolment as one request: the genesis that creates the Workspace
    and registers its founder, and the Root-signed self-grant that gives it
    authority.
    """
    ws = founder.founding_workspace  # type: ignore[attr-defined]
    got = founder.post_ops(
        ws,
        founder.genesis(ws),
        founder.grant(ws, founder.d, "owner", fixtures.uuid(secrets.token_bytes(16))),
    )
    assert got.status == 200, got.body
    founder.resync()
    return founder, ws


@pytest.fixture
def enrol(server: Server, root: bytes):
    """Bring a new device into an existing Workspace, the way a device joins.

    Register at the route, log in, post the same certificate as the device's own
    first op, and take a grant from a device that may issue one. The tip comes
    from the inviter rather than from the joiner, because a device holding no
    grant cannot read the log yet — bar 1 is exactly what it lacks.
    """

    def make(ws: bytes, inviter: Session, *, role: str | None = "participant",
             label: str | None = None, signer: bytes | None = None) -> Session:
        device = Device(label or secrets.token_hex(8))
        session = Session(server, device, root)
        cert, sig = session.register_cert(ws)
        got = session.register(cert, sig, admission=ADMISSION_TOKEN)
        assert got.status == 201, got.body
        assert session.log_in().status == 200

        inviter.resync()
        session.pending_tip = inviter.committed_tip(ws)
        got = session.post_ops(ws, session.member_register(ws))
        assert got.status == 200, got.body
        session.resync()

        if role is not None:
            inviter.resync()
            got = inviter.post_ops(ws, inviter.grant(
                ws, device, role, fixtures.uuid(secrets.token_bytes(16)), signer=signer))
            assert got.status == 200, got.body
            inviter.resync()
        return session

    return make


@pytest.fixture
def gid():
    """A fresh certificate id. Reuse is a refusal in its own right."""
    return lambda: fixtures.uuid(secrets.token_bytes(16))
