"""A device, speaking to a server over HTTP and WebSocket and nothing else.

There is deliberately no other way in. The observability lint asks whether a
black-box item is decidable from traffic alone, and the honest mechanical form
of that is "the test reaches for no fixture but the transport" — which this
suite makes true by construction, because no other fixture exists.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from . import crypto, fixtures, wire


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


HLC = [1700000000000, 0, "00000000000000000000000000000000"]


@dataclass
class Response:
    status: int
    body: dict[str, Any]

    @property
    def code(self) -> str | None:
        """The refusal code, or None on a success."""
        detail = self.body.get("detail")
        return detail.get("code") if isinstance(detail, dict) else None

    @property
    def detail(self) -> dict[str, Any]:
        return self.body.get("detail") or {}


class Server:
    """The system under test, reachable only as a client can reach it."""

    def __init__(self, base_url: str, namespace: str = fixtures.NAMESPACE):
        self.base = base_url.rstrip("/")
        self.namespace = namespace
        self.http = httpx.Client(base_url=self.base, timeout=10.0)
        self.ladder = wire.Ladder()

    def close(self) -> None:
        self.http.close()

    def request(self, method: str, path: str, *, token: str | None = None,
                json_body: Any = None, raw_body: str | None = None,
                headers: dict[str, str] | None = None) -> Response:
        h = dict(headers or {})
        if token:
            h["Authorization"] = f"Bearer {token}"
        content = raw_body.encode() if raw_body is not None else None
        if content is None and json_body is not None:
            content = json.dumps(json_body).encode()
            h.setdefault("Content-Type", "application/json")
        resp = self.http.request(method, path, content=content, headers=h)
        try:
            body = resp.json()
        except Exception:
            body = {}
        return Response(resp.status_code, body)

    def get(self, path: str, **kw) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw) -> Response:
        return self.request("PUT", path, **kw)

    @property
    def health(self) -> dict[str, Any]:
        return self.get("/health").body

    def ws_url(self, path: str) -> str:
        return "ws" + self.base[len("http"):] + path


@dataclass
class Device:
    """A member's three keys and its session."""

    label: str
    member_id: bytes = field(init=False)
    control: bytes = field(init=False)
    content: bytes = field(init=False)
    kex: bytes = field(init=False)
    access: str = ""
    refresh: str = ""
    author_seq: int = 0
    committed_seq: int = 0

    def __post_init__(self) -> None:
        self.member_id = fixtures.bytes16(f"suite/{self.label}")
        self.control = fixtures.seed(f"suite/{self.label}/control")
        self.content = fixtures.seed(f"suite/{self.label}/content")
        self.kex = fixtures.seed(f"suite/{self.label}/kex")

    @property
    def control_pk(self) -> bytes:
        return crypto.ed25519_public(self.control)

    @property
    def content_pk(self) -> bytes:
        return crypto.ed25519_public(self.content)

    @property
    def kex_pk(self) -> bytes:
        return crypto.x25519_public(self.kex)

    def next_seq(self) -> int:
        self.author_seq += 1
        return self.author_seq

    def registration_block(self, workspace: bytes | None = None) -> dict[str, Any]:
        block = {
            "member_id": fixtures.uuid(self.member_id),
            "member_kind": "device",
            "holder_ref": b64(bytes(32)),
            "control_pk": b64(self.control_pk),
            "control_key_id": b64(crypto.key_id(self.control_pk)),
            "content_pk": b64(self.content_pk),
            "content_key_id": b64(crypto.key_id(self.content_pk)),
            "kex_pk": b64(self.kex_pk),
            "kex_key_id": b64(crypto.key_id(self.kex_pk)),
            "registered_at_hlc": HLC,
        }
        if workspace is not None:
            block["workspace_id"] = fixtures.uuid(workspace)
        return block


class Session:
    """A device's whole story against one server: register, log in, write."""

    def __init__(self, server: Server, device: Device, root_seed: bytes):
        self.s = server
        self.d = device
        self.root = root_seed
        self.pending_tip: str | None = None

    # ── identity ────────────────────────────────────────────────────────────

    def register(self, cert: bytes, sig: bytes, *, key_ids: bool = True,
                 admission: str | None = None) -> Response:
        body = {
            "member_id": fixtures.uuid(self.d.member_id),
            "control_pk": b64(self.d.control_pk),
            "content_pk": b64(self.d.content_pk),
            "kex_pk": b64(self.d.kex_pk),
            "cert_b64": b64(cert),
            "cert_sig_b64": b64(sig),
            "root_pk_b64": b64(crypto.ed25519_public(self.root)),
        }
        if key_ids:
            body["key_ids"] = {
                "control_key_id": b64(crypto.key_id(self.d.control_pk)),
                "content_key_id": b64(crypto.key_id(self.d.content_pk)),
                "kex_key_id": b64(crypto.key_id(self.d.kex_pk)),
            }
        headers = {"Roundelay-Admission": admission} if admission else None
        return self.s.post("/v1/members", json_body=body, headers=headers)

    def log_in(self) -> Response:
        path = f"/v1/members/{fixtures.uuid(self.d.member_id)}"
        got = self.s.post(path + "/challenge")
        if got.status != 200:
            return got
        nonce = b64d(got.body["nonce"])
        sig = crypto.sign(
            self.d.control, wire.auth_challenge_input(self.s.namespace, self.d.member_id, nonce)
        )
        got = self.s.post(path + "/token", json_body={"nonce": b64(nonce), "signature": b64(sig)})
        if got.status == 200:
            self.d.access = got.body["access_token"]
            self.d.refresh = got.body["refresh_token"]
        return got

    # ── ops ─────────────────────────────────────────────────────────────────

    def envelope(self, *, op_class: int, payload: bytes, workspace: bytes,
                 suite: int = wire.SUITE_NONE, key_epoch: int = 0,
                 op_label: str | None = None, author_seq: int | None = None,
                 signer: bytes | None = None, key_id_of: bytes | None = None,
                 ext_name: str = "", content_key: bytes | None = None,
                 content_nonce: bytes | None = None) -> str:
        seq = author_seq if author_seq is not None else self.d.next_seq()
        signer = signer if signer is not None else (
            self.d.control if wire.server_reads(op_class) else self.d.content
        )
        pub = key_id_of if key_id_of is not None else crypto.ed25519_public(signer)
        header = wire.Header(
            op_class=op_class,
            suite=suite,
            workspace_id=workspace,
            key_epoch=key_epoch,
            op_id=fixtures.bytes16(op_label or f"{self.d.label}/op/{op_class}/{seq}"),
            author_member_id=self.d.member_id,
            author_key_id=crypto.key_id(pub),
            author_seq=seq,
            prev_author_hash=b"" if seq == 1 else fixtures.seed(f"prev/{seq}")[:32],
        )
        if seq == 1:
            header.prev_author_hash = bytes(32)
        body = self.s.ladder.pack_body(payload)
        if suite == wire.SUITE_ENCRYPTED:
            # A sealed op is really sealed, tag and all. Marking the byte and
            # sending a plaintext-length body would put the envelope 16 bytes
            # below the floor its own suite sets, and every such case would
            # answer envelope_too_short before reaching whatever it was testing.
            header.nonce = content_nonce if content_nonce is not None else fixtures.seed(
                f"{self.d.label}/nonce/{op_class}/{seq}")[:24]
            body = crypto.xchacha_seal(
                content_key if content_key is not None else fixtures.CONTENT_KEY,
                header.nonce, body, header.marshal())
        domain = wire.op_domain(self.s.namespace, op_class, ext_name)
        return b64(wire.sign_op(signer, domain, header.marshal(), body))

    def post_ops(self, workspace: bytes, *envelopes: str, token: str | None = None) -> Response:
        got = self.s.post(
            f"/v1/w/{fixtures.uuid(workspace)}/ops",
            token=token if token is not None else self.d.access,
            json_body={"ops": list(envelopes)},
        )
        # A batch is all or nothing, so a refused one consumed no positions and
        # the next op this device writes carries the sequence the refused one
        # tried to. Without this every test that expects a refusal poisons the
        # chain for everything after it, and the second assertion in a test
        # answers author_chain_conflict rather than what it was asking about.
        if got.status == 200:
            self.d.committed_seq = self.d.author_seq
        else:
            self.d.author_seq = self.d.committed_seq
        return got

    # ── control ops ─────────────────────────────────────────────────────────

    def control(self, workspace: bytes, payload: dict[str, Any], **kw) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        env = self.envelope(op_class=wire.CLASS_CONTROL, payload=raw, workspace=workspace, **kw)
        self.pending_tip = crypto.payload_hash(raw).hex()
        return env

    def tip(self, workspace: bytes) -> str:
        """The link the next control op must name.

        Within a batch the tip advances as the batch walks, so an op built after
        another in the same request links it — and the committed log cannot say
        so, because nothing has committed yet.
        """
        if self.pending_tip is not None:
            return self.pending_tip
        return self.committed_tip(workspace)

    def committed_tip(self, workspace: bytes) -> str:
        page = self.s.get(
            f"/v1/w/{fixtures.uuid(workspace)}/ops?include_reprised=true",
            token=self.d.access,
        )
        tip = "00" * 32
        for row in page.body.get("ops", []):
            raw = b64d(row["envelope"])
            header, body, _ = wire.parse_envelope(raw)
            if header.op_class == wire.CLASS_CONTROL:
                tip = crypto.payload_hash(self.s.ladder.unpack_body(body)).hex()
        return tip

    def resync(self) -> None:
        self.pending_tip = None

    def genesis(self, workspace: bytes) -> str:
        cert = json.dumps(
            {
                "workspace_id": fixtures.uuid(workspace),
                "root_pk": b64(crypto.ed25519_public(self.root)),
                "founder": self.d.registration_block(),
                "created_at_hlc": HLC,
            },
            separators=(",", ":"),
        ).encode()
        sig = crypto.sign(self.root, wire.cert_input(self.s.namespace, "workspace-genesis", cert))
        return self.control(
            workspace,
            {
                "type": "workspace_genesis",
                "prev_control_hash": "00" * 32,
                "cert_b64": b64(cert),
                "cert_sig_b64": b64(sig),
            },
        )

    def genesis_cert(self, workspace: bytes) -> tuple[bytes, bytes]:
        cert = json.dumps(
            {
                "workspace_id": fixtures.uuid(workspace),
                "root_pk": b64(crypto.ed25519_public(self.root)),
                "founder": self.d.registration_block(),
                "created_at_hlc": HLC,
            },
            separators=(",", ":"),
        ).encode()
        return cert, crypto.sign(
            self.root, wire.cert_input(self.s.namespace, "workspace-genesis", cert)
        )

    def register_cert(self, workspace: bytes) -> tuple[bytes, bytes]:
        cert = json.dumps(
            self.d.registration_block(workspace), separators=(",", ":")
        ).encode()
        return cert, crypto.sign(
            self.root, wire.cert_input(self.s.namespace, "member-register", cert)
        )

    def member_register(self, workspace: bytes) -> str:
        cert, sig = self.register_cert(workspace)
        return self.control(
            workspace,
            {
                "type": "member_register",
                "prev_control_hash": self.tip(workspace),
                "cert_b64": b64(cert),
                "cert_sig_b64": b64(sig),
            },
        )

    def grant(self, workspace: bytes, grantee: Device, role: str, grant_id: str,
              *, granter: str = "root", signer: bytes | None = None) -> str:
        cert = json.dumps(
            {
                "workspace_id": fixtures.uuid(workspace),
                "grant_id": grant_id,
                "member_id": fixtures.uuid(grantee.member_id),
                "role": role,
                "granter": granter,
                "granted_at_hlc": HLC,
            },
            separators=(",", ":"),
        ).encode()
        key = signer if signer is not None else self.root
        sig = crypto.sign(key, wire.cert_input(self.s.namespace, "grant", cert))
        return self.control(
            workspace,
            {
                "type": "grant",
                "prev_control_hash": self.tip(workspace),
                "granter": granter,
                "cert_b64": b64(cert),
                "cert_sig_b64": b64(sig),
            },
        )

    def revoke(self, workspace: bytes, grant_id: str, revoke_id: str,
               *, revoker: str = "root", signer: bytes | None = None) -> str:
        cert = json.dumps(
            {
                "workspace_id": fixtures.uuid(workspace),
                "revoke_id": revoke_id,
                "grant_id": grant_id,
                "revoker": revoker,
                "revoked_at_hlc": HLC,
            },
            separators=(",", ":"),
        ).encode()
        key = signer if signer is not None else self.root
        sig = crypto.sign(key, wire.cert_input(self.s.namespace, "revoke", cert))
        return self.control(
            workspace,
            {
                "type": "revoke",
                "prev_control_hash": self.tip(workspace),
                "revoker": revoker,
                "cert_b64": b64(cert),
                "cert_sig_b64": b64(sig),
            },
        )

    def certified(self, workspace: bytes, kind: str, doc: str, cert: dict[str, Any],
                  *, signer: bytes | None = None, extra: dict[str, Any] | None = None,
                  cert_bytes: bytes | None = None, **kw) -> str:
        """A control op whose payload is a signed certificate.

        Every type but rotate has this shape: a type, a link, the certificate's
        bytes and a signature over framed(<ns>/<doc>/v1, cert). Passing
        cert_bytes overrides the serialisation, which is how a test sends a
        certificate the client would never build.
        """
        raw = cert_bytes if cert_bytes is not None else json.dumps(
            cert, separators=(",", ":")).encode()
        sig = crypto.sign(signer if signer is not None else self.root,
                          wire.cert_input(self.s.namespace, doc, raw))
        payload = {
            "type": kind,
            "prev_control_hash": self.tip(workspace),
            "cert_b64": b64(raw),
            "cert_sig_b64": b64(sig),
        }
        payload.update(extra or {})
        return self.control(workspace, payload, **kw)

    def delegate(self, workspace: bytes, delegate_pk: bytes, delegation_id: str, **kw) -> str:
        return self.certified(workspace, "delegate", "delegate", {
            "workspace_id": fixtures.uuid(workspace),
            "delegation_id": delegation_id,
            "delegate_pk": b64(delegate_pk),
            "delegated_at_hlc": HLC,
        }, **kw)

    def revoke_delegation(self, workspace: bytes, delegation_id: str,
                          revocation_id: str, **kw) -> str:
        return self.certified(workspace, "revoke_delegation", "revoke-delegation", {
            "workspace_id": fixtures.uuid(workspace),
            "revocation_id": revocation_id,
            "delegation_id": delegation_id,
            "revoked_at_hlc": HLC,
        }, **kw)

    def handover(self, workspace: bytes, to_root_pk: bytes,
                 *, from_root_pk: bytes | None = None, **kw) -> str:
        return self.certified(workspace, "root_handover", "root-handover", {
            "workspace_id": fixtures.uuid(workspace),
            "from_root_pk": b64(from_root_pk if from_root_pk is not None
                                else crypto.ed25519_public(self.root)),
            "to_root_pk": b64(to_root_pk),
            "handed_over_at_hlc": HLC,
        }, **kw)

    def role_table(self, workspace: bytes, roles: list[dict[str, Any]], **kw) -> str:
        return self.certified(workspace, "role_table", "role-table", {
            "workspace_id": fixtures.uuid(workspace),
            "roles": roles,
            "adopted_at_hlc": HLC,
        }, **kw)

    def amend(self, workspace: bytes, amend_id: str, keys: dict[str, Any],
              *, member: Device | None = None, **kw) -> str:
        who = member if member is not None else self.d
        return self.certified(workspace, "member_amend", "member-amend", {
            "workspace_id": fixtures.uuid(workspace),
            "member_id": fixtures.uuid(who.member_id),
            "amend_id": amend_id,
            "keys": keys,
            "amended_at_hlc": HLC,
        }, **kw)

    def rotate(self, workspace: bytes, frm: int, to: int, digest: bytes) -> str:
        return self.control(
            workspace,
            {
                "type": "rotate",
                "prev_control_hash": self.tip(workspace),
                "workspace_id": fixtures.uuid(workspace),
                "from_epoch": frm,
                "to_epoch": to,
                "keywrap_digest_b64": b64(digest),
            },
        )

    def content(self, workspace: bytes, text: bytes = b"hello", **kw) -> str:
        return self.envelope(
            op_class=wire.CLASS_CONTENT, payload=text, workspace=workspace, **kw
        )
