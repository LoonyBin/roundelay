"""The v1 envelope, body framing and padding ladder.

Written from the specification rather than ported, for the reason
``crypto.py`` gives.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import crypto

HEADER_LEN = 158
SIG_LEN = 64
OVERHEAD = HEADER_LEN + SIG_LEN
TAG_LEN = 16
PAYLOAD_LEN_PREFIX = 4

SUITE_NONE = 0x00
SUITE_ENCRYPTED = 0x01

CLASS_CONTENT = 0x01
CLASS_REPRISE = 0x02
CLASS_CONTROL = 0x80
CLASS_PRUNE = 0x81
CLASS_EXT_BINDING = 0xBF


def server_reads(op_class: int) -> bool:
    """Bit 7: set, and the server unpacks the body."""
    return bool(op_class & 0x80)


def is_extension(op_class: int) -> bool:
    return op_class & 0xC0 == 0xC0


@dataclass
class Ladder:
    """The profile's body size classes and oversize step."""

    classes: list[int] = field(default_factory=lambda: [512, 4096])
    step: int = 4096

    def body_len(self, payload_len: int) -> int:
        required = PAYLOAD_LEN_PREFIX + payload_len
        for c in self.classes:
            if required <= c:
                return c
        # Above the largest class, to the next multiple of the step. The other
        # available reading — the largest class plus a multiple — agrees exactly
        # when the largest class is a multiple of the step, which acme/p1's is.
        return ((required + self.step - 1) // self.step) * self.step

    def legal_body_len(self, n: int) -> bool:
        if n in self.classes:
            return True
        return n > self.classes[-1] and n % self.step == 0

    def min_envelope_len(self, suite: int) -> int:
        n = HEADER_LEN + self.classes[0] + SIG_LEN
        return n + TAG_LEN if suite == SUITE_ENCRYPTED else n

    def pack_body(self, payload: bytes) -> bytes:
        n = self.body_len(len(payload))
        return struct.pack(">I", len(payload)) + payload + bytes(n - PAYLOAD_LEN_PREFIX - len(payload))

    def unpack_body(self, body: bytes) -> bytes:
        if not self.legal_body_len(len(body)):
            raise ValueError(f"body length {len(body)} is not a legal size class")
        (n,) = struct.unpack(">I", body[:PAYLOAD_LEN_PREFIX])
        if n > len(body) - PAYLOAD_LEN_PREFIX:
            raise ValueError("payload_len overruns the body")
        payload = body[PAYLOAD_LEN_PREFIX : PAYLOAD_LEN_PREFIX + n]
        if any(body[PAYLOAD_LEN_PREFIX + n :]):
            raise ValueError("padding is not all zero")
        return payload


@dataclass
class Header:
    op_class: int
    suite: int = SUITE_NONE
    workspace_id: bytes = bytes(16)
    key_epoch: int = 0
    op_id: bytes = bytes(16)
    author_member_id: bytes = bytes(16)
    author_key_id: bytes = bytes(8)
    author_seq: int = 1
    prev_author_hash: bytes = bytes(32)
    observed_head: bytes = bytes(32)
    nonce: bytes = bytes(24)

    def marshal(self) -> bytes:
        """Canonical order, fixed widths, big-endian integers."""
        out = (
            bytes([self.op_class, self.suite])
            + self.workspace_id
            + struct.pack(">I", self.key_epoch)
            + self.op_id
            + self.author_member_id
            + self.author_key_id
            + struct.pack(">Q", self.author_seq)
            + self.prev_author_hash
            + self.observed_head
            + self.nonce
        )
        assert len(out) == HEADER_LEN, len(out)
        return out

    @classmethod
    def parse(cls, raw: bytes) -> "Header":
        if len(raw) < HEADER_LEN:
            raise ValueError("fewer than 158 bytes, no header")
        return cls(
            op_class=raw[0],
            suite=raw[1],
            workspace_id=raw[2:18],
            key_epoch=struct.unpack(">I", raw[18:22])[0],
            op_id=raw[22:38],
            author_member_id=raw[38:54],
            author_key_id=raw[54:62],
            author_seq=struct.unpack(">Q", raw[62:70])[0],
            prev_author_hash=raw[70:102],
            observed_head=raw[102:134],
            nonce=raw[134:158],
        )


def op_domain(namespace: str, op_class: int, ext_name: str = "") -> str:
    """Every class below 0xC0 signs under ``<ns>/op/v1``.

    An extension class signs under ``<ns>/ext/<name>/v1`` instead, so a client
    built against one NAME cannot verify an op written under another.
    """
    if is_extension(op_class):
        return f"{namespace}/ext/{ext_name}/v1"
    return f"{namespace}/op/v1"


def sign_op(seed: bytes, domain: str, header: bytes, body: bytes) -> bytes:
    """Header, body, and a signature over ``framed(domain, header || body)``.

    Under suite 0x01 the signature covers the *sealed* body.
    """
    sig = crypto.sign(seed, crypto.framed(domain, header, body))
    return header + body + sig


def parse_envelope(raw: bytes) -> tuple[Header, bytes, bytes]:
    """Split under the v1 geometry. The body length is derived, not declared."""
    if len(raw) < OVERHEAD:
        raise ValueError("shorter than header + signature")
    return Header.parse(raw), raw[HEADER_LEN : len(raw) - SIG_LEN], raw[len(raw) - SIG_LEN :]


def auth_challenge_input(namespace: str, member_id: bytes, nonce: bytes) -> bytes:
    """``framed(<ns>/auth-challenge/v1, member_id || nonce)``.

    ``member_id`` is the 16 raw bytes, never a textual spelling.
    """
    return crypto.framed(f"{namespace}/auth-challenge/v1", member_id, nonce)


def vault_input(namespace: str, locator: bytes, version: int, blob: bytes) -> bytes:
    """``framed(<ns>/vault/v1, locator || version || blob)``."""
    return crypto.framed(
        f"{namespace}/vault/v1", locator, struct.pack(">Q", version), blob
    )


def cert_input(namespace: str, document: str, cert: bytes) -> bytes:
    """``framed(<ns>/<document>/v1, the literal certificate bytes)``.

    Never a re-serialisation: a verifier that re-encodes what it parsed is
    verifying a document nobody signed.
    """
    return crypto.framed(f"{namespace}/{document}/v1", cert)
