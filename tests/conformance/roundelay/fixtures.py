"""The same deterministic fixtures the frozen vectors are built from.

Every byte of key material is SHA-256 over ``roundelay/vectors/v1/`` and a
label, which is what lets this suite regenerate the corpus from the labels
alone and compare, rather than taking the Go implementation's word for it.
"""

from __future__ import annotations

import base64

import hashlib

SEED_PREFIX = "roundelay/vectors/v1/"

NAMESPACE = "acme"
EXT_NAME = "retention-sweep"

LABEL_ROOT = "root"
LABEL_DEVICE_A_CONTROL = "device-a/control"
LABEL_DEVICE_A_CONTENT = "device-a/content"
LABEL_DEVICE_A_KEX = "device-a/kex"
LABEL_DEVICE_B_KEX = "device-b/kex"


def seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def bytes16(label: str) -> bytes:
    return seed(label)[:16]


def nonce(label: str) -> bytes:
    return seed(label)[:24]


def filler(n: int) -> bytes:
    """Byte i is ``i mod 251``.

    251 rather than 256 so the pattern never aligns with a size class and hides
    an off-by-one in the padding.
    """
    return bytes(i % 251 for i in range(n))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def uuid(raw: bytes) -> str:
    """Canonical lowercase 8-4-4-4-12: no braces, no prefix, no uppercase."""
    h = raw.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def parse_uuid(text: str) -> bytes:
    return bytes.fromhex(text.replace("-", ""))


WORKSPACE_ID = bytes16("workspace/1")
MEMBER_A = bytes16("member/a")
MEMBER_B = bytes16("member/b")
CONTENT_KEY = seed("epoch/3/content-key")
MASTER_WRAP_KEY = seed("master-wrap-key")
