"""The protocol's cryptographic constructions, implemented independently.

This is deliberately a second implementation rather than a binding to the Go
one. A suite that shared the server's codec could not catch a framing bug: the
error would cancel out on both sides and every test would pass. What proves
anything is two implementations, written from the specification, agreeing on the
frozen vectors — which ``test_vectors.py`` checks before any other test runs.

``cryptography`` has no XChaCha20-Poly1305, so HChaCha20 is built here from the
ChaCha20 core. That is a cost and also the point: the construction is derived
from RFC 8439's quarter-round rather than taken on trust from a library that
might disagree with the server's.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── the framing rule ────────────────────────────────────────────────────────


def framed(domain: str, *parts: bytes) -> bytes:
    """``[1 byte: len(domain)] [domain] [rest]``.

    The length prefix is what makes the construction injective. Plain
    concatenation is not: with a varying namespace, ``acme`` + ``/op/v1`` and
    ``acme/op`` + ``/v1`` are the same bytes.
    """
    raw = domain.encode()
    if not 1 <= len(raw) <= 255:
        raise ValueError(f"domain must be 1-255 bytes, got {len(raw)}")
    return bytes([len(raw)]) + raw + b"".join(parts)


def envelope_hash(envelope: bytes) -> bytes:
    """SHA-256 over the complete envelope bytes, unframed.

    The one construction in the wire format that is not domain-framed: it
    identifies bytes, it does not authenticate them.
    """
    return hashlib.sha256(envelope).digest()


def payload_hash(payload: bytes) -> bytes:
    """Bare SHA-256 over a control op's unpacked payload bytes."""
    return hashlib.sha256(payload).digest()


def key_id(public_key: bytes) -> bytes:
    """The first 8 bytes of SHA-256 over a public key."""
    return hashlib.sha256(public_key).digest()[:8]


# ── XChaCha20-Poly1305, from the ChaCha20 core ──────────────────────────────

_SIGMA = b"expand 32-byte k"


def _rotl32(v: int, n: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20: twenty rounds, and the first and last four words out.

    Unlike ChaCha20 proper there is no feed-forward addition of the initial
    state — which is the whole difference, and the thing an implementation gets
    wrong.
    """
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("hchacha20 takes a 32-byte key and a 16-byte nonce")
    state = list(struct.unpack("<4I", _SIGMA))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))

    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    return struct.pack("<8I", *(state[0:4] + state[12:16]))


def _xchacha(key: bytes, nonce24: bytes) -> tuple[ChaCha20Poly1305, bytes]:
    if len(nonce24) != 24:
        raise ValueError("XChaCha20-Poly1305 takes a 24-byte nonce")
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey), b"\x00\x00\x00\x00" + nonce24[16:]


def xchacha_seal(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    aead, inner = _xchacha(key, nonce24)
    return aead.encrypt(inner, plaintext, aad)


def xchacha_open(key: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    aead, inner = _xchacha(key, nonce24)
    return aead.decrypt(inner, ciphertext, aad)


# ── signatures ──────────────────────────────────────────────────────────────


def sign(private_seed: bytes, message: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_seed).sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except Exception:
        return False
    return True


def ed25519_public(private_seed: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(private_seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def x25519_public(scalar: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return (
        x25519.X25519PrivateKey.from_private_bytes(scalar)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def x25519_shared(scalar: bytes, peer_public: bytes) -> bytes:
    return x25519.X25519PrivateKey.from_private_bytes(scalar).exchange(
        x25519.X25519PublicKey.from_public_bytes(peer_public)
    )


# ── the key plane ───────────────────────────────────────────────────────────

# RFC 5869's default salt: 32 zero bytes, not a zero-length key.
#
# A real fork point. HMAC pads a short key with zeros, so an empty salt and 32
# zero bytes happen to agree here — but a library that rejects an empty salt, or
# substitutes a different default, produces something else, and nothing in the
# ciphertext says which happened.
HKDF_SALT = bytes(32)


def member_wrap(
    namespace: str,
    workspace_id: bytes,
    epoch: int,
    member_id: bytes,
    kex_key_id: bytes,
    kex_public: bytes,
    ephemeral_scalar: bytes,
    nonce24: bytes,
    content_key: bytes,
) -> bytes:
    """The 104-byte member wrap: ``epk || nonce || XChaCha20-Poly1305(K)``."""
    epk = x25519_public(ephemeral_scalar)
    info = framed(
        f"{namespace}/keywrap/v1",
        epk,
        workspace_id,
        struct.pack(">I", epoch),
        member_id,
        kex_key_id,
    )
    shared = x25519_shared(ephemeral_scalar, kex_public)
    key = HKDF(algorithm=SHA256(), length=32, salt=HKDF_SALT, info=info).derive(shared)
    return epk + nonce24 + xchacha_seal(key, nonce24, content_key, info)


def escrow_info(namespace: str, workspace_id: bytes, epoch: int) -> bytes:
    return framed(
        f"{namespace}/epoch-key-escrow/v1", workspace_id, struct.pack(">I", epoch)
    )


def escrow_wrap(
    namespace: str,
    workspace_id: bytes,
    epoch: int,
    master_wrap_key: bytes,
    nonce24: bytes,
    content_key: bytes,
) -> bytes:
    """The 72-byte escrow wrap: ``nonce || XChaCha20-Poly1305(K)``."""
    info = escrow_info(namespace, workspace_id, epoch)
    return nonce24 + xchacha_seal(master_wrap_key, nonce24, content_key, info)


def keywrap_digest(
    namespace: str,
    epoch: int,
    entries: list[tuple[bytes, bytes, bytes]],
    escrow: bytes,
) -> bytes:
    """The commitment a rotate carries.

    Sorted by the raw 16-byte member id then the raw 8-byte key id, compared as
    unsigned bytes — not the UUID text, and emphatically not the base64
    spelling, whose alphabet is not monotonic in byte value.
    """
    ordered = sorted(entries, key=lambda e: (e[0], e[1]))
    seen = set()
    for member_id, kid, _ in ordered:
        if (member_id, kid) in seen:
            raise ValueError("duplicate (member_id, kex_key_id) in wrap set")
        seen.add((member_id, kid))

    rest = struct.pack(">II", epoch, len(ordered))
    for member_id, kid, wrap in ordered:
        rest += member_id + kid + hashlib.sha256(wrap).digest()
    rest += hashlib.sha256(escrow).digest()
    return hashlib.sha256(framed(f"{namespace}/keywrap-digest/v1", rest)).digest()
