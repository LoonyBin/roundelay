package wire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
)

// Fixed sizes for the v1 constructions. No deployment tunes one and no request
// negotiates one; a different construction ships under a new signing domain.
const (
	ContentKeyLen  = 32
	NonceLen       = chacha20poly1305.NonceSizeX // 24
	EphemeralPKLen = 32
	MemberWrapLen  = EphemeralPKLen + NonceLen + ContentKeyLen + TagLen // 104
	EscrowWrapLen  = NonceLen + ContentKeyLen + TagLen                  // 72
	DigestLen      = 32
)

// hkdfSalt is RFC 5869's default salt: 32 zero bytes, not a zero-length key.
//
// A real fork point, which is why it is a named constant rather than a nil
// argument. HMAC pads a short key with zeros, so an empty salt and 32 zero bytes
// happen to produce the same result here — but a library that rejects an empty
// salt, or substitutes a different default, produces a different one, and
// nothing in the ciphertext says which happened.
var hkdfSalt = make([]byte, 32)

// MemberWrapParams identifies the one slot a member wrap is bound to.
//
// Every field is inside the derivation info, which is also the associated data,
// so a mismatch on any of them is an authentication failure rather than a silent
// decryption to garbage.
type MemberWrapParams struct {
	Namespace   Namespace
	WorkspaceID [16]byte
	Epoch       uint32
	MemberID    [16]byte
	KexKeyID    [KeyIDLen]byte
	KexPub      []byte // the recipient device's 32-byte X25519 public key
}

// info builds the shared derivation info and associated data. epk is the
// ephemeral public key the wrap carries.
func (p MemberWrapParams) info(epk []byte) []byte {
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], p.Epoch)
	return Framed(p.Namespace.V1(DocKeywrap),
		epk, p.WorkspaceID[:], epoch[:], p.MemberID[:], p.KexKeyID[:])
}

// SealMemberWrap produces the 104-byte member wrap for one device, using the
// supplied ephemeral key and nonce.
//
// The explicit ephemeral and nonce are what make the construction testable: a
// frozen vector needs both pinned. NewMemberWrap generates them.
func SealMemberWrap(p MemberWrapParams, eph *ecdh.PrivateKey, nonce [NonceLen]byte, contentKey [ContentKeyLen]byte) ([]byte, error) {
	recipient, err := ecdh.X25519().NewPublicKey(p.KexPub)
	if err != nil {
		return nil, fmt.Errorf("wire: member wrap recipient key: %w", err)
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("wire: member wrap X25519: %w", err)
	}
	epk := eph.PublicKey().Bytes()
	info := p.info(epk)

	key, err := hkdf.Key(sha256.New, shared, hkdfSalt, string(info), ContentKeyLen)
	if err != nil {
		return nil, fmt.Errorf("wire: member wrap HKDF: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, MemberWrapLen)
	out = append(out, epk...)
	out = append(out, nonce[:]...)
	out = aead.Seal(out, nonce[:], contentKey[:], info)
	if len(out) != MemberWrapLen {
		return nil, fmt.Errorf("wire: member wrap is %d bytes, want %d", len(out), MemberWrapLen)
	}
	return out, nil
}

// NewMemberWrap seals a member wrap with a fresh ephemeral key and nonce.
func NewMemberWrap(rnd io.Reader, p MemberWrapParams, contentKey [ContentKeyLen]byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	var nonce [NonceLen]byte
	if _, err := io.ReadFull(rnd, nonce[:]); err != nil {
		return nil, err
	}
	return SealMemberWrap(p, eph, nonce, contentKey)
}

// ErrMalformedWrap reports a wrap of the wrong length.
var ErrMalformedWrap = errors.New("wire: wrap is not the length its construction fixes")

// OpenMemberWrap recovers the content key from a member wrap.
//
// The kex key id is inside the associated data, so a wrap minted before a kex
// amend opens under the retired sealing key and under nothing else. A device
// must therefore retain every sealing private key it has ever held, not merely
// its current one: the epochs a retired key was the key for have no other route.
func OpenMemberWrap(p MemberWrapParams, kexPriv *ecdh.PrivateKey, wrap []byte) ([ContentKeyLen]byte, error) {
	var out [ContentKeyLen]byte
	if len(wrap) != MemberWrapLen {
		return out, fmt.Errorf("%w: member wrap is %d bytes, want %d", ErrMalformedWrap, len(wrap), MemberWrapLen)
	}
	epk := wrap[:EphemeralPKLen]
	nonce := wrap[EphemeralPKLen : EphemeralPKLen+NonceLen]
	ct := wrap[EphemeralPKLen+NonceLen:]

	ephPub, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return out, fmt.Errorf("wire: member wrap ephemeral key: %w", err)
	}
	shared, err := kexPriv.ECDH(ephPub)
	if err != nil {
		return out, fmt.Errorf("wire: member wrap X25519: %w", err)
	}
	info := p.info(epk)

	key, err := hkdf.Key(sha256.New, shared, hkdfSalt, string(info), ContentKeyLen)
	if err != nil {
		return out, fmt.Errorf("wire: member wrap HKDF: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return out, err
	}
	pt, err := aead.Open(nil, nonce, ct, info)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	copy(out[:], pt)
	return out, nil
}

// EscrowInfo is the associated data of an epoch's escrow wrap:
// framed("<ns>/epoch-key-escrow/v1", workspace_id || epoch).
func EscrowInfo(ns Namespace, workspaceID [16]byte, epoch uint32) []byte {
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	return Framed(ns.V1(DocEpochKeyEscrow), workspaceID[:], e[:])
}

// SealEscrowWrap produces the 72-byte escrow wrap for one epoch.
//
// masterWrapKey must be the founding identity's, and no other. No server can
// check this: the digest commits to whatever was sealed, and 72 bytes sealed
// under the wrong key hash exactly as well as 72 sealed under the right one. A
// wrap minted under a key a client invented is accepted, committed and served
// back, and the mistake surfaces months later at the one moment the escrow
// existed for.
func SealEscrowWrap(ns Namespace, workspaceID [16]byte, epoch uint32, masterWrapKey [32]byte, nonce [NonceLen]byte, contentKey [ContentKeyLen]byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterWrapKey[:])
	if err != nil {
		return nil, err
	}
	info := EscrowInfo(ns, workspaceID, epoch)
	out := make([]byte, 0, EscrowWrapLen)
	out = append(out, nonce[:]...)
	out = aead.Seal(out, nonce[:], contentKey[:], info)
	if len(out) != EscrowWrapLen {
		return nil, fmt.Errorf("wire: escrow wrap is %d bytes, want %d", len(out), EscrowWrapLen)
	}
	return out, nil
}

// NewEscrowWrap seals an escrow wrap with a fresh nonce.
func NewEscrowWrap(rnd io.Reader, ns Namespace, workspaceID [16]byte, epoch uint32, masterWrapKey [32]byte, contentKey [ContentKeyLen]byte) ([]byte, error) {
	var nonce [NonceLen]byte
	if _, err := io.ReadFull(rnd, nonce[:]); err != nil {
		return nil, err
	}
	return SealEscrowWrap(ns, workspaceID, epoch, masterWrapKey, nonce, contentKey)
}

// OpenEscrowWrap recovers an epoch key from its escrow wrap. This is the
// recovery route: one master wrap key opens every epoch's escrow wrap, past and
// present, which is what lets a fresh device work with no other device online.
func OpenEscrowWrap(ns Namespace, workspaceID [16]byte, epoch uint32, masterWrapKey [32]byte, wrap []byte) ([ContentKeyLen]byte, error) {
	var out [ContentKeyLen]byte
	if len(wrap) != EscrowWrapLen {
		return out, fmt.Errorf("%w: escrow wrap is %d bytes, want %d", ErrMalformedWrap, len(wrap), EscrowWrapLen)
	}
	aead, err := chacha20poly1305.NewX(masterWrapKey[:])
	if err != nil {
		return out, err
	}
	pt, err := aead.Open(nil, wrap[:NonceLen], wrap[NonceLen:], EscrowInfo(ns, workspaceID, epoch))
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	copy(out[:], pt)
	return out, nil
}

// WrapEntry is one member's wrap within an epoch's published set.
type WrapEntry struct {
	MemberID [16]byte
	KexKeyID [KeyIDLen]byte
	Wrap     []byte
}

// ErrDuplicateWrapEntry reports two wraps for one (member, kex key) in one set.
// The digest sorts by that pair, so a duplicate would make the commitment depend
// on which copy the server happened to keep.
var ErrDuplicateWrapEntry = errors.New("wire: duplicate (member_id, kex_key_id) in wrap set")

// KeywrapDigest computes the commitment an epoch's rotate op carries, and that
// PUT .../keywraps is held to.
//
// This is what stops the server curating the set: the digest is signed into the
// log before any wrap is uploaded, so the server checking it is holding itself
// to somebody else's signed word rather than enforcing a policy of its own.
//
// The sort key is the raw 16-byte member id, then the raw 8-byte key id,
// compared as unsigned bytes — not the UUID text, and emphatically not the
// base64 spelling, whose alphabet is not monotonic in byte value. Getting it
// wrong yields a deterministic keywrap_digest_mismatch, which a well-behaved
// client terminalises, leaving the Workspace permanently unrotatable.
//
// Sorted at all so that the digest describes the set, not the upload order the
// server could shuffle.
func KeywrapDigest(ns Namespace, epoch uint32, entries []WrapEntry, escrowWrap []byte) ([DigestLen]byte, error) {
	var zero [DigestLen]byte

	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b WrapEntry) int {
		if c := bytes.Compare(a.MemberID[:], b.MemberID[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.KexKeyID[:], b.KexKeyID[:])
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].MemberID == sorted[i].MemberID && sorted[i-1].KexKeyID == sorted[i].KexKeyID {
			return zero, fmt.Errorf("%w: member %x", ErrDuplicateWrapEntry, sorted[i].MemberID)
		}
	}

	var epochBE, countBE [4]byte
	binary.BigEndian.PutUint32(epochBE[:], epoch)
	binary.BigEndian.PutUint32(countBE[:], uint32(len(sorted)))

	parts := make([][]byte, 0, 2+3*len(sorted)+1)
	parts = append(parts, epochBE[:], countBE[:])
	for _, e := range sorted {
		h := sha256.Sum256(e.Wrap)
		parts = append(parts, e.MemberID[:], e.KexKeyID[:], append([]byte(nil), h[:]...))
	}
	eh := sha256.Sum256(escrowWrap)
	parts = append(parts, eh[:])

	return sha256.Sum256(Framed(ns.V1(DocKeywrapDigest), parts...)), nil
}
