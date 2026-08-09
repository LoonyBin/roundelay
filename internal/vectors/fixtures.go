// Package vectors holds the deterministic fixtures behind the frozen test
// vectors in ../../vectors.
//
// Nothing here is random. Every byte of key material is SHA-256 over
// "roundelay/vectors/v1/" concatenated with a label, so the whole corpus is
// reproducible from the labels alone — which is the property that lets a second
// implementation regenerate it independently and compare, instead of taking this
// one's word for the values.
package vectors

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/loonybin/roundelay/wire"
)

// SeedPrefix is the domain the fixture derivation runs under. It is deliberately
// not one of the protocol's own domains: these are test keys, and nothing here
// may collide with a construction the specification reaches.
const SeedPrefix = "roundelay/vectors/v1/"

// The profile constants the corpus is generated against. They are acme/p1's —
// the fictional minimal profile of the profile-obligations document.
const (
	Namespace = "acme"
	ExtName   = "retention-sweep"
)

// Ladder is acme/p1's row 7: classes 512 and 4096, oversize step 4096.
var Ladder = wire.Ladder{Classes: []int{512, 4096}, Step: 4096}

// Key labels.
const (
	LabelRoot           = "root"
	LabelDeviceAControl = "device-a/control"
	LabelDeviceAContent = "device-a/content"
	LabelDeviceAKex     = "device-a/kex"
	LabelDeviceBControl = "device-b/control"
	LabelDeviceBContent = "device-b/content"
	LabelDeviceBKex     = "device-b/kex"
)

// Seed derives 32 deterministic bytes for a label.
func Seed(label string) [32]byte {
	return sha256.Sum256([]byte(SeedPrefix + label))
}

// Bytes32 is Seed under a friendlier name, for values that are not keys.
func Bytes32(label string) [32]byte { return Seed(label) }

// Bytes16 is the first 16 bytes of Seed — ids are 16 bytes throughout.
func Bytes16(label string) [16]byte {
	s := Seed(label)
	var out [16]byte
	copy(out[:], s[:16])
	return out
}

// Nonce is the first 24 bytes of Seed, the XChaCha20-Poly1305 nonce width.
func Nonce(label string) [24]byte {
	s := Seed(label)
	var out [24]byte
	copy(out[:], s[:24])
	return out
}

// SignPriv derives an Ed25519 key from a label. The seed is the private key
// seed, so ed25519.NewKeyFromSeed is the whole derivation.
func SignPriv(label string) ed25519.PrivateKey {
	s := Seed(label)
	return ed25519.NewKeyFromSeed(s[:])
}

// SignPub is SignPriv's public half.
func SignPub(label string) ed25519.PublicKey {
	return SignPriv(label).Public().(ed25519.PublicKey)
}

// KexPriv derives an X25519 key from a label. The seed is used as the scalar
// directly; RFC 7748 clamping happens inside the curve implementation.
func KexPriv(label string) *ecdh.PrivateKey {
	s := Seed(label)
	k, err := ecdh.X25519().NewPrivateKey(s[:])
	if err != nil {
		panic(fmt.Sprintf("vectors: x25519 key for %q: %v", label, err))
	}
	return k
}

// KexPub is KexPriv's 32-byte public half.
func KexPub(label string) []byte { return KexPriv(label).PublicKey().Bytes() }

// Fixed ids and keys used across the corpus.
var (
	WorkspaceID   = Bytes16("workspace/1")
	MemberA       = Bytes16("member/a")
	MemberB       = Bytes16("member/b")
	ContentKey    = Bytes32("epoch/3/content-key")
	MasterWrapKey = Bytes32("master-wrap-key")

	ZeroHash  [32]byte
	ZeroNonce [24]byte
)

// PrevHash stands in for an earlier envelope's hash. It is not the hash of any
// envelope in the corpus — the chain link's own construction is covered by the
// envelope_hash vectors, and a fixture that pretended otherwise would make these
// files order-dependent for no gain.
func PrevHash(label string) [32]byte { return Seed("prev-author-hash/" + label) }

// Filler builds a reproducible payload of n bytes: byte i is i mod 251.
//
// 251 rather than 256 so that the pattern does not align with any power of two —
// a payload whose period divides a size class would hide an off-by-one in the
// padding.
func Filler(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// UUID renders 16 raw bytes as a canonical lowercase 8-4-4-4-12 UUID: no braces,
// no urn:uuid: prefix, no uppercase, no missing dashes.
func UUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Header builds a v1 header for the corpus. op_id is derived from the author
// sequence so that each op in a chain has a distinct, reproducible id.
func Header(class, suite byte, keyEpoch uint32, authorSeq uint64, prevAuthorHash [32]byte, nonce [24]byte, signLabel string) wire.Header {
	return wire.Header{
		OpClass:        class,
		Suite:          suite,
		WorkspaceID:    WorkspaceID,
		KeyEpoch:       keyEpoch,
		OpID:           Bytes16(fmt.Sprintf("op/%d", authorSeq)),
		AuthorMemberID: MemberA,
		AuthorKeyID:    wire.KeyID(SignPub(signLabel)),
		AuthorSeq:      authorSeq,
		PrevAuthorHash: prevAuthorHash,
		Nonce:          nonce,
	}
}

// OrderingEntry is one row of the digest-ordering fixture below.
type OrderingEntry struct {
	Label    string
	MemberID [16]byte
	KexKeyID [wire.KeyIDLen]byte
	Wrap     []byte
}

// OrderingSet is a wrap set built to be diagnostic about the digest's sort key,
// which the ordinary device fixtures are not: their derived ids happen to sort
// the same way under every candidate comparison.
//
// The ids here are literal and chosen so that the raw-unsigned-bytes ordering
// the specification fixes disagrees with all three orderings an implementation
// might reach for by accident:
//
//	raw unsigned bytes   m1/k1, m1/k2, m2/k1   ← the only correct one
//	base64 spelling      m2/k1, m1/k2, m1/k1
//	signed 64-bit halves m2/k1, m1/k1, m1/k2
//
// 0x00 base64-encodes to a leading 'A' (0x41) and 0xd0 to a leading '0' (0x30),
// so base64 inverts the pair; 0xd0 sets the top bit, so a platform UUID type
// comparing two signed 64-bit halves inverts it too.
//
// The wraps are filler of the right length rather than real seals. The digest
// hashes each wrap and never opens one, so what is under test here is the
// ordering and nothing else.
var OrderingSet = []OrderingEntry{
	{
		Label:    "m1/k1",
		MemberID: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		KexKeyID: [8]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Wrap:     repeat(0x01, wire.MemberWrapLen),
	},
	{
		Label:    "m1/k2",
		MemberID: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		KexKeyID: [8]byte{0xd0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Wrap:     repeat(0x02, wire.MemberWrapLen),
	},
	{
		Label:    "m2/k1",
		MemberID: [16]byte{0xd0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		KexKeyID: [8]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Wrap:     repeat(0x03, wire.MemberWrapLen),
	},
}

// OrderingEscrow is the escrow wrap the ordering fixture commits to. Filler, for
// the same reason the wraps are.
var OrderingEscrow = repeat(0xee, wire.EscrowWrapLen)

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// ControlPayload is a grant control op's payload, as literal bytes. The wire
// package treats it as opaque; it is here so that the prev_control_hash vector
// has something real to hash.
const ControlPayload = `{"type":"grant","prev_control_hash":"0000000000000000000000000000000000000000000000000000000000000000","cert_b64":"","cert_sig_b64":""}`

// GrantCert is a grant certificate's literal bytes, including its exact
// whitespace. A certificate is signed bytes, never re-serialised JSON, so the
// spacing here is load-bearing: re-encode it and the signature stops verifying.
const GrantCert = `{"workspace_id":"00000000-0000-0000-0000-000000000000","grant_id":"11111111-1111-1111-1111-111111111111","member_id":"22222222-2222-2222-2222-222222222222","role":"owner","granter":"root","granted_at_hlc":[1700000000000,0,"00000000000000000000000000000000"]}`
