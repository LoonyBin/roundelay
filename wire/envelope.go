package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The v1 envelope geometry — suites 0x00 and 0x01 share it.
//
// A suite fixes the whole geometry, not just the sealing: which signature
// algorithm closes the envelope and how many bytes it occupies. These constants
// are therefore v1's, not the protocol's, and a later suite carries its own.
const (
	HeaderLen = 158
	SigLen    = 64
	Overhead  = HeaderLen + SigLen // 222
	TagLen    = 16                 // suite 0x01 only: rides on top of the size class
)

// Header field offsets. Big-endian integers, fixed widths, no length prefixes:
// the header is constant width and the signature's length is the suite's, so
// the envelope's own length gives the body's.
const (
	offOpClass        = 0   // 1
	offSuite          = 1   // 1
	offWorkspaceID    = 2   // 16
	offKeyEpoch       = 18  // 4
	offOpID           = 22  // 16
	offAuthorMemberID = 38  // 16
	offAuthorKeyID    = 54  // 8
	offAuthorSeq      = 62  // 8
	offPrevAuthorHash = 70  // 32
	offObservedHead   = 102 // 32
	offNonce          = 134 // 24
)

// Suite bytes. An open enum, not a flag: 0x00 is a member of it — "no sealing" —
// not the absence of a value, and a future construction ships as 0x02.
const (
	SuiteNone      byte = 0x00
	SuiteEncrypted byte = 0x01
)

// Core-assigned op classes.
const (
	ClassContent    byte = 0x01
	ClassReprise    byte = 0x02
	ClassControl    byte = 0x80
	ClassPrune      byte = 0x81
	ClassExtBinding byte = 0xBF
)

// ServerReads reports bit 7 of the class byte: set, and the server unpacks the
// body; clear, and the body is bytes it has no key for, for ever.
//
// This is the single most important boundary in the system, and it is one bit
// rather than a table an editor can loosen.
func ServerReads(class byte) bool { return class&0x80 != 0 }

// IsExtension reports whether the class falls in the implementation-extension
// range 0xC0-0xFF, whose ops are signed under ExtDomain rather than DocOp.
func IsExtension(class byte) bool { return class&0xC0 == 0xC0 }

// Header is the 158 clear bytes at the front of every v1 envelope.
type Header struct {
	OpClass        byte
	Suite          byte
	WorkspaceID    [16]byte
	KeyEpoch       uint32
	OpID           [16]byte
	AuthorMemberID [16]byte
	AuthorKeyID    [8]byte
	AuthorSeq      uint64
	PrevAuthorHash [32]byte
	ObservedHead   [32]byte // reserved in v1; all-zero
	Nonce          [24]byte // all-zero when unsealed
}

// Marshal renders the header in canonical order.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderLen)
	b[offOpClass] = h.OpClass
	b[offSuite] = h.Suite
	copy(b[offWorkspaceID:], h.WorkspaceID[:])
	binary.BigEndian.PutUint32(b[offKeyEpoch:], h.KeyEpoch)
	copy(b[offOpID:], h.OpID[:])
	copy(b[offAuthorMemberID:], h.AuthorMemberID[:])
	copy(b[offAuthorKeyID:], h.AuthorKeyID[:])
	binary.BigEndian.PutUint64(b[offAuthorSeq:], h.AuthorSeq)
	copy(b[offPrevAuthorHash:], h.PrevAuthorHash[:])
	copy(b[offObservedHead:], h.ObservedHead[:])
	copy(b[offNonce:], h.Nonce[:])
	return b
}

// ErrTruncatedEnvelope reports fewer than HeaderLen bytes: no header, and so no
// envelope of any suite this implementation serves.
var ErrTruncatedEnvelope = errors.New("wire: fewer than 158 bytes, no header")

// ParseHeader reads the first HeaderLen bytes of b. It judges nothing: an
// unserved class or suite, a reserved field carrying something, and a body that
// could not fit are all the caller's verdicts to reach, under the caller's own
// codes and in the caller's own order.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrTruncatedEnvelope, len(b))
	}
	var h Header
	h.OpClass = b[offOpClass]
	h.Suite = b[offSuite]
	copy(h.WorkspaceID[:], b[offWorkspaceID:])
	h.KeyEpoch = binary.BigEndian.Uint32(b[offKeyEpoch:])
	copy(h.OpID[:], b[offOpID:])
	copy(h.AuthorMemberID[:], b[offAuthorMemberID:])
	copy(h.AuthorKeyID[:], b[offAuthorKeyID:])
	h.AuthorSeq = binary.BigEndian.Uint64(b[offAuthorSeq:])
	copy(h.PrevAuthorHash[:], b[offPrevAuthorHash:])
	copy(h.ObservedHead[:], b[offObservedHead:])
	copy(h.Nonce[:], b[offNonce:])
	return h, nil
}

// Envelope is a parsed op: a fixed header, an opaque body, a signature.
type Envelope struct {
	Header Header
	Body   []byte
	Sig    [SigLen]byte
}

// Bytes renders header || body || signature — the form that is stored, served
// back byte-identical, hashed, and signed over.
func (e Envelope) Bytes() []byte {
	out := make([]byte, 0, HeaderLen+len(e.Body)+SigLen)
	out = append(out, e.Header.Marshal()...)
	out = append(out, e.Body...)
	out = append(out, e.Sig[:]...)
	return out
}

// ErrNoBody reports an envelope with a header and a signature but nothing
// between them. It is not the length floor — that is a profile question, asked
// by Ladder — only the arithmetic below which no body exists at all.
var ErrNoBody = errors.New("wire: envelope shorter than header + signature")

// ParseEnvelope splits b under the v1 geometry. The body length is derived, not
// declared: len(b) - 222.
//
// The caller must have decided the suite is one it serves before calling this.
// Where the signature starts is not knowable without the suite, so a parse under
// the wrong geometry trusts an offset it has no basis for.
func ParseEnvelope(b []byte) (Envelope, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Envelope{}, err
	}
	if len(b) < Overhead {
		return Envelope{}, fmt.Errorf("%w: %d bytes", ErrNoBody, len(b))
	}
	e := Envelope{Header: h}
	e.Body = make([]byte, len(b)-Overhead)
	copy(e.Body, b[HeaderLen:len(b)-SigLen])
	copy(e.Sig[:], b[len(b)-SigLen:])
	return e, nil
}

// EnvelopeHash is SHA-256 over the complete envelope bytes — header || body ||
// signature, exactly as stored and served. Nothing is prefixed, appended or
// re-serialised.
//
// This is the one construction in the wire format that is not domain-framed. It
// identifies bytes; it does not authenticate them. The authentication is the
// signature inside the very bytes being hashed, already framed under its own
// signing domain, and prefixing the digest input would add nothing to it.
//
// Three things name it and all three mean this: prev_author_hash, a prune
// target's envelope_hash, and the attestation an extension owes for any op it
// hides.
func EnvelopeHash(envelope []byte) [32]byte {
	return sha256.Sum256(envelope)
}

// PayloadHash is SHA-256 over a control op's unpacked payload bytes — the input
// to the next control op's prev_control_hash.
//
// The payload, not the envelope and not a re-serialisation: a link points at
// bare bytes, which is why every control payload must be self-identifying.
func PayloadHash(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}
