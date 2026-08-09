package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PayloadLenPrefix is the width of the body's leading length field: an unsigned
// 32-bit big-endian integer.
const PayloadLenPrefix = 4

// Ladder is the profile's body size classes and oversize step — row 7 of the
// profile obligations.
//
// Padding is a confidentiality mechanism, not a bandwidth one. Without it, body
// length leaks how much was written, so a coarse ladder is the padding working:
// each extra size class hands an observer one more bit about payload size.
//
// Row 7 has no additive direction. Every op already in a log was signed padded
// to the ladder in force when it was written, so changing the ladder — adding a
// class included — leaves those ops at a length no reader will accept.
type Ladder struct {
	Classes []int // ascending positive integers
	Step    int   // positive; the oversize step above the largest class
}

var (
	ErrEmptyLadder     = errors.New("wire: ladder has no size classes")
	ErrLadderNotSorted = errors.New("wire: ladder classes must be strictly ascending positive integers")
	ErrLadderStep      = errors.New("wire: ladder oversize step must be a positive integer")
)

// Validate checks the shape row 7 requires. A server refuses to start without a
// ladder, and there is no default: a guessed one is a convergence bug that
// surfaces as every peer refusing every op.
func (l Ladder) Validate() error {
	if len(l.Classes) == 0 {
		return ErrEmptyLadder
	}
	prev := 0
	for _, c := range l.Classes {
		if c <= prev {
			return fmt.Errorf("%w: %v", ErrLadderNotSorted, l.Classes)
		}
		prev = c
	}
	if l.Step <= 0 {
		return fmt.Errorf("%w: %d", ErrLadderStep, l.Step)
	}
	return nil
}

// Largest is the top size class.
func (l Ladder) Largest() int { return l.Classes[len(l.Classes)-1] }

// Smallest is the bottom size class, and so the body length in the envelope
// length floor.
func (l Ladder) Smallest() int { return l.Classes[0] }

// AmbiguousOversize reports whether this ladder distinguishes the two readings
// of "above the largest, to the next multiple of a fixed step".
//
// This package takes the plain reading: a multiple of the step, counted from
// zero. The other available reading — the largest class plus a multiple of the
// step — agrees with it exactly when the largest class is itself a multiple of
// the step, and disagrees otherwise. A ladder for which this returns true is one
// where two conforming implementations can pad the same payload to different
// lengths, and every op either of them writes is illegal to the other.
//
// The core does not forbid such a ladder. A profile should not choose one.
func (l Ladder) AmbiguousOversize() bool { return l.Largest()%l.Step != 0 }

// BodyLen returns the padded body length for a payload of payloadLen bytes:
// the smallest size class that fits payload_len plus the payload, or, above the
// largest class, the next multiple of the step.
//
// This is the plaintext body length. Under suite 0x01 the body on the wire is
// TagLen bytes longer.
func (l Ladder) BodyLen(payloadLen int) (int, error) {
	if payloadLen < 0 {
		return 0, fmt.Errorf("wire: negative payload length %d", payloadLen)
	}
	required := PayloadLenPrefix + payloadLen
	for _, c := range l.Classes {
		if required <= c {
			return c, nil
		}
	}
	n := ((required + l.Step - 1) / l.Step) * l.Step
	return n, nil
}

// LegalBodyLen reports whether n is a length a plaintext body may have: a size
// class, or a multiple of the step above the largest class.
//
// A multiple of the step that falls at or below the largest class is not legal.
// A payload that would fit there pads to a class instead, so accepting it would
// admit two spellings of one length.
func (l Ladder) LegalBodyLen(n int) bool {
	for _, c := range l.Classes {
		if n == c {
			return true
		}
	}
	return n > l.Largest() && n%l.Step == 0
}

// MinEnvelopeLen is the length floor for the given suite: header + the smallest
// size class + signature, and TagLen higher under suite 0x01, because a sealed
// body carries the authentication tag on top of the size class it padded to.
//
// The floor reads no body byte. Suite is a header field and the classes are the
// profile's, so both floors are known before the body is looked at — which is
// what keeps a length rule out of the range of things the server unpacks.
func (l Ladder) MinEnvelopeLen(suite byte) int {
	n := HeaderLen + l.Smallest() + SigLen
	if suite == SuiteEncrypted {
		n += TagLen
	}
	return n
}

// PackBody frames and pads a payload: payload_len, payload, zero padding to a
// size class. The result is the plaintext body, which suite 0x00 carries
// verbatim and suite 0x01 seals.
func (l Ladder) PackBody(payload []byte) ([]byte, error) {
	if uint64(len(payload)) > 0xFFFFFFFF {
		return nil, fmt.Errorf("wire: payload of %d bytes overruns the u32 length prefix", len(payload))
	}
	n, err := l.BodyLen(len(payload))
	if err != nil {
		return nil, err
	}
	body := make([]byte, n)
	binary.BigEndian.PutUint32(body, uint32(len(payload)))
	copy(body[PayloadLenPrefix:], payload)
	return body, nil
}

// The three rules that bind anyone who unpacks a body. The server enforces them
// on a class with bit 7 set; a client enforces them on every body it unpacks, on
// the decrypted plaintext when the op is sealed.
var (
	ErrInvalidBodyLength   = errors.New("wire: body length is not a legal size class")
	ErrPayloadOverrunsBody = errors.New("wire: payload_len overruns the body")
	ErrNonZeroPadding      = errors.New("wire: padding is not all zero")
)

// UnpackBody validates the three rules and returns the payload. It does not copy:
// the result aliases body.
func (l Ladder) UnpackBody(body []byte) ([]byte, error) {
	if !l.LegalBodyLen(len(body)) {
		return nil, fmt.Errorf("%w: %d", ErrInvalidBodyLength, len(body))
	}
	// len(body) is a legal class, so it is at least PayloadLenPrefix wide for any
	// ladder whose smallest class admits an empty payload; a ladder that does not
	// is refused here rather than indexed past.
	if len(body) < PayloadLenPrefix {
		return nil, fmt.Errorf("%w: %d", ErrInvalidBodyLength, len(body))
	}
	n := binary.BigEndian.Uint32(body)
	if uint64(n) > uint64(len(body)-PayloadLenPrefix) {
		return nil, fmt.Errorf("%w: payload_len %d, body %d", ErrPayloadOverrunsBody, n, len(body))
	}
	payload := body[PayloadLenPrefix : PayloadLenPrefix+n]
	for _, b := range body[PayloadLenPrefix+n:] {
		if b != 0 {
			return nil, ErrNonZeroPadding
		}
	}
	return payload, nil
}
