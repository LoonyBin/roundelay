package strictjson

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// b64 is the encoding every binary value on the wire uses: standard alphabet,
// padded, and Strict so that a final quantum with non-zero unused bits is
// refused rather than silently truncated.
//
// The plain StdEncoding accepts "QQ==" and "QR==" as the same byte. Two
// implementations that differ about which spellings exist differ about which
// payloads are legal, which is a convergence bug wearing an encoding's clothes.
var b64 = base64.StdEncoding.Strict()

func base64Any(s string) ([]byte, error) {
	out, err := b64.DecodeString(s)
	if err != nil {
		return nil, errors.New("is not strict padded standard base64")
	}
	return out, nil
}

func base64Exact(s string, n int) ([]byte, error) {
	out, err := base64Any(s)
	if err != nil {
		return nil, err
	}
	if len(out) != n {
		return nil, fmt.Errorf("decodes to %d bytes, want %d", len(out), n)
	}
	return out, nil
}

var lowerHex = regexp.MustCompile(`^[0-9a-f]*$`)

func hexExact(s string, n int) ([]byte, error) {
	if !lowerHex.MatchString(s) {
		return nil, errors.New("is not lowercase hex")
	}
	if len(s) != 2*n {
		return nil, fmt.Errorf("is %d hex characters, want %d", len(s), 2*n)
	}
	out := make([]byte, n)
	for i := range out {
		hi, lo := hexNibble(s[2*i]), hexNibble(s[2*i+1])
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

// uuidPattern is the canonical form and nothing else. A platform parser that
// also accepts braces, a urn:uuid: prefix, uppercase or missing dashes admits
// several spellings of one id — and an id is compared, sorted and signed over as
// raw bytes, so the spellings must not multiply on the way in.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ParseUUID decodes a canonical lowercase 8-4-4-4-12 UUID to its 16 raw bytes.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	if !uuidPattern.MatchString(s) {
		return out, errors.New("is not a canonical lowercase 8-4-4-4-12 UUID")
	}
	b, err := hexExact(strings.ReplaceAll(s, "-", ""), 16)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// FormatUUID renders 16 raw bytes in canonical lowercase form.
func FormatUUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var tokenPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ValidToken reports whether s is a 1-32 byte kebab-case token: the shape shared
// by role tokens, member_kind tokens, extension NAMEs and the namespace.
func ValidToken(s string) bool {
	return len(s) >= 1 && len(s) <= 32 && tokenPattern.MatchString(s)
}

// integer parses a JSON number literal as an integer, refusing every spelling
// that is not one.
//
// The literal is checked before strconv sees it, because strconv would accept
// forms JSON does not and this rule is about the wire, not about Go.
func integer(lit string) (int64, error) {
	if strings.ContainsAny(lit, ".eE") {
		return 0, fmt.Errorf("is %s, want a JSON integer", lit)
	}
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("is %s, which does not fit a signed 64-bit integer", lit)
	}
	return n, nil
}

// The ranges the conventions fix, named so that a route cites the table rather
// than repeating two numbers that must agree everywhere they appear.
const (
	MaxUint32 = 1<<32 - 1
	MaxInt64  = 1<<63 - 1
)

// Range is one row of the conventions' integer table.
type Range struct{ Lo, Hi int64 }

var (
	// EpochRange covers epoch, from_epoch, to_epoch, key_epoch and after_epoch.
	EpochRange = Range{0, MaxUint32}
	// SinceRange covers the ops cursor, where 0 asks for the whole log.
	SinceRange = Range{0, MaxInt64}
	// PositionRange covers a prune target's seq and author_seq. Both count from
	// 1, so neither has a zeroth value and 0 names no op that could exist.
	PositionRange = Range{1, MaxInt64}
	// VersionRange covers a vault record's version. There is no version 0: a
	// first write is version 1.
	VersionRange = Range{1, MaxInt64}
	// HLCWallRange covers an HLC's wall_ms, which may be negative.
	HLCWallRange = Range{-1 << 63, MaxInt64}
	// HLCCounterRange covers an HLC's counter.
	HLCCounterRange = Range{0, MaxInt64}
	// OpClassRange covers an op_class named inside a payload — an integer, never
	// a hex string, because JSON has no hex literal and a string would invite two
	// spellings of one value.
	OpClassRange = Range{0, 255}
	// ExtClassRange covers the op_class an ext_binding or a prune_ext may name.
	ExtClassRange = Range{0xC0, 0xFF}
)

// In reads a required integer member against a named range.
func (o *Object) In(name string, r Range) int64 { return o.Int(name, r.Lo, r.Hi) }
