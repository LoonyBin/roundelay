package strictjson

import (
	"fmt"
	"net/url"
	"slices"
)

// Query is a cursor over a request's query string, under the same rules as a
// body: an unrecognised parameter is refused, with its name as a single-segment
// path, and a value outside its range is refused rather than clamped.
//
// Clamping is the specific mistake worth naming. A client built against a
// deployment with a larger page ceiling would silently receive short pages and
// mistake one for the end of the log.
type Query struct {
	v    url.Values
	seen map[string]bool

	unknown   []string
	malformed []problem
}

// NewQuery returns a cursor over v.
func NewQuery(v url.Values) *Query {
	return &Query{v: v, seen: make(map[string]bool)}
}

// raw marks a parameter read and returns its single value.
//
// A parameter given more than once is malformed. Nothing in this protocol takes
// a repeated parameter, and the alternatives — first wins, last wins — are two
// readings of one request, which is the shape the duplicate-key rule already
// refuses in a body.
func (q *Query) raw(name string) (string, bool) {
	q.seen[name] = true
	vs, ok := q.v[name]
	if !ok {
		return "", false
	}
	if len(vs) != 1 {
		q.malformed = append(q.malformed, problem{name, fmt.Sprintf("given %d times, want once", len(vs))})
		return "", false
	}
	return vs[0], true
}

// Has reports whether a parameter is present, without marking it read.
func (q *Query) Has(name string) bool {
	_, ok := q.v[name]
	return ok
}

// Int reads an optional integer parameter against an inclusive range. The bool
// reports presence, so a caller can tell an absent parameter from one that
// happens to equal its default — after_epoch has no default value, and
// after_epoch=0 is a different request from omitting it.
func (q *Query) Int(name string, r Range) (int64, bool) {
	s, ok := q.raw(name)
	if !ok {
		return 0, false
	}
	n, err := integer(s)
	if err != nil {
		q.malformed = append(q.malformed, problem{name, err.Error()})
		return 0, false
	}
	if n < r.Lo || n > r.Hi {
		q.malformed = append(q.malformed, problem{name, fmt.Sprintf("is %d, want %d..%d", n, r.Lo, r.Hi)})
		return 0, false
	}
	return n, true
}

// Bool reads an optional boolean parameter. The value must be exactly "true" or
// "false" — not "1", not "TRUE", not an empty presence flag.
func (q *Query) Bool(name string) (bool, bool) {
	s, ok := q.raw(name)
	if !ok {
		return false, false
	}
	switch s {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	q.malformed = append(q.malformed, problem{name, `is not exactly "true" or "false"`})
	return false, false
}

// UUID reads an optional canonical-UUID parameter, such as the members cursor.
func (q *Query) UUID(name string) ([16]byte, bool) {
	s, ok := q.raw(name)
	if !ok {
		return [16]byte{}, false
	}
	id, err := ParseUUID(s)
	if err != nil {
		q.malformed = append(q.malformed, problem{name, err.Error()})
		return [16]byte{}, false
	}
	return id, true
}

// Err reports the query string's problems, or nil, in the same order Body.Err
// uses: unrecognised parameters before malformed values.
func (q *Query) Err() error {
	var unknown []string
	unknown = append(unknown, q.unknown...)
	for name := range q.v {
		if !q.seen[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return &UnknownFields{Fields: slices.Compact(unknown)}
	}
	if len(q.malformed) > 0 {
		return newMalformed(q.malformed)
	}
	return nil
}
