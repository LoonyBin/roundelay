package strictjson

import (
	"fmt"
	"strconv"
)

// Object is a cursor over a decoded JSON object. Accessors mark the members they
// read, so everything left unread at Err time is a member nobody asked for.
//
// A dead Object — one standing in for a member that was missing or of the wrong
// type — records nothing further. The parent already named the problem, and
// cascading a whole object's members underneath it would report a shape the
// caller never had.
type Object struct {
	b    *Body
	path string
	v    *value
	dead bool
}

// Root returns a cursor over the top-level object. A document whose root is not
// an object yields a dead cursor and one problem at the empty path.
func (b *Body) Root() *Object {
	if b.root == nil || b.root.kind != kindObject {
		got := "nothing"
		if b.root != nil {
			got = b.root.kind.String()
		}
		b.bad("", "top-level value is "+got+", want an object")
		return &Object{b: b, dead: true}
	}
	return &Object{b: b, v: b.root}
}

// Path is this object's dotted path from the body, empty at the root.
func (o *Object) Path() string { return o.path }

// take marks a member visited and returns it. A missing member yields nil
// without recording anything: whether its absence is a problem is the caller's
// question, and the optional accessors answer it differently.
func (o *Object) take(name string) *value {
	if o.dead || o.v == nil {
		return nil
	}
	m := o.v.member(name)
	if m == nil {
		return nil
	}
	m.visited = true
	return m.val
}

// require is take plus the missing-member problem, reported at the member's own
// path — key_ids.control_key_id rather than key_ids.
func (o *Object) require(name string) *value {
	v := o.take(name)
	if v == nil && !o.dead {
		o.b.bad(join(o.path, name), "required member is missing")
	}
	return v
}

func (o *Object) typed(name string, want kind) *value {
	v := o.require(name)
	if v == nil {
		return nil
	}
	if v.kind != want {
		o.b.bad(join(o.path, name), fmt.Sprintf("is %s, want %s", v.kind, want))
		return nil
	}
	return v
}

// Has reports whether a member is present, without marking it visited. Use it
// to branch on presence before reading; it is never on its own enough to keep a
// member out of the unknown set.
func (o *Object) Has(name string) bool {
	if o.dead || o.v == nil {
		return false
	}
	return o.v.member(name) != nil
}

// PeekString returns a member's string value without marking it visited and
// without recording a problem. The bool is false when the member is absent or is
// not a string.
//
// It exists for the one shape the ordinary accessors cannot express: a payload
// whose closed key set depends on one of its own members. Every server-read
// payload carries a mandatory `type`, and which keys are legal beside it follows
// from what that type is — so the type must be read before the key set can be
// judged, and reading it must not itself be a judgement.
//
// A caller still reads the member normally afterwards. Peeking does not consume
// it, so a payload whose type was peeked and never read reports `type` as
// unrecognised, which is the fail-closed direction.
func (o *Object) PeekString(name string) (string, bool) {
	if o.dead || o.v == nil {
		return "", false
	}
	m := o.v.member(name)
	if m == nil || m.val.kind != kindString {
		return "", false
	}
	return m.val.str, true
}

// Object reads a required sub-object.
func (o *Object) Object(name string) *Object {
	v := o.typed(name, kindObject)
	if v == nil {
		return &Object{b: o.b, path: join(o.path, name), dead: true}
	}
	return &Object{b: o.b, path: join(o.path, name), v: v}
}

// OptionalObject reads a sub-object that may be absent.
//
// Optional as a whole is not optional member by member: a caller that takes the
// true branch must go on to require every member the object declares, so that an
// object present with one member missing is refused rather than half-read.
func (o *Object) OptionalObject(name string) (*Object, bool) {
	if !o.Has(name) {
		return &Object{b: o.b, path: join(o.path, name), dead: true}, false
	}
	return o.Object(name), true
}

// Array reads a required array.
func (o *Object) Array(name string) *Array {
	v := o.typed(name, kindArray)
	if v == nil {
		return &Array{b: o.b, path: join(o.path, name), dead: true}
	}
	return &Array{b: o.b, path: join(o.path, name), v: v}
}

// Array is a cursor over a decoded JSON array.
type Array struct {
	b    *Body
	path string
	v    *value
	dead bool
}

// Len is the number of elements, zero on a dead cursor.
func (a *Array) Len() int {
	if a.dead || a.v == nil {
		return 0
	}
	return len(a.v.arr)
}

// Object reads element i as an object. Its path carries a bare decimal index —
// wraps.0.wrap_b64 — which is the whole of what an array position contributes.
func (a *Array) Object(i int) *Object {
	path := join(a.path, strconv.Itoa(i))
	if a.dead || a.v == nil || i < 0 || i >= len(a.v.arr) {
		return &Object{b: a.b, path: path, dead: true}
	}
	e := a.v.arr[i]
	if e.kind != kindObject {
		a.b.bad(path, fmt.Sprintf("is %s, want object", e.kind))
		return &Object{b: a.b, path: path, dead: true}
	}
	return &Object{b: a.b, path: path, v: e}
}

// String reads element i as a string. The path carries a bare decimal index —
// ops.3 — which is the whole of what an array position contributes.
func (a *Array) String(i int) string {
	path := join(a.path, strconv.Itoa(i))
	if a.dead || a.v == nil || i < 0 || i >= len(a.v.arr) {
		return ""
	}
	e := a.v.arr[i]
	if e.kind != kindString {
		a.b.bad(path, fmt.Sprintf("is %s, want string", e.kind))
		return ""
	}
	return e.str
}

// String reads a required string member.
func (o *Object) String(name string) string {
	v := o.typed(name, kindString)
	if v == nil {
		return ""
	}
	return v.str
}

// Bool reads a required boolean member. A JSON boolean, never the strings
// "true" and "false" — the wire has one spelling for each value.
func (o *Object) Bool(name string) bool {
	v := o.typed(name, kindBool)
	if v == nil {
		return false
	}
	return v.b
}

// Int reads a required integer member and checks it against an inclusive range.
//
// A JSON integer: never a float, never a boolean, never a string. 1.0 and 1e0
// are refused rather than accepted as 1, because two implementations that differ
// about which spellings are legal disagree about which payloads exist.
func (o *Object) Int(name string, lo, hi int64) int64 {
	v := o.typed(name, kindNumber)
	if v == nil {
		return 0
	}
	path := join(o.path, name)
	n, err := integer(v.num)
	if err != nil {
		o.b.bad(path, err.Error())
		return 0
	}
	if n < lo || n > hi {
		o.b.bad(path, fmt.Sprintf("is %d, want %d..%d", n, lo, hi))
		return 0
	}
	return n
}

// OptionalInt reads an integer member that may be absent.
func (o *Object) OptionalInt(name string, lo, hi int64) (int64, bool) {
	if !o.Has(name) {
		return 0, false
	}
	return o.Int(name, lo, hi), true
}

// Bytes reads a required base64 member and checks its decoded length.
//
// Standard base64, padded, validated strictly: a stray character, missing
// padding or a non-zero trailing bit is a refusal, never something to repair.
func (o *Object) Bytes(name string, n int) []byte {
	v := o.typed(name, kindString)
	if v == nil {
		return nil
	}
	path := join(o.path, name)
	b, err := base64Exact(v.str, n)
	if err != nil {
		o.b.bad(path, err.Error())
		return nil
	}
	return b
}

// BytesAny reads a required base64 member of any length.
//
// The vault blob is the case this exists for: the server stores it verbatim,
// never parses it, and MUST NOT even length-check it.
func (o *Object) BytesAny(name string) []byte {
	v := o.typed(name, kindString)
	if v == nil {
		return nil
	}
	path := join(o.path, name)
	b, err := base64Any(v.str)
	if err != nil {
		o.b.bad(path, err.Error())
		return nil
	}
	return b
}

// Hex reads a required lowercase-hex member of an exact decoded length.
func (o *Object) Hex(name string, n int) []byte {
	v := o.typed(name, kindString)
	if v == nil {
		return nil
	}
	path := join(o.path, name)
	b, err := hexExact(v.str, n)
	if err != nil {
		o.b.bad(path, err.Error())
		return nil
	}
	return b
}

// UUID reads a required canonical lowercase 8-4-4-4-12 member: no braces, no
// urn:uuid: prefix, no uppercase, no missing dashes.
func (o *Object) UUID(name string) [16]byte {
	v := o.typed(name, kindString)
	if v == nil {
		return [16]byte{}
	}
	path := join(o.path, name)
	id, err := ParseUUID(v.str)
	if err != nil {
		o.b.bad(path, err.Error())
		return [16]byte{}
	}
	return id
}

// Token reads a required kebab-case token: ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$,
// 1-32 bytes. Role tokens, member_kind tokens and extension NAMEs share it.
func (o *Object) Token(name string) string {
	v := o.typed(name, kindString)
	if v == nil {
		return ""
	}
	if !ValidToken(v.str) {
		o.b.bad(join(o.path, name), "is not a 1-32 byte kebab-case token")
		return ""
	}
	return v.str
}

// Authority reads a required granter or revoker: the literal "root", or a
// canonical UUID. The bool reports which — true for root.
func (o *Object) Authority(name string) ([16]byte, bool) {
	v := o.typed(name, kindString)
	if v == nil {
		return [16]byte{}, false
	}
	if v.str == "root" {
		return [16]byte{}, true
	}
	id, err := ParseUUID(v.str)
	if err != nil {
		o.b.bad(join(o.path, name), `is neither "root" nor a canonical UUID`)
		return [16]byte{}, false
	}
	return id, false
}

// Unknown records a path as unrecognised directly. It exists for the shapes this
// cursor cannot express — a member whose legality depends on a sibling's value,
// where the caller must read it and then judge it.
func (o *Object) Unknown(name string) {
	o.b.unknown = append(o.b.unknown, join(o.path, name))
}

// Int reads element i as an integer against an inclusive range.
func (a *Array) Int(i int, r Range) int64 {
	path := join(a.path, strconv.Itoa(i))
	e := a.element(i, path, kindNumber)
	if e == nil {
		return 0
	}
	n, err := integer(e.num)
	if err != nil {
		a.b.bad(path, err.Error())
		return 0
	}
	if n < r.Lo || n > r.Hi {
		a.b.bad(path, fmt.Sprintf("is %d, want %d..%d", n, r.Lo, r.Hi))
		return 0
	}
	return n
}

// Hex reads element i as lowercase hex of an exact decoded length.
func (a *Array) Hex(i, n int) []byte {
	path := join(a.path, strconv.Itoa(i))
	e := a.element(i, path, kindString)
	if e == nil {
		return nil
	}
	out, err := hexExact(e.str, n)
	if err != nil {
		a.b.bad(path, err.Error())
		return nil
	}
	return out
}

// Exactly records a problem unless the array has exactly n elements. A tuple —
// an HLC's three members, say — is a shape rather than a list.
func (a *Array) Exactly(n int) {
	if a.dead || a.v == nil {
		return
	}
	if len(a.v.arr) != n {
		a.b.bad(a.path, fmt.Sprintf("has %d elements, want exactly %d", len(a.v.arr), n))
	}
}

func (a *Array) element(i int, path string, want kind) *value {
	if a.dead || a.v == nil {
		return nil
	}
	if i < 0 || i >= len(a.v.arr) {
		a.b.bad(path, "is missing")
		return nil
	}
	e := a.v.arr[i]
	if e.kind != want {
		a.b.bad(path, fmt.Sprintf("is %s, want %s", e.kind, want))
		return nil
	}
	return e
}

// Reject records a problem against a member the caller judged for itself. It is
// for a rule the accessors cannot express — a value that must agree with another
// value in the same document.
func (o *Object) Reject(name, reason string) {
	if o.dead {
		return
	}
	o.b.bad(join(o.path, name), reason)
}
