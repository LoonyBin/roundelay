package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// MaxDepth bounds nesting. Nothing this protocol defines is deeper than three
// levels; the limit is here so that a small body cannot exhaust the stack.
//
// A body past it is Malformed rather than refused under a code of its own. There
// is no code for "too deep", the vocabulary is closed, and a deployment's
// request-body bound catches the ordinary shape of this abuse already.
const MaxDepth = 32

type kind uint8

const (
	kindNull kind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

func (k kind) String() string {
	switch k {
	case kindNull:
		return "null"
	case kindBool:
		return "boolean"
	case kindNumber:
		return "number"
	case kindString:
		return "string"
	case kindArray:
		return "array"
	default:
		return "object"
	}
}

type value struct {
	kind kind
	str  string
	num  string // the verbatim literal, so 1, 1.0 and 1e0 stay distinguishable
	b    bool
	arr  []*value
	obj  []*member
}

type member struct {
	name    string
	path    string // carried so the unvisited sweep needs no second walk to rebuild it
	val     *value
	visited bool
}

func (v *value) member(name string) *member {
	for _, m := range v.obj {
		if m.name == name {
			return m
		}
	}
	return nil
}

// ErrSyntax reports bytes that are not one well-formed JSON value.
//
// It is distinct from Malformed: nothing was decoded, so there is no path to
// name and no field set to report. A caller answers it under the same code it
// would use for Malformed, with no fields.
var ErrSyntax = errors.New("strictjson: not one well-formed JSON value")

// Body is a decoded document and the problems found while reading it.
type Body struct {
	root *value

	// Duplicated keys are held apart from other malformed paths because they are
	// judged first: a body that says one thing twice was not understood at all,
	// and reporting its unknown members alongside would be reporting a reading
	// nobody has.
	dup       []problem
	unknown   []string
	malformed []problem
}

// Parse decodes b. It returns ErrSyntax for bytes that are not one well-formed
// JSON value; every other finding is accumulated and surfaced by Err.
func Parse(b []byte) (*Body, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrSyntax)
	}
	body := &Body{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()

	root, err := body.parseValue(dec, "", 0)
	if err != nil {
		return nil, err
	}
	// One value, and nothing after it. A second document sharing a request is two
	// instructions where the route accepts one.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content after the top-level value", ErrSyntax)
	}
	body.root = root
	return body, nil
}

func (b *Body) parseValue(dec *json.Decoder, path string, depth int) (*value, error) {
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: empty", ErrSyntax)
		}
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return b.parseFrom(dec, tok, path, depth)
}

func (b *Body) parseFrom(dec *json.Decoder, tok json.Token, path string, depth int) (*value, error) {
	if depth > MaxDepth {
		b.bad(path, "nesting deeper than "+strconv.Itoa(MaxDepth))
		// Consume the subtree without building it, and iteratively — the recursion
		// is the stack this limit protects, so the skip must not use it.
		if err := skip(dec, tok); err != nil {
			return nil, err
		}
		return &value{kind: kindNull}, nil
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return b.parseObject(dec, path, depth)
		case '[':
			return b.parseArray(dec, path, depth)
		default:
			return nil, fmt.Errorf("%w: unexpected %q", ErrSyntax, t)
		}
	case string:
		return &value{kind: kindString, str: t}, nil
	case json.Number:
		return &value{kind: kindNumber, num: t.String()}, nil
	case bool:
		return &value{kind: kindBool, b: t}, nil
	case nil:
		return &value{kind: kindNull}, nil
	default:
		return nil, fmt.Errorf("%w: unexpected token %T", ErrSyntax, tok)
	}
}

func (b *Body) parseObject(dec *json.Decoder, path string, depth int) (*value, error) {
	v := &value{kind: kindObject}
	seen := make(map[string]bool)
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
		}
		name, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("%w: object key is not a string", ErrSyntax)
		}
		child, err := b.parseValue(dec, join(path, name), depth+1)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			// Keep the first occurrence and record the path. Parsing continues so
			// that a body with several duplicated keys reports all of them, on the
			// same one-round-trip rule the unknown set follows.
			b.dup = append(b.dup, problem{path: join(path, name), reason: "duplicate object key"})
			continue
		}
		seen[name] = true
		v.obj = append(v.obj, &member{name: name, path: join(path, name), val: child})
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return v, nil
}

func (b *Body) parseArray(dec *json.Decoder, path string, depth int) (*value, error) {
	v := &value{kind: kindArray}
	for dec.More() {
		child, err := b.parseValue(dec, join(path, strconv.Itoa(len(v.arr))), depth+1)
		if err != nil {
			return nil, err
		}
		v.arr = append(v.arr, child)
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return v, nil
}

// skip consumes the value tok opens, leaving the decoder positioned after it.
func skip(dec *json.Decoder, tok json.Token) error {
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil // a scalar is already consumed
	}
	for depth := 1; depth > 0; {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSyntax, err)
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// join builds a path: dot-separated from the body, with bare decimal indices for
// array positions.
func join(path, seg string) string {
	if path == "" {
		return seg
	}
	return path + "." + seg
}
