package strictjson

import (
	"slices"
	"strings"
)

// problem is one offending path and why. The reason never reaches the wire — a
// refusal detail carries paths and a code, and nothing else — but it is what
// makes a failing test and a server log readable.
type problem struct {
	path   string
	reason string
}

// UnknownFields reports members or parameters nobody asked for.
//
// On the versioned surface a caller answers this unknown_request_field; inside a
// signed payload it is malformed_control_payload, malformed_prune_payload or
// malformed_ext_binding_payload, by which door the bytes arrived at.
type UnknownFields struct {
	// Fields is every offending path, sorted lexicographically by UTF-8 bytes.
	Fields []string
}

func (e *UnknownFields) Error() string {
	return "strictjson: unrecognised fields: " + strings.Join(e.Fields, ", ")
}

// Malformed reports paths whose contents are wrong: a duplicated key, a value of
// the wrong JSON type, a value outside its range, a binary or textual value that
// does not meet its shape, or a required member omitted from an object that is
// present.
//
// A caller answers this malformed_request on the versioned surface, and the same
// three payload codes as UnknownFields inside a signed payload.
type Malformed struct {
	// Fields is every offending path, sorted lexicographically by UTF-8 bytes.
	Fields []string

	// Reasons pairs each path with a human-readable cause, for logs and tests.
	// It is not part of any refusal.
	Reasons map[string]string
}

func (e *Malformed) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		if r := e.Reasons[f]; r != "" {
			parts = append(parts, f+" ("+r+")")
			continue
		}
		parts = append(parts, f)
	}
	return "strictjson: malformed fields: " + strings.Join(parts, ", ")
}

// Err reports the document's problems, or nil.
//
// The order is fixed, and it is a choice this package makes where the
// specification is silent: a body carrying both a duplicated key and an
// unrecognised member is answered about the duplicate, and one carrying both an
// unrecognised member and a malformed value is answered about the member.
//
// Duplicates lead because a body that says one thing twice has no single
// reading, so anything reported beside them describes a document nobody holds.
// Unknown members precede malformed values because the two failures are not
// symmetrical: an unrecognised member is an instruction the server will not
// carry out, and the whole of Compatibility §4 is about never letting one pass
// quietly.
//
// Err is idempotent and may be called more than once.
func (b *Body) Err() error {
	if len(b.dup) > 0 {
		return newMalformed(b.dup)
	}
	if unknown := b.unvisited(); len(unknown) > 0 {
		return &UnknownFields{Fields: tidy(unknown)}
	}
	if len(b.malformed) > 0 {
		return newMalformed(b.malformed)
	}
	return nil
}

// unvisited sweeps the whole tree for members nobody asked for.
//
// A member that was not visited is reported and not descended into: its own path
// is the smallest true statement about it, and listing its children beside it
// would report a shape the caller never claimed to understand.
func (b *Body) unvisited() []string {
	out := slices.Clone(b.unknown)
	var walk func(v *value)
	walk = func(v *value) {
		if v == nil {
			return
		}
		switch v.kind {
		case kindObject:
			for _, m := range v.obj {
				if !m.visited {
					out = append(out, m.path)
					continue
				}
				walk(m.val)
			}
		case kindArray:
			for _, e := range v.arr {
				walk(e)
			}
		}
	}
	walk(b.root)
	return out
}

func newMalformed(ps []problem) *Malformed {
	paths := make([]string, 0, len(ps))
	reasons := make(map[string]string, len(ps))
	for _, p := range ps {
		paths = append(paths, p.path)
		if _, ok := reasons[p.path]; !ok {
			reasons[p.path] = p.reason
		}
	}
	return &Malformed{Fields: tidy(paths), Reasons: reasons}
}

func tidy(paths []string) []string {
	out := slices.Clone(paths)
	slices.Sort(out)
	return slices.Compact(out)
}

func (b *Body) bad(path, reason string) {
	b.malformed = append(b.malformed, problem{path: path, reason: reason})
}
