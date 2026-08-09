package oplog

import (
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

// MaxPruneTargets is wire-frozen, unlike the batch ceiling.
//
// The batch cap is server resource policy a client discovers and adapts to. This
// one is a shape rule other clients enforce on an op this server already
// accepted, so a server that raised it would mint ops its peers refuse.
const MaxPruneTargets = 1000

// Target is one op a prune names: the position for the server, the author and
// their sequence number to locate the hole, and the envelope hash so a verifier
// can chain past it.
type Target struct {
	Seq          int64
	Author       [16]byte
	AuthorSeq    int64
	EnvelopeHash [32]byte
}

// PrunePayload is a decoded 0x81 body. Which of the three types it is decides
// whether bytes survive and which side of bit 7 it reaches, so `type` is
// mandatory for ever and never inferred from which fields are present.
type PrunePayload struct {
	Type      string
	RepriseID [16]byte // `prune` only
	OpClass   byte     // `prune_ext` only
	Name      string   // `prune_ext` only
	Targets   []Target

	// repriseSeq is where the named reprise was found, so that
	// prune_target_is_its_own_reprise can be judged without a second lookup.
	repriseSeq int64
}

// ParsePrunePayload reads a 0x81 body under stage 3's shape rules.
func ParsePrunePayload(body []byte) (*PrunePayload, *Refusal) {
	malformed := func() *Refusal {
		return refuse(http.StatusUnprocessableEntity, codes.MalformedPrunePayload, nil)
	}

	doc, err := strictjson.Parse(body)
	if err != nil {
		return nil, malformed()
	}
	o := doc.Root()

	// `type` leads, and is peeked before the key set is judged: which keys are
	// legal beside it follows from what it is, so a payload that does not say
	// what it is cannot have its keys checked against anything. A missing or
	// non-string type is malformed; a well-formed one this server does not serve
	// is a different verdict.
	typ, ok := o.PeekString("type")
	if !ok {
		return nil, malformed()
	}
	switch typ {
	case wire.PruneSoft, wire.PruneExt, wire.PruneHard:
	default:
		return nil, refuse(http.StatusUnprocessableEntity, codes.UnsupportedPruneType, nil)
	}
	o.String("type")

	// The key set is now this type's, so a `reprise` on a prune_ext is an
	// unrecognised key rather than a change of lane.
	p := &PrunePayload{Type: typ}
	switch typ {
	case wire.PruneSoft:
		p.RepriseID = o.Object("reprise").UUID("op_id")
	case wire.PruneExt:
		p.OpClass = byte(o.In("op_class", strictjson.ExtClassRange))
		p.Name = o.Token("name")
	}

	arr := o.Array("targets")
	for i := range arr.Len() {
		e := arr.Object(i)
		t := Target{
			Seq:       e.In("seq", strictjson.PositionRange),
			Author:    e.UUID("author_member_id"),
			AuthorSeq: e.In("author_seq", strictjson.PositionRange),
		}
		copy(t.EnvelopeHash[:], e.Hex("envelope_hash", 32))
		p.Targets = append(p.Targets, t)
	}
	if doc.Err() != nil {
		return nil, malformed()
	}

	if r := checkTargetShape(p.Targets); r != nil {
		return nil, r
	}
	return p, nil
}

// checkTargetShape is the three rules that bind author and reader alike.
//
// Duplicates are refused at decode so that a later rowcount check has exactly
// one remaining explanation — a concurrent prune. Otherwise a race and a
// malformed payload become indistinguishable.
func checkTargetShape(targets []Target) *Refusal {
	if len(targets) == 0 {
		return refuse(http.StatusUnprocessableEntity, codes.PruneTargetsEmpty, nil)
	}
	if len(targets) > MaxPruneTargets {
		return refuse(http.StatusUnprocessableEntity, codes.PruneTargetsTooMany, nil)
	}
	bySeq := make(map[int64]bool, len(targets))
	type chainPos struct {
		author    [16]byte
		authorSeq int64
	}
	byChain := make(map[chainPos]bool, len(targets))
	for _, t := range targets {
		if bySeq[t.Seq] {
			return refuse(http.StatusUnprocessableEntity, codes.PruneDuplicateTarget, nil)
		}
		bySeq[t.Seq] = true
		c := chainPos{t.Author, t.AuthorSeq}
		if byChain[c] {
			return refuse(http.StatusUnprocessableEntity, codes.PruneDuplicateTarget, nil)
		}
		byChain[c] = true
	}
	return nil
}

// ExtBindingPayload is a decoded 0xBF body.
//
// There is no binding_id and no chain link, and both absences are deliberate. A
// member holds at most one live binding per class by rule, so the class is the
// key and `unbind` needs nothing else; and a binding already sits in its author's
// own chain through prev_author_hash, so a second chain would attest nothing the
// first does not.
type ExtBindingPayload struct {
	Type    string
	OpClass byte
	Name    string // `bind` only
}

// ParseExtBindingPayload reads a 0xBF body under stage 3's shape rules.
func ParseExtBindingPayload(body []byte) (*ExtBindingPayload, *Refusal) {
	malformed := func() *Refusal {
		return refuse(http.StatusUnprocessableEntity, codes.MalformedExtBindingPayload, nil)
	}

	doc, err := strictjson.Parse(body)
	if err != nil {
		return nil, malformed()
	}
	o := doc.Root()
	typ, ok := o.PeekString("type")
	if !ok {
		return nil, malformed()
	}
	switch typ {
	case wire.ExtBind, wire.ExtUnbind:
	default:
		return nil, refuse(http.StatusUnprocessableEntity, codes.UnsupportedExtBindingType, nil)
	}
	o.String("type")

	p := &ExtBindingPayload{Type: typ}
	// op_class is an integer, not a hex string: JSON has no hex literal, and a
	// string would invite two spellings of one value.
	p.OpClass = byte(o.In("op_class", strictjson.ExtClassRange))
	if typ == wire.ExtBind {
		p.Name = o.Token("name")
	}
	if doc.Err() != nil {
		return nil, malformed()
	}
	return p, nil
}
