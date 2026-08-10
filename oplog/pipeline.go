package oplog

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

var b64 = base64.StdEncoding.Strict()

// Op is one envelope in a batch, decoded far enough for the stage that is
// looking at it.
type Op struct {
	// Index is the zero-based position in the batch, which every per-op refusal
	// carries.
	Index int
	// Raw is the decoded envelope bytes, stored verbatim and served back
	// byte-identical. The envelope is the truth; every field parsed out of it is
	// an index.
	Raw []byte
	// Envelope is the parsed form.
	Envelope wire.Envelope
	// Body is the unpacked payload, set only for a class the server may unpack.
	Body []byte
}

// Header is shorthand for the parsed header.
func (o Op) Header() wire.Header { return o.Envelope.Header }

// Result is one entry of the positional results array.
type Result struct {
	OpID      [16]byte
	Seq       int64
	Duplicate bool
}

// Pipeline appends ops to one Workspace.
type Pipeline struct {
	Profile   *profile.Profile
	Store     Store
	Authority Authority

	// Notify is poked after a successful commit in which at least one op was
	// new.
	//
	// After, because a woken subscriber that pulls before the commit finds
	// nothing and the poke is wasted. Only if something was new, because a pure
	// repeat is not news.
	Notify func(workspace [16]byte)
}

// Append runs the six-stage walk.
//
// The whole batch commits, or none of it does. One refusal rejects every op in
// the request, including ops that would have been fine alone.
func (p *Pipeline) Append(ctx context.Context, workspace, device [16]byte, encoded []string) ([]Result, *Refusal) {
	// ── Stage 0: the batch ceiling ──────────────────────────────────────────
	//
	// It names no op, because no single op is at fault.
	if len(encoded) > p.Profile.Limits.MaxOpsPerBatch {
		return nil, refuse(http.StatusRequestEntityTooLarge, codes.BatchTooLarge,
			map[string]any{"max_ops": p.Profile.Limits.MaxOpsPerBatch})
	}
	if len(encoded) == 0 {
		// An empty ops array returns an empty results array and changes nothing.
		return []Result{}, nil
	}

	tx, err := p.Store.BeginAppend(ctx, workspace)
	if err != nil {
		return nil, refuse(http.StatusServiceUnavailable, codes.StoreUnavailable, nil)
	}
	defer tx.Rollback()

	results, r := p.walk(ctx, tx, workspace, device, encoded)
	if r != nil {
		return nil, r
	}
	if err := tx.Commit(); err != nil {
		return nil, refuse(http.StatusServiceUnavailable, codes.StoreUnavailable, nil)
	}
	if p.Notify != nil && anyNew(results) {
		p.Notify(workspace)
	}
	return results, nil
}

// anyNew reports whether the batch stored anything. A batch of pure repeats
// changed nothing, and there is nothing for a subscriber to fetch.
func anyNew(results []Result) bool {
	for _, r := range results {
		if !r.Duplicate {
			return true
		}
	}
	return false
}

func (p *Pipeline) walk(ctx context.Context, tx Tx, workspace, device [16]byte, encoded []string) ([]Result, *Refusal) {
	// ── Stage 1: every op, header only ──────────────────────────────────────
	//
	// A complete pass before any op reaches stage 2. That ordering is
	// observable, so it is protocol: a batch of [content op with no permission,
	// unparseable base64] answers about index 1.
	ops := make([]Op, len(encoded))
	for i, s := range encoded {
		op, r := p.stage1(i, workspace, device, s, tx)
		if r != nil {
			return nil, r
		}
		ops[i] = op
	}

	// ── Stage 0's other half, deferred ──────────────────────────────────────
	//
	// The access gate exempts an author's first op in a Workspace, and whether
	// the batch's first op *is* that op is a fact about its class, its payload
	// type and its certificate — none of which stage 0 has read. Only the
	// verdict is protocol; where the check runs is an implementation's business.
	registered, err := tx.Registered(device)
	if err != nil {
		return nil, storeDown()
	}
	if !registered && !p.Authority.EstablishesAccess(ops[0]) {
		return nil, refuse(http.StatusForbidden, codes.NoRegistration, nil)
	}

	// ── Stages 2 to 4, per op in arrival order ──────────────────────────────
	//
	// The effects of earlier ops in the same batch are visible to later ones, so
	// each op is applied as it passes rather than after the walk.
	results := make([]Result, len(ops))
	seen := make(map[[16]byte]int64, len(ops))
	headBefore, err := tx.AuthorHead(device)
	if err != nil {
		return nil, storeDown()
	}
	var fresh []Op

	for i := range ops {
		op := ops[i]
		id := op.Header().OpID

		// The idempotency lookup sits after stage 1 and before stage 2. A repeat
		// is answered from the op already stored — at the position it holds — and
		// stages 2 to 5 do not run for it.
		//
		// Which pins two answers that would otherwise differ per server. A stored
		// op whose key_epoch has since dropped below the floor answers
		// duplicate: true, never key_epoch_stale: it was judged at its own
		// position and nothing that changed afterwards re-judges it.
		if seq, ok := seen[id]; ok {
			results[i] = Result{OpID: id, Seq: seq, Duplicate: true}
			continue
		}
		stored, found, err := tx.OpByOpID(device, id)
		if err != nil {
			return nil, storeDown()
		}
		if found {
			seen[id] = stored.Seq
			results[i] = Result{OpID: id, Seq: stored.Seq, Duplicate: true}
			continue
		}

		if op.Header().OpClass != wire.ClassControl {
			if r := p.Authority.Stage2(ctx, tx, op); r != nil {
				return nil, r.At(i)
			}
		}
		if wire.IsExtension(op.Header().OpClass) {
			if r := p.checkExtensionOp(tx, op); r != nil {
				return nil, r.At(i)
			}
		}

		at, r := p.apply(ctx, tx, op)
		if r != nil {
			return nil, r.At(i)
		}
		seen[id] = at
		results[i] = Result{OpID: id, Seq: at, Duplicate: false}
		fresh = append(fresh, op)
	}

	// ── Stage 5: the author chain ───────────────────────────────────────────
	//
	// Run once every op has passed 2 to 4. Every op in a batch has the same
	// author, so one counter answers the whole walk.
	for n, op := range fresh {
		want := headBefore + uint64(n) + 1
		if got := op.Header().AuthorSeq; got != want {
			// A gap means the writing device's chain is broken, and accepting the
			// rest would make the break permanent. expected_author_seq is
			// load-bearing: a device compares it against what the server already
			// acknowledged, to tell an ordinary conflict from a server that lost
			// its writes.
			return nil, refuse(http.StatusConflict, codes.AuthorChainConflict, map[string]any{
				"author_seq":          got,
				"expected_author_seq": want,
			}).At(op.Index)
		}
	}

	return results, nil
}

func storeDown() *Refusal {
	return refuse(http.StatusServiceUnavailable, codes.StoreUnavailable, nil)
}

// stage1 reads the header and nothing else. No body is unpacked here, and no
// store state is consulted beyond the ids this device has held.
func (p *Pipeline) stage1(i int, workspace, device [16]byte, encoded string, tx Tx) (Op, *Refusal) {
	bad := func(status int, code codes.Code, extra map[string]any) (Op, *Refusal) {
		return Op{}, refuse(status, code, extra).At(i)
	}
	const u = http.StatusUnprocessableEntity

	raw, err := b64.DecodeString(encoded)
	if err != nil {
		return bad(u, codes.MalformedBase64, nil)
	}
	// Under 158 bytes there is no header, and so no envelope of any suite this
	// server serves — which is why this leads the two selector bytes.
	if len(raw) < wire.HeaderLen {
		return bad(u, codes.TruncatedEnvelope, nil)
	}
	h, err := wire.ParseHeader(raw)
	if err != nil {
		return bad(u, codes.TruncatedEnvelope, nil)
	}

	// The two selector bytes resolve before the floor, because the floor is the
	// suite's: a suite this server does not serve has no floor to measure
	// against.
	if !p.Profile.ServesClass(h.OpClass) {
		return bad(u, codes.UnsupportedOpClass, nil)
	}
	if !slices.Contains(wire.Suites, h.Suite) {
		return bad(u, codes.UnsupportedSuite, nil)
	}
	if len(raw) < p.Profile.SizeClasses.MinEnvelopeLen(h.Suite) {
		return bad(u, codes.EnvelopeTooShort, nil)
	}

	// Sealing a server-read class is forbidden for ever: the server must act on
	// those payloads and holds no key, so a sealed one is not a stricter op but a
	// useless one. The rule is on the bit, not on a list.
	if h.Suite != wire.SuiteNone && wire.ServerReads(h.OpClass) {
		switch h.OpClass {
		case wire.ClassControl:
			return bad(u, codes.EncryptedControlOp, nil)
		case wire.ClassPrune:
			return bad(u, codes.EncryptedPruneOp, nil)
		default:
			return bad(u, codes.EncryptedServerReadOp, nil)
		}
	}

	// Parsed fields are checked against the envelope bytes, never trusted over
	// them.
	if h.WorkspaceID != workspace {
		return bad(u, codes.WorkspaceMismatch, nil)
	}
	// A token speaks for exactly one device, and that device is the only author
	// it can post as. So a batch is one device's enrolment and never two.
	if h.AuthorMemberID != device {
		return bad(http.StatusForbidden, codes.AuthorMemberMismatch, nil)
	}

	// author_key_class_mismatch fires only on a positive match against an id this
	// device has held for the OTHER class — every id it has held for that class
	// here, so a member_amend never turns an honest stale client into a class
	// mismatch. An author_key_id the server holds no record of is not refused
	// here: that is the rotation the server declines to judge.
	other := SigningClassFor(h.OpClass).Other()
	held, err := tx.KeyIDsHeldForClass(device, other)
	if err != nil {
		return Op{}, storeDown()
	}
	if slices.ContainsFunc(held, func(id [8]byte) bool { return id == h.AuthorKeyID }) {
		return bad(u, codes.AuthorKeyClassMismatch, map[string]any{"op_class": int(h.OpClass)})
	}

	env, err := wire.ParseEnvelope(raw)
	if err != nil {
		return bad(u, codes.EnvelopeTooShort, nil)
	}
	return Op{Index: i, Raw: raw, Envelope: env}, nil
}

// apply runs stage 3 or stage 4 for an op and stores it.
//
// The op is appended first, so that its own position is available to the effect
// it causes — a prune marks its targets from the position it now occupies, and an
// ext_binding opens an interval there.
func (p *Pipeline) apply(ctx context.Context, tx Tx, op Op) (int64, *Refusal) {
	h := op.Header()

	at, err := tx.Append(StoredOp{
		Workspace:    h.WorkspaceID,
		Class:        h.OpClass,
		KeyEpoch:     h.KeyEpoch,
		OpID:         h.OpID,
		Author:       h.AuthorMemberID,
		AuthorKeyID:  h.AuthorKeyID,
		AuthorSeq:    h.AuthorSeq,
		EnvelopeHash: wire.EnvelopeHash(op.Raw),
		Envelope:     op.Raw,
	})
	if err != nil {
		return 0, storeDown()
	}

	switch {
	case h.OpClass == wire.ClassControl:
		if _, r := p.Authority.Stage4(ctx, tx, op, at); r != nil {
			return 0, r
		}
	case h.OpClass == wire.ClassPrune:
		if r := p.stage3Prune(ctx, tx, op, at); r != nil {
			return 0, r
		}
	case h.OpClass == wire.ClassExtBinding:
		if r := p.stage3ExtBinding(ctx, tx, op, at); r != nil {
			return 0, r
		}
	}
	return at, nil
}

// unpack is stage 3's framing step, and the server only ever runs it on a class
// with bit 7 set.
func (p *Pipeline) unpack(op Op) ([]byte, *Refusal) {
	body := op.Envelope.Body
	l := p.Profile.SizeClasses
	const u = http.StatusUnprocessableEntity
	switch payload, err := l.UnpackBody(body); {
	case err == nil:
		return payload, nil
	case is(err, wire.ErrInvalidBodyLength):
		return nil, refuse(u, codes.InvalidBodyLength, nil)
	case is(err, wire.ErrPayloadOverrunsBody):
		return nil, refuse(u, codes.PayloadOverrunsBody, nil)
	default:
		return nil, refuse(u, codes.NonZeroPadding, nil)
	}
}

func is(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
