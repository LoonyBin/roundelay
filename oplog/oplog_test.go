package oplog_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

var b64 = base64.StdEncoding

// ── a stand-in for the Authority layer ──────────────────────────────────────

// fakeAuthority answers stages 2 and 4 without deriving anything from a log. It
// exists so that the ordering rules this package owns can be exercised before
// Authority is built; every verdict it gives is one a test asked for.
type fakeAuthority struct {
	stage2      func(op oplog.Op) *oplog.Refusal
	pruneTypes  func(t string) *oplog.Refusal
	establishes func(op oplog.Op) bool
}

func (a *fakeAuthority) Stage2(_ context.Context, _ oplog.Tx, op oplog.Op) *oplog.Refusal {
	if a.stage2 != nil {
		return a.stage2(op)
	}
	return nil
}

func (a *fakeAuthority) Stage4(_ context.Context, _ oplog.Tx, _ oplog.Op, _ int64) (string, *oplog.Refusal) {
	return "", nil
}

func (a *fakeAuthority) PermitsPruneType(_ context.Context, _ oplog.Tx, _ [16]byte, t string) *oplog.Refusal {
	if a.pruneTypes != nil {
		return a.pruneTypes(t)
	}
	return nil
}

func (a *fakeAuthority) EstablishesAccess(op oplog.Op) bool {
	if a.establishes != nil {
		return a.establishes(op)
	}
	return false
}

// ── fixtures ────────────────────────────────────────────────────────────────

type harness struct {
	t     *testing.T
	p     *oplog.Pipeline
	store *memstore.Store
	auth  *fakeAuthority
	ws    [16]byte
	dev   [16]byte
}

func newHarness(t *testing.T, prof *profile.Profile) *harness {
	t.Helper()
	if err := prof.Validate(); err != nil {
		t.Fatalf("profile: %v", err)
	}
	st := memstore.New()
	auth := &fakeAuthority{}
	h := &harness{
		t: t, store: st, auth: auth,
		ws: vectors.WorkspaceID, dev: vectors.MemberA,
		p: &oplog.Pipeline{Profile: prof, Store: st, Authority: auth},
	}
	st.Seed(h.ws, func(s memstore.Seeder) {
		s.Exists()
		s.Register(h.dev,
			wire.KeyID(vectors.SignPub(vectors.LabelDeviceAControl)),
			wire.KeyID(vectors.SignPub(vectors.LabelDeviceAContent)))
	})
	return h
}

func (h *harness) append(ops ...string) ([]oplog.Result, *oplog.Refusal) {
	h.t.Helper()
	return h.p.Append(context.Background(), h.ws, h.dev, ops)
}

// op builds a signed envelope. The label decides the signing key, and so the
// author_key_id in the header.
type opts struct {
	class     byte
	suite     byte
	epoch     uint32
	authorSeq uint64
	payload   []byte
	label     string
	workspace *[16]byte
	author    *[16]byte
	extName   string
}

func (h *harness) op(o opts) string {
	h.t.Helper()
	if o.label == "" {
		o.label = vectors.LabelDeviceAContent
		if wire.ServerReads(o.class) {
			o.label = vectors.LabelDeviceAControl
		}
	}
	hdr := vectors.Header(o.class, o.suite, o.epoch, o.authorSeq,
		vectors.PrevHash(fmt.Sprint(o.authorSeq)), vectors.ZeroNonce, o.label)
	if o.workspace != nil {
		hdr.WorkspaceID = *o.workspace
	}
	if o.author != nil {
		hdr.AuthorMemberID = *o.author
	}
	// A distinct op id per (class, seq) so repeats are deliberate rather than
	// accidental.
	hdr.OpID = vectors.Bytes16(fmt.Sprintf("op/%d/%d", o.class, o.authorSeq))

	body, err := testprofile.Minimal().SizeClasses.PackBody(o.payload)
	if err != nil {
		h.t.Fatal(err)
	}
	if o.suite == wire.SuiteEncrypted {
		hdr.Nonce = vectors.Nonce(fmt.Sprint(o.authorSeq))
		body, err = wire.SealBody(hdr.Marshal(), vectors.ContentKey, body)
		if err != nil {
			h.t.Fatal(err)
		}
	}
	ns, _ := wire.NewNamespace(vectors.Namespace)
	env, err := wire.SignOp(vectors.SignPriv(o.label), ns.OpDomain(o.class, o.extName), hdr.Marshal(), body)
	if err != nil {
		h.t.Fatal(err)
	}
	return b64.EncodeToString(env)
}

func (h *harness) content(seq uint64) string {
	return h.op(opts{class: wire.ClassContent, suite: wire.SuiteNone, authorSeq: seq, payload: []byte("x")})
}

func (h *harness) prune(seq uint64, payload any) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.op(opts{class: wire.ClassPrune, suite: wire.SuiteNone, authorSeq: seq, payload: raw})
}

func wantCode(t *testing.T, r *oplog.Refusal, code codes.Code, index int) {
	t.Helper()
	if r == nil {
		t.Fatalf("expected %s, got acceptance", code)
	}
	if r.Code != code {
		t.Fatalf("got %s, want %s (fields %v)", r.Code, code, r.Fields)
	}
	if index >= 0 {
		if got, ok := r.Fields["index"]; !ok || got != index {
			t.Errorf("%s carries index %v, want %d", code, got, index)
		}
	} else if _, ok := r.Fields["index"]; ok {
		t.Errorf("%s carries an index, and names no op", code)
	}
}

// ── the observable ordering ─────────────────────────────────────────────────

// Stage 1 is a complete pass over every op before any op reaches stage 2, and
// that is protocol because it is observable.
func TestStage1IsACompletePass(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	h.auth.stage2 = func(op oplog.Op) *oplog.Refusal {
		return &oplog.Refusal{Status: 403, Code: codes.NoLiveGrant}
	}
	_, r := h.append(h.content(1), "not base64!!")
	wantCode(t, r, codes.MalformedBase64, 1)
}

// Stages 2 to 4 run per op in arrival order, so the earlier op's stage-3 failure
// answers before a later op's stage-2 one.
func TestStagesTwoToFourRunInArrivalOrder(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	// The prune's own class is permitted; the content op's is not. So index 0
	// reaches stage 3 and answers there, while index 1 would have answered at
	// stage 2 — which is the ordering the example pins.
	h.auth.stage2 = func(op oplog.Op) *oplog.Refusal {
		if op.Header().OpClass != wire.ClassContent {
			return nil
		}
		return &oplog.Refusal{Status: 403, Code: codes.NoLiveGrant}
	}
	empty := map[string]any{"type": "prune", "reprise": map[string]any{"op_id": uuid(vectors.Bytes16("r"))}, "targets": []any{}}
	_, r := h.append(h.prune(1, empty), h.content(2))
	wantCode(t, r, codes.PruneTargetsEmpty, 0)
}

// Within one op, the two selector bytes resolve before the floor, and
// truncated_envelope leads all three.
func TestStage1OrderWithinAnOp(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())

	_, r := h.append(b64.EncodeToString(make([]byte, 100)))
	wantCode(t, r, codes.TruncatedEnvelope, 0)

	// A header naming an unserved class, and far below the floor: the class
	// answers, not the length.
	hdr := vectors.Header(0x7F, wire.SuiteNone, 0, 1, vectors.ZeroHash, vectors.ZeroNonce, vectors.LabelDeviceAContent)
	short := append(hdr.Marshal(), make([]byte, wire.SigLen)...)
	_, r = h.append(b64.EncodeToString(short))
	wantCode(t, r, codes.UnsupportedOpClass, 0)

	// A served class with an unserved suite, still below the floor: the suite
	// answers, because the floor is the suite's.
	hdr = vectors.Header(wire.ClassContent, 0x02, 0, 1, vectors.ZeroHash, vectors.ZeroNonce, vectors.LabelDeviceAContent)
	short = append(hdr.Marshal(), make([]byte, wire.SigLen)...)
	_, r = h.append(b64.EncodeToString(short))
	wantCode(t, r, codes.UnsupportedSuite, 0)

	// Served class, served suite, no legal body could fit.
	hdr = vectors.Header(wire.ClassContent, wire.SuiteNone, 0, 1, vectors.ZeroHash, vectors.ZeroNonce, vectors.LabelDeviceAContent)
	short = append(hdr.Marshal(), make([]byte, wire.SigLen)...)
	_, r = h.append(b64.EncodeToString(short))
	wantCode(t, r, codes.EnvelopeTooShort, 0)
}

// Sealing a server-read class is forbidden for ever, and the first two get their
// own codes because a client that met one has learned something different.
func TestSealedServerReadClasses(t *testing.T) {
	h := newHarness(t, testprofile.Extended())
	for _, c := range []struct {
		class byte
		code  codes.Code
	}{
		{wire.ClassControl, codes.EncryptedControlOp},
		{wire.ClassPrune, codes.EncryptedPruneOp},
		{wire.ClassExtBinding, codes.EncryptedServerReadOp},
		{0xC5, codes.EncryptedServerReadOp},
	} {
		_, r := h.append(h.op(opts{class: c.class, suite: wire.SuiteEncrypted, epoch: 3, authorSeq: 1,
			payload: []byte("{}"), extName: "retention-sweep"}))
		wantCode(t, r, c.code, 0)
	}
}

// Parsed fields are checked against the envelope bytes, never trusted over them.
func TestHeaderCrossChecks(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())

	other := vectors.Bytes16("another-workspace")
	_, r := h.append(h.op(opts{class: wire.ClassContent, authorSeq: 1, payload: []byte("x"), workspace: &other}))
	wantCode(t, r, codes.WorkspaceMismatch, 0)

	stranger := vectors.MemberB
	_, r = h.append(h.op(opts{class: wire.ClassContent, authorSeq: 1, payload: []byte("x"), author: &stranger}))
	wantCode(t, r, codes.AuthorMemberMismatch, 0)

	// A content op signed with the control key: a positive match against an id
	// this device has held for the other class.
	_, r = h.append(h.op(opts{class: wire.ClassContent, authorSeq: 1, payload: []byte("x"),
		label: vectors.LabelDeviceAControl}))
	wantCode(t, r, codes.AuthorKeyClassMismatch, 0)
	if r.Fields["op_class"] != int(wire.ClassContent) {
		t.Errorf("author_key_class_mismatch carries op_class %v", r.Fields["op_class"])
	}
}

// An author_key_id the server holds no record of is not refused: that is the
// rotation the server declines to judge.
func TestUnknownAuthorKeyIsNotRefused(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	env := h.op(opts{class: wire.ClassContent, authorSeq: 1, payload: []byte("x"),
		label: vectors.LabelDeviceBContent})
	if _, r := h.append(env); r != nil {
		t.Fatalf("an unrecognised author_key_id was refused: %s", r.Code)
	}
}

// ── stage 0 ─────────────────────────────────────────────────────────────────

func TestBatchCeiling(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	h.p.Profile.Limits.MaxOpsPerBatch = 2
	_, r := h.append(h.content(1), h.content(2), h.content(3))
	wantCode(t, r, codes.BatchTooLarge, -1) // names no op
	if r.Fields["max_ops"] != 2 {
		t.Errorf("max_ops = %v", r.Fields["max_ops"])
	}
}

func TestEmptyBatch(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	res, r := h.append()
	if r != nil || len(res) != 0 {
		t.Errorf("res = %v, refusal = %v", res, r)
	}
}

// The access gate exempts an author's first op, and only its first.
func TestAccessGateCarveOut(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	stranger := memstore.New()
	h.p.Store = stranger
	stranger.Seed(h.ws, func(s memstore.Seeder) { s.Exists() })

	registers := func(op oplog.Op) bool { return op.Header().OpClass == wire.ClassControl }
	h.auth.establishes = registers

	_, r := h.append(h.content(1), h.op(opts{class: wire.ClassControl, authorSeq: 2, payload: []byte("{}")}))
	wantCode(t, r, codes.NoRegistration, -1)

	if _, r := h.append(h.op(opts{class: wire.ClassControl, authorSeq: 1, payload: []byte("{}")}), h.content(2)); r != nil {
		t.Fatalf("a batch whose first op establishes access was refused: %s", r.Code)
	}
}

// ── idempotency ─────────────────────────────────────────────────────────────

func TestRepeatsAreFree(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	one := h.content(1)

	res, r := h.append(one)
	if r != nil {
		t.Fatal(r.Code)
	}
	if res[0].Duplicate || res[0].Seq != 1 {
		t.Fatalf("first write: %+v", res[0])
	}

	res, r = h.append(one)
	if r != nil {
		t.Fatal(r.Code)
	}
	if !res[0].Duplicate || res[0].Seq != 1 {
		t.Errorf("a repeat in a later request: %+v", res[0])
	}
}

// Within one batch the first occurrence is not a repeat; every later one returns
// that same position.
func TestRepeatWithinOneBatch(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	one := h.content(1)
	res, r := h.append(one, one, one)
	if r != nil {
		t.Fatal(r.Code)
	}
	if res[0].Duplicate || res[0].Seq != 1 {
		t.Errorf("index 0: %+v", res[0])
	}
	for i := 1; i < 3; i++ {
		if !res[i].Duplicate || res[i].Seq != 1 {
			t.Errorf("index %d: %+v, want duplicate at position 1", i, res[i])
		}
	}
}

// The lookup sits after stage 1 and before stage 2, so a repeat is answered from
// the op already stored and stages 2 to 5 do not run for it.
func TestRepeatSkipsStagesTwoToFive(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	one := h.content(1)
	if _, r := h.append(one); r != nil {
		t.Fatal(r.Code)
	}

	// Everything that follows would refuse this op if it were judged again: no
	// grant, and an author_seq that is no longer the next one.
	h.auth.stage2 = func(op oplog.Op) *oplog.Refusal {
		return &oplog.Refusal{Status: 403, Code: codes.NoLiveGrant}
	}
	res, r := h.append(one)
	if r != nil {
		t.Fatalf("a repeat was re-judged: %s", r.Code)
	}
	if !res[0].Duplicate {
		t.Error("a repeat was not reported as one")
	}
}

// What sits above the lookup is not an exception to that. A repeat of a class
// the deployment has since disabled is unsupported_op_class: a server does not
// look an op up under a class it no longer serves.
func TestStage1RunsAboveTheLookup(t *testing.T) {
	h := newHarness(t, testprofile.Extended())
	ext := h.op(opts{class: 0xC5, suite: wire.SuiteNone, authorSeq: 1,
		payload: []byte(`{"x":1}`), extName: "retention-sweep"})

	// Bind the class so the op lands.
	bind, _ := json.Marshal(map[string]any{"type": "bind", "op_class": 197, "name": "retention-sweep"})
	if _, r := h.append(h.op(opts{class: wire.ClassExtBinding, authorSeq: 1, payload: bind})); r != nil {
		t.Fatal(r.Code)
	}
	ext = h.op(opts{class: 0xC5, suite: wire.SuiteNone, authorSeq: 2,
		payload: []byte(`{"x":1}`), extName: "retention-sweep"})
	if _, r := h.append(ext); r != nil {
		t.Fatal(r.Code)
	}

	// The deployment turns the class off, and the same bytes arrive again.
	h.p.Profile = testprofile.Minimal()
	_, r := h.append(ext)
	wantCode(t, r, codes.UnsupportedOpClass, 0)
}

// ── stage 5 ─────────────────────────────────────────────────────────────────

func TestAuthorChain(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	if _, r := h.append(h.content(1), h.content(2)); r != nil {
		t.Fatal(r.Code)
	}
	// A gap.
	_, r := h.append(h.content(4))
	wantCode(t, r, codes.AuthorChainConflict, 0)
	if r.Fields["author_seq"] != uint64(4) || r.Fields["expected_author_seq"] != uint64(3) {
		t.Errorf("fields = %v", r.Fields)
	}
}

// One refusal rejects every op in the request, including ops that would have
// been fine alone.
func TestBatchIsAllOrNothing(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	if _, r := h.append(h.content(1), h.content(3)); r == nil {
		t.Fatal("a batch with a chain gap committed")
	}
	if ops := h.store.Ops(h.ws); len(ops) != 0 {
		t.Errorf("%d ops survived a refused batch", len(ops))
	}
}

// Ops are stored byte-identical. The envelope is the truth; every field the
// server parsed out of it is an index.
func TestOpsAreStoredVerbatim(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	one := h.content(1)
	if _, r := h.append(one); r != nil {
		t.Fatal(r.Code)
	}
	raw, _ := b64.DecodeString(one)
	stored := h.store.Ops(h.ws)[0]
	if string(stored.Envelope) != string(raw) {
		t.Error("the stored envelope is not byte-identical to what was posted")
	}
	if stored.EnvelopeHash != wire.EnvelopeHash(raw) {
		t.Error("the stored envelope hash is not SHA-256 over the envelope bytes")
	}
}

// ── stage 3: prune ──────────────────────────────────────────────────────────

func uuid(b [16]byte) string { return vectors.UUID(b) }

func (h *harness) seedTargets(n int) []oplog.StoredOp {
	h.t.Helper()
	ops := make([]string, n)
	for i := range n {
		ops[i] = h.content(uint64(i + 1))
	}
	if _, r := h.append(ops...); r != nil {
		h.t.Fatal(r.Code)
	}
	return h.store.Ops(h.ws)
}

func target(op oplog.StoredOp) map[string]any {
	return map[string]any{
		"seq":              op.Seq,
		"author_member_id": uuid(op.Author),
		"author_seq":       op.AuthorSeq,
		"envelope_hash":    hex.EncodeToString(op.EnvelopeHash[:]),
	}
}

func TestPruneShapeRules(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	stored := h.seedTargets(2)
	reprise := map[string]any{"op_id": uuid(stored[0].OpID)}

	for _, c := range []struct {
		name    string
		targets []any
		code    codes.Code
	}{
		{"empty", []any{}, codes.PruneTargetsEmpty},
		{"duplicate by seq", []any{target(stored[0]), target(stored[0])}, codes.PruneDuplicateTarget},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, r := h.append(h.prune(3, map[string]any{
				"type": "prune", "reprise": reprise, "targets": c.targets}))
			wantCode(t, r, c.code, 0)
		})
	}

	// A duplicate by (author, author_seq) that is not a duplicate by seq.
	dup := target(stored[1])
	dup["seq"] = stored[0].Seq
	_, r := h.append(h.prune(3, map[string]any{
		"type": "prune", "reprise": reprise, "targets": []any{target(stored[1]), dup}}))
	wantCode(t, r, codes.PruneDuplicateTarget, 0)
}

func TestPruneUnknownType(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	_, r := h.append(h.prune(1, map[string]any{"type": "fold", "targets": []any{}}))
	wantCode(t, r, codes.UnsupportedPruneType, 0)

	// A payload that does not say what it is cannot be judged against anything.
	_, r = h.append(h.prune(1, map[string]any{"targets": []any{}}))
	wantCode(t, r, codes.MalformedPrunePayload, 0)

	// A reprise on a hard_prune is an unrecognised key, not a change of lane.
	_, r = h.append(h.prune(1, map[string]any{
		"type": "hard_prune", "reprise": map[string]any{"op_id": uuid(vectors.MemberA)}, "targets": []any{}}))
	wantCode(t, r, codes.MalformedPrunePayload, 0)
}

func TestPruneTargetRules(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	stored := h.seedTargets(2)
	reprise := map[string]any{"op_id": uuid(stored[0].OpID)}
	mk := func(targets ...any) string {
		return h.prune(3, map[string]any{"type": "prune", "reprise": reprise, "targets": targets})
	}

	missing := target(stored[0])
	missing["seq"] = int64(99)
	_, r := h.append(mk(missing))
	wantCode(t, r, codes.PruneTargetNotFound, 0)

	// The attestation is four fields, and any of them disagreeing is the same
	// verdict.
	forged := target(stored[1])
	forged["envelope_hash"] = hex.EncodeToString(make([]byte, 32))
	_, r = h.append(mk(forged))
	wantCode(t, r, codes.PruneTargetAttestationMismatch, 0)

	wrongSeq := target(stored[1])
	wrongSeq["author_seq"] = int64(99)
	_, r = h.append(mk(wrongSeq))
	wantCode(t, r, codes.PruneTargetAttestationMismatch, 0)

	// An op cannot reprise itself.
	_, r = h.append(mk(target(stored[0])))
	wantCode(t, r, codes.PruneTargetIsItsOwnReprise, 0)

	// A prune vouches for its own reprise; one that does not exist is refused
	// before any target is walked.
	_, r = h.append(h.prune(3, map[string]any{
		"type":    "prune",
		"reprise": map[string]any{"op_id": uuid(vectors.Bytes16("nothing"))},
		"targets": []any{target(stored[1])}}))
	wantCode(t, r, codes.PruneRepriseNotFound, 0)
}

func TestPruneMarksAndHardPruneDrops(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	stored := h.seedTargets(2)

	if _, r := h.append(h.prune(3, map[string]any{
		"type":    "prune",
		"reprise": map[string]any{"op_id": uuid(stored[0].OpID)},
		"targets": []any{target(stored[1])}})); r != nil {
		t.Fatal(r.Code)
	}
	after := h.store.Ops(h.ws)
	if !after[1].Reprised() || after[1].ReprisedBy != 3 {
		t.Fatalf("target was not marked: %+v", after[1])
	}
	// A prune deletes nothing.
	if after[1].Dropped() {
		t.Error("a soft prune destroyed bytes")
	}

	// Already reprised.
	_, r := h.append(h.prune(4, map[string]any{
		"type":    "prune",
		"reprise": map[string]any{"op_id": uuid(stored[0].OpID)},
		"targets": []any{target(after[1])}}))
	wantCode(t, r, codes.PruneTargetAlreadyReprised, 0)

	// hard_prune rule 4: the target must already be marked.
	_, r = h.append(h.prune(4, map[string]any{
		"type": "hard_prune", "targets": []any{target(after[0])}}))
	wantCode(t, r, codes.HardPruneTargetNotReprised, 0)

	// And rule 3 precedes rule 4: a prune target answers about being a prune,
	// never about a step that was skipped.
	_, r = h.append(h.prune(4, map[string]any{
		"type": "hard_prune", "targets": []any{target(after[2])}}))
	wantCode(t, r, codes.HardPruneTargetIsPrune, 0)

	// The bytes go, the tombstone stays.
	if _, r := h.append(h.prune(4, map[string]any{
		"type": "hard_prune", "targets": []any{target(after[1])}})); r != nil {
		t.Fatal(r.Code)
	}
	gone := h.store.Ops(h.ws)[1]
	if !gone.Dropped() {
		t.Error("hard_prune did not drop the envelope")
	}
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"seq", gone.Seq == after[1].Seq},
		{"op id", gone.OpID == after[1].OpID},
		{"author", gone.Author == after[1].Author},
		{"author seq", gone.AuthorSeq == after[1].AuthorSeq},
		{"class", gone.Class == after[1].Class},
		{"key epoch", gone.KeyEpoch == after[1].KeyEpoch},
		{"author key id", gone.AuthorKeyID == after[1].AuthorKeyID},
		{"reprised by", gone.ReprisedBy == after[1].ReprisedBy},
		{"envelope hash", gone.EnvelopeHash == after[1].EnvelopeHash},
	} {
		if !c.ok {
			t.Errorf("the tombstone lost its %s", c.name)
		}
	}

	// A repeat of the same hard_prune is not an error and applies nothing a
	// second time — but its attestation is still checked, against the hash the
	// tombstone retains.
	if _, r := h.append(h.prune(5, map[string]any{
		"type": "hard_prune", "targets": []any{target(after[1])}})); r != nil {
		t.Errorf("a repeated hard_prune was refused: %s", r.Code)
	}
	forged := target(after[1])
	forged["envelope_hash"] = hex.EncodeToString(make([]byte, 32))
	_, r = h.append(h.prune(6, map[string]any{"type": "hard_prune", "targets": []any{forged}}))
	wantCode(t, r, codes.PruneTargetAttestationMismatch, 0)
}

// The role verdict sits after the shape rules, not before them.
func TestRoleVerdictFollowsShape(t *testing.T) {
	h := newHarness(t, testprofile.Minimal())
	h.auth.pruneTypes = func(typ string) *oplog.Refusal {
		if typ == wire.PruneSoft {
			return nil
		}
		return &oplog.Refusal{Status: 403, Code: codes.RoleForbidsPruneType,
			Fields: map[string]any{"prune_type": typ}}
	}
	// Empty targets from a role holding bare 0x81 answers about the shape.
	_, r := h.append(h.prune(1, map[string]any{"type": "hard_prune", "targets": []any{}}))
	wantCode(t, r, codes.PruneTargetsEmpty, 0)

	// With a well-formed payload, the role answers.
	stored := h.seedTargets(1)
	_, r = h.append(h.prune(2, map[string]any{"type": "hard_prune", "targets": []any{target(stored[0])}}))
	wantCode(t, r, codes.RoleForbidsPruneType, 0)
}

// ── stage 3: ext_binding ────────────────────────────────────────────────────

func TestExtBinding(t *testing.T) {
	h := newHarness(t, testprofile.Extended())
	bind := func(seq uint64, class int, name string) string {
		raw, _ := json.Marshal(map[string]any{"type": "bind", "op_class": class, "name": name})
		return h.op(opts{class: wire.ClassExtBinding, authorSeq: seq, payload: raw})
	}
	unbind := func(seq uint64, class int) string {
		raw, _ := json.Marshal(map[string]any{"type": "unbind", "op_class": class})
		return h.op(opts{class: wire.ClassExtBinding, authorSeq: seq, payload: raw})
	}

	// A class the deployment does not permit. Distinct from unsupported_op_class,
	// which answers about the op's own class.
	_, r := h.append(bind(1, 200, "whatever"))
	wantCode(t, r, codes.ExtClassNotEnabled, 0)
	if r.Fields["op_class"] != 200 {
		t.Errorf("ext_class_not_enabled carries op_class %v", r.Fields["op_class"])
	}

	// A class is never bound under a name the server does not agree with.
	_, r = h.append(bind(1, 197, "publish-to-world"))
	wantCode(t, r, codes.ExtNameMismatch, 0)
	if r.Fields["expected"] != "retention-sweep" {
		t.Errorf("ext_name_mismatch expected %v", r.Fields["expected"])
	}

	if _, r := h.append(bind(1, 197, "retention-sweep")); r != nil {
		t.Fatal(r.Code)
	}
	_, r = h.append(bind(2, 197, "retention-sweep"))
	wantCode(t, r, codes.ExtClassAlreadyBound, 0)

	if _, r := h.append(unbind(2, 197)); r != nil {
		t.Fatal(r.Code)
	}
	_, r = h.append(unbind(3, 197))
	wantCode(t, r, codes.ExtClassNotBound, 0)
}

// A binding takes effect from its own position, decided by arrival order within
// a batch rather than by the batch as a whole.
func TestExtBindingTakesEffectByArrivalOrder(t *testing.T) {
	bindOp := func(h *harness, seq uint64) string {
		raw, _ := json.Marshal(map[string]any{"type": "bind", "op_class": 197, "name": "retention-sweep"})
		return h.op(opts{class: wire.ClassExtBinding, authorSeq: seq, payload: raw})
	}
	extOp := func(h *harness, seq uint64) string {
		return h.op(opts{class: 0xC5, authorSeq: seq, payload: []byte(`{"x":1}`), extName: "retention-sweep"})
	}

	h := newHarness(t, testprofile.Extended())
	if _, r := h.append(bindOp(h, 1), extOp(h, 2)); r != nil {
		t.Fatalf("[bind, op] was refused: %s", r.Code)
	}

	h = newHarness(t, testprofile.Extended())
	_, r := h.append(extOp(h, 1), bindOp(h, 2))
	wantCode(t, r, codes.ExtClassNotActive, 0)
}

// ── prune_ext ───────────────────────────────────────────────────────────────

// Meaning is positional, so removal is too: an op is folded under the meaning it
// was written with or not at all.
func TestPruneExtNameCheckIsPositional(t *testing.T) {
	h := newHarness(t, testprofile.Extended())
	bind := func(seq uint64, name string) string {
		raw, _ := json.Marshal(map[string]any{"type": "bind", "op_class": 197, "name": name})
		return h.op(opts{class: wire.ClassExtBinding, authorSeq: seq, payload: raw})
	}
	ext := func(seq uint64) string {
		return h.op(opts{class: 0xC5, authorSeq: seq, payload: []byte(`{"x":1}`), extName: "retention-sweep"})
	}
	if _, r := h.append(bind(1, "retention-sweep"), ext(2)); r != nil {
		t.Fatal(r.Code)
	}
	stored := h.store.Ops(h.ws)

	// The right class and the right NAME.
	if _, r := h.append(h.prune(3, map[string]any{
		"type": "prune_ext", "op_class": 197, "name": "retention-sweep",
		"targets": []any{target(stored[1])}})); r != nil {
		t.Fatalf("a correct prune_ext was refused: %s (%v)", r.Code, r.Fields)
	}

	// An ordinary prune cannot reach an extension class at all.
	h2 := newHarness(t, testprofile.Extended())
	if _, r := h2.append(bind(1, "retention-sweep")); r != nil {
		t.Fatal(r.Code)
	}
	if _, r := h2.append(h2.op(opts{class: 0xC5, authorSeq: 2, payload: []byte(`{"x":1}`), extName: "retention-sweep"})); r != nil {
		t.Fatal(r.Code)
	}
	s2 := h2.store.Ops(h2.ws)
	_, r := h2.append(h2.prune(3, map[string]any{
		"type": "prune", "reprise": map[string]any{"op_id": uuid(s2[0].OpID)},
		"targets": []any{target(s2[1])}}))
	wantCode(t, r, codes.PruneTargetIsServerRead, 0)

	// The wrong NAME, carrying the one that was in force there.
	h3 := newHarness(t, testprofile.Extended())
	if _, r := h3.append(bind(1, "retention-sweep")); r != nil {
		t.Fatal(r.Code)
	}
	if _, r := h3.append(h3.op(opts{class: 0xC5, authorSeq: 2, payload: []byte(`{"x":1}`), extName: "retention-sweep"})); r != nil {
		t.Fatal(r.Code)
	}
	s3 := h3.store.Ops(h3.ws)
	_, r = h3.append(h3.prune(3, map[string]any{
		"type": "prune_ext", "op_class": 197, "name": "copy",
		"targets": []any{target(s3[1])}}))
	wantCode(t, r, codes.PruneExtNameMismatch, 0)
	if r.Fields["expected"] != "retention-sweep" || r.Fields["seq"] != s3[1].Seq {
		t.Errorf("fields = %v", r.Fields)
	}

	// The attestation precedes the name check. Rule 7 reads state belonging to the
	// op actually stored — its author's bindings, not the author the payload
	// claims — so it is only worth asking once the author has proved which op they
	// mean. A target that gets both wrong must answer about the attestation, not
	// about a member the payload never named.
	both := target(s3[1])
	both["author_member_id"] = uuid(vectors.MemberB)
	_, r = h3.append(h3.prune(3, map[string]any{
		"type": "prune_ext", "op_class": 197, "name": "copy",
		"targets": []any{both}}))
	wantCode(t, r, codes.PruneTargetAttestationMismatch, 0)

	// A target of another class than the one named.
	_, r = h3.append(h3.prune(3, map[string]any{
		"type": "prune_ext", "op_class": 197, "name": "retention-sweep",
		"targets": []any{target(s3[0])}}))
	wantCode(t, r, codes.PruneTargetIsServerRead, 0)
}

// 0xBF is not foldable, by any type, ever. It is the record of what a class
// meant over a span of positions, and the name check reads that record.
func TestExtBindingIsNeverATarget(t *testing.T) {
	h := newHarness(t, testprofile.Extended())
	raw, _ := json.Marshal(map[string]any{"type": "bind", "op_class": 197, "name": "retention-sweep"})
	if _, r := h.append(h.op(opts{class: wire.ClassExtBinding, authorSeq: 1, payload: raw})); r != nil {
		t.Fatal(r.Code)
	}
	stored := h.store.Ops(h.ws)
	_, r := h.append(h.prune(2, map[string]any{
		"type": "prune_ext", "op_class": 197, "name": "retention-sweep",
		"targets": []any{target(stored[0])}}))
	wantCode(t, r, codes.PruneTargetIsServerRead, 0)
}
