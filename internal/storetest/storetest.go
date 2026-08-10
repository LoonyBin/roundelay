// Package storetest is the contract every store implementation must satisfy.
//
// It exists because there are now two of them. "The server is storage-agnostic"
// is a property of the specification, and it only becomes a property of this
// codebase if the same suite runs against both — otherwise the two drift, and
// the drift surfaces as a deployment that passes conformance on one store and
// fails on the other.
//
// Nothing here reaches past the interfaces. A test that needed a concrete type
// would be testing an implementation rather than the contract.
package storetest

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/keyplane"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
)

// Suite is the set of stores under test. A store that does not implement a
// plane leaves its field nil and those cases are skipped.
type Suite struct {
	Log      oplog.Store
	Identity identity.Store
	Vault    keyplane.VaultStore
	// Fresh returns a Workspace id nothing has touched, so cases do not collide
	// in a store that persists between them.
	Fresh func() [16]byte

	salt [16]byte
}

// Run executes the whole contract.
func Run(t *testing.T, s Suite) {
	t.Helper()
	// Every id the suite uses is salted, not only the Workspace ones.
	//
	// A store that persists between runs — which is the interesting one — carries
	// the identity and vault planes forward too, and those are keyed globally
	// rather than per Workspace. Fixed ids there pass against an in-memory store
	// and fail against a real one on the second run, which is exactly the drift
	// this suite exists to catch.
	s.salt = s.Fresh()
	t.Run("positions", s.testPositions)
	t.Run("uniqueness", s.testUniqueness)
	t.Run("rollback", s.testRollback)
	t.Run("tombstone", s.testTombstone)
	t.Run("reads", s.testReads)
	t.Run("members", s.testMembers)
	t.Run("intervals", s.testIntervals)
	t.Run("grants", s.testGrants)
	t.Run("roletable", s.testRoleTable)
	t.Run("keyplane", s.testKeyplane)
	if s.Identity != nil {
		t.Run("identity", s.testIdentity)
	}
	if s.Vault != nil {
		t.Run("vault", s.testVault)
	}
}

// id16 and id32 mix the run's salt in, so the same case run twice against a
// persistent store touches different rows.
func (s Suite) id16(n int) [16]byte {
	var out [16]byte
	copy(out[:8], s.salt[:8])
	binary.BigEndian.PutUint64(out[8:], uint64(n))
	return out
}

func (s Suite) id32(n int) [32]byte {
	var out [32]byte
	copy(out[:8], s.salt[:8])
	binary.BigEndian.PutUint64(out[24:], uint64(n))
	return out
}

func fill(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// op builds a StoredOp for an author's next position.
func (s Suite) op(author [16]byte, authorSeq uint64, class byte) oplog.StoredOp {
	return oplog.StoredOp{
		Class: class, OpID: s.id16(int(authorSeq) * 1000), Author: author,
		AuthorSeq: authorSeq, EnvelopeHash: s.id32(int(authorSeq)),
		Envelope: fill(32, byte(authorSeq)),
	}
}

func (s Suite) begin(t *testing.T, ws [16]byte) oplog.Tx {
	t.Helper()
	tx, err := s.Log.BeginAppend(t.Context(), ws)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	return tx
}

func (s Suite) read(t *testing.T, ws [16]byte) oplog.ReadTx {
	t.Helper()
	tx, err := s.Log.BeginRead(t.Context(), ws)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	return tx
}

// ── positions ───────────────────────────────────────────────────────────────

// Positions are contiguous from 1 and allocated inside the transaction, so a
// rolled-back batch consumes none.
func (s Suite) testPositions(t *testing.T) {
	ws := s.Fresh()
	author := s.id16(1)

	tx := s.begin(t, ws)
	for i := 1; i <= 3; i++ {
		got, err := tx.Append(s.op(author, uint64(i), 0x01))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if got != int64(i) {
			t.Fatalf("append %d landed at %d", i, got)
		}
	}
	if next, _ := tx.NextSeq(); next != 4 {
		t.Errorf("next_seq = %d, want 4", next)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// A rolled-back batch burns no positions: the counter moved inside the
	// transaction that discarded it.
	tx = s.begin(t, ws)
	if _, err := tx.Append(s.op(author, 4, 0x01)); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()

	tx = s.begin(t, ws)
	defer tx.Rollback()
	if next, _ := tx.NextSeq(); next != 4 {
		t.Errorf("after a rollback next_seq = %d, want 4", next)
	}
}

// ── uniqueness ──────────────────────────────────────────────────────────────

// Both rules are enforced by the storage layer, not by application code.
func (s Suite) testUniqueness(t *testing.T) {
	ws := s.Fresh()
	author := s.id16(1)

	tx := s.begin(t, ws)
	first := s.op(author, 1, 0x01)
	if _, err := tx.Append(first); err != nil {
		t.Fatal(err)
	}
	// The same (author, op_id).
	dup := s.op(author, 2, 0x01)
	dup.OpID = first.OpID
	if _, err := tx.Append(dup); err == nil {
		t.Error("a duplicate (workspace, author, op_id) was stored")
	}
	_ = tx.Rollback()

	tx = s.begin(t, ws)
	if _, err := tx.Append(s.op(author, 1, 0x01)); err != nil {
		t.Fatal(err)
	}
	// The same (author, author_seq).
	fork := s.op(author, 1, 0x01)
	fork.OpID = s.id16(999)
	if _, err := tx.Append(fork); err == nil {
		t.Error("a forked author chain was stored")
	}
	_ = tx.Rollback()
}

// ── rollback ────────────────────────────────────────────────────────────────

// The whole batch commits, or none of it does.
func (s Suite) testRollback(t *testing.T) {
	ws := s.Fresh()
	author := s.id16(1)

	tx := s.begin(t, ws)
	if _, err := tx.Append(s.op(author, 1, 0x01)); err != nil {
		t.Fatal(err)
	}
	if err := tx.PutGrant(oplog.Grant{GrantID: s.id16(7), Member: author, Role: "owner", Start: 1}); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkGenesis(1); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()

	rd := s.read(t, ws)
	defer rd.Close()
	if exists, _ := rd.WorkspaceExists(); exists {
		t.Error("a rolled-back genesis survived")
	}
	page, err := rd.ReadOps(0, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Ops) != 0 {
		t.Errorf("%d ops survived a rollback", len(page.Ops))
	}
	if had, _ := rd.HasAnyGrant(author); had {
		t.Error("a rolled-back grant survived")
	}
}

// ── the tombstone ───────────────────────────────────────────────────────────

// A hard_prune drops the envelope bytes and keeps every other fact on the row.
func (s Suite) testTombstone(t *testing.T) {
	ws := s.Fresh()
	author := s.id16(1)

	tx := s.begin(t, ws)
	before := s.op(author, 1, 0x01)
	if _, err := tx.Append(before); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Append(s.op(author, 2, 0x81)); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkReprised(1, 2); err != nil {
		t.Fatal(err)
	}
	if err := tx.DropEnvelope(1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tx = s.begin(t, ws)
	defer tx.Rollback()
	got, found, err := tx.OpAt(1)
	if err != nil || !found {
		t.Fatalf("the tombstone is not found: %v %v", found, err)
	}
	if !got.Dropped() {
		t.Error("the bytes were not dropped")
	}
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"seq", got.Seq == 1},
		{"class", got.Class == before.Class},
		{"key epoch", got.KeyEpoch == before.KeyEpoch},
		{"op id", got.OpID == before.OpID},
		{"author", got.Author == before.Author},
		{"author key id", got.AuthorKeyID == before.AuthorKeyID},
		{"author seq", got.AuthorSeq == before.AuthorSeq},
		{"reprised by", got.ReprisedBy == 2},
		{"envelope hash", got.EnvelopeHash == before.EnvelopeHash},
	} {
		if !c.ok {
			t.Errorf("the tombstone lost its %s", c.name)
		}
	}
	// Uniqueness still refuses a re-append, so a destroyed op cannot be
	// resurrected as a new one.
	if _, err := tx.Append(s.op(author, 1, 0x01)); err == nil {
		t.Error("a destroyed op was resurrected")
	}
}

// ── reads ───────────────────────────────────────────────────────────────────

func (s Suite) testReads(t *testing.T) {
	ws := s.Fresh()
	author := s.id16(1)

	tx := s.begin(t, ws)
	for i := 1; i <= 5; i++ {
		if _, err := tx.Append(s.op(author, uint64(i), 0x01)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.MarkReprised(3, 5); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rd := s.read(t, ws)
	defer rd.Close()

	seqs := func(p oplog.Page) []int64 {
		out := make([]int64, 0, len(p.Ops))
		for _, o := range p.Ops {
			out = append(out, o.Seq)
		}
		return out
	}

	p, _ := rd.ReadOps(0, 10, false)
	if got := seqs(p); len(got) != 4 || got[2] != 4 {
		t.Errorf("default read = %v, want the marked op hidden", got)
	}
	if p.HasMore {
		t.Error("has_more true on a complete page")
	}
	p, _ = rd.ReadOps(0, 10, true)
	if got := seqs(p); len(got) != 5 {
		t.Errorf("history view = %v", got)
	}

	// since is exclusive.
	p, _ = rd.ReadOps(2, 10, true)
	if got := seqs(p); len(got) != 3 || got[0] != 3 {
		t.Errorf("since=2 gave %v", got)
	}

	// has_more is exact, and counts servable entries only: a page ending at 2
	// with 3 hidden and 4 servable answers true.
	p, _ = rd.ReadOps(0, 2, false)
	if got := seqs(p); len(got) != 2 || !p.HasMore {
		t.Errorf("limit=2 gave %v has_more=%v", got, p.HasMore)
	}
	p, _ = rd.ReadOps(2, 2, false)
	if got := seqs(p); len(got) != 2 || got[0] != 4 || p.HasMore {
		t.Errorf("the last filtered page gave %v has_more=%v", got, p.HasMore)
	}
	p, _ = rd.ReadOps(5, 10, true)
	if len(p.Ops) != 0 || p.HasMore {
		t.Errorf("past the end gave %v has_more=%v", seqs(p), p.HasMore)
	}
}

// ── members ─────────────────────────────────────────────────────────────────

// Ordered by raw member id bytes as unsigned, which is not the order a base64
// spelling or a signed 64-bit comparison of two halves gives.
func (s Suite) testMembers(t *testing.T) {
	ws := s.Fresh()
	low := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	high := [16]byte{0xd0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	tx := s.begin(t, ws)
	for _, m := range [][16]byte{high, low} {
		if err := tx.PutRegistration(oplog.MemberRecord{
			MemberID: m, Kind: "device", ControlPK: s.id32(int(m[0])),
			ContentPK: s.id32(int(m[0]) + 1), KexPK: s.id32(int(m[0]) + 2),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rd := s.read(t, ws)
	defer rd.Close()
	page, err := rd.ReadMembers(nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Members) != 2 {
		t.Fatalf("%d members", len(page.Members))
	}
	if !bytes.Equal(page.Members[0].MemberID[:], low[:]) {
		t.Errorf("first is %x; 0x00… sorts before 0xd0… as unsigned bytes", page.Members[0].MemberID)
	}

	// after is exclusive, and a position rather than a lookup: a value naming no
	// member is legal.
	page, _ = rd.ReadMembers(&low, 10)
	if len(page.Members) != 1 || page.Members[0].MemberID != high {
		t.Errorf("after=low gave %d members", len(page.Members))
	}
	nobody := s.id16(0x7777)
	if _, err := rd.ReadMembers(&nobody, 10); err != nil {
		t.Errorf("an after naming no member was refused: %v", err)
	}
	page, _ = rd.ReadMembers(nil, 1)
	if !page.HasMore {
		t.Error("has_more false with a further member")
	}
}

// ── key intervals ───────────────────────────────────────────────────────────

// An amend closes the interval at its own position and opens the next there.
// Every op below keeps resolving to the key it was signed with.
func (s Suite) testIntervals(t *testing.T) {
	ws := s.Fresh()
	member := s.id16(1)
	old, next := s.id32(10), s.id32(11)

	tx := s.begin(t, ws)
	if err := tx.PutRegistration(oplog.MemberRecord{
		MemberID: member, Kind: "device", ControlPK: old, ContentPK: s.id32(2), KexPK: s.id32(3),
		RegisteredAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.PutAmend(member, s.id16(9), &oplog.KeyChange{PK: next, KeyID: [8]byte{9}}, nil, nil, 5); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tx = s.begin(t, ws)
	defer tx.Rollback()
	for _, c := range []struct {
		at   int64
		want [32]byte
	}{{1, old}, {4, old}, {5, next}, {99, next}} {
		got, ok, err := tx.ControlKeyAt(member, c.at)
		if err != nil || !ok {
			t.Fatalf("at %d: %v %v", c.at, ok, err)
		}
		if got != c.want {
			t.Errorf("at %d resolved to the wrong key", c.at)
		}
	}
	// Every id the device has held for the class, never only the registration's:
	// an amend must not turn an honest stale client into a class mismatch.
	ids, err := tx.KeyIDsHeldForClass(member, oplog.ControlSigning)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Errorf("held control key ids = %d, want 2", len(ids))
	}
	if used, _ := tx.AmendIDUsed(s.id16(9)); !used {
		t.Error("the amend id was not booked")
	}
}

// ── grants and delegations ──────────────────────────────────────────────────

func (s Suite) testGrants(t *testing.T) {
	ws := s.Fresh()
	member := s.id16(1)

	tx := s.begin(t, ws)
	if err := tx.PutGrant(oplog.Grant{
		GrantID: s.id16(7), Member: member, Role: "owner", GranterIsRoot: true, Start: 13,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.CloseGrant(s.id16(7), 18); err != nil {
		t.Fatal(err)
	}
	// The end position is write-once: moving it forward would widen the window
	// an already-revoked grant covers.
	if err := tx.CloseGrant(s.id16(7), 20); err == nil {
		t.Error("a grant's end position was rewritten")
	}
	if err := tx.PutDelegation(oplog.Delegation{DelegationID: s.id16(8), PK: s.id32(4), Start: 13}); err != nil {
		t.Fatal(err)
	}
	if err := tx.CloseDelegation(s.id16(8), 18); err != nil {
		t.Fatal(err)
	}
	if err := tx.CloseDelegation(s.id16(8), 20); err == nil {
		t.Error("a delegation's end position was rewritten")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tx = s.begin(t, ws)
	defer tx.Rollback()
	// Both bounds are strict.
	for _, c := range []struct {
		at   int64
		live bool
	}{{13, false}, {14, true}, {17, true}, {18, false}} {
		grants, err := tx.LiveGrantsAt(member, c.at)
		if err != nil {
			t.Fatal(err)
		}
		if (len(grants) > 0) != c.live {
			t.Errorf("grant live at %d = %v, want %v", c.at, len(grants) > 0, c.live)
		}
		dels, err := tx.LiveDelegationsAt(c.at)
		if err != nil {
			t.Fatal(err)
		}
		if (len(dels) > 0) != c.live {
			t.Errorf("delegation live at %d = %v, want %v", c.at, len(dels) > 0, c.live)
		}
	}
	// A device that held a grant and holds none live is revoked; the row is what
	// says so.
	if had, _ := tx.HasAnyGrant(member); !had {
		t.Error("a closed grant stopped counting as ever having existed")
	}
	if _, found, _ := tx.GrantByID(s.id16(7)); !found {
		t.Error("a closed grant vanished")
	}
}

// ── the role table ──────────────────────────────────────────────────────────

// The table in force at a position is the one carried by the latest role_table
// op below it.
func (s Suite) testRoleTable(t *testing.T) {
	ws := s.Fresh()

	tx := s.begin(t, ws)
	if _, ok, err := tx.RoleTableAt(1); err != nil || ok {
		t.Errorf("an empty log reported a table: %v %v", ok, err)
	}
	first := profile.RoleTable{"owner": {Classes: []byte{0x01}}}
	second := profile.RoleTable{"owner": {Classes: []byte{0x01, 0x02}, PruneTypes: []string{"prune"}}}
	if err := tx.PutRoleTable(first, 5); err != nil {
		t.Fatal(err)
	}
	if err := tx.PutRoleTable(second, 10); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tx = s.begin(t, ws)
	defer tx.Rollback()
	for _, c := range []struct {
		at      int64
		ok      bool
		classes int
	}{{5, false, 0}, {6, true, 1}, {10, true, 1}, {11, true, 2}} {
		table, ok, err := tx.RoleTableAt(c.at)
		if err != nil {
			t.Fatal(err)
		}
		if ok != c.ok {
			t.Errorf("at %d: ok = %v, want %v", c.at, ok, c.ok)
			continue
		}
		if ok && len(table["owner"].Classes) != c.classes {
			t.Errorf("at %d: %d classes, want %d", c.at, len(table["owner"].Classes), c.classes)
		}
	}
}

// ── the key plane ───────────────────────────────────────────────────────────

func (s Suite) testKeyplane(t *testing.T) {
	ws := s.Fresh()
	member, other := s.id16(1), s.id16(2)

	tx := s.begin(t, ws)
	for _, m := range [][16]byte{member, other} {
		if err := tx.PutRegistration(oplog.MemberRecord{
			MemberID: m, Kind: "device", ControlPK: s.id32(int(m[15])),
			ContentPK: s.id32(int(m[15]) + 10), KexPK: s.id32(int(m[15]) + 20),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A rotate materialises the record; the escrow wrap arrives later.
	if err := tx.PutRotate(0, 1, s.id32(77), 3); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tx = s.begin(t, ws)
	rec, ok, err := tx.EpochRecord(1)
	if err != nil || !ok {
		t.Fatalf("the rotate did not materialise: %v %v", ok, err)
	}
	if rec.Published || rec.EscrowWrap != nil {
		t.Error("an unpublished epoch reported a wrap set")
	}
	if cur, _ := tx.CurrentEpoch(); cur != 1 {
		t.Errorf("current epoch = %d, want 1", cur)
	}
	if err := tx.PublishWraps(1, s.id32(77), fill(72, 0xEE), []oplog.MemberWrap{
		{Epoch: 1, Member: member, KexKeyID: [8]byte{1}, Wrap: fill(104, 1)},
		{Epoch: 1, Member: other, KexKeyID: [8]byte{2}, Wrap: fill(104, 2)},
	}); err != nil {
		t.Fatal(err)
	}
	// A second rotate with no wraps: the window the omission rule exists for.
	if err := tx.PutRotate(1, 2, s.id32(88), 9); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rd := s.read(t, ws)
	defer rd.Close()

	wraps, err := rd.ReadMemberWraps(member, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(wraps.Wraps) != 1 || wraps.Wraps[0].Member != member {
		t.Errorf("keywraps/me is not scoped to the caller: %+v", wraps.Wraps)
	}

	epochs, err := rd.ReadEpochKeys(nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(epochs.Epochs) != 1 || epochs.Epochs[0].Epoch != 1 {
		t.Errorf("epoch-keys = %+v, want epoch 1 only with 2 omitted", epochs.Epochs)
	}

	// after_epoch is exclusive and has no default: absent means from the start.
	zero := uint32(0)
	if p, _ := rd.ReadMemberWraps(member, &zero, 10); len(p.Wraps) != 1 {
		t.Errorf("after_epoch=0 gave %d wraps", len(p.Wraps))
	}
	one := uint32(1)
	if p, _ := rd.ReadMemberWraps(member, &one, 10); len(p.Wraps) != 0 {
		t.Errorf("after_epoch=1 gave %d wraps", len(p.Wraps))
	}
}

// ── identity ────────────────────────────────────────────────────────────────

func (s Suite) testIdentity(t *testing.T) {
	ctx := t.Context()
	dev := identity.Device{MemberID: s.id16(500), ControlPK: s.id32(1), ContentPK: s.id32(2), KexPK: s.id32(3)}
	if err := s.Identity.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Identity.Device(ctx, dev.MemberID)
	if err != nil || !ok || *got != dev {
		t.Fatalf("device round trip: %+v %v %v", got, ok, err)
	}

	// A shell falls back to its registered key, or the founding ceremony could
	// not begin.
	keys, err := s.Identity.ControlKeysInForce(ctx, dev.MemberID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != dev.ControlPK {
		t.Errorf("a shell's control keys = %v", keys)
	}

	now := time.Unix(1700000000, 0)
	nonce := s.id32(42)
	if err := s.Identity.PutChallenge(ctx, dev.MemberID, nonce, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Spent by the attempt, win or lose.
	gotNonce, live, err := s.Identity.TakeChallenge(ctx, dev.MemberID, now)
	if err != nil || !live || gotNonce != nonce {
		t.Fatalf("take challenge: %v %v", live, err)
	}
	if _, live, _ := s.Identity.TakeChallenge(ctx, dev.MemberID, now); live {
		t.Error("a spent challenge was reusable")
	}
	// And expiry is enforced.
	if err := s.Identity.PutChallenge(ctx, dev.MemberID, nonce, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, live, _ := s.Identity.TakeChallenge(ctx, dev.MemberID, now.Add(2*time.Minute)); live {
		t.Error("an expired challenge was live")
	}

	// Fixed window: it opens at the first counted request and is not extended.
	key := s.id16(501)
	for i := range 2 {
		ok, _, err := s.Identity.CountChallenge(ctx, key, now, time.Minute, 2)
		if err != nil || !ok {
			t.Fatalf("count %d: %v %v", i, ok, err)
		}
	}
	ok, retry, err := s.Identity.CountChallenge(ctx, key, now.Add(30*time.Second), time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the limit did not bite")
	}
	if retry.Round(time.Second) != 30*time.Second {
		t.Errorf("retry = %v, want 30s of the original window", retry)
	}
	if ok, _, _ := s.Identity.CountChallenge(ctx, key, now.Add(61*time.Second), time.Minute, 2); !ok {
		t.Error("the window did not reopen")
	}

	// Refresh tokens: single-use, scoped, and consumed only on success.
	hash := s.id32(900)
	if err := s.Identity.PutRefresh(ctx, hash, dev.MemberID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Identity.TakeRefresh(ctx, hash, s.id16(999), now); got {
		t.Error("a refresh token was spendable by another device")
	}
	if got, _ := s.Identity.TakeRefresh(ctx, hash, dev.MemberID, now); !got {
		t.Error("a wrong-device attempt consumed the token")
	}
	if got, _ := s.Identity.TakeRefresh(ctx, hash, dev.MemberID, now); got {
		t.Error("a refresh token was reusable")
	}

	// The cascade's reach.
	if err := s.Identity.PutRefresh(ctx, s.id32(901), dev.MemberID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Identity.RevokeRefreshFor(ctx, dev.MemberID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Identity.TakeRefresh(ctx, s.id32(901), dev.MemberID, now); got {
		t.Error("the cascade left a live refresh token")
	}
}

// ── the vault ───────────────────────────────────────────────────────────────

func (s Suite) testVault(t *testing.T) {
	ctx := t.Context()
	locator := s.id32(600)
	root, successor := s.id32(601), s.id32(602)

	if _, found, err := s.Vault.Slot(ctx, locator); err != nil || found {
		t.Fatalf("a fresh locator held something: %v %v", found, err)
	}

	first := keyplane.Slot{Locator: locator, Version: 1, Blob: fill(64, 1), PinnedRoot: root}
	won, err := s.Vault.PutSlot(ctx, first, 0)
	if err != nil || !won {
		t.Fatalf("first write: %v %v", won, err)
	}
	// A create races with itself: expected 0 twice, exactly one winner.
	if won, _ := s.Vault.PutSlot(ctx, first, 0); won {
		t.Error("two creates both won")
	}

	// A later write must name the version it read.
	second := keyplane.Slot{Locator: locator, Version: 2, Blob: fill(64, 2), PinnedRoot: successor}
	if won, _ := s.Vault.PutSlot(ctx, second, 1); !won {
		t.Error("a correct compare-and-set lost")
	}
	if won, _ := s.Vault.PutSlot(ctx, second, 1); won {
		t.Error("a stale compare-and-set won")
	}
	got, _, err := s.Vault.Slot(ctx, locator)
	if err != nil {
		t.Fatal(err)
	}
	// The pin moves with the write that installed it.
	if got.Version != 2 || got.PinnedRoot != successor {
		t.Errorf("slot = version %d pin %x", got.Version, got.PinnedRoot[:4])
	}
	// The blob is stored verbatim and never length-checked.
	if !bytes.Equal(got.Blob, fill(64, 2)) {
		t.Error("the blob did not round-trip")
	}
	for _, n := range []int{0, 1, 500} {
		loc := s.id32(700 + n)
		s.Vault.PutSlot(ctx, keyplane.Slot{Locator: loc, Version: 1, Blob: fill(n, 3), PinnedRoot: root}, 0)
		back, _, err := s.Vault.Slot(ctx, loc)
		if err != nil || back == nil || len(back.Blob) != n {
			t.Errorf("a blob of %d bytes did not round-trip", n)
		}
	}

	// The audit is append-only, one row per read served.
	if err := s.Vault.RecordFetch(ctx, locator, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Vault.RecordFetch(ctx, locator, time.Unix(1700000001, 0)); err != nil {
		t.Fatal(err)
	}
}
