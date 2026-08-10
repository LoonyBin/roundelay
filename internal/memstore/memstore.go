// Package memstore is an in-memory oplog.Store for tests and single-process
// deployments.
//
// It takes the Workspace's lock for the whole transaction, which is the
// heavy-handed version of what the ordering rule demands: positions allocated
// under the same serialisation as the commit, so a read can never return
// position S while a lower position is still uncommitted. A Postgres store
// bumps a per-Workspace counter row inside the append transaction instead, and
// gets the same property from the row lock.
//
// Rollback is exact because a transaction mutates a clone and Commit swaps it
// in. That is not how a real store works, and it is why this one is honest
// about being a test store.
package memstore

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

type bindingKey struct {
	member [16]byte
	class  byte
}

type interval struct {
	name  string
	start int64
	end   int64 // 0 while open; write-once
}

type keyKey struct {
	member [16]byte
	class  oplog.SigningClass
}

type keyInterval struct {
	pk    [32]byte
	start int64
	end   int64 // 0 while open; write-once
}

type roleTableRow struct {
	at    int64
	table profile.RoleTable
}

type state struct {
	ops        []*oplog.StoredOp // index is seq-1
	exists     bool
	genesisAt  int64
	root       [32]byte
	hasRoot    bool
	registered map[[16]byte]bool
	keyIDs     map[keyKey][][8]byte
	bindings   map[bindingKey][]interval

	members         map[[16]byte]oplog.MemberRecord
	controlKeys     map[[16]byte][]keyInterval
	grants          map[[16]byte]oplog.Grant
	grantOrder      [][16]byte
	delegations     map[[16]byte]oplog.Delegation
	delegationOrder [][16]byte
	roleTables      []roleTableRow
	amendIDs        map[[16]byte]bool
	epochs          []uint32
	digests         map[uint32][32]byte
	sessionsEnded   [][16]byte
}

func newState() *state {
	return &state{
		registered:  map[[16]byte]bool{},
		keyIDs:      map[keyKey][][8]byte{},
		bindings:    map[bindingKey][]interval{},
		members:     map[[16]byte]oplog.MemberRecord{},
		controlKeys: map[[16]byte][]keyInterval{},
		grants:      map[[16]byte]oplog.Grant{},
		delegations: map[[16]byte]oplog.Delegation{},
		amendIDs:    map[[16]byte]bool{},
		digests:     map[uint32][32]byte{},
	}
}

func (s *state) clone() *state {
	c := &state{
		exists:          s.exists,
		genesisAt:       s.genesisAt,
		root:            s.root,
		hasRoot:         s.hasRoot,
		registered:      maps.Clone(s.registered),
		keyIDs:          map[keyKey][][8]byte{},
		bindings:        map[bindingKey][]interval{},
		ops:             make([]*oplog.StoredOp, len(s.ops)),
		members:         maps.Clone(s.members),
		controlKeys:     map[[16]byte][]keyInterval{},
		grants:          maps.Clone(s.grants),
		grantOrder:      slices.Clone(s.grantOrder),
		delegations:     maps.Clone(s.delegations),
		delegationOrder: slices.Clone(s.delegationOrder),
		roleTables:      slices.Clone(s.roleTables),
		amendIDs:        maps.Clone(s.amendIDs),
		epochs:          slices.Clone(s.epochs),
		digests:         maps.Clone(s.digests),
		sessionsEnded:   slices.Clone(s.sessionsEnded),
	}
	for k, v := range s.controlKeys {
		c.controlKeys[k] = slices.Clone(v)
	}
	for k, v := range s.keyIDs {
		c.keyIDs[k] = slices.Clone(v)
	}
	for k, v := range s.bindings {
		c.bindings[k] = slices.Clone(v)
	}
	for i, op := range s.ops {
		cp := *op
		cp.Envelope = slices.Clone(op.Envelope)
		c.ops[i] = &cp
	}
	return c
}

type workspace struct {
	mu sync.Mutex
	st *state
}

// Store holds every Workspace.
type Store struct {
	mu sync.Mutex
	ws map[[16]byte]*workspace
}

// New returns an empty store.
func New() *Store { return &Store{ws: map[[16]byte]*workspace{}} }

func (s *Store) workspace(id [16]byte) *workspace {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.ws[id]
	if !ok {
		w = &workspace{st: newState()}
		s.ws[id] = w
	}
	return w
}

// BeginAppend takes the Workspace's lock and hands out a transaction over a
// clone of its state.
func (s *Store) BeginAppend(_ context.Context, id [16]byte) (oplog.Tx, error) {
	w := s.workspace(id)
	w.mu.Lock()
	return &tx{ws: w, id: id, st: w.st.clone()}, nil
}

// Seed applies a mutation outside the append path, for building a fixture.
func (s *Store) Seed(id [16]byte, f func(Seeder)) {
	w := s.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	f(Seeder{st: w.st})
}

// Seeder writes the facts an append path would otherwise establish through
// Authority — registrations, key ids, and the Workspace's own existence.
type Seeder struct{ st *state }

// Exists marks the Workspace as having an accepted genesis.
func (s Seeder) Exists() { s.st.exists = true }

// Register records an accepted registration and the device's key ids.
func (s Seeder) Register(member [16]byte, controlKeyID, contentKeyID [8]byte) {
	s.st.registered[member] = true
	s.st.keyIDs[keyKey{member, oplog.ControlSigning}] = append(
		s.st.keyIDs[keyKey{member, oplog.ControlSigning}], controlKeyID)
	s.st.keyIDs[keyKey{member, oplog.ContentSigning}] = append(
		s.st.keyIDs[keyKey{member, oplog.ContentSigning}], contentKeyID)
}

// Member records a full registration, for a fixture that needs the member list
// to have something in it.
func (s Seeder) Member(rec oplog.MemberRecord) {
	s.st.members[rec.MemberID] = rec
	s.st.registered[rec.MemberID] = true
	s.st.keyIDs[keyKey{rec.MemberID, oplog.ControlSigning}] = append(
		s.st.keyIDs[keyKey{rec.MemberID, oplog.ControlSigning}], wire.KeyID(rec.ControlPK[:]))
	s.st.keyIDs[keyKey{rec.MemberID, oplog.ContentSigning}] = append(
		s.st.keyIDs[keyKey{rec.MemberID, oplog.ContentSigning}], wire.KeyID(rec.ContentPK[:]))
	s.st.controlKeys[rec.MemberID] = append(s.st.controlKeys[rec.MemberID],
		keyInterval{pk: rec.ControlPK, start: rec.RegisteredAt})
}

// Grant records a grant with its positional window.
func (s Seeder) Grant(g oplog.Grant) {
	s.st.grants[g.GrantID] = g
	s.st.grantOrder = append(s.st.grantOrder, g.GrantID)
}

// Ops returns the committed log, for assertions.
func (s *Store) Ops(id [16]byte) []oplog.StoredOp {
	w := s.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]oplog.StoredOp, 0, len(w.st.ops))
	for _, op := range w.st.ops {
		out = append(out, *op)
	}
	return out
}

type tx struct {
	ws     *workspace
	id     [16]byte
	st     *state
	closed bool
}

var errClosed = errors.New("memstore: transaction is closed")

func (t *tx) WorkspaceExists() (bool, error) { return t.st.exists, nil }

func (t *tx) Registered(member [16]byte) (bool, error) { return t.st.registered[member], nil }

func (t *tx) KeyIDsHeldForClass(member [16]byte, class oplog.SigningClass) ([][8]byte, error) {
	return t.st.keyIDs[keyKey{member, class}], nil
}

func (t *tx) OpByOpID(author, opID [16]byte) (*oplog.StoredOp, bool, error) {
	for _, op := range t.st.ops {
		if op.Author == author && op.OpID == opID {
			return op, true, nil
		}
	}
	return nil, false, nil
}

func (t *tx) OpAt(seq int64) (*oplog.StoredOp, bool, error) {
	if seq < 1 || seq > int64(len(t.st.ops)) {
		return nil, false, nil
	}
	return t.st.ops[seq-1], true, nil
}

func (t *tx) AuthorHead(member [16]byte) (uint64, error) {
	var head uint64
	for _, op := range t.st.ops {
		if op.Author == member && op.AuthorSeq > head {
			head = op.AuthorSeq
		}
	}
	return head, nil
}

func (t *tx) ExtBindingAt(member [16]byte, class byte, seq int64) (string, bool, error) {
	for _, iv := range t.st.bindings[bindingKey{member, class}] {
		if seq >= iv.start && (iv.end == 0 || seq < iv.end) {
			return iv.name, true, nil
		}
	}
	return "", false, nil
}

func (t *tx) LiveExtBinding(member [16]byte, class byte) (string, bool, error) {
	for _, iv := range t.st.bindings[bindingKey{member, class}] {
		if iv.end == 0 {
			return iv.name, true, nil
		}
	}
	return "", false, nil
}

// Append enforces the two uniqueness rules in the storage layer, not in
// application code.
//
// The write path reads the author's current head and then inserts. Two
// concurrent batches can both read the same head and both believe they own the
// next slot — a write skew no amount of application logic closes — and a forked
// author chain is unrecoverable, because prev_author_hash would name two
// different successors.
var (
	ErrDuplicateOpID     = errors.New("memstore: (workspace, author, op_id) is not unique")
	ErrDuplicateAuthSeq  = errors.New("memstore: (workspace, author, author_seq) is not unique")
	ErrEnvelopeImmutable = errors.New("memstore: an op's envelope is never rewritten")
)

func (t *tx) Append(op oplog.StoredOp) (int64, error) {
	if t.closed {
		return 0, errClosed
	}
	for _, existing := range t.st.ops {
		if existing.Author != op.Author {
			continue
		}
		if existing.OpID == op.OpID {
			return 0, ErrDuplicateOpID
		}
		if existing.AuthorSeq == op.AuthorSeq {
			return 0, ErrDuplicateAuthSeq
		}
	}
	op.Seq = int64(len(t.st.ops)) + 1
	op.Envelope = slices.Clone(op.Envelope)
	t.st.ops = append(t.st.ops, &op)
	return op.Seq, nil
}

func (t *tx) MarkReprised(seq, byPos int64) error {
	op, ok, _ := t.OpAt(seq)
	if !ok {
		return errors.New("memstore: no op at that position")
	}
	op.ReprisedBy = byPos
	return nil
}

// DropEnvelope destroys the bytes and keeps the tombstone — every other fact on
// the row, including the envelope hash, which is materialised from the bytes
// about to be dropped and never taken from the payload that asked for the
// destruction.
func (t *tx) DropEnvelope(seq int64) error {
	op, ok, _ := t.OpAt(seq)
	if !ok {
		return errors.New("memstore: no op at that position")
	}
	op.Envelope = nil
	return nil
}

func (t *tx) OpenExtBinding(member [16]byte, class byte, name string, at int64) error {
	k := bindingKey{member, class}
	t.st.bindings[k] = append(t.st.bindings[k], interval{name: name, start: at})
	return nil
}

// CloseExtBinding writes the interval's end position, which is write-once.
func (t *tx) CloseExtBinding(member [16]byte, class byte, at int64) error {
	k := bindingKey{member, class}
	ivs := t.st.bindings[k]
	for i := range ivs {
		if ivs[i].end == 0 {
			ivs[i].end = at
			return nil
		}
	}
	return errors.New("memstore: no open interval to close")
}

func (t *tx) Commit() error {
	if t.closed {
		return errClosed
	}
	t.closed = true
	t.ws.st = t.st
	t.ws.mu.Unlock()
	return nil
}

func (t *tx) Rollback() error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.ws.mu.Unlock()
	return nil
}

// ── Authority's rows ────────────────────────────────────────────────────────

func (t *tx) CurrentRoot() ([32]byte, bool, error) { return t.st.root, t.st.hasRoot, nil }

func (t *tx) SetRoot(pk [32]byte) error {
	t.st.root, t.st.hasRoot = pk, true
	return nil
}

func (t *tx) MarkGenesis(at int64) error {
	t.st.exists = true
	t.st.genesisAt = at
	return nil
}

func (t *tx) MemberRecord(member [16]byte) (*oplog.MemberRecord, bool, error) {
	rec, ok := t.st.members[member]
	if !ok {
		return nil, false, nil
	}
	cp := rec
	return &cp, true, nil
}

func (t *tx) PutRegistration(rec oplog.MemberRecord) error {
	t.st.members[rec.MemberID] = rec
	t.st.registered[rec.MemberID] = true
	// Interval zero for every key name is the registration's own.
	t.st.keyIDs[keyKey{rec.MemberID, oplog.ControlSigning}] = append(
		t.st.keyIDs[keyKey{rec.MemberID, oplog.ControlSigning}], wire.KeyID(rec.ControlPK[:]))
	t.st.keyIDs[keyKey{rec.MemberID, oplog.ContentSigning}] = append(
		t.st.keyIDs[keyKey{rec.MemberID, oplog.ContentSigning}], wire.KeyID(rec.ContentPK[:]))
	t.st.controlKeys[rec.MemberID] = append(t.st.controlKeys[rec.MemberID],
		keyInterval{pk: rec.ControlPK, start: rec.RegisteredAt})
	return nil
}

// ControlKeyAt resolves the interval whose span contains the position.
func (t *tx) ControlKeyAt(member [16]byte, at int64) ([32]byte, bool, error) {
	var out [32]byte
	for _, iv := range t.st.controlKeys[member] {
		if at >= iv.start && (iv.end == 0 || at < iv.end) {
			return iv.pk, true, nil
		}
	}
	return out, false, nil
}

func (t *tx) GrantByID(id [16]byte) (*oplog.Grant, bool, error) {
	g, ok := t.st.grants[id]
	if !ok {
		return nil, false, nil
	}
	cp := g
	return &cp, true, nil
}

func (t *tx) LiveGrantsAt(member [16]byte, at int64) ([]oplog.Grant, error) {
	var out []oplog.Grant
	for _, g := range t.st.grantOrder {
		row := t.st.grants[g]
		if row.Member == member && row.LiveAt(at) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (t *tx) HasAnyGrant(member [16]byte) (bool, error) {
	for _, g := range t.st.grantOrder {
		if t.st.grants[g].Member == member {
			return true, nil
		}
	}
	return false, nil
}

func (t *tx) PutGrant(g oplog.Grant) error {
	if _, dup := t.st.grants[g.GrantID]; dup {
		return errors.New("memstore: grant id is not unique")
	}
	t.st.grants[g.GrantID] = g
	t.st.grantOrder = append(t.st.grantOrder, g.GrantID)
	return nil
}

// CloseGrant writes the end position, which is write-once.
func (t *tx) CloseGrant(id [16]byte, at int64) error {
	g, ok := t.st.grants[id]
	if !ok {
		return errors.New("memstore: no such grant")
	}
	if g.End != 0 {
		return errors.New("memstore: a grant's end position is write-once")
	}
	g.End = at
	t.st.grants[id] = g
	return nil
}

func (t *tx) DelegationByID(id [16]byte) (*oplog.Delegation, bool, error) {
	d, ok := t.st.delegations[id]
	if !ok {
		return nil, false, nil
	}
	cp := d
	return &cp, true, nil
}

func (t *tx) LiveDelegationsAt(at int64) ([]oplog.Delegation, error) {
	var out []oplog.Delegation
	for _, id := range t.st.delegationOrder {
		if d := t.st.delegations[id]; d.LiveAt(at) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (t *tx) IsRegisteredSigningKey(pk [32]byte) (bool, error) {
	for _, rec := range t.st.members {
		if rec.ControlPK == pk || rec.ContentPK == pk {
			return true, nil
		}
	}
	for _, ivs := range t.st.controlKeys {
		for _, iv := range ivs {
			if iv.pk == pk {
				return true, nil
			}
		}
	}
	return false, nil
}

func (t *tx) PutDelegation(d oplog.Delegation) error {
	if _, dup := t.st.delegations[d.DelegationID]; dup {
		return errors.New("memstore: delegation id is not unique")
	}
	t.st.delegations[d.DelegationID] = d
	t.st.delegationOrder = append(t.st.delegationOrder, d.DelegationID)
	return nil
}

func (t *tx) CloseDelegation(id [16]byte, at int64) error {
	d, ok := t.st.delegations[id]
	if !ok {
		return errors.New("memstore: no such delegation")
	}
	if d.End != 0 {
		return errors.New("memstore: a delegation's end position is write-once")
	}
	d.End = at
	t.st.delegations[id] = d
	return nil
}

// RoleTableAt is the table carried by the latest role_table op below a position.
func (t *tx) RoleTableAt(at int64) (profile.RoleTable, bool, error) {
	var best *roleTableRow
	for i := range t.st.roleTables {
		row := &t.st.roleTables[i]
		if row.at < at && (best == nil || row.at > best.at) {
			best = row
		}
	}
	if best == nil {
		return nil, false, nil
	}
	return best.table, true, nil
}

func (t *tx) PutRoleTable(table profile.RoleTable, at int64) error {
	t.st.roleTables = append(t.st.roleTables, roleTableRow{at: at, table: table})
	return nil
}

func (t *tx) AmendIDUsed(id [16]byte) (bool, error) { return t.st.amendIDs[id], nil }

func (t *tx) PutAmend(member, amendID [16]byte, control, content, kex *oplog.KeyChange, at int64) error {
	t.st.amendIDs[amendID] = true
	// The member row carries the keys in force, which is the latest interval
	// materialised. Every op below the amend keeps verifying under the keys it
	// was signed with; what moves is only what the next one is judged against.
	if rec, ok := t.st.members[member]; ok {
		if control != nil {
			rec.ControlPK = control.PK
		}
		if content != nil {
			rec.ContentPK = content.PK
		}
		if kex != nil {
			rec.KexPK = kex.PK
		}
		t.st.members[member] = rec
	}
	if control != nil {
		// The interval the amend closes ends at the amend's own position, and the
		// new one opens there. Every op below keeps verifying under the keys it
		// was signed with, for ever.
		ivs := t.st.controlKeys[member]
		for i := range ivs {
			if ivs[i].end == 0 {
				ivs[i].end = at
			}
		}
		t.st.controlKeys[member] = append(ivs, keyInterval{pk: control.PK, start: at})
		t.st.keyIDs[keyKey{member, oplog.ControlSigning}] = append(
			t.st.keyIDs[keyKey{member, oplog.ControlSigning}], control.KeyID)
	}
	if content != nil {
		t.st.keyIDs[keyKey{member, oplog.ContentSigning}] = append(
			t.st.keyIDs[keyKey{member, oplog.ContentSigning}], content.KeyID)
	}
	return nil
}

// CurrentEpoch is the maximum materialised epoch, computed on demand. A stored
// value would be a cache of that maximum, free to disagree with the records that
// produced it.
func (t *tx) CurrentEpoch() (uint32, error) {
	var max uint32
	for _, e := range t.st.epochs {
		if e > max {
			max = e
		}
	}
	return max, nil
}

func (t *tx) PutRotate(from, to uint32, digest [32]byte, at int64) error {
	t.st.epochs = append(t.st.epochs, to)
	t.st.digests[to] = digest
	return nil
}

func (t *tx) LastControlOpBefore(seq int64) (*oplog.StoredOp, bool, error) {
	for i := len(t.st.ops) - 1; i >= 0; i-- {
		op := t.st.ops[i]
		if op.Seq < seq && op.Class == wire.ClassControl {
			return op, true, nil
		}
	}
	return nil, false, nil
}

// EndDeviceSessions is the cascade. Sessions live outside this store, so what is
// recorded here is that it happened — which is what a test can observe and what
// a real deployment would fan out to its token table and its socket registry.
func (t *tx) EndDeviceSessions(member [16]byte) error {
	t.st.sessionsEnded = append(t.st.sessionsEnded, member)
	return nil
}

func (t *tx) NextSeq() (int64, error) { return int64(len(t.st.ops)) + 1, nil }

// SessionsEnded reports the devices whose sessions the cascade closed, for
// assertions.
func (s *Store) SessionsEnded(id [16]byte) [][16]byte {
	w := s.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.st.sessionsEnded)
}

// Grants returns the committed grants, for assertions.
func (s *Store) Grants(id [16]byte) []oplog.Grant {
	w := s.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]oplog.Grant, 0, len(w.st.grantOrder))
	for _, g := range w.st.grantOrder {
		out = append(out, w.st.grants[g])
	}
	return out
}

// Root returns the committed current Root, for assertions.
func (s *Store) Root(id [16]byte) ([32]byte, bool) {
	w := s.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st.root, w.st.hasRoot
}

// ── reading ─────────────────────────────────────────────────────────────────

// BeginRead takes the Workspace's lock and serves from the committed state.
//
// Holding the lock is what makes a read unable to observe a partially committed
// batch: an append mutates a clone and swaps it in under the same lock, so a
// reader sees the state before or the state after and never a state between.
func (s *Store) BeginRead(_ context.Context, id [16]byte) (oplog.ReadTx, error) {
	w := s.workspace(id)
	w.mu.Lock()
	return &readTx{ws: w, st: w.st}, nil
}

type readTx struct {
	ws     *workspace
	st     *state
	closed bool
}

func (r *readTx) WorkspaceExists() (bool, error) { return r.st.exists, nil }

func (r *readTx) Registered(member [16]byte) (bool, error) { return r.st.registered[member], nil }

func (r *readTx) HasAnyGrant(member [16]byte) (bool, error) {
	for _, id := range r.st.grantOrder {
		if r.st.grants[id].Member == member {
			return true, nil
		}
	}
	return false, nil
}

func (r *readTx) LiveGrantsAt(member [16]byte, at int64) ([]oplog.Grant, error) {
	var out []oplog.Grant
	for _, id := range r.st.grantOrder {
		if row := r.st.grants[id]; row.Member == member && row.LiveAt(at) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (r *readTx) NextSeq() (int64, error) { return int64(len(r.st.ops)) + 1, nil }

func (r *readTx) ReadOps(since int64, limit int, includeReprised bool) (oplog.Page, error) {
	var page oplog.Page
	for _, op := range r.st.ops {
		if op.Seq <= since {
			continue
		}
		// A hard-pruned op is absent from every page, under either filter. It is
		// necessarily reprised — rule 4 requires the mark first — so the default
		// filter already hides it; this is what keeps the history view from
		// serving a hole.
		if op.Envelope == nil {
			continue
		}
		if !includeReprised && op.Reprised() {
			continue
		}
		// One past the limit answers has_more exactly, without a second query
		// and without counting the whole log.
		if len(page.Ops) == limit {
			page.HasMore = true
			break
		}
		page.Ops = append(page.Ops, *op)
	}
	return page, nil
}

func (r *readTx) ReadMembers(after *[16]byte, limit int) (oplog.MemberPage, error) {
	ids := make([][16]byte, 0, len(r.st.members))
	for id := range r.st.members {
		ids = append(ids, id)
	}
	// Ordered by raw member id bytes, as unsigned. Not by the UUID text, and
	// emphatically not by a platform UUID type comparing two signed 64-bit
	// halves, which reorders every id whose top bit is set.
	slices.SortFunc(ids, func(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) })

	var page oplog.MemberPage
	for _, id := range ids {
		if after != nil && bytes.Compare(id[:], after[:]) <= 0 {
			continue
		}
		if len(page.Members) == limit {
			page.HasMore = true
			break
		}
		page.Members = append(page.Members, r.st.members[id])
	}
	return page, nil
}

func (r *readTx) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.ws.mu.Unlock()
	return nil
}
