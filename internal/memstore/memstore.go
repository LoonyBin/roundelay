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
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/loonybin/roundelay/oplog"
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

type state struct {
	ops        []*oplog.StoredOp // index is seq-1
	exists     bool
	registered map[[16]byte]bool
	keyIDs     map[keyKey][][8]byte
	bindings   map[bindingKey][]interval
}

func newState() *state {
	return &state{
		registered: map[[16]byte]bool{},
		keyIDs:     map[keyKey][][8]byte{},
		bindings:   map[bindingKey][]interval{},
	}
}

func (s *state) clone() *state {
	c := &state{
		exists:     s.exists,
		registered: maps.Clone(s.registered),
		keyIDs:     map[keyKey][][8]byte{},
		bindings:   map[bindingKey][]interval{},
		ops:        make([]*oplog.StoredOp, len(s.ops)),
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
